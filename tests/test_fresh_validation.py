"""Fresh evidence, explicit scope and durable one-use admission precede paid calls."""
import hashlib
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from daedalus.application.realwork import VALIDATION_STUDY
from daedalus.infrastructure.knowledge import atomic_json
from daedalus.service import validation_admission as admission
from daedalus.service.capability_budget import json_digest
from daedalus.service.realwork_routes import realwork_router
from tests.test_development_replay import replay


@pytest.fixture
def fresh_batch(replay):  # noqa: F811 - pytest fixture injection
    folder = replay.data / admission.DIRECTORY
    authorization = {
        "scope": "fresh-batch-only", "max_cost_cny": None, "source": "explicit test authorization",
        "fixed_cases": 6, "arms": ["single", "daedalus"],
        "max_tokens_per_arm": 60000, "max_calls_per_arm": 12,
        "stop_on_unknown_usage": True, "no_automatic_resume": True,
    }
    archive = replay.data / "downloads/base.tar.gz"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"synthetic frozen archive identity")
    cases = []
    for index in range(6):
        case = json.loads(json.dumps(replay.plan["cases"][0]))
        case.update(case=f"fresh_{index}", initial_tree="a" * 40,
                    archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
        atomic_json(replay.data / "tasks" / case["case"] / "task.json", {"instance_id": case["case"]})
        cases.append(case)
    atomic_json(folder / "authorization.json", authorization)
    atomic_json(folder / "selection-rule.json", {"model_outcomes_used": False})
    atomic_json(folder / "qualification.json", [{"case": row["case"], "qualified": True} for row in cases])
    plan = {
        "version": 1, "study": VALIDATION_STUDY, "phase": "fresh-paired-validation",
        "arms": ["single", "daedalus"], "max_tokens_per_arm": 60000, "max_calls_per_arm": 12,
        "no_automatic_resume": True, "stop_on_unknown_usage": True,
        "price_checked": "2026-10-30", "authorization": authorization, "cases": cases,
        "implementation_sha256": {str(replay.implementation.relative_to(replay.project)):
                                  hashlib.sha256(replay.implementation.read_bytes()).hexdigest()},
        "selection_rule_sha256": hashlib.sha256((folder / "selection-rule.json").read_bytes()).hexdigest(),
        "task_sha256": {row["case"]: hashlib.sha256((
            replay.data / "tasks" / row["case"] / "task.json").read_bytes()).hexdigest() for row in cases},
    }

    def freeze():
        plan.pop("sha256", None)
        plan["sha256"] = json_digest(plan)
        atomic_json(folder / "frozen-plan.json", plan)

    freeze()
    replay.fresh_plan, replay.fresh_folder, replay.fresh_archive = plan, folder, archive
    replay.freeze_fresh = freeze
    yield replay


def post(batch, **changes):
    body = {"confirm_paid_calls": True, "plan_sha256": batch.fresh_plan["sha256"]}
    body.update(changes)
    return batch.client.post("/api/realwork-validation-batches", json=body)


def test_no_fee_ceiling_does_not_reset_or_rededuct_sealed_history(fresh_batch):
    before = {path: path.read_bytes() for path in fresh_batch.root.glob("realwork_*/**/*.json")}
    context = admission.admit_validation(fresh_batch.data, fresh_batch.project, fresh_batch.root,
                                        fresh_batch.fresh_plan["sha256"])
    assert context["monetary_admission"] is None
    assert context["authorization"]["max_cost_cny"] is None
    assert all(path.read_bytes() == value for path, value in before.items())


@pytest.mark.parametrize("fault", [
    "source", "task", "archive", "reserved", "protocol", "reference", "order", "selection",
    "missing_fee_intent", "changed_bounds", "isolation", "tree",
])
def test_invalid_fresh_evidence_never_constructs_a_paid_client(fresh_batch, fault):
    batch = fresh_batch
    case = batch.fresh_plan["cases"][0]
    if fault == "source":
        batch.implementation.write_text("VALUE = 2\n")
    elif fault == "task":
        atomic_json(batch.data / "tasks" / case["case"] / "task.json", {"instance_id": "changed"})
    elif fault == "archive":
        batch.fresh_archive.write_bytes(b"changed")
    elif fault in {"reserved", "protocol"}:
        parent = batch.root / batch.jobs[0]
        if fault == "reserved":
            old = json.loads((parent / "job.json").read_text())
            old["planned_case_ids"] = [case["case"]]
            atomic_json(parent / "job.json", old)
        else:
            atomic_json(parent / "results/protocol.json", {"cases": [{"case": case["case"]}]})
    elif fault == "reference":
        case["contract_qualification"]["hidden_reference"]["passed"] = False
        batch.freeze_fresh()
    elif fault == "order":
        batch.fresh_plan["cases"].reverse()
        batch.freeze_fresh()
    elif fault == "selection":
        atomic_json(batch.fresh_folder / "selection-rule.json", {"model_outcomes_used": True})
    elif fault == "missing_fee_intent":
        del batch.fresh_plan["authorization"]["max_cost_cny"]
        atomic_json(batch.fresh_folder / "authorization.json", batch.fresh_plan["authorization"])
        batch.freeze_fresh()
    elif fault == "changed_bounds":
        batch.fresh_plan["max_tokens_per_arm"] = 1
        batch.freeze_fresh()
    elif fault == "isolation":
        batch.available.value = False
    elif fault == "tree":
        case["initial_tree"] = "not-a-tree"
        batch.freeze_fresh()
    assert post(batch).status_code == 409
    assert not batch.clients and not batch.submissions


@pytest.mark.parametrize("value", [False, "true", 1])
def test_fee_authorization_requires_explicit_boolean_confirmation(fresh_batch, value):
    assert post(fresh_batch, confirm_paid_calls=value).status_code == 422
    assert not fresh_batch.clients and not fresh_batch.submissions


def test_one_use_survives_missing_receipt_and_router_recreation(fresh_batch):
    batch = fresh_batch
    started = post(batch)
    assert started.status_code == 202
    job = started.json()["job_id"]
    (batch.root / job / "job.json").unlink()
    app = FastAPI()
    app.include_router(realwork_router(batch.state))
    with TestClient(app) as restarted:
        result = restarted.post("/api/realwork-validation-batches", json={
            "confirm_paid_calls": True, "plan_sha256": batch.fresh_plan["sha256"],
        })
    assert result.status_code == 409
    assert len(batch.clients) == len(batch.submissions) == 1


def test_active_job_refuses_new_experiment_before_client_construction(fresh_batch):
    fresh_batch.active.value = True
    assert post(fresh_batch).status_code == 409
    assert not fresh_batch.clients and not fresh_batch.submissions
