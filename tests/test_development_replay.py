"""Replay admission validates real digests, contracts, receipts, and budget boundaries."""
import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from daedalus.application.realwork_workers import baseline_path
from daedalus.application.upstream_contract import compile_contract
from daedalus.infrastructure.knowledge import atomic_json
from daedalus.service import replay_admission as admission
from daedalus.service.capability_budget import json_digest


@pytest.fixture
def replay(tmp_path, monkeypatch):
    from daedalus.application import realwork
    from daedalus.service import realwork_routes as routes

    data, project, root = tmp_path / "data", tmp_path / "project", tmp_path / "workspace/realwork-evaluations"
    implementation = project / "src/daedalus/worker.py"
    implementation.parent.mkdir(parents=True)
    implementation.write_text("VALUE = 1\n")
    (tmp_path / "module.py").write_text("class Tests:\n    def test_stable(self): pass\n")
    contract = compile_contract(
        {"repo": "django/django", "PASS_TO_PASS": ["test_stable (module.Tests)"],
         "FAIL_TO_PASS": ["test_issue (module.Tests)"]}, ["module"], tmp_path)
    proof = {
        key: {"passed": key != "hidden_original", "tests": 1, "executed": 1,
              "complete": True, "evidence_kind": "native_runner_counters", "isolation": "seatbelt"}
        for key in ("public_original", "public_reference", "hidden_original", "hidden_reference")
    }
    cases = [
        {"case": name, "repo": "django/django", "base_commit": "base", "targets": ["solution.py"],
         "labels": ["module"], "archive_sha256": "archive", "source_chars": 100,
         "test_contract": contract, "contract_qualification": proof, "isolation": "seatbelt"}
        for name in ("known_a", "known_b", "known_c")
    ]
    baseline = baseline_path(data, "efficiency-v1")
    baseline.parent.mkdir(parents=True)
    baseline.write_text("class ModelWorker: pass\n")
    baseline_digest = hashlib.sha256(baseline.read_bytes()).hexdigest()
    parents, ledgers, protocols = {}, {}, {}
    jobs = [f"realwork_cycle_parent_{index}" for index in range(6)] + [admission.COMPARISON_JOB]
    for index, job_id in enumerate(jobs):
        study = ("capability-cycle-v1" if index < 2 else "capability-cycle-transport-v1"
                 if index < 5 else "worker-efficiency-v1" if index == 5 else "worker-efficiency-v2")
        old = {"job_id": job_id, "study": study, "status": "INCOMPLETE" if index == 1 else "COMPLETE",
               "session_id": "historical"}
        records = [{"index": 1, "request_dispatched": True, "usage_available": True,
                    "prompt_tokens": 0, "completion_tokens": 0}]
        allowances = []
        if index == 1:
            records[0].update(usage_available=False, input_digest="sealed-input", max_output_tokens=2048,
                              error_type="IncompleteRead")
            allowances = [{"index": 1, "input_digest": "sealed-input", "reserved_cost_cny": 2.25}]
        ledger = {"call_records": records}
        protocol = {"model": "deepseek-flash", "inference_profile": "deepseek_bounded_json", "study": study}
        ledgers[job_id], protocols[job_id] = ledger, protocol
        parents[job_id] = {"usage_sha256": json_digest(ledger), "protocol_sha256": json_digest(protocol),
                           "unknown_reservations": allowances}
        atomic_json(root / job_id / "job.json", old)
        atomic_json(root / job_id / "results/series-usage.json", ledger)
        atomic_json(root / job_id / "results/protocol.json", protocol)
    compact = {"version": 1, "study": "worker-efficiency-v2", "max_cost_cny": 4.5,
               "baseline_worker_sha256": baseline_digest,
               "parent_jobs": {job: parents[job] for job in jobs[:6]},
               "batches": [{"phase": "paired-development-compact", "cases": cases}]}
    compact["sha256"] = json_digest(compact)
    atomic_json(data / "diagnostics/worker-efficiency-20261028/compact-plan.json", compact)
    # Synthetic frozen evidence has its own trusted anchor; no admission checks are mocked.
    monkeypatch.setattr(admission, "SELECTION_DIGEST", compact["sha256"])
    comparison = protocols[jobs[-1]]
    comparison.update(
        selection_rule_sha256=compact["sha256"],
        cases=[{key: case[key] for key in ("case", "base_commit", "targets", "labels", "archive_sha256", "source_chars")}
               for case in cases],
        arms=["baseline", "optimized"], cycle={"baseline_worker_sha256": baseline_digest},
        max_tokens_per_arm=30000, max_calls_per_arm=6,
    )
    parents[jobs[-1]]["protocol_sha256"] = json_digest(comparison)
    atomic_json(root / jobs[-1] / "results/protocol.json", comparison)
    old = json.loads((root / jobs[-1] / "job.json").read_text())
    old["plan_sha256"] = compact["sha256"]
    atomic_json(root / jobs[-1] / "job.json", old)
    plan = {
        "version": 1, "study": admission.STUDY, "phase": admission.PHASE,
        "max_cost_cny": 1, "user_authorized_cap_cny": 1, "reserve_cny": 0,
        "authorization": dict(admission.AUTHORIZATION),
        "historical_budget": {"max_cost_cny": 4.5, "user_authorized_cap_cny": 5,
                              "reserve_cny": 0.5, "unknown_reserved_cost_cny": 2.25,
                              "occupied_cost_cny": 2.25},
        "comparison_job_id": admission.COMPARISON_JOB,
        "comparison_arm": "optimized", "selection_plan_sha256": compact["sha256"],
        "cases": cases, "parent_jobs": parents,
        "implementation_sha256": {str(implementation.relative_to(project)):
                                    hashlib.sha256(implementation.read_bytes()).hexdigest()},
    }
    plan_path = data / "diagnostics/known-task-replay-20261030/frozen-plan.json"

    def freeze():
        plan.pop("sha256", None)
        plan["sha256"] = json_digest(plan)
        atomic_json(plan_path, plan)

    freeze()
    available = SimpleNamespace(value=True)
    monkeypatch.setattr(admission.SeatbeltDriver, "probe", lambda self: SimpleNamespace(available=available.value))
    monkeypatch.setattr(routes, "DATA", data)
    monkeypatch.setattr(realwork, "PROJECT", project)
    clients, submissions = [], []
    active = SimpleNamespace(value=False)
    model = SimpleNamespace(model="deepseek-flash")
    model.for_profile = lambda profile: model
    state = SimpleNamespace(
        settings=SimpleNamespace(workspace=SimpleNamespace(root_path=root.parent)),
        lifecycle=SimpleNamespace(session_id="current"),
        dispatcher=SimpleNamespace(busy_runs=lambda: active.value,
                                   submit=lambda *args: submissions.append(args)),
        build_model_client=lambda role: (clients.append(role), model)[1],
    )
    app = FastAPI()
    app.include_router(routes.realwork_router(state))
    with TestClient(app) as client:
        yield SimpleNamespace(
            data=data, project=project, root=root, implementation=implementation, plan=plan,
            plan_path=plan_path, compact=compact, parents=parents, ledgers=ledgers, protocols=protocols,
            jobs=jobs, freeze=freeze, baseline=baseline, available=available, active=active,
            clients=clients, submissions=submissions, state=state, client=client, model=model,
        )


def admit(replay):
    return admission.admit_replay(replay.data, replay.project, replay.root, replay.plan["sha256"])


def post(replay, **changes):
    body = {"confirm_paid_calls": True, "confirm_known_task_replay": True,
            "plan_sha256": replay.plan["sha256"]}
    body.update(changes)
    return replay.client.post("/api/realwork-development-replays", json=body)


def test_admission_derives_spend_and_preserves_historical_anchors(replay):
    context = admit(replay)
    assert context["cases"] == replay.compact["batches"][0]["cases"]
    assert context["comparison_arm"] == "optimized"
    assert context["monetary_admission"] == {
        "max_total_cost_cny": 1, "prior_cost_upper_cny": 0,
        "user_authorized_cap_cny": 1, "reserve_cny": 0, "unknown_reserved_cost_cny": 0,
    }
    assert context["historical_budget"]["occupied_cost_cny"] == 2.25
    assert context["historical_budget"]["unknown_reserved_cost_cny"] == 2.25
    assert context["authorization"] == admission.AUTHORIZATION
    assert context["selection_plan_sha256"] == replay.compact["sha256"]
    assert context["comparison_protocol_sha256"] == replay.parents[admission.COMPARISON_JOB]["protocol_sha256"]


@pytest.mark.parametrize("fault", ["plan_digest", "request_digest", "implementation_changed", "implementation_added",
                                 "implementation_removed", "case_order", "baseline_source", "missing_parent",
                                 "parent_usage", "parent_protocol", "new_unknown", "reservation", "comparison_arm",
                                 "unsealed_parent", "qualification", "reserve", "cap", "authorization", "sandbox"])
def test_invalid_evidence_cannot_construct_a_paid_client(replay, fault):
    if fault == "plan_digest":
        saved = json.loads(replay.plan_path.read_text())
        saved["version"] = 2
        atomic_json(replay.plan_path, saved)
    elif fault == "request_digest":
        pass
    elif fault == "implementation_changed":
        replay.implementation.write_text("VALUE = 2\n")
    elif fault == "implementation_added":
        (replay.implementation.parent / "new.py").write_text("VALUE = 2\n")
    elif fault == "implementation_removed":
        replay.implementation.unlink()
    elif fault == "case_order":
        replay.plan["cases"] = list(reversed(replay.plan["cases"]))
        replay.freeze()
    elif fault == "baseline_source":
        replay.baseline.write_text("class DifferentWorker: pass\n")
    elif fault == "missing_parent":
        (replay.root / replay.jobs[0] / "results/series-usage.json").unlink()
    elif fault in {"parent_usage", "new_unknown"}:
        usage = replay.ledgers[replay.jobs[-1]]
        usage["call_records"][0].update(prompt_tokens=100, usage_available=fault != "new_unknown")
        atomic_json(replay.root / replay.jobs[-1] / "results/series-usage.json", usage)
        if fault == "new_unknown":
            replay.parents[replay.jobs[-1]]["usage_sha256"] = json_digest(usage)
            replay.freeze()
    elif fault == "parent_protocol":
        protocol = replay.protocols[replay.jobs[0]]
        protocol["model"] = "changed-model"
        atomic_json(replay.root / replay.jobs[0] / "results/protocol.json", protocol)
    elif fault == "reservation":
        replay.parents[replay.jobs[1]]["unknown_reservations"][0]["reserved_cost_cny"] = 0
        replay.freeze()
    elif fault == "comparison_arm":
        replay.plan["comparison_arm"] = "baseline"
        replay.freeze()
    elif fault == "unsealed_parent":
        path = replay.root / replay.jobs[0] / "job.json"
        old = json.loads(path.read_text())
        old["status"] = "INTERRUPTED"
        atomic_json(path, old)
    elif fault == "qualification":
        replay.plan["cases"][0]["contract_qualification"]["hidden_original"]["complete"] = False
        replay.freeze()
    elif fault in {"reserve", "cap", "authorization"}:
        field = {"reserve": "reserve_cny", "cap": "max_cost_cny", "authorization": "user_authorized_cap_cny"}[fault]
        replay.plan[field] = 6
        replay.freeze()
    elif fault == "sandbox":
        replay.available.value = False
    response = post(replay, **({"plan_sha256": "f" * 64} if fault == "request_digest" else {}))
    assert response.status_code == 409
    assert not replay.clients and not replay.submissions


@pytest.mark.parametrize("kind", ["known_spend", "unknown_spend", "incomplete", "orphan_directory", "protocol_only_scope"])
def test_every_additional_shared_study_receipt_blocks_replay(replay, kind):
    job = replay.root / ("realwork_unclassified" if kind == "protocol_only_scope" else "realwork_cycle_new")
    job.mkdir(parents=True)
    if kind != "orphan_directory":
        atomic_json(job / "job.json", {"job_id": job.name, "session_id": "old", "status": "COMPLETE",
                                      "study": "unclassified" if kind == "protocol_only_scope" else "worker-efficiency-v2"})
        if kind != "incomplete":
            atomic_json(job / "results/series-usage.json", {"call_records": [{"usage_available": kind != "unknown_spend",
                                                                           "prompt_tokens": 100}]})
        if kind == "protocol_only_scope":
            atomic_json(job / "results/protocol.json", {"monetary_admission": {"user_authorized_cap_cny": 5}})
    assert post(replay).status_code == 409
    assert not replay.clients and not replay.submissions


@pytest.mark.parametrize("prompt_tokens,accepted", [(1124999, True), (1125000, True), (1125001, False)])
def test_new_cap_does_not_rededuct_historical_spend_or_unknown_reserve(replay, prompt_tokens, accepted):
    job = admission.COMPARISON_JOB
    replay.ledgers[job]["call_records"][0]["prompt_tokens"] = prompt_tokens
    replay.parents[job]["usage_sha256"] = json_digest(replay.ledgers[job])
    atomic_json(replay.root / job / "results/series-usage.json", replay.ledgers[job])
    historical_cost = 2.25 + prompt_tokens * 2 / 1e6
    replay.plan["historical_budget"]["occupied_cost_cny"] = historical_cost
    replay.freeze()
    if accepted:
        context = admit(replay)
        assert context["historical_budget"]["occupied_cost_cny"] == pytest.approx(historical_cost)
        assert context["monetary_admission"]["prior_cost_upper_cny"] == 0
        assert context["monetary_admission"]["max_total_cost_cny"] == 1
        assert context["monetary_admission"]["unknown_reserved_cost_cny"] == 0
    else:
        assert post(replay).status_code == 409
        assert not replay.clients and not replay.submissions


@pytest.mark.parametrize("body", [
    {"confirm_paid_calls": False}, {"confirm_known_task_replay": False},
    {"confirm_known_task_replay": "true"}, {"confirm_paid_calls": 1},
    {"max_tokens": 90001}, {"max_calls": 19}, {"max_calls": 0},
    {"plan_sha256": "not-a-digest"}, {"max_cost_cny": 5},
])
def test_request_requires_both_explicit_intents_and_fixed_bounds(replay, body):
    assert post(replay, **body).status_code == 422
    assert not replay.clients and not replay.submissions


def test_active_job_and_wrong_saved_model_do_not_dispatch(replay):
    replay.active.value = True
    assert post(replay).status_code == 409
    assert not replay.clients
    replay.active.value = False
    replay.model.model = "not-deepseek-flash"
    assert post(replay).status_code == 422
    assert not replay.submissions


@pytest.mark.parametrize("terminal_status", ["CANCELED", "ERROR", "INCOMPLETE", "ADMISSION_FAILED"])
def test_replay_plan_consumption_survives_stops_and_router_recreation(replay, terminal_status):
    from daedalus.service.realwork_routes import realwork_router

    before = {path: path.read_bytes() for path in replay.root.glob("realwork_*/**/*.json")}
    response = post(replay)
    assert response.status_code == 202
    row = response.json()
    assert row["job_id"].startswith("realwork_replay_") and row["planned_trials"] == 3
    assert row["automatic_resume"] is False
    assert len(replay.submissions) == len(replay.clients) == 1
    job = row["job_id"]
    assert replay.client.get("/api/realwork-evaluations/" + job).status_code == 200
    assert replay.client.get("/api/realwork-evaluations").status_code == 200
    assert replay.client.post("/api/realwork-evaluations/" + job + "/cancel").status_code == 202
    assert all(path.read_bytes() == content for path, content in before.items())
    row["status"] = terminal_status
    atomic_json(replay.root / job / "job.json", row)
    app = FastAPI()
    app.include_router(realwork_router(replay.state))
    with TestClient(app) as restarted:
        assert restarted.post("/api/realwork-development-replays", json={
            "confirm_paid_calls": True, "confirm_known_task_replay": True,
            "plan_sha256": replay.plan["sha256"],
        }).status_code == 409
    assert len(replay.submissions) == len(replay.clients) == 1


@pytest.mark.parametrize("same_digest", [True, False])
def test_persisted_consumption_marker_blocks_even_without_job_receipt(replay, same_digest):
    digest = replay.plan["sha256"] if same_digest else "f" * 64
    atomic_json(replay.root / "replay-admissions" / (digest + ".json"),
                {"job_id": "realwork_replay_failed", "plan_sha256": digest})
    assert post(replay).status_code == 409
    assert not replay.clients and not replay.submissions


def test_get_request_never_dispatches(replay):
    assert replay.client.get("/api/realwork-development-replays").status_code == 405
    assert not replay.clients and not replay.submissions


@pytest.mark.parametrize("field,value", [
    ("max_cost_cny", 0.99), ("max_cost_cny", 1.01),
    ("authorization.scope", "shared-history"), ("authorization.max_cost_cny", 2),
    ("authorization.source", "balance is not spending authorization"),
    ("authorization.available_balance_cny", 100),
    ("historical_budget.occupied_cost_cny", 0),
    ("historical_budget.unknown_reserved_cost_cny", 0),
    ("historical_budget.reserve_cny", 0),
])
def test_new_authorization_and_historical_accounting_cannot_be_reinterpreted(replay, field, value):
    if "." in field:
        group, key = field.split(".")
        replay.plan[group][key] = value
    else:
        replay.plan[field] = value
    replay.freeze()
    assert post(replay).status_code == 409
    assert not replay.clients and not replay.submissions


@pytest.mark.parametrize("tokens", [-1, 1.5, True, "100"])
def test_invalid_sealed_token_counts_cannot_reduce_accounted_history(replay, tokens):
    job = admission.COMPARISON_JOB
    replay.ledgers[job]["call_records"][0]["prompt_tokens"] = tokens
    replay.parents[job]["usage_sha256"] = json_digest(replay.ledgers[job])
    atomic_json(replay.root / job / "results/series-usage.json", replay.ledgers[job])
    replay.freeze()
    assert post(replay).status_code == 409
    assert not replay.clients and not replay.submissions


def test_dispatch_admission_failure_still_consumes_the_plan(replay):
    from daedalus.errors import DaedalusError

    def reject(*_args):
        raise DaedalusError("dispatcher refused")

    replay.state.dispatcher.submit = reject
    with pytest.raises(DaedalusError, match="dispatcher refused"):
        post(replay)
    jobs = list(replay.root.glob("realwork_replay_*/job.json"))
    assert len(jobs) == 1
    assert json.loads(jobs[0].read_text())["status"] == "ADMISSION_FAILED"
    assert post(replay).status_code == 409
    assert len(replay.clients) == 1 and not replay.submissions
