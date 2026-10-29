"""A new paid cycle has immutable tasks, a shared ceiling and no resume/rerun path."""

import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from daedalus.application.upstream_contract import compile_contract
from daedalus.config import Settings, WorkspaceSettings
from daedalus.service.app import create_app


@pytest.fixture
def cycle(tmp_path, monkeypatch):
    import daedalus.service.realwork_routes as routes
    from daedalus.infrastructure.sandbox import SeatbeltDriver

    monkeypatch.setattr(SeatbeltDriver, "probe", lambda self: SimpleNamespace(available=True))

    data = tmp_path / "data"
    folder = data / "diagnostics/capability-cycle-20261027"
    folder.mkdir(parents=True)
    (tmp_path / "module.py").write_text("class Tests:\n    def test_stable(self): pass\n")
    contract = compile_contract(
        {
            "repo": "django/django",
            "PASS_TO_PASS": ["test_stable (module.Tests)"],
            "FAIL_TO_PASS": ["test_issue (module.Tests)"],
        },
        ["module"],
        tmp_path,
    )
    proof = {
        key: {
            "passed": key != "hidden_original",
            "tests": 1,
            "executed": 1,
            "complete": True,
            "evidence_kind": "native_runner_counters",
            "isolation": "seatbelt",
        }
        for key in ("public_original", "public_reference", "hidden_original", "hidden_reference")
    }
    cases = [
        {
            "case": key,
            "repo": "django/django",
            "labels": ["module"],
            "test_contract": contract,
            "contract_qualification": proof,
            "isolation": "seatbelt",
        }
        for key in ("fresh_a", "fresh_b")
    ]
    plan = {
        "version": 1,
        "max_cost_cny": 4.5,
        "batches": [
            {"phase": "development", "cases": [cases[0]]},
            {"phase": "heldout", "cases": [cases[1]]},
        ],
    }

    def freeze():
        plan.pop("sha256", None)
        plan["sha256"] = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
        (folder / "frozen-plan.json").write_text(json.dumps(plan))

    freeze()
    monkeypatch.setattr(routes, "DATA", data)
    monkeypatch.setattr(routes, "catalog", lambda: [])
    workspace = tmp_path / "workspace"
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(workspace))))
    clients, executions = [], []
    model = SimpleNamespace(model="deepseek-flash")
    model.for_profile = lambda _: model
    monkeypatch.setattr(
        app.state.daedalus, "build_model_client", lambda role: (clients.append(role), model)[1]
    )

    def execute(destination, client, **options):
        executions.append(options)
        destination.mkdir(parents=True)
        usage = {
            "call_records": [
                {"usage_available": True, "prompt_tokens": 100, "completion_tokens": 50}
            ]
        }
        (destination / "series-usage.json").write_text(json.dumps(usage))
        return {"status": "COMPLETE", "series_reported_tokens": 150, "series_logical_calls": 1}

    monkeypatch.setattr(routes, "run_realwork", execute)
    with TestClient(app) as client:
        yield client, plan, freeze, workspace, clients, executions


def wait_finished(client, job):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        row = client.get("/api/realwork-evaluations/" + job).json()
        if row["status"] not in ("RUNNING", "QUEUED"):
            return row
        time.sleep(0.01)
    pytest.fail("isolated test dispatcher did not finish")


def test_cycle_runs_each_fresh_batch_once_and_carries_shared_spend(cycle):
    client, _plan, _freeze, _workspace, clients, executions = cycle
    assert (
        client.post("/api/realwork-cycle", json={"batch_index": 0, "max_cost_cny": 5}).status_code
        == 422
    )
    assert (
        client.post(
            "/api/realwork-cycle", json={"batch_index": 1, "confirm_paid_calls": True}
        ).status_code
        == 409
    )
    assert not clients
    first = client.post("/api/realwork-cycle", json={"batch_index": 0, "confirm_paid_calls": True})
    assert first.status_code == 202 and first.json()["automatic_resume"] is False
    assert wait_finished(client, first.json()["job_id"])["status"] == "COMPLETE"
    assert (
        client.post(
            "/api/realwork-cycle", json={"batch_index": 0, "confirm_paid_calls": True}
        ).status_code
        == 409
    )
    second = client.post("/api/realwork-cycle", json={"batch_index": 1, "confirm_paid_calls": True})
    assert second.status_code == 202
    wait_finished(client, second.json()["job_id"])
    assert len(clients) == len(executions) == 2
    money = executions[1]["cycle"]["monetary_admission"]
    assert money["max_total_cost_cny"] == 4.5 and money["prior_cost_upper_cny"] == pytest.approx(
        0.0006
    )
    assert money["reserve_cny"] == 0.5 and executions[1]["max_tokens"] == 540000


@pytest.mark.parametrize("fault", ["digest", "ceiling", "proof", "isolation"])
def test_invalid_cycle_never_constructs_model_client(cycle, fault):
    client, plan, freeze, _workspace, clients, executions = cycle
    if fault == "ceiling":
        plan["max_cost_cny"] = 5
    elif fault == "proof":
        plan["batches"][0]["cases"][0]["contract_qualification"]["hidden_original"]["complete"] = (
            False
        )
    elif fault == "isolation":
        plan["batches"][0]["cases"][0]["isolation"] = "host-process"
    else:
        plan["version"] = 2
    freeze()
    assert (
        client.post(
            "/api/realwork-cycle", json={"batch_index": 0, "confirm_paid_calls": True}
        ).status_code
        == 409
    )
    assert not clients and not executions


def test_unknown_prior_usage_stops_next_batch_before_model(cycle):
    client, plan, _freeze, workspace, clients, executions = cycle
    folder = workspace / "realwork-evaluations/realwork_cycle_previous"
    (folder / "results").mkdir(parents=True)
    (folder / "job.json").write_text(
        json.dumps(
            {
                "job_id": folder.name,
                "study": "capability-cycle-v1",
                "status": "COMPLETE",
                "session_id": "old",
                "batch_index": 0,
                "plan_sha256": plan["sha256"],
                "planned_case_ids": ["fresh_a"],
            }
        )
    )
    (folder / "results/series-usage.json").write_text(
        json.dumps({"call_records": [{"usage_available": False}]})
    )
    assert (
        client.post(
            "/api/realwork-cycle", json={"batch_index": 1, "confirm_paid_calls": True}
        ).status_code
        == 409
    )
    assert not clients and not executions


@pytest.mark.parametrize("ceiling,expected_calls", [(4.5, 3), (0.00001, 0)])
def test_cycle_runner_uses_three_arms_and_refuses_unaffordable_provider_dispatch(
    cycle, tmp_path, monkeypatch, ceiling, expected_calls
):
    from daedalus.application import realwork
    from daedalus.model.base import Completion, Message

    _client, plan, _freeze, _workspace, _clients, _executions = cycle
    case = dict(
        plan["batches"][0]["cases"][0],
        base_commit="base",
        targets=["solution.py"],
        archive_sha256="archive",
        source_chars=10,
    )
    data = tmp_path / "runner-data"
    task = data / "tasks" / case["case"] / "task.json"
    task.parent.mkdir(parents=True)
    task.write_text("{}")
    monkeypatch.setattr(realwork, "DATA", data)
    monkeypatch.setattr(realwork, "_setup", lambda *a: (None, None, "tree", {}))
    monkeypatch.setattr(
        realwork,
        "_evaluate",
        lambda *a: {"public_passed": True, "heldout_passed": True, "policy_passed": True},
    )
    calls = []

    def complete(*a, **kw):
        admission_folder = tmp_path/"cycle-results/monetary-admissions"
        prepared = json.loads((admission_folder/f"request-{len(calls)+1:03}.json").read_text())
        assert prepared["state"] == "PREPARED"
        calls.append(kw)
        return Completion("{}", "deepseek-flash", 100, 20)

    provider = SimpleNamespace(model="deepseek-flash", name="fake", complete=complete)

    def attempt(*args, **kwargs):
        worker = args[2]
        worker.inner.client.complete([Message("user", "bounded JSON prompt")], max_tokens=1024)
        return {"status": "COMPLETED", "delivered": True, "candidate_commit": "fake"}

    monkeypatch.setattr(realwork, "_single_loop", attempt)
    monkeypatch.setattr(realwork, "_daedalus", attempt)
    report = realwork.run_realwork(
        tmp_path / "cycle-results",
        provider,
        max_tokens=540000,
        stop_requested=lambda: False,
        cycle={
            "study":"capability-cycle-transport-v1",
            "cases": [case],
            "phase": "development",
            "plan_sha256": "frozen",
            "monetary_admission": {"max_total_cost_cny": ceiling, "prior_cost_upper_cny": 0},
        },
    )
    assert len(calls) == expected_calls
    assert report["series_logical_calls"] == expected_calls
    assert report["status"] == ("COMPLETE" if expected_calls else "INCOMPLETE")
    if expected_calls:
        assert {r["arm"] for r in report["trials"]} == {"model", "single", "daedalus"}
        admissions = list((tmp_path/"cycle-results/monetary-admissions").glob("*.json"))
        assert len(admissions) == 3
        assert all(json.loads(p.read_text())["call_record"]["usage_available"] for p in admissions)
    else:
        assert report["stop_reason"] == "whole_study_monetary_reserve"


@pytest.mark.parametrize("fault", [None, "ledger", "reserve", "extra_unknown", "protocol"])
def test_explicit_transport_amendment_reserves_unknown_cost_without_rewriting_it(cycle, fault):
    from copy import deepcopy

    from daedalus.service.capability_budget import json_digest

    client, plan, _freeze, workspace, clients, executions = cycle
    folder = workspace.parent / "data/diagnostics/capability-cycle-20261027"
    parents = {}
    ledgers = []
    for batch in range(2):
        job = f"realwork_cycle_parent_{batch}"
        target = workspace / "realwork-evaluations" / job
        (target / "results").mkdir(parents=True)
        (target / "job.json").write_text(json.dumps({
            "job_id":job,"study":"capability-cycle-v1","status":"INCOMPLETE" if batch else "COMPLETE",
            "session_id":"old","batch_index":batch,"plan_sha256":plan["sha256"],
            "planned_case_ids":[f"old_{batch}"],
        }))
        records = [{"index":1,"usage_available":True,"prompt_tokens":100,"completion_tokens":50}]
        unknown = {"index":2,"usage_available":False,"input_digest":"unknown_digest",
                   "max_output_tokens":2048,"error_type":"IncompleteRead"}
        if batch:
            records.append(unknown)
        ledger = {"call_records":records}
        ledger_file = target/"results/series-usage.json"
        ledger_file.write_text(json.dumps(ledger))
        ledgers.append((ledger_file,ledger_file.read_bytes()))
        protocol = {"model":"deepseek-flash","inference_profile":"deepseek_bounded_json"}
        (target/"results/protocol.json").write_text(json.dumps(protocol))
        parents[job] = {"usage_sha256":json_digest(ledger),"protocol_sha256":json_digest(protocol),
                        "unknown_reservations":[{"index":2,"input_digest":"unknown_digest",
                            "reserved_cost_cny":2.25}] if batch else []}
    amendment = {"version":1,"max_cost_cny":4.5,"unknown_reserved_cost_cny":2.25,
                 "parent_jobs":parents,"batches":[deepcopy(plan["batches"][1])]}
    if fault == "ledger":
        parents["realwork_cycle_parent_1"]["usage_sha256"] = "wrong"
    elif fault == "reserve":
        parents["realwork_cycle_parent_1"]["unknown_reservations"][0]["reserved_cost_cny"] = 0
    elif fault == "extra_unknown":
        ledger_file = ledgers[1][0]
        ledger = json.loads(ledger_file.read_text())
        ledger["call_records"].append(dict(unknown,index=3))
        ledger_file.write_text(json.dumps(ledger))
        ledgers[1] = (ledger_file,ledger_file.read_bytes())
        parents["realwork_cycle_parent_1"]["usage_sha256"] = json_digest(ledger)
    elif fault == "protocol":
        (ledgers[1][0].parent/"protocol.json").write_text("{}")
    amendment["sha256"] = json_digest(amendment)
    (folder/"transport-amendment-plan.json").write_text(json.dumps(amendment))
    request = {"batch_index":0,"confirm_paid_calls":True,"protocol":"transport-amendment-v1"}
    response = client.post("/api/realwork-cycle",json=request)
    assert response.status_code == (202 if fault is None else 409)
    if fault is None:
        row = wait_finished(client,response.json()["job_id"])
        assert row["study"] == "capability-cycle-transport-v1"
        assert executions[0]["cycle"]["monetary_admission"]["prior_cost_upper_cny"] == pytest.approx(2.2512)
        assert client.post("/api/realwork-cycle",json=request).status_code == 409
        assert client.post("/api/realwork-cycle",json={"batch_index":0,"confirm_paid_calls":True}).status_code == 409
    else:
        assert not clients and not executions
    assert all(path.read_bytes() == original for path,original in ledgers)
