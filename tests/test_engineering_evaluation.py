"""Fixed engineering suite, strong baselines, bounded jobs and safe rendered metrics."""

import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from daedalus.application.benchmark import run_comparison
from daedalus.application.engineering_cases import ENGINEERING_CASES
from daedalus.config import Settings, WorkspaceSettings
from daedalus.service.app import create_app


def test_three_arms_share_the_same_tree_and_all_reference_deliveries_are_scored(tmp_path):
    report = run_comparison(
        tmp_path / "results",
        mode="controlled",
        repeats=1,
        arms=("model", "single", "daedalus"),
        cases=ENGINEERING_CASES[:1],
    )
    assert report["status"] == "COMPLETE" and len(report["trials"]) == 3
    assert len({r["initial_tree"] for r in report["trials"]}) == 1
    assert all(
        r["safe_delivery"] and r["public_passed"] and r["heldout_passed"] for r in report["trials"]
    )
    assert set(report["summary"]) == {"model", "single", "daedalus"}
    assert report["summary"]["daedalus"]["quality_trials"] == 1
    assert report["real_model_completions"] == 0


def test_stop_request_prevents_every_model_or_worker_dispatch(tmp_path):
    report = run_comparison(
        tmp_path / "stopped",
        mode="controlled",
        repeats=1,
        arms=("model", "single", "daedalus"),
        cases=ENGINEERING_CASES[:1],
        stop_requested=lambda: True,
    )
    assert report["status"] == "INTERRUPTED" and report["trials"] == []
    assert all(r["scheduled_trials"] == 1 for r in report["summary"].values())


def test_job_api_uses_saved_profile_and_serves_only_fixed_artifacts(tmp_path, monkeypatch):
    import daedalus.service.engineering_routes as routes

    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "workspace"))))
    calls = []
    monkeypatch.setattr(
        app.state.daedalus,
        "build_model_client",
        lambda role: calls.append(role) or SimpleNamespace(model="offline", name="offline"),
    )

    def controlled(destination, **kwargs):
        kwargs.update(mode="controlled", client_factory=None)
        return run_comparison(destination, **kwargs)

    monkeypatch.setattr(routes, "run_comparison", controlled)
    with TestClient(app) as client:
        catalog = client.get("/api/engineering-evaluations").json()
        assert len(catalog["cases"]) == 6 and calls == []
        assert "heldout" not in json.dumps(catalog) and "answer" not in json.dumps(catalog)
        for body in [
            {"cases": ["config_migration", "config_migration"]},
            {"repo_path": "/private"},
            {"series_tokens": 300001},
        ]:
            assert client.post("/api/engineering-evaluations", json=body).status_code == 422
        assert calls == []
        response = client.post("/api/engineering-evaluations", json={"cases": ["api_pagination"]})
        assert response.status_code == 202 and calls == ["coder"]
        job_id = response.json()["job_id"]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            row = client.get(f"/api/engineering-evaluations/{job_id}").json()
            if row["status"] not in {"QUEUED", "RUNNING"}:
                break
            time.sleep(0.05)
        else:
            pytest.fail("bounded engineering job did not finish")
        row = client.get(f"/api/engineering-evaluations/{job_id}").json()
        assert row["status"] == "COMPLETE" and len(row["report"]["trials"]) == 3
        assert row["series_logical_calls"] == 0 and not row["automatic_resume"]
        assert (
            client.get(f"/api/engineering-evaluations/{job_id}/artifacts/report.json").status_code
            == 200
        )
        assert (
            client.get(
                f"/api/engineering-evaluations/{job_id}/artifacts/credential.json"
            ).status_code
            == 422
        )
        state = app.state.daedalus
        state.lifecycle.session_id = "different-session"
        # Completed records remain complete; only unfinished previous jobs become interrupted.
        assert client.get(f"/api/engineering-evaluations/{job_id}").json()["status"] == "COMPLETE"


def test_engineering_renderer_handles_unknown_usage_and_hostile_labels():
    source = Path(__file__).parents[1] / "src/daedalus/service/static/engineering.js"
    script = r"""
const fs=require('fs'),vm=require('vm'),a=require('assert');
const window={},handlers={};
vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),{window,document:{addEventListener:(n,f)=>handlers[n]=f}});
const ui=window.DaedalusEngineering;
const output=ui.render({request:{cases:['x']},progress:[{case:'<img src=x>',arm:'single',status:'<script>x</script>',tokens:null,model_calls:2,call_records:[{usage_available:true,prompt_tokens:10,completion_tokens:2},{usage_available:false}],wall_seconds:1}]});
a(!output.table.includes('<img')&&!output.table.includes('<script>'));
a(output.table.includes('&lt;img')&&output.table.includes('12 + 未知'));
a(output.cards.includes('用量部分未知')&&output.count===1&&output.total===3);
const empty=ui.render(null,[{key:'x'}]);a(empty.count===0&&empty.cards.includes('待测 1'));
const stopped=ui.render({request:{cases:['x']},progress:[{case:'x',arm:'model',status:'FAILED',tokens:null,dispatched_model_calls:0,call_records:[{request_dispatched:false}],model_calls:1}]});
a(stopped.table.includes('未派发')&&!stopped.table.includes(' + 未知'));
a(!stopped.cards.includes('用量部分未知')&&stopped.cards.includes('次逻辑调用'));
"""
    subprocess.run(["node", "-e", script, str(source)], check=True, capture_output=True, text=True)


def test_job_specific_cancel_prevents_later_work_without_stopping_backend(tmp_path, monkeypatch):
    import threading

    import daedalus.service.engineering_routes as routes

    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "workspace"))))
    monkeypatch.setattr(
        app.state.daedalus,
        "build_model_client",
        lambda role: SimpleNamespace(model="offline", name="offline"),
    )
    started = threading.Event()

    def waiting(destination, **kwargs):
        assert kwargs["series_limits"]["max_calls"] == 17
        started.set()
        deadline = time.monotonic() + 5
        while not kwargs["stop_requested"]():
            if time.monotonic() > deadline:
                raise AssertionError("cancel signal did not arrive")
            time.sleep(0.01)
        return {"status": "INTERRUPTED"}

    monkeypatch.setattr(routes, "run_comparison", waiting)
    with TestClient(app) as client:
        response = client.post(
            "/api/engineering-evaluations", json={"cases": ["api_pagination"], "series_calls": 17}
        )
        assert response.status_code == 202 and started.wait(5)
        job_id = response.json()["job_id"]
        assert client.post("/api/engineering-evaluations", json={}).status_code == 409
        assert (
            client.post(f"/api/engineering-evaluations/{job_id}/cancel", json={}).status_code == 202
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            row = client.get(f"/api/engineering-evaluations/{job_id}").json()
            if row["status"] == "INTERRUPTED":
                break
            time.sleep(0.02)
        assert row["status"] == "INTERRUPTED" and row["cancellation_requested"]
        assert row["series_logical_calls"] == 0
        assert client.get("/api/health").status_code == 200
        assert (
            client.post(f"/api/engineering-evaluations/{job_id}/cancel", json={}).status_code == 409
        )
