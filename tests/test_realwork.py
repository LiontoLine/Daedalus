"""Independent upstream scoring, API budget and passive read contracts."""
import json
import io
from pathlib import Path
import sys
import zipfile
from types import SimpleNamespace
import time

import pytest

from fastapi.testclient import TestClient

from daedalus.application import realwork
from daedalus.config import Settings, WorkspaceSettings
from daedalus.infrastructure.git_sandbox import _git
from daedalus.service.app import create_app
from daedalus.model.base import Message
from daedalus.errors import ModelError


@pytest.mark.parametrize("include_reproduction", [False, True])
def test_hidden_upstream_patch_is_absent_until_independent_evaluation(
    tmp_path, monkeypatch, include_reproduction
):
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    (upstream / "solution.py").write_text("def value(): return 1\n")
    (upstream / "upstream_tests.py").write_text("from solution import value\nassert value() > 0\n")
    task = {"problem_statement":"Return two", "_hidden_verifier":"../../outside.py", "test_patch":
            "diff --git a/upstream_tests.py b/upstream_tests.py\n"
            "--- a/upstream_tests.py\n+++ b/upstream_tests.py\n@@ -1,2 +1,2 @@\n"
            " from solution import value\n-assert value() > 0\n+assert value() == 2\n"}
    data = tmp_path / "data"
    task_path = data / "tasks" / "issue" / "task.json"
    task_path.parent.mkdir(parents=True)
    task_path.write_text(json.dumps(task))
    monkeypatch.setattr(realwork,"PROJECT",tmp_path)
    monkeypatch.setattr(realwork,"DATA",data)
    monkeypatch.setattr(realwork,"test_command",lambda row:[sys.executable,"upstream_tests.py"])
    row = {"case":"issue", "upstream_root":"upstream", "targets":["solution.py"]}
    if include_reproduction:
        row["public_reproduction"] = {"statement":"value must be two",
                                     "code":"from solution import value\nassert value() == 2\n"}
        # The fixed interpreter path is operator-owned; no additional dependency is installed.
        (data / "env/bin").mkdir(parents=True)
        (data / "env/bin/python").symlink_to(sys.executable)
    root = tmp_path / "trial"
    root.mkdir()
    repo,bundle,tree,frozen = realwork._setup(row,root,30000)
    before = _git(repo,["rev-parse","HEAD"],check=True).stdout.strip()
    assert "== 2" not in (repo/"upstream_tests.py").read_text()
    buggy = realwork._evaluate(repo,bundle,frozen,root,before)
    assert buggy["public_passed"] is (not include_reproduction)
    assert not buggy["heldout_passed"] and buggy["policy_passed"]
    assert "verify_issue.py" not in bundle.boundary.fs_whitelist
    assert "== 2" not in (repo/"upstream_tests.py").read_text()
    (repo/"solution.py").write_text("def value(): return 2\n")
    _git(repo,["add","solution.py"],check=True)
    _git(repo,["commit","-m","candidate"],check=True)
    candidate = _git(repo,["rev-parse","HEAD"],check=True).stdout.strip()
    # Evaluation worktree names cannot be reused, so give the second evaluation a fresh root.
    again = tmp_path / "again"
    again.mkdir()
    fixed = realwork._evaluate(repo,bundle,frozen,again,candidate)
    assert fixed["public_passed"] and fixed["heldout_passed"] and fixed["policy_passed"]
    assert fixed["changed_files"] == ["solution.py"] and tree


def test_realwork_reads_never_construct_clients_and_requests_cannot_raise_caps(tmp_path,monkeypatch):
    import daedalus.service.realwork_routes as routes
    monkeypatch.setattr(routes,"catalog",lambda:[])
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path/"workspace"))))
    calls = []
    monkeypatch.setattr(app.state.daedalus,"build_model_client",lambda role:calls.append(role))
    with TestClient(app) as client:
        for _ in range(2):
            assert client.get("/api/realwork-evaluations").json()["jobs"] == []
        assert client.post("/api/realwork-evaluations",json={}).status_code == 422
        for body in [{"max_tokens":300001},{"max_calls":145},{"repo_path":"/tmp"}]:
            assert client.post("/api/realwork-evaluations",json=body).status_code == 422
        assert client.post("/api/realwork-evaluations",json={"confirm_paid_calls":True}).status_code == 409
        assert client.get("/api/realwork-evaluations/missing").status_code == 404
        assert not calls


def test_frozen_study_receipt_prevents_any_paid_rerun(tmp_path,monkeypatch):
    import daedalus.service.realwork_routes as routes
    monkeypatch.setattr(routes,"catalog",lambda:[{"case":"x","targets":["solution.py"]}])
    workspace=tmp_path/"workspace"
    existing=workspace/"realwork-evaluations/realwork_old/job.json"
    existing.parent.mkdir(parents=True)
    existing.write_text(json.dumps({"job_id":"realwork_old","status":"RUNNING","session_id":"old"}))
    app=create_app(Settings(workspace=WorkspaceSettings(root=str(workspace))))
    calls=[]
    monkeypatch.setattr(app.state.daedalus,"build_model_client",lambda role:calls.append(role))
    with TestClient(app) as client:
        row=client.get("/api/realwork-evaluations/realwork_old").json()
        assert row["status"]=="INTERRUPTED" and row["automatic_resume"] is False
        assert client.post("/api/realwork-evaluations",json={"confirm_paid_calls":True}).status_code==409
        assert not calls


def test_stopped_evidence_api_exports_only_allowed_files(tmp_path,monkeypatch):
    import daedalus.service.realwork_routes as routes
    monkeypatch.setattr(routes,"catalog",lambda:[])
    workspace=tmp_path/"workspace"
    job=workspace/"realwork-evaluations/realwork_study"
    results=job/"results"
    results.mkdir(parents=True)
    (job/"job.json").write_text(json.dumps({"status":"COMPLETE","session_id":"old"}))
    (results/"report.json").write_text(json.dumps({"trials":[]}))
    (results/"private-credential.txt").write_text("must-never-be-exported")
    app=create_app(Settings(workspace=WorkspaceSettings(root=str(workspace))))
    with TestClient(app) as client:
        response=client.get("/api/realwork-evaluations/realwork_study/artifacts/evidence.zip")
        assert response.status_code==200
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            assert archive.namelist()==["report.json"]


def test_budget_phase_only_admits_never_dispatched_arms_once(tmp_path,monkeypatch):
    import daedalus.service.realwork_routes as routes
    monkeypatch.setattr(routes,"catalog",lambda:[{"case":"x","targets":["solution.py"]}])
    workspace=tmp_path/"workspace"
    prior=workspace/"realwork-evaluations/realwork_initial"
    (prior/"results").mkdir(parents=True)
    (prior/"job.json").write_text(json.dumps({"job_id":"realwork_initial","status":"INCOMPLETE","session_id":"old"}))
    (prior/"results/report.json").write_text(json.dumps({"protocol_sha256":"frozen","trials":[{"case":"x","arm":"model","dispatched_model_calls":1}]}))
    (prior/"results/series-usage.json").write_text(json.dumps({"call_records":[{"usage_available":True,"prompt_tokens":100,"completion_tokens":50}]}))
    app=create_app(Settings(workspace=WorkspaceSettings(root=str(workspace))))
    model=SimpleNamespace(model="deepseek-flash",for_profile=lambda _:SimpleNamespace(model="deepseek-flash"))
    monkeypatch.setattr(app.state.daedalus,"build_model_client",lambda role:model)
    observed=[]

    def execute(destination,client,**kwargs):
        observed.append(kwargs)
        return {"status":"COMPLETE","series_reported_tokens":0,"series_logical_calls":0}

    monkeypatch.setattr(routes,"run_realwork",execute)
    with TestClient(app) as client:
        response=client.post("/api/realwork-evaluations/remaining",json={"confirm_paid_calls":True})
        assert response.status_code==202
        deadline=time.monotonic()+5
        while not observed and time.monotonic()<deadline:time.sleep(.01)
        context=observed[0]["continuation"]
        assert context["remaining_keys"]==[("x","single"),("x","daedalus")]
        assert context["max_total_cost_cny"]==3 and context["prior_cost_upper_cny"]==.0006
        assert client.post("/api/realwork-evaluations/remaining",json={"confirm_paid_calls":True}).status_code==409


def test_monetary_guard_refuses_before_actual_provider_dispatch(tmp_path,monkeypatch):
    data=tmp_path/"data"
    task=data/"tasks/x/task.json"
    task.parent.mkdir(parents=True)
    task.write_text("{}")
    evidence=tmp_path/"evidence"
    evidence.mkdir()
    (evidence/"selection-rule.json").write_text("{}")
    monkeypatch.setattr(realwork,"DATA",data)
    monkeypatch.setattr(realwork,"EVIDENCE",evidence)
    case={"case":"x","base_commit":"a","targets":["solution.py"],"labels":["tests"],"archive_sha256":"b","source_chars":1}
    monkeypatch.setattr(realwork,"catalog",lambda:[case])
    monkeypatch.setattr(realwork,"_setup",lambda *args:(None,None,"tree",{}))
    monkeypatch.setattr(realwork,"_evaluate",lambda *args:{})
    dispatch=[]
    client=SimpleNamespace(model="deepseek-flash",name="fake",complete=lambda *args,**kwargs:dispatch.append(True))

    def attempt(repo,bundle,worker,root,max_tokens,**options):
        try:worker.inner.client.complete([Message("user","bounded prompt")],max_tokens=1024)
        except ModelError:pass
        return {"status":"FAILED","delivered":False,"candidate_commit":"fake"}

    monkeypatch.setattr(realwork,"_single_loop",attempt)
    report=realwork.run_realwork(tmp_path/"results",client,stop_requested=lambda:False,
        continuation={"remaining_keys":[["x","model"]],"prior_cost_upper_cny":2.999,"max_total_cost_cny":3.0})
    assert not dispatch and report["series_logical_calls"]==0
    assert report["stop_reason"]=="whole_study_monetary_reserve" and report["status"]=="INCOMPLETE"


def test_provider_export_is_read_only_and_filters_labels(tmp_path,monkeypatch):
    import daedalus.service.realwork_routes as routes
    monkeypatch.setattr(routes,"catalog",lambda:[])
    workspace=tmp_path/"workspace"
    folder=workspace/"realwork-evaluations/realwork_stopped"
    folder.mkdir(parents=True)
    (folder/"job.json").write_text(json.dumps({"status":"COMPLETE","session_id":"old","started_at":"2000","finished_at":"2100"}))
    app=create_app(Settings(workspace=WorkspaceSettings(root=str(workspace))))
    state=app.state.daedalus
    state.store.record_metric(name="provider_attempts",value=1,labels={"role":"coder","request_id":"example","unrelated":"must-not-export"})
    state.store.record_metric(name="unrelated_metric",value=999)
    with TestClient(app) as client:
        response=client.get("/api/realwork-evaluations/realwork_stopped/artifacts/provider-metrics.json")
        assert response.status_code==200
        assert len(response.json())==1 and response.json()[0]["value"]==1
        assert response.json()[0]["labels"]=={"role":"coder","request_id":"example"}


def test_optimization_refuses_prior_cases_or_duplicate_receipts_before_model(tmp_path, monkeypatch):
    import daedalus.service.realwork_routes as routes
    fresh_dir = tmp_path / "docs/failure_optimization_2026-10-27"
    fresh_dir.mkdir(parents=True)
    (fresh_dir / "cases.json").write_text(json.dumps([{"case":"old"}]))
    monkeypatch.setattr(realwork, "PROJECT", tmp_path)
    monkeypatch.setattr(routes, "catalog", lambda:[{"case":"old"}])
    workspace = tmp_path / "workspace"
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(workspace))))
    calls = []
    monkeypatch.setattr(app.state.daedalus, "build_model_client", lambda role:calls.append(role))
    with TestClient(app) as client:
        assert client.post("/api/realwork-optimization", json={}).status_code == 422
        assert client.post("/api/realwork-optimization", json={"confirm_paid_calls":True}).status_code == 409
        (fresh_dir / "cases.json").write_text(json.dumps([{"case":"new"}]))
        existing = workspace / "realwork-evaluations/realwork_opt_old"
        existing.mkdir(parents=True)
        (existing / "job.json").write_text("{}")
        assert client.post("/api/realwork-optimization", json={"confirm_paid_calls":True}).status_code == 409
        assert calls == []


def test_optimization_money_guard_never_dispatches_unaffordable_prompt(tmp_path, monkeypatch):
    project = tmp_path / "project"
    fresh = project / "docs/failure_optimization_2026-10-27"
    fresh.mkdir(parents=True)
    case = {"case":"new", "base_commit":"a", "targets":["solution.py"],
            "labels":["tests"], "archive_sha256":"b", "source_chars":1}
    (fresh / "cases.json").write_text(json.dumps([case]))
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "selection-rule.json").write_text("{}")
    task = tmp_path / "data/tasks/new/task.json"
    task.parent.mkdir(parents=True)
    task.write_text("{}")
    monkeypatch.setattr(realwork,"PROJECT",project)
    monkeypatch.setattr(realwork,"EVIDENCE",evidence)
    monkeypatch.setattr(realwork,"DATA",tmp_path / "data")
    monkeypatch.setattr(realwork,"_setup",lambda *args:(None,None,"tree",{}))
    monkeypatch.setattr(realwork,"_evaluate",lambda *args:{})
    dispatched = []
    fake = SimpleNamespace(model="deepseek-flash", name="offline", complete=lambda *a,**k:dispatched.append(True))

    def attempt(repo,bundle,worker,root,max_tokens,**options):
        assert worker.inner.review_headroom_tokens == 8192
        try:
            worker.inner.client.inner.complete([Message("user", "x" * 330000)], max_tokens=1024)
        except ModelError:
            pass
        return {"status":"FAILED", "delivered":False, "candidate_commit":"fake"}

    monkeypatch.setattr(realwork,"_single_loop",attempt)
    report = realwork.run_realwork(tmp_path/"result",fake,stop_requested=lambda:False,optimization=True)
    assert not dispatched and report["status"] == "INCOMPLETE"
    assert report["stop_reason"] == "whole_study_monetary_reserve"


def test_contract_check_uses_only_unspent_existing_cap_and_never_reopens(tmp_path,monkeypatch):
    import daedalus.service.realwork_routes as routes
    from daedalus.application.upstream_contract import compile_contract
    workspace=tmp_path/"workspace"
    prior=workspace/"realwork-evaluations/realwork_opt_one"
    (prior/"results").mkdir(parents=True)
    (prior/"job.json").write_text(json.dumps({"job_id":"realwork_opt_one","status":"COMPLETE","session_id":"old"}))
    (prior/"results/report.json").write_text(json.dumps({"trials":[]}))
    (prior/"results/series-usage.json").write_text(json.dumps({"call_records":[
        {"usage_available":True,"prompt_tokens":10,"completion_tokens":5}]}))
    data=tmp_path/"data"
    (data/"diagnostics").mkdir(parents=True)
    (tmp_path/"module.py").write_text("class Class:\n    def test_one(self): pass\n")
    contract=compile_contract({"repo":"django/django","PASS_TO_PASS":["test_one (module.Class)"],
                               "FAIL_TO_PASS":["test_other (module.Class)"]},["module"],tmp_path)
    row={"case":"fresh","repo":"django/django","labels":["module"],"test_contract":contract,
         "contract_qualification":{name:{"passed":True,"tests":1,"complete":True,"executed":1,"evidence_kind":"native_runner_counters"}
             for name in ["public_original","public_reference","hidden_reference"]}}
    row["contract_qualification"]["hidden_original"]={"passed":False,"complete":True,"executed":1,"evidence_kind":"native_runner_counters"}
    (data/"diagnostics/fresh-smoke-cases.json").write_text(json.dumps([row]))
    monkeypatch.setattr(routes,"DATA",data)
    app=create_app(Settings(workspace=WorkspaceSettings(root=str(workspace))))
    model=SimpleNamespace(model="deepseek-flash",for_profile=lambda _:SimpleNamespace(model="deepseek-flash"))
    clients=[]
    monkeypatch.setattr(app.state.daedalus,"build_model_client",lambda role:(clients.append(role),model)[1])
    observed=[]
    def execute(*args,**kwargs):
        observed.append(kwargs)
        return {"status":"COMPLETE","series_reported_tokens":0,"series_logical_calls":0}
    monkeypatch.setattr(routes,"run_realwork",execute)
    with TestClient(app) as client:
        assert client.post("/api/realwork-contract-check",json={"max_cost_cny":5}).status_code==422
        invalid=json.loads(json.dumps(row))
        invalid["contract_qualification"]["hidden_original"].pop("complete")
        (data/"diagnostics/fresh-smoke-cases.json").write_text(json.dumps([invalid]))
        assert client.post("/api/realwork-contract-check",json={"confirm_paid_calls":True}).status_code==409
        assert not clients and not observed
        (data/"diagnostics/fresh-smoke-cases.json").write_text(json.dumps([row]))
        result=client.post("/api/realwork-contract-check",json={"confirm_paid_calls":True})
        assert result.status_code==202 and result.json()["automatic_resume"] is False
        deadline=time.monotonic()+5
        while not observed and time.monotonic()<deadline:time.sleep(.01)
        assert observed[0]["contract_smoke"]["max_total_cost_cny"]==.65
        assert observed[0]["contract_smoke"]["prior_cost_upper_cny"]==.00006
        assert observed[0]["max_calls"]==12 and observed[0]["max_tokens"]==60000
        assert client.post("/api/realwork-contract-check",json={"confirm_paid_calls":True}).status_code==409
