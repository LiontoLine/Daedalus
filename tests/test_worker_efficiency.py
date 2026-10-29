"""Mechanical waste is rejected before writes without accepting a weaker candidate."""

import hashlib
import json
from dataclasses import replace

import pytest

from daedalus.application.coding_worker import ModelWorker
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.model.base import Completion
from tests import test_capability_cycle as cycle_tests
from tests.conftest import TARGET
from tests.test_agent_investigation import context_for

cycle = cycle_tests.cycle


@pytest.mark.parametrize("operation", ["write", "replace", "cancel"])
def test_unchanged_rejected_candidate_is_not_resubmitted_or_written(
    git_repo,tmp_path,monkeypatch,operation
):
    box = GitSandbox.create(repo_path=git_repo,run_root=tmp_path/"trees",name="no-resubmit")
    try:
        box.write_file(TARGET,"already rejected candidate")
        current = box.read_file(TARGET)
        if operation == "write":
            ops = [{"op":"write","path":TARGET,"content":current}]
        elif operation == "replace":
            ops = [{"op":"replace","path":TARGET,"old_text":current,"new_text":current}]
        else:
            ops = [{"op":"write","path":TARGET,"content":"temporary"},
                   {"op":"write","path":TARGET,"content":current}]

        class Client:
            def complete(self,*args,**kwargs):
                return Completion(json.dumps({"operations":ops}),prompt_tokens=10,completion_tokens=20)

        monkeypatch.setattr(box,"write_file",lambda *a:pytest.fail("no-op batch reached a write"))
        result = ModelWorker(Client()).implement(box,context_for(box))
        assert not result.ok and result.error == "worker_no_change"
        assert result.tokens_used == 30
        assert box.read_file(TARGET) == current and box.changed_files() == (TARGET,)
    finally:
        box.remove()


def test_retry_identity_does_not_break_the_shared_source_prefix(git_repo,tmp_path):
    box = GitSandbox.create(repo_path=git_repo,run_root=tmp_path/"trees",name="prefix")
    try:
        worker = ModelWorker(None)
        context = context_for(box)
        first = worker._render(box,context)
        second = worker._render(box,replace(context,step_id="different-runtime-id",attempt=2))
        assert first.split("\nSTEP:")[0] == second.split("\nSTEP:")[0]
        assert first != second and "WRITABLE PATHS (and nothing else)" in second
    finally:
        box.remove()


def test_invalid_inspection_returns_compact_schema_feedback_without_a_tool(git_repo,tmp_path):
    box = GitSandbox.create(repo_path=git_repo,run_root=tmp_path/"trees",name="schema-feedback")
    try:
        original = box.read_file(TARGET)
        payload = {"rationale":"excessive explanation "*200,"operations":[
            {"op":"inspect","tool":"grep","query":"count","path":TARGET}
        ]}

        class Client:
            def complete(self,*args,**kwargs):
                return Completion(json.dumps(payload),prompt_tokens=10,completion_tokens=20)

        result = ModelWorker(Client(),inspection_context=lambda *a:pytest.fail("invalid tool ran")).implement(
            box,context_for(box))
        assert result.error == "invalid_edit_plan" and result.tokens_used == 30
        assert '"gap":"need the current definition"' in result.execution_log
        assert len(result.execution_log) < 700 and "excessive explanation" not in result.execution_log
        assert box.read_file(TARGET) == original
    finally:
        box.remove()


def test_baseline_bytes_are_verified_before_any_execution(tmp_path):
    from daedalus.application.realwork_workers import baseline_path, baseline_worker

    path = baseline_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("raise AssertionError('unverified code executed')")
    with pytest.raises(ValueError,match="digest"):
        baseline_worker(tmp_path,"wrong")
    path.write_text("class ModelWorker: pass\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert baseline_worker(tmp_path,digest).__name__ == "ModelWorker"
    path.write_text("raise AssertionError('changed after initial load')")
    with pytest.raises(ValueError,match="digest"):
        baseline_worker(tmp_path,digest)


@pytest.mark.parametrize("fault", [None,"parent_count","new_unknown","worker_digest","calls"])
@pytest.mark.parametrize("compact", [False,True])
def test_paired_worker_admission_carries_all_parent_ledgers_and_unknown_reserve(cycle,fault,compact):
    from daedalus.application.realwork_workers import baseline_path
    from daedalus.service.capability_budget import json_digest

    client,original,_freeze,workspace,clients,executions = cycle
    data = workspace.parent/"data"
    parents = {}
    parent_count = 6 if compact else 5
    for index in range(parent_count):
        job = f"realwork_parent_{index}"
        folder = workspace/"realwork-evaluations"/job
        (folder/"results").mkdir(parents=True)
        (folder/"job.json").write_text(json.dumps({
            "job_id":job,"study":"capability-cycle-v1" if index<2 else
            "capability-cycle-transport-v1" if index<5 else "worker-efficiency-v1",
            "status":"INCOMPLETE" if index==1 else "COMPLETE","session_id":"old",
            "planned_case_ids":[f"old_case_{index}"],
        }))
        records = [{"index":1,"usage_available":True,"prompt_tokens":100,"completion_tokens":50}]
        allowances = []
        if index==1 or (index==parent_count-1 and fault=="new_unknown"):
            records.append({"index":2,"usage_available":False,"input_digest":"unknown",
                            "max_output_tokens":2048,"error_type":"IncompleteRead"})
            if index==1:
                allowances = [{"index":2,"input_digest":"unknown","reserved_cost_cny":2.25}]
        usage = {"call_records":records}
        protocol = {"model":"deepseek-flash","inference_profile":"deepseek_bounded_json"}
        (folder/"results/series-usage.json").write_text(json.dumps(usage))
        (folder/"results/protocol.json").write_text(json.dumps(protocol))
        parents[job] = {"usage_sha256":json_digest(usage),"protocol_sha256":json_digest(protocol),
                        "unknown_reservations":allowances}
    baseline = baseline_path(data,"efficiency-v1" if compact else "poststudy")
    baseline.parent.mkdir(parents=True)
    baseline.write_text("class ModelWorker: pass\n")
    plan = {"version":1,"max_cost_cny":4.5,"unknown_reserved_cost_cny":2.25,
            "baseline_worker_sha256":hashlib.sha256(baseline.read_bytes()).hexdigest(),
            "parent_jobs":parents,"batches":[original["batches"][1]]}
    if fault=="parent_count":
        parents.pop(f"realwork_parent_{parent_count-1}")
    elif fault=="worker_digest":
        plan["baseline_worker_sha256"] = "wrong"
    plan["sha256"] = json_digest(plan)
    folder = data/"diagnostics/worker-efficiency-20261028"
    folder.mkdir(exist_ok=True)
    (folder/("compact-plan.json" if compact else "frozen-plan.json")).write_text(json.dumps(plan))
    study = "worker-efficiency-v2" if compact else "worker-efficiency-v1"
    request = {"confirm_paid_calls":True,"protocol":study,"batch_index":0,
               "max_tokens":180000 if compact else 360000,
               "max_calls":108 if fault=="calls" else 36 if compact else 72}
    response = client.post("/api/realwork-cycle",json=request)
    assert response.status_code == (202 if fault is None else 409)
    if fault is None:
        result = cycle_tests.wait_finished(client,response.json()["job_id"])
        assert result["planned_trials"] == 2 and result["study"] == study
        assert executions[0]["cycle"]["monetary_admission"]["prior_cost_upper_cny"] == pytest.approx(2.25+.0006*parent_count)
        assert client.post("/api/realwork-cycle",json=request).status_code == 409
    else:
        assert not clients and not executions


@pytest.mark.parametrize("compact", [False,True])
def test_runner_uses_both_workers_with_identical_daedalus_gates(cycle,tmp_path,monkeypatch,compact):
    from types import SimpleNamespace

    from daedalus.application import realwork
    from daedalus.application.realwork_workers import baseline_path
    from daedalus.model.base import Message

    _client,plan,_freeze,_workspace,_clients,_executions = cycle
    data = tmp_path/"runner-data"
    control = baseline_path(data,"efficiency-v1" if compact else "poststudy")
    control.parent.mkdir(parents=True)
    control.write_text(
        "class ModelWorker:\n"
        "    def __init__(self, client, **options): self.client = client\n"
    )
    digest = hashlib.sha256(control.read_bytes()).hexdigest()
    case = dict(plan["batches"][0]["cases"][0],base_commit="base",targets=["module.py"],
                archive_sha256="archive",source_chars=10)
    task = data/"tasks"/case["case"]/"task.json"
    task.parent.mkdir(parents=True)
    task.write_text("{}")
    monkeypatch.setattr(realwork,"DATA",data)
    monkeypatch.setattr(realwork,"_setup",lambda *a:(None,None,"same_tree",{}))
    monkeypatch.setattr(realwork,"_evaluate",lambda *a:{
        "public_passed":True,"heldout_passed":True,"policy_passed":True,
    })
    observed = []

    def daedalus(repo,bundle,worker,client,root,max_tokens):
        observed.append(type(worker.inner).__module__)
        worker.inner.client.complete([Message("user","bounded")],max_tokens=2048)
        return {"status":"COMPLETED","delivered":True,"candidate_commit":"candidate"}

    monkeypatch.setattr(realwork,"_daedalus",daedalus)
    monkeypatch.setattr(realwork,"_single_loop",lambda *a,**kw:pytest.fail("comparison bypassed gate pipeline"))
    provider = SimpleNamespace(model="deepseek-flash",name="offline",
        complete=lambda *a,**kw:Completion("{}",prompt_tokens=100,completion_tokens=20))
    report = realwork.run_realwork(tmp_path/"results",provider,max_tokens=360000,max_calls=72,
        stop_requested=lambda:False,
        cycle={"cases":[case],"study":"worker-efficiency-v2" if compact else "worker-efficiency-v1","phase":"development",
               "plan_sha256":"frozen","baseline_worker_sha256":digest,
               "monetary_admission":{"max_total_cost_cny":4.5,"prior_cost_upper_cny":0}})
    assert report["status"] == "COMPLETE" and report["arms"] == ("baseline","optimized")
    assert observed[0].startswith("_daedalus_worker_control_")
    assert observed[1] == "daedalus.application.coding_worker"
    assert all(r["safe_delivery"] for r in report["trials"])
