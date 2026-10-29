"""Real checkpoints and reviewed continuation; transports are offline and credential-free."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.resume import resume_run
from daedalus.application.scheduler import Quota
from daedalus.application.service_lifecycle import (
    ServiceLifecycle,
    assert_checkpoint_reviewed,
    atomic_json,
    checkpoint,
    cooperative_stop,
    review_checkpoint,
)
from daedalus.config import Settings, WorkspaceSettings
from daedalus.domain.spec import PlanNode
from daedalus.errors import DaedalusError
from daedalus.infrastructure.git_sandbox import _git
from daedalus.infrastructure.store import EventStore
from daedalus.service import control
from daedalus.service.app import create_app
from daedalus.service.dispatcher import RunDispatcher, ServiceBusy
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
from tests.test_parallel_and_rebase import _bundle

SECOND = "src/example_project/checkpoint_extra.py"


def parked_run(git_repo, tmp_path):
    store = EventStore(tmp_path / "ws" / "daedalus.db")
    signal = threading.Event()
    calls = []

    class Worker:
        name = "checkpoint-worker"

        def implement(self, sandbox, context):
            calls.append(context.node.node_id)
            if context.node.node_id == "first":
                signal.set()
                ops = (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)
            else:
                ops = (FileOp(op="write", path=SECOND, content="VALUE = 1\n"),)
            return ScriptedWorker(ops=ops).implement(sandbox, context)

    worker = Worker()
    bundle = _bundle(
        (
            PlanNode(node_id="first", objective="fix counter", expected_artifacts=(TARGET,)),
            PlanNode(
                node_id="second",
                objective="finish later",
                deps=("first",),
                expected_artifacts=(SECOND,),
            ),
        ),
        whitelist=(TARGET, SECOND),
    )
    owner = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "ws" / "worktrees",
        bundle=bundle,
        worker=worker,
        quota=Quota(max_parallel_steps=1),
    )
    owner.register_spec()
    original = _git(git_repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
    with cooperative_stop(signal):
        result = owner.run()
    assert result.status == "AWAITING_APPROVAL" and calls == ["first"]
    assert _git(git_repo, ["rev-parse", "HEAD"], check=True).stdout.strip() == original
    return store, result, worker, calls


def test_stop_keeps_first_receipt_and_human_review_resumes_only_the_frontier(git_repo, tmp_path):
    store, result, worker, calls = parked_run(git_repo, tmp_path)
    try:
        view = checkpoint(store, result.run_id)
        assert view["verified_nodes"] == ["first"]
        assert [node["node_id"] for node in view["frontier"]] == ["second"]
        assert view["review_required"] and not view["automatic_resume"] and not view["blockers"]
        with pytest.raises(DaedalusError, match="人工审查"):
            resume_run(
                store=store, run_id=result.run_id, workspace=str(tmp_path / "ws"), worker=worker
            )
        review_checkpoint(
            store,
            result.run_id,
            reviewed_by="operator",
            checkpoint_digest=view["checkpoint_digest"],
            note="first verified; proceed with second",
        )
        assert calls == ["first"], "saving a review must never dispatch work"
        resumed = resume_run(
            store=store, run_id=result.run_id, workspace=str(tmp_path / "ws"), worker=worker
        )
        assert resumed.status == "COMPLETED" and calls == ["first", "second"]
        assert (
            len(
                [
                    e
                    for e in store.events_for_execution(result.execution_id)
                    if e.event_type == "StepCommitted"
                ]
            )
            == 2
        )
        assert not store.verify_sequences() and not store.step_invariant_violations()
    finally:
        store.close()


def test_a_new_shutdown_checkpoint_invalidates_a_previous_review(git_repo, tmp_path):
    store, result, _, _ = parked_run(git_repo, tmp_path)
    try:
        view = checkpoint(store, result.run_id)
        review_checkpoint(
            store,
            result.run_id,
            reviewed_by="operator",
            checkpoint_digest=view["checkpoint_digest"],
        )
        assert_checkpoint_reviewed(store, result.run_id)
        lifecycle = ServiceLifecycle(store, tmp_path / "ws")
        assert lifecycle.describe()["reminders"]
        with pytest.raises(DaedalusError, match="人工审查"):
            assert_checkpoint_reviewed(store, result.run_id)
        with pytest.raises(DaedalusError, match="已变化"):
            review_checkpoint(
                store,
                result.run_id,
                reviewed_by="operator",
                checkpoint_digest=view["checkpoint_digest"],
            )
    finally:
        store.close()


def test_session_stops_with_verified_snapshot_and_restart_only_reminds(git_repo, tmp_path):
    store, result, _, calls = parked_run(git_repo, tmp_path)
    lifecycle = ServiceLifecycle(store, tmp_path / "ws")
    lifecycle.stopping("inspect first node after restart")
    lifecycle.stopped()
    saved = json.loads(lifecycle.path.read_text())
    assert saved["checkpoint_saved"] and Path(saved["checkpoint_snapshot"]).is_file()
    store.close()
    with EventStore(tmp_path / "ws" / "daedalus.db") as reopened:
        boot = ServiceLifecycle(reopened, tmp_path / "ws")
        assert boot.previous["note"] == "inspect first node after restart"
        assert boot.describe()["reminders"][0]["run_id"] == result.run_id
        assert reopened.get_run(result.run_id)["status"] == "AWAITING_APPROVAL"
        assert calls == ["first"]


def test_review_api_is_a_separate_manual_action_and_cannot_skip_review(git_repo, tmp_path):
    store, result, _, _ = parked_run(git_repo, tmp_path)
    store.close()
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    with TestClient(app) as client:
        assert "上次会话提醒" in client.get("/").text
        assert not app.state.daedalus.dispatcher.busy_runs()
        refused = client.post(f"/api/runs/{result.run_id}/resume")
        assert refused.status_code == 409 and refused.json()["detail"]["recovery_required"]
        view = client.get(f"/api/runs/{result.run_id}/recovery").json()
        reviewed = client.post(
            f"/api/runs/{result.run_id}/recovery-review",
            json={
                "reviewed_by": "operator",
                "checkpoint_digest": view["checkpoint_digest"],
                "note": "manual review",
            },
        )
        assert reviewed.status_code == 200 and not reviewed.json()["automatic_resume"]
        assert not app.state.daedalus.dispatcher.busy_runs()
        assert (
            client.get(f"/api/runs/{result.run_id}").json()["run"]["status"] == "AWAITING_APPROVAL"
        )


def test_dispatcher_stop_does_not_start_a_job_waiting_for_the_same_repository(tmp_path):
    settings = Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws")))
    with EventStore(settings.workspace.database_path) as store:
        dispatcher = RunDispatcher(settings=settings, store=store)
        dispatcher.start()
        started, release = threading.Event(), threading.Event()
        called = []

        def first():
            started.set()
            release.wait(5)
            from daedalus.application.orchestrator import RunResult

            return RunResult(
                run_id="first", execution_id="e", spec_digest="s", status="AWAITING_APPROVAL"
            )

        dispatcher.submit("first", str(tmp_path / "repo"), first)
        assert started.wait(3)
        dispatcher.submit("second", str(tmp_path / "repo"), lambda: called.append("second"))
        dispatcher.request_stop()
        with pytest.raises(ServiceBusy):
            dispatcher.submit("third", str(tmp_path), lambda: None)
        release.set()
        dispatcher.shutdown(wait=True)
        assert called == []


def test_unmanaged_service_and_cross_origin_control_do_not_stop_dispatcher(tmp_path):
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    with TestClient(app) as client:
        assert client.post("/api/service/control", json={"action": "stop"}).status_code == 403
        assert (
            client.post(
                "/api/service/control",
                headers={"X-Daedalus-Control": "1", "Origin": "https://external.example"},
                json={"action": "stop"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/service/control", headers={"X-Daedalus-Control": "1"}, json={"action": "stop"}
            ).status_code
            == 409
        )
        assert app.state.daedalus.dispatcher.describe()["accepting"]


def test_managed_web_restart_saves_note_and_blocks_new_jobs(tmp_path, monkeypatch):
    settings = Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws")))
    app = create_app(settings)
    state_path = settings.workspace.root_path / ".service" / "controller.json"
    atomic_json(
        state_path,
        {
            "status": "running",
            "token": "test-control-token",
            "supervisor_pid": os.getpid(),
            "backend_pid": os.getpid(),
        },
    )
    monkeypatch.setenv("DAEDALUS_SERVICE_TOKEN", "test-control-token")
    with TestClient(app) as client:
        assert client.get("/api/service").json()["control"]["managed"]
        response = client.post(
            "/api/service/control",
            headers={"X-Daedalus-Control": "1"},
            json={"action": "restart", "note": "check saved frontier after update"},
        )
        assert response.status_code == 202 and response.json()["accepted"]
        assert not app.state.daedalus.dispatcher.describe()["accepting"]
        request = control._read(state_path.with_name("request.json"))
        assert request["action"] == "restart" and request["backend_pid"] == os.getpid()
    assert (
        control._read(state_path.with_name("session.json"))["note"]
        == "check saved frontier after update"
    )


def test_enabling_identity_checks_does_not_accept_an_old_unverified_recovery_review(
    git_repo, tmp_path
):
    from daedalus.application.identity import OwnerRegistry

    store, result, _, _ = parked_run(git_repo, tmp_path)
    try:
        view = checkpoint(store, result.run_id)
        review_checkpoint(
            store,
            result.run_id,
            reviewed_by="operator",
            checkpoint_digest=view["checkpoint_digest"],
        )
        with pytest.raises(DaedalusError, match="签名"):
            assert_checkpoint_reviewed(
                store, result.run_id, identity=OwnerRegistry(store=store, required=True)
            )
    finally:
        store.close()


def test_restricted_start_never_signals_the_existing_service(tmp_path, monkeypatch):
    config = tmp_path / "console.toml"
    config.write_text(
        "[workspace]\nroot = " + json.dumps(str(tmp_path / "ws")) + "\n[service]\nport = 13499\n"
    )

    class DeniedSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def setsockopt(self, *args):
            pass

        def bind(self, *args):
            raise PermissionError("denied")

    monkeypatch.setattr(control.socket, "socket", DeniedSocket)
    monkeypatch.setattr(
        control.subprocess,
        "Popen",
        lambda *a, **k: pytest.fail("must not launch after failed bind"),
    )
    with pytest.raises(DaedalusError, match="现有服务未被停止"):
        control.command("start", config)


@pytest.mark.parametrize("signal_exit,checkpoint_ok", [(False, True), (True, True), (True, False)])
def test_supervisor_restarts_only_its_own_child_and_never_runs_tasks(
    tmp_path, signal_exit, checkpoint_ok
):
    """A real supervisor process and two disposable children; no network sockets."""
    config = tmp_path / "console.toml"
    workspace = tmp_path / "workspace"
    config.write_text("[workspace]\nroot = " + json.dumps(str(workspace)) + "\n")
    runner = tmp_path / "supervise_test.py"
    runner.write_text("""
import json,os,subprocess,sys
from pathlib import Path
from daedalus.service import control
from daedalus.application.service_lifecycle import atomic_json
config=Path(sys.argv[1]); workspace=Path(sys.argv[2]); directory=workspace/'.service'
signal_exit=sys.argv[3]=='1';checkpoint_ok=sys.argv[4]=='1'
def spawn(config,token,output):
 code="import signal,time;signal.signal(signal.SIGTERM,lambda *a:exit(0));time.sleep(60)"
 if signal_exit:
  code="import signal,time,os;signal.signal(signal.SIGTERM,lambda *a:(signal.signal(signal.SIGTERM,signal.SIG_DFL),os.kill(os.getpid(),signal.SIGTERM)));time.sleep(60)"
 return subprocess.Popen([sys.executable,'-c',code],stdout=output,stderr=output)
def health(settings,pid):
 # Readiness is controlled, but supervisor signalling/exit/restart is real.
 import time;time.sleep(.15)
 session='session-'+str(pid)
 atomic_json(directory/'session.json',{'session_id':session,'checkpoint_saved':checkpoint_ok})
 return {'process_id':pid,'service_session_id':session}
control._spawn_backend=spawn;control._health=health
raise SystemExit(control.supervise(config))
""")
    process = subprocess.Popen(
        [sys.executable, str(runner), str(config), str(workspace),
         str(int(signal_exit)), str(int(checkpoint_ok))],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    state_path = workspace / ".service" / "controller.json"

    def wait_for(predicate):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            state = control._read(state_path)
            if predicate(state):
                return state
            if process.poll() is not None:
                raise AssertionError(process.communicate()[1].decode())
            time.sleep(0.05)
        raise AssertionError(control._read(state_path))

    try:
        first = wait_for(lambda s: s.get("status") == "running")
        request = state_path.with_name("request.json")
        atomic_json(
            request, {"token": first["token"], "backend_pid": os.getpid(), "action": "restart"}
        )
        time.sleep(0.35)
        assert control._read(state_path)["backend_pid"] == first["backend_pid"]
        atomic_json(
            request,
            {"token": first["token"], "backend_pid": first["backend_pid"], "action": "restart"},
        )
        if not checkpoint_ok:
            assert process.wait(timeout=8) == 1
            state = control._read(state_path)
            assert state["status"] == "stopped" and state["generation"] == 0
            assert state["exit_code"] != 0 and not state["checkpoint_saved"]
            return
        second = wait_for(lambda s: s.get("status") == "running" and s.get("generation") == 1)
        assert second["backend_pid"] != first["backend_pid"] and not second["automatic_resume"]
        atomic_json(
            request,
            {"token": second["token"], "backend_pid": second["backend_pid"], "action": "stop"},
        )
        assert process.wait(timeout=8) == 0
        assert control._read(state_path)["status"] == "stopped"
        state = control._read(state_path)
        assert state["exit_code"] == 0 and state["checkpoint_saved"]
        assert state["raw_exit_code"] == (-15 if signal_exit else 0)
        assert not control._alive(first["backend_pid"]) and not control._alive(
            second["backend_pid"]
        )
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=8)


def test_bare_daedalus_command_enters_the_terminal_console(monkeypatch):
    from daedalus.cli import main
    from daedalus.service import terminal

    calls = []
    monkeypatch.setattr(terminal, "run_console", lambda **options: calls.append(options) or 0)
    assert main([]) == 0
    assert calls == [{"config_path": "", "open_browser": False}]
    assert main(["--config", "/tmp/explicit.toml", "--open"]) == 0
    assert calls[-1] == {"config_path": "/tmp/explicit.toml", "open_browser": True}


def test_queued_job_frontier_is_derived_without_declaring_or_starting_steps(git_repo, tmp_path):
    with EventStore(tmp_path / "ws" / "daedalus.db") as store:
        bundle = _bundle(
            (PlanNode(node_id="first", objective="fix counter", expected_artifacts=(TARGET,)),),
            whitelist=(TARGET,),
        )
        owner = RunOrchestrator(
            store=store, repo_path=git_repo, run_root=tmp_path / "ws" / "worktrees", bundle=bundle
        )
        owner.register_spec()
        owner.create_run()
        assert store.list_steps(owner.run_id) == []
        view = checkpoint(store, owner.run_id)
        assert [node["node_id"] for node in view["frontier"]] == ["first"]
        assert store.list_steps(owner.run_id) == []


def test_checkpoint_snapshot_uses_live_connection_when_original_path_has_disappeared(tmp_path):
    from daedalus.application.backup import _verify

    root = tmp_path / "workspace"
    with EventStore(root / "daedalus.db") as store:
        lifecycle = ServiceLifecycle(store, root)
        store.path.unlink()
        lifecycle.stopped()
        record = json.loads(lifecycle.path.read_text())
        assert not store.path.exists()
        assert _verify(Path(record["checkpoint_snapshot"])).verified
        assert record["checkpoint_saved"]


def test_correction_stage_cannot_resume_as_a_fresh_budget(git_repo, tmp_path):
    from daedalus.application.fsm_service import StateMachineService
    from daedalus.domain.spec import SpecBundle

    store, parent, _, _ = parked_run(git_repo, tmp_path)
    try:
        bundle = SpecBundle.from_dict(json.loads(store.get_spec(parent.spec_digest)["document"]))
        child = RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "ws" / "worktrees",
            bundle=bundle,
            target_branch=store.get_run(parent.run_id)["branch"],
            goal_stage_parent=parent.run_id,
            goal_stage_number=2,
        )
        child.create_run()
        StateMachineService(store).transition_run(
            run_id=child.run_id,
            execution_id=child.execution_id,
            event_type="RunEscalated",
            actor="operator",
            payload={"reason": "manual pause"},
        )
        assert any("stage" in reason for reason in checkpoint(store, child.run_id)["blockers"])
        with pytest.raises(DaedalusError, match="goal-audit stages"):
            resume_run(store=store, run_id=child.run_id, workspace=str(tmp_path / "ws"))
    finally:
        store.close()
