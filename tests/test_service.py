"""The service and console (Spec §15, §10).

These tests drive the real ASGI application through a real HTTP client, so routing, status
codes, error mapping and the same-origin console are all exercised rather than assumed.

The properties under test:

* a run is **accepted durably** and executed on a bounded pool, not synchronously;
* the read surface is a projection of the event store and never a second source of truth;
* every command goes through the same service the CLI uses;
* domain errors become meaningful HTTP statuses, not opaque 500s;
* the console renders the escalation with the answer controls attached.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.fsm_service import StateMachineService
from daedalus.config import Settings, load_settings, write_example_config
from daedalus.domain.approval import ApprovalDecision
from daedalus.domain.fsm import RunState
from daedalus.infrastructure.git_sandbox import GitSandbox, init_repo, initial_commit
from daedalus.infrastructure.store import EventStore
from daedalus.service.app import ServiceState, create_app
from daedalus.service.dispatcher import RunDispatcher, ServiceBusy
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND


def _repo(tmp_path: Path) -> Path:
    """A target repository, built the same way the demo builds one."""
    from tests.conftest import DEMO_PROJECT

    repo = init_repo(tmp_path / "repo")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".DS_Store")
    shutil.copytree(DEMO_PROJECT / "src", repo / "src", ignore=ignore)
    shutil.copytree(DEMO_PROJECT / "tests", repo / "tests", ignore=ignore)
    shutil.copy2(DEMO_PROJECT / "pyproject.toml", repo / "pyproject.toml")
    shutil.copy2(DEMO_PROJECT / ".gitignore", repo / ".gitignore")
    initial_commit(repo, "chore: import the demo project")
    return repo


@pytest.fixture()
def service(tmp_path: Path):
    settings = load_settings(None, workspace_root=str(tmp_path / "ws"))
    app = create_app(settings)
    with TestClient(app) as client:
        yield client, app.state.daedalus, settings


def _wait_for(
    client: TestClient,
    run_id: str,
    *,
    terminal: set[str],
    timeout: float = 90.0,
    must_leave: str = "",
):
    """Poll until the run reaches one of the expected statuses, with the dispatcher idle.

    Two phases, because one is not enough. A queued resume returns 202 before the pool picks the
    job up, so for a moment the run is still `AWAITING_APPROVAL` *and* not active — and a single
    phase would treat that as a settled result. `must_leave` names the status the job has to
    move out of, so the wait cannot return before the work it is waiting for has begun.
    """
    deadline = time.monotonic() + timeout
    status = ""

    if must_leave:
        moved = False
        while time.monotonic() < deadline:
            detail = client.get(f"/api/runs/{run_id}").json()
            if detail.get("active") or detail["run"]["status"] != must_leave:
                moved = True
                break
            time.sleep(0.05)
        if not moved:
            raise AssertionError(
                f"run {run_id} never left {must_leave!r}: the queued job did not start"
            )

    seen_active = False
    while time.monotonic() < deadline:
        detail = client.get(f"/api/runs/{run_id}").json()
        status = detail["run"]["status"]
        active = bool(detail.get("active"))
        seen_active = seen_active or active
        if status in terminal and not active:
            return status
        time.sleep(0.2)
    raise AssertionError(
        f"run {run_id} stayed {status!r} (active={seen_active}); "
        f"expected one of {sorted(terminal)} with the dispatcher idle"
    )


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


def test_health_reports_the_workspace_and_dispatcher(service) -> None:
    client, _state, settings = service
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["database"] == str(settings.workspace.database_path)
    assert body["dispatcher"]["max_concurrent_runs"] == settings.service.max_concurrent_runs
    assert body["startup_findings"] == 0


def test_config_endpoint_never_returns_a_credential(tmp_path, monkeypatch) -> None:
    config = write_example_config(tmp_path / "daedalus.toml")
    settings = load_settings(config, workspace_root=str(tmp_path / "wsc"))
    monkeypatch.setenv("DAEDALUS_MODEL_API_KEY", "sk-abcdefghijklmnopqrstuvwxyz012345")
    with TestClient(create_app(settings)) as client:
        body = client.get("/api/config").json()
        rendered = json.dumps(body)
    assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in rendered
    assert body["providers"]["coder"]["key_present"] is True
    assert body["providers"]["coder"]["api_key_env"] == "DAEDALUS_MODEL_API_KEY"


def test_meta_spec_is_readable_so_the_boundary_is_inspectable(service) -> None:
    client, _state, _settings = service
    meta = client.get("/api/meta-spec").json()
    assert meta["allow_gatekeeper_self_modification"] is False
    assert meta["protected_paths"]
    assert "gatekeeper" in meta["human_approval_required"]


# ---------------------------------------------------------------------------
# Submitting and observing runs
# ---------------------------------------------------------------------------


def test_a_run_is_accepted_and_then_executed(service, tmp_path) -> None:
    client, state, _settings = service
    repo = _repo(tmp_path)
    # Replace the worker factory so the run uses the scripted worker: the service API is
    # what is under test here, not the model transport.
    state.build_worker = lambda *, use_model, enable_review, budget=None, repo_path="": (  # type: ignore[assignment]
        ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="w-service",
        ),
        None,
    )

    response = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "make summarize() count words",
            "goal_id": "GOAL-SVC",
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
        },
    )
    assert response.status_code == 202, response.text
    receipt = response.json()
    assert receipt["accepted"] is True
    assert receipt["run_id"]
    assert receipt["spec_digest"]

    status = _wait_for(client, receipt["run_id"], terminal={"COMPLETED", "FAILED", "PARTIAL_FAILURE"})
    assert status == "COMPLETED"

    detail = client.get(f"/api/runs/{receipt['run_id']}").json()
    assert detail["run"]["status"] == "COMPLETED"
    assert detail["steps"][0]["state"] == "COMMITTED"
    assert detail["steps"][0]["artifacts"], "a committed step must have an artifact"
    assert detail["timeline"], "the timeline must be projected"
    goal_audit = client.get(f"/api/runs/{receipt['run_id']}/goal-audit").json()
    assert goal_audit["enabled"] and goal_audit["status"] == "APPROVE"
    assert goal_audit["stages"][0]["scope"] == "acceptance_only"
    audit = client.get(f"/api/runs/{receipt['run_id']}/audit").json()
    assert audit["goal_audit"] == goal_audit
    task = next(run for run in client.get("/api/runs").json()["runs"] if run["run_id"] == receipt["run_id"])
    assert task["objective"] == "make summarize() count words"
    workspace = client.get(f"/execution/{receipt['run_id']}").text
    assert f'data-run-id="{receipt["run_id"]}"' in workspace
    assert 'data-page="workflow"' in workspace
    assert 'href="#flow-plan"' in workspace
    assert 'href="#flow-audit"' in workspace
    # And the commit really landed.
    from daedalus.infrastructure.git_sandbox import _git

    assert _git(repo, ["log", "--oneline", "-1"], check=True).stdout.strip()


def test_submitting_to_a_directory_that_is_not_a_repository_is_a_400(service, tmp_path) -> None:
    client, _state, _settings = service
    response = client.post(
        "/api/runs",
        json={
            "repo_path": str(tmp_path / "not-a-repo"),
            "objective": "do something",
            "target_paths": ["a.py"],
            "test_command": "true",
        },
    )
    assert response.status_code == 400
    assert "not a Git repository" in response.json()["detail"]


def test_an_unknown_run_is_a_404(service) -> None:
    client, _state, _settings = service
    assert client.get("/api/runs/does-not-exist").status_code == 404
    assert client.get("/api/runs/does-not-exist/audit").status_code == 404


def test_the_run_list_is_a_projection(service, tmp_path) -> None:
    client, state, _settings = service
    repo = _repo(tmp_path)
    state.build_worker = lambda *, use_model, enable_review, budget=None, repo_path="": (  # type: ignore[assignment]
        ScriptedWorker(ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)),
        None,
    )
    receipt = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "fix it",
            "goal_id": "GOAL-LIST",
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
        },
    ).json()
    _wait_for(client, receipt["run_id"], terminal={"COMPLETED", "FAILED", "PARTIAL_FAILURE"})

    listing = client.get("/api/runs").json()["runs"]
    assert len(listing) == 1
    assert listing[0]["goal_id"] == "GOAL-LIST"
    assert listing[0]["steps"].get("COMMITTED") == 1
    assert len(listing[0]["spec_digest"]) == 12


def test_metrics_are_exposed(service) -> None:
    client, _state, _settings = service
    metrics = client.get("/api/metrics").json()
    assert "step_total" in metrics
    assert "event_count" in metrics


# ---------------------------------------------------------------------------
# Escalation through HTTP
# ---------------------------------------------------------------------------


def test_escalation_is_listed_approved_and_resumed_over_http(service, tmp_path) -> None:
    """The full operator journey, driven only through the API."""
    client, state, _settings = service
    repo = _repo(tmp_path)

    # Park a run directly through the service's own state, using an escalating reviewer.
    from daedalus.application.gatekeeper.tier2 import Tier2Gate
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from daedalus.application.scheduler import Quota
    from daedalus.domain.spec import NetworkPolicy, RiskLevel

    class Escalating:
        def complete(self, prompt: str, *, subject_digest: str) -> str:
            return json.dumps(
                {
                    "decision": "ESCALATE",
                    "subject_digest": subject_digest,
                    "reasons": ["needs a human"],
                    "violations": [],
                    "confidence": 0.4,
                }
            )

    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="R",
            goal_id="GOAL-ESC",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    orchestrator = RunOrchestrator(
        store=state.store,
        repo_path=repo,
        run_root=state.settings.workspace.worktrees_path,
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),), worker_id="w"
        ),
        tier2=Tier2Gate(reviewer=Escalating()),
        quota=Quota(max_parallel_steps=1),
        park_on_escalation=True,
    )
    orchestrator.register_spec()
    parked = orchestrator.run()
    assert parked.status == RunState.AWAITING_APPROVAL.value

    # The operator sees it.
    escalations = client.get("/api/escalations").json()["escalations"]
    assert len(escalations) == 1
    item = escalations[0]
    assert item["run_id"] == parked.run_id
    assert item["artifact_digest"]

    # Approving without naming anyone is refused.
    bad = client.post(
        f"/api/runs/{parked.run_id}/approve",
        json={"step": item["step_id"], "decision": "proceed", "approved_by": "  "},
    )
    assert bad.status_code == 400
    assert "who gave it" in json.dumps(bad.json())

    # A well-formed approval is accepted and the escalation clears.
    ok = client.post(
        f"/api/runs/{parked.run_id}/approve",
        json={
            "step": item["step_id"],
            "decision": "proceed",
            "approved_by": "operator@example",
            "note": "reviewed the diff by hand",
        },
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["approved_by"] == "operator@example"
    assert client.get("/api/escalations").json()["escalations"] == []

    # Resume runs on the bounded pool and lands the commit.
    resumed = client.post(f"/api/runs/{parked.run_id}/resume")
    assert resumed.status_code == 202, resumed.text
    # `must_leave` closes the race between the 202 and the pool picking the job up.
    status = _wait_for(
        client,
        parked.run_id,
        terminal={"COMPLETED", "FAILED"},
        must_leave="AWAITING_APPROVAL",
    )
    assert status == "COMPLETED"

    audit = client.get(f"/api/runs/{parked.run_id}/audit").json()
    assert audit["approvals"] and audit["approvals"][0]["approved_by"] == "operator@example"
    assert audit["commits"][0]["owner_override"] is True
    assert audit["commits"][0]["approved_by"] == "operator@example"


def test_approving_a_step_that_is_not_escalated_is_a_400(service, tmp_path) -> None:
    client, state, _settings = service
    repo = _repo(tmp_path)
    state.build_worker = lambda *, use_model, enable_review, budget=None, repo_path="": (  # type: ignore[assignment]
        ScriptedWorker(ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)),
        None,
    )
    receipt = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "fix it",
            "goal_id": "GOAL-NE",
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
        },
    ).json()
    _wait_for(client, receipt["run_id"], terminal={"COMPLETED", "FAILED", "PARTIAL_FAILURE"})

    detail = client.get(f"/api/runs/{receipt['run_id']}").json()
    step_id = detail["steps"][0]["step_id"]
    response = client.post(
        f"/api/runs/{receipt['run_id']}/approve",
        json={"step": step_id, "decision": "proceed", "approved_by": "alice"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "not_escalated"


# ---------------------------------------------------------------------------
# High-risk spec sign-off
# ---------------------------------------------------------------------------


def test_a_high_risk_run_requires_a_spec_signoff(service, tmp_path) -> None:
    client, state, _settings = service
    repo = _repo(tmp_path)
    state.build_worker = lambda *, use_model, enable_review, budget=None, repo_path="": (  # type: ignore[assignment]
        ScriptedWorker(ops=(), worker_id="w"), None
    )

    without = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "risky change",
            "goal_id": "GOAL-RISK",
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
            "risk_level": "critical",
        },
    )
    # 428 Precondition Required, synchronously: a 202 that later turns out to have been
    # unsignable would be a worse answer than an immediate refusal.
    assert without.status_code == 428, without.text
    assert without.json()["error"]["code"] == "spec_approval_required"
    assert client.get("/api/runs").json()["runs"] == [], "a refused run must not be created"

    with_signoff = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "risky change",
            "goal_id": "GOAL-RISK",
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
            "risk_level": "critical",
            "approve_spec_by": "alice",
        },
    )
    # New high-risk runs require verified approval even in an unenrolled workspace.
    assert with_signoff.status_code == 409, with_signoff.text
    assert with_signoff.json()["error"]["code"] == "identity_required"
    assert client.get("/api/runs").json()["runs"] == []


def test_approving_an_unknown_spec_is_a_404(service) -> None:
    client, _state, _settings = service
    assert client.post("/api/specs/deadbeef/approve", json={"approved_by": "a"}).status_code == 404


# ---------------------------------------------------------------------------
# Operations through HTTP
# ---------------------------------------------------------------------------


def test_recover_reports_and_repairs(service) -> None:
    client, _state, _settings = service
    dry = client.post("/api/recover?apply=false").json()
    assert dry["findings"] == 0
    applied = client.post("/api/recover?apply=true").json()
    assert applied["repaired"] == 0


def test_backup_and_list_over_http(service) -> None:
    client, state, settings = service
    # Put something in the store so the snapshot is not empty.
    state.store.append(
        aggregate_id="run:probe",
        execution_id="exec-probe",
        event_type="RunStarted",
        actor="test",
        payload={},
    )
    created = client.post("/api/backup?label=http").json()
    assert created["verified"] is True
    assert created["integrity"] == "ok"
    listed = client.get("/api/backups").json()["backups"]
    assert len(listed) == 1
    assert listed[0]["verified"] is True


def test_restore_refuses_a_bad_source_with_a_409(service, tmp_path) -> None:
    client, _state, _settings = service
    bad = tmp_path / "nope"
    bad.write_text("not a database", encoding="utf-8")
    response = client.post("/api/restore", json={"source": str(bad), "force": True})
    assert response.status_code == 409


def test_rollback_over_http_records_a_rollback(service, tmp_path) -> None:
    client, state, _settings = service
    repo = _repo(tmp_path)
    state.build_worker = lambda *, use_model, enable_review, budget=None, repo_path="": (  # type: ignore[assignment]
        ScriptedWorker(ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)),
        None,
    )
    receipt = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "fix it",
            "goal_id": "GOAL-RB",
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
        },
    ).json()
    _wait_for(client, receipt["run_id"], terminal={"COMPLETED", "FAILED", "PARTIAL_FAILURE"})

    before = GitSandbox.main_commit(repo)
    result = client.post(
        f"/api/runs/{receipt['run_id']}/rollback",
        json={"reason": "a regression was found"},
    )
    assert result.status_code == 200
    body = result.json()
    assert body["status"] == RunState.CANCELLED.value
    assert GitSandbox.main_commit(repo) == before, "rollback must not move the target branch"
    assert "email" in " ".join(body["not_rolled_back"])

    # Rolling back twice is a refusal with a domain code.
    again = client.post(
        f"/api/runs/{receipt['run_id']}/rollback", json={"reason": "again"}
    )
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "not_rollbackable"


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------


def test_the_console_renders_every_page(service) -> None:
    """Every page answers 200 and carries a heading only that page would render.

    The markers are asserted on the rendered text rather than on a status code, because a
    template that renders an empty shell answers 200 as well.
    """
    client, _state, _settings = service
    for path, marker in (
        # `/` is the intake now; the run list and its rates moved to `/runs`.
        ("/", "从一个目标开始"),
        ("/runs", "运行"),
        ("/escalations", "待处理事项"),
        ("/operations", "故障修复"),
        ("/planning", "任务依赖图"),
        ("/audit", "事件追溯"),
        ("/execution", "执行任务"),
    ):
        response = client.get(path)
        assert response.status_code == 200, path
        assert marker in response.text, path
        if path in {"/", "/planning", "/execution", "/audit"}:
            stages = ['id="flow-' + name + '"' for name in ("task", "plan", "execute", "audit")]
            assert [response.text.index(stage) for stage in stages] == sorted(response.text.index(stage) for stage in stages)
            assert 'data-page="workflow"' in response.text
            assert response.text.count('id="run-picker"') == 1
            assert response.text.count('id="refresh"') == 1
        # Same-origin assets, so there is no CORS surface and no second deployment.
        assert "/static/console.css" in response.text
        assert "/static/console.js" in response.text
        from html.parser import HTMLParser

        class PageStructure(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids = []
                self.in_title = False

            def handle_starttag(self, tag, attrs):
                assert not self.in_title, "page markup must not be injected into its title"
                self.in_title = tag == "title"
                self.ids.extend(value for key, value in attrs if key == "id")

            def handle_endtag(self, tag):
                if tag == "title":
                    self.in_title = False

        structure = PageStructure()
        structure.feed(response.text)
        assert len(structure.ids) == len(set(structure.ids)), path



def test_the_run_page_renders_for_a_real_run(service, tmp_path) -> None:
    client, state, _settings = service
    repo = _repo(tmp_path)
    state.build_worker = lambda *, use_model, enable_review, budget=None, repo_path="": (  # type: ignore[assignment]
        ScriptedWorker(ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)),
        None,
    )
    receipt = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "fix it",
            "goal_id": "GOAL-PAGE",
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
        },
    ).json()
    _wait_for(client, receipt["run_id"], terminal={"COMPLETED", "FAILED", "PARTIAL_FAILURE"})

    page = client.get(f"/runs/{receipt['run_id']}")
    assert page.status_code == 200
    assert receipt["run_id"] in page.text

    assert client.get("/runs/unknown-run").status_code == 404


def test_the_console_never_serves_a_credential(service, monkeypatch) -> None:
    client, _state, _settings = service
    monkeypatch.setenv("DAEDALUS_MODEL_API_KEY", "sk-abcdefghijklmnopqrstuvwxyz012345")
    for path in ("/", "/operations", "/escalations"):
        assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in client.get(path).text


# ---------------------------------------------------------------------------
# Dispatcher behaviour
# ---------------------------------------------------------------------------


def test_the_dispatcher_is_bounded_and_serialises_per_repository(service) -> None:
    client, state, _settings = service
    dispatcher = state.dispatcher
    assert dispatcher.describe()["max_concurrent_runs"] == 2

    import threading

    started: list[str] = []
    release = threading.Event()

    def slow(name: str):
        def invoke():
            started.append(name)
            release.wait(timeout=10)
            from daedalus.application.orchestrator import RunResult

            return RunResult(
                run_id=name, execution_id="e", spec_digest="s", status="COMPLETED"
            )

        return invoke

    first = dispatcher.submit("run-a", "/repo/one", slow("a"))
    second = dispatcher.submit("run-b", "/repo/two", slow("b"))
    assert first.accepted and second.accepted
    # A duplicate run id is refused rather than silently queued twice.
    with pytest.raises(ServiceBusy):
        dispatcher.submit("run-a", "/repo/one", slow("a-again"))

    deadline = time.monotonic() + 10
    while len(started) < 2 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert sorted(started) == ["a", "b"], "two different repositories may run concurrently"
    release.set()


def test_the_dispatcher_stops_accepting_on_shutdown(service) -> None:
    client, state, _settings = service
    dispatcher: RunDispatcher = state.dispatcher
    dispatcher.shutdown(wait=False)
    with pytest.raises(ServiceBusy, match="not accepting"):
        dispatcher.submit("run-x", "/repo", lambda: None)  # type: ignore[arg-type]


def test_startup_reports_interrupted_work_without_resuming_it(tmp_path) -> None:
    """Spec §1.4: an implicit resume is more dangerous than a visible failure."""
    settings = load_settings(None, workspace_root=str(tmp_path / "ws2"))
    settings.ensure_directories()
    store = EventStore(settings.workspace.database_path)
    fsm = StateMachineService(store)
    store.project_run(
        {
            "run_id": "run-interrupted",
            "goal_id": "G",
            "execution_id": "e",
            "spec_digest": "s",
            "status": "RUNNING",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    )
    fsm.declare_step(
        step_id="s1", run_id="run-interrupted", execution_id="e", node_id="n1",
        spec_digest="s", expected_artifacts=("a.py",),
    )
    fsm.transition_step(step_id="s1", event_type="StepActivated", actor="t")
    store.close()

    app = create_app(settings)
    with TestClient(app) as client:
        health = client.get("/api/health").json()
        assert health["startup_findings"] >= 1
        # The run was reported, not resumed: it is still RUNNING with its step in READY.
        detail = client.get("/api/runs/run-interrupted").json()
        assert detail["run"]["status"] == "RUNNING"
        assert detail["steps"][0]["state"] == "READY"


def test_service_state_exposes_configured_limits(tmp_path) -> None:
    settings: Settings = load_settings(
        None, workspace_root=str(tmp_path / "ws3"), max_parallel_steps=3, max_attempts=2
    )
    state = ServiceState(settings)
    try:
        assert state.settings.quota.max_parallel_steps == 3
        assert state.settings.execution.max_attempts == 2
        assert state.dispatcher.max_concurrent_runs == settings.service.max_concurrent_runs
    finally:
        state.close()


def test_the_isolation_endpoint_names_the_gaps(service) -> None:
    """A security reviewer must be able to ask the running system what protects it."""
    client, _state, _settings = service
    payload = client.get("/api/isolation").json()
    assert payload["selected"]
    assert payload["selected_reason"]
    assert len(payload["drivers"]) == 3
    for driver in payload["drivers"]:
        assert "capabilities" in driver
        assert "available" in driver
        assert {"code_isolation", "process_isolation", "filesystem", "network",
                "resource_limits", "identity"} <= set(driver["capabilities"])
    # Where the strongest level is unavailable, the reason must be stated, not implied.
    unavailable = [d for d in payload["drivers"] if not d["available"]]
    for driver in unavailable:
        assert driver["detail"], f"{driver['driver']} must say why it is unavailable"


def test_an_explicit_unavailable_isolation_level_is_refused_over_http(service) -> None:
    """428/409-class refusal, never a silent downgrade to a weaker driver."""
    from daedalus.infrastructure.sandbox import ContainerDriver

    if ContainerDriver().probe().available:  # pragma: no cover - host has a runtime
        pytest.skip("this host has a container runtime")
    client, _state, _settings = service
    response = client.get("/api/isolation?isolation_level=container").json()
    assert response["selected"] == "none"
    assert "unavailable" in response["selected_reason"]
    assert response["gaps"]


def test_a_run_records_the_isolation_it_ran_under(service, tmp_path) -> None:
    client, state, _settings = service
    repo = _repo(tmp_path)
    state.build_worker = lambda *, use_model, enable_review, budget=None, repo_path="": (  # type: ignore[assignment]
        ScriptedWorker(ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)),
        None,
    )
    receipt = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "fix it",
            "goal_id": "GOAL-ISO",
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
        },
    ).json()
    _wait_for(client, receipt["run_id"], terminal={"COMPLETED", "FAILED", "PARTIAL_FAILURE"})

    detail = client.get(f"/api/runs/{receipt['run_id']}").json()
    recorded = detail["isolation"]
    assert recorded is not None, "the isolation decision must be recorded with the run"
    assert recorded["selected"]
    assert recorded["reason"]
    assert "capabilities" in recorded["isolation"]
    assert detail["run"]["status"] == "COMPLETED"


# ---------------------------------------------------------------------------
# Replay from a step (Spec §13.1 B, as the console's 重现 action uses it)
# ---------------------------------------------------------------------------


def _completed_run(client, state, tmp_path: Path, *, goal_id: str = "GOAL-REPLAY") -> dict:
    """One committed run, so a replay has a real commit to start from."""
    repo = _repo(tmp_path)
    state.build_worker = lambda *, use_model, enable_review, budget=None, repo_path="": (  # type: ignore[assignment]
        ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="w-replay",
        ),
        None,
    )
    receipt = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "make summarize() count words",
            "goal_id": goal_id,
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
        },
    ).json()
    status = _wait_for(client, receipt["run_id"], terminal={"COMPLETED", "FAILED"})
    assert status == "COMPLETED", status
    return client.get(f"/api/runs/{receipt['run_id']}").json()


def test_the_run_view_names_the_commit_a_step_produced(service, tmp_path) -> None:
    """`result_commit` is what makes "replay from this step" expressible at all.

    An artifact records `parent_commit` — the tree its work was based on — and never the commit
    it produced, so the result of a step existed only inside a `StepCommitted` event payload. The
    console had no commit to offer and the replay guard rejected the one an operator means.
    """
    client, state, _settings = service
    detail = _completed_run(client, state, tmp_path)

    step = detail["steps"][0]
    assert step["state"] == "COMMITTED"
    assert step["result_commit"], "a committed step must report the commit it produced"
    assert step["result_commit"] != step["base_commit"], "a commit is not its own base"
    assert step["artifacts"][-1]["parent_commit"] == step["base_commit"]

    # And it is the commit that actually landed on the branch, read from the event log rather
    # than guessed from the projection.
    events = state.store.events_for_execution(str(detail["run"]["execution_id"]))
    committed = [event for event in events if event.event_type == "StepCommitted"]
    assert [str(event.payload["commit"]) for event in committed] == [step["result_commit"]]


def test_replaying_from_a_step_commit_is_accepted(service, tmp_path) -> None:
    """The commit the console offers must be a commit the service accepts.

    Asserting the 202 is the point: the two halves of this feature are written in different
    languages and were briefly inconsistent — the view advertised a commit the guard refused.
    """
    client, state, _settings = service
    detail = _completed_run(client, state, tmp_path)
    run_id = detail["run"]["run_id"]
    from_commit = detail["steps"][0]["result_commit"]

    response = client.post(
        f"/api/runs/{run_id}/replay",
        json={"reason": "replay from the console", "from_commit": from_commit, "use_model": False},
    )
    assert response.status_code == 202, response.text
    receipt = response.json()
    assert receipt["replay_from_commit"] == from_commit
    assert receipt["run_id"] != run_id, "a replay is a new run, not a mutation of the old one"
    assert receipt["replayed_execution_id"] == detail["run"]["execution_id"]


def test_replaying_from_the_run_base_is_accepted(service, tmp_path) -> None:
    """The other legitimate baseline: the run's own base, which re-executes everything."""
    client, state, _settings = service
    detail = _completed_run(client, state, tmp_path)
    run_id = detail["run"]["run_id"]

    response = client.post(
        f"/api/runs/{run_id}/replay",
        json={"reason": "redo it", "from_commit": detail["run"]["base_commit"]},
    )
    assert response.status_code == 202, response.text
    assert response.json()["replay_from_commit"] == detail["run"]["base_commit"]


def test_replaying_from_an_unrecorded_commit_is_refused(service, tmp_path) -> None:
    """A commit the run never recorded is a 409, not a replay of something unrelated.

    Refusing here is what lets the console pass a commit straight through from a node box: the
    server, not the UI, is the thing that decides which baselines are legitimate.
    """
    client, state, _settings = service
    detail = _completed_run(client, state, tmp_path)
    run_id = detail["run"]["run_id"]
    before = len(client.get("/api/runs").json()["runs"])

    response = client.post(
        f"/api/runs/{run_id}/replay",
        json={"reason": "typo", "from_commit": "0" * 40},
    )
    assert response.status_code == 409, response.text
    assert "not a commit this run recorded" in response.json()["detail"]
    assert len(client.get("/api/runs").json()["runs"]) == before, (
        "a refused replay must not create a run"
    )


def test_an_empty_from_commit_falls_back_to_the_run_base(service, tmp_path) -> None:
    """Omitting the baseline is not an error: it means "replay this run from the start"."""
    client, state, _settings = service
    # A run id whose base is known, but with no steps recorded: the base is still the answer.
    detail = _completed_run(client, state, tmp_path, goal_id="GOAL-REPLAY-EMPTY")
    run_id = detail["run"]["run_id"]

    response = client.post(f"/api/runs/{run_id}/replay", json={"reason": "from the top"})
    assert response.status_code == 202, response.text
    assert response.json()["replay_from_commit"] == detail["run"]["base_commit"]


def test_an_unknown_run_cannot_be_replayed_from(service) -> None:
    client, _state, _settings = service
    response = client.post(
        "/api/runs/run_does_not_exist/replay",
        json={"reason": "nope", "from_commit": "0" * 40},
    )
    assert response.status_code == 404, response.text
