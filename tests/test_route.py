"""The run route: what actually happened, attempt by attempt (Spec §4, §14, §16).

The console used to draw the *plan* with each box coloured by the step's current state. That
shows the intended shape of the work and hides its history: a step that was revised twice,
rebased once and parked for an hour was one box. These tests hold the properties that make the
route worth drawing:

* an attempt is the unit, so a retry is a new box with its own gate verdict and its own failure;
* the route comes from the event log, so it cannot disagree with the authority;
* a node offers only actions that would succeed, and says why when it cannot.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.route import build_route
from daedalus.domain.approval import ApprovalDecision
from daedalus.domain.fsm import StepState
from daedalus.domain.identity import Role
from daedalus.domain.spec import NetworkPolicy, RiskLevel
from daedalus.infrastructure.store import EventStore
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

BROKEN = '''"""Text statistics."""


def summarize(text: str) -> dict[str, int]:
    tokens = text.split()
    return {
        "lines": len(text.splitlines()),
        "words": len(tokens) + 1,
        "characters": len(text),
    }
'''


def _bundle(goal_id: str = "GOAL-ROUTE", risk: RiskLevel = RiskLevel.NORMAL):
    return DeterministicPlanner().plan(
        PlanRequest(
            request_id=f"REQ-{goal_id}",
            goal_id=goal_id,
            objective="fix the word counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=risk,
            network_policy=NetworkPolicy.DENY,
        )
    )


def _repo_at(path: Path) -> Path:
    from daedalus.infrastructure.git_sandbox import init_repo, initial_commit

    import shutil

    from tests.conftest import DEMO_PROJECT

    repo = init_repo(path)
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".DS_Store")
    shutil.copytree(DEMO_PROJECT / "src", repo / "src", ignore=ignore)
    shutil.copytree(DEMO_PROJECT / "tests", repo / "tests", ignore=ignore)
    shutil.copy2(DEMO_PROJECT / "pyproject.toml", repo / "pyproject.toml")
    shutil.copy2(DEMO_PROJECT / ".gitignore", repo / ".gitignore")
    initial_commit(repo, "chore: import the demo project")
    return repo


class _Attempts(ScriptedWorker):
    """A worker whose first attempt is wrong and whose second is right."""

    def __init__(self) -> None:
        super().__init__(ops=(), worker_id="worker-route")
        self.calls = 0

    def implement(self, sandbox, context):  # type: ignore[no-untyped-def]
        self.calls += 1
        content = BROKEN if self.calls == 1 else CORRECT_IMPLEMENTATION
        sandbox.write_file(TARGET, content)
        from daedalus.application.worker import WorkerResult

        return WorkerResult(
            ok=True,
            summary=f"attempt {self.calls}",
            execution_log="",
            worker_id=self.worker_id,
        )


def test_a_retry_is_its_own_box_with_its_own_failure(git_repo, tmp_path) -> None:
    """The property the whole route exists for: a retry is a new candidate, not a counter."""
    repo = _repo_at(tmp_path / "repo")
    store = EventStore(tmp_path / "route.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt",
        bundle=_bundle(),
        worker=_Attempts(),
    )
    orchestrator.register_spec()
    orchestrator.create_run()
    result = orchestrator.run()
    assert result.status == "COMPLETED", result.describe()

    route = build_route(store, result.run_id).to_payload()
    attempts = [node for node in route["nodes"] if node["kind"] == "attempt"]
    assert len(attempts) == 2, [(n["label"], n["state"]) for n in attempts]
    assert attempts[0]["state"] == StepState.REVISE.value, attempts[0]
    assert attempts[1]["state"] == StepState.COMMITTED.value, attempts[1]
    # Each attempt carries its own verdict, which is what a single box per step cannot show.
    assert attempts[0]["gate_tier1"] == "REVISE"
    assert attempts[1]["gate_tier1"] == "PASS"
    assert attempts[0]["failure"], "the first attempt must record why it was rejected"
    assert attempts[0]["artifact_digest"] != attempts[1]["artifact_digest"]

    retries = [edge for edge in route["edges"] if edge["kind"] == "retry"]
    assert len(retries) == 1
    assert retries[0]["from"] == attempts[0]["key"] and retries[0]["to"] == attempts[1]["key"]
    assert attempts[0]["failure"][:20] in retries[0]["label"], retries[0]
    store.close()


def test_the_route_contains_only_this_runs_events(git_repo, tmp_path) -> None:
    """Two runs in one workspace must not be interleaved into one route.

    `sequence` restarts at 1 for every aggregate, so ordering on it (or filtering with a
    loose `or`) mixes runs — which showed up as an attempt appearing twice, once for each run.
    """
    store = EventStore(tmp_path / "two.db")
    for index in range(2):
        # A separate repository per run: the second run would otherwise find the file already
        # fixed and produce an empty diff, which tier-1 refuses for reasons unrelated to what
        # this test is about.
        repo = _repo_at(tmp_path / f"repo{index}")
        orchestrator = RunOrchestrator(
            store=store,
            repo_path=repo,
            run_root=tmp_path / f"wt{index}",
            bundle=_bundle(f"GOAL-{index}"),
            worker=ScriptedWorker(
                ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
                worker_id=f"w{index}",
            ),
        )
        orchestrator.register_spec()
        orchestrator.create_run()
        assert orchestrator.run().status == "COMPLETED"

    runs = store.list_runs()
    assert len(runs) == 2
    for run in runs:
        route = build_route(store, str(run["run_id"])).to_payload()
        assert route["run_id"] == str(run["run_id"])
        executions = {node["key"] for node in route["nodes"]}
        assert len(executions) == len(route["nodes"]), "node keys must be unique"
        # Every attempt belongs to this run's execution.
        for node in route["nodes"]:
            if node["kind"] == "attempt":
                assert node["step_id"].startswith(str(run["run_id"]))
        assert route["status"] == "COMPLETED"
    store.close()


def test_a_parked_run_offers_retry_and_reject_and_explains_what_is_blocked(
    git_repo, tmp_path
) -> None:
    """The actions must be the ones that would succeed, and a blocked one must say why."""
    from daedalus.application.gatekeeper.tier2 import Tier2Gate

    class _Escalate:
        name = "escalating"

        def complete(self, prompt: str, *, subject_digest: str) -> str:
            return json.dumps(
                {
                    "decision": "APPROVE",
                    "subject_digest": subject_digest,
                    "reasons": ["needs a human"],
                    "violations": [],
                    "confidence": 0.9,
                }
            )

    repo = _repo_at(tmp_path / "repo")
    store = EventStore(tmp_path / "parked.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt",
        bundle=_bundle(risk=RiskLevel.CRITICAL),
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-park",
        ),
        tier2=Tier2Gate(reviewer=_Escalate()),
        park_on_escalation=True,
    )
    orchestrator.register_spec()
    orchestrator.approve_spec(approved_by="alice")
    orchestrator.create_run()
    result = orchestrator.run()
    assert result.status == "AWAITING_APPROVAL", result.describe()

    route = build_route(store, result.run_id).to_payload()
    assert route["status"] == "AWAITING_APPROVAL"
    attempts = [node for node in route["nodes"] if node["kind"] == "attempt"]
    assert len(attempts) == 1
    node = attempts[-1]
    assert node["state"] == StepState.ESCALATED.value, node

    actions = {action["id"]: action for action in node["actions"]}
    assert actions["detail"]["enabled"] is True
    assert actions["retry"]["enabled"] is True, actions["retry"]
    assert actions["reject"]["enabled"] is True, actions["reject"]
    assert actions["rollback"]["enabled"] is True
    # A parked run's park node is on the control-plane lane, so the route shows *where* it
    # stopped rather than only that a step escalated.
    park = [n for n in route["nodes"] if n["state"] == "park"]
    assert park, [n["state"] for n in route["nodes"]]
    assert park[0]["lane"] == -1
    store.close()


def test_a_committed_node_refuses_a_retry_and_says_why(git_repo, tmp_path) -> None:
    """A button whose only outcome is an error is worse than no button."""
    repo = _repo_at(tmp_path / "repo")
    store = EventStore(tmp_path / "done.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt",
        bundle=_bundle(),
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-done",
        ),
    )
    orchestrator.register_spec()
    orchestrator.create_run()
    result = orchestrator.run()
    route = build_route(store, result.run_id).to_payload()
    node = next(n for n in route["nodes"] if n["kind"] == "attempt")
    actions = {action["id"]: action for action in node["actions"]}
    assert actions["retry"]["enabled"] is False
    assert "已提交" in actions["retry"]["reason"]
    assert actions["reject"]["enabled"] is False
    assert actions["reject"]["reason"]
    # Rolling back is still available: a committed step has a commit to return to.
    assert actions["rollback"]["enabled"] is True
    assert actions["rollback"]["to_commit"]
    store.close()


def test_an_old_attempt_cannot_be_acted_on(git_repo, tmp_path) -> None:
    """Only the latest attempt of a step may be disposed of; the others are history."""
    repo = _repo_at(tmp_path / "repo")
    store = EventStore(tmp_path / "old.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt",
        bundle=_bundle(),
        worker=_Attempts(),
    )
    orchestrator.register_spec()
    orchestrator.create_run()
    result = orchestrator.run()
    route = build_route(store, result.run_id).to_payload()
    attempts = sorted(
        (n for n in route["nodes"] if n["kind"] == "attempt"), key=lambda n: n["attempt"]
    )
    actions = {action["id"]: action for action in attempts[0]["actions"]}
    assert actions["retry"]["enabled"] is False
    store.close()


def test_an_enrolled_workspace_marks_that_a_signature_is_needed(git_repo, tmp_path) -> None:
    """The console has to ask for a signature when the workspace verifies them."""
    from daedalus.application.gatekeeper.tier2 import Tier2Gate
    from daedalus.application.identity import OwnerRegistry

    class _Escalate:
        name = "escalating"

        def complete(self, prompt: str, *, subject_digest: str) -> str:
            return json.dumps(
                {
                    "decision": "APPROVE",
                    "subject_digest": subject_digest,
                    "reasons": ["needs a human"],
                    "violations": [],
                    "confidence": 0.9,
                }
            )

    repo = _repo_at(tmp_path / "repo")
    store = EventStore(tmp_path / "signed.db")
    identity = OwnerRegistry(store=store, environ={"K": "secret"})
    identity.enroll("alice", role=Role.OWNER, secret_env="K")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt",
        bundle=_bundle("GOAL-SIGNED", RiskLevel.CRITICAL),
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-signed",
        ),
        tier2=Tier2Gate(reviewer=_Escalate()),
        park_on_escalation=True,
        identity=identity,
    )
    orchestrator.register_spec()
    orchestrator.approve_spec(
        approved_by="alice", signature=identity.sign("alice", orchestrator.spec_digest)
    )
    orchestrator.create_run()
    result = orchestrator.run()
    assert result.status == "AWAITING_APPROVAL", result.describe()

    route = build_route(store, result.run_id).to_payload()
    node = next(n for n in route["nodes"] if n["kind"] == "attempt" and n["state"] == "ESCALATED")
    actions = {a["id"]: a for a in node["actions"]}
    assert actions["retry"]["enabled"] is True
    assert actions["retry"]["requires_signature"] is True
    assert actions["reject"]["requires_signature"] is False, (
        "rejecting stops the step and must not need a key"
    )
    store.close()


def test_the_route_is_json_serialisable_and_stable(git_repo, tmp_path) -> None:
    """The console polls this payload; it must be plain data and reproducible."""
    repo = _repo_at(tmp_path / "repo")
    store = EventStore(tmp_path / "stable.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt",
        bundle=_bundle(),
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-stable",
        ),
    )
    orchestrator.register_spec()
    orchestrator.create_run()
    result = orchestrator.run()
    first = build_route(store, result.run_id).to_payload()
    second = build_route(store, result.run_id).to_payload()
    assert first == second, "the route must not depend on iteration order"
    assert json.loads(json.dumps(first)) == first
    store.close()


def test_an_unstarted_run_says_so_rather_than_drawing_nothing(git_repo, tmp_path) -> None:
    """An empty graph with no explanation reads as a broken page."""
    repo = _repo_at(tmp_path / "repo")
    store = EventStore(tmp_path / "empty.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt",
        bundle=_bundle(),
        worker=ScriptedWorker(ops=(), worker_id="w"),
    )
    orchestrator.register_spec()
    orchestrator.create_run()
    route = build_route(store, orchestrator.run_id).to_payload()
    assert not any(node["kind"] == "attempt" for node in route["nodes"])
    assert route["notes"], "a route with no attempts must explain itself"
    store.close()


def test_the_http_endpoint_serves_the_route(git_repo, tmp_path) -> None:
    from fastapi.testclient import TestClient

    from daedalus.config import load_settings
    from daedalus.service.app import create_app

    repo = _repo_at(tmp_path / "repo")
    app = create_app(load_settings(None, workspace_root=str(tmp_path / "ws")))
    with TestClient(app) as client:
        app.state.daedalus.build_worker = lambda **_: (  # type: ignore[assignment]
            ScriptedWorker(
                ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
                worker_id="worker-http",
            ),
            None,
        )
        accepted = client.post(
            "/api/runs",
            json={
                "repo_path": str(repo),
                "objective": "fix the word counter",
                "target_paths": [TARGET],
                "test_command": TEST_COMMAND,
            },
        )
        assert accepted.status_code == 202, accepted.text
        run_id = accepted.json()["run_id"]
        import time

        deadline = time.time() + 60
        view = client.get(f"/api/runs/{run_id}").json()
        while view["run"]["status"] not in {"COMPLETED", "FAILED"} and time.time() < deadline:
            time.sleep(0.1)
            view = client.get(f"/api/runs/{run_id}").json()
        assert view["run"]["status"] == "COMPLETED"

        response = client.get(f"/api/runs/{run_id}/route")
        assert response.status_code == 200, response.text
        route = response.json()
        assert route["run_id"] == run_id
        assert any(node["kind"] == "attempt" for node in route["nodes"])
        assert any(edge["kind"] == "route" for edge in route["edges"])
        assert client.get("/api/runs/does-not-exist/route").status_code == 404
