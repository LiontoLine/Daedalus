"""Owner approval, parking and resuming (Spec §10, §16).

The capability under test is the one that makes the system usable rather than merely
correct: an escalation is a question, and a human can answer it and have the run continue.

The tests are adversarial about the *binding*. An approval that authorises "whatever comes
next" would be worse than no approval at all, so most of what follows tries to get a commit
through with an approval that does not actually name the artifact.
"""

from __future__ import annotations

import json

import pytest

from daedalus.application.approvals import ApprovalError, ApprovalService, NotEscalated
from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.fsm_service import StateMachineService
from daedalus.application.gatekeeper.decision import GateDecision
from daedalus.application.gatekeeper.tier2 import (
    SemanticReviewRequest,
    SemanticReviewResult,
    Tier2Gate,
)
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.resume import ResumeError, load_manifest, resume_run
from daedalus.application.scheduler import Quota
from daedalus.domain.approval import ApprovalDecision, approval_required
from daedalus.domain.fsm import RunState, StepState
from daedalus.domain.spec import NetworkPolicy, RiskLevel
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.infrastructure.store import EventStore
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND


class AlwaysEscalate:
    """A reviewer that provides a well-formed subject-bound ESCALATE."""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, prompt: str, *, subject_digest: str) -> str:
        self.calls += 1
        return json.dumps(
            {
                "decision": "ESCALATE",
                "subject_digest": subject_digest,
                "reasons": ["this change touches a policy-relevant path"],
                "violations": [],
                "confidence": 0.4,
            }
        )


def _request(risk: RiskLevel = RiskLevel.NORMAL) -> PlanRequest:
    return PlanRequest(
        request_id="REQ-APR",
        goal_id="GOAL-APR",
        objective="make summarize() count words",
        target_paths=(TARGET,),
        test_command=TEST_COMMAND,
        risk_level=risk,
        network_policy=NetworkPolicy.DENY,
    )


def _run_to_park(git_repo, tmp_path, *, risk: RiskLevel = RiskLevel.CRITICAL, reviewer=None):
    """Drive a run until a step escalates, leaving it parked."""
    store = EventStore(tmp_path / "approval.db")
    bundle = DeterministicPlanner().plan(_request(risk))
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="w-approval",
        ),
        tier2=Tier2Gate(reviewer=reviewer or _Approve()) if reviewer is not False else None,
        quota=Quota(),
        park_on_escalation=True,
    )
    orchestrator.register_spec()
    if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        orchestrator.approve_spec(approved_by="alice", signature="fixture-spec-approval")
    result = orchestrator.run()
    return store, orchestrator, result



# ---------------------------------------------------------------------------
# Parking
# ---------------------------------------------------------------------------


def test_inconclusive_review_stops_without_requesting_approval(git_repo, tmp_path) -> None:
    store, orchestrator, result = _run_to_park(
        git_repo, tmp_path, risk=RiskLevel.NORMAL, reviewer=AlwaysEscalate(),
    )

    assert result.status == RunState.FAILED.value, result.describe()
    assert not ApprovalService(store, orchestrator.fsm).pending_escalations()
    assert store.get_run(result.run_id)["status"] == RunState.FAILED.value
    # The pending change is the subject of the decision, so its worktree must survive.
    step = store.list_steps(result.run_id)[0]
    assert str(step["state"]) == StepState.ESCALATED.value
    assert step["worktree_path"], "the worktree holding the pending change must be recorded"
    from pathlib import Path

    assert Path(str(step["worktree_path"])).is_dir(), "a parked run must keep its worktree"
    # Nothing was committed.
    assert not result.commits
    store.close()


class _Approve:
    def complete(self, prompt: str, *, subject_digest: str) -> str:
        return json.dumps(
            {
                "decision": "APPROVE",
                "subject_digest": subject_digest,
                "reasons": ["fine"],
                "violations": [],
                "confidence": 0.99,
            }
        )


def test_a_critical_spec_cannot_run_without_an_owner_signoff(git_repo, tmp_path) -> None:
    """Spec §3.2: sign-off is enforced before any work starts, not asserted in prose."""
    from daedalus.errors import SpecApprovalRequired

    store = EventStore(tmp_path / "critical.db")
    bundle = DeterministicPlanner().plan(_request(RiskLevel.CRITICAL))
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wtc",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),), worker_id="w"
        ),
        tier2=Tier2Gate(reviewer=_Approve()),
        quota=Quota(),
    )
    orchestrator.register_spec()
    with pytest.raises(SpecApprovalRequired, match="no owner approval"):
        orchestrator.run()
    assert not store.list_runs(), "a refused run must not even be created"
    store.close()


def test_critical_risk_parks_even_when_the_reviewer_approves(git_repo, tmp_path) -> None:
    store = EventStore(tmp_path / "critical2.db")
    bundle = DeterministicPlanner().plan(_request(RiskLevel.CRITICAL))
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wtc2",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),), worker_id="w"
        ),
        tier2=Tier2Gate(reviewer=_Approve()),
        quota=Quota(),
        park_on_escalation=True,
    )
    orchestrator.register_spec()
    orchestrator.approve_spec(approved_by="alice", signature="sig-2026-09-23")
    assert store.is_spec_approved(orchestrator.spec_digest)

    result = orchestrator.run()
    # The reviewer approved, but Spec §10 forbids auto-merging a critical change.
    assert result.status == RunState.AWAITING_APPROVAL.value, result.describe()
    assert not result.commits, "Spec §10: a critical change may not auto-merge"
    gate_events = [e for e in store.all_events() if e.event_type == "StepTier2Decided"]
    assert gate_events[-1].payload["reviewer_decision"] == "APPROVE"
    assert gate_events[-1].payload["effective_decision"] == "ESCALATE"
    assert gate_events[-1].payload["overridden_by_policy"] is True
    store.close()


def test_spec_approval_must_name_who_signed(git_repo, tmp_path) -> None:
    from daedalus.errors import SpecApprovalRequired

    store = EventStore(tmp_path / "critical3.db")
    bundle = DeterministicPlanner().plan(_request(RiskLevel.CRITICAL))
    orchestrator = RunOrchestrator(
        store=store, repo_path=git_repo, run_root=tmp_path / "wtc3", bundle=bundle,
        worker=ScriptedWorker(ops=(), worker_id="w"), quota=Quota(),
    )
    orchestrator.register_spec()
    with pytest.raises(SpecApprovalRequired, match="must name who"):
        orchestrator.approve_spec(approved_by="  ")
    store.close()


def test_park_can_be_turned_off_for_batch_runs(git_repo, tmp_path) -> None:
    store = EventStore(tmp_path / "noPark.db")
    bundle = DeterministicPlanner().plan(_request())
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt2",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),), worker_id="w"
        ),
        tier2=Tier2Gate(reviewer=AlwaysEscalate()),
        quota=Quota(),
        park_on_escalation=False,
    )
    orchestrator.register_spec()
    result = orchestrator.run()
    assert result.status != RunState.AWAITING_APPROVAL.value
    assert result.status in {"FAILED", "PARTIAL_FAILURE"}
    store.close()


# ---------------------------------------------------------------------------
# The approval binding
# ---------------------------------------------------------------------------


def test_approval_is_refused_for_a_step_that_is_not_escalated(git_repo, tmp_path) -> None:
    store, _orchestrator, result = _run_to_park(git_repo, tmp_path)
    service = ApprovalService(store=store, fsm=StateMachineService(store))
    step_id = str(store.list_steps(result.run_id)[0]["step_id"])

    # A second approval for the same step is fine while it is still escalated; the point is
    # that a non-escalated step cannot be approved at all.
    store.update_step_state(step_id, state=StepState.COMMITTED.value)
    with pytest.raises(NotEscalated):
        service.approve(
            run_id=result.run_id,
            step_id=step_id,
            decision=ApprovalDecision.PROCEED,
            approved_by="alice",
        )
    store.close()


def test_approval_must_name_who_approved(git_repo, tmp_path) -> None:
    store, _orchestrator, result = _run_to_park(git_repo, tmp_path)
    service = ApprovalService(store=store, fsm=StateMachineService(store))
    step_id = str(store.list_steps(result.run_id)[0]["step_id"])
    with pytest.raises(ApprovalError, match="who gave it"):
        service.approve(
            run_id=result.run_id,
            step_id=step_id,
            decision=ApprovalDecision.PROCEED,
            approved_by="   ",
        )
    store.close()


def test_approval_is_bound_to_one_artifact_digest(git_repo, tmp_path) -> None:
    store, _orchestrator, result = _run_to_park(git_repo, tmp_path)
    service = ApprovalService(store=store, fsm=StateMachineService(store))
    step_id = str(store.list_steps(result.run_id)[0]["step_id"])
    artifact = store.artifacts_for_step(step_id)[-1]

    approved = service.approve(
        run_id=result.run_id,
        step_id=step_id,
        decision=ApprovalDecision.PROCEED,
        approved_by="alice",
        note="accepted after reading the diff",
        artifact_digest=str(artifact["artifact_digest"]),
    )
    assert approved.artifact_digest == str(artifact["artifact_digest"])

    # The recorded approval authorises exactly that digest and no other.
    assert store.find_approval_authorising(step_id, str(artifact["artifact_digest"]))
    assert not store.find_approval_authorising(step_id, "0" * 64)
    store.close()


def test_cannot_approve_an_artifact_from_another_step(git_repo, tmp_path) -> None:
    store, _orchestrator, result = _run_to_park(git_repo, tmp_path)
    service = ApprovalService(store=store, fsm=StateMachineService(store))
    step_id = str(store.list_steps(result.run_id)[0]["step_id"])
    with pytest.raises(ApprovalError, match="does not belong to step"):
        service.approve(
            run_id=result.run_id,
            step_id=step_id,
            decision=ApprovalDecision.PROCEED,
            approved_by="alice",
            artifact_digest="f" * 64,
        )
    store.close()


def test_proceed_without_an_artifact_is_refused(git_repo, tmp_path) -> None:
    """A boundary violation produces no artifact, so there is nothing to accept."""
    store = EventStore(tmp_path / "noArtifact.db")
    bundle = DeterministicPlanner().plan(_request())
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt3",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(
                FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),
                FileOp(op="write", path="src/example_project/smuggled.py", content="x = 1\n"),
            ),
            worker_id="w-escape",
        ),
        quota=Quota(max_parallel_steps=1),
        park_on_escalation=True,
    )
    orchestrator.register_spec()
    result = orchestrator.run()
    assert result.status == RunState.FAILED.value
    step_id = str(store.list_steps(result.run_id)[0]["step_id"])
    assert not store.artifacts_for_step(step_id), "a refused worker produced no artifact"

    service = ApprovalService(store=store, fsm=StateMachineService(store))
    with pytest.raises(ApprovalError):
        service.approve(
            run_id=result.run_id,
            step_id=step_id,
            decision=ApprovalDecision.PROCEED,
            approved_by="alice",
        )
    store.close()


def test_approval_requirement_helper() -> None:
    assert approval_required(
        gate_decision="ESCALATE", risk_level="normal", manual_review_levels=("critical",)
    )
    assert approval_required(
        gate_decision="APPROVE", risk_level="critical", manual_review_levels=("critical",)
    )
    assert not approval_required(
        gate_decision="APPROVE", risk_level="normal", manual_review_levels=("critical",)
    )


# ---------------------------------------------------------------------------
# Resuming
# ---------------------------------------------------------------------------


def test_proceed_commits_the_approved_artifact_on_resume(git_repo, tmp_path) -> None:
    store, _orchestrator, parked = _run_to_park(git_repo, tmp_path)
    main_before = GitSandbox.main_commit(git_repo)
    step_id = str(store.list_steps(parked.run_id)[0]["step_id"])
    artifact_digest = str(store.artifacts_for_step(step_id)[-1]["artifact_digest"])

    service = ApprovalService(store=store, fsm=StateMachineService(store))
    service.approve(
        run_id=parked.run_id,
        step_id=step_id,
        decision=ApprovalDecision.PROCEED,
        approved_by="alice",
        note="reviewed the semantic risk by hand",
    )

    resumed = resume_run(store=store, run_id=parked.run_id, workspace=str(tmp_path))
    assert resumed.status == "COMPLETED", resumed.describe()
    assert resumed.commits, "an approved artifact must actually land"
    assert GitSandbox.main_commit(git_repo) != main_before

    # The commit must record that a human overrode the escalation.
    commits = [e for e in store.all_events() if e.event_type == "StepCommitted"]
    assert commits[-1].payload["owner_override"] is True
    assert commits[-1].payload["approved_by"] == "alice"
    # And the approval trail is retrievable, bound to the artifact that was reviewed —
    # otherwise "proceed" would authorise whatever the step happened to produce next.
    recorded = store.approvals_for_run(parked.run_id)
    assert [a["decision"] for a in recorded] == ["proceed"]
    assert str(recorded[0]["artifact_digest"]) == artifact_digest
    store.close()


def test_retry_grants_attempts_and_the_step_runs_again(git_repo, tmp_path) -> None:
    store, _orchestrator, parked = _run_to_park(git_repo, tmp_path)
    step_id = str(store.list_steps(parked.run_id)[0]["step_id"])
    service = ApprovalService(store=store, fsm=StateMachineService(store))
    service.approve(
        run_id=parked.run_id,
        step_id=step_id,
        decision=ApprovalDecision.RETRY,
        approved_by="alice",
        note="the intent is right, the approach is not",
        granted_attempts=2,
    )
    applied = service.apply_decisions(parked.run_id)
    assert applied[step_id] == "retry(+2)"
    assert store.get_step(step_id)["state"] == StepState.READY.value
    assert int(store.get_step(step_id)["granted_attempts"]) == 2
    store.close()


def test_reject_stops_the_step(git_repo, tmp_path) -> None:
    store, _orchestrator, parked = _run_to_park(git_repo, tmp_path)
    step_id = str(store.list_steps(parked.run_id)[0]["step_id"])
    service = ApprovalService(store=store, fsm=StateMachineService(store))
    service.approve(
        run_id=parked.run_id,
        step_id=step_id,
        decision=ApprovalDecision.REJECT,
        approved_by="alice",
        note="wrong approach entirely",
    )
    applied = service.apply_decisions(parked.run_id)
    assert applied[step_id] == "rejected"
    assert store.get_step(step_id)["state"] == StepState.CANCELLED.value
    store.close()


def test_resume_without_a_decision_stays_parked(git_repo, tmp_path) -> None:
    store, _orchestrator, parked = _run_to_park(git_repo, tmp_path)
    again = resume_run(store=store, run_id=parked.run_id, workspace=str(tmp_path))
    assert again.status == RunState.AWAITING_APPROVAL.value
    assert not again.commits
    store.close()


def test_resume_refuses_a_vanished_worktree(git_repo, tmp_path) -> None:
    """An approval cannot be honoured if the content it describes is gone."""
    import shutil

    store, _orchestrator, parked = _run_to_park(git_repo, tmp_path)
    step_id = str(store.list_steps(parked.run_id)[0]["step_id"])
    worktree = str(store.get_step(step_id)["worktree_path"])
    ApprovalService(store=store, fsm=StateMachineService(store)).approve(
        run_id=parked.run_id,
        step_id=step_id,
        decision=ApprovalDecision.PROCEED,
        approved_by="alice",
    )
    shutil.rmtree(worktree, ignore_errors=True)

    resumed = resume_run(store=store, run_id=parked.run_id, workspace=str(tmp_path))
    assert not resumed.commits
    assert any("worktree" in note for note in resumed.notes), resumed.notes
    # And the operator can see why.
    from daedalus.application.recovery import Finding, recover_workspace

    report = recover_workspace(store=store, apply=False)
    assert any(item.finding is Finding.MISSING_WORKTREE for item in report.items)
    store.close()


def test_resume_refuses_when_the_spec_is_missing(git_repo, tmp_path) -> None:
    store, _orchestrator, parked = _run_to_park(git_repo, tmp_path)
    store.connection.execute("DELETE FROM specs")
    with pytest.raises(ResumeError, match="not in the registry"):
        load_manifest(store, parked.run_id)
    store.close()


def test_manifest_records_what_a_resume_needs(git_repo, tmp_path) -> None:
    store, _orchestrator, parked = _run_to_park(git_repo, tmp_path)
    manifest = load_manifest(store, parked.run_id)
    assert manifest.run_id == parked.run_id
    assert manifest.repo_path == str(git_repo)
    assert manifest.base_commit
    assert manifest.bundle.goal.goal_id == "GOAL-APR"
    store.close()


def test_pending_escalations_lists_what_needs_an_answer(git_repo, tmp_path) -> None:
    store, _orchestrator, parked = _run_to_park(git_repo, tmp_path)
    service = ApprovalService(store=store, fsm=StateMachineService(store))
    pending = service.pending_escalations()
    assert len(pending) == 1
    assert pending[0]["run_id"] == parked.run_id
    assert pending[0]["node_id"]
    assert pending[0]["artifact_digest"]

    service.approve(
        run_id=parked.run_id,
        step_id=str(pending[0]["step_id"]),
        decision=ApprovalDecision.PROCEED,
        approved_by="alice",
    )
    assert service.pending_escalations() == [], "an answered escalation is no longer pending"
    store.close()
