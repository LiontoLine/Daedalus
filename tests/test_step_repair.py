"""Ordinary candidate failures repair automatically; only usable delivery awaits review."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from daedalus.application.approvals import ApprovalError, ApprovalService
from daedalus.application.coding_worker import FileOp, ModelWorker, ScriptedWorker
from daedalus.application.gatekeeper.tier2 import Tier2Gate
from daedalus.application.independent_validation import pending_validation
from daedalus.application.worker import WorkerResult
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, PlanNode, PlanSpec
from daedalus.errors import ModelError, ModelResponseIncomplete
from daedalus.infrastructure.git_sandbox import _git
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
from tests.test_branch_repair import owner_for
from tests.test_goal_audit import GoalReviewer, make_owner


def branch_events(owner, kind):
    return [event.payload for event in owner.store.events_for_execution(owner.execution_id)
            if event.event_type == kind]


class RepairWorker:
    name = "isolated-step-repair"

    def __init__(self):
        self.contexts = []
        self.worktrees = []

    def implement(self, sandbox, context):
        self.contexts.append(context)
        self.worktrees.append(sandbox.worktree_path)
        if context.attempt == 1:
            return WorkerResult(ok=False, error="invalid_edit_plan", summary="stale edit",
                                execution_log="The current function differs from the proposed anchor.")
        return ScriptedWorker(ops=(FileOp("write", TARGET, CORRECT_IMPLEMENTATION),)).implement(
            sandbox, context)


def test_step_failure_repairs_before_the_only_delivery_approval(git_repo, tmp_path):
    worker = RepairWorker()
    owner = make_owner(git_repo, tmp_path, worker=worker)
    owner.manual_review_levels = ("normal",)
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    frozen = owner.bundle.to_dict()
    try:
        result = owner.run()
        assert result.status == "AWAITING_APPROVAL", result.describe()
        assert all(row["state"] == "COMMITTED" for row in owner.store.list_steps(owner.run_id))
        assert pending_validation(owner.store, owner.run_id)["commit"] == owner.pool.integration_head()
        assert branch_events(owner, "GoalAuditCompleted")[-1]["decision"] == "APPROVE"
        started = branch_events(owner, "RepairBranchStarted")
        promoted = branch_events(owner, "RepairBranchPromoted")
        assert len(started) == len(promoted) == 1
        assert started[0]["phase"] == "step" and started[0]["attempt"] == 2
        assert promoted[0]["branch_id"] == started[0]["branch_id"]
        assert worker.worktrees[0] != worker.worktrees[1]
        assert Path(worker.worktrees[0]).is_dir()
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == original
        assert owner.bundle.to_dict() == frozen
        assert not owner.store.verify_sequences()
    finally:
        owner.store.close()


def test_security_failure_is_failed_not_an_approval_request(git_repo, tmp_path):
    class Forbidden:
        name = "forbidden-worker"

        def implement(self, sandbox, context):
            return WorkerResult(ok=False, error="boundary_violation", summary="write not authorized")

    owner = make_owner(git_repo, tmp_path, worker=Forbidden())
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    try:
        result = owner.run()
        assert result.status == "FAILED", result.describe()
        assert owner.store.get_run(owner.run_id)["status"] == "FAILED"
        assert not branch_events(owner, "RepairBranchStarted")
        assert pending_validation(owner.store, owner.run_id) is None
        assert not result.promoted_commit
        with pytest.raises(ApprovalError):
            ApprovalService(owner.store, owner.fsm).approve(
                run_id=owner.run_id, step_id=owner.store.list_steps(owner.run_id)[0]["step_id"],
                decision="retry", approved_by="alice",
            )
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == original
    finally:
        owner.store.close()


def test_same_rejected_candidate_does_not_buy_the_same_review_again(git_repo, tmp_path):
    class Reject:
        def __init__(self):
            self.calls = 0

        def complete(self, prompt, *, subject_digest):
            self.calls += 1
            return json.dumps({"decision": "REVISE", "subject_digest": subject_digest,
                               "reasons": ["required behavior is missing"],
                               "violations": ["provide a different candidate satisfying the boundary"],
                               "confidence": 0.9})

    review = Reject()
    owner = make_owner(git_repo, tmp_path, worker=ScriptedWorker(
        ops=(FileOp("write", TARGET, CORRECT_IMPLEMENTATION),)))
    owner.tier2 = Tier2Gate(reviewer=review)
    try:
        result = owner.run()
        assert result.status == "FAILED", result.describe()
        assert review.calls == 1
        assert len(branch_events(owner, "RepairBranchStarted")) == 2
        assert len(branch_events(owner, "RepairBranchRejected")) == 2
        assert not branch_events(owner, "RepairBranchPromoted")
        assert not result.promoted_commit
        assert not pending_validation(owner.store, owner.run_id)
    finally:
        owner.store.close()


def test_changed_trunk_allows_the_same_patch_to_receive_fresh_review(git_repo, tmp_path):
    class Review(GoalReviewer):
        def __init__(self):
            super().__init__(["APPROVE"])
            self.node_reviews = 0

        def complete(self, prompt, *, subject_digest):
            if "FINAL GOAL audit" not in prompt:
                self.node_reviews += 1
                if self.node_reviews == 1:
                    return json.dumps({
                        "decision": "REVISE", "subject_digest": subject_digest,
                        "reasons": ["dependency state is not ready"],
                        "violations": ["revalidate after the other independent node commits"],
                        "confidence": 0.9,
                    })
            return super().complete(prompt, subject_digest=subject_digest)

    review = Review()
    owner = make_owner(git_repo, tmp_path, reviewer=review)
    original_criteria = owner.bundle.goal.acceptance_criteria
    side = AcceptanceCriterion("side", AssertionKind.FILE_CONTENT, path="side.txt", expect="ready")
    owner.bundle = replace(
        owner.bundle,
        goal=replace(owner.bundle.goal, acceptance_criteria=(*original_criteria, side)),
        plan=PlanSpec(plan_id="parallel-repair", goal_id=owner.bundle.goal.goal_id, nodes=(
            PlanNode(node_id="word", objective="word counting", expected_artifacts=(TARGET,),
                     extra={"acceptance_criteria": [c.to_dict() for c in original_criteria]}),
            PlanNode(node_id="side", objective="dependency", expected_artifacts=("side.txt",),
                     extra={"acceptance_criteria": [side.to_dict()]}),
        )),
        boundary=replace(owner.bundle.boundary, fs_whitelist=(TARGET, "side.txt")),
    )
    review.criteria = [c.criterion_id for c in owner.bundle.goal.acceptance_criteria]
    owner.register_spec()

    class Worker:
        name = "parallel-repair"

        def implement(self, sandbox, context):
            path, text = ((TARGET, CORRECT_IMPLEMENTATION) if context.node.node_id == "word"
                          else ("side.txt", "ready\n"))
            return ScriptedWorker(ops=(FileOp("write", path, text),)).implement(sandbox, context)

    owner.worker = Worker()
    owner.quota = replace(owner.quota, max_parallel_steps=2)
    try:
        result = owner.run()
        assert result.status == "COMPLETED", result.describe()
        assert review.node_reviews == 3
        branch = branch_events(owner, "RepairBranchStarted")[0]
        side_commit = next(event["commit"] for event in branch_events(owner, "TrunkNodeValidated")
                           if event["node_id"] == "side")
        assert branch["base_commit"] == side_commit
        assert len(branch_events(owner, "RepairBranchPromoted")) == 1
    finally:
        owner.store.close()


def test_step_and_goal_repairs_share_the_same_two_branch_allowance(git_repo, tmp_path):
    owner = owner_for(git_repo, tmp_path)
    initial_worker = owner.worker

    class Worker:
        name = "shared-repair-allowance"

        def implement(self, sandbox, context):
            if (context.node.node_id == "a" and context.attempt == 1
                    and not context.node.extra.get("repair_root_spec_digest")):
                return WorkerResult(ok=False, error="invalid_edit_plan", summary="stale edit")
            return initial_worker.implement(sandbox, context)

    owner.worker = Worker()
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE", result.describe()
        starts = branch_events(owner, "RepairBranchStarted")
        assert [branch["phase"] for branch in starts] == ["step", "goal"]
        assert initial_worker.repairs == ["b"]
        assert not result.promoted_commit
        assert pending_validation(owner.store, owner.run_id) is None
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == original
    finally:
        owner.store.close()


def test_local_goal_repair_does_not_request_human_review_before_root_delivery(git_repo, tmp_path):
    review = GoalReviewer(["REVISE", "APPROVE"])
    owner = make_owner(git_repo, tmp_path, reviewer=review)
    owner.manual_review_levels = ("normal",)
    try:
        result = owner.run()
        assert result.status == "AWAITING_APPROVAL", result.describe()
        assert [event["decision"] for event in branch_events(owner, "GoalAuditCompleted")] == [
            "REVISE", "APPROVE",
        ]
        branch = branch_events(owner, "RepairBranchStarted")[0]
        assert owner.store.get_run(branch["run_id"])["status"] == "COMPLETED"
        events = owner.store.events_for_execution(owner.execution_id)
        required = [i for i, event in enumerate(events)
                    if event.event_type == "IndependentValidationRequired"]
        audited = [i for i, event in enumerate(events)
                   if event.event_type == "GoalAuditCompleted"]
        assert len(required) == 1 and required[0] > audited[-1]
        assert all(row["state"] == "COMMITTED" for row in owner.store.list_steps(owner.run_id))
        assert not result.promoted_commit
    finally:
        owner.store.close()


@pytest.mark.parametrize("failure", ["unknown", "incomplete_unknown", "not_dispatched"])
def test_model_failure_never_retries_unknown_or_terminal_provider_usage(
    git_repo, tmp_path, failure,
):
    class Client:
        name = "local-failing-client"
        model = "offline"

        def __init__(self):
            self.calls = 0

        def complete(self, *args, **kwargs):
            self.calls += 1
            if failure == "incomplete_unknown":
                raise ModelResponseIncomplete("truncated without usage")
            raise ModelError("supplier failed", request_not_dispatched=failure == "not_dispatched")

    client = Client()
    owner = make_owner(git_repo, tmp_path, worker=ModelWorker(client))
    try:
        result = owner.run()
        assert result.status == "FAILED", result.describe()
        assert client.calls == 1
        assert not branch_events(owner, "RepairBranchStarted")
        assert pending_validation(owner.store, owner.run_id) is None
        failure_event = branch_events(owner, "StepExecutionFailed")[-1]
        assert failure_event["error_code"] == (
            "model_call_failed" if failure == "not_dispatched" else "model_usage_unknown"
        )
    finally:
        owner.store.close()
