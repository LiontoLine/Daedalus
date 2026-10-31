"""Goal fulfillment must gate delivery independently of step compliance."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.goal_audit import goal_audit_view
from daedalus.application.gatekeeper.tier2 import Tier2Gate
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.resume import ResumeError, resume_run
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, PlanNode, PlanSpec
from daedalus.infrastructure.git_sandbox import _git
from daedalus.infrastructure.store import EventStore
from tests.conftest import TARGET, TEST_COMMAND, CORRECT_IMPLEMENTATION


class GoalReviewer:
    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.goals = 0
        self.step_reviews = 0
        self.criteria = []

    def complete(self, prompt, *, subject_digest):
        goal = "FINAL GOAL audit" in prompt
        decision = self.outcomes[min(self.goals, len(self.outcomes) - 1)] if goal else "APPROVE"
        if goal:
            self.goals += 1
        else:
            self.step_reviews += 1
        answer = {
            "decision": decision,
            "subject_digest": subject_digest,
            "reasons": ["evaluated original goal against integrated change"],
            "violations": ["add the missing goal behavior"] if decision == "REVISE" else [],
            "confidence": 0.9,
        }
        if goal:
            answer["criterion_results"] = [
                {
                    "criterion_id": c,
                    "status": "UNMET" if decision == "REVISE" else "MET",
                    "evidence": "cumulative diff and executable criterion",
                }
                for c in self.criteria
            ]
        return json.dumps(answer)


def make_owner(git_repo, tmp_path, reviewer=None, worker=None):
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="r",
            goal_id="G",
            objective="fix word counting",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
        )
    )
    if reviewer:
        reviewer.criteria = [c.criterion_id for c in bundle.goal.acceptance_criteria]
    if worker is None:

        class StageWorker:
            name = "stage-worker"

            def __init__(self):
                self.feedback = []

            def implement(self, sandbox, context):
                self.feedback.append(context.revision_feedback)
                return ScriptedWorker(
                    ops=(
                        FileOp(
                            op="write",
                            path=TARGET,
                            content=CORRECT_IMPLEMENTATION + f"\n# stage {len(self.feedback)}\n",
                        ),
                    )
                ).implement(sandbox, context)

        worker = StageWorker()
    store = EventStore(tmp_path / "audit.db")
    owner = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "trees",
        bundle=bundle,
        worker=worker,
        tier2=Tier2Gate(reviewer=reviewer) if reviewer else None,
        goal_audit_enabled=True,
        retry_backoff_sec=0,
    )
    owner.register_spec()
    return owner


def test_goal_drift_starts_new_stage_before_target_promotion(git_repo, tmp_path):
    reviewer = GoalReviewer(["REVISE", "APPROVE"])
    owner = make_owner(git_repo, tmp_path, reviewer)
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    seen = []
    complete = reviewer.complete

    def observe(prompt, *, subject_digest):
        from daedalus.model.base import Completion

        owner.budget.record(Completion(text="", completion_tokens=10))
        if "FINAL GOAL audit" in prompt:
            seen.append(_git(git_repo, ["rev-parse", "main"], check=True).stdout.strip())
        return complete(prompt, subject_digest=subject_digest)

    reviewer.complete = observe
    try:
        result = owner.run()
        assert result.status == "COMPLETED", result.describe()
        assert reviewer.goals == 2 and reviewer.step_reviews == 2
        assert owner.budget.run_used == 40 and result.tokens_used == 40
        assert seen == [original, original]
        assert result.promoted_commit != original
        view = goal_audit_view(owner.store, owner.run_id)
        assert [s["decision"] for s in view["stages"]] == ["REVISE", "APPROVE"]
        assert len(view["iterations"]) == 1
        assert "missing goal behavior" in owner.worker.feedback[1]
        child = owner.store.get_run(view["iterations"][0]["run_id"])
        assert child["execution_id"] != owner.execution_id
        child_spec = json.loads(owner.store.get_spec(child["spec_digest"])["document"])
        assert child_spec["spec_01_goal"] == owner.bundle.goal.to_dict()
        assert child_spec["spec_03_boundary"] == owner.bundle.boundary.to_dict()
        assert child_spec["meta_spec"] == owner.bundle.meta.to_dict()
        assert child_spec["parent_spec_digest"] == owner.spec_digest
        assert not owner.store.verify_sequences()
    finally:
        owner.store.close()


def test_three_total_stages_stop_and_cannot_reset_by_resume(git_repo, tmp_path):
    owner = make_owner(git_repo, tmp_path, GoalReviewer(["REVISE"]))
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE"
        view = goal_audit_view(owner.store, owner.run_id)
        assert len(view["stages"]) == 3 and len(view["iterations"]) == 2, view
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == original
        assert not result.promoted_commit
        assert view["status"] == "ESCALATE"
        with pytest.raises(ResumeError):
            resume_run(store=owner.store, run_id=owner.run_id, workspace=str(tmp_path))
    finally:
        owner.store.close()


def test_inconclusive_goal_review_does_not_iterate(git_repo, tmp_path):
    reviewer = GoalReviewer(["APPROVE"])
    owner = make_owner(git_repo, tmp_path, reviewer)
    original_complete = reviewer.complete

    def missing_evidence(prompt, *, subject_digest):
        response = json.loads(original_complete(prompt, subject_digest=subject_digest))
        response.pop("criterion_results", None)
        return json.dumps(response)

    reviewer.complete = missing_evidence
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE"
        assert len(goal_audit_view(owner.store, owner.run_id)["stages"]) == 1
        assert not goal_audit_view(owner.store, owner.run_id)["iterations"]
    finally:
        owner.store.close()


def test_scripted_tasks_report_acceptance_only_not_semantic_pass(git_repo, tmp_path):
    owner = make_owner(git_repo, tmp_path)
    try:
        result = owner.run()
        assert result.status == "COMPLETED", result.describe()
        assert result.goal_audit["stages"][0]["scope"] == "acceptance_only"
    finally:
        owner.store.close()


def test_final_goal_criteria_are_rechecked_after_all_nodes(git_repo, tmp_path):
    owner = make_owner(git_repo, tmp_path)
    a = AcceptanceCriterion(
        criterion_id="a", kind=AssertionKind.FILE_CONTENT, path=TARGET, expect="first"
    )
    b = AcceptanceCriterion(
        criterion_id="b", kind=AssertionKind.FILE_CONTENT, path=TARGET, expect="second"
    )
    owner.bundle = replace(
        owner.bundle,
        goal=replace(owner.bundle.goal, acceptance_criteria=(a, b)),
        plan=PlanSpec(
            plan_id="p",
            goal_id="G",
            nodes=(
                PlanNode(
                    node_id="a",
                    expected_artifacts=(TARGET,),
                    extra={"acceptance_criteria": [a.to_dict()]},
                ),
                PlanNode(
                    node_id="b",
                    deps=("a",),
                    expected_artifacts=(TARGET,),
                    extra={"acceptance_criteria": [b.to_dict()]},
                ),
            ),
        ),
    )

    class OverwritingWorker:
        name = "overwriter"

        def implement(self, sandbox, context):
            text = (
                "first second"
                if context.revision_feedback
                else "first"
                if context.node.node_id == "a"
                else "second"
            )
            return ScriptedWorker(
                ops=(FileOp(op="write", path=TARGET, content=f"# {text}\n"),)
            ).implement(sandbox, context)

    owner.worker = OverwritingWorker()
    owner.register_spec()
    try:
        result = owner.run()
        assert result.status == "COMPLETED"
        stages = goal_audit_view(owner.store, owner.run_id)["stages"]
        assert len(stages) == 2
        assert [s["decision"] for s in stages] == ["REVISE", "APPROVE"]
        assert all(s["deterministic"]["evidence"]["criteria_source"] == "goal" for s in stages)
        assert result.promoted_commit
    finally:
        owner.store.close()


@pytest.mark.parametrize(
    "failure", ["wrong_subject", "unknown", "transport", "contradictory_revision"]
)
def test_goal_review_uncertainty_never_promotes_or_restarts(git_repo, tmp_path, failure):
    reviewer = GoalReviewer(["APPROVE"])
    owner = make_owner(git_repo, tmp_path, reviewer)
    complete = reviewer.complete

    def uncertain(prompt, *, subject_digest):
        answer = json.loads(complete(prompt, subject_digest=subject_digest))
        if "FINAL GOAL audit" in prompt:
            if failure == "transport":
                raise RuntimeError("reviewer unavailable")
            if failure == "wrong_subject":
                answer["subject_digest"] = "different-tree"
            if failure == "unknown":
                answer["criterion_results"][0]["status"] = "UNKNOWN"
            if failure == "contradictory_revision":
                answer["decision"] = "REVISE"
                answer["violations"] = ["claimed mismatch without an unmet criterion"]
        return json.dumps(answer)

    reviewer.complete = uncertain
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE"
        assert not result.promoted_commit
        assert not goal_audit_view(owner.store, owner.run_id)["iterations"]
    finally:
        owner.store.close()


def test_goal_budget_exhaustion_does_not_call_reviewer(git_repo, tmp_path):
    reviewer = GoalReviewer(["APPROVE"])
    owner = make_owner(git_repo, tmp_path, reviewer)
    owner.budget.max_tokens_per_run = 1
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE"
        assert reviewer.goals == 0
        assert not result.promoted_commit
    finally:
        owner.store.close()




def test_new_high_risk_repair_plan_cannot_reuse_original_approval(git_repo, tmp_path):
    from daedalus.domain.spec import RiskLevel

    reviewer = GoalReviewer(["REVISE"])
    owner = make_owner(git_repo, tmp_path, reviewer)
    owner.bundle = replace(owner.bundle, goal=replace(owner.bundle.goal, risk_level=RiskLevel.HIGH))
    owner.register_spec()
    owner.approve_spec(approved_by="operator")
    try:
        result = owner.run()
        view = goal_audit_view(owner.store, owner.run_id)
        assert result.status == "PARTIAL_FAILURE" and not result.promoted_commit
        child_spec = view["iterations"][0]["spec_digest"]
        assert not owner.store.is_spec_approved(child_spec)
        assert view["iterations"][0]["exists"] is False
    finally:
        owner.store.close()
