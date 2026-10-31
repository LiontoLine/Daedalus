"""Actual Git/FSM branch repairs: accumulate progress without publishing rejected work."""

from dataclasses import replace

import pytest

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.trunk_view import trunk_view
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, PlanNode, PlanSpec
from daedalus.infrastructure.git_sandbox import _git
from daedalus.model.base import Completion
from tests.test_goal_audit import make_owner


def owner_for(git_repo, tmp_path, mode="partial"):
    owner = make_owner(git_repo, tmp_path)
    criteria = tuple(
        AcceptanceCriterion(criterion_id=name, kind=AssertionKind.FILE_CONTENT,
                            path=f"{name}.py", expect=f"{name.upper()}_OK")
        for name in "abc"
    )
    if mode == "regression":
        criteria = (criteria[0], replace(criteria[1], expect="new"),
                    replace(criteria[2], path="b.py", expect="old"))
    nodes = tuple(
        PlanNode(node_id=name, objective=f"Implement {name}", expected_artifacts=(f"{name}.py",),
                 deps=("a", "b") if name == "c" else (),
                 extra={"acceptance_criteria": [criterion.to_dict()]})
        for name, criterion in zip("abc", criteria, strict=True)
    )
    owner.bundle = replace(
        owner.bundle,
        goal=replace(owner.bundle.goal, acceptance_criteria=criteria),
        plan=PlanSpec(plan_id="repair-dag", goal_id=owner.bundle.goal.goal_id, nodes=nodes),
        boundary=replace(owner.bundle.boundary, fs_whitelist=("a.py", "b.py", "c.py")),
    )
    owner.quota = replace(owner.quota, max_parallel_steps=1)
    owner.register_spec()

    class Worker:
        name = "branch-behavior-worker"

        def __init__(self):
            self.repairs = []
            self.targets_during_repair = []

        def implement(self, sandbox, context):
            name = context.node.node_id
            repair = bool(context.node.extra.get("repair_root_spec_digest"))
            owner.budget.record(Completion("", prompt_tokens=30, completion_tokens=10))
            text = f"# {name.upper()}_OK\n"
            operations = []
            if mode == "regression" and name == "b":
                text = "# new old\n"
            if repair:
                self.repairs.append(name)
                self.targets_during_repair.append(
                    _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
                )
                if mode == "reject" and name == "b":
                    text = "# still wrong\n"
                if mode == "boundary":
                    operations.append(FileOp("write", "a.py", "# unauthorized repair scope\n"))
                if mode == "regression" and name == "b" and len(self.repairs) == 1:
                    text = "# new\n"
            elif name == "c":
                operations.append(FileOp("write", "b.py", "# old\n" if mode == "regression" else "# broken\n"))
                if mode != "regression":
                    operations.append(FileOp("write", "a.py", "# broken\n"))
            operations.append(FileOp("write", f"{name}.py", text))
            return ScriptedWorker(ops=tuple(operations)).implement(sandbox, context)

    owner.worker = Worker()
    return owner


def events(owner, kind):
    return [event.payload for event in owner.store.events_for(f"goal:{owner.run_id}")
            if event.event_type == kind]


def test_independent_repairs_accumulate_on_promoted_trunk_before_real_delivery(git_repo, tmp_path):
    owner = owner_for(git_repo, tmp_path)
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    frozen = owner.bundle.to_dict()
    try:
        result = owner.run()
        assert result.status == "COMPLETED", result.describe()
        assert owner.worker.repairs == ["b", "a"]
        assert owner.worker.targets_during_repair == [original, original]
        branches = events(owner, "RepairBranchPromoted")
        assert len(branches) == 2
        assert branches[1]["base_commit"] == branches[0]["commit"]
        assert [row["decision"] for row in events(owner, "GoalAuditCompleted")] == ["REVISE", "REVISE", "APPROVE"]
        assert owner.bundle.to_dict() == frozen
        for name in "abc":
            assert f"{name.upper()}_OK" in _git(git_repo, ["show", f"main:{name}.py"], check=True).stdout
        assert result.tokens_used == owner.budget.run_used == 200
        assert owner.budget.calls == 5  # Only the worker's existing calls; no scoring role.
        view = trunk_view(owner.store, owner.run_id)
        assert view["commit"] == result.promoted_commit
        assert all(node["status"] == "MET" for node in view["nodes"])
        assert not owner.store.verify_sequences()
    finally:
        owner.store.close()


def test_rejected_branch_retains_base_then_tries_another_attributable_node(git_repo, tmp_path):
    owner = owner_for(git_repo, tmp_path, "reject")
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE" and not result.promoted_commit
        assert owner.worker.repairs == ["b", "a"]
        rejected = events(owner, "RepairBranchRejected")
        promoted = events(owner, "RepairBranchPromoted")
        assert len(rejected) == len(promoted) == 1
        assert rejected[0]["base_commit"] == promoted[0]["base_commit"]
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == original
        view = trunk_view(owner.store, owner.run_id)
        assert [branch["status"] for branch in view["branches"]] == ["REJECTED", "PROMOTED"]
        assert view["commit"] == promoted[0]["commit"]
        failed_child = owner.store.get_run(rejected[0]["run_id"])
        retained = [event.payload for event in owner.store.events_for_execution(failed_child["execution_id"])
                    if event.event_type == "TrunkNodeFailed" and event.payload.get("patch")]
        assert retained and "still wrong" in retained[-1]["patch"]
        assert rejected[0]["validation"]["criteria"][0]["ok"] is False
    finally:
        owner.store.close()


def test_new_nonregression_counterexample_allows_a_distinct_repair_hypothesis(git_repo, tmp_path):
    owner = owner_for(git_repo, tmp_path, "regression")
    try:
        result = owner.run()
        assert result.status == "COMPLETED", result.describe()
        assert owner.worker.repairs == ["b", "b"]
        rejected = events(owner, "RepairBranchRejected")
        assert len(rejected) == 1
        assert any(row["criterion_id"] == "c" and row["ok"] is False
                   for row in rejected[0]["validation"]["criteria"])
        promoted = events(owner, "RepairBranchPromoted")
        assert len(promoted) == 1 and promoted[0]["base_commit"] == rejected[0]["base_commit"]
        assert "new old" in _git(git_repo, ["show", "main:b.py"], check=True).stdout
    finally:
        owner.store.close()


def test_nonretryable_scope_violation_stops_without_touching_trunk(git_repo, tmp_path):
    owner = owner_for(git_repo, tmp_path, "boundary")
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE"
        assert owner.worker.repairs == ["b"]
        assert not events(owner, "RepairBranchPromoted")
        assert len(events(owner, "RepairBranchRejected")) == 1
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == original
        view = trunk_view(owner.store, owner.run_id)
        assert view["commit"] == events(owner, "RepairBranchStarted")[0]["base_commit"]
    finally:
        owner.store.close()


def test_rebased_trunk_evidence_names_the_gate_for_the_committed_artifact(git_repo, tmp_path):
    owner = owner_for(git_repo, tmp_path)
    owner.quota = replace(owner.quota, max_parallel_steps=2)

    class Worker:
        name = "parallel-frozen-evidence"

        def implement(self, sandbox, context):
            name = context.node.node_id
            return ScriptedWorker(ops=(
                FileOp("write", f"{name}.py", f"# {name.upper()}_OK\n"),
            )).implement(sandbox, context)

    owner.worker = Worker()
    try:
        result = owner.run()
        assert result.status == "COMPLETED" and result.rebase_count == 1
        rebased = next(step for step in result.steps if step.rebased)
        evidence = next(
            event.payload for event in owner.store.events_for(f"run:{owner.run_id}")
            if event.event_type == "TrunkNodeValidated"
            and event.payload["node_id"] == rebased.node_id
        )
        recorded = next(
            gate for gate in owner.store.gate_results_for_step(rebased.step_id)
            if gate["gate_result_id"] == evidence["gate_result_id"]
        )
        assert recorded["artifact_digest"] == rebased.artifact_digest
    finally:
        owner.store.close()
