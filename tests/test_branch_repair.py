"""Actual Git/FSM branch repairs: accumulate progress without publishing rejected work."""

import json
from dataclasses import replace

import pytest

from daedalus.application.coding_worker import FileOp, ModelWorker, ScriptedWorker
from daedalus.application.trunk_view import trunk_view
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, PlanNode, PlanSpec
from daedalus.infrastructure.git_sandbox import _git
from daedalus.model.base import Completion
from tests.test_goal_audit import make_owner


def owner_for(git_repo, tmp_path, mode="partial"):
    owner = make_owner(git_repo, tmp_path)
    preserve_old = mode in {"regression", "frozen-regression"}
    criteria = tuple(
        AcceptanceCriterion(criterion_id=name, kind=AssertionKind.FILE_CONTENT,
                            path=f"{name}.py", expect=f"{name.upper()}_OK")
        for name in "abc"
    )
    if mode == "regression":
        criteria = (criteria[0], replace(criteria[1], expect="new"),
                    replace(criteria[2], path="b.py", expect="old"))
    elif preserve_old:
        criteria = (criteria[0], replace(criteria[1], expect="new"), criteria[2])
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
            self.repair_memory = []

        def implement(self, sandbox, context):
            name = context.node.node_id
            repair = bool(context.node.extra.get("repair_root_spec_digest"))
            owner.budget.record(Completion("", prompt_tokens=30, completion_tokens=10))
            text = f"# {name.upper()}_OK\n"
            operations = []
            if preserve_old and name == "b":
                text = "# new old\n"
            if repair:
                self.repairs.append(name)
                self.repair_memory.append(context.repair_memory)
                self.targets_during_repair.append(
                    _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
                )
                if mode == "reject" and name == "b":
                    text = "# still wrong\n"
                if mode == "boundary":
                    operations.append(FileOp("write", "a.py", "# unauthorized repair scope\n"))
                if preserve_old and name == "b" and len(self.repairs) == 1:
                    text = "# new\n"
            elif name == "c":
                operations.append(FileOp("write", "b.py", "# old\n" if preserve_old else "# broken\n"))
                if not preserve_old:
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


def test_rejected_branch_retains_base_then_tries_another_attributable_node(git_repo, tmp_path, monkeypatch):
    from tests.test_agentic_rag import Controller

    owner = owner_for(git_repo, tmp_path, "reject")
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    original_implement = owner.worker.implement
    client = Controller([{"operations": [{"op": "write", "path": "a.py", "content": "# A_OK\n"}]}])
    next_worker = ModelWorker(client, budget=owner.budget)

    def capture_next_repair(sandbox, context):
        if context.node.node_id == "a" and context.node.extra.get("repair_root_spec_digest"):
            return next_worker.implement(sandbox, context)
        return original_implement(sandbox, context)

    monkeypatch.setattr(owner.worker, "implement", capture_next_repair)
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE" and not result.promoted_commit
        assert owner.worker.repairs == ["b"]
        rejected = events(owner, "RepairBranchRejected")
        promoted = events(owner, "RepairBranchPromoted")
        assert len(rejected) == len(promoted) == 1
        assert [branch["node_id"] for branch in (rejected[0], promoted[0])] == ["b", "a"]
        messages, = client.calls
        assert "still wrong" not in messages[-1].content
        assert rejected[0]["branch_id"] not in messages[-1].content
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


@pytest.mark.parametrize("prior_unmet", [False, True])
@pytest.mark.parametrize("interrupted", [False, True])
def test_frozen_preservation_requires_a_settled_counterexample_to_retry_same_owner(
    git_repo, tmp_path, interrupted, prior_unmet,
):
    from daedalus.application.requirement_evidence import bind_bundle, qualify, seal

    owner = owner_for(git_repo, tmp_path, "frozen-regression")
    driver = owner.isolation.driver
    boundary = replace(owner.bundle.boundary, isolation=driver.name)
    owner.bundle = replace(owner.bundle, boundary=boundary)
    changed_path, marker = ("b.py", "new") if prior_unmet else ("c.py", "C_OK")
    invariant = ("raise RuntimeError('private verifier interruption')" if interrupted
                 else "self.fail('private invariant failure')")
    contract = seal({
        "version": 1, "objective": owner.bundle.goal.objective, "open_questions": [],
        "requirements": [{"id": "R1", "statement": "Complete the change while preserving the old marker"}],
        "checks": [
            {"test_name": "test_create", "requirement_id": "R1", "role": "change"},
            {"test_name": "test_preserve", "requirement_id": "R1", "role": "invariant"},
        ],
        "source": f"""import unittest
from pathlib import Path

class RequirementTests(unittest.TestCase):
    def test_create(self):
        path = Path({changed_path!r})
        self.assertTrue(path.exists() and {marker!r} in path.read_text())

    def test_preserve(self):
        path = Path('b.py')
        if path.exists() and 'old' not in path.read_text():
            {invariant}
""",
    })
    proof = qualify(git_repo, contract, list(boundary.fs_whitelist), boundary,
                    tmp_path / "frozen-baseline", driver=driver)
    owner.bundle = bind_bundle(owner.bundle, contract, proof)
    criterion = owner.bundle.goal.acceptance_criteria[-1]
    if prior_unmet:
        plan = owner.bundle.plan
        nodes = []
        for node in plan.nodes:
            checks = [item for item in node.acceptance_criteria if item != criterion]
            if node.node_id == "b":
                checks.append(criterion)
            nodes.append(replace(node, extra={**node.extra, "acceptance_criteria": [
                item.to_dict() for item in checks
            ]}))
        owner.bundle = replace(owner.bundle, plan=replace(plan, nodes=tuple(nodes)))
    owner.register_spec()
    baseline = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    try:
        result = owner.run()
        assert owner.worker.repairs == (["b"] if interrupted else ["b", "b"])
        assert (result.status == "COMPLETED") is not interrupted, result.describe()
        assert (_git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() != baseline) is not interrupted
        rejected, = events(owner, "RepairBranchRejected")
        criterion_id = criterion.criterion_id
        receipt = next(row for row in rejected["historical_child_evidence"]["validation"]
                       if row["criterion_id"] == criterion_id)
        assert receipt["executed"] is not interrupted
        assert receipt["ok"] is (None if interrupted else False)
        assert "private" not in json.dumps(receipt)
        expected_statuses = {"change": "UNKNOWN", "invariant": "UNKNOWN"} if interrupted else {
            "change": "MET", "invariant": "UNMET",
        }
        assert {row["role"]: row["status"] for row in receipt["behavior_outcomes"]} == expected_statuses
        if not interrupted:
            recalled = next(row for row in owner.worker.repair_memory[-1]
                            if row.get("evidence_kind") == "rejected_child_failure")
            projected = next(row for row in recalled["validation"] if row["criterion_id"] == criterion_id)
            assert projected["behavior_outcomes"] == receipt["behavior_outcomes"]
            assert "test_preserve" not in json.dumps(recalled)
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


def test_rejected_native_child_evidence_reaches_next_model_prompt_despite_long_original_feedback(
    git_repo, tmp_path, monkeypatch,
):
    from daedalus.application import branch_repair

    owner = owner_for(git_repo, tmp_path, "reject")
    native = AcceptanceCriterion(
        "native-b", AssertionKind.TEST_RESULT, command="python3 b.py",
        statement="b must execute without an assertion failure",
    )
    owner.bundle = replace(
        owner.bundle,
        goal=replace(owner.bundle.goal, acceptance_criteria=(
            *owner.bundle.goal.acceptance_criteria, native,
        )),
        plan=replace(owner.bundle.plan, nodes=tuple(
            replace(node, extra={**node.extra, "acceptance_criteria": [
                *(criterion.to_dict() for criterion in node.acceptance_criteria),
                native.to_dict(),
            ]}) if node.node_id == "b" else node
            for node in owner.bundle.plan.nodes
        )),
    )
    owner.register_spec()
    original_worker = owner.worker
    prompts = []

    class Client:
        def __init__(self, node_id):
            self.node_id = node_id

        def complete(self, messages, **kwargs):
            prompts.append((self.node_id, messages[-1].content))
            content = (
                "raise AssertionError('native_branch_failure')\n"
                if self.node_id == "b" and len(prompts) == 1
                else f"# {self.node_id.upper()}_OK\n"
            )
            return Completion(json.dumps({"operations": [{
                "op": "write", "path": f"{self.node_id}.py", "content": content,
            }]}), prompt_tokens=20, completion_tokens=20)

    class Worker:
        name = "repair-model-consumer"

        def implement(self, sandbox, context):
            if not context.node.extra.get("repair_root_spec_digest"):
                return original_worker.implement(sandbox, context)
            return ModelWorker(
                Client(context.node.node_id), budget=owner.budget,
            ).implement(sandbox, context)

    owner.worker = Worker()
    original_audit = branch_repair.audit_delivery

    def long_original_feedback(*args, **kwargs):
        reviewed = original_audit(*args, **kwargs)
        return {**reviewed, "required_changes": ["original issue explanation " * 2000]}

    monkeypatch.setattr(branch_repair, "audit_delivery", long_original_feedback)
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE", result.describe()
        # The new native counterexample keeps the existing same-owner retry policy.
        assert [name for name, _ in prompts] == ["b", "b"]
        prompt = prompts[-1][1]
        stage_feedback = events(owner, "GoalStageStarted")[-1]["feedback"]
        assert "Frozen failure evidence:" in stage_feedback
        assert prompt.count(stage_feedback) == 1
        assert stage_feedback in prompt.split("PREVIOUS ATTEMPT FEEDBACK", 1)[1]
        section = prompt.split("SCOPED REPAIR MEMORY", 1)[1].split("\n", 1)[1]
        memory, _ = json.JSONDecoder().raw_decode(section)
        rejected = next(row for row in memory if row.get("evidence_kind") == "rejected_child_failure")
        branch = events(owner, "RepairBranchRejected")[0]
        assert rejected["source_run_id"] == branch["run_id"]
        assert rejected["source_execution_id"] == owner.store.get_run(branch["run_id"])["execution_id"]
        assert rejected["source_spec_digest"] == branch["spec_digest"]
        assert rejected["root_spec_digest"] == owner.spec_digest
        assert rejected["base_commit"] == branch["base_commit"]
        assert rejected["historical"] and rejected["approved"] is False
        assert rejected["branch_status"] == "REJECTED"
        assert rejected["candidate_tree"] and rejected["patch_digest"]
        assert "native_branch_failure" in rejected["patch"]
        native_receipt = next(row for row in rejected["validation"] if row["criterion_id"] == "native-b")
        assert native_receipt["ok"] is False and native_receipt["kind"] == "test_result"
        assert native_receipt["exit_code"] != 0
        assert "native_branch_failure" in (
            native_receipt["output"] + rejected["observation"] + rejected["patch"]
        )
        child_failure = next(event.payload for event in owner.store.events_for_execution(
            rejected["source_execution_id"]
        ) if event.event_type == "TrunkNodeFailed" and event.payload.get("patch_digest"))
        assert rejected["error_code"] == child_failure["error_code"]
        assert rejected["candidate_tree"] == child_failure["candidate_tree"]
        assert len(json.dumps(memory, ensure_ascii=False)) <= 6200
        assert not result.promoted_commit
    finally:
        owner.store.close()


def test_rejected_child_projection_redacts_and_bounds_actual_model_context(git_repo, tmp_path):
    from types import SimpleNamespace

    from daedalus.application.branch_repair import _ScopedWorker, rejected_child_evidence
    from daedalus.infrastructure.git_sandbox import GitSandbox
    from tests.test_agent_investigation import context_for

    credential = "sk-" + "A" * 32
    event = SimpleNamespace(
        event_id="failure-event",
        event_type="TrunkNodeFailed",
        payload={
            "node_id": "owner", "patch_digest": "patch-digest", "candidate_tree": "rejected-tree",
            "error_code": "worker_validation_failed",
            "reason": "native failure " + credential,
            "detail": "failure detail " * 10000 + credential,
            "patch": "+ failing source " + credential + '\n"\\' * 10000,
        },
    )
    child = SimpleNamespace(
        run_id="rejected-run", execution_id="rejected-execution",
        store=SimpleNamespace(events_for_execution=lambda _: [event]),
    )
    evidence = rejected_child_evidence(child, {
        "node_id": "owner", "branch_id": "rejected-branch", "spec_digest": "child-spec",
        "root_spec_digest": "root-spec", "base_commit": "accepted-base",
    }, [
        {"criterion_id": f"check-{index}", "ok": False, "executed": True,
         "output": credential + "failure " * 10000}
        for index in range(30)
    ], [credential + "required change " * 10000] * 10)
    serialized = json.dumps(evidence, ensure_ascii=False)
    assert credential not in serialized
    assert evidence["truncated"] and evidence["validation_rows_omitted"] > 0
    assert len(serialized) <= 5500
    prompts = []

    class Client:
        def complete(self, messages, **kwargs):
            prompts.append(messages[-1].content)
            return Completion('{"operations":[]}', prompt_tokens=10, completion_tokens=10)

    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "projection", name="consumer")
    try:
        context = context_for(box)
        context = replace(context, repair_memory=tuple(
            {"observation": "older failure " * 2000} for _ in range(10)
        ), revision_feedback="original failure " * 3000)
        _ScopedWorker(
            ModelWorker(Client()), context.writable_paths, (evidence,),
        ).implement(box, context)
        assert len(prompts) == 1 and credential not in prompts[0]
        section = prompts[0].split("SCOPED REPAIR MEMORY", 1)[1].split("\n", 1)[1]
        memory, _ = json.JSONDecoder().raw_decode(section)
        assert any(row.get("branch_id") == "rejected-branch" for row in memory)
        assert len(json.dumps(memory, ensure_ascii=False)) <= 6200
    finally:
        box.remove()


@pytest.mark.parametrize("restriction", ["whitelist", "denylist", "protected", "meta_writable"])
def test_existing_unauthorized_artifact_cannot_become_goal_repair_write_authority(
    git_repo, tmp_path, restriction,
):
    from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
    from tests.test_goal_audit import GoalReviewer

    outside = "outside/user_data.txt"
    original_text = "user-owned content\n"
    (git_repo / outside).parent.mkdir()
    (git_repo / outside).write_text(original_text)
    _git(git_repo, ["add", outside], check=True)
    _git(git_repo, ["commit", "-m", "retain existing out-of-scope artifact"], check=True)
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    notes = git_repo / "user-notes.txt"
    notes.write_text("untracked user notes\n")
    calls = []

    class Worker:
        name = "declared-artifact-is-not-authority"

        def implement(self, sandbox, context):
            calls.append(context)
            operations = [FileOp("write", TARGET, CORRECT_IMPLEMENTATION)]
            if context.node.extra.get("repair_root_spec_digest"):
                operations.append(FileOp("write", outside, "overwritten by repair\n"))
            return ScriptedWorker(ops=tuple(operations)).implement(sandbox, context)

    review = GoalReviewer(["REVISE", "APPROVE"])
    owner = make_owner(git_repo, tmp_path, reviewer=review, worker=Worker())
    node = owner.bundle.plan.nodes[0]
    boundary = owner.bundle.boundary
    meta = owner.bundle.meta
    if restriction != "whitelist":
        boundary = replace(boundary, fs_whitelist=(*boundary.fs_whitelist, outside))
    if restriction == "denylist":
        boundary = replace(boundary, fs_denylist=(*boundary.fs_denylist, outside))
    elif restriction == "protected":
        meta = replace(meta, protected_paths=(*meta.protected_paths, outside))
    elif restriction == "meta_writable":
        meta = replace(meta, agent_writable_paths=(TARGET,))
    owner.bundle = replace(
        owner.bundle, boundary=boundary, meta=meta,
        plan=replace(owner.bundle.plan, nodes=(
            replace(node, expected_artifacts=(*node.expected_artifacts, outside)),
        )),
    )
    owner.register_spec()
    frozen = owner.bundle.to_dict()
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE", result.describe()
        assert result.committed_count == 1  # Initial allowed edit legitimately passed.
        assert len(calls) == 1  # No repair worker or child gate received wider authority.
        assert review.goals == 1 and review.step_reviews == 1
        assert not events(owner, "RepairBranchStarted")
        assert not events(owner, "RepairBranchPromoted")
        assert "repair scope exceeds the frozen boundary" in events(
            owner, "GoalAuditEscalated",
        )[-1]["reason"]
        assert not result.promoted_commit
        assert owner.bundle.to_dict() == frozen
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == original
        assert _git(git_repo, ["show", f"main:{outside}"], check=True).stdout == original_text
        assert (git_repo / outside).read_text() == original_text
        assert notes.read_text() == "untracked user notes\n"
    finally:
        owner.store.close()


def test_nested_glob_whitelist_repairs_only_concrete_declared_outputs_and_delivers(
    git_repo, tmp_path,
):
    from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
    from tests.test_goal_audit import GoalReviewer

    calls = []

    class Worker:
        name = "nested-authorized-repair"

        def implement(self, sandbox, context):
            calls.append(context)
            return ScriptedWorker(ops=(
                FileOp("write", TARGET, CORRECT_IMPLEMENTATION + f"\n# stage {len(calls)}\n"),
            )).implement(sandbox, context)

    owner = make_owner(
        git_repo, tmp_path, reviewer=GoalReviewer(["REVISE", "APPROVE"]), worker=Worker(),
    )
    owner.bundle = replace(
        owner.bundle, boundary=replace(owner.bundle.boundary, fs_whitelist=("src/**",)),
    )
    owner.register_spec()
    frozen = owner.bundle.to_dict()
    try:
        result = owner.run()
        assert result.status == "COMPLETED", result.describe()
        assert len(calls) == 2
        assert calls[0].bundle.boundary.fs_whitelist == ("src/**",)
        assert calls[1].bundle.boundary.fs_whitelist == (TARGET,)
        assert len(events(owner, "RepairBranchPromoted")) == 1
        assert "# stage 2" in _git(git_repo, ["show", f"main:{TARGET}"], check=True).stdout
        assert owner.bundle.to_dict() == frozen
    finally:
        owner.store.close()


def test_goal_repair_gate_rejects_raw_worker_writes_outside_selected_artifacts(
    git_repo, tmp_path,
):
    from daedalus.application.worker import WorkerResult
    from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
    from tests.test_goal_audit import GoalReviewer

    calls = []
    sibling = "sibling.txt"

    class Worker:
        name = "untrusted-raw-repair-writer"

        def implement(self, sandbox, context):
            calls.append(context)
            sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION + f"\n# stage {len(calls)}\n")
            if context.node.extra.get("repair_root_spec_digest"):
                # Deliberately bypass the worker's guard: Tier-1 remains authoritative.
                sandbox.write_file(sibling, "not a selected repair artifact\n")
            return WorkerResult(ok=True, summary="raw candidate")

    review = GoalReviewer(["REVISE", "APPROVE"])
    owner = make_owner(git_repo, tmp_path, reviewer=review, worker=Worker())
    owner.bundle = replace(
        owner.bundle, boundary=replace(owner.bundle.boundary, fs_whitelist=("src/**", sibling)),
    )
    owner.register_spec()
    original = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    try:
        result = owner.run()
        assert result.status == "PARTIAL_FAILURE", result.describe()
        assert len(calls) == 2 and calls[1].bundle.boundary.fs_whitelist == (TARGET,)
        assert review.step_reviews == 1  # The child deterministic failure never reaches Tier-2.
        assert len(events(owner, "RepairBranchRejected")) == 1
        assert not events(owner, "RepairBranchPromoted")
        child_id = events(owner, "RepairBranchStarted")[0]["run_id"]
        child_step = owner.store.list_steps(child_id)[0]["step_id"]
        checks = [
            check
            for gate in owner.store.gate_results_for_step(child_step) if gate["tier"] == 1
            for check in json.loads(gate["evidence"])["checks"]
        ]
        assert any(not check["passed"] and sibling in json.dumps(check) for check in checks)
        assert not result.promoted_commit
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == original
        assert not (git_repo / sibling).exists()
    finally:
        owner.store.close()


@pytest.mark.parametrize("path", ["outside/user_data.txt", "src/**"])
def test_scoped_worker_refuses_unauthorized_or_pattern_scope_before_dispatch(
    git_repo, tmp_path, path,
):
    from daedalus.application.branch_repair import _ScopedWorker
    from daedalus.errors import BoundaryViolation
    from daedalus.infrastructure.git_sandbox import GitSandbox
    from tests.test_agent_investigation import context_for

    calls = []

    class Worker:
        def implement(self, sandbox, context):
            calls.append(context)
            sandbox.write_file("outside/user_data.txt", "unauthorized\n")

    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "scope", name="consumer")
    try:
        with pytest.raises(BoundaryViolation):
            _ScopedWorker(Worker(), (path,)).implement(box, context_for(box))
        assert not calls
        assert not box.changed_files()
        assert not box.exists("outside/user_data.txt")
    finally:
        box.remove()
