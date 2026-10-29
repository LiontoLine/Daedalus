"""Selective replay: re-executing only what the change actually invalidated (Spec §13.1 B).

The tension these tests resolve: §13.2 requires a spec digest match before any artifact may be
reused, while §13.1 B asks for "changed nodes -> downstream closure -> STALE -> selective
replay". If the reuse key carried the whole-bundle digest, any change anywhere would invalidate
everything and selective replay could never happen. The key therefore carries a **node-level**
subject digest, and the tests below pin down exactly which changes invalidate which nodes.

They also pin the other direction: a change *upstream* of a node must still invalidate it, or
selective replay would be unsound rather than merely coarse.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from daedalus.application.artifact_cache import ArtifactCache, ReuseKey
from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest, SpecHardening
from daedalus.application.replay import ChangeKind, classify_spec_change, plan_selective_replay
from daedalus.application.scheduler import Quota, Scheduler
from daedalus.application.fsm_service import StateMachineService
from daedalus.domain.fsm import StepState
from daedalus.domain.spec import (
    AcceptanceCriterion,
    AssertionKind,
    BoundarySpec,
    GoalSpec,
    MetaSpec,
    NetworkPolicy,
    PlanNode,
    PlanSpec,
    RetryPolicy,
    RiskLevel,
    SpecBundle,
    node_subject_digest,
)
from daedalus.infrastructure.git_sandbox import init_repo, initial_commit
from daedalus.infrastructure.store import EventStore
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

FILE_A = "src/example_project/textstats.py"
FILE_B = "src/example_project/helper_b.py"
FILE_C = "src/example_project/helper_c.py"
FILE_D = "src/example_project/helper_d.py"


def _node(node_id: str, artifact: str, deps: tuple[str, ...] = (), *, intent: str = "") -> PlanNode:
    return PlanNode(
        node_id=node_id,
        objective=f"fix {artifact}",
        deps=deps,
        expected_artifacts=(artifact,),
        allowed_tools=("read", "write", "test"),
        retry_policy=RetryPolicy(max_attempts=3),
        timeout_sec=300,
        intent=intent or f"fix {artifact}",
    )


def _chain_bundle(
    *,
    nodes: tuple[PlanNode, ...] | None = None,
    objective: str = "fix the chain",
    whitelist: tuple[str, ...] = (FILE_A, FILE_B, FILE_C, FILE_D),
) -> SpecBundle:
    """a -> b -> c, plus an independent d, so the downstream closure is observable."""
    plan_nodes = nodes or (
        _node("a", FILE_A),
        _node("b", FILE_B, ("a",)),
        _node("c", FILE_C, ("b",)),
        _node("d", FILE_D),
    )
    bundle = SpecBundle(
        goal=GoalSpec(
            goal_id="GOAL-CHAIN",
            objective=objective,
            invariants=("no file outside the whitelist may change",),
            acceptance_criteria=(
                AcceptanceCriterion(
                    criterion_id="AC-tests",
                    kind=AssertionKind.EXIT_CODE,
                    command=TEST_COMMAND,
                ),
            ),
            risk_level=RiskLevel.NORMAL,
        ),
        plan=PlanSpec(plan_id="PLAN-CHAIN", goal_id="GOAL-CHAIN", nodes=plan_nodes),
        boundary=BoundarySpec(
            boundary_id="BOUND-CHAIN",
            goal_id="GOAL-CHAIN",
            fs_whitelist=whitelist,
            network_policy=NetworkPolicy.DENY,
            allowed_tools=("read", "write", "test"),
        ),
        meta=MetaSpec.default(),
    )
    return SpecHardening(meta=bundle.meta).harden(bundle)


# ---------------------------------------------------------------------------
# What invalidates what
# ---------------------------------------------------------------------------


def test_editing_a_leaf_invalidates_only_that_leaf() -> None:
    before = _chain_bundle()
    edited = tuple(
        replace(node, intent="a different approach") if node.node_id == "c" else node
        for node in before.plan.nodes
    )
    after = _chain_bundle(nodes=edited)
    report = plan_selective_replay(before, after)

    assert report.change.kind is ChangeKind.PLAN_LOCAL
    assert report.stale_nodes == ("c",)
    assert report.reusable_nodes == ("a", "b", "d")


def test_editing_a_root_invalidates_its_downstream_closure() -> None:
    before = _chain_bundle()
    edited = tuple(
        replace(node, intent="a different approach") if node.node_id == "a" else node
        for node in before.plan.nodes
    )
    after = _chain_bundle(nodes=edited)
    report = plan_selective_replay(before, after)

    # a's artifact is an input to b, and b's to c, so both are invalidated.
    assert report.stale_nodes == ("a", "b", "c")
    assert report.reusable_nodes == ("d",)


def test_a_whitelist_change_for_an_unrelated_path_invalidates_only_that_node() -> None:
    """The interaction §13.1 B and §13.2 only allow once the reuse key is node-level."""
    before = _chain_bundle(whitelist=(FILE_A, FILE_B, FILE_C))
    after = _chain_bundle(whitelist=(FILE_A, FILE_B, FILE_C, FILE_D))

    assert before.digest() != after.digest(), "the bundle digest did change"
    report = plan_selective_replay(before, after)
    assert report.change.kind is ChangeKind.BOUNDARY_ONLY
    # Only d touches FILE_D, so only d is invalidated even though the bundle digest moved.
    assert report.stale_nodes == ("d",)
    assert report.reusable_nodes == ("a", "b", "c")


def test_a_goal_change_invalidates_everything() -> None:
    before = _chain_bundle()
    after = _chain_bundle(objective="implement something else entirely")
    report = plan_selective_replay(before, after)
    assert report.change.kind is ChangeKind.GOAL_BREAKING
    assert set(report.stale_nodes) == {"a", "b", "c", "d"}
    assert report.reusable_nodes == ()
    assert report.must_reexecute_everything


def test_an_identical_spec_is_fully_reusable() -> None:
    bundle = _chain_bundle()
    report = plan_selective_replay(bundle, bundle)
    assert report.change.kind is ChangeKind.IDENTICAL
    assert report.is_fully_reusable
    assert report.reusable_nodes == ("a", "b", "c", "d")


def test_a_network_change_invalidates_every_node() -> None:
    """A network posture change reaches every command, so nothing may be reused."""
    before = _chain_bundle()
    after = replace(
        before,
        boundary=replace(
            before.boundary,
            network_policy=NetworkPolicy.ALLOWLIST,
            allowed_domains=("pypi.org",),
        ),
    )
    report = plan_selective_replay(before, after)
    assert report.change.network_changed
    assert report.stale_nodes == ("a", "b", "c", "d")
    assert report.reusable_nodes == ()


def test_a_resource_limit_change_reaches_every_node() -> None:
    """Resource limits affect how every command runs, so they invalidate every node."""
    before = _chain_bundle()
    after = replace(before, boundary=replace(before.boundary, max_tokens_per_step=1_000))
    report = plan_selective_replay(before, after)
    assert report.reusable_nodes == ()
    assert report.stale_nodes


# ---------------------------------------------------------------------------
# The node-level subject digest itself
# ---------------------------------------------------------------------------


def test_the_node_digest_ignores_other_nodes() -> None:
    before = _chain_bundle()
    after = _chain_bundle(
        nodes=tuple(
            replace(node, intent="changed") if node.node_id == "d" else node
            for node in before.plan.nodes
        )
    )
    assert node_subject_digest(before, before.plan.node("a")) == node_subject_digest(
        after, after.plan.node("a")
    )
    assert node_subject_digest(before, before.plan.node("d")) != node_subject_digest(
        after, after.plan.node("d")
    )


def test_the_node_digest_ignores_an_unrelated_whitelist_entry() -> None:
    before = _chain_bundle(whitelist=(FILE_A, FILE_B, FILE_C))
    after = _chain_bundle(whitelist=(FILE_A, FILE_B, FILE_C, FILE_D))
    assert node_subject_digest(before, before.plan.node("a")) == node_subject_digest(
        after, after.plan.node("a")
    )


def test_the_node_digest_tracks_its_own_node_and_the_goal() -> None:
    before = _chain_bundle()
    edited = _chain_bundle(
        nodes=tuple(
            # `intent` is not clamped by hardening, unlike `timeout_sec`, which the boundary's
            # max_runtime_sec caps.
            replace(node, intent="a materially different approach") if node.node_id == "b" else node
            for node in before.plan.nodes
        )
    )
    assert node_subject_digest(before, before.plan.node("b")) != node_subject_digest(
        edited, edited.plan.node("b")
    )
    # And a goal change moves every node's digest, because each node serves the goal.
    re_goaled = _chain_bundle(objective="something else")
    for node_id in ("a", "b", "c", "d"):
        assert node_subject_digest(before, before.plan.node(node_id)) != node_subject_digest(
            re_goaled, re_goaled.plan.node(node_id)
        )


def test_the_node_digest_excludes_timestamps_and_owner() -> None:
    before = _chain_bundle()
    after = replace(before, owner_id="someone-else", created_at="2099-01-01T00:00:00Z")
    assert node_subject_digest(before, before.plan.node("a")) == node_subject_digest(
        after, after.plan.node("a")
    )


# ---------------------------------------------------------------------------
# The cache honours the node digest
# ---------------------------------------------------------------------------


def test_the_cache_matches_on_the_node_digest(git_repo: Path, tmp_path: Path) -> None:
    store = EventStore(tmp_path / "keys.db")
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="R",
            goal_id="GOAL-K",
            objective="fix it",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),), worker_id="w"
        ),
        quota=Quota(max_parallel_steps=1),
        reuse_artifacts=True,
        park_on_escalation=False,
    )
    orchestrator.register_spec()
    result = orchestrator.run()
    assert result.status == "COMPLETED"

    step = store.list_steps(result.run_id)[0]
    artifact = store.artifacts_for_step(str(step["step_id"]))[-1]
    node = bundle.plan.node(str(step["node_id"]))
    assert str(artifact["node_spec_digest"]) == node_subject_digest(bundle, node)

    key = ReuseKey(
        spec_digest=str(artifact["node_spec_digest"]),
        code_base_digest=str(artifact["code_base_digest"]),
        dependency_digest=str(artifact["dependency_digest"]),
        toolchain_digest=str(artifact["toolchain_digest"]),
        input_artifact_digest=str(artifact["input_artifact_digest"]),
    )
    assert ArtifactCache(store=store).lookup(key).reusable
    store.close()


# ---------------------------------------------------------------------------
# Selective replay, end to end
# ---------------------------------------------------------------------------


class _PerNodeWorker:
    """Writes only the file its own node declares.

    `ScriptedWorker` applies its whole script on every step, which is fine for a single-node
    plan and silently wrong for a multi-node one: the first step would commit every file and
    the rest would then fail Tier-1 for an empty change set.
    """

    name = "per-node-worker"

    def __init__(self, contents: dict[str, str], *, worker_id: str = "w-per-node") -> None:
        self.contents = contents
        self.worker_id = worker_id
        self.calls: list[str] = []

    def implement(self, sandbox, context):  # noqa: ANN001, ANN201
        from daedalus.application.worker import WorkerResult

        self.calls.append(context.node.node_id)
        written: list[str] = []
        for artifact in context.node.expected_artifacts:
            content = self.contents.get(artifact)
            if content is None:
                continue
            sandbox.write_file(artifact, content)
            written.append(artifact)
        if not written:
            return WorkerResult(
                ok=False,
                summary=f"no script for {context.node.node_id}",
                worker_id=self.worker_id,
                error="no_script",
            )
        return WorkerResult(
            ok=True,
            summary=f"{context.node.node_id} wrote {written}",
            changed_files=tuple(written),
            worker_id=self.worker_id,
            model="per-node",
        )


def _three_file_repo(tmp_path: Path) -> Path:
    """A repository with three modules so a multi-node plan can actually run."""
    repo = init_repo(tmp_path / "selective_repo")
    (repo / "src" / "example_project").mkdir(parents=True, exist_ok=True)
    (repo / "tests").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "example_project" / "__init__.py").write_text("", encoding="utf-8")
    # Start BROKEN (0), so the workers' writes produce a real diff. A repository that is
    # already correct would make every step fail Tier-1 for an empty change set.
    for name in ("a", "d"):
        (repo / f"src/example_project/{name}.py").write_text(
            f'"""Module {name}."""\n\n\ndef value() -> int:\n    return 0\n',
            encoding="utf-8",
        )
    # One test file per module, so a node can be judged on its own contribution. A single
    # combined test would make every node responsible for every other node's work.
    (repo / "tests" / "test_a.py").write_text(
        "from example_project.a import value as a_value\n\n\n"
        "def test_a_value() -> None:\n"
        "    assert a_value() == 1\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_d.py").write_text(
        "from example_project.d import value as d_value\n\n\n"
        "def test_d_value() -> None:\n"
        "    assert d_value() == 4\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\npythonpath = [\"src\"]\n",
        encoding="utf-8",
    )
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n.pytest_cache/\n", encoding="utf-8")
    initial_commit(repo, "chore: three modules")
    return repo


def _two_node_bundle(*, a_intent: str, d_intent: str) -> SpecBundle:
    """Two independent nodes, each verified on its own module.

    Node-scoped acceptance criteria are what make a multi-node plan gateable: a shared suite
    would make each node fail on the other node's unfixed module, which is a property of the
    test layout rather than of the change.
    """
    a_tests = AcceptanceCriterion(
        criterion_id="AC-a",
        kind=AssertionKind.EXIT_CODE,
        command="python3 -m pytest tests/test_a.py -q",
    )
    d_tests = AcceptanceCriterion(
        criterion_id="AC-d",
        kind=AssertionKind.EXIT_CODE,
        command="python3 -m pytest tests/test_d.py -q",
    )
    bundle = SpecBundle(
        goal=GoalSpec(
            goal_id="GOAL-SEL",
            objective="fix two modules",
            invariants=("no file outside the whitelist may change",),
            # The goal declares the union; `SpecBundle.validate` requires the node criteria to
            # cover it, so splitting work cannot weaken verification.
            acceptance_criteria=(a_tests, d_tests),
            risk_level=RiskLevel.NORMAL,
        ),
        plan=PlanSpec(
            plan_id="PLAN-SEL",
            goal_id="GOAL-SEL",
            nodes=(
                PlanNode(
                    node_id="fix-a",
                    objective="fix module a",
                    expected_artifacts=("src/example_project/a.py",),
                    allowed_tools=("read", "write", "test"),
                    retry_policy=RetryPolicy(max_attempts=2),
                    timeout_sec=300,
                    intent=a_intent,
                    extra={"acceptance_criteria": [a_tests.to_dict()]},
                ),
                PlanNode(
                    node_id="fix-d",
                    objective="fix module d",
                    expected_artifacts=("src/example_project/d.py",),
                    allowed_tools=("read", "write", "test"),
                    retry_policy=RetryPolicy(max_attempts=2),
                    timeout_sec=300,
                    intent=d_intent,
                    extra={"acceptance_criteria": [d_tests.to_dict()]},
                ),
            ),
        ),
        boundary=BoundarySpec(
            boundary_id="BOUND-SEL",
            goal_id="GOAL-SEL",
            fs_whitelist=("src/example_project/a.py", "src/example_project/d.py"),
            network_policy=NetworkPolicy.DENY,
            allowed_tools=("read", "write", "test"),
        ),
        meta=MetaSpec.default(),
    )
    return SpecHardening(meta=bundle.meta).harden(bundle)


def test_a_selective_replay_reuses_the_unaffected_node_and_reruns_the_rest(
    tmp_path: Path,
) -> None:
    """The end-to-end proof: only the invalidated node executes on the second pass."""
    repo = _three_file_repo(tmp_path)
    store = EventStore(tmp_path / "selective.db")

    first_bundle = _two_node_bundle(a_intent="return 1", d_intent="return 4")
    module_a = '"""Module a."""\n\n\ndef value() -> int:\n    return 1\n'
    module_d = '"""Module d."""\n\n\ndef value() -> int:\n    return 4\n'
    first_worker = _PerNodeWorker(
        {"src/example_project/a.py": module_a, "src/example_project/d.py": module_d},
        worker_id="w-first",
    )
    first = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt1",
        bundle=first_bundle,
        worker=first_worker,
        quota=Quota(max_parallel_steps=1),
        reuse_artifacts=True,
        park_on_escalation=False,
    )
    first.register_spec()
    first_result = first.run()
    assert first_result.status == "COMPLETED", first_result.describe()

    # Only node d's definition changes. Its subject digest moves; node a's does not.
    second_bundle = _two_node_bundle(a_intent="return 1", d_intent="return 4, more explicitly")
    plan = plan_selective_replay(first_bundle, second_bundle)
    assert plan.stale_nodes == ("fix-d",), plan.describe()
    assert plan.reusable_nodes == ("fix-a",)

    second_worker = _PerNodeWorker(
        {"src/example_project/a.py": module_a, "src/example_project/d.py": module_d},
        worker_id="w-second",
    )
    second = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt2",
        bundle=second_bundle,
        worker=second_worker,
        quota=Quota(max_parallel_steps=1),
        reuse_artifacts=True,
        park_on_escalation=False,
        parent_execution_id=first_result.execution_id,
        # A replay starts from the commit the original run started from, not from the branch it
        # advanced. Starting from the advanced branch would find the work already done and every
        # step would fail Tier-1 for an empty change set.
        replay_from_commit=store.get_run(first_result.run_id)["base_commit"],
    )
    second.register_spec()
    second_result = second.run()
    # The original run already advanced main. Replaying from its old base creates
    # divergent history: successful node execution is not successful delivery.
    assert second_result.status == "PARTIAL_FAILURE", second_result.describe()
    assert not second_result.promoted_commit
    assert any("promotion refused" in note for note in second_result.notes)

    by_node = {step.node_id: step for step in second_result.steps}
    assert by_node["fix-a"].decision == "REUSED", "the unaffected node must be reused"
    assert by_node["fix-d"].decision != "REUSED", "the changed node must actually re-execute"
    # The worker must not have been asked to do fix-a's work again.
    assert "fix-a" not in second_worker.calls, second_worker.calls
    assert "fix-d" in second_worker.calls

    # And the reuse is attributable in the event log.
    hits = [event for event in store.all_events() if event.event_type == "StepCacheHit"]
    assert len(hits) == 1
    assert hits[0].payload["reuse_key"]["spec_digest"] == node_subject_digest(
        second_bundle, second_bundle.plan.node("fix-a")
    )
    store.close()


def test_an_upstream_change_still_invalidates_its_downstream(tmp_path: Path) -> None:
    """Selective must not become unsound: a dependency change must reach its consumers."""
    before = _chain_bundle()
    edited = tuple(
        replace(node, intent="different") if node.node_id == "a" else node
        for node in before.plan.nodes
    )
    after = _chain_bundle(nodes=edited)
    plan = plan_selective_replay(before, after)
    assert "b" in plan.stale_nodes and "c" in plan.stale_nodes, (
        "b consumes a's artifact and c consumes b's, so both must be invalidated"
    )
    # And the input-artifact component of the reuse key enforces this independently of the
    # node digest: b's inputs changed because a was re-executed.
    assert "input_artifact_digest" in ReuseKey(
        spec_digest="x", code_base_digest="y", dependency_digest="z",
        toolchain_digest="w", input_artifact_digest="v",
    ).to_dict()


def test_selective_drift_marking_is_limited_to_the_given_nodes(tmp_path: Path) -> None:
    """The scheduler must be able to go STALE on a subgraph, not on the whole run."""
    store = EventStore(tmp_path / "drift.db")
    fsm = StateMachineService(store)
    store.project_run(
        {
            "run_id": "r",
            "goal_id": "G",
            "execution_id": "e",
            "spec_digest": "spec-1",
            "status": "RUNNING",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    )
    for node_id in ("a", "b", "c", "d"):
        fsm.declare_step(
            step_id=f"r:{node_id}",
            run_id="r",
            execution_id="e",
            node_id=node_id,
            spec_digest="spec-1",
            expected_artifacts=(f"src/{node_id}.py",),
        )
    plan = PlanSpec(
        plan_id="P",
        goal_id="G",
        nodes=tuple(
            PlanNode(node_id=n, expected_artifacts=(f"src/{n}.py",)) for n in ("a", "b", "c", "d")
        ),
    )
    scheduler = Scheduler(store=store, fsm=fsm, plan=plan, execution_id="e", run_id="r")

    drifted = scheduler.mark_drifted_steps("spec-2", only_node_ids=("a", "b", "c"))
    assert set(drifted) == {"r:a", "r:b", "r:c"}
    assert store.get_step("r:a")["state"] == StepState.STALE.value
    assert store.get_step("r:d")["state"] == StepState.PENDING.value, (
        "a node outside the selective scope must be left alone"
    )
    store.close()
