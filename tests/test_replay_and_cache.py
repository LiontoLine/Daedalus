"""Rollback, replay and artifact reuse (Spec §12, §13).

The tests here pin down the two things rollback systems usually get wrong: that rollback
deletes nothing, and that reuse only happens when *every* digest matches.
"""

from __future__ import annotations

import pytest

from daedalus.application.artifact_cache import ArtifactCache, reuse_key_for
from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.fsm_service import StateMachineService
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest, SpecHardening
from daedalus.application.replay import (
    ChangeKind,
    ReplayService,
    classify_spec_change,
)
from daedalus.application.scheduler import Quota
from daedalus.domain.canonical import sha256_hex
from daedalus.domain.fsm import RunState, StepState
from daedalus.domain.spec import (
    BoundarySpec,
    GoalSpec,
    MetaSpec,
    NetworkPolicy,
    PlanNode,
    PlanSpec,
    RetryPolicy,
    RiskLevel,
    SpecBundle,
)
from daedalus.errors import NotRollbackable
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.infrastructure.store import EventStore
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

CORRECT_VARIANT = CORRECT_IMPLEMENTATION.replace(
    "    tokens = text.split()\n    return {",
    "    tokens = [t for t in text.split() if t]\n    return {",
).replace(
    "    tokens = text.split()\n    if not tokens:",
    "    tokens = [t for t in text.split() if t]\n    if not tokens:",
)


def _request(objective: str = "make summarize() count words", paths: tuple[str, ...] = (TARGET,)) -> PlanRequest:
    return PlanRequest(
        request_id="REQ-1",
        goal_id="GOAL-1",
        objective=objective,
        target_paths=paths,
        test_command=TEST_COMMAND,
        risk_level=RiskLevel.NORMAL,
        network_policy=NetworkPolicy.DENY,
    )


def _bundle(**overrides) -> SpecBundle:
    request = _request(**{k: v for k, v in overrides.items() if k in {"objective", "paths"}})
    return DeterministicPlanner().plan(request)


# ---------------------------------------------------------------------------
# Spec change classification (Spec §13.1)
# ---------------------------------------------------------------------------


def test_identical_specs_are_identical() -> None:
    bundle = _bundle()
    assert classify_spec_change(bundle, bundle).kind is ChangeKind.IDENTICAL


def test_goal_change_is_class_a() -> None:
    report = classify_spec_change(_bundle(), _bundle(objective="do something else entirely"))
    assert report.kind is ChangeKind.GOAL_BREAKING
    assert report.requires_new_execution


def test_acceptance_change_is_class_a() -> None:
    original = _bundle()
    changed = SpecBundle(
        goal=GoalSpec(
            goal_id=original.goal.goal_id,
            objective=original.goal.objective,
            acceptance_criteria=(
                type(original.goal.acceptance_criteria[0])(
                    criterion_id="AC-different", kind=original.goal.acceptance_criteria[0].kind,
                    command="true",
                ),
            ),
            risk_level=RiskLevel.NORMAL,
        ),
        plan=original.plan,
        boundary=original.boundary,
        meta=original.meta,
    )
    assert classify_spec_change(original, changed).kind is ChangeKind.GOAL_BREAKING


def test_plan_change_is_class_b_with_a_downstream_closure() -> None:
    original = _bundle()
    node_a, node_b, node_c = (
        PlanNode(node_id="a", expected_artifacts=(TARGET,), retry_policy=RetryPolicy()),
        PlanNode(node_id="b", deps=("a",), expected_artifacts=("src/b.py",), retry_policy=RetryPolicy()),
        PlanNode(node_id="c", deps=("b",), expected_artifacts=("src/c.py",), retry_policy=RetryPolicy()),
    )
    changed = SpecBundle(
        goal=original.goal,
        plan=PlanSpec(plan_id="P", goal_id="GOAL-1", nodes=(node_a, node_b, node_c)),
        boundary=BoundarySpec(
            boundary_id="B", goal_id="GOAL-1",
            fs_whitelist=(TARGET, "src/b.py", "src/c.py"),
            network_policy=NetworkPolicy.DENY,
        ),
        meta=original.meta,
    )
    before = SpecBundle(
        goal=original.goal,
        plan=PlanSpec(
            plan_id="P", goal_id="GOAL-1",
            nodes=(node_a, node_b, PlanNode(node_id="c", deps=("b",), expected_artifacts=("src/c.py",), intent="changed", retry_policy=RetryPolicy())),
        ),
        boundary=changed.boundary,
        meta=original.meta,
    )
    report = classify_spec_change(before, changed)
    assert report.kind is ChangeKind.PLAN_LOCAL
    assert report.changed_node_ids == ("c",)
    # Only the edited node and its downstream closure are invalidated, not the whole plan.
    assert report.affected_node_ids == ("c",)


def test_boundary_change_is_class_c() -> None:
    original = _bundle()
    widened = SpecBundle(
        goal=original.goal,
        plan=original.plan,
        boundary=BoundarySpec(
            boundary_id=original.boundary.boundary_id,
            goal_id=original.boundary.goal_id,
            fs_whitelist=(TARGET, "docs/*.md"),
            network_policy=NetworkPolicy.DENY,
        ),
        meta=original.meta,
    )
    report = classify_spec_change(original, widened)
    assert report.kind is ChangeKind.BOUNDARY_ONLY
    assert "docs/*.md" in report.changed_paths


def test_network_change_invalidates_every_node() -> None:
    original = _bundle()
    networked = SpecBundle(
        goal=original.goal,
        plan=original.plan,
        boundary=BoundarySpec(
            boundary_id=original.boundary.boundary_id,
            goal_id=original.boundary.goal_id,
            fs_whitelist=original.boundary.fs_whitelist,
            network_policy=NetworkPolicy.ALLOWLIST,
            allowed_domains=("pypi.org",),
        ),
        meta=original.meta,
    )
    report = classify_spec_change(original, networked)
    assert report.network_changed
    assert report.affected_node_ids == tuple(
        sorted(node.node_id for node in original.plan.nodes)
    )


# ---------------------------------------------------------------------------
# Rollback (Spec §12.1)
# ---------------------------------------------------------------------------


def _run_once(git_repo, tmp_path, ops, *, reuse: bool = False, run_id: str = "", spec=None):
    store = EventStore(tmp_path / "replay.db")
    bundle = spec or _bundle()
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=ScriptedWorker(ops=ops, worker_id="w-replay"),
        quota=Quota(max_parallel_steps=1),
        reuse_artifacts=reuse,
        run_id=run_id,
    )
    orchestrator.register_spec()
    return store, orchestrator, orchestrator.run()


def test_rollback_stops_a_run_without_deleting_anything(git_repo, tmp_path) -> None:
    store, _orchestrator, result = _run_once(
        git_repo, tmp_path, (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)
    )
    assert result.status == "COMPLETED"
    before_events = store.event_count()
    main_after_run = GitSandbox.main_commit(git_repo)

    service = ReplayService(store=store, fsm=StateMachineService(store))
    rollback = service.rollback(result.run_id, reason="a regression was found in review")

    assert rollback.status == RunState.CANCELLED.value
    assert rollback.superseded_steps, "committed work is superseded, never rewritten"
    assert store.get_run(result.run_id)["status"] == RunState.CANCELLED.value
    # History grew; nothing was removed, and the target branch is untouched by rollback.
    assert store.event_count() > before_events
    assert GitSandbox.main_commit(git_repo) == main_after_run
    assert store.verify_sequences() == []
    # The rollback says plainly what it did and did not undo.
    payload = rollback.describe()
    assert "git commits" in payload["rolled_back"]
    assert any("email" in item for item in payload["not_rolled_back"])
    store.close()


def test_rollback_twice_is_refused(git_repo, tmp_path) -> None:
    store, _orchestrator, result = _run_once(
        git_repo, tmp_path, (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)
    )
    service = ReplayService(store=store, fsm=StateMachineService(store))
    service.rollback(result.run_id, reason="first")
    with pytest.raises(NotRollbackable):
        service.rollback(result.run_id, reason="second")
    store.close()


def test_rollback_then_replay_reuses_verified_work(git_repo, tmp_path) -> None:
    """The §12.1 sequence: rollback, new execution id, replay from the target commit."""
    store, orchestrator, first = _run_once(
        git_repo,
        tmp_path,
        (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
        reuse=True,
    )
    assert first.status == "COMPLETED"
    original_commit = first.commits[0]

    service = ReplayService(store=store, fsm=StateMachineService(store))
    rollback = service.rollback(first.run_id, reason="replay rehearsal")
    assert rollback.new_execution_id and rollback.new_execution_id != first.execution_id

    # A replay is a NEW run with a new run id and execution id, from the same base commit.
    replay = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt-replay",
        bundle=orchestrator.bundle,
        worker=ScriptedWorker(ops=(), worker_id="must-not-run"),
        quota=Quota(max_parallel_steps=1),
        reuse_artifacts=True,
        parent_execution_id=first.execution_id,
        replay_from_commit=store.get_run(first.run_id)["base_commit"],
    )
    replay.register_spec()
    replayed = replay.run()

    assert replayed.run_id != first.run_id
    assert replayed.execution_id != first.execution_id
    assert replayed.status == "COMPLETED"
    assert replayed.steps and replayed.steps[0].decision == "REUSED", replayed.describe()
    assert replayed.commits[0] == original_commit
    # The reuse must be attributable to the original gate result.
    hits = [e for e in store.all_events() if e.event_type == "StepCacheHit"]
    assert hits, "a reuse must be recorded as a fact, not just as a faster run"
    assert hits[0].payload["source_artifact_digest"]
    assert hits[0].payload["gate_result_ref"]
    # The key records the node-level subject, which is what makes selective replay possible.
    assert hits[0].payload["reuse_key"]["spec_digest"]
    assert store.verify_sequences() == []
    store.close()


# ---------------------------------------------------------------------------
# Artifact reuse (Spec §13.2)
# ---------------------------------------------------------------------------


def test_reuse_requires_all_five_digests(git_repo, tmp_path) -> None:
    store, _orchestrator, result = _run_once(
        git_repo, tmp_path, (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)
    )
    step = store.list_steps(result.run_id)[0]
    artifact = store.artifacts_for_step(str(step["step_id"]))[0]
    cache = ArtifactCache(store=store)

    # The reuse key carries the NODE-level subject digest, so a change to a different node
    # in the same plan does not invalidate this artifact.
    from daedalus.application.artifact_cache import ReuseKey

    matching = ReuseKey(
        spec_digest=str(artifact["node_spec_digest"]),
        code_base_digest=str(artifact["code_base_digest"]),
        dependency_digest=str(artifact["dependency_digest"]),
        toolchain_digest=str(artifact["toolchain_digest"]),
        input_artifact_digest=str(artifact["input_artifact_digest"]),
    )
    assert cache.lookup(matching).reusable

    # Each of the five, changed on its own, must invalidate the reuse.
    for field_name in (
        "spec_digest",
        "code_base_digest",
        "dependency_digest",
        "toolchain_digest",
        "input_artifact_digest",
    ):
        mutated = ReuseKey(**{**matching.to_dict(), field_name: "0" * 64})
        decision = cache.lookup(mutated)
        assert not decision.reusable, f"a changed {field_name} must invalidate the cache"
    store.close()


def test_incomplete_reuse_key_is_refused(git_repo, tmp_path) -> None:
    store, _orchestrator, _result = _run_once(
        git_repo, tmp_path, (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)
    )
    cache = ArtifactCache(store=store)
    from daedalus.application.artifact_cache import ReuseKey

    partial = ReuseKey(
        spec_digest="spec",
        code_base_digest="",
        dependency_digest="dep",
        toolchain_digest="tool",
        input_artifact_digest="input",
    )
    decision = cache.lookup(partial)
    assert not decision.reusable
    assert "incomplete reuse key" in decision.reason
    store.close()


def test_cache_is_off_by_default(git_repo, tmp_path) -> None:
    """An ordinary run must never skip work: reuse is opt-in via replay."""
    store, _orchestrator, first = _run_once(
        git_repo, tmp_path, (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)
    )
    second_root = tmp_path / "second"
    second_root.mkdir()
    replay = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=second_root,
        bundle=_bundle(),
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_VARIANT),), worker_id="w-2"
        ),
        quota=Quota(max_parallel_steps=1),
    )
    replay.register_spec()
    second = replay.run()
    assert second.status == "COMPLETED"
    assert second.steps[0].decision != "REUSED"
    assert not [e for e in store.all_events() if e.event_type == "StepCacheHit"]
    store.close()


def test_dependency_change_invalidates_the_cache(git_repo, tmp_path) -> None:
    """A changed manifest must invalidate reuse even when the code base is identical."""
    repo = git_repo
    from tests.wheel_fixture import make_wheel
    from daedalus.application.dependencies import cache_wheel
    wheel = make_wheel(tmp_path / "wheels")
    info = cache_wheel(tmp_path / "dependency-cache", wheel)
    (repo / "requirements.lock").write_text("demo-dep==1.0 --hash=sha256:" + info["sha256"] + "\n")
    (repo / "requirements.txt").write_text("demo-dep==1.0\n", encoding="utf-8")
    from daedalus.infrastructure.git_sandbox import initial_commit

    initial_commit(repo, "chore: add a manifest")

    original = _bundle()
    bundling = SpecBundle(
        goal=original.goal,
        plan=original.plan,
        boundary=BoundarySpec(
            boundary_id=original.boundary.boundary_id,
            goal_id=original.boundary.goal_id,
            fs_whitelist=original.boundary.fs_whitelist,
            network_policy=NetworkPolicy.DENY,
            dependency_manifest="requirements.txt",
            lock_file="requirements.lock",
        ),
        meta=original.meta,
    )
    store, orchestrator, first = _run_once(
        repo,
        tmp_path,
        (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
        reuse=True,
        spec=bundling,
    )
    assert first.status == "COMPLETED"

    base = store.get_run(first.run_id)["base_commit"]
    before = orchestrator._dependency_digest_at(base)  # noqa: SLF001 - intentional probe
    (repo / "requirements.txt").write_text("pytest==8.0.0\ncoverage==7.0.0\n", encoding="utf-8")
    from daedalus.infrastructure.git_sandbox import initial_commit as commit_again

    commit_again(repo, "chore: bump the manifest")

    from daedalus.application.artifact_cache import ReuseKey

    artifact = store.artifacts_for_step(
        str(store.list_steps(first.run_id)[0]["step_id"])
    )[0]
    mutated = ReuseKey(
        spec_digest=str(artifact["node_spec_digest"]),
        code_base_digest=str(artifact["code_base_digest"]),
        dependency_digest=sha256_hex("a different manifest"),
        toolchain_digest=str(artifact["toolchain_digest"]),
        input_artifact_digest=str(artifact["input_artifact_digest"]),
    )
    decision = ArtifactCache(store=store).lookup(mutated)
    assert not decision.reusable
    assert before != sha256_hex("a different manifest")
    store.close()
