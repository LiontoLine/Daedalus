"""Phase 2: real concurrency, run-branch integration and the rebase re-gate (Spec §6.4, §11.2).

These tests exist because "the scheduler respects max_parallel_steps" was previously an
untestable claim: one worktree per run made concurrency impossible. Now that every step
owns a worktree, both the concurrency and the integration protocol can be proven.
"""

from __future__ import annotations

import json
import shutil
import threading
from pathlib import Path

import pytest

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest, SpecHardening
from daedalus.application.scheduler import Quota
from daedalus.application.worker import WorkerResult
from daedalus.application.worktree_pool import WorktreePool
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
)
from daedalus.infrastructure.git_sandbox import GitSandbox, _git, initial_commit
from daedalus.infrastructure.store import EventStore
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

EXTRA = "src/example_project/extra.py"

EXTRA_FIXED = '''"""A second module for parallel-step tests."""

from __future__ import annotations


def is_blank(text: str) -> bool:
    """True when `text` has no non-whitespace content."""
    return not text.strip()
'''

EXTRA_BROKEN = '''"""A second module for parallel-step tests."""

from __future__ import annotations


def is_blank(text: str) -> bool:
    return True
'''

#: A second valid implementation of the same file, used to force a rebase conflict.
CORRECT_ALTERNATIVE = CORRECT_IMPLEMENTATION.replace(
    "    tokens = text.split()\n    return {",
    "    tokens = [token for token in text.split() if token]\n    return {",
).replace(
    "    tokens = text.split()\n    if not tokens:",
    "    tokens = [token for token in text.split() if token]\n    if not tokens:",
)


def _prepare_two_module_repo(tmp_path: Path, git_repo: Path, *, broken_extra: bool = True) -> Path:
    """Add a second module (and, unless disabled, a failing test for it) to the repo."""
    (git_repo / EXTRA).write_text(EXTRA_BROKEN if broken_extra else EXTRA_FIXED, encoding="utf-8")
    (git_repo / "tests" / "test_extra.py").write_text(
        "from example_project.extra import is_blank\n\n\n"
        "def test_is_blank() -> None:\n"
        '    assert is_blank("  \\n ") is True\n'
        '    assert is_blank("x") is False\n',
        encoding="utf-8",
    )
    initial_commit(git_repo, "test: add the second module")
    return git_repo


def _bundle(
    nodes: tuple[PlanNode, ...],
    *,
    whitelist: tuple[str, ...],
    attempts: int = 3,
    extra_criteria: tuple[AcceptanceCriterion, ...] = (),
) -> SpecBundle:
    # When every node declares its own criteria, the goal declares the union so that the
    # coverage rule in SpecBundle.validate is satisfied and the whole goal is verified.
    node_declared = [c for node in nodes for c in node.acceptance_criteria]
    if node_declared:
        criteria = (*node_declared, *extra_criteria)
    else:
        criteria = (
            AcceptanceCriterion(
                criterion_id="AC-tests", kind=AssertionKind.EXIT_CODE, command=TEST_COMMAND
            ),
            *extra_criteria,
        )
    bundle = SpecBundle(
        goal=GoalSpec(
            goal_id="GOAL-PAR",
            objective="fix both modules",
            invariants=("no file outside the whitelist may change",),
            acceptance_criteria=criteria,
            risk_level=RiskLevel.NORMAL,
        ),
        plan=PlanSpec(
            plan_id="PLAN-PAR",
            goal_id="GOAL-PAR",
            nodes=tuple(
                PlanNode(
                    node_id=node.node_id,
                    objective=node.objective,
                    deps=node.deps,
                    expected_artifacts=node.expected_artifacts,
                    allowed_tools=("read", "write", "test"),
                    retry_policy=RetryPolicy(max_attempts=attempts),
                    timeout_sec=300,
                    intent=node.intent,
                    extra=dict(node.extra),
                )
                for node in nodes
            ),
        ),
        boundary=BoundarySpec(
            boundary_id="BOUND-PAR",
            goal_id="GOAL-PAR",
            fs_whitelist=whitelist,
            network_policy=NetworkPolicy.DENY,
            allowed_tools=("read", "write", "test"),
        ),
        meta=MetaSpec.default(),
    )
    return SpecHardening(meta=bundle.meta).harden(bundle)


TEXTSTATS_TESTS = AcceptanceCriterion(
    criterion_id="AC-textstats",
    kind=AssertionKind.EXIT_CODE,
    statement="the textstats tests pass",
    command="python3 -m pytest tests/test_textstats.py -q",
)

EXTRA_TESTS = AcceptanceCriterion(
    criterion_id="AC-extra",
    kind=AssertionKind.EXIT_CODE,
    statement="the extra module tests pass",
    command="python3 -m pytest tests/test_extra.py -q",
)


def _nodes() -> tuple[PlanNode, ...]:
    """Two independent nodes, each verifying only its own module.

    Node-scoped acceptance criteria are what make a multi-node plan gateable: the goal's
    criteria are covered by the union of the two nodes, and each node is judged on the
    part of the goal it actually owns.
    """
    return (
        PlanNode(
            node_id="fix-textstats",
            objective="fix the word counter",
            expected_artifacts=(TARGET,),
            intent="count words with split() and handle empty input",
            extra={"acceptance_criteria": [TEXTSTATS_TESTS.to_dict()]},
        ),
        PlanNode(
            node_id="fix-extra",
            objective="fix is_blank",
            expected_artifacts=(EXTRA,),
            intent="is_blank must actually inspect the text",
            extra={"acceptance_criteria": [EXTRA_TESTS.to_dict()]},
        ),
    )


class _BarrierWorker:
    """Proves concurrency: both workers must be in flight at the same time or they fail."""

    name = "barrier-worker"
    worker_id = "worker-barrier"

    def __init__(self, ops_by_path: dict[str, str], parties: int) -> None:
        self.ops_by_path = ops_by_path
        self.barrier = threading.Barrier(parties, timeout=10)
        self.arrived = 0
        self.overlapped = 0
        self.failures = 0
        self._lock = threading.Lock()

    def implement(self, sandbox: GitSandbox, context):  # noqa: ANN001, ANN201
        with self._lock:
            self.arrived += 1
        try:
            self.barrier.wait()
        except threading.BrokenBarrierError:
            with self._lock:
                self.failures += 1
            return WorkerResult(
                ok=False,
                summary="workers did not overlap in time",
                execution_log="the concurrency barrier timed out",
                worker_id=self.worker_id,
                error="no_concurrency",
            )
        with self._lock:
            self.overlapped += 1
        path = str(context.node.expected_artifacts[0])
        sandbox.write_file(path, self.ops_by_path[path])
        return WorkerResult(
            ok=True,
            summary=f"wrote {path}",
            changed_files=(path,),
            worker_id=self.worker_id,
            model="barrier",
        )


def _run(git_repo: Path, tmp_path: Path, bundle: SpecBundle, worker, *, parallel: int = 2):
    store = EventStore(tmp_path / "parallel.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=worker,
        quota=Quota(max_parallel_steps=parallel),
        # Batch mode: these tests assert final outcomes, so escalations must end the run.
        park_on_escalation=False,
    )
    orchestrator.register_spec()
    return store, orchestrator.run()


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_independent_steps_run_concurrently(git_repo, tmp_path) -> None:
    """Two independent nodes must genuinely overlap, not merely be scheduled."""
    repo = _prepare_two_module_repo(tmp_path, git_repo)
    bundle = _bundle(_nodes(), whitelist=(TARGET, EXTRA))
    worker = _BarrierWorker({TARGET: CORRECT_IMPLEMENTATION, EXTRA: EXTRA_FIXED}, parties=2)
    store, result = _run(repo, tmp_path, bundle, worker, parallel=2)

    # The barrier is only released when both workers are inside `implement` at once, so a
    # successful pass is direct evidence of real overlap rather than interleaved scheduling.
    assert worker.failures == 0, "workers never overlapped: execution was serial"
    assert worker.overlapped >= 2
    assert result.status == "COMPLETED", result.describe()
    assert result.committed_count == 2
    assert len(result.commits) == 2
    from daedalus.domain.canonical import digest_of

    for event in store.events_for_execution(result.execution_id):
        if event.event_type != "StepCommitted":
            continue
        artifact = store.get_artifact(event.payload["artifact_digest"])
        expected = digest_of(
            {
                "step_id": event.step_id,
                "execution_id": result.execution_id,
                "artifact_digest": artifact["artifact_digest"],
                "subject_digest": result.spec_digest,
                "decision": "APPROVE",
            }
        )
        assert artifact["gate_result_ref"] == expected, (
            "rebased receipt must name its own newly reviewed artifact"
        )
    store.close()


def test_quota_one_keeps_execution_serial(git_repo, tmp_path) -> None:
    """With max_parallel_steps=1 the same two nodes must not overlap."""
    repo = _prepare_two_module_repo(tmp_path, git_repo)
    bundle = _bundle(_nodes(), whitelist=(TARGET, EXTRA))
    worker = _BarrierWorker({TARGET: CORRECT_IMPLEMENTATION, EXTRA: EXTRA_FIXED}, parties=2)
    store, result = _run(repo, tmp_path, bundle, worker, parallel=1)

    # The barrier can never be satisfied with one worker at a time, so each worker reports
    # a failure rather than silently succeeding.
    assert result.status != "COMPLETED"
    assert all(step.state != "COMMITTED" for step in result.steps)
    store.close()


# ---------------------------------------------------------------------------
# Run-branch integration and the rebase re-gate
# ---------------------------------------------------------------------------


def test_concurrent_steps_rebase_onto_the_run_branch(git_repo, tmp_path) -> None:
    """Two steps prepared at the same commit: the second must rebase and be re-gated."""
    repo = _prepare_two_module_repo(tmp_path, git_repo)
    bundle = _bundle(_nodes(), whitelist=(TARGET, EXTRA))
    worker = _BarrierWorker({TARGET: CORRECT_IMPLEMENTATION, EXTRA: EXTRA_FIXED}, parties=2)
    store, result = _run(repo, tmp_path, bundle, worker, parallel=2)

    assert result.status == "COMPLETED"
    event_types = [event.event_type for event in store.all_events()]
    assert "RunRebaseRequired" in event_types, (
        "the second step landed on a run branch that had already moved, so a rebase "
        f"must have been recorded; events were {event_types}"
    )
    assert result.rebase_count >= 1
    # The re-gate must have been re-run and recorded for the rebased tree.
    regates = store.connection.execute(
        "SELECT COUNT(*) AS n FROM metrics WHERE name = 'regate_after_rebase'"
    ).fetchone()["n"]
    assert regates >= 1
    # The re-gate must have produced its own artifact record, so the audit can show that
    # the rebased tree was reviewed as a distinct subject rather than reusing the old
    # verdict. The `stage` lives in the artifact document.
    stages = {
        json.loads(row["document"]).get("extra", {}).get("stage")
        for run in store.list_runs()
        for step in store.list_steps(str(run["run_id"]))
        for row in store.artifacts_for_step(str(step["step_id"]))
    }
    assert "REBASE_REQUIRED" in stages, stages
    # And the rebase must appear in the timeline as a fact, not only in memory.
    assert any(
        "rebase" in row["summary"].lower() for row in store.timeline_for_run(result.run_id)
    ) or any(event.event_type == "RunRebaseRequired" for event in store.all_events())
    store.close()


def test_rebase_conflict_returns_revise_then_recovers(git_repo, tmp_path) -> None:
    """A conflicting rebase is a REVISE, never a force-through."""
    repo = _prepare_two_module_repo(tmp_path, git_repo)

    class _SameFileWorker:
        """Writes the same file from both nodes with different valid implementations.

        No barrier is needed: both nodes are admitted in the same round and their
        worktrees are created before either worker starts, so they necessarily begin from
        the same commit. That is precisely the race the rebase protocol exists for.
        """

        name = "same-file-worker"
        worker_id = "worker-same-file"

        def implement(self, sandbox, context):  # noqa: ANN001, ANN201
            content = (
                CORRECT_IMPLEMENTATION
                if context.node.node_id == "fix-textstats"
                else CORRECT_ALTERNATIVE
            )
            sandbox.write_file(TARGET, content)
            return WorkerResult(
                ok=True,
                summary="wrote the shared file",
                changed_files=(TARGET,),
                worker_id=self.worker_id,
                model="same-file",
            )

    # Both nodes must target the same file and be judged by the same criterion, otherwise
    # the gate would reject a node for a module it never claimed to fix.
    shared = (
        PlanNode(
            node_id="fix-textstats",
            objective="fix the word counter",
            expected_artifacts=(TARGET,),
            intent="count words with split()",
            extra={"acceptance_criteria": [TEXTSTATS_TESTS.to_dict()]},
        ),
        PlanNode(
            node_id="fix-extra",
            objective="also fix the word counter",
            expected_artifacts=(TARGET,),
            intent="an alternative valid implementation",
            extra={"acceptance_criteria": [TEXTSTATS_TESTS.to_dict()]},
        ),
    )
    bundle = _bundle(shared, whitelist=(TARGET, EXTRA), attempts=3)

    store, result = _run(repo, tmp_path, bundle, _SameFileWorker(), parallel=2)

    conflicts = [
        step
        for step in result.steps
        if any("rebase" in reason for reason in step.reasons) and step.state != "COMMITTED"
    ]
    assert conflicts, f"expected a rebase conflict REVISE, got {result.describe()}"
    assert conflicts[0].decision in {"REVISE", "ESCALATE"}
    assert result.status == "COMPLETED", (
        "the conflicting step must be retried from the new integration point and succeed"
    )
    store.close()


def test_partial_failure_keeps_the_target_branch_untouched(git_repo, tmp_path) -> None:
    """A run that half-succeeds promotes nothing, but keeps its commits on the run branch."""
    repo = _prepare_two_module_repo(tmp_path, git_repo)

    class _OneFailsWorker:
        name = "one-fails"
        worker_id = "worker-one-fails"

        def __init__(self) -> None:
            self.barrier = threading.Barrier(2, timeout=10)

        def implement(self, sandbox, context):  # noqa: ANN001, ANN201
            try:
                self.barrier.wait()
            except threading.BrokenBarrierError:
                return WorkerResult(ok=False, summary="no overlap", error="no_concurrency")
            if context.node.node_id == "fix-extra":
                # A boundary escape is terminal (Spec §17), so this node escalates.
                sandbox.write_file("src/example_project/secret_extra.py", "x = 1\n")
                return WorkerResult(
                    ok=False,
                    summary="attempted an out-of-bounds write",
                    error="boundary_violation",
                    worker_id=self.worker_id,
                )
            sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
            return WorkerResult(
                ok=True,
                summary="fixed the counter",
                changed_files=(TARGET,),
                worker_id=self.worker_id,
                model="one-fails",
            )

    bundle = _bundle(_nodes(), whitelist=(TARGET, EXTRA), attempts=1)
    before = GitSandbox.main_commit(repo)
    store, result = _run(repo, tmp_path, bundle, _OneFailsWorker(), parallel=2)

    # One node committed, one escalated: that is a partial failure. The successful commit
    # stays on the run branch as evidence, but a partial failure must never be promoted.
    assert result.status == "PARTIAL_FAILURE", result.describe()
    assert result.commits, "the successful step's commit must be preserved as evidence"
    assert result.promoted_commit == ""
    assert GitSandbox.main_commit(repo) == before
    # The run branch must still exist and be recorded, holding the evidence.
    run = store.get_run(result.run_id)
    assert run["branch"], "the run branch is the record of what did land"
    assert _git(repo, ["rev-parse", "--verify", run["branch"]], check=False).ok
    assert any("NOT advanced" in note for note in result.notes)
    store.close()


# ---------------------------------------------------------------------------
# The gated tree must be the committed tree
# ---------------------------------------------------------------------------


def test_a_test_that_mutates_the_tree_blocks_the_commit(git_repo, tmp_path) -> None:
    """Running the acceptance tests must not be able to smuggle changes into the commit."""
    repo = _prepare_two_module_repo(tmp_path, git_repo, broken_extra=False)
    mutator = AcceptanceCriterion(
        criterion_id="AC-mutating-test",
        kind=AssertionKind.EXIT_CODE,
        statement="a badly behaved test that edits a tracked file",
        command=(
            "python3 -c \"open('src/example_project/textstats.py','a')"
            ".write('# written by the test run\\n')\""
        ),
    )
    bundle = _bundle(
        (PlanNode(node_id="fix-textstats", expected_artifacts=(TARGET,)),),
        whitelist=(TARGET,),
        attempts=1,
        extra_criteria=(mutator,),
    )
    # The mutating criterion must run after the normal tests so Tier-1 passes first; the
    # tree-identity check is what has to catch the mutation, not the test result.
    assert [c.criterion_id for c in bundle.goal.acceptance_criteria][0] == "AC-tests"
    store, result = _run(
        repo,
        tmp_path,
        bundle,
        ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="w-mutator",
        ),
        parallel=1,
    )

    assert result.status == "FAILED"
    assert not result.commits
    # `reasons` carries the classification; `feedback` carries the detail.
    assert any(
        "changed after the gate reviewed it" in reason
        for step in result.steps
        for reason in step.reasons
    ), result.describe()
    assert any(
        "gated tree" in step.feedback and "current tree" in step.feedback for step in result.steps
    ), result.describe()
    assert GitSandbox.main_commit(repo) == store.get_run(result.run_id)["base_commit"]
    store.close()


# ---------------------------------------------------------------------------
# WorktreePool
# ---------------------------------------------------------------------------


def test_pool_hands_out_isolated_worktrees(git_repo, tmp_path) -> None:
    base = GitSandbox.main_commit(git_repo)
    pool = WorktreePool(
        repo_path=git_repo,
        run_root=tmp_path / "pool",
        run_id="run-pool",
        base_commit=base,
        max_size=2,
    )
    first = pool.acquire("step-a")
    second = pool.acquire("step-b")
    assert first.worktree_path != second.worktree_path
    assert first.base_commit == second.base_commit == base

    first.write_file(TARGET, CORRECT_IMPLEMENTATION)
    assert "ACCEPTED" not in second.read_file(TARGET), "worktrees must not share files"

    # Raising max_size is the pool's contract: admission control belongs to the scheduler.
    from daedalus.application.worktree_pool import PoolExhausted

    with pytest.raises(PoolExhausted):
        pool.acquire("step-c")

    pool.release("step-a")
    third = pool.acquire("step-c")
    assert third.worktree_path.exists()
    pool.destroy()


def test_pool_refuses_to_promote_a_diverged_branch(git_repo, tmp_path) -> None:
    base = GitSandbox.main_commit(git_repo)
    pool = WorktreePool(
        repo_path=git_repo,
        run_root=tmp_path / "pool2",
        run_id="run-diverge",
        base_commit=base,
        max_size=1,
    )
    # Move the target branch forward independently, then make the run branch diverge.
    sandbox = pool.acquire("step-a")
    sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
    sandbox.commit("run commit")
    pool.integrate(sandbox)

    other = tmp_path / "other"
    other.mkdir()
    _git(git_repo, ["worktree", "add", "--detach", str(other), "main"], check=True)
    (other / "unrelated.txt").write_text("independent\n", encoding="utf-8")
    _git(other, ["add", "-A"], check=True)
    _git(other, ["commit", "-m", "unrelated main change", "--no-verify"], check=True)
    _git(
        git_repo,
        [
            "update-ref",
            "refs/heads/main",
            _git(other, ["rev-parse", "HEAD"], check=True).stdout.strip(),
        ],
        check=True,
    )

    from daedalus.errors import DaedalusError

    with pytest.raises(DaedalusError, match="diverged"):
        pool.promote_to_target()
    pool.destroy()


def test_rebase_cannot_bypass_a_conservative_pipeline_verdict(git_repo, tmp_path, monkeypatch):
    from dataclasses import replace
    from daedalus.application.gatekeeper.pipeline import Gatekeeper
    from daedalus.application.gatekeeper.decision import GateDecision

    original = Gatekeeper.gate

    def review(self, **kwargs):
        outcome = original(self, **kwargs)
        if kwargs.get("execution_log", "").startswith("re-gate after rebase"):
            return replace(outcome, decision=GateDecision.ESCALATE)
        return outcome

    monkeypatch.setattr(Gatekeeper, "gate", review)
    repo = _prepare_two_module_repo(tmp_path, git_repo)
    before = GitSandbox.main_commit(repo)
    bundle = _bundle(_nodes(), whitelist=(TARGET, EXTRA))
    worker = _BarrierWorker({TARGET: CORRECT_IMPLEMENTATION, EXTRA: EXTRA_FIXED}, parties=2)
    store, result = _run(repo, tmp_path, bundle, worker, parallel=2)
    try:
        assert result.status == "PARTIAL_FAILURE"
        assert result.committed_count == 1
        assert not result.promoted_commit
        assert GitSandbox.main_commit(repo) == before
    finally:
        store.close()
