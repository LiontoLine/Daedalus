"""Daedalus closed-loop demo (Spec §23).

Six scenarios run against a real Git repository, a real SQLite event store and a real
gate. No network, no credential, no model required — the coding worker is scripted, so
what you are watching is the *control plane*, not a model's luck.

  1. legitimate fix            -> Tier-1 pass -> commit -> main advanced
  2. out-of-bounds edit        -> refused before the write, run fails, no commit
  3. syntax error then repair  -> REVISE, retry, pass on attempt 2
  4. touching a protected file -> refused, retries exhausted, ESCALATED
  5. failing test then repair  -> REVISE, retry, pass on attempt 2
  6. semantic review REVISE    -> Tier-2 blocks an otherwise-Tier-1-clean change

Run it:

    python3 -m daedalus.demo            # or: python3 scripts/run_demo.py
"""

from __future__ import annotations

import json
import shutil
import threading
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.gatekeeper.decision import GateDecision
from daedalus.application.gatekeeper.tier2 import (
    SemanticReviewRequest,
    SemanticReviewResult,
    Tier2Gate,
)
from daedalus.application.approvals import ApprovalService
from daedalus.application.cache_worker import CacheMissWorker
from daedalus.application.fsm_service import StateMachineService
from daedalus.application.identity import OwnerRegistry
from daedalus.application.orchestrator import RunOrchestrator, RunResult
from daedalus.application.replay import ReplayService
from daedalus.application.resume import resume_run
from daedalus.application.planner import (
    DeterministicPlanner,
    PlanRequest,
    SpecHardening,
)
from daedalus.application.scheduler import Quota
from daedalus.application.worker import WorkerContext, WorkerResult
from daedalus.domain.identity import Role
from daedalus.errors import DaedalusError
from daedalus.domain.approval import ApprovalDecision
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
from daedalus.infrastructure.git_sandbox import GitSandbox, init_repo, initial_commit
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Completion, Message

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_PROJECT = REPO_ROOT / "examples" / "demo_project"

TARGET = "src/example_project/textstats.py"
SECRETS = "src/example_project/secrets.py"
TEST_COMMAND = "python3 -m pytest tests -q"

CORRECT_IMPLEMENTATION = '''"""Text statistics."""

from __future__ import annotations


def summarize(text: str) -> dict[str, int]:
    """Return word/line/character counts for `text`."""
    tokens = text.split()
    return {
        "lines": len(text.splitlines()),
        "words": len(tokens),
        "characters": len(text),
    }


def average_word_length(text: str) -> float:
    """Mean length of a whitespace-separated token.

    Empty input has no tokens, so the mean is defined as 0.0 rather than undefined.
    """
    tokens = text.split()
    if not tokens:
        return 0.0
    return len("".join(tokens)) / len(tokens)
'''

SECOND_TARGET = "src/example_project/wordrules.py"
SECOND_TEST = "tests/test_wordrules.py"

#: A second module with its own defect, used by the concurrency scenario. It is only
#: present in that scenario's repository, so the single-module scenarios stay unaffected.
SECOND_BROKEN = '''"""Word classification."""

from __future__ import annotations


def is_blank(text: str) -> bool:
    """True when `text` carries no information.

    BUG (intentional): the return value is constant.
    """
    return True
'''

SECOND_FIXED = '''"""Word classification."""

from __future__ import annotations


def is_blank(text: str) -> bool:
    """True when `text` carries no information."""
    return not text.strip()
'''

# Raw string: the whitespace escapes below must reach the test file verbatim, otherwise
# the generated test source would contain a real newline inside a string literal.
SECOND_TEST_SOURCE = r'''"""Tests for the second module."""

from __future__ import annotations

from example_project.wordrules import is_blank


def test_blank_input() -> None:
    assert is_blank("   \n\t ") is True


def test_non_blank_input() -> None:
    assert is_blank("x") is False
'''

BROKEN_IMPLEMENTATION = '''"""Text statistics."""

from __future__ import annotations


def summarize(text: str) -> dict[str, int]:
    """Return word/line/character counts for `text`."""
    return {
        "lines": len(text.splitlines(
        "words": len(text.split()),
        "characters": len(text),
    }


def average_word_length(text: str) -> float:
    tokens = text.split()
    if not tokens:
        return 0.0
    return len("".join(tokens)) / len(tokens)
'''


# ---------------------------------------------------------------------------
# A deliberately simple Tier-2 reviewer, so scenario 6 stays deterministic
# ---------------------------------------------------------------------------


@dataclass
class KeywordReviewer:
    """Approves unless the diff contains one of the configured veto keywords."""

    vetoes: tuple[str, ...]
    name: str = "keyword-reviewer"
    seen_subjects: list[str] = field(default_factory=list)

    def complete(self, prompt: str, *, subject_digest: str) -> str:
        self.seen_subjects.append(subject_digest)
        for veto in self.vetoes:
            if veto in prompt:
                return json.dumps(
                    {
                        "decision": "REVISE",
                        "subject_digest": subject_digest,
                        "reasons": [f"diff mentions {veto!r}, which this review forbids"],
                        "violations": [f"remove the reference to {veto!r}"],
                        "confidence": 0.8,
                    }
                )
        return json.dumps(
            {
                "decision": "APPROVE",
                "subject_digest": subject_digest,
                "reasons": ["the change matches the stated intent"],
                "violations": [],
                "confidence": 0.9,
            }
        )


# ---------------------------------------------------------------------------
# Scenario plumbing
# ---------------------------------------------------------------------------


@dataclass
class BarrierWorker:
    """Runs two workers at once and fails if they never overlap.

    The barrier is the honest way to show concurrency: it is only released when both
    workers are inside `implement` simultaneously, so a serial implementation cannot
    pass by accident.
    """

    writes: dict[str, str]
    parties: int
    name: str = "barrier-worker"
    worker_id: str = "worker-parallel"
    barrier: threading.Barrier = field(init=False)
    overlapped: int = 0
    failures: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.barrier = threading.Barrier(self.parties, timeout=20)

    def implement(self, sandbox: GitSandbox, context: WorkerContext) -> WorkerResult:
        try:
            self.barrier.wait()
        except threading.BrokenBarrierError:
            with self._lock:
                self.failures += 1
            return WorkerResult(
                ok=False,
                summary="the two steps never ran at the same time",
                execution_log="the concurrency barrier timed out",
                worker_id=self.worker_id,
                error="no_concurrency",
            )
        with self._lock:
            self.overlapped += 1
        path = str(context.node.expected_artifacts[0])
        content = self.writes.get(path, "")
        if not content:
            return WorkerResult(
                ok=False,
                summary=f"no script for {path}",
                worker_id=self.worker_id,
                error="no_script",
            )
        sandbox.write_file(path, content)
        return WorkerResult(
            ok=True,
            summary=f"wrote {path}",
            changed_files=(path,),
            worker_id=f"{self.worker_id}-{context.node.node_id}",
            model="barrier",
        )


@dataclass
class Scenario:
    name: str
    title: str
    worker: ScriptedWorker
    expectation: str
    tier2: Tier2Gate | None = None
    worktree_edit: str = ""
    risk_level: RiskLevel = RiskLevel.NORMAL
    max_attempts: int = 3


def _bundle(goal_id: str, objective: str, test_command: str = TEST_COMMAND) -> SpecBundle:
    request = PlanRequest(
        request_id=f"REQ-{goal_id}",
        goal_id=goal_id,
        objective=objective,
        target_paths=(TARGET,),
        test_command=test_command,
        invariants=(
            "no file outside src/example_project/textstats.py may change",
            "the public function signatures stay stable",
        ),
        risk_level=RiskLevel.NORMAL,
        network_policy=NetworkPolicy.DENY,
    )
    planner = DeterministicPlanner()
    return planner.plan(request)


def _prepare_repo(root: Path) -> Path:
    """Copy the demo project into a fresh repository.

    Byte-code caches are excluded on purpose: a stale `__pycache__` copied from the
    source tree would let Python import the *old* module after the worker rewrites the
    `.py` file, which would make the demo lie about what the gate saw.
    """
    repo = init_repo(root / "target_repo")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".DS_Store")
    shutil.copytree(DEMO_PROJECT / "src", repo / "src", ignore=ignore)
    shutil.copytree(DEMO_PROJECT / "tests", repo / "tests", ignore=ignore)
    shutil.copy2(DEMO_PROJECT / "pyproject.toml", repo / "pyproject.toml")
    shutil.copy2(DEMO_PROJECT / ".gitignore", repo / ".gitignore")
    initial_commit(repo, "chore: import the demo project")
    return repo


def _scenarios() -> list[Scenario]:
    return [
        Scenario(
            name="01-legitimate-fix",
            title="A correct fix passes Tier-1 and is committed",
            worker=ScriptedWorker(
                ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
                worker_id="worker-correct",
                summary="count words with split() and handle empty input",
            ),
            expectation="COMPLETED, one commit, main advanced",
        ),
        Scenario(
            name="02-out-of-bounds",
            title="An edit outside the SPEC-03 whitelist is refused before the write",
            worker=ScriptedWorker(
                ops=(
                    FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),
                    FileOp(
                        op="write",
                        path="src/example_project/other_module.py",
                        content="# this file is not whitelisted\n",
                    ),
                ),
                worker_id="worker-escape",
                summary="attempt to fix the target and add an unlisted module",
            ),
            expectation="FAILED, no commit, boundary_violation recorded",
            max_attempts=2,
        ),
        Scenario(
            name="03-syntax-error",
            title="A syntax error is rejected by Tier-1, then repaired on retry",
            worker=ScriptedWorker(
                ops=(FileOp(op="write", path=TARGET, content=BROKEN_IMPLEMENTATION),),
                worker_id="worker-syntax",
                summary="first attempt is not valid Python",
            ),
            expectation="REVISE then commit on a later attempt",
            max_attempts=3,
        ),
        Scenario(
            name="04-protected-path",
            title="A Meta-Spec protected path is refused and the retries are exhausted",
            worker=ScriptedWorker(
                ops=(
                    FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),
                    FileOp(
                        op="write",
                        path=SECRETS,
                        content="API_TOKEN = 'rotated-by-agent'\n",
                    ),
                ),
                worker_id="worker-protected",
                summary="rewrite the credential module to make the tests pass",
            ),
            expectation="ESCALATED after the retry budget is spent",
            max_attempts=2,
        ),
        Scenario(
            name="05-failing-test",
            title="A change that breaks the acceptance tests is rejected by Tier-1",
            worker=ScriptedWorker(
                ops=(
                    FileOp(
                        op="write",
                        path=TARGET,
                        content=CORRECT_IMPLEMENTATION.replace(
                            "    tokens = text.split()\n    if not tokens:\n        return 0.0\n",
                            "",
                        ),
                    ),
                ),
                worker_id="worker-broken-test",
                summary="fix word counting but leave the empty-input crash in place",
            ),
            expectation="REVISE then commit once the empty-input case is handled",
            max_attempts=3,
        ),
        Scenario(
            name="06-tier2-revise",
            title="Tier-2 blocks a change that passed every deterministic check",
            worker=ScriptedWorker(
                ops=(
                    FileOp(
                        op="write",
                        path=TARGET,
                        content=CORRECT_IMPLEMENTATION.replace(
                            "def summarize",
                            "# TODO: revisit this later\n\n\ndef summarize",
                        ),
                    ),
                ),
                worker_id="worker-tier2",
                summary="technically correct change with a TODO the reviewer dislikes",
            ),
            expectation="Tier-1 PASS, Tier-2 REVISE, no commit",
            tier2=Tier2Gate(reviewer=KeywordReviewer(vetoes=("TODO",))),
            max_attempts=1,
        ),
    ]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _rule(char: str = "=", width: int = 96) -> str:
    return char * width


def run_scenario(scenario: Scenario, workspace: Path) -> dict[str, Any]:
    root = workspace / scenario.name
    root.mkdir(parents=True, exist_ok=True)
    repo = _prepare_repo(root)
    store = EventStore(root / "daedalus.db")

    bundle = _bundle(scenario.name.replace("-", "_"), scenario.title)
    if scenario.risk_level is not RiskLevel.NORMAL:
        bundle = _with_risk(bundle, scenario.risk_level)

    # Each scenario gets an explicit attempt sequence, so a REVISE loop is observable
    # rather than simulated.
    worker = _with_repair(scenario.worker, scenario)

    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=root / "worktrees",
        bundle=bundle,
        worker=worker,
        tier2=scenario.tier2,
        quota=Quota(max_parallel_steps=1),
        target_branch="main",
        # The per-scenario expectations below describe final outcomes, so these run in batch
        # mode. Parking and owner approval get their own scenario (09).
        park_on_escalation=False,
    )
    main_before = GitSandbox.main_commit(repo)
    orchestrator.register_spec()
    result = orchestrator.run()

    main_after = GitSandbox.main_commit(repo)
    report = {
        "scenario": scenario.name,
        "title": scenario.title,
        "expectation": scenario.expectation,
        "status": result.status,
        "steps": [outcome.to_row() for outcome in result.steps],
        "commits": [commit[:12] for commit in result.commits],
        "main_before": main_before[:12],
        "main_after": main_after[:12],
        "main_advanced": main_before != main_after,
        "events": store.event_count(),
        "sequences_ok": not store.verify_sequences(),
        "idempotency_ok": _idempotency_ok(store),
        "metrics": store.metric_summary(),
        "timeline": [row["summary"] for row in store.timeline_for_run(result.run_id)],
        "notes": result.notes,
        "runs": store.list_runs(),
        "replay": _replay_check(store),
        "findings": _findings(store, result),
    }
    store.close()
    return report


@dataclass
class AttemptScriptWorker:
    """Applies a different operation script on each successive attempt.

    This is the honest way to demo the REVISE loop: attempt 1 really does produce the
    defect, the gate really does reject it, and attempt 2 is a genuinely different
    candidate that the gate evaluates from scratch.
    """

    attempts: tuple[tuple[FileOp, ...], ...]
    worker_id: str = "worker-repairing"
    name: str = "attempt-script-worker"
    _call: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def implement(self, sandbox: GitSandbox, context: WorkerContext) -> WorkerResult:
        # Workers may run concurrently, so the attempt counter needs a lock.
        with self._lock:
            index = self._call
            self._call += 1
        script = self.attempts[index] if index < len(self.attempts) else ()
        delegate = ScriptedWorker(
            ops=script,
            worker_id=self.worker_id,
            summary=f"attempt {index + 1} script",
        )
        return delegate.implement(sandbox, context)


def _with_repair(worker: ScriptedWorker, scenario: Scenario) -> AttemptScriptWorker:
    """Turn a one-shot script into an attempt sequence, where a repair exists.

    A boundary escape and a protected-path attempt have no repair: repeating them is
    exactly what the terminal-failure rule in Spec §17 forbids, so those scenarios keep
    a single script and are expected to escalate.
    """
    repairs: dict[str, tuple[FileOp, ...]] = {
        "03-syntax-error": (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
        "05-failing-test": (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
        "06-tier2-revise": (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
    }
    repair = repairs.get(scenario.name)
    if repair is None:
        return AttemptScriptWorker(attempts=(worker.ops,), worker_id=worker.worker_id)
    return AttemptScriptWorker(attempts=(worker.ops, repair), worker_id=worker.worker_id)


def _with_risk(bundle: SpecBundle, risk: RiskLevel) -> SpecBundle:
    from daedalus.domain.spec import GoalSpec

    goal: GoalSpec = bundle.goal
    return SpecBundle(
        goal=GoalSpec(
            goal_id=goal.goal_id,
            objective=goal.objective,
            invariants=goal.invariants,
            acceptance_criteria=goal.acceptance_criteria,
            risk_level=risk,
            owner_id=goal.owner_id,
        ),
        plan=bundle.plan,
        boundary=bundle.boundary,
        meta=bundle.meta,
    )


def _idempotency_ok(store: EventStore) -> bool:
    """No execution may hold two commits for the same step."""
    seen: dict[tuple[str, str], int] = {}
    for event in store.all_events():
        if event.event_type != "StepCommitted":
            continue
        key = (event.execution_id, event.step_id)
        seen[key] = seen.get(key, 0) + 1
    return all(count == 1 for count in seen.values())


def _replay_check(store: EventStore) -> dict[str, str]:
    """Rebuild step state from the log and compare with the projection."""
    from daedalus.application.fsm_service import StateMachineService

    replayed = StateMachineService(store).rebuild_step_states()
    mismatches: dict[str, str] = {}
    for row in store.list_runs():
        for step in store.list_steps(str(row["run_id"])):
            step_id = str(step["step_id"])
            derived = replayed.get(step_id)
            if derived is None:
                mismatches[step_id] = f"projection={step['state']} replay=<absent>"
            elif derived.value != str(step["state"]):
                mismatches[step_id] = f"projection={step['state']} replay={derived.value}"
    return mismatches


def _findings(store: EventStore, result: RunResult) -> dict[str, Any]:
    """The audit answers the Spec §27 questions from persisted evidence alone."""
    rejected: list[str] = []
    for row in store.latest_gate_results(result.execution_id):
        decisions = json.loads(row["reasons"]) if row["reasons"] else []
        if row["decision"] in {"FAIL", "REVISE", "ESCALATE"}:
            rejected.append(f"tier{row['tier']} {row['decision']}: {' | '.join(decisions)[:200]}")
    return {
        "gate_rejections": rejected,
        "escalated": [s.step_id for s in result.steps if s.state == "ESCALATED"],
        "protected_touched": [
            path
            for event in store.all_events()
            for path in ([event.payload.get("path")] if event.payload.get("path") else [])
        ][:8],
    }


def _prepare_parallel_repo(root: Path) -> Path:
    """A repository with a second broken module, for the concurrency scenario."""
    repo = _prepare_repo(root)
    (repo / SECOND_TARGET).write_text(SECOND_BROKEN, encoding="utf-8")
    (repo / SECOND_TEST).write_text(SECOND_TEST_SOURCE, encoding="utf-8")
    initial_commit(repo, "test: add a second module with its own defect")
    return repo


def run_parallel_scenario(workspace: Path) -> dict[str, Any]:
    """Scenario 07: two independent nodes in flight at once, integrating through a rebase.

    This is the Phase-2 capability that Phase 1 could not express: one worktree per run
    capped the DAG at a single step, so `max_parallel_steps` was a comment rather than a
    constraint. Both nodes are admitted in the same scheduling round, so both branch from
    the same commit; the second one to finish must rebase onto the run branch and be
    re-gated before it is allowed to land.
    """
    name = "07-concurrent-steps"
    root = workspace / name
    root.mkdir(parents=True, exist_ok=True)
    repo = _prepare_parallel_repo(root)
    store = EventStore(root / "daedalus.db")

    textstats_tests = AcceptanceCriterion(
        criterion_id="AC-textstats",
        kind=AssertionKind.EXIT_CODE,
        statement="the textstats tests pass",
        command="python3 -m pytest tests/test_textstats.py -q",
    )
    wordrules_tests = AcceptanceCriterion(
        criterion_id="AC-wordrules",
        kind=AssertionKind.EXIT_CODE,
        statement="the wordrules tests pass",
        command="python3 -m pytest tests/test_wordrules.py -q",
    )
    bundle = SpecBundle(
        goal=GoalSpec(
            goal_id="GOAL-concurrent",
            objective="fix both modules",
            invariants=("no file outside the declared paths may change",),
            # A node-scoped criterion for each module, and a goal that declares the union:
            # splitting work across nodes must not weaken what gets verified.
            acceptance_criteria=(textstats_tests, wordrules_tests),
            risk_level=RiskLevel.NORMAL,
        ),
        plan=PlanSpec(
            plan_id="PLAN-concurrent",
            goal_id="GOAL-concurrent",
            nodes=(
                PlanNode(
                    node_id="fix-textstats",
                    objective="fix the word counter",
                    expected_artifacts=(TARGET,),
                    allowed_tools=("read", "write", "test"),
                    retry_policy=RetryPolicy(max_attempts=2),
                    timeout_sec=300,
                    intent="count words with split() and handle empty input",
                    extra={"acceptance_criteria": [textstats_tests.to_dict()]},
                ),
                PlanNode(
                    node_id="fix-wordrules",
                    objective="fix is_blank",
                    expected_artifacts=(SECOND_TARGET,),
                    allowed_tools=("read", "write", "test"),
                    retry_policy=RetryPolicy(max_attempts=2),
                    timeout_sec=300,
                    intent="is_blank must actually inspect its input",
                    extra={"acceptance_criteria": [wordrules_tests.to_dict()]},
                ),
            ),
        ),
        boundary=BoundarySpec(
            boundary_id="BOUND-concurrent",
            goal_id="GOAL-concurrent",
            fs_whitelist=(TARGET, SECOND_TARGET),
            fs_denylist=MetaSpec.default().protected_paths,
            network_policy=NetworkPolicy.DENY,
            allowed_tools=("read", "write", "test"),
        ),
        meta=MetaSpec.default(),
    )
    bundle.validate()
    bundle = SpecHardening(meta=bundle.meta).harden(bundle)

    worker = BarrierWorker(
        writes={TARGET: CORRECT_IMPLEMENTATION, SECOND_TARGET: SECOND_FIXED},
        parties=2,
    )
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=root / "worktrees",
        bundle=bundle,
        worker=worker,
        quota=Quota(max_parallel_steps=2),
        target_branch="main",
        park_on_escalation=False,
    )
    main_before = GitSandbox.main_commit(repo)
    orchestrator.register_spec()
    result = orchestrator.run()
    main_after = GitSandbox.main_commit(repo)

    report = {
        "scenario": name,
        "title": "Two independent steps run at once, integrate via rebase, and re-gate",
        "expectation": "COMPLETED, both committed, >=1 rebase, target branch advanced",
        "status": result.status,
        "steps": [outcome.to_row() for outcome in result.steps],
        "commits": [commit[:12] for commit in result.commits],
        "main_before": main_before[:12],
        "main_after": main_after[:12],
        "main_advanced": main_before != main_after,
        "events": store.event_count(),
        "sequences_ok": not store.verify_sequences(),
        "idempotency_ok": _idempotency_ok(store),
        "metrics": store.metric_summary(),
        "timeline": [row["summary"] for row in store.timeline_for_run(result.run_id)],
        "notes": result.notes,
        "runs": store.list_runs(),
        "replay": _replay_check(store),
        "findings": _findings(store, result),
        "parallel": {
            "overlapped": worker.overlapped,
            "barrier_failures": worker.failures,
            "rebase_count": result.rebase_count,
            "run_branch": result.run_branch,
            "rebase_events": [
                event.payload
                for event in store.all_events()
                if event.event_type == "RunRebaseRequired"
            ],
        },
    }
    store.close()
    return report


def run_rollback_replay_scenario(workspace: Path) -> dict[str, Any]:
    """Scenario 08: the Spec §12.1 sequence, plus a §13.2 cache hit.

    A run completes, is rolled back (which deletes nothing and does not touch the target
    branch), and is then replayed as a *new execution* from the same base commit. The
    replay must reuse the already-verified artifact rather than re-running the worker —
    the worker for the replay is deliberately one that refuses to work, so a completed
    replay is proof that the reuse path, not the execution path, did the job.
    """
    name = "08-rollback-and-replay"
    root = workspace / name
    root.mkdir(parents=True, exist_ok=True)
    repo = _prepare_repo(root)
    store = EventStore(root / "daedalus.db")
    bundle = _bundle("GOAL-rollback-replay", "fix the word counter")

    first_orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=root / "worktrees",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-first",
            summary="count words with split() and handle empty input",
        ),
        quota=Quota(max_parallel_steps=1),
        reuse_artifacts=True,
    )
    first_orchestrator.register_spec()
    first = first_orchestrator.run()
    main_after_first = GitSandbox.main_commit(repo)

    events_before_rollback = store.event_count()
    service = ReplayService(store=store, fsm=StateMachineService(store))
    rollback = service.rollback(
        first.run_id, reason="the owner found a regression after the run completed"
    )
    events_after_rollback = store.event_count()

    replay = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=root / "replays",
        bundle=bundle,
        worker=CacheMissWorker(),
        quota=Quota(max_parallel_steps=1),
        reuse_artifacts=True,
        parent_execution_id=first.execution_id,
        replay_from_commit=store.get_run(first.run_id)["base_commit"],
    )
    replay.register_spec()
    replayed = replay.run()

    hits = [event for event in store.all_events() if event.event_type == "StepCacheHit"]
    report = {
        "scenario": name,
        "title": "Rollback deletes nothing; a replay reuses the verified artifact",
        "expectation": (
            "rollback CANCELLED the run without touching main; the replay is a new "
            "execution and every step is REUSED"
        ),
        "status": replayed.status,
        "steps": [outcome.to_row() for outcome in replayed.steps],
        "commits": [commit[:12] for commit in replayed.commits],
        "main_before": main_after_first[:12],
        "main_after": GitSandbox.main_commit(repo)[:12],
        "main_advanced": GitSandbox.main_commit(repo) != main_after_first,
        "events": store.event_count(),
        "sequences_ok": not store.verify_sequences(),
        "idempotency_ok": _idempotency_ok(store),
        "metrics": store.metric_summary(),
        "timeline": [row["summary"] for row in store.timeline_for_run(replayed.run_id)],
        "notes": replayed.notes,
        "runs": store.list_runs(),
        "replay": _replay_check(store),
        "findings": _findings(store, replayed),
        "rollback": {
            "run_id": rollback.run_id,
            "status": rollback.status,
            "stopped": list(rollback.stopped_steps),
            "superseded": list(rollback.superseded_steps),
            "new_execution_id": rollback.new_execution_id,
            "rolled_back": rollback.describe()["rolled_back"],
            "not_rolled_back": rollback.describe()["not_rolled_back"],
            "events_added": events_after_rollback - events_before_rollback,
            "events_deleted": 0,
            "main_untouched_by_rollback": GitSandbox.main_commit(repo) == main_after_first,
        },
        "reuse": {
            "replayed_run_id": replayed.run_id,
            "source_run_id": first.run_id,
            "cache_hits": len(hits),
            "source_artifact": str(hits[0].payload.get("source_artifact_digest", ""))[:12]
            if hits
            else "",
            "gate_result_ref": str(hits[0].payload.get("gate_result_ref", ""))[:12]
            if hits
            else "",
            "same_commit": bool(replayed.commits) and replayed.commits[0] == first.commits[0],
            "reuse_key": hits[0].payload.get("reuse_key") if hits else {},
        },
    }
    store.close()
    return report


def run_approval_scenario(workspace: Path) -> dict[str, Any]:
    """Scenario 09: the human-in-the-loop cycle.

    A semantic review escalates, the run parks and keeps the pending change alive, a human
    owner approves that exact artifact, and the resumed run commits it. Without this cycle
    the system is correct but unusable: every escalation would be a dead end.

    The spec is deliberately HIGH risk and the workspace deliberately has an owner enrolled,
    because that is the only configuration in which Spec §3.2 does anything. A demo that ran
    with no owners would exercise the unenrolled path where a typed name is accepted — which
    is the path that needs no demonstration, and is precisely how a §3.2 regression would go
    unnoticed by CI.
    """
    name = "09-owner-approval"
    owner_secret_env = "DAEDALUS_DEMO_OWNER_SECRET"
    demo_env = {owner_secret_env: "demo-owner-signing-secret"}
    root = workspace / name
    root.mkdir(parents=True, exist_ok=True)
    repo = _prepare_repo(root)
    store = EventStore(root / "daedalus.db")
    bundle = _with_risk(_bundle("GOAL-owner-approval", "fix the word counter"), RiskLevel.HIGH)

    class EscalatingReviewer:
        """A well-formed, subject-bound ESCALATE: the kind of question a human must answer."""

        name = "escalating-reviewer"

        def complete(self, prompt: str, *, subject_digest: str) -> str:
            return json.dumps(
                {
                    "decision": "ESCALATE",
                    "subject_digest": subject_digest,
                    "reasons": ["the change alters a function other modules depend on"],
                    "violations": [],
                    "confidence": 0.35,
                }
            )

    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=root / "worktrees",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-park",
            summary="count words with split() and handle empty input",
        ),
        tier2=Tier2Gate(reviewer=EscalatingReviewer()),
        quota=Quota(max_parallel_steps=1),
        park_on_escalation=True,
    )
    main_before = GitSandbox.main_commit(repo)
    identity = OwnerRegistry(store=store, environ=demo_env)
    identity.enroll("owner@example", role=Role.OWNER, secret_env=owner_secret_env)
    orchestrator.identity = identity
    orchestrator.register_spec()
    # §3.2 layer one: the frozen spec itself must be signed before any work starts.
    orchestrator.approve_spec(
        approved_by="owner@example",
        signature=identity.sign("owner@example", orchestrator.spec_digest),
    )
    parked = orchestrator.run()

    step = store.list_steps(parked.run_id)[0]
    step_id = str(step["step_id"])
    artifact_digest = str(store.artifacts_for_step(step_id)[-1]["artifact_digest"])
    worktree = str(step["worktree_path"])
    # Measured *while parked*: the resume legitimately removes the worktree once the work has
    # landed, so checking later would report the wrong thing.
    worktree_kept_while_parked = Path(worktree).is_dir()
    # §3.2 layer two: the decision that lets the escalated artifact commit must also be
    # signed, and the signature names this exact artifact.
    signature = identity.sign_step(
        "owner@example",
        parked.run_id,
        step_id,
        "proceed",
        artifact_digest,
        attempt=int(step["attempt"]),
    )
    approval_service = ApprovalService(
        store=store, fsm=StateMachineService(store), identity=identity
    )
    pending = approval_service.pending_escalations(parked.run_id)
    approval = approval_service.approve(
        run_id=parked.run_id,
        step_id=step_id,
        decision=ApprovalDecision.PROCEED,
        approved_by="owner@example",
        note="read the diff; the callers are all updated in the same change",
        artifact_digest=artifact_digest,
        signature=signature,
    )
    # An unsigned decision must be refused here, so the demo proves the control is enforcing
    # rather than merely present. The refusal happens before anything is recorded, so the
    # probe cannot disturb the run — which an earlier version of this scenario did, on a
    # NORMAL-risk spec where an unsigned retry is legitimately allowed.
    unsigned_refused = False
    try:
        approval_service.approve(
            run_id=parked.run_id,
            step_id=step_id,
            decision=ApprovalDecision.RETRY,
            approved_by="owner@example",
            note="unsigned attempt, which must not be accepted",
        )
    except DaedalusError:
        unsigned_refused = True
    resumed = resume_run(
        store=store, run_id=parked.run_id, workspace=str(root), identity=identity
    )
    main_after = GitSandbox.main_commit(repo)

    report = {
        "scenario": name,
        "title": "An escalation parks the run; the owner approves; the resume commits",
        "expectation": (
            "parked in AWAITING_APPROVAL with the worktree kept -> approval binds to the "
            "artifact -> resume commits it and records who approved"
        ),
        "status": resumed.status,
        "steps": [outcome.to_row() for outcome in resumed.steps],
        "commits": [commit[:12] for commit in resumed.commits],
        "approval_verified": approval.verified,
        "approval_scheme": approval.approval_scheme,
        "identity_enforced": identity.enforced,
        "unsigned_decision_refused": unsigned_refused,
        "main_before": main_before[:12],
        "main_after": main_after[:12],
        "main_advanced": main_before != main_after,
        "events": store.event_count(),
        "sequences_ok": not store.verify_sequences(),
        "idempotency_ok": _idempotency_ok(store),
        "metrics": store.metric_summary(),
        "timeline": [row["summary"] for row in store.timeline_for_run(parked.run_id)],
        "notes": resumed.notes,
        "runs": store.list_runs(),
        "replay": _replay_check(store),
        "findings": _findings(store, resumed),
        "human_loop": {
            "parked_status": parked.status,
            "parked_escalations": len(pending),
            "worktree_kept": worktree_kept_while_parked,
            "artifact_digest": artifact_digest[:12],
            "approval_id": approval.approval_id,
            "approved_by": approval.approved_by,
            "bound_artifact": approval.artifact_digest[:12],
            "commit_records_owner_override": any(
                event.event_type == "StepCommitted" and event.payload.get("owner_override")
                for event in store.all_events()
            ),
            "commit_approved_by": next(
                (
                    str(event.payload.get("approved_by", ""))
                    for event in store.all_events()
                    if event.event_type == "StepCommitted" and event.payload.get("owner_override")
                ),
                "",
            ),
        },
    }
    store.close()
    return report


def _print_report(report: dict[str, Any]) -> None:
    status = report["status"]
    marker = {
        "COMPLETED": "PASS",
        "PARTIAL_FAILURE": "PARTIAL",
        "FAILED": "BLOCKED",
    }.get(status, status)

    print(_rule())
    print(f"[{marker}] {report['scenario']}  —  {report['title']}")
    print(f"  expectation : {report['expectation']}")
    print(f"  status      : {status}   commits={report['commits']}")
    print(
        f"  main        : {report['main_before']} -> {report['main_after']} "
        f"(advanced={report['main_advanced']})"
    )
    for step in report["steps"]:
        print(
            f"    step {step['node_id']:<22} {step['state']:<12} "
            f"attempt={step['attempt']} gate={step['gate']:<8} commit={step['commit']}"
        )
        if step["feedback"]:
            first = step["feedback"].splitlines()[0][:110]
            print(f"      feedback: {first}")
    metrics = report["metrics"]
    print(
        f"  events={report['events']} sequences_ok={report['sequences_ok']} "
        f"idempotency_ok={report['idempotency_ok']} "
        f"replay_mismatches={len(report['replay'])}"
    )
    print(
        f"  metrics     : step_success_rate={metrics['step_success_rate']:.2f} "
        f"gate_reject_rate={metrics['gate_reject_rate']:.2f} "
        f"gate_decisions={metrics['gate_decisions']} retry_rate={metrics['retry_rate']:.2f}"
    )
    for rejection in report["findings"]["gate_rejections"][:4]:
        print(f"  rejected    : {rejection}")
    if report["findings"]["escalated"]:
        print(f"  escalated   : {report['findings']['escalated']}")
    for note in report["notes"][:3]:
        print(f"  note        : {note}")
    rollback = report.get("rollback")
    if rollback:
        print(
            f"  rollback    : {rollback['status']} stopped={len(rollback['stopped'])} "
            f"superseded={len(rollback['superseded'])} "
            f"events_added={rollback['events_added']} events_deleted={rollback['events_deleted']}"
        )
        print(
            f"    main untouched by rollback: {rollback['main_untouched_by_rollback']} "
            f"| next execution id: {rollback['new_execution_id']}"
        )
        print(f"    rolled back    : {', '.join(rollback['rolled_back'])}")
        print(f"    NOT rolled back: {', '.join(rollback['not_rolled_back'][:3])} ...")
    reuse = report.get("reuse")
    if reuse:
        print(
            f"  reuse       : cache_hits={reuse['cache_hits']} "
            f"source={reuse['source_artifact']} gate={reuse['gate_result_ref']} "
            f"same_commit={reuse['same_commit']}"
        )
        key = reuse["reuse_key"]
        if key:
            print(
                "    reuse key : "
                + " ".join(f"{name}={str(value)[:8]}" for name, value in sorted(key.items()))
            )
    loop = report.get("human_loop")
    if loop:
        print(
            f"  escalation  : parked={loop['parked_status']} "
            f"pending={loop['parked_escalations']} worktree_kept={loop['worktree_kept']}"
        )
        print(
            f"    approval  : {loop['approval_id'][:20]} by {loop['approved_by']} "
            f"bound_to_artifact={loop['bound_artifact']}"
        )
        print(
            f"    commit    : owner_override={loop['commit_records_owner_override']} "
            f"approved_by={loop['commit_approved_by']}"
        )
    parallel = report.get("parallel")
    if parallel:
        print(
            f"  concurrency : overlapped={parallel['overlapped']} "
            f"barrier_failures={parallel['barrier_failures']} "
            f"rebases={parallel['rebase_count']} "
            f"run_branch={parallel['run_branch']}"
        )
        for event in parallel["rebase_events"]:
            print(
                f"    REBASE_REQUIRED: {str(event.get('node_id'))} "
                f"{str(event.get('commit'))[:12]} onto {str(event.get('upstream'))[:12]}"
            )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    keep = "--keep" in argv
    only = [a for a in argv if not a.startswith("-")]

    workspace = Path(tempfile.mkdtemp(prefix="daedalus-demo-"))
    print(_rule("*"))
    print("Daedalus closed-loop demo")
    print(f"workspace: {workspace}")
    print(_rule("*"))

    reports: list[dict[str, Any]] = []
    failures: list[str] = []
    parallel_name = "07-concurrent-steps"
    for scenario in _scenarios():
        if only and scenario.name not in only:
            continue
        report = run_scenario(scenario, workspace)
        reports.append(report)
        _print_report(report)
        if report["replay"]:
            failures.append(f"{scenario.name}: replay mismatch {report['replay']}")
        if not report["sequences_ok"]:
            failures.append(f"{scenario.name}: event sequence gap")
        if not report["idempotency_ok"]:
            failures.append(f"{scenario.name}: duplicate commit for one step")

    if not only or parallel_name in only:
        parallel_report = run_parallel_scenario(workspace)
        reports.append(parallel_report)
        _print_report(parallel_report)
        if not parallel_report["parallel"]["overlapped"] >= 2:
            failures.append(f"{parallel_name}: the two steps never overlapped")
        if parallel_report["replay"]:
            failures.append(f"{parallel_name}: replay mismatch {parallel_report['replay']}")
        if not parallel_report["sequences_ok"]:
            failures.append(f"{parallel_name}: event sequence gap")

    rollback_name = "08-rollback-and-replay"
    if not only or rollback_name in only:
        rollback_report = run_rollback_replay_scenario(workspace)
        reports.append(rollback_report)
        _print_report(rollback_report)
        if rollback_report["reuse"]["cache_hits"] < 1:
            failures.append(f"{rollback_name}: the replay did not reuse a verified artifact")
        if not rollback_report["reuse"]["same_commit"]:
            failures.append(f"{rollback_name}: the replay produced a different commit")
        if not rollback_report["rollback"]["main_untouched_by_rollback"]:
            failures.append(f"{rollback_name}: rollback moved the target branch")
        if rollback_report["replay"]:
            failures.append(f"{rollback_name}: replay mismatch {rollback_report['replay']}")

    approval_name = "09-owner-approval"
    if not only or approval_name in only:
        approval_report = run_approval_scenario(workspace)
        reports.append(approval_report)
        _print_report(approval_report)
        loop = approval_report["human_loop"]
        if loop["parked_status"] != "AWAITING_APPROVAL":
            failures.append(f"{approval_name}: the run did not park on escalation")
        if not loop["worktree_kept"]:
            failures.append(f"{approval_name}: the parked worktree was discarded")
        if not loop["commit_records_owner_override"]:
            failures.append(f"{approval_name}: the commit does not record the owner override")
        if not approval_report["commits"]:
            failures.append(f"{approval_name}: the approved artifact was not committed")

    print(_rule("*"))
    committed = [r for r in reports if r["main_advanced"]]
    blocked = [r for r in reports if not r["main_advanced"]]
    print(
        f"summary: {len(reports)} scenarios | {len(committed)} advanced main | "
        f"{len(blocked)} changed nothing"
    )
    print("         every refusal happened before an authoritative write")
    if failures:
        print("FAILURES:")
        for failure in failures:
            print(f"  - {failure}")
    print(_rule("*"))

    if keep:
        print(f"workspace kept at {workspace}")
    else:
        shutil.rmtree(workspace, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
