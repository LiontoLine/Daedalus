"""Data security and state-machine consistency fixes.

Each test here corresponds to a specific gap found in the section-by-section audit, and each one
would have failed before the fix. The two that matter most:

* an outbound prompt containing a credential is **refused**, not redacted — redacting would make
  the model write the placeholder back into the file;
* a commit is refused once its execution has expired (Spec §11.1), which the commit path never
  checked.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from daedalus.application.coding_worker import FileOp, ModelWorker, ScriptedWorker
from daedalus.application.fsm_service import StateMachineService
from daedalus.application.gatekeeper.decision import GateDecision
from daedalus.application.gatekeeper.tier1 import Tier1Gate
from daedalus.application.gatekeeper.tier2 import (
    SemanticReviewRequest,
    Tier2Gate,
)
from daedalus.application.orchestrator import NON_RETRYABLE_ERRORS, RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.scheduler import Quota, Scheduler
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
from daedalus.infrastructure.redact import REDACTED, redact_text
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Completion, Message
from daedalus.security.outbound import (
    SecretInPayload,
    assert_outbound_clean,
    scan_added_lines,
    scan_text,
)
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

FAKE_SECRET = "sk-abcdefghijklmnopqrstuvwxyz012345"


def _boundary() -> BoundarySpec:
    return BoundarySpec(
        boundary_id="B", goal_id="G", fs_whitelist=(TARGET,), network_policy=NetworkPolicy.DENY
    )


def _node() -> PlanNode:
    return PlanNode(node_id="n1", expected_artifacts=(TARGET,))


# ---------------------------------------------------------------------------
# Outbound secret guard
# ---------------------------------------------------------------------------


def test_the_scanner_finds_credential_shapes_without_returning_values() -> None:
    findings = scan_text(f"token = '{FAKE_SECRET}'")
    assert findings and findings[0].kind == "openai_key"
    # The finding identifies the kind and count, never the value.
    assert FAKE_SECRET not in str([f.describe() for f in findings])


@pytest.mark.parametrize("source", [
    "self.secret = self.secret or settings.SECRET_KEY",
    "    secret=self.secret,",
    "build_token(secret=self.secret)",
    "secret = settings.SECRET_KEY",
])
def test_computed_credential_references_are_not_literal_credentials(source):
    assert scan_text(source) == ()
    assert redact_text(source) == source
    encoded = json.dumps({"candidate_sources": [{"text": source}]})
    assert scan_text(encoded) == ()
    assert redact_text(encoded) == encoded


@pytest.mark.parametrize("source", [
    'secret = "self.password"',
    'secret = "literal-credential"',
    'secret = unquoted_credential',
    'secret = self.secret or "literal-credential"',
    'secret = settings.SECRET_KEY and "literal-credential"',
    '# secret = "literal-credential"',
])
def test_reference_handling_cannot_hide_literal_fallback_credentials(source):
    assert any(f.kind == "key_value" for f in scan_text(source))
    scrubbed = redact_text(source)
    assert REDACTED in scrubbed
    assert "literal-credential" not in scrubbed
    assert "unquoted_credential" not in scrubbed
    encoded = json.dumps({"text": source})
    assert any(f.kind == "key_value" for f in scan_text(encoded))
    assert REDACTED in redact_text(encoded)


def test_only_added_lines_are_scanned() -> None:
    """A credential that already existed must not block every edit to that file."""
    patch = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        f" context line with {FAKE_SECRET}\n"
        "+SAFE = 1\n"
    )
    assert scan_added_lines(patch) == ()

    introducing = patch + f'+LEAK = "{FAKE_SECRET}"\n'
    assert scan_added_lines(introducing), "introducing a credential must be caught"


def test_the_guard_refuses_and_explains_why_it_does_not_redact() -> None:
    with pytest.raises(SecretInPayload) as error:
        assert_outbound_clean(f"content {FAKE_SECRET}", where="a test")
    message = error.value.message
    assert "refusing to send" in message
    assert "placeholder" in message, "the reason for refusing rather than redacting must be stated"


def test_the_coding_worker_refuses_to_send_a_credential(tmp_path: Path) -> None:
    class LeakyClient:
        name = "leaky"
        model = "leaky"

        def complete(self, messages, **kwargs):  # noqa: ANN001, ANN201
            raise AssertionError("the client must not be called when the prompt is unclean")

    from daedalus.application.worker import WorkerContext
    from daedalus.infrastructure.git_sandbox import init_repo, initial_commit

    repo = init_repo(tmp_path / "leaky")
    (repo / TARGET).parent.mkdir(parents=True, exist_ok=True)
    (repo / TARGET).write_text(f'KEY = "{FAKE_SECRET}"\n', encoding="utf-8")
    initial_commit(repo, "add a file with a credential in it")

    from daedalus.infrastructure.git_sandbox import GitSandbox

    sandbox = GitSandbox.create_from(
        repo_path=repo, run_root=tmp_path / "wt", name="leaky", base_commit=GitSandbox.main_commit(repo)
    )
    bundle = SpecBundle(
        goal=GoalSpec(
            goal_id="G",
            objective="fix it",
            acceptance_criteria=(
                __import__("daedalus.domain.spec", fromlist=["AcceptanceCriterion"])
                .AcceptanceCriterion(
                    criterion_id="AC", kind=__import__("daedalus.domain.spec", fromlist=["AssertionKind"]).AssertionKind.EXIT_CODE,
                    command="true",
                ),
            ),
            risk_level=RiskLevel.NORMAL,
        ),
        plan=PlanSpec(plan_id="P", goal_id="G", nodes=(_node(),)),
        boundary=_boundary(),
        meta=MetaSpec.default(),
    )
    result = ModelWorker(client=LeakyClient()).implement(
        sandbox,
        WorkerContext(
            step_id="s1", execution_id="e1", node=_node(), bundle=bundle,
            base_commit=sandbox.base_commit, attempt=1,
        ),
    )
    assert not result.ok
    assert result.error == "secret_in_payload"
    assert "credential" in result.summary
    assert "secret_in_payload" in NON_RETRYABLE_ERRORS, "retrying would re-send it"
    sandbox.remove()


def test_the_reviewer_fails_closed_when_the_diff_carries_a_credential() -> None:
    class NeverCalled:
        def complete(self, prompt: str, *, subject_digest: str) -> str:
            raise AssertionError("the reviewer must not be called")

    request = SemanticReviewRequest(
        step_id="s1",
        execution_id="e1",
        artifact_digest="a1",
        goal_intent="fix it",
        node_intent="fix it",
        changed_files=(TARGET,),
        patch=f"--- a\n+++ b\n+KEY = \"{FAKE_SECRET}\"\n",
    )
    result = Tier2Gate(reviewer=NeverCalled()).review(request)
    assert result.decision is GateDecision.ESCALATE
    assert result.fail_closed
    assert result.failure_reason == "secret_in_payload"


@pytest.fixture()
def sandbox(git_repo, tmp_path):
    """A worktree, mirroring the fixture the gatekeeper tests use."""
    from daedalus.infrastructure.git_sandbox import GitSandbox

    box = GitSandbox.create(
        repo_path=git_repo, run_root=tmp_path / "gate-wt", name="gate", base_ref="HEAD"
    )
    yield box
    box.remove()


def test_tier1_flags_a_change_that_introduces_a_credential(sandbox) -> None:
    gate = Tier1Gate(
        goal=GoalSpec(
            goal_id="G",
            objective="fix it",
            acceptance_criteria=(
                __import__("daedalus.domain.spec", fromlist=["AcceptanceCriterion"]).AcceptanceCriterion(
                    criterion_id="AC",
                    kind=__import__("daedalus.domain.spec", fromlist=["AssertionKind"]).AssertionKind.EXIT_CODE,
                    command="true",
                ),
            ),
            risk_level=RiskLevel.NORMAL,
        ),
        plan_node=_node(),
        boundary=_boundary(),
        meta=MetaSpec.default(),
    )
    from daedalus.domain.artifacts import Artifact

    sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION + f'\nKEY = "{FAKE_SECRET}"\n')
    diff = sandbox.diff()
    report = gate.run(
        step_id="s1",
        execution_id="e1",
        sandbox=sandbox,
        artifact=Artifact(
            step_id="s1", execution_id="e1", parent_commit=sandbox.base_commit,
            changed_files=diff.files,
        ),
    )
    assert report.decision is GateDecision.REVISE
    assert any(check.name == "12_secret_content" and not check.passed for check in report.checks)


# ---------------------------------------------------------------------------
# causation_id / causal chain
# ---------------------------------------------------------------------------


def test_events_are_wired_into_a_causal_chain(tmp_path: Path) -> None:
    """Spec §5.1: `causation_id` records which event caused this one.

    Before the fix the field was serialised as an empty string forever, so "what led to this?"
    had no answer in the log.
    """
    store = EventStore(tmp_path / "causal.db")
    fsm = StateMachineService(store)
    store.project_run(
        {
            "run_id": "r", "goal_id": "G", "execution_id": "e", "spec_digest": "sp",
            "status": "PENDING", "created_at": "n", "updated_at": "n",
        }
    )
    fsm.declare_step(
        step_id="s1", run_id="r", execution_id="e", node_id="n1", spec_digest="sp",
        expected_artifacts=(TARGET,),
    )
    fsm.transition_step(step_id="s1", event_type="StepActivated", actor="t")
    fsm.transition_step(step_id="s1", event_type="StepLeaseAcquired", actor="w", execution_id="e")

    events = store.events_for("step:s1")
    assert events[0].causation_id == "", "the first event on an aggregate has no cause"
    assert events[1].causation_id == events[0].event_id
    assert events[2].causation_id == events[1].event_id

    chain = store.causal_chain(events[-1].event_id)
    assert [event.event_type for event in chain] == [
        "StepDeclared",
        "StepActivated",
        "StepLeaseAcquired",
    ]
    store.close()


# ---------------------------------------------------------------------------
# Execution expiry (Spec §11.1)
# ---------------------------------------------------------------------------


def _orchestrator(git_repo: Path, tmp_path: Path, **overrides) -> RunOrchestrator:
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="R",
            goal_id="GOAL-EXP",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    return RunOrchestrator(
        store=EventStore(tmp_path / "expiry.db"),
        repo_path=git_repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),), worker_id="w"
        ),
        quota=Quota(max_parallel_steps=1),
        park_on_escalation=False,
        sleeper=overrides.pop("sleeper", lambda _delay: None),
        **overrides,
    )


def test_a_commit_is_refused_once_the_execution_expires(git_repo, tmp_path) -> None:
    """Spec §11.1 lists this as a commit precondition and nothing checked it."""
    orchestrator = _orchestrator(git_repo, tmp_path, execution_ttl_sec=1)
    orchestrator.register_spec()
    orchestrator.create_run()
    # Age the run so the precondition fails.
    orchestrator.store.connection.execute(
        "UPDATE runs SET created_at = '2000-01-01T00:00:00Z' WHERE run_id = ?",
        (orchestrator.run_id,),
    )
    result = orchestrator.run()

    assert result.status != "COMPLETED"
    assert not result.commits
    assert orchestrator._execution_expired()
    assert any("expired" in reason for step in result.steps for reason in step.reasons)


def test_a_commit_is_allowed_while_the_execution_is_current(git_repo, tmp_path) -> None:
    orchestrator = _orchestrator(git_repo, tmp_path, execution_ttl_sec=3600)
    orchestrator.register_spec()
    result = orchestrator.run()
    assert result.status == "COMPLETED"
    assert result.commits


def test_expiry_can_be_disabled(git_repo, tmp_path) -> None:
    orchestrator = _orchestrator(git_repo, tmp_path, execution_ttl_sec=0)
    orchestrator.register_spec()
    orchestrator.create_run()
    orchestrator.store.connection.execute(
        "UPDATE runs SET created_at = '2000-01-01T00:00:00Z' WHERE run_id = ?",
        (orchestrator.run_id,),
    )
    assert not orchestrator._execution_expired()


# ---------------------------------------------------------------------------
# Retry backoff (Spec §17)
# ---------------------------------------------------------------------------


def test_retry_backoff_is_applied_with_a_cap(git_repo, tmp_path) -> None:
    """`backoff_seconds` existed and was never called, so retries were immediate."""
    slept: list[float] = []
    orchestrator = _orchestrator(
        git_repo,
        tmp_path,
        retry_backoff_sec=1.0,
        retry_backoff_factor=2.0,
        retry_backoff_cap_sec=3.0,
        sleeper=slept.append,
    )
    for attempt in (1, 2, 3, 4, 5):
        orchestrator._sleep_before_retry(attempt)
    assert slept == [1.0, 2.0, 3.0, 3.0, 3.0], slept
    # And the delay is recorded, so a slow run can be explained after the fact.
    rows = orchestrator.store.connection.execute(
        "SELECT value FROM metrics WHERE name = 'retry_backoff_ms'"
    ).fetchall()
    assert len(rows) == 5


def test_zero_backoff_sleeps_not_at_all(git_repo, tmp_path) -> None:
    slept: list[float] = []
    orchestrator = _orchestrator(
        git_repo, tmp_path, retry_backoff_sec=0.0, sleeper=slept.append
    )
    orchestrator._sleep_before_retry(3)
    assert slept == []


# ---------------------------------------------------------------------------
# Resource-aware admission (Spec §6.4)
# ---------------------------------------------------------------------------


def test_admission_accounts_for_cpu_and_memory_not_only_parallelism(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "quota.db")
    fsm = StateMachineService(store)
    store.project_run(
        {
            "run_id": "r", "goal_id": "G", "execution_id": "e", "spec_digest": "sp",
            "status": "RUNNING", "created_at": "n", "updated_at": "n",
        }
    )
    plan = PlanSpec(
        plan_id="P",
        goal_id="G",
        nodes=tuple(
            PlanNode(node_id=f"n{i}", expected_artifacts=(f"src/{i}.py",)) for i in range(4)
        ),
    )
    scheduler = Scheduler(
        store=store,
        fsm=fsm,
        plan=plan,
        execution_id="e",
        run_id="r",
        quota=Quota(max_parallel_steps=8, max_cpu=4.0, max_memory_mb=8192),
        boundary=BoundarySpec(
            boundary_id="B", goal_id="G", fs_whitelist=("src/**",),
            network_policy=NetworkPolicy.DENY, cpu_limit=2.0, memory_mb=4096,
        ),
    )
    for index in range(4):
        fsm.declare_step(
            step_id=f"r:n{index}", run_id="r", execution_id="e", node_id=f"n{index}",
            spec_digest="sp", expected_artifacts=(f"src/{index}.py",),
        )
    assert scheduler.admission_capacity() == 2, "4 CPU / 2 per step fits exactly 2"

    for step_id in ("r:n0", "r:n1"):
        scheduler.acquire_lease(step_id, worker_id="w")
    assert scheduler.admission_capacity() == 0
    assert scheduler.binding_constraint()[1] == "cpu"
    store.close()


# ---------------------------------------------------------------------------
# Orphan worktrees (Spec §16)
# ---------------------------------------------------------------------------


def test_a_leaked_worktree_is_detected_and_removed(git_repo, tmp_path) -> None:
    """Spec §16's "Sandbox 泄漏 → 强制清理" needs a detector; there was none."""
    from daedalus.application.recovery import Finding, recover_workspace
    from daedalus.infrastructure.git_sandbox import GitSandbox

    store = EventStore(tmp_path / "orphan.db")
    worktrees = tmp_path / "worktrees"
    leaked = GitSandbox.create_from(
        repo_path=git_repo, run_root=worktrees, name="leaked", base_commit=GitSandbox.main_commit(git_repo)
    )
    assert leaked.worktree_path.is_dir()

    dry = recover_workspace(store=store, apply=False, worktrees_root=worktrees)
    orphans = [item for item in dry.items if item.finding is Finding.ORPHAN_WORKTREE]
    assert len(orphans) == 1, dry.describe()
    assert not orphans[0].action, "a dry run must not delete anything"
    assert leaked.worktree_path.is_dir()

    applied = recover_workspace(store=store, apply=True, worktrees_root=worktrees)
    assert any(
        item.finding is Finding.ORPHAN_WORKTREE and item.action for item in applied.items
    )
    assert not leaked.worktree_path.exists(), "the leaked worktree must be gone"
    store.close()


def test_a_parked_runs_worktree_is_not_an_orphan(git_repo, tmp_path) -> None:
    """A parked worktree is the subject of a pending decision, not leakage."""
    from daedalus.application.recovery import Finding, recover_workspace

    store = EventStore(tmp_path / "parked.db")
    fsm = StateMachineService(store)
    worktrees = tmp_path / "worktrees"
    worktree = worktrees / "run-parked"
    worktree.mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: /tmp/nonexistent\n", encoding="utf-8")

    store.project_run(
        {
            "run_id": "run-parked", "goal_id": "G", "execution_id": "e", "spec_digest": "sp",
            "status": RunState.AWAITING_APPROVAL.value, "created_at": "n", "updated_at": "n",
        }
    )
    fsm.declare_step(
        step_id="run-parked:n1", run_id="run-parked", execution_id="e", node_id="n1",
        spec_digest="sp", expected_artifacts=(TARGET,),
    )
    store.update_step_state(
        "run-parked:n1", state=StepState.ESCALATED.value, worktree_path=str(worktree)
    )

    report = recover_workspace(store=store, apply=False, worktrees_root=worktrees)
    assert not [item for item in report.items if item.finding is Finding.ORPHAN_WORKTREE]
    store.close()


# ---------------------------------------------------------------------------
# Spec §15 metrics
# ---------------------------------------------------------------------------


def test_the_four_missing_metrics_are_now_reported(git_repo, tmp_path) -> None:
    orchestrator = _orchestrator(git_repo, tmp_path)
    orchestrator.register_spec()
    result = orchestrator.run()
    assert result.status == "COMPLETED"

    metrics = orchestrator.store.metric_summary()
    for key in (
        "task_success_rate",
        "rollback_rate",
        "queue_latency_ms",
        "resource_usage_cpu_seconds",
    ):
        assert key in metrics, f"{key} is required by Spec §15"
    assert metrics["run_total"] == 1
    assert metrics["task_success_rate"] == 1.0
    assert metrics["rollback_rate"] == 0.0
    assert metrics["queue_latency_ms"] >= 0
    assert metrics["resource_usage_cpu_seconds"] >= 0
    assert metrics["peak_parallel_steps"] >= 1
