"""Run orchestration: the loop that turns a frozen spec into committed work.

This is the only place the pieces meet. The order of operations inside one step is the
whole design in miniature:

    lease -> worktree -> run worker -> artifact -> Tier-1 -> Tier-2 -> commit
          -> integrate into the run branch (rebase + re-gate if it moved) -> promote

Concurrency model (Spec §6.4). The control plane is **single-threaded**; only the
untrusted worker runs concurrently. Leases, worktrees, gates, commits and integration
all happen on this thread, in a fixed order, so every Git and SQLite mutation is
deterministic no matter how many steps are in flight. This is the architecture's core
claim applied to its own execution: an uncertain plane wrapped in a certain one.

Integration model (Spec §11.2). Steps integrate into a **run branch**, not into the
authoritative branch. Independent steps therefore all branch from the same integration
point and can run at the same time, while a partial failure still leaves the target
branch untouched. When a step's commit is not a fast-forward of the run branch, the
sequence is exactly the one the spec prescribes:

    REBASE_REQUIRED -> rebase -> Tier-1 -> Tier-2 -> commit -> integrate

A rebase that conflicts, or a re-gate that fails, returns the step to REVISE instead of
landing work whose evidence no longer describes the tree it would land on.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from daedalus.application.approvals import ApprovalService
from daedalus.application.artifact_cache import ArtifactCache, ReuseKey, reuse_key_for
from daedalus.application.execution_log import execution_log_ref
from daedalus.application.inspection import safe_receipts
from daedalus.application.fsm_service import StateMachineService
from daedalus.application.identity import (
    IdentityRequired,
    OwnerRegistry,
    decision_needs_signature,
)
from daedalus.application.observability import get_logger, log_context
from daedalus.application.gatekeeper.decision import GateDecision
from daedalus.application.gatekeeper.pipeline import (
    GateOutcome,
    Gatekeeper,
    gate_result_digest,
)
from daedalus.application.gatekeeper.tier1 import Tier1Gate
from daedalus.application.gatekeeper.tier2 import Tier2Gate
from daedalus.application.scheduler import Quota, Scheduler
from daedalus.application.worker import CodingWorker, WorkerContext, WorkerResult
from daedalus.application.worktree_pool import WorktreePool
from daedalus.domain.artifacts import Artifact
from daedalus.domain.canonical import digest_of, sha256_hex
from daedalus.domain.approval import ApprovalDecision, Approval, approval_required
from daedalus.domain.fsm import RunState, StepState, execution_counters
from daedalus.domain.ids import new_id, utc_now
from daedalus.domain.spec import PlanNode, SpecBundle, node_subject_digest
from daedalus.errors import (
    CommitConflict,
    DaedalusError,
    SpecApprovalRequired,
    SpecDigestMismatch,
)
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.infrastructure.sandbox import DriverChoice, DriverRegistry, IsolationUnavailable
from daedalus.infrastructure.store.event_store import EventStore, idempotency_key
from daedalus.model.base import TokenBudget

#: Failure classes that must never be auto-retried (Spec §17). Retrying these spends
#: budget on a question whose answer cannot change, and in the boundary case would
#: mean repeatedly asking a model to do something it is not permitted to do.
logger = get_logger("orchestrator")

#: How much of a diff is kept for the console. Large enough for a real review, small enough
#: that a pathological patch cannot bloat the event store.
PATCH_PREVIEW_BYTES = 262_144

#: Module-level so the test suite can replace it once instead of threading a no-op sleeper
#: through every orchestrator construction. Production keeps a real sleep.
_DEFAULT_SLEEPER: Any = time.sleep


NON_RETRYABLE_ERRORS = frozenset(
    {
        "boundary_violation",
        "meta_spec_violation",
        "spec_digest_mismatch",
        "illegal_transition",
        "commit_conflict",
        "model_budget_exceeded",
        "worker_no_progress",
        "model_tls_configuration_error",
        "model_tls_verification_failed",
        "execution_environment_unavailable",
        # A credential in a file does not disappear by trying again.
        "secret_in_payload",
        # An approval that is absent, unauthorised or unverifiable is a decision about a
        # principal, not a transient fault. Retrying asks the same question and gets the same
        # answer, while implying the operator only needs to wait.
        "signature_required",
        "signature_mismatch",
        "identity_required",
        "owner_not_registered",
        "owner_revoked",
        "insufficient_authority",
        "signing_key_unavailable",
    }
)


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StepOutcome:
    step_id: str
    node_id: str
    state: str
    attempt: int
    decision: str = ""
    commit: str = ""
    artifact_digest: str = ""
    feedback: str = ""
    tokens_used: int = 0
    duration_ms: int = 0
    reasons: tuple[str, ...] = ()
    rebased: int = 0

    @property
    def committed(self) -> bool:
        return self.state == StepState.COMMITTED.value

    def to_row(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "node_id": self.node_id,
            "state": self.state,
            "attempt": self.attempt,
            "gate": self.decision,
            "commit": self.commit[:12],
            "artifact": self.artifact_digest[:12],
            "tokens": self.tokens_used,
            "duration_ms": self.duration_ms,
            "rebased": self.rebased,
            "feedback": self.feedback[:160],
        }


@dataclass
class RunResult:
    run_id: str
    execution_id: str
    spec_digest: str
    status: str
    steps: list[StepOutcome] = field(default_factory=list)
    commits: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    worktree_path: str = ""
    tokens_used: int = 0
    run_branch: str = ""
    promoted_commit: str = ""
    rebase_count: int = 0
    escalated_steps: tuple[str, ...] = ()
    goal_audit: dict[str, Any] = field(default_factory=dict)

    @property
    def committed_count(self) -> int:
        return len([s for s in self.steps if s.committed])

    @property
    def all_committed(self) -> bool:
        return bool(self.steps) and all(s.committed for s in self.steps)

    def describe(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "execution_id": self.execution_id,
            "spec_digest": self.spec_digest,
            "status": self.status,
            "steps": [s.to_row() for s in self.steps],
            "commits": [c[:12] for c in self.commits],
            "committed": self.committed_count,
            "tokens_used": self.tokens_used,
            "worktree_path": self.worktree_path,
            "run_branch": self.run_branch,
            "promoted_commit": self.promoted_commit[:12],
            "rebase_count": self.rebase_count,
            "escalated_steps": list(self.escalated_steps),
            "goal_audit": self.goal_audit,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


@dataclass
class RunOrchestrator:
    """Owns one DAG run against one frozen spec digest."""

    store: EventStore
    repo_path: Path
    run_root: Path
    bundle: SpecBundle
    worker: CodingWorker = field(default_factory=lambda: _default_worker())
    tier2: Tier2Gate | None = None
    quota: Quota = field(default_factory=Quota)
    target_branch: str = "main"
    actor: str = "orchestrator"
    run_id: str = ""
    execution_id: str = ""
    parent_execution_id: str = ""
    replay_from_commit: str = ""
    correlation_id: str = ""
    max_steps_per_run: int = 64
    #: Spec §13.2 artifact reuse. Off by default so an ordinary run never silently skips
    #: work; a replay turns it on deliberately.
    reuse_artifacts: bool = False
    #: Park the run in AWAITING_APPROVAL when a step escalates (Spec §16). Off, the run
    #: ends as a partial failure with the step escalated, which is right for a batch job.
    park_on_escalation: bool = True
    #: Risk levels that may never auto-merge on a semantic review alone (Spec §10).
    manual_review_levels: tuple[str, ...] = ("critical",)
    #: Resume mode: continue a run that was parked, applying recorded owner decisions.
    resume: bool = False
    #: Spec §3.2 / §10: a HIGH or CRITICAL spec must carry an owner approval before any work
    #: starts. Enforced rather than documented, because "we meant to get sign-off" is how an
    #: unreviewed high-risk change ships.
    require_spec_approval: bool = True
    #: Container image for the container driver, when one is selected.
    sandbox_image: str = "python:3.12-slim"
    #: Spec §11.1 commit precondition. 0 disables.
    execution_ttl_sec: int = 86_400
    #: Spec §17 exponential backoff between infrastructure retries.
    retry_backoff_sec: float = 1.0
    retry_backoff_factor: float = 2.0
    retry_backoff_cap_sec: float = 30.0
    #: Injected so tests can observe the delay instead of waiting for it.
    sleeper: Any = None
    #: Spec §3.2 owner identity + approval authority. Injected rather than constructed here,
    #: because whether verification is enforced is a property of the deployment, not of a run.
    identity: OwnerRegistry | None = None

    # New service/CLI tasks opt in; historical callers retain their frozen execution contract.
    goal_audit_enabled: bool = False
    independent_validation_levels: tuple[str, ...] = ()
    _independent_approved_commit: str = field(default="", init=False, repr=False)
    _independent_validation_id: str = field(default="", init=False, repr=False)
    goal_stage_parent: str = ""
    goal_stage_number: int = 1
    stage_feedback: str = ""
    _goal_approved_commit: str = field(default="", init=False, repr=False)

    fsm: StateMachineService = field(init=False)
    pool: WorktreePool | None = field(default=None, init=False)
    budget: TokenBudget = field(init=False)
    #: Set by `_rebase_and_integrate` when a rebase or re-gate fails, so the caller can
    #: return the already-constructed StepOutcome. A rebase is a nested failure path, and
    #: threading an outcome through the success return type would hide that.
    _rebase_failure: StepOutcome | None = field(default=None, init=False, repr=False)
    _rebase_gate: GateOutcome | None = field(default=None, init=False, repr=False)
    #: The step whose worker is currently spending tokens, for the metric recorder.
    _current_step_id: str = field(default="", init=False, repr=False)
    cache: ArtifactCache = field(init=False)
    #: The isolation actually in force, decided once per run and recorded with it.
    isolation: DriverChoice | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.bundle.validate()
        self.fsm = StateMachineService(self.store)
        # Spec §3.2, fail-closed. Every construction site that forgot `identity=` silently
        # disabled owner verification, because the policy read
        # `self.identity is not None and self.identity.enforced`. Three separate bypasses
        # (`daedalus run`, `daedalus replay`, and `resume_run`) were exactly that omission —
        # and no test failed, because the default was fail-open.
        #
        # Deriving the registry from the workspace instead means the control's state comes
        # from the enrolment that actually exists, not from whether a caller remembered a
        # keyword argument. A workspace with no owners behaves exactly as before; a workspace
        # with an owner is verified no matter which entry point reaches it. The parameter
        # stays injectable so tests and callers can supply a specific environment.
        if self.identity is None:
            self.identity = OwnerRegistry.for_store(self.store)
        self.cache = ArtifactCache(store=self.store, enabled=self.reuse_artifacts)
        self.run_id = self.run_id or new_id("run")
        self.execution_id = self.execution_id or new_id("exec")
        self.correlation_id = self.correlation_id or new_id("corr")
        self.budget = TokenBudget(
            max_tokens_per_step=self.bundle.boundary.max_tokens_per_step,
            max_tokens_per_run=self.quota.max_tokens_per_run,
            on_record=self._record_model_usage,
        )
        self._select_isolation()

    def _select_isolation(self) -> None:
        """Decide the process-isolation mechanism before any work starts.

        Done in `__post_init__` so an unavailable level is refused before a spec is registered
        or a run row exists. Selecting it lazily would mean a deployment could believe it was
        running containers until the first escalated step told it otherwise.
        """
        registry = DriverRegistry.default(
            **({"image": self.sandbox_image} if self.sandbox_image else {})
        )
        self.isolation = registry.select(
            self.bundle.boundary, requested=self.bundle.boundary.isolation
        )
        report = self.isolation.report
        logger.info(
            "isolation: %s (%s)", report.driver, self.isolation.reason
        )
        if not report.network.enforced:
            logger.warning(
                "network_policy=%s is enforced at gate time only under %s; commands can still "
                "reach the network at runtime",
                self.bundle.boundary.network_policy.value,
                report.driver,
            )

    def _record_queue_and_parallelism(self, step_id: str) -> None:
        """Spec §15's `queue_latency` and the aggregate behind `resource_usage`.

        Queue latency is measured once per run: the delay between the run being created and its
        first step starting. Measuring it per step would average in the time each attempt spent
        running, which is not queueing.
        """
        existing = self.store.connection.execute(
            "SELECT COUNT(*) AS n FROM metrics WHERE name = 'queue_latency_ms' AND run_id = ?",
            (self.run_id,),
        ).fetchone()
        if existing is not None and int(existing["n"]) == 0:
            run = self.store.get_run(self.run_id)
            if run is not None:
                from datetime import UTC, datetime

                try:
                    created = datetime.fromisoformat(
                        str(run["created_at"]).replace("Z", "+00:00")
                    )
                    waited_ms = max(
                        0.0, (datetime.now(UTC) - created).total_seconds() * 1000
                    )
                except ValueError:
                    waited_ms = 0.0
                self.store.record_metric(
                    name="queue_latency_ms",
                    value=waited_ms,
                    unit="ms",
                    run_id=self.run_id,
                    step_id=step_id,
                )
        _cpu, _memory, in_flight = self.scheduler().in_flight_resources()
        self.store.record_metric(
            name="peak_parallel_steps",
            value=float(in_flight),
            unit="count",
            run_id=self.run_id,
            step_id=step_id,
        )

    def _sleep_before_retry(self, attempt: int) -> None:
        """Wait before retrying, with exponential backoff (Spec §17)."""
        base = self.retry_backoff_sec
        if base <= 0:
            return
        delay = min(base * (self.retry_backoff_factor ** max(0, attempt - 1)), self.retry_backoff_cap_sec)
        sleep = self.sleeper or _DEFAULT_SLEEPER
        logger.info("backing off %.1fs before retrying (attempt %d)", delay, attempt)
        self.store.record_metric(
            name="retry_backoff_ms",
            value=delay * 1000,
            unit="ms",
            run_id=self.run_id,
            labels={"attempt": attempt},
        )
        sleep(delay)

    def _execution_expired(self) -> bool:
        """Spec §11.1: a commit requires the execution to still be current."""
        if self.execution_ttl_sec <= 0:
            return False
        run = self.store.get_run(self.run_id)
        if run is None:
            return False
        from datetime import UTC, datetime

        try:
            created = datetime.fromisoformat(str(run["created_at"]).replace("Z", "+00:00"))
        except ValueError:
            return False
        age = (datetime.now(UTC) - created).total_seconds()
        return age > self.execution_ttl_sec

    def _record_model_usage(self, completion: Any) -> None:
        """Persist Spec §15's model metrics for every call the run makes.

        The budget's thread-local attempt identity follows the actual model caller rather
        than whichever step happened to be prepared last on the control-plane thread.
        """
        step_id = completion.raw.get("budget_step_id", self._current_step_id)
        attempt = completion.raw.get("budget_attempt", 0)
        self.store.record_metric(
            name="llm_tokens",
            value=float(completion.total_tokens),
            unit="tokens",
            run_id=self.run_id,
            step_id=step_id,
            labels={"model": completion.model or "unknown", "phase": completion.raw.get("phase", "execution"),
                    "failed_response": bool(completion.raw.get("failed_response")), "attempt": attempt},
        )
        self.store.record_metric(
            name="llm_calls",
            value=1.0,
            unit="count",
            run_id=self.run_id,
            step_id=step_id,
            labels={"model": completion.model or "unknown", "attempt": attempt},
        )
        self.store.record_metric(
            name="llm_latency_ms",
            value=float(getattr(completion, "latency_ms", 0) or 0),
            unit="ms",
            run_id=self.run_id,
            step_id=step_id,
            labels={"model": completion.model or "unknown", "attempt": attempt},
        )

    def _restore_model_budget(self) -> None:
        """Rebuild reported spend, including the current attempt's later re-gates."""
        steps = {str(s["step_id"]): int(s["attempt"]) for s in self.store.list_steps(self.run_id)}
        usage: dict[tuple[str, int], int] = {}
        total = 0
        for row in self.store.connection.execute(
            "SELECT step_id,value,labels FROM metrics WHERE name='llm_tokens' AND run_id=?",
            (self.run_id,),
        ):
            tokens = int(row["value"])
            if tokens < 0 or tokens != row["value"]:
                raise DaedalusError("model usage has an invalid token count")
            total += tokens
            step_id = str(row["step_id"] or "")
            if not step_id:
                continue  # completed planning/goal reviews do not consume a pending step
            labels = json.loads(row["labels"] or "{}")
            attempt = labels.get("attempt", steps.get(step_id, 0))
            if type(attempt) is not int or attempt < 0:
                raise DaedalusError("model usage has an invalid attempt identity")
            key = (step_id, attempt)
            usage[key] = usage.get(key, 0) + tokens
        self.budget.run_used = total
        for (step_id, attempt), tokens in usage.items():
            with self.budget.step_scope(step_id, attempt):
                self.budget.step_used = tokens

    # ------------------------------------------------------------------- spec
    @property
    def spec_digest(self) -> str:
        return self.bundle.digest()

    def register_spec(self) -> bool:
        """Freeze the spec in the registry. Returns False if already registered."""
        inserted = self.store.register_spec(
            spec_digest=self.spec_digest,
            goal_id=self.bundle.goal.goal_id,
            spec_version=self.bundle.spec_version,
            document=self.bundle.to_dict(),
            risk_level=self.bundle.goal.risk_level.value,
            owner_id=self.bundle.owner_id,
            parent_spec_digest=self.bundle.parent_spec_digest,
        )
        if inserted:
            self.store.append(
                aggregate_id=f"spec:{self.bundle.goal.goal_id}",
                execution_id=self.execution_id,
                event_type="SpecRegistered",
                actor=self.actor,
                payload={
                    "goal_id": self.bundle.goal.goal_id,
                    "spec_digest": self.spec_digest,
                    "spec_version": self.bundle.spec_version,
                    "risk_level": self.bundle.goal.risk_level.value,
                    "parent_spec_digest": self.bundle.parent_spec_digest,
                },
                correlation_id=self.correlation_id,
            )
        return inserted

    # --------------------------------------------------------------------- setup
    def create_run(self, *, base_ref: str = "HEAD") -> WorktreePool:
        """Create the run branch and the worktree pool that integrates into it."""
        base_commit = self.replay_from_commit or GitSandbox.main_commit(self.repo_path, base_ref)
        pool = WorktreePool(
            repo_path=self.repo_path,
            run_root=self.run_root,
            run_id=self.run_id,
            base_commit=base_commit,
            target_branch=self.target_branch,
            max_size=max(1, self.quota.max_parallel_steps),
        )
        self.pool = pool
        self.store.project_run(
            {
                "run_id": self.run_id,
                "goal_id": self.bundle.goal.goal_id,
                "execution_id": self.execution_id,
                "spec_digest": self.spec_digest,
                "parent_execution_id": self.parent_execution_id,
                "replay_from_commit": self.replay_from_commit,
                "status": "PENDING",
                "base_commit": base_commit,
                "worktree_path": str(self.run_root),
                "branch": pool.run_branch,
                "correlation_id": self.correlation_id,
                "created_at": utc_now(),
                "updated_at": utc_now(),
            }
        )
        # Spec §19: an execution is an entity, not just a column scattered across other
        # tables. Recording it here is what makes "what was this execution, and what did it
        # produce?" a single query rather than a join the operator has to invent.
        #
        # NOTE: this projection is written *before* the authoritative `RunStarted` event and
        # outside its transaction, which contradicts the four-step order used everywhere else.
        # It is deliberate — the receipt must be durable the moment the run is accepted, so a
        # caller that is handed a run id can always look it up — and the consequence is that a
        # projection row can exist with no event. `recovery` reconciles exactly that case.
        self.store.upsert_execution(
            {
                "execution_id": self.execution_id,
                "run_id": self.run_id,
                "parent_execution_id": self.parent_execution_id,
                "replay_from_commit": self.replay_from_commit,
                "kind": "replay" if self.parent_execution_id else "run",
                "status": "RUNNING",
                "spec_digest": self.spec_digest,
                "started_at": utc_now(),
            }
        )
        self._touch_worker(status="IDLE")
        self.fsm.transition_run(
            run_id=self.run_id,
            execution_id=self.execution_id,
            event_type="RunStarted",
            actor=self.actor,
            payload={
                "goal_id": self.bundle.goal.goal_id,
                "spec_digest": self.spec_digest,
                "base_commit": base_commit,
                "run_branch": pool.run_branch,
                "max_parallel_steps": self.quota.max_parallel_steps,
                "quota": self.quota.describe(),
                "execution_ttl_sec": self.execution_ttl_sec,
                "manual_review_levels": list(self.manual_review_levels),
                "repo_path": str(self.repo_path),
                "reuse_artifacts": self.reuse_artifacts,
                "target_branch": self.target_branch,
                "goal_audit_enabled": self.goal_audit_enabled,
                "independent_validation_levels": list(self.independent_validation_levels),
                "goal_stage_parent": self.goal_stage_parent,
                "goal_stage_number": self.goal_stage_number,
                "isolation": self.isolation.describe() if self.isolation else None,
            },
            correlation_id=self.correlation_id,
        )
        return pool

    def scheduler(self) -> Scheduler:
        return Scheduler(
            store=self.store,
            fsm=self.fsm,
            plan=self.bundle.plan,
            execution_id=self.execution_id,
            run_id=self.run_id,
            quota=self.quota,
            boundary=self.bundle.boundary,
            actor=self.actor,
            correlation_id=self.correlation_id,
        )

    # ------------------------------------------------------------------ the loop
    def run(self, *, max_rounds: int = 64) -> RunResult:
        """Drive one repository under an interprocess writer lock."""
        from daedalus.infrastructure.repository_lock import repository_lock
        with repository_lock(self.repo_path):
            if self.resume:
                from daedalus.application.service_lifecycle import assert_checkpoint_reviewed
                assert_checkpoint_reviewed(self.store, self.run_id, identity=self.identity)
            return self._drive_run(max_rounds=max_rounds)

    def _drive_run(self, *, max_rounds: int = 64) -> RunResult:
        """Drive the whole DAG to a terminal state."""
        self.assert_spec_may_run()
        pool = self.pool if self.pool is not None else self.create_run()
        scheduler = self.scheduler()
        scheduler.declare_all_nodes(self.spec_digest, base_commit=pool.base_commit)

        result = RunResult(
            run_id=self.run_id,
            execution_id=self.execution_id,
            spec_digest=self.spec_digest,
            status="RUNNING",
            worktree_path=str(self.run_root),
            run_branch=pool.run_branch,
        )
        terminal: set[str] = set()

        from daedalus.application.service_lifecycle import stop_requested
        if stop_requested():
            return self._park_for_service_stop(pool, result)

        if self.resume:
            self._restore_model_budget()
            self.budget.check()
            self._apply_resume(result, pool=pool, scheduler=scheduler)
            # Whether we are still parked is decided by whether any escalated step remains
            # *without* an answer, not by the run's status: the status only changes once we
            # decide to unpark, so reading it here would always look parked.
            if self._has_escalation():
                result.status = RunState.AWAITING_APPROVAL.value
                result.escalated_steps = tuple(self._escalated_step_ids())
                result.notes.append(
                    "still parked: at least one escalated step has no owner decision yet, or "
                    "its approved content could not be committed"
                )
                return result
            for step in self.store.list_steps(self.run_id):
                if str(step["execution_id"]) != self.execution_id:
                    continue
                if StepState(str(step["state"])) in {
                    StepState.COMMITTED,
                    StepState.CANCELLED,
                    StepState.SUPERSEDED,
                    StepState.FAILED,
                    StepState.TIMEOUT,
                    StepState.ESCALATED,
                }:
                    terminal.add(str(step["step_id"]))
            self._restore_committed_receipts(result)
            if self.store.get_run(self.run_id)["status"] == "AWAITING_APPROVAL":
                self.fsm.transition_run(
                    run_id=self.run_id,
                    execution_id=self.execution_id,
                    event_type="RunResumed",
                    actor=self.actor,
                    payload={"reason": "owner decisions applied"},
                    correlation_id=self.correlation_id,
                )
            self.store.append(aggregate_id=f"run:{self.run_id}", execution_id=self.execution_id,
                event_type="AuditNote", actor="resume", payload={"message":"explicit resume; committed receipts restored without rerunning them"},
                correlation_id=self.correlation_id)
            result.notes.append("resumed explicitly from recorded decisions and commit receipts")

        for _round in range(max_rounds):
            if stop_requested():
                return self._park_for_service_stop(pool, result)
            decision = scheduler.refresh(self.spec_digest)
            for note in decision.notes:
                if note not in result.notes:
                    result.notes.append(note)

            for step_id in decision.to_escalate:
                self._escalate(step_id, "retry policy exhausted", result)
                terminal.add(step_id)

            admitted = [item for item in decision.to_activate if item not in terminal]
            if not admitted:
                if decision.deadlocked or self._is_finished():
                    break
                # Nothing runnable and nothing in flight: the remaining work waits on a
                # dependency that will never commit.
                break

            # --- control plane: reuse verified work, then admit the rest ---
            # A cache hit is decided before any worktree is created or any lease is
            # issued, so skipping a step costs nothing and cannot half-apply.
            to_run: list[str] = []
            for step_id in admitted:
                reused = self._try_cache_hit(step_id, pool=pool)
                if reused is None:
                    to_run.append(step_id)
                    continue
                result.steps.append(reused)
                result.commits.append(reused.commit)
                terminal.add(step_id)

            prepared: list[_PreparedStep] = []
            for step_id in to_run:
                # Spec §27 requires the logs to carry step_id and worker_id, not just the run.
                # Bound around each phase of the step rather than at the top of the run,
                # because the whole point is to tell one step's lines from another's — and
                # because a worker thread must not inherit another step's context.
                with log_context(step_id=step_id, worker_id=self.worker_id):
                    candidate = self._prepare_step(step_id, pool=pool, scheduler=scheduler)
                if candidate is not None:
                    prepared.append(candidate)

            # --- execution plane: run the untrusted workers concurrently ---
            executions = self._run_workers(prepared)

            # --- control plane: gate, commit and integrate, one step at a time ---
            for execution in executions:
                with log_context(
                    step_id=execution.prepared.step_id, worker_id=self.worker_id
                ):
                    outcome = self._finish_step(execution, pool=pool, scheduler=scheduler)
                    result.steps.append(outcome)
                    if outcome.committed:
                        result.commits.append(outcome.commit)
                        result.rebase_count += outcome.rebased
                        terminal.add(outcome.step_id)
                    else:
                        self._handle_failed_step(outcome.step_id, outcome, result)
                        # REVISE stays eligible: the next round re-attempts it under a new
                        # lease and a fresh attempt counter. Everything else is terminal.
                        if StepState(outcome.state) is not StepState.REVISE:
                            terminal.add(outcome.step_id)
                    pool.release(outcome.step_id, keep=not outcome.committed)

            # Parking is checked BEFORE the terminal check: an escalated step counts as
            # terminal for a batch run, so asking "are we finished?" first would end the run
            # as a partial failure and never give the owner a chance to answer.
            if self.park_on_escalation and self._has_escalation():
                # Spec §16: freeze and wait for the Owner. The worktrees are kept, because
                # the pending change is the subject of the decision.
                self.fsm.transition_run(
                    run_id=self.run_id,
                    execution_id=self.execution_id,
                    event_type="RunEscalated",
                    actor=self.actor,
                    payload={"escalated_steps": self._escalated_step_ids()},
                    correlation_id=self.correlation_id,
                )
                pool.park()
                result.status = RunState.AWAITING_APPROVAL.value
                result.tokens_used = self.budget.run_used
                result.escalated_steps = tuple(self._escalated_step_ids())
                result.notes.append(
                    "parked in AWAITING_APPROVAL: "
                    f"{len(result.escalated_steps)} step(s) need an owner decision; "
                    "run `daedalus approve` then `daedalus resume`"
                )
                return result

            if self._is_finished():
                break
        else:
            result.notes.append(
                f"loop budget exhausted after {max_rounds} rounds without reaching a "
                "terminal state; this indicates a retry cycle that the FSM could not "
                "resolve and is reported rather than hidden"
            )

        if stop_requested():
            return self._park_for_service_stop(pool, result)
        result.status = self._final_status()
        result.tokens_used = self.budget.run_used
        if result.status == "COMPLETED" and self.goal_audit_enabled:
            from daedalus.application.goal_audit import ensure_goal_delivery
            if not ensure_goal_delivery(self, pool, result):
                pool.park()
                return result
        result.tokens_used = self.budget.run_used
        if stop_requested():
            return self._park_for_service_stop(pool, result)
        self._integrate(pool, result)
        if result.status == "AWAITING_APPROVAL":
            pool.park()
            return result
        pool.destroy(keep_failed=False)
        self._close_run(result)
        return result

    def _park_for_service_stop(self, pool, result):
        """Keep verified receipts, leases settled, and the target branch unpublished."""
        run = self.store.get_run(self.run_id)
        if run["status"] == "RUNNING":
            self.fsm.transition_run(run_id=self.run_id, execution_id=self.execution_id,
                event_type="RunEscalated", actor=self.actor,
                payload={"reason": "service stopped at a recoverable boundary", "source": "service_shutdown"},
                correlation_id=self.correlation_id)
        from daedalus.application.service_lifecycle import CHECKPOINT_KIND
        self.store.append(aggregate_id=f"run:{self.run_id}", execution_id=self.execution_id,
            event_type="AuditNote", actor="service", payload={"kind": CHECKPOINT_KIND,
            "note": "停止在步骤批次边界；下次启动仅提醒，人工审查后继续", "automatic_resume": False})
        pool.park()
        result.status = "AWAITING_APPROVAL"
        result.tokens_used = self.budget.run_used
        result.notes.append("service checkpoint saved; manual review required before resuming")
        return result

    def _restore_committed_receipts(self, result: RunResult) -> None:
        receipts = {
            e.step_id: e.payload
            for e in self.store.events_for_execution(self.execution_id)
            if e.event_type in {"StepCommitted", "StepCacheHit"}
        }
        known = {s.step_id for s in result.steps}
        for step in self.store.list_steps(self.run_id):
            if (
                step["execution_id"] != self.execution_id
                or step["state"] != "COMMITTED"
                or step["step_id"] in known
            ):
                continue
            receipt = receipts.get(step["step_id"])
            if not receipt or not receipt.get("commit"):
                raise DaedalusError("committed step has no recorded commit receipt; refusing resume")
            result.steps.append(
                StepOutcome(
                    step_id=step["step_id"],
                    node_id=step["node_id"],
                    state="COMMITTED",
                    attempt=int(step["attempt"]),
                    commit=receipt["commit"],
                    artifact_digest=receipt.get("artifact_digest", ""),
                    decision="APPROVE",
                )
            )
            result.commits.append(receipt["commit"])


    def complete_validated_delivery(self) -> RunResult:
        from daedalus.application.independent_validation import IndependentValidationService, _head
        from daedalus.infrastructure.repository_lock import repository_lock

        with repository_lock(self.repo_path):
            from daedalus.application.service_lifecycle import assert_checkpoint_reviewed, stop_requested
            assert_checkpoint_reviewed(self.store, self.run_id, identity=self.identity)
            self.assert_spec_may_run()
            run = self.store.get_run(self.run_id)
            if run is None or run["status"] != "AWAITING_APPROVAL" or self._execution_expired():
                raise DaedalusError("validated delivery is no longer current")
            commit = _head(self.repo_path, run["branch"])
            receipt = IndependentValidationService(self.store, self.identity).authorise_delivery(
                self.run_id, commit
            )
            if self.goal_audit_enabled:
                goals = self.store.events_for(f"goal:{self.run_id}")
                if (
                    not goals
                    or goals[-1].event_type != "GoalAuditCompleted"
                    or goals[-1].payload.get("decision") != "APPROVE"
                    or goals[-1].payload.get("commit") != commit
                ):
                    raise DaedalusError("the existing goal approval does not authorize this commit")
                self._goal_approved_commit = commit
            steps = self.store.list_steps(self.run_id)
            if not steps or any(s["state"] != "COMMITTED" for s in steps):
                raise DaedalusError("validated delivery has unfinished steps")
            self._independent_approved_commit = commit
            self._independent_validation_id = receipt["validation_id"]
            result = RunResult(
                self.run_id, self.execution_id, self.spec_digest, "COMPLETED", run_branch=run["branch"]
            )
            self._restore_committed_receipts(result)
            self._restore_model_budget()
            self.budget.check()
            result.tokens_used = self.budget.run_used
            if stop_requested():
                if self.pool is None:
                    raise DaedalusError("delivery requires the recorded integration pool")
                return self._park_for_service_stop(self.pool, result)
            self.fsm.transition_run(
                run_id=self.run_id,
                execution_id=self.execution_id,
                event_type="RunResumed",
                actor=self.actor,
                payload={
                    "reason": "independent validation attested",
                    "validation_id": receipt["validation_id"],
                },
                correlation_id=self.correlation_id,
            )
            pool = self.pool
            if pool is None:
                raise DaedalusError("delivery requires the recorded integration pool")
            self._integrate(pool, result)
            pool.destroy(keep_failed=False)
            self._close_run(result)
            return result

    # ------------------------------------------------------------ spec approval
    def assert_spec_may_run(self) -> None:
        """Refuse to execute a HIGH/CRITICAL spec that no owner has signed off (Spec §3.2).

        Two different questions are answered here, and they are not the same question:

        * has anyone signed off at all?  — the original §10 requirement;
        * was that sign-off *verified*?  — the §3.2 requirement, which only bites once owner
          identity is enrolled or required.

        Keeping them apart is what lets a single-user workspace keep working while a
        deployment that has enrolled owners cannot be talked out of checking them.
        """
        if not self.require_spec_approval:
            return
        risk = self.bundle.goal.risk_level.value
        # The *requirement* is about high-risk change (§10). Enrolling owners raises the bar
        # for an approval that is given; it must not make every ordinary edit need one, or
        # operators would disable the control to get their work done.
        if risk not in {"high", "critical"}:
            return
        verified_required = self._identity_enforced() or risk in self.independent_validation_levels
        if self.store.is_spec_approved(self.spec_digest, verified_only=verified_required):
            return
        if verified_required and self.store.is_spec_approved(self.spec_digest):
            raise IdentityRequired(
                f"spec {self.spec_digest[:12]} has an owner approval, but it was not a "
                "verified signature, and this workspace verifies approvals. Re-approve it "
                f"with a signature: `daedalus approve-spec --spec {self.spec_digest} "
                "--by <owner> --signature <hex>`",
                spec_digest=self.spec_digest,
                risk_level=risk,
            )
        raise SpecApprovalRequired(
            f"spec {self.spec_digest[:12]} is risk={risk} and has no owner approval. "
            "Approve it first: `daedalus approve-spec --spec "
            f"{self.spec_digest} --by <you>`",
            spec_digest=self.spec_digest,
            risk_level=risk,
        )

    def approve_spec(self, *, approved_by: str, signature: str = "") -> None:
        """Record an owner's sign-off on the frozen spec, verified when identity is enforced."""
        if not approved_by.strip():
            raise SpecApprovalRequired(
                "a spec approval must name who gave it (Spec §27)"
            )
        risk = self.bundle.goal.risk_level
        # `register_spec` first: the registry reads the spec's risk level from the caller, and
        # an approval for a spec that is not registered would be an approval of nothing.
        self.store.register_spec(
            spec_digest=self.spec_digest,
            goal_id=self.bundle.goal.goal_id,
            spec_version=self.bundle.spec_version,
            document=self.bundle.to_dict(),
            risk_level=risk.value,
            owner_id=self.bundle.owner_id,
            parent_spec_digest=self.bundle.parent_spec_digest,
        )
        self._spec_approvals().record(
            spec_digest=self.spec_digest,
            approved_by=approved_by.strip(),
            signature=signature,
            execution_id=self.execution_id,
            correlation_id=self.correlation_id,
        )

    def _identity_enforced(self) -> bool:
        """Whether this workspace verifies owner decisions (Spec §3.2).

        A workspace with no owners enrolled records decisions unverified; one with an owner
        ever registered must not commit on a typed name. Read once, here, so the commit gate
        and run admission cannot disagree about the policy.

        `identity` is never None after `__post_init__`, so this cannot silently report
        "unenforced" for a workspace that has owners — the failure mode that made three
        entry points bypass the control.
        """
        assert self.identity is not None, "the registry is established in __post_init__"
        return self.identity.enforced

    def _spec_approvals(self) -> Any:
        """The shared approval service, so this path and the HTTP path cannot diverge.

        Before this existed, `POST /api/specs/{id}/approve` wrote the approval straight to the
        projection and never consulted the registry at all — a second write path with a second
        policy, in the one place where that is least acceptable.
        """
        from daedalus.application.spec_approval import SpecApprovalService

        if self.identity is None:
            # No registry: an unverified approval is exactly what `authorise` returns when
            # enforcement is off, so a default registry keeps one code path rather than two.
            self.identity = OwnerRegistry(store=self.store, required=False)
        return SpecApprovalService(store=self.store, identity=self.identity)

    # ------------------------------------------------------------ park / resume
    def _run_status(self) -> str:
        run = self.store.get_run(self.run_id)
        return str(run["status"]) if run else ""

    def _escalated_step_ids(self) -> list[str]:
        return [
            str(row["step_id"])
            for row in self.store.list_steps(self.run_id)
            if str(row["execution_id"]) == self.execution_id
            and str(row["state"]) == StepState.ESCALATED.value
        ]

    def _has_escalation(self) -> bool:
        return bool(self._escalated_step_ids())

    def _apply_resume(
        self,
        result: RunResult,
        *,
        pool: WorktreePool,
        scheduler: Scheduler,
    ) -> None:
        """Apply recorded owner decisions, in the order that keeps the audit honest.

        REJECT and RETRY are pure state transitions. PROCEED needs the worktree, so it is
        committed here with the same tree-digest check as any other commit: the owner
        approved a *specific artifact*, and we re-verify that the artifact is still what the
        worktree holds.
        """
        service = ApprovalService(
            store=self.store, fsm=self.fsm, actor=self.actor, identity=self.identity
        )
        applied = service.apply_decisions(self.run_id)
        for step_id, action in sorted(applied.items()):
            result.notes.append(f"owner decision on {step_id.split(':')[-1]}: {action}")
            if action != "proceed":
                continue

            approval_row = self.store.latest_approval(step_id)
            artifact_digest = str(approval_row["artifact_digest"]) if approval_row else ""
            outcome = self._commit_approved(
                step_id=step_id,
                artifact_digest=artifact_digest,
                pool=pool,
                scheduler=scheduler,
                result=result,
            )
            result.steps.append(outcome)
            if outcome.committed:
                result.commits.append(outcome.commit)

    def _commit_approved(
        self,
        *,
        step_id: str,
        artifact_digest: str,
        pool: WorktreePool,
        scheduler: Scheduler,
        result: RunResult,
    ) -> StepOutcome:
        step = self.store.get_step(step_id)
        with self.budget.step_scope(step_id, int(step["attempt"])):
            return self._commit_approved_in_scope(
                step_id=step_id, artifact_digest=artifact_digest,
                pool=pool, scheduler=scheduler, result=result,
            )

    def _commit_approved_in_scope(
        self,
        *,
        step_id: str,
        artifact_digest: str,
        pool: WorktreePool,
        scheduler: Scheduler,
        result: RunResult,
    ) -> StepOutcome:
        """Commit an artifact the owner explicitly accepted.

        Refuses in three ways, all fail-closed:

        * no approval names this exact artifact,
        * the worktree is gone, so the approved content cannot be reconstructed,
        * the worktree no longer holds the gated tree, so the approval describes something
          that no longer exists.
        """
        step = self.store.get_step(step_id)
        node = self.bundle.plan.node(str(step["node_id"]))
        # The gate is the domain predicate, not the lookup. `Approval.authorises()` was
        # documented as "the single predicate the commit path consults" while the commit path
        # actually called `find_approval_authorising`, whose query omitted the frozen-spec
        # comparison the predicate performs — so half the binding was never enforced. A
        # docstring is not a control; the predicate now decides, and the store is only asked
        # for the record.
        authorising = self.store.find_approval_authorising(
            step_id, artifact_digest, subject_digest=self.spec_digest
        )
        # The requirement is symmetric with the one the approval was verified under, so a
        # legitimate normal-risk override is not retroactively refused at commit time.
        if not authorising or not Approval.from_row(authorising).authorises(
            artifact_digest,
            self.spec_digest,
            require_verified=(
                self._identity_enforced()
                and decision_needs_signature(self.bundle.goal.risk_level)
            ),
        ):
            result.notes.append(
                f"{node.node_id}: no approval authorises artifact {artifact_digest[:12]} "
                f"under spec {self.spec_digest[:12]}; staying parked"
            )
            return self._uncommitted_outcome(step_id, node.node_id, "missing approval")

        artifact_row = self.store.get_artifact(artifact_digest)
        if artifact_row is None:
            result.notes.append(f"{node.node_id}: artifact {artifact_digest[:12]} is gone")
            return self._uncommitted_outcome(step_id, node.node_id, "artifact missing")

        document = json.loads(str(artifact_row["document"]))
        gated_tree = str(document.get("extra", {}).get("gated_tree", ""))
        worktree_path = str(step["worktree_path"])
        if not worktree_path:
            result.notes.append(
                f"{node.node_id}: no worktree recorded for the escalated attempt; "
                "re-run the step instead of approving it"
            )
            return self._uncommitted_outcome(step_id, node.node_id, "worktree not recorded")

        try:
            sandbox = pool.reopen_step(
                step_id,
                base_commit=str(step["base_commit"] or pool.base_commit),
                worktree_path=worktree_path,
            )
        except DaedalusError as error:
            result.notes.append(f"{node.node_id}: {error.message}")
            return self._uncommitted_outcome(step_id, node.node_id, "worktree unusable")

        actual_tree = sandbox.tree_digest()
        if gated_tree and actual_tree != gated_tree:
            # The content moved after the owner looked at it. The approval is void.
            result.notes.append(
                f"{node.node_id}: the worktree no longer holds the approved tree "
                f"({gated_tree[:12]} != {actual_tree[:12]}); the approval is void"
            )
            return self._uncommitted_outcome(step_id, node.node_id, "approval no longer valid")

        self.fsm.transition_step(
            step_id=step_id,
            event_type="StepApproved",
            actor=self.actor,
            execution_id=self.execution_id,
            payload={
                "artifact_digest": artifact_digest,
                "approved_by": str(
                    (self.store.latest_approval(step_id) or {}).get("approved_by", "")
                ),
                "owner_override": True,
            },
            correlation_id=self.correlation_id,
        )
        gate = self._reconstruct_gate_outcome(step_id, artifact_digest, str(node.node_id))
        outcome = self._commit_step(
            step_id=step_id,
            node=node,
            sandbox=sandbox,
            pool=pool,
            scheduler=scheduler,
            lease_id="",
            artifact_digest=artifact_digest,
            gated_tree=gated_tree,
            gate=gate,
            attempt=int(step["attempt"]),
            duration_ms=0,
            approved=True,
        )
        pool.release(step_id, keep=not outcome.committed)
        return outcome

    def _reconstruct_gate_outcome(
        self, step_id: str, artifact_digest: str, node_id: str
    ) -> GateOutcome:
        """Rebuild the gate verdict for an already-gated artifact.

        The commit path needs a `GateOutcome` for its provenance, and re-running the gate
        would be wrong: the owner overrode the *recorded* verdict, and the artifact must
        keep pointing at the verdict it actually received.
        """
        rows = [row for row in self.store.gate_results_for_step(step_id) if row["artifact_digest"] == artifact_digest]
        tier1 = next((row for row in reversed(rows) if int(row["tier"]) == 1), None)
        tier2 = next((row for row in reversed(rows) if int(row["tier"]) == 2), None)
        if tier1 is None or tier1["decision"] != "PASS" or tier1["subject_digest"] != self.spec_digest:
            raise DaedalusError("the approved artifact has no matching passing deterministic gate")
        subject = str(tier1["subject_digest"])

        from daedalus.application.gatekeeper.decision import GateDecision
        from daedalus.application.gatekeeper.tier1 import CheckResult, Tier1Report
        from daedalus.application.gatekeeper.tier2 import SemanticReviewResult

        tier1_report = Tier1Report(
            step_id=step_id,
            subject_digest=subject,
            checks=(
                CheckResult(
                    name="owner_override",
                    passed=True,
                    detail="deterministic checks were recorded when the gate first ran",
                    evidence={"reconstructed": True},
                ),
            ),
            decision=GateDecision(
                str(tier1["decision"]) if tier1 else GateDecision.PASS.value
            ),
            reasons=(),
        )
        review = None
        if tier2 is not None:
            review = SemanticReviewResult(
                decision=GateDecision(str(tier2["decision"])),
                reasons=tuple(json.loads(str(tier2["reasons"]))),
                violations=tuple(json.loads(str(tier2["violations"]))),
                confidence=float(tier2["confidence"] or 0.0),
            )
        return GateOutcome(
            step_id=step_id,
            execution_id=self.execution_id,
            artifact_digest=artifact_digest,
            subject_digest=subject,
            decision=GateDecision.APPROVE,
            tier1=tier1_report,
            tier2=review,
            tier1_result_id=str(tier1["gate_result_id"]) if tier1 else "",
            tier2_result_id=str(tier2["gate_result_id"]) if tier2 else "",
            skipped_tier2=False,
        )

    def _uncommitted_outcome(self, step_id: str, node_id: str, reason: str) -> StepOutcome:
        return StepOutcome(
            step_id=step_id,
            node_id=node_id,
            state=StepState.ESCALATED.value,
            attempt=0,
            decision="ESCALATE",
            feedback=reason,
            reasons=(reason,),
        )

    def _adopt_worker_budget(self) -> None:
        """Make the control plane's budget the single accounting object.

        If the worker was handed its own budget, the **stricter** limit of the two wins and
        the worker is pointed at the control plane's object. Two independent budgets would
        mean the worker's spending is accounted somewhere the gate never inspects, which
        silently disables the resource boundary — the gate would pass a step that had already
        blown its allowance.
        """
        if not hasattr(self.worker, "budget"):
            # The worker has no budget concept at all (a scripted worker), which is fine.
            return
        worker_budget = getattr(self.worker, "budget", None)
        if worker_budget is self.budget:
            return
        if worker_budget is None:
            # The control plane hands its budget to the worker. Leaving it unset would mean
            # the SPEC-03 limit is only checked after the money is spent.
            self.worker.budget = self.budget  # type: ignore[attr-defined]
            return
        tightened_step = min(
            self.budget.max_tokens_per_step, int(getattr(worker_budget, "max_tokens_per_step", 0) or 0)
        )
        tightened_run = min(
            self.budget.max_tokens_per_run, int(getattr(worker_budget, "max_tokens_per_run", 0) or 0)
        )
        if tightened_step != self.budget.max_tokens_per_step:
            logger.info(
                "tightening the per-step token budget from %s to %s",
                self.budget.max_tokens_per_step,
                tightened_step,
            )
        self.budget.max_tokens_per_step = tightened_step
        self.budget.max_tokens_per_run = tightened_run
        try:
            self.worker.budget = self.budget  # type: ignore[attr-defined]
        except AttributeError:
            # A frozen worker is not an error: it simply has no budget to adopt.
            return
        # Preserve usage already spent on planning before this execution was created.
        # Only usage metadata is retained; prompts and generated text are never copied.
        history = getattr(worker_budget, "usage_history", ())
        for completion in history:
            carried = replace(completion, raw={**completion.raw, "phase": "planning"})
            self.budget.record(carried)
        if history:
            self.budget.reset_step()

    # ----------------------------------------------------------- artifact reuse
    def _dependency_digest_at(self, commit: str) -> str:
        """Dependency digest computed straight from Git, with no worktree."""
        manifest = self.bundle.boundary.dependency_manifest
        lock = self.bundle.boundary.lock_file
        entries: dict[str, str] = {}
        for path in (manifest, lock):
            if not path:
                continue
            blob = GitSandbox.read_file_at(self.repo_path, commit, path)
            if blob:
                entries[path] = sha256_hex(blob)
        return digest_of(entries)

    def _reuse_key(self, step_id: str, pool: WorktreePool) -> ReuseKey:
        row = self.store.get_step(step_id)
        node = self.bundle.plan.node(str(row["node_id"])) if row else None
        deps = _json_list(str(row["deps"])) if row else []
        inputs: list[tuple[str, str]] = []
        for dep in deps:
            for artifact in self.store.artifacts_for_step(f"{self.run_id}:{dep}"):
                if str(artifact["status"]) == "COMMITTED":
                    inputs.append(
                        (str(artifact["step_id"]), str(artifact["artifact_digest"]))
                    )
        base = pool.integration_head()
        return reuse_key_for(
            # The node's own subject, not the whole bundle: a change elsewhere in the plan
            # must not invalidate this node's verified work (Spec §13.1 B).
            spec_digest=node_subject_digest(self.bundle, node),
            base_commit=base,
            dependency_digest=self._dependency_digest_at(base),
            toolchain_digest=self._toolchain_digest(),
            input_artifacts=tuple(sorted(inputs)),
        )

    def _try_cache_hit(self, step_id: str, *, pool: WorktreePool) -> StepOutcome | None:
        """Reuse an already-verified artifact, or return None to execute normally.

        Fail-closed by construction: every uncertainty (disabled cache, incomplete key,
        missing gate provenance, a commit that cannot be reached from the current
        integration point, an artifact from this very execution) results in `None`, which
        means "run it".
        """
        if not self.reuse_artifacts:
            return None

        # Cached code cannot bypass the current content-addressed dependency cache.
        if self.bundle.boundary.dependency_manifest or self.bundle.boundary.lock_file:
            from daedalus.application.dependencies import validate_dependencies
            try:
                validate_dependencies(boundary=self.bundle.boundary, changed_files=(),
                    read=lambda path: GitSandbox.read_file_at(self.repo_path,pool.integration_head(),path),
                    cache=self.store.path.parent / "dependency-cache")
            except Exception:  # noqa: BLE001 - an uncertain cache is never reusable
                return None
        row = self.store.get_step(step_id)
        if row is None:
            return None
        node = self.bundle.plan.node(str(row["node_id"]))
        key = self._reuse_key(step_id, pool)
        decision = self.cache.lookup(key, exclude_execution_id=self.execution_id)
        if not decision.reusable:
            self.store.record_metric(
                name="cache_misses",
                value=1,
                unit="count",
                run_id=self.run_id,
                step_id=step_id,
                labels={"reason": decision.reason[:120]},
            )
            return None

        head = pool.integration_head()
        if not pool.contains_commit(decision.commit):
            # The cached commit must be reachable from where this run currently is.
            artifact = self.store.get_artifact(decision.artifact_digest)
            base_digest = str(artifact["code_base_digest"]) if artifact else ""
            if sha256_hex(head) != base_digest:
                self.store.record_metric(
                    name="cache_misses",
                    value=1,
                    unit="count",
                    run_id=self.run_id,
                    step_id=step_id,
                    labels={"reason": "cached commit not reachable from the integration point"},
                )
                return None
            if not _is_ancestor_commit(self.repo_path, head, decision.commit):
                return None
            _git_update_ref(self.repo_path, pool.run_branch, decision.commit, head)

        self.store.record_metric(
            name="cache_hits",
            value=1,
            unit="count",
            run_id=self.run_id,
            step_id=step_id,
            labels={"source": decision.artifact_digest[:12]},
        )
        from daedalus.application.fsm_service import _cache_hit_transaction

        dependents = tuple(
            (f"{self.run_id}:{candidate.node_id}", decision.commit)
            for candidate in self.bundle.plan.nodes
            if node.node_id in candidate.deps
        )
        _cache_hit_transaction(
            self.fsm,
            step_id=step_id,
            execution_id=self.execution_id,
            actor=self.actor,
            payload={
                "source_artifact_digest": decision.artifact_digest,
                "gate_result_ref": decision.gate_result_ref,
                "reuse_key": key.to_dict(),
                "reason": decision.reason,
            },
            correlation_id=self.correlation_id,
            run_id=self.run_id,
            node_id=node.node_id,
            commit=decision.commit,
            dependents=dependents,
        )
        self.store.update_artifact_status(
            decision.artifact_digest,
            status="COMMITTED",
            gate_result_ref=decision.gate_result_ref,
        )
        return StepOutcome(
            step_id=step_id,
            node_id=node.node_id,
            state=StepState.COMMITTED.value,
            attempt=0,
            decision="REUSED",
            commit=decision.commit,
            artifact_digest=decision.artifact_digest,
            feedback=f"reused {decision.artifact_digest[:12]}: {decision.reason}",
        )

    # ------------------------------------------------------------- concurrency
    def _run_workers(self, prepared: list["_PreparedStep"]) -> list["_StepExecution"]:
        """Run the untrusted workers concurrently, and nothing else.

        The thread pool exists only around `worker.implement`. Every store write, Git
        mutation and gate decision happens on the caller's thread.
        """
        if not prepared:
            return []
        if len(prepared) == 1 or self.quota.max_parallel_steps <= 1:
            return [self._execute_worker(item) for item in prepared]
        with ThreadPoolExecutor(
            max_workers=min(len(prepared), self.quota.max_parallel_steps),
            thread_name_prefix="daedalus-worker",
        ) as pool:
            return list(pool.map(self._execute_worker, prepared))

    def _execute_worker(self, prepared: "_PreparedStep") -> "_StepExecution":
        started = time.monotonic()
        try:
            # Bound inside the thread so a concurrently running step's lines are not mixed
            # with this one's, and reset on exit so a reused pool thread starts clean.
            with self.budget.step_scope(prepared.step_id, prepared.attempt), log_context(
                step_id=prepared.step_id, worker_id=self.worker_id, phase="worker"
            ):
                worker_result = self.worker.implement(prepared.sandbox, prepared.context)
        except Exception as error:  # noqa: BLE001 - a crashed worker is a failed candidate
            worker_result = WorkerResult(
                ok=False,
                summary="worker raised an unhandled exception",
                execution_log=f"{type(error).__name__}: {error}",
                worker_id=self.worker_id,
                error="worker_crashed",
            )
        return _StepExecution(
            prepared=prepared,
            worker_result=worker_result,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    # ------------------------------------------------------------------- promote
    def _integrate(self, pool: WorktreePool, result: RunResult) -> None:
        """Promote the run branch onto the authoritative branch, all-or-nothing.

        A partially failed run keeps its successful commits on the run branch — they are
        evidence, and history is never deleted (Spec §12.1) — but the target branch is not
        advanced to half a plan.
        """
        if not result.commits:
            result.notes.append("no step committed; the target branch was left untouched by design")
            return
        if result.status != "COMPLETED":
            result.notes.append(
                f"{result.committed_count} step(s) committed on {pool.run_branch}, but the "
                "run is partial: the target branch was NOT advanced automatically"
            )
            return
        if self.goal_audit_enabled and pool.integration_head() != self._goal_approved_commit:
            result.status = "PARTIAL_FAILURE"
            result.notes.append("promotion blocked: no goal approval for the current commit")
            return
        if (
            self.bundle.goal.risk_level.value in self.independent_validation_levels
            and self._independent_approved_commit != pool.integration_head()
        ):
            from daedalus.application.independent_validation import pending_validation

            request = pending_validation(self.store, self.run_id)
            if request is None:
                request = {
                    "request_id": new_id("validation-request"),
                    "run_id": self.run_id,
                    "execution_id": self.execution_id,
                    "spec_digest": self.spec_digest,
                    "commit": pool.integration_head(),
                    "created_at": utc_now(),
                }
                self.store.append(
                    aggregate_id=f"validation:{self.run_id}",
                    execution_id=self.execution_id,
                    event_type="IndependentValidationRequired",
                    actor=self.actor,
                    payload=request,
                    correlation_id=self.correlation_id,
                )
            self.fsm.transition_run(
                run_id=self.run_id,
                execution_id=self.execution_id,
                event_type="RunEscalated",
                actor=self.actor,
                payload={"source": "independent_validation", "request_id": request["request_id"]},
                correlation_id=self.correlation_id,
            )
            result.status = "AWAITING_APPROVAL"
            result.notes.append(
                "waiting for fresh acceptance and a distinct registered validator's attestation"
            )
            return
        if self.bundle.goal.risk_level.value in self.independent_validation_levels:
            from daedalus.application.independent_validation import IndependentValidationService

            IndependentValidationService(self.store, self.identity).recorded_delivery(
                self.run_id, pool.integration_head(), validation_id=self._independent_validation_id
            )
        from daedalus.infrastructure.git_sandbox import _git

        before = _git(
            self.repo_path, ["rev-parse", "refs/heads/" + self.target_branch], check=True
        ).stdout.strip()
        delivery = {
            "run_id": self.run_id,
            "execution_id": self.execution_id,
            "spec_digest": self.spec_digest,
            "target_branch": self.target_branch,
            "before": before,
            "commit": pool.integration_head(),
            "goal_audit_enabled": self.goal_audit_enabled,
            "goal_approved_commit": self._goal_approved_commit,
            "independent_validation_required": self.bundle.goal.risk_level.value
            in self.independent_validation_levels,
            "independent_validation_id": self._independent_validation_id,
        }
        self.store.append(
            aggregate_id=f"delivery:{self.run_id}",
            execution_id=self.execution_id,
            event_type="DeliveryRequested",
            actor=self.actor,
            payload=delivery,
            correlation_id=self.correlation_id,
        )
        try:
            promoted = pool.promote_to_target(
                expected_commit=self._goal_approved_commit if self.goal_audit_enabled else ""
            )
        except DaedalusError as error:
            result.status = "PARTIAL_FAILURE"
            result.notes.append(f"promotion refused: {error.message}")
            return
        self.store.append(
            aggregate_id=f"delivery:{self.run_id}",
            execution_id=self.execution_id,
            event_type="DeliveryCompleted",
            actor=self.actor,
            payload=delivery,
            correlation_id=self.correlation_id,
        )
        result.promoted_commit = promoted
        result.notes.append(f"target branch {self.target_branch} fast-forwarded to {promoted[:12]}")

    # ------------------------------------------------------------- one step
    def _prepare_step(
        self,
        step_id: str,
        *,
        pool: WorktreePool,
        scheduler: Scheduler,
    ) -> "_PreparedStep | None":
        """Admit one step: lease it and give it its own worktree.

        Runs on the control-plane thread. Everything here is deterministic and cheap;
        the expensive, untrusted part is deferred to `_execute_worker`.
        """
        row = self.store.get_step(step_id)
        if row is None:
            return None

        node = self.bundle.plan.node(str(row["node_id"]))
        # The control plane owns the budget (SPEC-03 per step, quota per run). A worker that
        # was handed a different TokenBudget would have its spending accounted somewhere the
        # gate never looks, which silently disables the resource boundary.
        self._adopt_worker_budget()
        self._current_step_id = step_id
        # Always branch from the current integration point. A dependency-ordered step can
        # only be admitted once its deps have committed into the run branch, so this is
        # never behind them; and a retry after a rebase conflict must re-base on what has
        # already landed, otherwise it would replay the same conflict until it escalated.
        base_commit = pool.integration_head()

        self._touch_worker(status="BUSY", current_step_id=step_id)
        lease = scheduler.acquire_lease(step_id, worker_id=self.worker_id)
        try:
            sandbox = pool.acquire(step_id, base_commit=base_commit)
        except DaedalusError:
            scheduler.release_lease_by_id(lease.lease_id, "RELEASED")
            raise

        self.fsm.transition_step(
            step_id=step_id,
            event_type="StepStarted",
            actor=self.worker_id,
            execution_id=self.execution_id,
            payload={
                "lease_id": lease.lease_id,
                # The expiry travels with the lease id. `lease_expires_at` is written
                # unconditionally, so omitting it here left a RUNNING step holding a lease id
                # with no expiry — an inconsistent pair, and one condition away from the
                # double lease that leases exist to prevent.
                "expire_at": lease.expire_at,
                "timeout_sec": node.timeout_sec,
                "worktree": str(sandbox.worktree_path),
                "base_commit": base_commit,
            },
            correlation_id=self.correlation_id,
        )
        self._record_queue_and_parallelism(step_id)
        # Record exactly which worktree holds this attempt, so a parked or crashed run can
        # re-attach to the pending change instead of guessing or re-running.
        self.store.update_step_state(
            step_id, state=StepState.RUNNING.value, worktree_path=str(sandbox.worktree_path)
        )

        context = WorkerContext(
            step_id=step_id,
            execution_id=self.execution_id,
            node=node,
            bundle=self.bundle,
            base_commit=base_commit,
            attempt=int(row["attempt"]) + 1,
            revision_feedback="\n".join(filter(None, [self.stage_feedback, str(row["last_failure"] or "")])),
            input_artifacts=self._input_artifacts(node.deps),
        )
        return _PreparedStep(
            step_id=step_id,
            node=node,
            attempt=int(row["attempt"]) + 1,
            lease_id=lease.lease_id,
            sandbox=sandbox,
            context=context,
            base_commit=base_commit,
        )

    def _finish_step(
        self,
        execution: "_StepExecution",
        *,
        pool: WorktreePool,
        scheduler: Scheduler,
    ) -> StepOutcome:
        prepared = execution.prepared
        with self.budget.step_scope(prepared.step_id, prepared.attempt):
            return self._finish_step_in_scope(execution, pool=pool, scheduler=scheduler)

    def _finish_step_in_scope(
        self,
        execution: "_StepExecution",
        *,
        pool: WorktreePool,
        scheduler: Scheduler,
    ) -> StepOutcome:
        """Gate, commit and integrate one executed candidate, on the control-plane thread."""
        prepared = execution.prepared
        step_id = prepared.step_id
        sandbox = prepared.sandbox
        node = prepared.node
        worker_result = execution.worker_result
        duration_ms = execution.duration_ms

        self.store.record_metric(
            name="sandbox_runtime_ms",
            value=duration_ms,
            unit="ms",
            run_id=self.run_id,
            step_id=step_id,
        )

        # ---- worker failure: never reaches the gate as a candidate to approve
        if not worker_result.ok:
            return self._fail_step(
                step_id=step_id,
                node_id=node.node_id,
                attempt=prepared.attempt,
                reason=worker_result.summary or worker_result.error or "worker failed",
                detail=worker_result.execution_log,
                duration_ms=duration_ms,
                tokens_used=worker_result.tokens_used,
                scheduler=scheduler,
                lease_id=prepared.lease_id,
                decision="FAIL",
                non_retryable=worker_result.error in NON_RETRYABLE_ERRORS,
                sandbox=sandbox,
            )

        self.fsm.transition_step(
            step_id=step_id,
            event_type="StepGatekeeperEntered",
            actor=self.actor,
            execution_id=self.execution_id,
            payload={"changed_files": list(worker_result.changed_files)},
            correlation_id=self.correlation_id,
        )

        artifact = self._build_artifact(
            step_id=step_id,
            node_id=node.node_id,
            sandbox=sandbox,
            worker_result=worker_result,
            attempt=prepared.attempt,
        )
        artifact_digest = self.fsm.record_artifact(artifact)
        artifact = replace(artifact, artifact_digest=artifact_digest)

        gate = self._gate(
            node=node,
            artifact=artifact,
            sandbox=sandbox,
            execution_log=worker_result.execution_log,
            elapsed_sec=duration_ms / 1000.0,
        )
        self._record_gate(gate, artifact_digest=artifact_digest)

        # ---- tier1 decision
        self.fsm.transition_step(
            step_id=step_id,
            event_type="StepTier1Decided",
            actor=self.actor,
            execution_id=self.execution_id,
            outcome="pass" if gate.tier1.passed else "revise",
            payload={
                "summary": "; ".join(
                    f"{c.name}={'pass' if c.passed else 'FAIL'}" for c in gate.tier1.checks
                ),
                "reason": gate.tier1.revise_feedback() or "all deterministic checks passed",
                "error_codes": list(gate.tier1.infrastructure_errors),
                "artifact_digest": artifact_digest,
            },
            correlation_id=self.correlation_id,
        )

        if not gate.tier1.passed:
            return self._fail_step(
                step_id=step_id,
                node_id=node.node_id,
                attempt=prepared.attempt,
                reason="execution environment unavailable" if gate.tier1.infrastructure_errors else "Tier-1 deterministic gate failed",
                detail=gate.tier1.revise_feedback(),
                duration_ms=duration_ms,
                tokens_used=self.budget.step_used,
                scheduler=scheduler,
                lease_id=prepared.lease_id,
                decision=GateDecision.REVISE.value,
                already_decided=True,
                non_retryable=any(code in NON_RETRYABLE_ERRORS for code in gate.tier1.infrastructure_errors),
                sandbox=sandbox,
            )

        # ---- tier2 decision (only reachable after tier1 passed)
        tier2_outcome = self._emit_tier2_decision(
            step_id=step_id, gate=gate, artifact_digest=artifact_digest
        )

        if tier2_outcome is GateDecision.ESCALATE:
            # ESCALATED, not SUPERSEDED: the step is not discarded, it is waiting. A parked
            # run keeps this step and its worktree so the owner has something to decide on.
            self.fsm.transition_step(
                step_id=step_id,
                event_type="StepExecutionFailed",
                actor=self.actor,
                execution_id=self.execution_id,
                outcome="escalate",
                payload={"reason": "tier-2 escalated to a human owner"},
                correlation_id=self.correlation_id,
            )
            scheduler.release_lease_by_id(prepared.lease_id, "RELEASED")
            return StepOutcome(
                step_id=step_id,
                node_id=node.node_id,
                state=StepState.ESCALATED.value,
                attempt=prepared.attempt,
                decision=GateDecision.ESCALATE.value,
                artifact_digest=artifact_digest,
                feedback=" ".join(gate.tier2.reasons) if gate.tier2 else "",
                tokens_used=self.budget.step_used,
                duration_ms=duration_ms,
                reasons=tuple(gate.tier2.reasons) if gate.tier2 else (),
            )

        if tier2_outcome is GateDecision.REVISE:
            return self._fail_step(
                step_id=step_id,
                node_id=node.node_id,
                attempt=prepared.attempt,
                reason="Tier-2 semantic review requested changes",
                detail="\n".join(gate.tier2.violations) if gate.tier2 else "",
                duration_ms=duration_ms,
                tokens_used=self.budget.step_used,
                scheduler=scheduler,
                lease_id=prepared.lease_id,
                decision=GateDecision.REVISE.value,
                already_decided=True,
                sandbox=sandbox,
            )

        # ---- commit and integrate
        return self._commit_step(
            step_id=step_id,
            node=node,
            sandbox=sandbox,
            pool=pool,
            scheduler=scheduler,
            lease_id=prepared.lease_id,
            artifact_digest=artifact_digest,
            gated_tree=str(artifact.extra.get("gated_tree") or ""),
            gate=gate,
            attempt=prepared.attempt,
            duration_ms=duration_ms,
        )

    def _emit_tier2_decision(
        self,
        *,
        step_id: str,
        gate: GateOutcome,
        artifact_digest: str,
    ) -> GateDecision:
        if gate.tier2 is None:
            self.fsm.transition_step(
                step_id=step_id,
                event_type="StepTier2Decided",
                actor=self.actor,
                execution_id=self.execution_id,
                outcome="approve",
                payload={
                    "summary": "no semantic reviewer configured; Tier-1 pass is sufficient",
                    "artifact_digest": artifact_digest,
                },
                correlation_id=self.correlation_id,
            )
            return GateDecision.APPROVE

        outcome_map = {
            GateDecision.APPROVE: "approve",
            GateDecision.REVISE: "revise",
            GateDecision.ESCALATE: "escalate",
        }
        # The transition follows the PIPELINE's decision, not the reviewer's. The pipeline may
        # have escalated a review the reviewer approved (Spec §10: a CRITICAL change may not
        # auto-merge on a semantic review alone). Using the reviewer's own decision here
        # silently discarded that escalation and let a critical change commit automatically.
        effective = gate.decision
        self.fsm.transition_step(
            step_id=step_id,
            event_type="StepTier2Decided",
            actor=self.actor,
            execution_id=self.execution_id,
            outcome=outcome_map.get(effective, "escalate"),
            payload={
                "summary": " ".join(gate.tier2.reasons)
                or f"reviewer said {gate.tier2.decision.value}",
                "violations": list(gate.tier2.violations),
                "confidence": gate.tier2.confidence,
                "fail_closed": gate.tier2.fail_closed,
                # Both are recorded: the reviewer's own verdict and the effective one, so the
                # audit can show that a human was required even though the model approved.
                "reviewer_decision": gate.tier2.decision.value,
                "effective_decision": effective.value,
                "overridden_by_policy": effective is not gate.tier2.decision,
                "artifact_digest": artifact_digest,
            },
            correlation_id=self.correlation_id,
        )
        return effective

    @property
    def worker_id(self) -> str:
        return getattr(self.worker, "worker_id", "worker-01")

    # ------------------------------------------------------------------ commit
    def _commit_step(
        self,
        *,
        step_id: str,
        node: PlanNode,
        sandbox: GitSandbox,
        pool: WorktreePool,
        scheduler: Scheduler,
        lease_id: str,
        artifact_digest: str,
        gated_tree: str,
        gate: GateOutcome,
        attempt: int,
        duration_ms: int,
        approved: bool = False,
    ) -> StepOutcome:
        """Commit inside the step's worktree, then integrate it into the run branch.

        Two things make this safe under concurrency:

        * the commit is **content-addressed** — the tree that was gated (`expected_tree`)
          is what gets committed, so a crash between `git commit` and the control-plane
          transaction reuses the existing commit instead of creating a second one;
        * integration is a fast-forward, and a step that cannot fast-forward is rebased
          and **re-gated** before it is allowed to land (Spec §11.2).
        """
        key = idempotency_key(self.execution_id, step_id, "commit")
        existing = self.store.idempotent_result(key)
        if existing is not None:
            commit = str(existing.get("commit", ""))
            row = self.store.get_step(step_id)
            if row is None or row["state"] != StepState.COMMITTED.value or existing.get("artifact_digest") != artifact_digest:
                raise DaedalusError("commit receipt conflicts with the step projection or artifact; run recovery")
            return StepOutcome(
                step_id=step_id,
                node_id=node.node_id,
                state=StepState.COMMITTED.value,
                attempt=attempt,
                decision=gate.decision.value,
                commit=commit,
                artifact_digest=artifact_digest,
                tokens_used=self.budget.step_used,
                duration_ms=duration_ms,
            )

        row = self.store.get_step(step_id)
        # Spec §11.1: re-verify every precondition at the moment of commit.
        if self._execution_expired():
            return self._fail_step(
                step_id=step_id,
                node_id=node.node_id,
                attempt=attempt,
                reason="the execution has expired and may no longer commit",
                detail=(
                    f"the run was created more than {self.execution_ttl_sec}s ago; a commit "
                    "against a base the world has moved past is refused (Spec §11.1)"
                ),
                duration_ms=duration_ms,
                tokens_used=self.budget.step_used,
                scheduler=scheduler,
                lease_id=lease_id,
                decision=GateDecision.ESCALATE.value,
                non_retryable=True,
                sandbox=sandbox,
            )
        if str(row["spec_digest"]) != self.spec_digest:
            raise SpecDigestMismatch(
                f"step {step_id} is pinned to {str(row['spec_digest'])[:12]} but the run "
                f"is pinned to {self.spec_digest[:12]}"
            )

        if not approved:
            # The ordinary path: APPROVED -> COMMITTING. An owner-approved commit already
            # reached COMMITTING via `StepApproved`, so re-emitting would be illegal.
            self.fsm.transition_step(
                step_id=step_id,
                event_type="StepCommitRequested",
                actor=self.actor,
                execution_id=self.execution_id,
                payload={
                    "artifact_digest": artifact_digest,
                    "gate_result_digest": gate_result_digest(gate),
                    "idempotency_key": key,
                    "run_branch": pool.run_branch,
                    "gated_tree": gated_tree,
                    "lease_id": lease_id,
                    "base_commit": sandbox.base_commit,
                    "spec_digest": self.spec_digest,
                    "gate_result_ids": [gate.tier1_result_id, gate.tier2_result_id],
                },
                correlation_id=self.correlation_id,
            )

        # Invariant: the tree that lands must be the tree the gate approved. Anything the
        # gate's own test run (or the worker) wrote after the review would otherwise ride
        # into the commit unreviewed.
        expected_tree = gated_tree
        actual_tree = sandbox.tree_digest()
        if expected_tree and actual_tree != expected_tree:
            return self._fail_step(
                step_id=step_id,
                node_id=node.node_id,
                attempt=attempt,
                reason="the worktree changed after the gate reviewed it",
                detail=(
                    f"gated tree {expected_tree[:12]} != current tree {actual_tree[:12]}; "
                    "the change set is no longer the reviewed one"
                ),
                duration_ms=duration_ms,
                tokens_used=self.budget.step_used,
                scheduler=scheduler,
                lease_id=lease_id,
                decision=GateDecision.REVISE.value,
                sandbox=sandbox,
            )

        commit = sandbox.commit_once(
            self._commit_message(node, artifact_digest, gate), expected_tree=expected_tree
        )
        rebased = 0

        # Integrate into the run branch. A genuine non-fast-forward is the ONLY thing that
        # requires the Spec §11.2 sequence, so we attempt the fast-forward first and treat
        # `CommitConflict` as the trigger. Asking "is this commit already an ancestor of
        # the branch?" is a different question, and answering it here caused a spurious
        # rebase-and-re-gate on every ordinary commit.
        try:
            integrated = pool.integrate(sandbox)
        except CommitConflict:
            rebased, _rebased_commit, effective_digest = self._rebase_and_integrate(
                step_id=step_id,
                node=node,
                sandbox=sandbox,
                pool=pool,
                scheduler=scheduler,
                lease_id=lease_id,
                artifact_digest=artifact_digest,
                gate=gate,
                attempt=attempt,
                duration_ms=duration_ms,
            )
            if rebased < 0:
                # `_rebase_and_integrate` already produced the failed outcome.
                assert self._rebase_failure is not None
                return self._rebase_failure
            artifact_digest = effective_digest or artifact_digest
            if self._rebase_gate is None or not self._rebase_gate.allows_commit:
                raise DaedalusError("the rebased artifact has no accepting gate")
            gate = self._rebase_gate
            approved = False  # acceptance now comes from the new gate, not an old artifact's approval
            # The rebased tree is what lands, so re-message it rather than leaving a commit
            # description that talks about a tree nobody reviewed.
            _git_amend_message(sandbox, self._commit_message(node, artifact_digest, gate))
            integrated = pool.integrate(sandbox)

        # One transaction for: idempotency claim, commit event, run event, lease release
        # and dependent base advance. A crash either leaves all of it or none.
        from daedalus.application.fsm_service import _commit_step_transaction

        dependents = tuple(
            (f"{self.run_id}:{candidate.node_id}", integrated)
            for candidate in self.bundle.plan.nodes
            if node.node_id in candidate.deps
        )
        _commit_step_transaction(
            self.fsm,
            step_id=step_id,
            execution_id=self.execution_id,
            actor=self.actor,
            payload={
                "commit": integrated,
                "artifact_digest": artifact_digest,
                "node_id": node.node_id,
                "attempt": attempt,
                "run_branch": pool.run_branch,
                "rebased": rebased,
                # Non-empty only when a human overrode an escalation. The commit record must
                # show that, otherwise a high-risk merge looks like an automatic one.
                "approved_by": (
                    str((self.store.latest_approval(step_id) or {}).get("approved_by", ""))
                    if approved
                    else ""
                ),
                "owner_override": approved,
            },
            correlation_id=self.correlation_id,
            idempotency_key=key,
            idempotency_result={
                "commit": integrated,
                "artifact_digest": artifact_digest,
                "gate_result_digest": gate_result_digest(gate),
                "rebased": rebased,
            },
            run_id=self.run_id,
            node_id=node.node_id,
            commit=integrated,
            dependents=dependents,
            lease_id=lease_id,
        )
        self.store.record_metric(
            name="step_rebases",
            value=float(rebased),
            unit="count",
            run_id=self.run_id,
            step_id=step_id,
        )

        return StepOutcome(
            step_id=step_id,
            node_id=node.node_id,
            state=StepState.COMMITTED.value,
            attempt=attempt,
            decision=gate.decision.value,
            commit=integrated,
            artifact_digest=artifact_digest,
            tokens_used=self.budget.step_used,
            duration_ms=duration_ms,
            rebased=rebased,
        )

    def _rebase_and_integrate(
        self,
        *,
        step_id: str,
        node: PlanNode,
        sandbox: GitSandbox,
        pool: WorktreePool,
        scheduler: Scheduler,
        lease_id: str,
        artifact_digest: str,
        gate: GateOutcome,
        attempt: int,
        duration_ms: int,
    ) -> tuple[int, str, str]:
        """Spec §11.2: REBASE_REQUIRED -> rebase -> Tier-1 -> Tier-2 -> commit.

        Returns `(rebases_applied, commit, effective_artifact_digest)` on success. On
        failure it records `self._rebase_failure` and returns `(-1, "", "")`.

        The re-gate produces its own artifact and gate results, because the rebased tree
        is *not* the tree the original gate approved. Reusing the earlier verdict would be
        exactly the "cache the wrong thing" failure that Spec §13.2 warns about.
        """
        upstream = pool.integration_head()
        self._note_rebase_required(step_id, node.node_id, sandbox.head(), upstream)

        ok, detail = sandbox.rebase_onto(upstream)
        if not ok:
            # The change does not apply on top of what has already landed. That is a
            # semantic conflict the worker must resolve, never something to force through.
            self._rebase_failure = self._fail_step(
                step_id=step_id,
                node_id=node.node_id,
                attempt=attempt,
                reason="rebase onto the run branch conflicted",
                detail=f"the change does not apply on top of {upstream[:12]}: {detail}",
                duration_ms=duration_ms,
                tokens_used=self.budget.step_used,
                scheduler=scheduler,
                lease_id=lease_id,
                decision=GateDecision.REVISE.value,
                sandbox=sandbox,
            )
            return -1, "", ""

        rebase_artifact = self._artifact_for(
            step_id=step_id,
            node_id=node.node_id,
            sandbox=sandbox,
            attempt=attempt,
            status="REBASE_REQUIRED",
        )
        rebase_artifact_digest = self.fsm.record_artifact(rebase_artifact)
        rebase_artifact = replace(rebase_artifact, artifact_digest=rebase_artifact_digest)
        regate = self._gate(
            node=node,
            artifact=rebase_artifact,
            sandbox=sandbox,
            execution_log=f"re-gate after rebase onto {upstream[:12]}",
            elapsed_sec=duration_ms / 1000.0,
        )
        self._record_gate(regate, artifact_digest=rebase_artifact_digest)
        self.store.record_metric(
            name="regate_after_rebase",
            value=1,
            unit="count",
            run_id=self.run_id,
            step_id=step_id,
            labels={"tier1": regate.tier1.decision.value},
        )

        if not regate.tier1.passed:
            self._rebase_failure = self._fail_step(
                step_id=step_id,
                node_id=node.node_id,
                attempt=attempt,
                reason="Tier-1 failed after rebasing onto the run branch",
                detail=regate.tier1.revise_feedback(),
                duration_ms=duration_ms,
                tokens_used=self.budget.step_used,
                scheduler=scheduler,
                lease_id=lease_id,
                decision=GateDecision.REVISE.value,
                sandbox=sandbox,
            )
            return -1, "", ""

        if not regate.allows_commit:
            self._rebase_failure = self._fail_step(
                step_id=step_id,
                node_id=node.node_id,
                attempt=attempt,
                reason="Tier-2 rejected the rebased tree",
                detail=" ".join(regate.reasons + regate.violations),
                duration_ms=duration_ms,
                tokens_used=self.budget.step_used,
                scheduler=scheduler,
                lease_id=lease_id,
                decision=regate.decision.value,
                sandbox=sandbox,
            )
            return -1, "", ""

        self._rebase_gate = regate
        return 1, sandbox.head(), rebase_artifact_digest

    def _note_rebase_required(
        self, step_id: str, node_id: str, commit: str, upstream: str
    ) -> None:
        try:
            self.fsm.transition_run(
                run_id=self.run_id,
                execution_id=self.execution_id,
                event_type="RunRebaseRequired",
                actor=self.actor,
                payload={
                    "step_id": step_id,
                    "node_id": node_id,
                    "commit": commit,
                    "upstream": upstream,
                },
                correlation_id=self.correlation_id,
            )
        except DaedalusError:
            # The run may already be terminal; the rebase itself still has to happen.
            pass

    def _commit_message(self, node: PlanNode, artifact_digest: str, gate: GateOutcome) -> str:
        return (
            f"{self.bundle.goal.goal_id}: {node.node_id}\n\n"
            f"execution: {self.execution_id}\n"
            f"spec: {self.spec_digest[:12]}\n"
            f"artifact: {artifact_digest[:12]}\n"
            f"gate: tier1={gate.tier1.decision.value} "
            f"tier2={gate.tier2.decision.value if gate.tier2 else 'n/a'}\n"
        )

    def _artifact_common(
        self,
        *,
        step_id: str,
        node_id: str,
        sandbox: GitSandbox,
        attempt: int,
        status: str,
        changed_files: tuple[str, ...],
        patch: str,
        model: str,
        extra: dict[str, Any],
    ) -> Artifact:
        """The fields every recorded artifact carries, written once.

        Both artifact paths need: the §14 traceability reference, the digests that make the
        artefact reproducible, and `gated_tree` — the identity of the tree the gate reviewed,
        which the commit path re-checks. They were spelled out twice and drifted, so the rebase
        artifact had neither a log reference nor a gated tree, and a rebased commit therefore
        skipped the "the tree that lands is the tree that was approved" check entirely.
        """
        return Artifact(
            step_id=step_id,
            execution_id=self.execution_id,
            parent_commit=sandbox.head(),
            changed_files=tuple(sorted(changed_files)),
            patch_digest=sha256_hex(patch),
            artifact_digest="",
            spec_digest=self.spec_digest,
            node_spec_digest=node_subject_digest(self.bundle, self.bundle.plan.node(node_id)),
            dependency_digest=self._dependency_digest(sandbox),
            toolchain_digest=self._toolchain_digest(),
            code_base_digest=sha256_hex(sandbox.head()),
            input_artifact_digest=self._input_digest(node_id),
            execution_log_ref=execution_log_ref(self.run_id, step_id),
            status=status,
            worker_id=self.worker_id,
            sandbox_image="host-process",
            model=model,
            created_at=utc_now(),
            extra={
                "node_id": node_id,
                "attempt": attempt,
                "diff_stat": sandbox.diff().stat,
                # The patch itself, bounded. A rejected attempt has no commit, so Git cannot be
                # asked for it later — and a rejected attempt is exactly what an operator wants
                # to look at.
                "patch_preview": patch[:PATCH_PREVIEW_BYTES],
                "patch_truncated": len(patch) > PATCH_PREVIEW_BYTES,
                "gated_tree": sandbox.tree_digest(),
                **extra,
            },
        )

    def _input_digest(self, node_id: str) -> str:
        return digest_of(
            sorted(
                (artifact.step_id, artifact.artifact_digest)
                for artifact in self._input_artifacts(self.bundle.plan.node(node_id).deps)
            )
        )

    def _artifact_for(
        self,
        *,
        step_id: str,
        node_id: str,
        sandbox: GitSandbox,
        attempt: int,
        status: str,
    ) -> Artifact:
        """An artifact for a stage that ran without a worker (currently: the rebase re-gate)."""
        diff = sandbox.diff()
        return self._artifact_common(
            step_id=step_id,
            node_id=node_id,
            sandbox=sandbox,
            attempt=attempt,
            status=status,
            changed_files=tuple(sorted(diff.files)),
            patch=diff.patch,
            model=str(getattr(self.worker, "name", "")),
            extra={"stage": status},
        )

    # ------------------------------------------------------------------ failure
    def _fail_step(
        self,
        *,
        step_id: str,
        node_id: str,
        attempt: int,
        reason: str,
        detail: str,
        duration_ms: int,
        tokens_used: int,
        scheduler: Scheduler,
        lease_id: str,
        decision: str = "REVISE",
        already_decided: bool = False,
        non_retryable: bool = False,
        sandbox: GitSandbox | None = None,
    ) -> StepOutcome:
        # Revert the rejected attempt inside the step's own worktree, so it cannot leak
        # into a later accepted attempt of the same step.
        if sandbox is not None:
            sandbox.reset_hard()

        retryable = (not non_retryable) and attempt < self._max_attempts(step_id)
        if retryable:
            # Spec §17: exponential backoff, capped. Sleeping here rather than in the scheduler
            # keeps the delay attributable to the step that failed.
            self._sleep_before_retry(attempt)

        # A retrying gate result is already in REVISE. A terminal gate/environment fault
        # must still move REVISE -> ESCALATED, or the scheduler will lease it again.
        if not already_decided or not retryable:
            self.fsm.transition_step(
                step_id=step_id,
                event_type="StepExecutionFailed",
                actor=self.actor,
                execution_id=self.execution_id,
                outcome="revise" if retryable else "escalate",
                payload={
                    "reason": reason,
                    "detail": detail[:4000],
                    "recoverable": retryable,
                },
                correlation_id=self.correlation_id,
            )

        scheduler.release_lease_by_id(lease_id, "RELEASED")
        self.store.record_metric(
            name="step_failures",
            value=1,
            unit="count",
            run_id=self.run_id,
            step_id=step_id,
            labels={"reason": reason[:80]},
        )

        if retryable:
            # REVISE is already a lease-ready state and needs no recovery event;
            # LOST / FAILED / TIMEOUT do. Sending StepRecovered to REVISE would be an
            # illegal transition, and swallowing that quietly is exactly how a retry
            # loop stops retrying without anyone noticing.
            current = self.store.get_step(step_id)
            if current is not None and current["state"] != StepState.REVISE.value:
                self.fsm.transition_step(
                    step_id=step_id,
                    event_type="StepRecovered",
                    actor=self.actor,
                    payload={"reason": f"retry {attempt} of {self._max_attempts(step_id)}"},
                    correlation_id=self.correlation_id,
                )
        state = self.store.get_step(step_id)
        return StepOutcome(
            step_id=step_id,
            node_id=node_id,
            state=str(state["state"]) if state else StepState.FAILED.value,
            attempt=attempt,
            decision=decision,
            feedback=detail,
            tokens_used=tokens_used,
            duration_ms=duration_ms,
            reasons=(reason,),
        )

    def _escalate(self, step_id: str, reason: str, result: RunResult) -> None:
        row = self.store.get_step(step_id)
        if row is None:
            return
        state = StepState(row["state"])
        if state is StepState.ESCALATED:
            return
        try:
            self.fsm.transition_step(
                step_id=step_id,
                event_type="StepExecutionFailed",
                actor=self.actor,
                execution_id=self.execution_id,
                outcome="escalate",
                payload={"reason": reason},
                correlation_id=self.correlation_id,
            )
        except DaedalusError as error:
            result.notes.append(f"could not escalate {step_id}: {error.message}")

    def _handle_failed_step(
        self,
        step_id: str,
        outcome: StepOutcome,
        result: RunResult,
    ) -> None:
        state = StepState(outcome.state)
        if state in {StepState.ESCALATED, StepState.FAILED, StepState.TIMEOUT}:
            node_id = outcome.node_id
            affected = self.scheduler().propagate_failure(node_id)
            if affected:
                result.notes.append(
                    f"failure in {node_id} unreachable downstream nodes: {affected}"
                )

    def _max_attempts(self, step_id: str) -> int:
        row = self.store.get_step(step_id)
        return int(row["max_attempts"]) if row else 3

    # --------------------------------------------------------------- artifacts
    def _build_artifact(
        self,
        *,
        step_id: str,
        node_id: str,
        sandbox: GitSandbox,
        worker_result: Any,
        attempt: int,
    ) -> Artifact:
        diff = sandbox.diff()
        changed = tuple(sorted(set(diff.files) | set(worker_result.changed_files)))
        return self._artifact_common(
            step_id=step_id,
            node_id=node_id,
            sandbox=sandbox,
            attempt=attempt,
            status="AWAITING_GATEKEEPER",
            changed_files=changed,
            patch=diff.patch,
            model=str(getattr(worker_result, "model", "")),
            extra={"worker_summary": getattr(worker_result, "summary", ""),
                   "inspection_receipts": safe_receipts(getattr(worker_result, "extra", {}))},
        )

    def _input_artifacts(self, deps: tuple[str, ...]) -> tuple[Artifact, ...]:
        found: list[Artifact] = []
        for dep in deps:
            step_id = f"{self.run_id}:{dep}"
            for row in self.store.artifacts_for_step(step_id):
                found.append(
                    Artifact(
                        step_id=str(row["step_id"]),
                        execution_id=str(row["execution_id"]),
                        parent_commit=str(row["parent_commit"]),
                        changed_files=tuple(_json_list(str(row["changed_files"]))),
                        patch_digest=str(row["patch_digest"]),
                        artifact_digest=str(row["artifact_digest"]),
                        spec_digest=str(row["spec_digest"]),
                        status=str(row["status"]),
                    )
                )
        return tuple(found)

    def _dependency_digest(self, sandbox: GitSandbox) -> str:
        manifest = self.bundle.boundary.dependency_manifest
        lock = self.bundle.boundary.lock_file
        entries: dict[str, str] = {}
        for path in (manifest, lock):
            if path and sandbox.exists(path):
                entries[path] = sha256_hex(sandbox.read_file(path))
        return digest_of(entries)

    def _toolchain_digest(self) -> str:
        import platform
        import sys

        return digest_of(
            {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "gatekeeper": "daedalus-gatekeeper/3",
            }
        )

    # ---------------------------------------------------------------- gatekeeper
    def _gate(
        self,
        *,
        node: PlanNode,
        artifact: Artifact,
        sandbox: GitSandbox,
        execution_log: str,
        elapsed_sec: float,
    ) -> GateOutcome:
        """Run the two-tier gate against one worktree, bound to the frozen spec digest."""
        gatekeeper = self._get_gatekeeper(node)
        return gatekeeper.gate(
            artifact=artifact,
            sandbox=sandbox,
            goal_intent=self.bundle.goal.objective,
            node_intent=node.intent or node.objective,
            acceptance_criteria=tuple(
                f"{c.criterion_id}: {c.statement or c.command or c.path}"
                for c in self.bundle.goal.acceptance_criteria
            ),
            subject_digest=self.spec_digest,
            execution_log=execution_log,
            elapsed_sec=elapsed_sec,
            tokens_used=self.budget.step_used,
        )

    def _get_gatekeeper(self, node: Any) -> Gatekeeper:
        if self.tier2 is not None and hasattr(self.tier2.reviewer, "budget"):
            self.tier2.reviewer.budget = self.budget
        tier1 = Tier1Gate(
            goal=self.bundle.goal,
            plan_node=node,
            boundary=self.bundle.boundary,
            meta=self.bundle.meta,
            driver=self.isolation.driver if self.isolation else None,
            dependency_cache=self.store.path.parent / "dependency-cache",
        )
        return Gatekeeper(
            tier1=tier1,
            tier2=self.tier2,
            risk_level=self.bundle.goal.risk_level.value,
            manual_review_levels=frozenset(self.manual_review_levels),
        )

    def _record_gate(self, gate: GateOutcome, *, artifact_digest: str) -> None:
        self.store.record_gate_result(
            gate_result_id=gate.tier1_result_id or new_id("gate"),
            step_id=gate.step_id,
            execution_id=gate.execution_id,
            artifact_digest=artifact_digest,
            tier=1,
            decision=gate.tier1.decision.value,
            subject_digest=gate.subject_digest,
            reasons=list(gate.tier1.reasons),
            violations=list(gate.tier1.revise_feedback().splitlines()) if gate.tier1.reasons else [],
            confidence=None,
            evidence={"checks": [c.to_payload() for c in gate.tier1.checks]},
        )
        if gate.tier2 is not None:
            self.store.record_gate_result(
                gate_result_id=gate.tier2_result_id or new_id("gate"),
                step_id=gate.step_id,
                execution_id=gate.execution_id,
                artifact_digest=artifact_digest,
                tier=2,
                decision=gate.tier2.decision.value,
                subject_digest=gate.subject_digest,
                reasons=list(gate.tier2.reasons),
                violations=list(gate.tier2.violations),
                confidence=gate.tier2.confidence,
                evidence={"fail_closed": gate.tier2.fail_closed},
            )

    # -------------------------------------------------------------------- status
    def _is_finished(self) -> bool:
        steps = self.store.list_steps(self.run_id)
        if not steps:
            return False
        for row in steps:
            if str(row["execution_id"]) != self.execution_id:
                continue
            state = StepState(row["state"])
            if state not in {
                StepState.COMMITTED,
                StepState.CANCELLED,
                StepState.SUPERSEDED,
                StepState.FAILED,
                StepState.TIMEOUT,
                StepState.ESCALATED,
            }:
                return False
        return True

    def _final_status(self) -> str:
        steps = [
            row
            for row in self.store.list_steps(self.run_id)
            if str(row["execution_id"]) == self.execution_id
        ]
        if not steps:
            return "FAILED"
        committed = [r for r in steps if str(r["state"]) == StepState.COMMITTED.value]
        if len(committed) == len(steps):
            return "COMPLETED"
        if committed:
            return "PARTIAL_FAILURE"
        return "FAILED"

    #: The terminal statuses a run can be closed with. `AWAITING_APPROVAL` is deliberately
    #: absent: a parked run has *not* finished, and the park path returns before this point.
    #: Naming the mapping by constant means a future status that reaches here is a clear
    #: error rather than a bare `KeyError` three frames deep.
    _CLOSE_EVENTS = {
        "COMPLETED": "RunCompleted",
        "PARTIAL_FAILURE": "RunPartiallyFailed",
        "FAILED": "RunFailed",
        "CANCELLED": "RunCancelled",
    }

    def _close_run(self, result: RunResult) -> None:
        try:
            event_type = self._CLOSE_EVENTS[result.status]
        except KeyError:
            raise DaedalusError(
                f"run status {result.status!r} has no closing event. A parked run must not "
                "reach `_close_run`: it is not finished, and closing it would record a "
                "terminal outcome for work that is still waiting on a human."
            ) from None
        self.fsm.transition_run(
            run_id=self.run_id,
            execution_id=self.execution_id,
            event_type=event_type,
            actor=self.actor,
            payload={
                "status": result.status,
                "committed": result.committed_count,
                "steps": len(result.steps),
                "tokens_used": result.tokens_used,
                "commits": result.commits,
            },
            correlation_id=self.correlation_id,
        )
        self._close_execution(result)
        self.store.record_metric(
            name="run_tokens",
            value=float(result.tokens_used),
            unit="tokens",
            run_id=self.run_id,
        )

    # --------------------------------------------------- §19 projections
    def _touch_worker(self, *, status: str, current_step_id: str | None = None) -> None:
        """Keep the worker registry current.

        Best-effort on purpose: a worker that cannot be registered is a visibility gap, not a
        reason to abandon a run whose work is already committed to the repository.
        """
        worker_id = self.worker_id
        if not worker_id:
            return
        try:
            self.store.register_worker(
                worker_id,
                kind="model" if getattr(self.worker, "uses_model", False) else "scripted",
                status=status,
                current_step_id=current_step_id,
                notes=type(self.worker).__name__,
            )
        except Exception:  # noqa: BLE001 - visibility must not break execution
            get_logger("orchestrator").warning(
                "could not update the worker registry for %s", worker_id, exc_info=True
            )

    def _close_execution(self, result: RunResult) -> None:
        """Write the execution's outcome, derived from its steps rather than counted."""
        steps = [r for r in self.store.list_steps(self.run_id) if r["execution_id"] == self.execution_id]
        # One summary function, so the counters reconcile by construction and cannot disagree
        # with the metric summary or the per-worker counts. This previously listed a
        # `"REJECTED"` state that does not exist and omitted ESCALATED, so a PARTIAL_FAILURE
        # run could report zero failures.
        counters = execution_counters([str(row["state"]) for row in steps])
        self.store.upsert_execution(
            {
                "execution_id": self.execution_id,
                "run_id": self.run_id,
                "parent_execution_id": self.parent_execution_id,
                "replay_from_commit": self.replay_from_commit,
                "kind": "replay" if self.parent_execution_id else "run",
                "status": result.status,
                "spec_digest": self.spec_digest,
                "finished_at": utc_now(),
                **counters,
            }
        )
        self._touch_worker(status="IDLE")


# ---------------------------------------------------------------------------
# Internal step-pipeline records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PreparedStep:
    """An admitted step: leased, with its own worktree and a frozen worker context."""

    step_id: str
    node: PlanNode
    attempt: int
    lease_id: str
    sandbox: GitSandbox
    context: WorkerContext
    base_commit: str


@dataclass(frozen=True, slots=True)
class _StepExecution:
    """The result of running one prepared step's worker."""

    prepared: _PreparedStep
    worker_result: WorkerResult
    duration_ms: int


def _default_worker() -> CodingWorker:
    from daedalus.application.coding_worker import ScriptedWorker

    return ScriptedWorker(ops=(), worker_id="worker-empty")


def _is_ancestor_commit(repo_path: Path, ancestor: str, descendant: str) -> bool:
    from daedalus.infrastructure.git_sandbox import _git  # noqa: PLC2701 - same package

    return _git(repo_path, ["merge-base", "--is-ancestor", ancestor, descendant], check=False).exit_code == 0


def _git_update_ref(repo_path: Path, ref: str, new: str, old: str) -> None:
    from daedalus.infrastructure.git_sandbox import _git  # noqa: PLC2701 - same package

    _git(repo_path, ["update-ref", f"refs/heads/{ref}", new, old], check=True)


def _git_amend_message(sandbox: GitSandbox, message: str) -> None:
    """Rewrite only the message of the step's own commit. Never rewrites shared history."""
    from daedalus.infrastructure.git_sandbox import _git  # noqa: PLC2701 - same package

    _git(sandbox.worktree_path, ["commit", "--amend", "-m", message, "--no-verify"], check=True)


def _json_list(raw: str) -> list[str]:
    import json

    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return [str(item) for item in value] if isinstance(value, list) else []


def _is_ancestor(sandbox: GitSandbox, commit: str) -> bool:
    from daedalus.infrastructure.git_sandbox import _git

    result = _git(
        sandbox.worktree_path,
        ["merge-base", "--is-ancestor", commit, "HEAD"],
        check=False,
    )
    return result.exit_code == 0
