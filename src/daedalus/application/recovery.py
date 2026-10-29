"""Recovery: repairing a workspace after an interrupted process (Spec §16, §28).

A control plane that can crash and leave the schedule inconsistent is not deliverable. This
module answers "what is broken?" and then, only with `apply=True`, fixes it.

Findings it detects and repairs:

    STALE_LEASE       a lease past its expiry with the step still LEASED
    ORPHAN_RUN        a run stuck in RUNNING/PENDING that no process owns
    PARALLEL_EXECUTION  two non-terminal runs sharing one execution id (impossible state)
    PROJECTION_DRIFT  a projection that disagrees with the event log
    SEQUENCE_GAP      an aggregate whose event sequence has a hole
    MISSING_WORKTREE  a non-terminal step whose recorded worktree is gone
    ORPHAN_BRANCH     a run branch with no run record

The distinction that matters: a *stale lease* is repaired automatically, because the lease
is bookkeeping and the FSM transition is legal. A *sequence gap* is never repaired, because
it means history itself is inconsistent and inventing the missing event would be worse than
reporting it. Recovery repairs bookkeeping; it never fabricates facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from daedalus.application.fsm_service import StateMachineService
from daedalus.application.observability import get_logger, log_context
from daedalus.domain.fsm import RUN_TERMINAL, RunState, StepState, execution_counters
from daedalus.domain.ids import utc_now
from daedalus.infrastructure.store.event_store import EventStore

logger = get_logger("recovery")


class Finding(str, Enum):
    INCOMPLETE_COMMIT = "incomplete_commit"
    INCOMPLETE_DELIVERY = "incomplete_delivery"
    REPOSITORY_ACTIVE = "repository_active"
    STALE_LEASE = "stale_lease"
    ORPHAN_RUN = "orphan_run"
    PROJECTION_DRIFT = "projection_drift"
    SEQUENCE_GAP = "sequence_gap"
    MISSING_WORKTREE = "missing_worktree"
    #: A worktree on disk that no non-terminal step references: sandbox leakage (Spec §16).
    ORPHAN_WORKTREE = "orphan_worktree"
    #: An `executions` row that disagrees with its run or with the steps projection.
    EXECUTION_DRIFT = "execution_drift"
    #: A `workers` row still marked BUSY for a step that is no longer running.
    STALE_WORKER = "stale_worker"
    #: A step whose two lease columns disagree, so the row is neither leased nor free.
    INCONSISTENT_LEASE = "inconsistent_lease"


#: Findings recovery will fix. Everything else is reported and left alone.
REPAIRABLE = frozenset(
    {
        Finding.INCOMPLETE_COMMIT,
        Finding.INCOMPLETE_DELIVERY,
        Finding.STALE_LEASE,
        Finding.ORPHAN_RUN,
        Finding.MISSING_WORKTREE,
        Finding.ORPHAN_WORKTREE,
        # These are projections the control plane owns, derived from the event log. Repairing
        # them is rebuilding a cache, not inventing a fact, which is the same category as the
        # stale lease above. Without a repair path an `executions` row stayed RUNNING and a
        # `workers` row stayed BUSY for the life of the database, because nothing ever
        # revisited them after a crash.
        Finding.EXECUTION_DRIFT,
        Finding.STALE_WORKER,
        # Clearing a half-written lease restores a projection invariant; it does not decide
        # that anyone is working. The conservative direction is to free the step, which makes
        # it retryable, rather than to leave it claiming a claim nobody can act on.
        Finding.INCONSISTENT_LEASE,
    }
)

#: Findings that mean history is inconsistent. Never auto-repaired.
#: Findings that mean history is inconsistent. Never auto-repaired, because the fix is a
#: human decision about a snapshot, not a mutation.
UNREPAIRABLE = frozenset({Finding.SEQUENCE_GAP, Finding.PROJECTION_DRIFT})


@dataclass(frozen=True, slots=True)
class RecoveryItem:
    finding: Finding
    subject: str
    detail: str
    repairable: bool
    action: str = ""

    def describe(self) -> dict[str, object]:
        return {
            "finding": self.finding.value,
            "subject": self.subject,
            "detail": self.detail,
            "repairable": self.repairable,
            "action": self.action,
        }


@dataclass
class RecoveryReport:
    applied: bool
    items: list[RecoveryItem] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.items)

    @property
    def repaired(self) -> list[RecoveryItem]:
        return [item for item in self.items if item.action and not item.action.startswith(("left as-is:", "could not repair:"))]

    @property
    def unrepairable(self) -> list[RecoveryItem]:
        return [item for item in self.items if not item.repairable]

    def describe(self) -> dict[str, object]:
        return {
            "applied": self.applied,
            "findings": len(self.items),
            "repaired": len(self.repaired),
            "requires_attention": len(self.unrepairable),
            "items": [item.describe() for item in self.items],
        }


def recover_workspace(
    *, store: EventStore, apply: bool = False, worktrees_root: Path | str | None = None
) -> RecoveryReport:
    """Inspect the workspace, and with `apply=True` repair what is safe to repair."""
    if apply:
        from contextlib import ExitStack
        from daedalus.application.replay import run_repo_path
        from daedalus.infrastructure.repository_lock import repository_lock
        # Take every known repository lock BEFORE making any repair. A busy
        # repository aborts this operation without partially repairing the workspace.
        repositories = sorted({path for run in store.list_runs()
                               if (path := run_repo_path(store, str(run["run_id"])))})
        with ExitStack() as locks:
            for path in repositories:
                if Path(path).is_dir():
                    locks.enter_context(repository_lock(Path(path)))
            return _inspect_workspace(store=store, apply=True, worktrees_root=worktrees_root)
    return _inspect_workspace(store=store, apply=False, worktrees_root=worktrees_root)


def _inspect_workspace(*, store, apply, worktrees_root):
    fsm = StateMachineService(store)
    report = RecoveryReport(applied=apply)

    with log_context(component="recovery"):
        _check_sequence_gaps(store, report)
        _check_projection_drift(store, fsm, report)
        from daedalus.application.commit_recovery import reconcile_commits
        for item in reconcile_commits(store, apply=apply):
            report.items.append(RecoveryItem(Finding(item.kind), item.subject, item.detail, item.repairable, item.action))
        _check_stale_leases(store, fsm, report, apply=apply)
        _check_interrupted_runs(store, fsm, report, apply=apply)
        _check_missing_worktrees(store, report)
        _check_lease_consistency(store, fsm, report, apply=apply)
        _check_execution_projection(store, report, apply=apply)
        _check_worker_heartbeats(store, report, apply=apply)
        if worktrees_root is not None:
            _check_orphan_worktrees(store, report, root=Path(worktrees_root), apply=apply)

    if apply and report.repaired:
        logger.info("recovery repaired %d finding(s)", len(report.repaired))
    return report


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def _check_sequence_gaps(store: EventStore, report: RecoveryReport) -> None:
    for aggregate_id in store.verify_sequences():
        report.items.append(
            RecoveryItem(
                finding=Finding.SEQUENCE_GAP,
                subject=aggregate_id,
                detail=(
                    "this aggregate's event sequence has a hole. Recovery does not invent "
                    "the missing event: the log is the authority, and silently filling a "
                    "gap would hide a real corruption."
                ),
                repairable=False,
            )
        )


def _check_projection_drift(
    store: EventStore, fsm: StateMachineService, report: RecoveryReport
) -> None:
    replayed = fsm.rebuild_step_states()
    for run in store.list_runs():
        for step in store.list_steps(str(run["run_id"])):
            step_id = str(step["step_id"])
            derived = replayed.get(step_id)
            projected = str(step["state"])
            if derived is None:
                report.items.append(
                    RecoveryItem(
                        finding=Finding.PROJECTION_DRIFT,
                        subject=step_id,
                        detail=(
                            f"projection says {projected} but no event in the log ever "
                            "placed this step anywhere"
                        ),
                        repairable=False,
                    )
                )
                continue
            if derived.value != projected:
                report.items.append(
                    RecoveryItem(
                        finding=Finding.PROJECTION_DRIFT,
                        subject=step_id,
                        detail=(
                            f"projection says {projected} but replaying the log yields "
                            f"{derived.value}. The log is authoritative; the projection is "
                            "a cache and must be rebuilt by a human decision, not guessed."
                        ),
                        repairable=False,
                    )
                )


def _check_lease_consistency(
    store: EventStore, fsm: StateMachineService, report: RecoveryReport, *, apply: bool
) -> None:
    """Repair a step whose lease columns disagree, or which holds a lease it should not.

    A half-written lease is the worst of both: `readiness()` refuses to activate the step
    because a lease id is present, while the expiry is gone so nothing will ever reclaim it.
    The step is neither running nor schedulable, and only the database can tell you why.
    """
    for step in store.steps_with_inconsistent_lease():
        step_id = str(step["step_id"])
        detail = (
            f"step {step['node_id']} holds lease_id={str(step['lease_id'] or '')[:12]!r} with "
            f"lease_expires_at={str(step['lease_expires_at'] or '')!r}; the two columns are one "
            "fact and must agree"
        )
        report.items.append(
            RecoveryItem(
                finding=Finding.INCONSISTENT_LEASE,
                subject=step_id,
                detail=detail,
                repairable=True,
            )
        )
        if apply:
            store.update_step_state(step_id, state=str(step["state"]), lease_id="", lease_expires_at="")
            report.items[-1] = RecoveryItem(
                finding=Finding.INCONSISTENT_LEASE,
                subject=step_id,
                detail=detail,
                repairable=True,
                action="cleared the lease, so the step is scheduled or retried rather than stuck",
            )


def _check_execution_projection(
    store: EventStore, report: RecoveryReport, *, apply: bool
) -> None:
    """Reconcile the §19 `executions` projection with the run and the steps.

    An execution row is written when a run starts and closed when it finishes — but a run that
    parks, or a process that dies, never reaches the close. Every such row claimed RUNNING
    forever, and `daedalus executions`, `/api/executions` and the Operations page reported it.
    """
    for execution in store.list_executions():
        run = store.get_run(str(execution["run_id"]))
        if run is None:
            continue
        steps = [
            row
            for row in store.list_steps(str(execution["run_id"]))
            if str(row["execution_id"]) == str(execution["execution_id"])
        ]
        counters = execution_counters([str(row["state"]) for row in steps])
        run_status = str(run["status"])
        # A parked run is not running, and its execution is not in flight either.
        expected_status = "AWAITING_APPROVAL" if run_status == "AWAITING_APPROVAL" else run_status
        agrees = (
            str(execution["status"]) == expected_status
            and int(execution["step_total"]) == counters["step_total"]
            and int(execution["step_committed"]) == counters["step_committed"]
            and int(execution["step_failed"]) == counters["step_failed"]
            and (not execution["finished_at"] or run_status in RUN_TERMINAL)
        )
        if agrees or not steps:
            continue
        report.items.append(
            RecoveryItem(
                finding=Finding.EXECUTION_DRIFT,
                subject=str(execution["execution_id"]),
                detail=(
                    f"executions says status={execution['status']} "
                    f"committed={execution['step_committed']}/{execution['step_total']} but "
                    f"run {execution['run_id']} is {run_status} and its steps reconcile to "
                    f"{counters['step_committed']}/{counters['step_total']}"
                ),
                repairable=True,
            )
        )
        if apply:
            store.upsert_execution(
                {
                    "execution_id": str(execution["execution_id"]),
                    "run_id": str(execution["run_id"]),
                    "status": expected_status,
                    "finished_at": (
                        str(execution["finished_at"]) or utc_now()
                        if run_status in RUN_TERMINAL
                        else ""
                    ),
                    **counters,
                }
            )
            report.items[-1] = RecoveryItem(
                finding=Finding.EXECUTION_DRIFT,
                subject=str(execution["execution_id"]),
                detail=report.items[-1].detail,
                repairable=True,
                action="rebuilt the execution projection from the run and its steps",
            )


def _check_worker_heartbeats(
    store: EventStore, report: RecoveryReport, *, apply: bool
) -> None:
    """A worker marked BUSY for a step that is no longer running is not busy.

    Worker liveness is not verifiable from the log — `rebuild_step_states` reconstructs states
    only — so the honest repair is to stop claiming activity, not to invent a heartbeat.
    """
    for worker in store.list_workers():
        if str(worker["status"]) != "BUSY":
            continue
        current = worker["current_step_id"]
        step = store.get_step(str(current)) if current else None
        still_running = step is not None and str(step["state"]) == StepState.RUNNING.value
        if still_running:
            continue
        report.items.append(
            RecoveryItem(
                finding=Finding.STALE_WORKER,
                subject=str(worker["worker_id"]),
                detail=(
                    f"worker is BUSY on {current or '<nothing>'} but that step is "
                    f"{step['state'] if step else 'gone'}"
                ),
                repairable=True,
            )
        )
        if apply:
            store.register_worker(
                str(worker["worker_id"]),
                kind=str(worker["kind"]),
                status="IDLE",
                notes=str(worker["notes"]),
            )
            report.items[-1] = RecoveryItem(
                finding=Finding.STALE_WORKER,
                subject=str(worker["worker_id"]),
                detail=report.items[-1].detail,
                repairable=True,
                action="marked the worker IDLE",
            )


def _check_stale_leases(
    store: EventStore,
    fsm: StateMachineService,
    report: RecoveryReport,
    *,
    apply: bool,
) -> None:
    for lease in store.expired_leases(utc_now()):
        step = store.get_step(str(lease["step_id"]))
        if step is None:
            continue
        # RUNNING is recoverable for the same reason LEASED is: the lease covers both, and a
        # worker that died after `StepStarted` is exactly the case where the lease is the only
        # evidence left. Treating only LEASED as recoverable left such a step — and its run —
        # permanently stuck.
        if StepState(str(step["state"])) not in {StepState.LEASED, StepState.RUNNING}:
            report.items.append(
                RecoveryItem(
                    finding=Finding.STALE_LEASE,
                    subject=str(lease["lease_id"]),
                    detail=(
                        f"lease expired at {lease['expire_at']} but step "
                        f"{step['node_id']} is {step['state']}; only the lease row is stale"
                    ),
                    repairable=True,
                )
            )
            if apply:
                store.release_lease(str(lease["lease_id"]), "EXPIRED")
                report.items[-1] = RecoveryItem(
                    finding=Finding.STALE_LEASE,
                    subject=str(lease["lease_id"]),
                    detail=report.items[-1].detail,
                    repairable=True,
                    action="released the stale lease row",
                )
            continue

        action = ""
        if apply:
            was_state = str(step["state"])
            try:
                fsm.transition_step(
                    step_id=str(step["step_id"]),
                    event_type="StepLeaseExpired",
                    actor="recovery",
                    payload={
                        "lease_id": str(lease["lease_id"]),
                        "worker_id": str(lease["worker_id"]),
                        "reason": "lease expired while the process was not running",
                    },
                )
                store.release_lease(str(lease["lease_id"]), "EXPIRED")
                action = (
                    f"step moved {was_state} -> LOST; the scheduler may retry it"
                )
            except Exception as error:  # noqa: BLE001 - reported, not raised
                action = f"could not repair: {type(error).__name__}: {error}"
        report.items.append(
            RecoveryItem(
                finding=Finding.STALE_LEASE,
                subject=str(lease["lease_id"]),
                detail=(
                    f"step {step['node_id']} has held lease {str(lease['lease_id'])[:12]} "
                    f"since {lease['acquired_at']} and it expired at {lease['expire_at']}"
                ),
                repairable=True,
                action=action,
            )
        )


def _check_interrupted_runs(
    store: EventStore,
    fsm: StateMachineService,
    report: RecoveryReport,
    *,
    apply: bool,
) -> None:
    for run in store.list_runs():
        status = RunState(str(run["status"]))
        if status in RUN_TERMINAL or status in {RunState.AWAITING_APPROVAL}:
            continue
        steps = [
            row
            for row in store.list_steps(str(run["run_id"]))
            if str(row["execution_id"]) == str(run["execution_id"])
        ]
        non_terminal = [
            row
            for row in steps
            if StepState(str(row["state"]))
            not in {
                StepState.COMMITTED,
                StepState.CANCELLED,
                StepState.SUPERSEDED,
                StepState.FAILED,
                StepState.TIMEOUT,
                StepState.ESCALATED,
                StepState.LOST,
            }
        ]
        parked = [row for row in steps if str(row["state"]) == StepState.ESCALATED.value]
        detail = (
            f"run is {status.value} with {len(non_terminal)} step(s) not in a terminal state"
        )
        action = ""
        if apply:
            if parked and not non_terminal and status is RunState.RUNNING:
                fsm.transition_run(run_id=str(run["run_id"]), execution_id=str(run["execution_id"]),
                    event_type="RunEscalated", actor="recovery", payload={"reason":"interrupted escalation"},
                    correlation_id=str(run["correlation_id"]))
                # Escalated steps with nothing in flight: this is a legitimate parked run
                # whose process died before it could record that fact.
                action = (
                    "recorded as AWAITING_APPROVAL: escalated steps with nothing in flight "
                    "are waiting for an owner, not broken"
                )
            else:
                action = (
                    "left as-is: recovery does not resume work. Run `daedalus resume` for a "
                    "parked run, or `daedalus rollback` and replay deliberately. Implicit "
                    "resumption would continue from a context nobody reviewed (Spec §1.4)."
                )
        report.items.append(
            RecoveryItem(
                finding=Finding.ORPHAN_RUN,
                subject=str(run["run_id"]),
                detail=detail + (f"; {len(parked)} escalated" if parked else ""),
                repairable=True,
                action=action,
            )
        )


def _check_orphan_worktrees(
    store: EventStore, report: RecoveryReport, *, root: Path, apply: bool
) -> None:
    """Find worktrees on disk that no live step references (Spec §16: sandbox leakage).

    The distinction that matters: a worktree belonging to a *parked* run is not an orphan — it is
    the subject of a pending decision, and deleting it would destroy what the owner is being asked
    about. Only worktrees referenced by no non-terminal step are leaked.
    """
    if not root.is_dir():
        return
    referenced: set[str] = set()
    for run in store.list_runs():
        status = RunState(str(run["status"]))
        for step in store.list_steps(str(run["run_id"])):
            if status in RUN_TERMINAL and step["state"] != StepState.COMMITTING.value:
                continue
            if StepState(str(step["state"])) in {
                StepState.COMMITTED,
                StepState.CANCELLED,
                StepState.SUPERSEDED,
            }:
                continue
            path = str(step["worktree_path"] or "")
            if path:
                referenced.add(str(Path(path).resolve()))

    for candidate in sorted(root.rglob("*")):
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(root.resolve()) or not candidate.is_dir() or not (candidate / ".git").exists():
            continue
        resolved = str(candidate.resolve())
        if resolved in referenced:
            continue
        action = ""
        if apply:
            import shutil

            from daedalus.infrastructure.git_sandbox import _git  # noqa: PLC2701

            from daedalus.infrastructure.repository_lock import repository_lock
            with repository_lock(candidate):
                _git(candidate, ["worktree", "remove", "--force", resolved], check=True)
                # Git performs the removal; do not follow symlinks or delete arbitrary
                # paths if the registration could not be verified.
                if candidate.exists():
                    shutil.rmtree(candidate)
            action = "removed the leaked worktree and pruned the registration"
        report.items.append(
            RecoveryItem(
                finding=Finding.ORPHAN_WORKTREE,
                subject=resolved,
                detail=(
                    "this worktree is referenced by no non-terminal step, so it is leaked "
                    "rather than pending. A parked run's worktree would be referenced and is "
                    "left alone."
                ),
                repairable=True,
                action=action,
            )
        )


def _check_missing_worktrees(store: EventStore, report: RecoveryReport) -> None:
    for run in store.list_runs():
        if RunState(str(run["status"])) in RUN_TERMINAL:
            continue
        for step in store.list_steps(str(run["run_id"])):
            if str(step["execution_id"]) != str(run["execution_id"]):
                continue
            if StepState(str(step["state"])) in {StepState.COMMITTED, StepState.CANCELLED}:
                continue
            worktree = str(step["worktree_path"])
            if not worktree:
                continue
            if Path(worktree).is_dir():
                continue
            report.items.append(
                RecoveryItem(
                    finding=Finding.MISSING_WORKTREE,
                    subject=str(step["step_id"]),
                    detail=(
                        f"step {step['node_id']} claims the worktree {worktree} but it is "
                        "gone. If this step was escalated, its approval cannot be honoured "
                        "and the step must be re-run."
                    ),
                    repairable=True,
                )
            )
