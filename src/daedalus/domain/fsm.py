"""The authoritative step/run state machine (Spec §4).

This module is the *single* place allowed to declare what a legal transition is.
Nothing else in the codebase may write a step status directly: every mutation goes
`validate_precondition -> append_event -> persist_state -> emit_side_effect`
(Spec §4.2).

The table below is deliberately explicit and complete. `ILLEGAL_TRANSITIONS` names
the transitions we deliberately refuse, so the refusal is a tested contract rather
than an accident of a missing dict entry.
"""

from __future__ import annotations

from enum import Enum

from daedalus.errors import IllegalTransition


_TERMINAL: frozenset["StepState"] = frozenset()


class StepState(str, Enum):
    """Lifecycle of one DAG node execution (Spec §4.1)."""

    # Nominal path
    PENDING = "PENDING"
    READY = "READY"
    LEASED = "LEASED"
    RUNNING = "RUNNING"
    AWAITING_GATEKEEPER = "AWAITING_GATEKEEPER"
    TIER1_PASSED = "TIER1_PASSED"
    TIER2_REVIEWING = "TIER2_REVIEWING"
    APPROVED = "APPROVED"
    COMMITTING = "COMMITTING"
    COMMITTED = "COMMITTED"

    # Exception path
    FAILED = "FAILED"
    REVISE = "REVISE"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"
    STALE = "STALE"
    ESCALATED = "ESCALATED"
    TIMEOUT = "TIMEOUT"
    LOST = "LOST"

    # A Superseded step becomes eligible again on the new execution id only.
    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL


_TERMINAL = frozenset({StepState.COMMITTED, StepState.CANCELLED, StepState.SUPERSEDED})

# ---------------------------------------------------------------------------
# Outcome buckets
#
# Three separate components report "how many steps failed" — the executions projection, the
# metric summary and the per-worker counts — and they each grew their own set. They disagreed:
# one counted ESCALATED as failed and another did not, one omitted LOST, and one listed
# `"REJECTED"`, which is not a step state at all. The result was a row that could not
# reconcile (a PARTIAL_FAILURE run reporting zero failures) and three answers to one question.
#
# Defined here, next to the states themselves, so a new state forces a decision about which
# bucket it belongs to instead of silently falling outside all of them.
# ---------------------------------------------------------------------------

#: A step that ended without producing accepted work, for a reason that needs attention.
FAILED_STATES: frozenset[str] = frozenset(
    {
        StepState.FAILED.value,
        StepState.TIMEOUT.value,
        StepState.LOST.value,
        StepState.ESCALATED.value,
    }
)

#: A step that ended without producing work, for a reason that is nobody's fault: it was
#: cancelled, superseded by a newer spec, or invalidated because the plan moved.
NEUTRAL_STATES: frozenset[str] = frozenset(
    {
        StepState.CANCELLED.value,
        StepState.SUPERSEDED.value,
        StepState.STALE.value,
    }
)

#: The states in which a step legitimately holds a lease. Every other state must have both
#: lease columns empty: a lease is a claim that someone is working on this step right now.
LEASE_HOLDING_STATES: frozenset[str] = frozenset(
    {StepState.LEASED.value, StepState.RUNNING.value}
)

#: A step still able to progress. The complement of the two above plus COMMITTED.
UNSETTLED_STATES: frozenset[str] = frozenset(
    state.value for state in StepState
) - FAILED_STATES - NEUTRAL_STATES - {StepState.COMMITTED.value}


def execution_counters(states) -> dict[str, int]:
    """The one way to summarise a set of step states.

    Every counter derives from the same three buckets, so `total == committed + failed +
    neutral + unsettled` holds by construction and a caller cannot invent a fourth answer.
    """
    counted = [str(state) for state in states]
    return {
        "step_total": len(counted),
        "step_committed": sum(1 for s in counted if s == StepState.COMMITTED.value),
        "step_failed": sum(1 for s in counted if s in FAILED_STATES),
        "step_neutral": sum(1 for s in counted if s in NEUTRAL_STATES),
        "step_unsettled": sum(1 for s in counted if s in UNSETTLED_STATES),
    }


class RunState(str, Enum):
    """Lifecycle of one DAG run (one execution id over one frozen spec digest)."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    #: Spec §16: "Tier-2 ESCALATE -> freeze and wait for the Owner". A parked run keeps its
    #: worktrees and commits nothing further until a human answers.
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    PARTIAL_FAILURE = "PARTIAL_FAILURE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# ---------------------------------------------------------------------------
# Step transition table: (current_state, event_type) -> next_state
# ---------------------------------------------------------------------------

ALLOWED_TRANSITIONS: dict[tuple[StepState, str], StepState] = {
    # activation
    (StepState.PENDING, "StepActivated"): StepState.READY,
    # Spec §13.2: a step whose five digests all match an already-committed artifact may
    # reuse that result instead of re-executing. The destination is COMMITTED, but only
    # because the *same content* already passed the gate — `StateMachineService` refuses
    # a cache hit that does not name the source artifact and its gate result.
    (StepState.PENDING, "StepCacheHit"): StepState.COMMITTED,
    (StepState.READY, "StepCacheHit"): StepState.COMMITTED,
    # `StepExecutionFailed` is legal from every state that has not yet committed; the
    # destination is REVISE by default and the outcome may only push it to a *more*
    # terminal state (FAILED / TIMEOUT / ESCALATED). The table entry is the gate that
    # keeps this event away from COMMITTED, CANCELLED and SUPERSEDED.
    (StepState.PENDING, "StepExecutionFailed"): StepState.REVISE,
    (StepState.READY, "StepExecutionFailed"): StepState.REVISE,
    (StepState.LEASED, "StepExecutionFailed"): StepState.REVISE,
    (StepState.RUNNING, "StepExecutionFailed"): StepState.REVISE,
    (StepState.AWAITING_GATEKEEPER, "StepExecutionFailed"): StepState.REVISE,
    (StepState.TIER1_PASSED, "StepExecutionFailed"): StepState.REVISE,
    (StepState.TIER2_REVIEWING, "StepExecutionFailed"): StepState.REVISE,
    (StepState.APPROVED, "StepExecutionFailed"): StepState.REVISE,
    (StepState.REVISE, "StepExecutionFailed"): StepState.REVISE,
    (StepState.COMMITTING, "StepExecutionFailed"): StepState.REVISE,
    (StepState.LOST, "StepExecutionFailed"): StepState.REVISE,
    (StepState.STALE, "StepExecutionFailed"): StepState.REVISE,
    (StepState.ESCALATED, "StepExecutionFailed"): StepState.ESCALATED,
    # lease
    (StepState.READY, "StepLeaseAcquired"): StepState.LEASED,
    (StepState.LEASED, "StepStarted"): StepState.RUNNING,
    # Both leased and running steps can lose their lease. A worker that dies *after*
    # `StepStarted` never writes another event, so without the RUNNING edge the step — and the
    # run — could never leave RUNNING: not retryable, not terminal, recoverable only by
    # editing the database by hand. The lease is the liveness mechanism, and it has to cover
    # the whole time the lease is held.
    (StepState.LEASED, "StepLeaseExpired"): StepState.LOST,
    (StepState.RUNNING, "StepLeaseExpired"): StepState.LOST,
    # Gatekeeper pipeline
    (StepState.RUNNING, "StepGatekeeperEntered"): StepState.AWAITING_GATEKEEPER,
    (StepState.AWAITING_GATEKEEPER, "StepTier1Decided"): StepState.TIER1_PASSED,
    (StepState.TIER1_PASSED, "StepTier2Decided"): StepState.APPROVED,
    (StepState.APPROVED, "StepCommitRequested"): StepState.COMMITTING,
    (StepState.COMMITTING, "StepCommitted"): StepState.COMMITTED,
    # revise loop (bounded by the retry policy, never by the FSM)
    (StepState.REVISE, "StepLeaseAcquired"): StepState.LEASED,
    # recovery loop after a lost lease
    (StepState.LOST, "StepRecovered"): StepState.READY,
    # escalation resolution by a human
    #: RETRY: back to the queue with granted attempts.
    (StepState.ESCALATED, "StepRecovered"): StepState.READY,
    #: PROCEED: the owner accepted *this artifact*, so it goes straight to commit. The
    #: orchestrator refuses this transition unless an approval names the artifact digest.
    (StepState.ESCALATED, "StepApproved"): StepState.COMMITTING,
    #: REJECT: stop the step.
    (StepState.ESCALATED, "StepRejected"): StepState.CANCELLED,
    (StepState.ESCALATED, "StepCancelled"): StepState.CANCELLED,
    # spec drift invalidates an in-flight subject
    (StepState.READY, "StepMarkedStale"): StepState.STALE,
    (StepState.PENDING, "StepMarkedStale"): StepState.STALE,
    (StepState.STALE, "StepActivated"): StepState.READY,
    # explicit cancellation is legal from anything not yet committed
    (StepState.PENDING, "StepCancelled"): StepState.CANCELLED,
    (StepState.LEASED, "StepCancelled"): StepState.CANCELLED,
    (StepState.RUNNING, "StepCancelled"): StepState.CANCELLED,
    (StepState.AWAITING_GATEKEEPER, "StepCancelled"): StepState.CANCELLED,
    (StepState.TIER1_PASSED, "StepCancelled"): StepState.CANCELLED,
    (StepState.TIER2_REVIEWING, "StepCancelled"): StepState.CANCELLED,
    (StepState.APPROVED, "StepCancelled"): StepState.CANCELLED,
    (StepState.REVISE, "StepCancelled"): StepState.CANCELLED,
    (StepState.LOST, "StepCancelled"): StepState.CANCELLED,
    (StepState.FAILED, "StepCancelled"): StepState.CANCELLED,
    (StepState.TIMEOUT, "StepCancelled"): StepState.CANCELLED,
    # a new execution supersedes an uncommitted step from an older execution
    (StepState.PENDING, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.READY, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.LEASED, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.RUNNING, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.REVISE, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.FAILED, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.TIMEOUT, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.LOST, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.ESCALATED, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.STALE, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.AWAITING_GATEKEEPER, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.TIER1_PASSED, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.TIER2_REVIEWING, "StepSuperseded"): StepState.SUPERSEDED,
    (StepState.APPROVED, "StepSuperseded"): StepState.SUPERSEDED,
}

# Event types whose next state is carried in the event payload's `outcome` field
# rather than being determined by the current state alone.
OUTCOME_EVENTS = {
    "StepTier1Decided": {  # TIER1_PASSED handled separately; these are the negatives
        "fail": StepState.FAILED,
        "revise": StepState.REVISE,
        "escalate": StepState.ESCALATED,
    },
    "StepTier2Decided": {
        "approve": StepState.APPROVED,
        "revise": StepState.REVISE,
        "escalate": StepState.ESCALATED,
    },
    "StepExecutionFailed": {
        "revise": StepState.REVISE,
        "failed": StepState.FAILED,
        "timeout": StepState.TIMEOUT,
        "escalate": StepState.ESCALATED,
    },
}

RUN_TRANSITIONS: dict[tuple[RunState, str], RunState] = {
    (RunState.PENDING, "RunStarted"): RunState.RUNNING,
    (RunState.RUNNING, "RunStepCommitted"): RunState.RUNNING,
    (RunState.RUNNING, "RunStepFailed"): RunState.RUNNING,
    (RunState.RUNNING, "RunRebaseRequired"): RunState.RUNNING,
    # escalation parks the run instead of ending it; resume unparks it
    (RunState.RUNNING, "RunEscalated"): RunState.AWAITING_APPROVAL,
    (RunState.AWAITING_APPROVAL, "RunResumed"): RunState.RUNNING,
    (RunState.AWAITING_APPROVAL, "RunRolledBack"): RunState.CANCELLED,
    (RunState.AWAITING_APPROVAL, "RunCancelled"): RunState.CANCELLED,
    (RunState.AWAITING_APPROVAL, "RunCompleted"): RunState.COMPLETED,
    (RunState.AWAITING_APPROVAL, "RunPartiallyFailed"): RunState.PARTIAL_FAILURE,
    (RunState.AWAITING_APPROVAL, "RunFailed"): RunState.FAILED,
    (RunState.RUNNING, "RunCompleted"): RunState.COMPLETED,
    (RunState.RUNNING, "RunPartiallyFailed"): RunState.PARTIAL_FAILURE,
    (RunState.RUNNING, "RunFailed"): RunState.FAILED,
    (RunState.RUNNING, "RunCancelled"): RunState.CANCELLED,
    (RunState.PENDING, "RunCancelled"): RunState.CANCELLED,
    # Rollback (Spec §12.1) stops the affected execution; it never deletes anything. A
    # completed run may be rolled back too — that is the situation rollback exists for.
    (RunState.RUNNING, "RunRolledBack"): RunState.CANCELLED,
    (RunState.PENDING, "RunRolledBack"): RunState.CANCELLED,
    (RunState.COMPLETED, "RunRolledBack"): RunState.CANCELLED,
    (RunState.PARTIAL_FAILURE, "RunRolledBack"): RunState.CANCELLED,
    (RunState.FAILED, "RunRolledBack"): RunState.CANCELLED,
    (RunState.PARTIAL_FAILURE, "RunCompleted"): RunState.COMPLETED,
}

RUN_TERMINAL = frozenset(
    {RunState.COMPLETED, RunState.PARTIAL_FAILURE, RunState.FAILED, RunState.CANCELLED}
)

#: A parked run is not terminal: it is waiting to be answered.
RUN_PARKED = frozenset({RunState.AWAITING_APPROVAL})

# ---------------------------------------------------------------------------
# Explicitly refused transitions (Spec §4.3)
# ---------------------------------------------------------------------------

ILLEGAL_TRANSITIONS: frozenset[tuple[StepState, str]] = frozenset(
    {
        # A committed step is immutable history. Re-execution must create a NEW
        # execution id and replay, never overwrite (Spec §4.3, §12.1).
        (StepState.COMMITTED, "StepStarted"),
        (StepState.COMMITTED, "StepLeaseAcquired"),
        (StepState.COMMITTED, "StepActivated"),
        (StepState.COMMITTED, "StepCommitRequested"),
        (StepState.COMMITTED, "StepSuperseded"),
        (StepState.SUPERSEDED, "StepLeaseAcquired"),
        (StepState.CANCELLED, "StepLeaseAcquired"),
        (StepState.CANCELLED, "StepStarted"),
        # Gatekeeper may not be skipped on the way to commit.
        (StepState.RUNNING, "StepCommitRequested"),
        (StepState.AWAITING_GATEKEEPER, "StepCommitRequested"),
        (StepState.TIER1_PASSED, "StepCommitted"),
        (StepState.APPROVED, "StepCommitted"),
        # Tier-2 must never be reached before Tier-1 has passed (Spec §9.1).
        (StepState.RUNNING, "StepTier2Decided"),
        (StepState.AWAITING_GATEKEEPER, "StepTier2Decided"),
        (StepState.REVISE, "StepCommitted"),
        (StepState.FAILED, "StepCommitted"),
        # A failure report must never be able to reopen settled history. Without these
        # entries an outcome-carrying event could move a COMMITTED step back to REVISE,
        # which would defeat the whole point of making COMMITTED terminal.
        (StepState.COMMITTED, "StepExecutionFailed"),
        (StepState.CANCELLED, "StepExecutionFailed"),
        (StepState.SUPERSEDED, "StepExecutionFailed"),
        (StepState.COMMITTED, "StepTier1Decided"),
        (StepState.COMMITTED, "StepTier2Decided"),
        (StepState.CANCELLED, "StepTier1Decided"),
        (StepState.SUPERSEDED, "StepTier1Decided"),
        (StepState.CANCELLED, "StepTier2Decided"),
        (StepState.SUPERSEDED, "StepTier2Decided"),
    }
)


def resolve_transition(
    current: StepState,
    event_type: str,
    outcome: str | None = None,
) -> StepState:
    """Return the next state or raise `IllegalTransition`.

    `outcome` disambiguates events whose target depends on the decision payload
    (e.g. `StepTier2Decided` with `approve` vs `revise`).
    """
    if (current, event_type) in ILLEGAL_TRANSITIONS:
        raise IllegalTransition(
            f"Refusing illegal transition {current.value} -[{event_type}]-> : "
            "this transition is explicitly forbidden by the state machine",
            aggregate_id="",
            from_state=current.value,
            event_type=event_type,
        )

    if event_type in OUTCOME_EVENTS:
        # The declared table decides *whether* this event is acceptable from here; the payload
        # only decides *where* it lands. This guard is applied to every outcome-carrying event in
        # one place because it used to be written out three times and one copy was missing: only
        # `StepExecutionFailed` consulted the table, so `StepTier2Decided` with `approve` was
        # accepted from *any* state. A step sitting in READY could jump straight to APPROVED and
        # then commit — no Tier-1, no Tier-2 — and a step in FAILED or TIMEOUT could be reopened.
        # Anything the table does not declare for this (state, event) pair is refused before the
        # outcome is looked at, which is the only order that makes the table authoritative.
        if (current, event_type) not in ALLOWED_TRANSITIONS:
            raise IllegalTransition(
                f"Refusing illegal transition {current.value} -[{event_type}]-> : "
                "no such transition is declared, so the payload does not get to decide",
                aggregate_id="",
                from_state=current.value,
                event_type=event_type,
            )
        if event_type == "StepTier1Decided" and outcome == "pass":
            # `pass` is the one outcome the table maps to a *forward* state rather than a
            # negative one, so it is not in OUTCOME_EVENTS and is spelled here.
            return StepState.TIER1_PASSED
        return _outcome_state(event_type, outcome, current)

    try:
        return ALLOWED_TRANSITIONS[(current, event_type)]
    except KeyError:
        raise IllegalTransition(
            f"Refusing illegal transition {current.value} -[{event_type}]-> : "
            "no such transition is declared",
            aggregate_id="",
            from_state=current.value,
            event_type=event_type,
        ) from None


def _outcome_state(event_type: str, outcome: str | None, current: StepState) -> StepState:
    table = OUTCOME_EVENTS.get(event_type, {})
    if outcome is None or outcome not in table:
        raise IllegalTransition(
            f"Event {event_type} from {current.value} requires one of "
            f"{sorted(table)} but got outcome={outcome!r}",
            aggregate_id="",
            from_state=current.value,
            event_type=event_type,
        )
    return table[outcome]


def next_step_state(
    current: StepState | str,
    event_type: str,
    outcome: str | None = None,
) -> StepState:
    """String-friendly wrapper used by the event store."""
    return resolve_transition(StepState(current), event_type, outcome)


def resolve_run_transition(current: RunState | str, event_type: str) -> RunState:
    run_state = RunState(current)
    try:
        return RUN_TRANSITIONS[(run_state, event_type)]
    except KeyError:
        raise IllegalTransition(
            f"Refusing illegal run transition {run_state.value} -[{event_type}]->",
            aggregate_id="",
            from_state=run_state.value,
            event_type=event_type,
        ) from None
