"""The state machine is a contract, so test it as one (Spec §4, §28).

These tests are the executable form of "the system must refuse". A passing suite here
is what makes the claim "a model cannot overwrite history" checkable rather than
aspirational.
"""

from __future__ import annotations

import pytest

from daedalus.domain.fsm import (
    ALLOWED_TRANSITIONS,
    ILLEGAL_TRANSITIONS,
    OUTCOME_EVENTS,
    RunState,
    StepState,
    next_step_state,
    resolve_run_transition,
    resolve_transition,
)
from daedalus.errors import IllegalTransition, SpecDigestMismatch
from daedalus.application.fsm_service import StateMachineService
from daedalus.infrastructure.store import EventStore

NOMINAL_PATH = [
    ("StepActivated", None),
    ("StepLeaseAcquired", None),
    ("StepStarted", None),
    ("StepGatekeeperEntered", None),
    ("StepTier1Decided", "pass"),
    ("StepTier2Decided", "approve"),
    ("StepCommitRequested", None),
    ("StepCommitted", None),
]


def _declare(store: EventStore, spec_digest: str = "spec-a", step_id: str = "s1") -> StateMachineService:
    store.project_run(
        {
            "run_id": "run-1",
            "goal_id": "GOAL-1",
            "execution_id": "exec-1",
            "spec_digest": spec_digest,
            "status": "PENDING",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    )
    service = StateMachineService(store)
    service.declare_step(
        step_id=step_id,
        run_id="run-1",
        execution_id="exec-1",
        node_id="n1",
        spec_digest=spec_digest,
        expected_artifacts=("src/x.py",),
    )
    return service


def test_nominal_path_reaches_committed(tmp_path) -> None:
    with EventStore(tmp_path / "d.db") as store:
        service = _declare(store)
        for event_type, outcome in NOMINAL_PATH:
            service.transition_step(
                step_id="s1",
                event_type=event_type,
                actor="test",
                outcome=outcome,
                execution_id="exec-1",
            )
        assert store.get_step("s1")["state"] == StepState.COMMITTED.value


def test_committed_step_cannot_be_reopened(tmp_path) -> None:
    with EventStore(tmp_path / "d.db") as store:
        service = _declare(store)
        for event_type, outcome in NOMINAL_PATH:
            service.transition_step(
                step_id="s1",
                event_type=event_type,
                actor="test",
                outcome=outcome,
                execution_id="exec-1",
            )
        for event_type in ("StepStarted", "StepLeaseAcquired", "StepActivated", "StepSuperseded"):
            with pytest.raises(IllegalTransition):
                service.transition_step(
                    step_id="s1", event_type=event_type, actor="attacker", execution_id="exec-1"
                )


def test_gatekeeper_cannot_be_skipped(tmp_path) -> None:
    """A step may not jump from RUNNING to COMMITTING."""
    with EventStore(tmp_path / "d.db") as store:
        service = _declare(store)
        service.transition_step(step_id="s1", event_type="StepActivated", actor="test")
        service.transition_step(
            step_id="s1", event_type="StepLeaseAcquired", actor="test", execution_id="exec-1"
        )
        service.transition_step(
            step_id="s1", event_type="StepStarted", actor="test", execution_id="exec-1"
        )
        with pytest.raises(IllegalTransition):
            service.transition_step(
                step_id="s1", event_type="StepCommitRequested", actor="test", execution_id="exec-1"
            )


def test_tier2_cannot_be_reached_before_tier1(tmp_path) -> None:
    with EventStore(tmp_path / "d.db") as store:
        service = _declare(store)
        service.transition_step(step_id="s1", event_type="StepActivated", actor="test")
        service.transition_step(
            step_id="s1", event_type="StepLeaseAcquired", actor="test", execution_id="exec-1"
        )
        service.transition_step(
            step_id="s1", event_type="StepStarted", actor="test", execution_id="exec-1"
        )
        with pytest.raises(IllegalTransition):
            service.transition_step(
                step_id="s1",
                event_type="StepTier2Decided",
                actor="test",
                outcome="approve",
                execution_id="exec-1",
            )


def test_spec_drift_is_refused_before_the_fsm_decision(tmp_path) -> None:
    with EventStore(tmp_path / "d.db") as store:
        service = _declare(store)
        service.transition_step(step_id="s1", event_type="StepActivated", actor="test")
        with pytest.raises(SpecDigestMismatch):
            service.transition_step(
                step_id="s1",
                event_type="StepLeaseAcquired",
                actor="test",
                payload={"spec_digest": "spec-b"},
                execution_id="exec-1",
            )


def test_retry_loop_is_legal_and_bounded(tmp_path) -> None:
    """REVISE is re-leasable; an illegal re-entry after COMMITTED is not."""
    with EventStore(tmp_path / "d.db") as store:
        service = _declare(store)
        service.transition_step(step_id="s1", event_type="StepActivated", actor="test")
        service.transition_step(
            step_id="s1", event_type="StepLeaseAcquired", actor="test", execution_id="exec-1"
        )
        service.transition_step(
            step_id="s1", event_type="StepStarted", actor="test", execution_id="exec-1"
        )
        service.transition_step(
            step_id="s1",
            event_type="StepExecutionFailed",
            actor="test",
            outcome="revise",
            execution_id="exec-1",
        )
        assert store.get_step("s1")["state"] == StepState.REVISE.value
        service.transition_step(
            step_id="s1", event_type="StepLeaseAcquired", actor="test", execution_id="exec-1"
        )
        assert store.get_step("s1")["state"] == StepState.LEASED.value


def test_illegal_transitions_table_is_not_empty_and_is_enforced() -> None:
    assert ILLEGAL_TRANSITIONS, "the explicit refusal table must not be empty"
    for (state, event_type) in ILLEGAL_TRANSITIONS:
        with pytest.raises(IllegalTransition):
            next_step_state(state, event_type, "approve")


def test_outcome_event_requires_a_known_outcome() -> None:
    with pytest.raises(IllegalTransition):
        next_step_state(StepState.AWAITING_GATEKEEPER, "StepTier1Decided", "maybe")


def test_run_transitions_reject_illegal_moves() -> None:
    assert resolve_run_transition(RunState.PENDING, "RunStarted") is RunState.RUNNING
    with pytest.raises(IllegalTransition):
        resolve_run_transition(RunState.COMPLETED, "RunStarted")


def test_the_declared_table_is_authoritative_for_every_outcome_event() -> None:
    """No (state, event) pair outside `ALLOWED_TRANSITIONS` may ever be accepted.

    The guard that enforces this was written out three times and one copy was missing: only
    `StepExecutionFailed` consulted the table, so `StepTier2Decided` with `approve` was honoured
    from *any* state. Through the real service that meant:

        READY  -[StepTier2Decided/approve]-> APPROVED -[StepCommitRequested]-> COMMITTING
               -[StepCommitted]-> COMMITTED

    i.e. a step could commit with no Tier-1 and no Tier-2 — and `FAILED`/`TIMEOUT`/`LOST` could
    be reopened as APPROVED. This test walks every state against every outcome-carrying event and
    every one of its outcomes, so the next such event cannot be added without the guard.
    """
    offenders = []
    for state in StepState:
        for event, outcomes in OUTCOME_EVENTS.items():
            for outcome in (*outcomes, "pass", "approve"):
                try:
                    resolve_transition(state, event, outcome)
                except IllegalTransition:
                    continue
                if (state, event) not in ALLOWED_TRANSITIONS:
                    offenders.append(f"{state.value} -[{event}/{outcome}]-> accepted undeclared")
    assert not offenders, (
        "these transitions were accepted without being declared in ALLOWED_TRANSITIONS: "
        + "; ".join(offenders)
    )


@pytest.mark.parametrize(
    "state",
    [StepState.PENDING, StepState.READY, StepState.RUNNING, StepState.FAILED,
     StepState.TIMEOUT, StepState.LOST, StepState.ESCALATED, StepState.COMMITTED],
)
def test_the_gate_cannot_be_skipped_from_an_unrelated_state(state: StepState) -> None:
    """A gate decision may only be honoured from the state the gate runs in."""
    with pytest.raises(IllegalTransition):
        resolve_transition(state, "StepTier2Decided", "approve")
    with pytest.raises(IllegalTransition):
        resolve_transition(state, "StepTier1Decided", "pass")


def test_the_legal_gate_path_still_works() -> None:
    assert resolve_transition(
        StepState.AWAITING_GATEKEEPER, "StepTier1Decided", "pass"
    ) is StepState.TIER1_PASSED
    assert resolve_transition(
        StepState.TIER1_PASSED, "StepTier2Decided", "approve"
    ) is StepState.APPROVED
    assert resolve_transition(
        StepState.AWAITING_GATEKEEPER, "StepTier1Decided", "revise"
    ) is StepState.REVISE
    assert resolve_transition(
        StepState.TIER1_PASSED, "StepTier2Decided", "escalate"
    ) is StepState.ESCALATED
