"""Immutable event contract (Spec §5.1).

An event is a fact that already happened. It is never updated, never deleted, and
never renumbered. `sequence` is monotonic per `aggregate_id`; a gap is a corruption
signal, not something to paper over (Spec §5.3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import new_id, utc_now

SCHEMA_VERSION = 1

EVENT_TYPES: frozenset[str] = frozenset(
    {
        # run lifecycle
        "RunCreated",
        "RunStarted",
        "RunStepCommitted",
        "RunStepFailed",
        "RunCompleted",
        "RunPartiallyFailed",
        "RunFailed",
        "RunCancelled",
        "RunRebaseRequired",
        "RunRolledBack",
        "RunEscalated",
        "RunResumed",
        # spec lifecycle
        "SpecRegistered",
        "SpecSuperseded",
        "SpecDriftDetected",
        "SpecApproved",
        # step lifecycle
        "StepDeclared",
        "StepActivated",
        "StepLeaseAcquired",
        "StepStarted",
        "StepGatekeeperEntered",
        "StepTier1Decided",
        "StepTier2Decided",
        "StepCommitRequested",
        "StepCommitted",
        "StepCacheHit",
        "StepApproved",
        "StepRejected",
        "ApprovalRecorded",
        "StepExecutionFailed",
        "StepLeaseExpired",
        "StepRecovered",
        "StepMarkedStale",
        "StepCancelled",
        "StepSuperseded",
        "IndependentValidationRequired",
        "IndependentValidationEvaluated",
        "IndependentValidationAttested",
        "DeliveryRequested",
        "DeliveryCompleted",
        "GoalAuditStarted",
        "GoalAuditCompleted",
        "GoalAuditEscalated",
        "GoalStageStarted",
        "GoalStageFinished",
        # audit side-channel
        "AuditNote",
        # intake lifecycle. The intake happens *before* any run exists, so these are recorded
        # on an `intake:<id>` aggregate with no execution — the same shape as a spec sign-off,
        # and for the same reason: the decision precedes the work it authorises.
        "IntakeQuestionsAsked",
        "IntakeAnswered",
        "IntakeSpecDerived",
        "IntakeFrozen",
        "IntakeAbandoned",
    }
)


@dataclass(frozen=True, slots=True)
class Event:
    """One immutable fact in the event store."""

    event_id: str
    aggregate_id: str
    execution_id: str
    sequence: int
    event_type: str
    actor: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION
    timestamp: str = field(default_factory=utc_now)
    correlation_id: str = ""
    causation_id: str = ""

    def __post_init__(self) -> None:
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event_type: {self.event_type!r}")
        if self.sequence < 1:
            raise ValueError(f"sequence must be >= 1, got {self.sequence}")
        if not self.aggregate_id:
            raise ValueError("aggregate_id is required")
        # `execution_id` is required for events that happen *inside* an execution, which is
        # where an unscoped event would be a real mistake: it would be invisible to the
        # per-execution audit queries that reconstruct what a run did.
        #
        # A spec event is not part of an execution. Registration and sign-off happen before
        # any run exists — that is the whole point of approving a high-risk spec first — so
        # `SpecApproved` is recorded on the `spec:` aggregate with no execution. Requiring an
        # id here forced callers to invent one, which is how the HTTP approval endpoint ended
        # up raising instead of recording anything at all.
        if not self.execution_id and not self.aggregate_id.startswith(("spec:", "intake:")):
            raise ValueError("execution_id is required")

    @property
    def is_spec_event(self) -> bool:
        """True for a spec-aggregate event, which belongs to no execution."""
        return self.aggregate_id.startswith("spec:")

    @property
    def step_id(self) -> str:
        """The step this event belongs to, or `""` for a run-level event.

        The aggregate id is `step:<step_id>` or `run:<run_id>`. Returning the run id for a
        run-level event makes every run-level row look like it belonged to a step whose id
        happens to equal the run id, which is exactly what an audit trail cannot afford.
        """
        prefix, separator, rest = self.aggregate_id.partition(":")
        return rest if separator and prefix == "step" else ""

    def digest(self) -> str:
        """Digest of the event body, excluding the surrogate event_id."""
        return digest_of(
            {
                "aggregate_id": self.aggregate_id,
                "execution_id": self.execution_id,
                "sequence": self.sequence,
                "event_type": self.event_type,
                "actor": self.actor,
                "payload": dict(self.payload),
                "schema_version": self.schema_version,
                "timestamp": self.timestamp,
                "correlation_id": self.correlation_id,
                "causation_id": self.causation_id,
            }
        )


def new_event_id() -> str:
    return new_id("evt")


def append_event_factory(
    *,
    aggregate_id: str,
    execution_id: str,
    sequence: int,
    event_type: str,
    actor: str,
    payload: Mapping[str, Any] | None = None,
    correlation_id: str = "",
    causation_id: str = "",
) -> Event:
    return Event(
        event_id=new_event_id(),
        aggregate_id=aggregate_id,
        execution_id=execution_id,
        sequence=sequence,
        event_type=event_type,
        actor=actor,
        payload=dict(payload or {}),
        correlation_id=correlation_id,
        causation_id=causation_id,
    )


def step_aggregate(step_id: str) -> str:
    return f"step:{step_id}"


def run_aggregate(run_id: str) -> str:
    return f"run:{run_id}"
