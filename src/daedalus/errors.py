"""Typed error taxonomy.

Every error carries enough classification for the retry policy (Spec §17) to
decide automatically whether it is retryable without inspecting a message string.
"""

from __future__ import annotations

from enum import Enum


class ErrorClass(str, Enum):
    """Whether an error may be retried automatically."""

    RETRYABLE = "retryable"
    TERMINAL = "terminal"


class DaedalusError(Exception):
    """Base class for every Daedalus error."""

    error_class: ErrorClass = ErrorClass.TERMINAL
    code: str = "daedalus_error"

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def to_payload(self) -> dict[str, object]:
        return {
            "code": self.code,
            "error_class": self.error_class.value,
            "message": self.message,
            "context": dict(self.context),
        }


class RetryableInfrastructureError(DaedalusError):
    """Transient infrastructure faults: network blips, model timeouts, crashes."""

    error_class = ErrorClass.RETRYABLE
    code = "infrastructure_error"


class SpecError(DaedalusError):
    """Spec is missing, malformed, or fails its own schema contract."""

    code = "spec_error"


class SpecDigestMismatch(DaedalusError):
    """A frozen subject moved after it was approved. Never retried."""

    code = "spec_digest_mismatch"


class PlanGraphError(SpecError):
    """DAG is cyclic, has dangling deps or duplicate node ids."""

    code = "plan_graph_error"


class IllegalTransition(DaedalusError):
    """The FSM refused a transition. Never retried (Spec §4.3)."""

    code = "illegal_transition"

    def __init__(
        self,
        message: str,
        *,
        aggregate_id: str = "",
        from_state: str = "",
        event_type: str = "",
    ) -> None:
        super().__init__(
            message,
            aggregate_id=aggregate_id,
            from_state=from_state,
            event_type=event_type,
        )
        self.aggregate_id = aggregate_id
        self.from_state = from_state
        self.event_type = event_type


class SequenceConflict(DaedalusError):
    """Event store saw a gap in an aggregate's monotonic sequence (Spec §5.3)."""

    code = "sequence_conflict"


class BoundaryViolation(DaedalusError):
    """A write escaped the SPEC-03 fs whitelist, or a forbidden path was touched."""

    code = "boundary_violation"


class GateRejected(DaedalusError):
    """Deterministic (Tier-1) gate said no. Auto-retry of the same input is pointless."""

    code = "gate_rejected"


class LeaseError(DaedalusError):
    code = "lease_error"


class CommitConflict(DaedalusError):
    """Main branch moved under us. Requires REBASE_REQUIRED, never force-push."""

    code = "commit_conflict"


class QuotaExceeded(DaedalusError):
    code = "quota_exceeded"


class SpecValidationError(SpecError):
    """Tri-Spec failed schema or cross-spec validation."""

    code = "spec_validation_error"


class ArtifactMissing(DaedalusError):
    """A required artifact was not produced. Commit is not allowed (Spec §16)."""

    code = "artifact_missing"


class MetaSpecViolation(DaedalusError):
    """A change tried to touch a Meta-Spec protected path. Never auto-retried."""

    code = "meta_spec_violation"


class SchedulerError(DaedalusError):
    code = "scheduler_error"


class UnknownEventType(DaedalusError):
    code = "unknown_event_type"


class RollbackError(DaedalusError):
    code = "rollback_error"


class NotRollbackable(DaedalusError):
    """The run cannot be rolled back in its current state."""

    code = "not_rollbackable"


class SpecApprovalRequired(DaedalusError):
    """A high-risk spec needs an owner sign-off before it may run (Spec §3.2).

    Never auto-retried: no amount of re-running produces a human signature.
    """

    code = "spec_approval_required"


class ModelError(DaedalusError):
    """A model call failed in a way that is not worth retrying (bad request, bad output)."""

    code = "model_error"


class ModelResponseIncomplete(ModelError):
    """A response consumed usage but did not provide a complete visible answer."""

    code = "model_output_incomplete"


class ModelTimeout(RetryableInfrastructureError):
    code = "model_timeout"


class ModelUnavailable(RetryableInfrastructureError):
    code = "model_unavailable"


class ModelBudgetExceeded(QuotaExceeded):
    code = "model_budget_exceeded"

