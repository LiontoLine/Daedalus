"""Pure domain layer: state machine, specs, events, artifacts.

No I/O, no SQLite, no subprocess. This layer is the only place allowed to decide
whether a state transition is legal.
"""

from daedalus.domain.artifacts import Artifact
from daedalus.domain.events import Event, append_event_factory, new_event_id
from daedalus.domain.fsm import (
    ALLOWED_TRANSITIONS,
    ILLEGAL_TRANSITIONS,
    IllegalTransition,
    RunState,
    StepState,
    next_step_state,
)
from daedalus.domain.ids import new_id, stable_id, utc_now
from daedalus.domain.lease import Lease

__all__ = [
    "ALLOWED_TRANSITIONS",
    "ILLEGAL_TRANSITIONS",
    "Artifact",
    "Event",
    "IllegalTransition",
    "Lease",
    "RunState",
    "StepState",
    "append_event_factory",
    "new_event_id",
    "new_id",
    "next_step_state",
    "stable_id",
    "utc_now",
]
