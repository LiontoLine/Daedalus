"""Gate outcome vocabulary.

Kept intentionally small. `GateDecision` is what the FSM consumes; `CheckResult` is
what a single Tier-1 check reports.
"""

from __future__ import annotations

from enum import Enum


class GateDecision(str, Enum):
    """The only decisions the gate may return (Spec §9.2)."""

    PASS = "PASS"
    APPROVE = "APPROVE"
    REVISE = "REVISE"
    FAIL = "FAIL"
    ESCALATE = "ESCALATE"

    @property
    def allows_commit(self) -> bool:
        return self in {GateDecision.PASS, GateDecision.APPROVE}
