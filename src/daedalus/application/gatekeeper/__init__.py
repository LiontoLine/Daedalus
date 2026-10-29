"""Gatekeeper: the two-tier gate between untrusted output and authoritative history.

Tier-1 is deterministic and mandatory. It is the reason a model cannot talk its way
into a commit: paths, diffs, syntax, lint, types, tests and artifacts are all checked
by code that the model cannot influence.

Tier-2 is *semantic review, not verification* (Spec §0.1, §9.2). It may only
downgrade or escalate a decision — it can never turn a Tier-1 failure into a pass.

The pipeline is fail-closed: any ambiguity, malformed reviewer output, timeout or
internal exception resolves to "do not commit".
"""

from __future__ import annotations

from daedalus.application.gatekeeper.pipeline import (
    GateDecision,
    GateOutcome,
    Gatekeeper,
)
from daedalus.application.gatekeeper.tier1 import (
    CheckResult,
    Tier1Gate,
    Tier1Report,
)
from daedalus.application.gatekeeper.tier2 import (
    ClientReviewer,
    SemanticReviewRequest,
    SemanticReviewer,
    SemanticReviewResult,
    Tier2Gate,
)

__all__ = [
    "CheckResult",
    "ClientReviewer",
    "GateDecision",
    "GateOutcome",
    "Gatekeeper",
    "SemanticReviewRequest",
    "SemanticReviewResult",
    "SemanticReviewer",
    "Tier1Gate",
    "Tier1Report",
    "Tier2Gate",
]
