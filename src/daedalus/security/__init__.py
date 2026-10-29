"""Security layer: boundary enforcement and the secret broker.

These modules are Meta-Spec protected. A task may not rewrite the policy that judges
it (Spec §21).
"""

from daedalus.security.boundary import (
    ALWAYS_DENIED_PATHS,
    FORBIDDEN_COMMAND_PATTERNS,
    BoundaryDecision,
    BoundaryGuard,
)

__all__ = [
    "ALWAYS_DENIED_PATHS",
    "FORBIDDEN_COMMAND_PATTERNS",
    "BoundaryDecision",
    "BoundaryGuard",
]
