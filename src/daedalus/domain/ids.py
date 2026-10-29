"""Identifier and clock helpers.

Ids are lexicographically sortable (`<prefix>_<utc-ts>_<entropy>`) so an event
store ordered by id is also chronologically ordered.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime


def utc_now() -> str:
    """ISO-8601 UTC with second precision plus microseconds, always suffixed Z."""
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    """Sortable, collision-resistant id."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    return f"{prefix}_{stamp}_{secrets.token_hex(4)}"


def stable_id(prefix: str, *parts: str) -> str:
    """Deterministic id derived from inputs — used for reproducibility in the demo."""
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:16]}"
