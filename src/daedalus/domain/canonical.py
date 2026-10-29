"""JSON canonicalization and digest primitives (Spec §3.1).

A digest is only meaningful if the bytes it covers are deterministic. Every hash in
Daedalus goes through `canonical_json` so that key order, unicode escaping and
separators can never change the digest of semantically identical content.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

ALGORITHM = "sha256"


def canonical_json(value: Any) -> str:
    """RFC-8785-flavoured canonical form: sorted keys, no spaces, ASCII-safe."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def sha256_hex(payload: str | bytes) -> str:
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    return hashlib.sha256(data).hexdigest()


def digest_of(value: Any) -> str:
    """Digest of any JSON-serialisable value."""
    return sha256_hex(canonical_json(value))


def digest_of_bytes(value: bytes) -> str:
    return sha256_hex(value)


def digest_of_files(base: "object", relative_paths: list[str]) -> str:
    """Order-independent digest over a set of files.

    Used for the code-base / dependency / toolchain digests that gate artifact reuse
    (Spec §13.2). Returns a digest even when the set is empty.
    """
    from pathlib import Path

    root = Path(str(base))
    entries: list[dict[str, str]] = []
    for rel in sorted(relative_paths):
        path = root / rel
        if path.is_file():
            entries.append({"path": rel, "digest": sha256_hex(path.read_bytes())})
        else:
            entries.append({"path": rel, "digest": "<missing>"})
    return digest_of(entries)


def short(digest: str, length: int = 12) -> str:
    """Human-facing abbreviation. Never used as an identity."""
    return digest[:length] if digest else ""


def verify_digest(value: Any, expected: str) -> None:
    """Raise `SpecDigestMismatch` when the frozen subject moved."""
    from daedalus.errors import SpecDigestMismatch

    actual = digest_of(value)
    if actual != expected:
        raise SpecDigestMismatch(
            f"subject digest mismatch: expected {expected}, computed {actual}",
            expected=expected,
            actual=actual,
        )
