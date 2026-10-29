"""redact — secret redaction for anything that can leave the process.

Spec §8: secrets must never reach Git, event payloads, execution logs, LLM prompts
or artifacts. This module is the single choke point that makes that claim testable.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "***REDACTED***"

# A key name is secret when it *ends with* one of these, or contains one of the
# unambiguous multi-word markers below. Suffix matching rather than substring matching is
# deliberate: `tokens_used`, `max_tokens` and `token_budget` are ordinary metric names,
# and redacting them would hide real evidence while protecting nothing.
#: Suffixes that are secret-shaped on their own.
SECRET_KEY_SUFFIXES = (
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
    "_CREDENTIAL",
    "_CREDENTIALS",
    "_APIKEY",
)

#: Unambiguous markers: safe to match anywhere in the name. Note that a bare `_KEY`
#: suffix is deliberately NOT here: it would mask `reuse_key`, `cache_key`,
#: `idempotency_key` and `sort_key`, which are ordinary vocabulary. A credential is
#: named by a *concept* (`api_key`, `access_key`, `signing_key`), not by the word "key".
SECRET_NAME_MARKERS = (
    "API_KEY",
    "APIKEY",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "PUBLIC_KEY_PATH",
    "ACCESS_KEY",
    "SESSION_KEY",
    "SIGNING_KEY",
    "ENCRYPTION_KEY",
)

#: Bare names that are unambiguously a credential.
SECRET_EXACT_NAMES = frozenset(
    {
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "APIKEY",
        "AUTH",
        "BEARER",
    }
)

#: Names that look secret by suffix but are ordinary accounting vocabulary.
NON_SECRET_NAMES = frozenset(
    {
        "MAX_TOKENS",
        "MAX_TOKENS_PER_STEP",
        "MAX_TOKENS_PER_RUN",
        "TOTAL_TOKENS",
        "PROMPT_TOKENS",
        "COMPLETION_TOKENS",
        "LLM_TOKENS",
        "TOKENS_USED",
        "TOKEN_BUDGET",
        "TOKEN_COUNT",
        "TOKENS_PER_CHAR",
        "MAX_LLM_REQUESTS",
        "MONKEY",
        "KEY",
        "KEYFILE",
        # Ordinary identifiers that end in `_KEY` but name no credential.
        "REUSE_KEY",
        "CACHE_KEY",
        "IDEMPOTENCY_KEY",
        "SORT_KEY",
        "PRIMARY_KEY",
        "FOREIGN_KEY",
        "SHARD_KEY",
        "GROUP_KEY",
        "PARTITION_KEY",
        "LOOKUP_KEY",
    }
)

# Value-shaped patterns, applied even when the key name looks innocent.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{12,}")),
    (
        "key_value",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd|credential)\b\s*[:=]\s*"
            # A quoted literal remains credential-shaped even with punctuation.
            # An unquoted Python call/subscript is a computed value, not a
            # hard-coded credential. Requiring a complete bare value prevents
            # matching just `self._peek` in `token = self._peek()`.
            r"(?:[\"'][^\r\n\"']{8,}[\"']|"
            r"[^\s\"',;()\[\]{}]{8,}(?=$|[\s\"',;]))"
        ),
    ),
    (
        "url_credentials",
        re.compile(r"(?P<scheme>[a-z][a-z0-9+.\-]*)://[^/\s:@]+:[^/\s@]+@"),
    ),
)

def is_secret_key(name: str) -> bool:
    """True when an environment variable or payload key must be treated as secret.

    Precedence: explicit safe names win, then exact credential names, then unambiguous
    markers, then secret-shaped suffixes. The safe list exists so that metric and budget
    keys such as `tokens_used` are never masked — over-redaction silently destroys the
    audit trail this system exists to produce.
    """
    upper = name.upper().strip()
    if not upper or upper in NON_SECRET_NAMES:
        return False
    if upper in SECRET_EXACT_NAMES:
        return True
    if any(marker in upper for marker in SECRET_NAME_MARKERS):
        return True
    return upper.endswith(SECRET_KEY_SUFFIXES)


def redact_text(text: str) -> str:
    """Scrub value-shaped secrets from arbitrary text."""
    result = text
    for name, pattern in _PATTERNS:
        if name == "url_credentials":
            result = pattern.sub(lambda m: f"{m.group('scheme')}://{REDACTED}@", result)
        elif name == "bearer":
            result = pattern.sub(f"Bearer {REDACTED}", result)
        elif name == "key_value":
            result = pattern.sub(lambda m: f"{m.group(1)}={REDACTED}", result)
        else:
            result = pattern.sub(REDACTED, result)
    return result


def redact(value: Any, *, _key: str = "") -> Any:
    """Recursively redact a JSON-like structure.

    Keys whose *name* is secret have their value replaced wholesale, so a secret with
    an unrecognisable shape still never reaches a log or an event payload.
    """
    if isinstance(value, dict):
        return {
            str(key): (
                REDACTED if is_secret_key(str(key)) and item not in (None, "") else redact(item, _key=str(key))
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_env(environ: dict[str, str]) -> dict[str, str]:
    """Project an environment mapping into something safe to persist."""
    return {
        key: (REDACTED if is_secret_key(key) else redact_text(str(value)))
        for key, value in environ.items()
    }


def assert_clean(payload: Any, *, where: str) -> None:
    """Fail loudly if a supposedly-clean payload still contains a secret shape.

    Used by the tests and by the audit/artifact writers as a last line of defence.
    """
    text = repr(redact(payload))
    original = repr(payload)
    if REDACTED in text:
        return
    for name, pattern in _PATTERNS:
        if pattern.search(original):
            raise ValueError(f"unredacted secret ({name}) detected in {where}")
