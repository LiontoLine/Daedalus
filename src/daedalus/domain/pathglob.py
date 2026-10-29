"""Glob matching for SPEC-03 filesystem boundaries.

Deliberately implemented here rather than with `fnmatch`/`pathlib.match`, because
`Path.match` treats `**` inconsistently across platforms and we cannot have a
security boundary that behaves differently on macOS and Linux.

Supported syntax:

    *    any run of characters except "/"
    ?    exactly one character except "/"
    **   any run of characters including "/" (only as a whole path segment)
"""

from __future__ import annotations

import re

_CACHE: dict[str, re.Pattern[str]] = {}


def _compile(pattern: str) -> re.Pattern[str]:
    cached = _CACHE.get(pattern)
    if cached is not None:
        return cached

    out: list[str] = ["^"]
    segments = pattern.split("/")
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            # `**/` may match zero segments, so it must not force a slash.
            out.append("(?:[^/]+/)*" if not last else ".*")
            continue
        out.append(_compile_segment(segment))
        if not last:
            out.append("/")
    out.append("$")
    compiled = re.compile("".join(out))
    _CACHE[pattern] = compiled
    return compiled


def _compile_segment(segment: str) -> str:
    pieces: list[str] = []
    for char in segment:
        if char == "*":
            pieces.append("[^/]*")
        elif char == "?":
            pieces.append("[^/]")
        else:
            pieces.append(re.escape(char))
    return "".join(pieces)


def normalize_path(path: str) -> str:
    """Repo-relative, forward-slash, no leading `./`, no `..` escape."""
    cleaned = path.replace("\\", "/").strip()
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip("/")
    parts: list[str] = []
    for part in cleaned.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def path_matches(pattern: str, path: str) -> bool:
    """True when `path` (repo-relative) is covered by `pattern`."""
    return bool(_compile(normalize_path(pattern)).match(normalize_path(path)))


def matches_any(patterns: list[str] | tuple[str, ...], path: str) -> bool:
    return any(path_matches(pattern, path) for pattern in patterns)


def glob_depth(pattern: str) -> int:
    """Number of literal path segments a pattern constrains (for diagnostics)."""
    return sum(1 for part in normalize_path(pattern).split("/") if part not in ("*", "**"))
