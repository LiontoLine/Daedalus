"""Text statistics with a deliberate defect for the demo to find and fix."""

from __future__ import annotations


def summarize(text: str) -> dict[str, int]:
    """Return word/line/character counts for `text`.

    BUG (intentional): `words` counts characters rather than tokens, and
    `average_word_length` divides by zero on empty input.
    """
    tokens = text.split()
    return {
        "lines": len(text.splitlines()),
        "words": len(text),  # BUG: should be len(tokens)
        "characters": len(text),
    }


def average_word_length(text: str) -> float:
    """Mean length of a whitespace-separated token.

    BUG (intentional): counts the separators too, and divides by zero on empty input.
    The correct implementation is `len("".join(tokens)) / len(tokens)`.
    """
    stats = summarize(text)
    return stats["characters"] / stats["words"]
