"""Acceptance tests for the demo target."""

from __future__ import annotations

import pytest

from example_project.textstats import average_word_length, summarize


def test_counts_words_not_characters() -> None:
    stats = summarize("the quick brown fox")
    assert stats["words"] == 4
    assert stats["characters"] == 19
    assert stats["lines"] == 1


def test_counts_lines() -> None:
    stats = summarize("alpha\nbeta\ngamma")
    assert stats["lines"] == 3
    assert stats["words"] == 3


def test_average_word_length_is_sane() -> None:
    # "abc de" -> 5 characters over 2 words
    assert average_word_length("abc de") == 2.5


def test_empty_input_is_handled() -> None:
    stats = summarize("")
    assert stats["words"] == 0
    assert average_word_length("") == 0.0
