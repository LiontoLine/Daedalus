"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from daedalus.infrastructure.git_sandbox import init_repo, initial_commit

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_PROJECT = REPO_ROOT / "examples" / "demo_project"

TARGET = "src/example_project/textstats.py"
TEST_COMMAND = "python3 -m pytest tests -q"

CORRECT_IMPLEMENTATION = '''"""Text statistics."""

from __future__ import annotations

#: Marker proving this file is the accepted version, not the fixture.
ACCEPTED_IMPLEMENTATION = True


def summarize(text: str) -> dict[str, int]:
    """Return word/line/character counts for `text`."""
    tokens = text.split()
    return {
        "lines": len(text.splitlines()),
        "words": len(tokens),
        "characters": len(text),
    }


def average_word_length(text: str) -> float:
    """Mean length of a whitespace-separated token."""
    tokens = text.split()
    if not tokens:
        return 0.0
    return len("".join(tokens)) / len(tokens)
'''

SYNTAX_ERROR_IMPLEMENTATION = '''"""Text statistics."""

from __future__ import annotations


def summarize(text: str) -> dict[str, int]:
    return {
        "lines": len(text.splitlines(
        "words": len(text.split()),
        "characters": len(text),
    }
'''


@pytest.fixture()
def git_repo(tmp_path: Path) -> Path:
    """A fresh checkout of the demo project, with caches excluded."""
    repo = init_repo(tmp_path / "target_repo")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".DS_Store")
    shutil.copytree(DEMO_PROJECT / "src", repo / "src", ignore=ignore)
    shutil.copytree(DEMO_PROJECT / "tests", repo / "tests", ignore=ignore)
    shutil.copy2(DEMO_PROJECT / "pyproject.toml", repo / "pyproject.toml")
    shutil.copy2(DEMO_PROJECT / ".gitignore", repo / ".gitignore")
    initial_commit(repo, "chore: import the demo project")
    return repo


@pytest.fixture()
def failing_tests_pass() -> bool:
    """True when the demo project's test command is actually runnable here."""
    try:
        completed = subprocess.run(
            ["python3", "-m", "pytest", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


@pytest.fixture(autouse=True)
def _no_real_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make retry backoff instant for the whole suite.

    The mechanism is real and is tested explicitly with a recording sleeper; what the suite must
    not do is spend 1s per retry, because several tests are about retries.
    """
    from daedalus.application import orchestrator as orchestrator_module

    monkeypatch.setattr(
        orchestrator_module, "_DEFAULT_SLEEPER", lambda _delay: None, raising=False
    )
