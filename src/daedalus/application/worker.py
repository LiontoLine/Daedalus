"""Coding worker contract.

A worker is the untrusted execution plane's entry point. It receives a worktree, a
frozen subject digest and a budget, and returns a *candidate* — never a commit, never
a state change. The control plane decides what the candidate is worth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from daedalus.domain.artifacts import Artifact
from daedalus.domain.spec import PlanNode, SpecBundle
from daedalus.infrastructure.git_sandbox import GitSandbox


@dataclass(frozen=True, slots=True)
class WorkerContext:
    """Everything a worker is told. There is no ambient state to reach for."""

    step_id: str
    execution_id: str
    node: PlanNode
    bundle: SpecBundle
    base_commit: str
    attempt: int
    revision_feedback: str = ""
    input_artifacts: tuple[Artifact, ...] = ()

    @property
    def writable_paths(self) -> tuple[str, ...]:
        return tuple(self.bundle.boundary.fs_whitelist)


@dataclass
class WorkerResult:
    """What a worker produced. `ok=False` is a normal, expected outcome."""

    ok: bool
    summary: str = ""
    changed_files: tuple[str, ...] = ()
    execution_log: str = ""
    tokens_used: int = 0
    model: str = ""
    worker_id: str = ""
    error: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class CodingWorker(Protocol):
    name: str

    def implement(self, sandbox: GitSandbox, context: WorkerContext) -> WorkerResult: ...
