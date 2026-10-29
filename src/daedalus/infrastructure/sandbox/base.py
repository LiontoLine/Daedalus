"""Sandbox driver contract and the isolation report (Spec §7).

The point of this abstraction is to stop conflating two different boundaries:

* **code isolation** — which files an attempt may touch, enforced by a Git worktree;
* **process isolation** — what a command may do, enforced by the OS.

Phase 1 had code isolation and only rlimits for process isolation, and the documentation said
so. This package makes the second boundary a pluggable, *probed* thing, so the system can use
the strongest mechanism the host actually supports instead of the one it was written against.

The rule that shapes everything here: **never report isolation that has not been verified.**
Every driver answers `probe()` by *trying* the mechanism, and `IsolationReport` carries both
what is in force and what is missing. A deployment that cannot run containers must be able to
see that it cannot, in one command, rather than inferring it from a document.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence

from daedalus.domain.spec import BoundarySpec
from daedalus.infrastructure.process import command_output_excerpt

#: Isolation strength, weakest to strongest. Used to pick a driver, never to claim one.
STRENGTH = {"host-process": 0, "seatbelt": 1, "container": 2}


@dataclass(frozen=True, slots=True)
class Capability:
    """One isolation property, and the evidence for it."""

    name: str
    enforced: bool
    evidence: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"enforced": self.enforced, "evidence": self.evidence}


@dataclass(frozen=True, slots=True)
class IsolationReport:
    """What a driver can actually do on this host, right now."""

    driver: str
    available: bool
    code_isolation: Capability
    process_isolation: Capability
    filesystem: Capability
    network: Capability
    resource_limits: Capability
    identity: Capability
    detail: str = ""
    missing_prerequisites: tuple[str, ...] = ()

    @property
    def capabilities(self) -> dict[str, Capability]:
        return {
            "code_isolation": self.code_isolation,
            "process_isolation": self.process_isolation,
            "filesystem": self.filesystem,
            "network": self.network,
            "resource_limits": self.resource_limits,
            "identity": self.identity,
        }

    @property
    def enforced_network_isolation(self) -> bool:
        return self.network.enforced

    def describe(self) -> dict[str, object]:
        return {
            "driver": self.driver,
            "available": self.available,
            "strength": STRENGTH.get(self.driver, -1),
            "capabilities": {
                name: capability.to_dict() for name, capability in self.capabilities.items()
            },
            "detail": self.detail,
            "missing_prerequisites": list(self.missing_prerequisites),
        }

    def summary_line(self) -> str:
        marks = "".join(
            ("+" if cap.enforced else "-") for cap in self.capabilities.values()
        )
        return f"{self.driver:<14} {'available' if self.available else 'unavailable':<12} {marks}"


class SandboxDriver(Protocol):
    """Runs one command on behalf of the control plane, with whatever isolation exists."""

    name: str

    def probe(self) -> IsolationReport: ...

    def run(
        self,
        *,
        worktree: Path,
        command: Sequence[str],
        timeout_sec: int,
        boundary: BoundarySpec,
        environment: dict[str, str] | None = None,
    ) -> "CommandOutcome": ...

    def describe(self) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    """The result of a sandboxed command, plus how it was isolated."""

    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    driver: str = ""
    isolation: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def combined(self, limit: int = 20_000) -> str:
        text = (self.stdout + ("\n" if self.stdout and self.stderr else "") + self.stderr).strip()
        return command_output_excerpt(text, limit)

    def to_command_result(self) -> object:
        """Adapt to the legacy `CommandResult` the gate already understands."""
        from daedalus.infrastructure.git_sandbox import CommandResult

        return CommandResult(
            command=self.command,
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
            duration_ms=self.duration_ms,
            timed_out=self.timed_out,
        )
