"""Host-process driver: the Phase-1 behaviour, described honestly.

This driver does **not** claim process or network isolation, because it has none. It has code
isolation (a worktree), rlimits, a scrubbed environment and a wall-clock timeout, and the
report says exactly that. Most of the value of this file is the honesty: everything else in
the package is judged against it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from daedalus.domain.spec import BoundarySpec
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.infrastructure.process import resource_enforcement
from daedalus.infrastructure.sandbox.base import (
    Capability,
    CommandOutcome,
    IsolationReport,
)

NAME = "host-process"


@dataclass(frozen=True, slots=True)
class HostProcessDriver:
    """Runs the command directly, with rlimits and a scrubbed environment."""

    name: str = NAME
    #: Extra environment allowed through to the child. Never includes a credential.
    env_allowlist: tuple[str, ...] = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")

    def probe(self) -> IsolationReport:
        """Probe the rlimit mechanism by looking for the module that actually provides it.

        `os.setrlimit` does not exist — the API lives in `resource` — so checking `os` reported
        resource limits as unavailable on a platform where they work, which understated the
        isolation instead of overstating it. A capability probe that is wrong in either
        direction is useless, so this checks the real thing.
        """
        rlimit_available, rlimit_evidence = _probe_rlimits()
        return IsolationReport(
            driver=self.name,
            available=True,
            code_isolation=Capability(
                "worktree", True, "each step owns a Git worktree; the diff is its boundary"
            ),
            process_isolation=Capability(
                "none",
                False,
                "no namespace or seatbelt: a command could read anything the service user can",
            ),
            filesystem=Capability(
                "gate-time only",
                False,
                "SPEC-03 paths are enforced before the write and by the gate, not by the kernel",
            ),
            network=Capability(
                "gate-time only",
                False,
                "network_policy is checked on the diff and the command line, not at runtime",
            ),
            resource_limits=Capability(
                "rlimit + timeout",
                False,
                rlimit_evidence + "; partial: no task-wide memory, CPU rate or total disk quota",
            ),
            identity=Capability(
                "service user",
                False,
                "commands run as the service user; the driver does not drop privileges",
            ),
            detail=(
                "the weakest driver: code isolation and resource limits only. Use it where no "
                "stronger mechanism exists, and do not describe it as container isolation."
            ),
            missing_prerequisites=(
                "a container runtime for process/network isolation, or macOS sandbox-exec",
            ),
        )

    def run(
        self,
        *,
        worktree: Path,
        command: Sequence[str],
        timeout_sec: int,
        boundary: BoundarySpec,
        environment: dict[str, str] | None = None,
    ) -> CommandOutcome:
        sandbox = GitSandbox(
            repo_path=worktree,
            worktree_path=worktree,
            branch="",
            base_commit="",
            run_root=worktree.parent,
            _created=False,
        )
        started = time.monotonic()
        result = sandbox.run(
            list(command),
            timeout_sec=min(timeout_sec, boundary.max_runtime_sec),
            env_allowlist=self.env_allowlist,
            extra_env=environment,
            network=False,
            boundary=boundary,
        )
        return CommandOutcome(
            command=result.command,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=int((time.monotonic() - started) * 1000),
            timed_out=result.timed_out,
            driver=self.name,
            isolation={"network": "not enforced at runtime", "resources": resource_enforcement(),
                       "process_cleanup": "owned process group"},
        )

    def describe(self) -> dict[str, object]:
        return {"driver": self.name, "env_allowlist": list(self.env_allowlist), "resources": resource_enforcement()}


def _probe_rlimits() -> tuple[bool, str]:
    """Whether this host can bound a child's CPU, file size, descriptors and processes."""
    try:
        import resource
    except ImportError:
        return False, "the `resource` module is unavailable, so no rlimits can be applied"
    required = ("RLIMIT_CPU", "RLIMIT_NOFILE", "RLIMIT_FSIZE")
    missing = [name for name in required if not hasattr(resource, name)]
    if missing:
        return False, f"this platform lacks {missing}, so the resource boundary is partial"
    return True, (
        "RLIMIT_CPU/NOFILE/FSIZE plus wall-clock timeout; inherited uid process limit retained, no task PID cap"
    )
