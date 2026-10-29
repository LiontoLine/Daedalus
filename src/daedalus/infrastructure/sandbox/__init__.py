"""Sandbox drivers: code isolation and process isolation, kept distinct (Spec §7.1).

`GitSandbox` owns the code boundary; a driver owns the process boundary. Keeping them in
separate types is what stops the Phase-1 conflation of "a worktree" with "a sandbox".
"""

from daedalus.infrastructure.sandbox.base import (
    STRENGTH,
    Capability,
    CommandOutcome,
    IsolationReport,
    SandboxDriver,
)
from daedalus.infrastructure.sandbox.container import (
    ContainerDriver,
    ContainerRuntime,
    ContainerUnavailable,
)
from daedalus.infrastructure.sandbox.host import HostProcessDriver
from daedalus.infrastructure.sandbox.probe import (
    ISOLATION_LEVELS,
    DriverChoice,
    DriverRegistry,
    IsolationUnavailable,
    isolation_documentation,
)
from daedalus.infrastructure.sandbox.seatbelt import SeatbeltDriver

__all__ = [
    "ISOLATION_LEVELS",
    "STRENGTH",
    "Capability",
    "CommandOutcome",
    "ContainerDriver",
    "ContainerRuntime",
    "ContainerUnavailable",
    "DriverChoice",
    "DriverRegistry",
    "HostProcessDriver",
    "IsolationReport",
    "IsolationUnavailable",
    "SandboxDriver",
    "SeatbeltDriver",
    "isolation_documentation",
]
