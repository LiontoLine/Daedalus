"""Driver selection (Spec §7.1).

Picking an isolation mechanism is a *policy* decision with a safety property: the system must
never quietly fall back to a weaker driver when the stronger one was requested. The rules:

* `auto` picks the strongest driver that is available **and** can honour the boundary's network
  policy. A driver that cannot honour the policy is not a candidate, because "isolated but
  able to reach the network anyway" is the failure mode this exists to prevent.
* An explicit request (`container`, `seatbelt`) that is unavailable is a **refusal**, not a
  downgrade. Falling back silently would mean an operator who asked for a container gets an
  unsandboxed process and never learns.
* Every decision carries the reason, and the reason is persisted with the run.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from daedalus.domain.spec import BoundarySpec, NetworkPolicy
from daedalus.errors import DaedalusError
from daedalus.infrastructure.sandbox.base import (
    STRENGTH,
    IsolationReport,
    SandboxDriver,
)
from daedalus.infrastructure.sandbox.container import ContainerDriver
from daedalus.infrastructure.sandbox.host import HostProcessDriver
from daedalus.infrastructure.sandbox.seatbelt import SeatbeltDriver


class IsolationUnavailable(DaedalusError):
    """The requested isolation mechanism cannot be provided on this host.

    Never auto-retried: no amount of re-running installs a container runtime, and silently
    downgrading to a weaker driver is exactly the outcome this error prevents.
    """

    code = "isolation_unavailable"


#: Named isolation levels a spec may request.
ISOLATION_LEVELS = ("auto", "host-process", "seatbelt", "container")


@dataclass(frozen=True, slots=True)
class DriverChoice:
    driver: SandboxDriver
    report: IsolationReport
    requested: str
    reason: str
    considered: tuple[tuple[str, bool, str], ...] = ()

    def describe(self) -> dict[str, object]:
        return {
            "requested": self.requested,
            "selected": self.report.driver,
            "reason": self.reason,
            "isolation": self.report.describe(),
            "considered": [
                {"driver": name, "available": available, "why": why}
                for name, available, why in self.considered
            ],
        }


@dataclass
class DriverRegistry:
    """The drivers this build knows about, in strength order."""

    drivers: dict[str, SandboxDriver] = field(default_factory=dict)

    @staticmethod
    def default(image: str = "") -> "DriverRegistry":
        container = ContainerDriver(**({"image": image} if image else {}))
        return DriverRegistry(
            drivers={
                "container": container,
                "seatbelt": SeatbeltDriver(),
                "host-process": HostProcessDriver(),
            }
        )

    def get(self, name: str) -> SandboxDriver:
        try:
            return self.drivers[name]
        except KeyError:
            raise IsolationUnavailable(
                f"unknown sandbox driver {name!r}; known: {sorted(self.drivers)}"
            ) from None

    def probe_all(self, boundary: BoundarySpec | None = None) -> list[IsolationReport]:
        reports: list[IsolationReport] = []
        for name in sorted(self.drivers, key=lambda n: -STRENGTH.get(n, -1)):
            driver = self.drivers[name]
            policy = boundary.network_policy if boundary else NetworkPolicy.DENY
            reports.append(_probe(driver, policy))
        return reports

    def select(
        self,
        boundary: BoundarySpec,
        *,
        requested: str = "auto",
    ) -> DriverChoice:
        """Pick a driver, or refuse. There is no silent downgrade."""
        wanted = (requested or "auto").strip().lower()
        if wanted not in ISOLATION_LEVELS:
            raise IsolationUnavailable(
                f"unknown isolation level {requested!r}; known: {list(ISOLATION_LEVELS)}"
            )

        considered: list[tuple[str, bool, str]] = []
        if wanted != "auto":
            driver = self.get(wanted)
            report = _probe(driver, boundary.network_policy)
            considered.append((wanted, report.available, report.detail))
            if not report.available:
                raise IsolationUnavailable(
                    f"isolation level {wanted!r} was requested but is unavailable: "
                    f"{report.detail}"
                    + (
                        " Missing: " + "; ".join(report.missing_prerequisites)
                        if report.missing_prerequisites
                        else ""
                    ),
                    requested=wanted,
                    missing=list(report.missing_prerequisites),
                )
            return DriverChoice(
                driver=driver,
                report=report,
                requested=wanted,
                reason=f"{wanted} was requested explicitly and is available",
                considered=tuple(considered),
            )

        # `auto`: strongest first, skipping anything that cannot honour the network policy.
        for name in sorted(self.drivers, key=lambda n: -STRENGTH.get(n, -1)):
            driver = self.drivers[name]
            report = _probe(driver, boundary.network_policy)
            considered.append((name, report.available, report.detail))
            if report.available:
                return DriverChoice(
                    driver=driver,
                    report=report,
                    requested="auto",
                    reason=(
                        f"{name} is the strongest available driver that can honour "
                        f"network_policy={boundary.network_policy.value}"
                    ),
                    considered=tuple(considered),
                )
        # The host-process driver is always available, so this is unreachable unless the
        # registry was built by hand without it.
        raise IsolationUnavailable(
            "no sandbox driver is available on this host; the host-process driver should "
            "always be present, so the registry is misconfigured",
            considered=[{"driver": n, "available": a, "why": w} for n, a, w in considered],
        )


def _probe(driver: SandboxDriver, policy: NetworkPolicy) -> IsolationReport:
    """Probe a driver, honouring its optional `probe_for_network` refinement."""
    refined = getattr(driver, "probe_for_network", None)
    if callable(refined):
        return refined(policy)
    return driver.probe()


def isolation_documentation() -> dict[str, object]:
    """A static description of each level, for `daedalus preflight` and the console."""
    return {
        "levels": {
            "host-process": {
                "code_isolation": "Git worktree per step",
                "process_isolation": "none",
                "filesystem": "enforced at gate time only",
                "network": "enforced at gate time only",
                "requires": "nothing",
                "honest_summary": (
                    "the weakest level. Fine for trusted, offline, low-risk tasks; do not "
                    "describe it as container isolation."
                ),
            },
            "seatbelt": {
                "code_isolation": "Git worktree per step",
                "process_isolation": "macOS Seatbelt (sandbox-exec)",
                "filesystem": "kernel-enforced allowlist",
                "network": "kernel-enforced deny (no domain allowlist)",
                "requires": "macOS with sandbox-exec permitted in this process context",
                "honest_summary": (
                    "real kernel enforcement with no installation. Cannot express a domain "
                    "allowlist, and Apple deprecates sandbox-exec, so it is probed at runtime."
                ),
            },
            "container": {
                "code_isolation": "Git worktree per step",
                "process_isolation": "container namespaces",
                "filesystem": "worktree as the only writable mount, read-only base image",
                "network": "--network none by default; an allowlist needs extra configuration",
                "requires": "a running docker or podman daemon",
                "honest_summary": (
                    "the strongest level. Verified by running `docker info`, so a CLI with no "
                    "daemon reports unavailable."
                ),
            },
        },
        "selection": (
            "`auto` picks the strongest available level that can honour the boundary's network "
            "policy. An explicit level that is unavailable is refused, never downgraded."
        ),
    }
