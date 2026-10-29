"""Preflight: what isolation is actually in force on this host (Spec §7, §25).

Written because "we run in containers" is the kind of claim that is made from a design document
and never checked. This reports what the machine can do, what the current configuration would
select, and what is therefore *not* protected — in one command, from evidence it gathered by
actually probing.

It is also the honest answer to a security review: an assessor should be able to run one command
and see the gap rather than read a claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from daedalus.application.identity import OwnerRegistry
from daedalus.config import Settings
from daedalus.domain.spec import BoundarySpec, MetaSpec, NetworkPolicy
from daedalus.infrastructure.sandbox import (
    DriverRegistry,
    IsolationReport,
    isolation_documentation,
)


@dataclass(frozen=True, slots=True)
class PreflightReport:
    settings_summary: dict[str, object]
    drivers: tuple[IsolationReport, ...]
    selected: str
    selection_reason: str
    requested: str
    gaps: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)
    #: Spec §3.2 state, so a reviewer sees the approval control beside the isolation level.
    identity: dict[str, object] = field(default_factory=dict)

    @property
    def worst_gap(self) -> str:
        return self.gaps[0] if self.gaps else "none"

    def describe(self) -> dict[str, object]:
        return {
            "drivers": [report.describe() for report in self.drivers],
            "selected": self.selected,
            "selected_reason": self.selection_reason,
            "requested": self.requested,
            "gaps": list(self.gaps),
            "notes": list(self.notes),
            "settings": self.settings_summary,
            "identity": self.identity,
            "levels": isolation_documentation()["levels"],
        }


def run_preflight(
    settings: Settings, *, requested: str = "", store: Any = None
) -> PreflightReport:
    """Probe every driver, then report what the current configuration would select.

    `store` is optional: isolation probing needs no database, but the §3.2 identity report
    does. Without it the identity line is reported as unexamined rather than passed over.
    """
    policy = NetworkPolicy(settings.policy.network_policy)
    # A representative boundary: the shape a real task gets before SPEC-03 exists.
    boundary = BoundarySpec(
        boundary_id="PREFLIGHT",
        goal_id="PREFLIGHT",
        fs_whitelist=("src/**",),
        network_policy=policy,
        isolation=requested or "auto",
    )
    registry = DriverRegistry.default()
    reports = tuple(registry.probe_all(boundary))

    gaps: list[str] = []
    notes: list[str] = []
    identity_state: dict[str, object] = {}
    if store is not None:
        identity_state = OwnerRegistry(
            store=store, required=settings.identity.required
        ).describe()
    else:
        identity_state = {
            "examined": False,
            "note": "no workspace was supplied, so the §3.2 approval control was not checked",
        }
    try:
        choice = registry.select(boundary, requested=requested or "auto")
    except Exception as error:  # noqa: BLE001 - reported as the primary gap
        return PreflightReport(
            settings_summary=settings.describe(),
            drivers=reports,
            selected="none",
            selection_reason=str(getattr(error, "message", error)),
            requested=requested or "auto",
            gaps=(
                f"the requested isolation level is unavailable: "
                f"{getattr(error, 'message', error)}",
            ),
            notes=("no task can run until an available level is chosen",),
            identity=identity_state,
        )

    report = choice.report
    if not report.process_isolation.enforced:
        gaps.append(
            f"no process isolation: commands run as the service user with no namespace or "
            f"seatbelt ({report.driver})"
        )
    if not report.network.enforced:
        gaps.append(
            "network_policy is enforced at gate time only: a command can still open a socket "
            f"at runtime under {report.driver}"
        )
    if not report.filesystem.enforced:
        gaps.append(
            "filesystem limits are enforced before the write and by the gate, not by the "
            "kernel"
        )
    if not report.identity.enforced:
        gaps.append(
            "the command runs as the service user; no privilege drop is applied by the driver"
        )

    if not MetaSpec.default().protected_paths:
        gaps.append("the Meta-Spec protects no paths, which would allow self-modification")

    # Spec §3.2 is reported here for the same reason isolation is: it is a control that a
    # security reviewer should be able to ask the running system about, and an unenforced
    # control that is never mentioned reads as an enforced one.
    identity_enforced = bool(identity_state.get("enforced"))
    signers = int(identity_state.get("owners_enrolled") or 0)
    if store is not None and not identity_enforced:
        gaps.append(
            "spec approvals are not signature-verified: no owner is enrolled, so an "
            "approval is a name rather than evidence (Spec §3.2). Enrol owners with "
            "`daedalus owners add`."
        )
    elif settings.identity.required and signers == 0:
        gaps.append(
            "[identity] required = true but no enrolled owner can sign, so high-risk specs "
            "cannot be approved"
        )

    notes.append(
        "the control plane's own guarantees (FSM, gate, event log, worktrees, redaction) do "
        "not depend on the isolation level"
    )
    notes.append(
        "raise the level with `[policy] network_policy` and SPEC-03 `isolation`, or install a "
        "container runtime and re-run this command"
    )
    return PreflightReport(
        settings_summary=settings.describe(),
        drivers=reports,
        selected=report.driver,
        selection_reason=choice.reason,
        requested=requested or "auto",
        gaps=tuple(gaps),
        notes=tuple(notes),
        identity=identity_state,
    )
