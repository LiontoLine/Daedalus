"""Alerting rules over persisted evidence (Spec §15, §25).

A dashboard nobody is watching is not observability. These rules turn the projections the
control plane already keeps into named, actionable conditions, so an operator can ask "is
anything wrong?" with one command instead of reading six tables.

Each rule states what it observed (with the numbers), why it matters, and what to do about it.

Two deliberate properties:

**Rules only read.** An alert engine that can mutate state becomes a second control plane, and
the value of this system is that there is exactly one. Remediation is always an explicit operator
command.

**No rule fires on missing data.** A metric that has never been recorded is not a pass and not a
failure. Silently treating "no data" as healthy is how a broken exporter looks like a healthy
system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from daedalus.application.recovery import recover_workspace
from daedalus.config import Settings
from daedalus.domain.fsm import RunState, StepState
from daedalus.infrastructure.store.event_store import EventStore


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "warning": 1, "critical": 2}[self.value]


@dataclass(frozen=True, slots=True)
class Alert:
    rule: str
    severity: Severity
    summary: str
    evidence: dict[str, object] = field(default_factory=dict)
    action: str = ""

    def describe(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "summary": self.summary,
            "evidence": dict(self.evidence),
            "action": self.action,
        }


@dataclass(frozen=True, slots=True)
class AlertReport:
    alerts: tuple[Alert, ...]
    evaluated: tuple[str, ...]
    skipped: tuple[str, ...] = ()

    @property
    def worst(self) -> Severity | None:
        return max((alert.severity for alert in self.alerts), key=lambda s: s.rank, default=None)

    @property
    def active(self) -> tuple[Alert, ...]:
        return tuple(alert for alert in self.alerts if alert.severity is not Severity.INFO)

    @property
    def healthy(self) -> bool:
        return not self.active

    def describe(self) -> dict[str, object]:
        return {
            "healthy": self.healthy,
            "worst": self.worst.value if self.worst else None,
            "count": len(self.alerts),
            "alerts": [alert.describe() for alert in self.alerts],
            "evaluated": list(self.evaluated),
            "skipped": list(self.skipped),
        }


@dataclass(frozen=True, slots=True)
class AlertThresholds:
    """Operator-tunable limits. Defaults assume a small deployment."""

    min_step_success_rate: float = 0.6
    max_retry_rate: float = 0.5
    max_gate_reject_rate: float = 0.5
    #: Below this many decisions, a rejection rate is noise rather than a signal.
    min_gate_decisions: int = 5
    max_token_usage_fraction: float = 0.9
    max_pending_escalations: int = 0
    #: A parked run older than this is probably forgotten rather than being considered.
    max_parked_minutes: int = 240
    max_hours_since_backup: int = 48
    max_orphan_runs: int = 0

    def describe(self) -> dict[str, object]:
        return dict(self.__dict__)


def evaluate_alerts(
    *,
    store: EventStore,
    settings: Settings,
    thresholds: AlertThresholds | None = None,
    include_recovery: bool = True,
) -> AlertReport:
    """Evaluate every rule against the current projections."""
    limits = thresholds or AlertThresholds()
    alerts: list[Alert] = []
    evaluated: list[str] = []

    metrics = store.metric_summary()
    evaluated.extend(
        [
            "step_success_rate",
            "retry_rate",
            "gate_reject_rate",
            "token_budget",
            "pending_escalations",
            "parked_runs",
            "backup_recency",
            "event_integrity",
        ]
    )

    _rule_step_success(metrics, limits, alerts)
    _rule_retry_rate(metrics, limits, alerts)
    _rule_gate_rejections(metrics, limits, alerts)
    _rule_token_budget(store, metrics, settings, limits, alerts)
    _rule_escalations(store, limits, alerts)
    _rule_parked_runs(store, limits, alerts)
    _rule_backup_recency(settings, limits, alerts)
    _rule_event_integrity(store, alerts)

    if include_recovery:
        evaluated.append("workspace_recovery")
        _rules_recovery(store, limits, alerts)

    return AlertReport(alerts=tuple(alerts), evaluated=tuple(evaluated))


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _rule_step_success(
    metrics: dict[str, object], limits: AlertThresholds, alerts: list[Alert]
) -> None:
    total = int(metrics.get("step_total", 0) or 0)
    if total == 0:
        return
    rate = float(metrics.get("step_success_rate", 0.0) or 0.0)
    if rate < limits.min_step_success_rate:
        alerts.append(
            Alert(
                rule="step_success_rate_low",
                severity=Severity.WARNING,
                summary=(
                    f"only {rate:.0%} of steps committed "
                    f"(threshold {limits.min_step_success_rate:.0%})"
                ),
                evidence={
                    "step_total": total,
                    "step_committed": metrics.get("step_committed"),
                    "step_failed": metrics.get("step_failed"),
                },
                action=(
                    "inspect the gate rejections with `daedalus audit`; a low rate usually means "
                    "the task statement or the acceptance criteria need revising, not the worker."
                ),
            )
        )


def _rule_retry_rate(
    metrics: dict[str, object], limits: AlertThresholds, alerts: list[Alert]
) -> None:
    total = int(metrics.get("step_total", 0) or 0)
    if total == 0:
        return
    rate = float(metrics.get("retry_rate", 0.0) or 0.0)
    if rate > limits.max_retry_rate:
        alerts.append(
            Alert(
                rule="retry_rate_high",
                severity=Severity.WARNING,
                summary=(
                    f"{rate:.0%} of steps needed more than one attempt "
                    f"(threshold {limits.max_retry_rate:.0%})"
                ),
                evidence={"step_total": total, "retry_rate": rate},
                action=(
                    "repeated retries usually mean the first attempt lacked information. Read the "
                    "REVISE feedback in the timeline."
                ),
            )
        )


def _rule_gate_rejections(
    metrics: dict[str, object], limits: AlertThresholds, alerts: list[Alert]
) -> None:
    decisions = int(metrics.get("gate_decisions", 0) or 0)
    if decisions < limits.min_gate_decisions:
        # Too few decisions for a rate to mean anything. Reporting one anyway would be noise
        # dressed up as signal.
        return
    rate = float(metrics.get("gate_reject_rate", 0.0) or 0.0)
    if rate > limits.max_gate_reject_rate:
        alerts.append(
            Alert(
                rule="gate_reject_rate_high",
                severity=Severity.WARNING,
                summary=(
                    f"{rate:.0%} of {decisions} gate decisions were rejections "
                    f"(threshold {limits.max_gate_reject_rate:.0%})"
                ),
                evidence={"gate_decisions": decisions, "gate_reject_rate": rate},
                action=(
                    "either the model's output quality dropped or the boundary is too narrow for "
                    "the task. Compare rejection reasons across runs."
                ),
            )
        )


def _rule_token_budget(
    store: EventStore,
    metrics: dict[str, object],
    settings: Settings,
    limits: AlertThresholds,
    alerts: list[Alert],
) -> None:
    budget = settings.quota.max_tokens_per_run
    if budget <= 0:
        return
    used = int(metrics.get("llm_token_usage", 0) or 0)
    if used == 0:
        return
    row = store.connection.execute("SELECT COUNT(*) AS n FROM runs").fetchone()
    run_count = max(1, int(row["n"]) if row else 1)
    per_run = used / run_count
    if per_run >= budget * limits.max_token_usage_fraction:
        alerts.append(
            Alert(
                rule="token_budget_nearly_exhausted",
                severity=Severity.WARNING,
                summary=(
                    f"average {per_run:.0f} tokens per run against a {budget} budget "
                    f"({per_run / budget:.0%})"
                ),
                evidence={
                    "total_tokens": used,
                    "runs": run_count,
                    "tokens_per_run": int(per_run),
                    "budget_per_run": budget,
                },
                action=(
                    "raise `quota.max_tokens_per_run` or narrow the task. A run that exhausts its "
                    "budget is refused rather than truncated, so it fails visibly."
                ),
            )
        )


def _rule_escalations(store: EventStore, limits: AlertThresholds, alerts: list[Alert]) -> None:
    pending: list[tuple[str, str]] = []
    for run in store.list_runs():
        for step in store.list_steps(str(run["run_id"])):
            if str(step["state"]) != StepState.ESCALATED.value:
                continue
            if store.latest_approval(str(step["step_id"])) is None:
                pending.append((str(run["run_id"]), str(step["node_id"])))
    if len(pending) > limits.max_pending_escalations:
        alerts.append(
            Alert(
                rule="escalations_pending",
                severity=Severity.WARNING,
                summary=f"{len(pending)} escalation(s) are waiting for an owner decision",
                evidence={"escalations": [{"run_id": r, "node": n} for r, n in pending[:10]]},
                action=(
                    "a parked run makes no progress. Answer it with `daedalus approve`, then "
                    "`daedalus resume`."
                ),
            )
        )


def _rule_parked_runs(store: EventStore, limits: AlertThresholds, alerts: list[Alert]) -> None:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    stale: list[dict[str, object]] = []
    for run in store.list_runs():
        if str(run["status"]) != RunState.AWAITING_APPROVAL.value:
            continue
        try:
            updated = datetime.fromisoformat(str(run["updated_at"]).replace("Z", "+00:00"))
        except ValueError:
            continue
        minutes = (now - updated).total_seconds() / 60
        if minutes > limits.max_parked_minutes:
            stale.append({"run_id": str(run["run_id"]), "parked_minutes": int(minutes)})
    if stale:
        alerts.append(
            Alert(
                rule="parked_runs_stale",
                severity=Severity.WARNING,
                summary=(
                    f"{len(stale)} run(s) have been parked longer than "
                    f"{limits.max_parked_minutes} minutes"
                ),
                evidence={"runs": stale[:10]},
                action=(
                    "a parked run holds a worktree and is work nobody has decided on. Answer it or "
                    "roll it back."
                ),
            )
        )


def _rule_backup_recency(settings: Settings, limits: AlertThresholds, alerts: list[Alert]) -> None:
    from datetime import UTC, datetime

    from daedalus.application.backup import list_backups

    backups = list_backups(settings.workspace)
    if not backups:
        alerts.append(
            Alert(
                rule="no_backup",
                severity=Severity.CRITICAL,
                summary="this workspace has never been backed up",
                evidence={"backups_path": str(settings.workspace.backups_path)},
                action=(
                    "run `daedalus backup` — a workspace with no snapshot has no recovery path."
                ),
            )
        )
        return
    newest = backups[0].get("created_at")
    if not newest:
        return
    try:
        created = datetime.fromisoformat(str(newest).replace("Z", "+00:00"))
    except ValueError:
        return
    hours = (datetime.now(UTC) - created).total_seconds() / 3600
    if hours > limits.max_hours_since_backup:
        alerts.append(
            Alert(
                rule="backup_stale",
                severity=Severity.WARNING,
                summary=(
                    f"the newest verified snapshot is {hours:.0f}h old "
                    f"(threshold {limits.max_hours_since_backup}h)"
                ),
                evidence={"newest_backup": backups[0].get("path"), "age_hours": int(hours)},
                action="run `daedalus backup`, and rehearse a restore.",
            )
        )


def _rule_event_integrity(store: EventStore, alerts: list[Alert]) -> None:
    broken = store.verify_sequences()
    if broken:
        alerts.append(
            Alert(
                rule="event_sequence_gap",
                severity=Severity.CRITICAL,
                summary=f"{len(broken)} aggregate(s) have a gap in the event sequence",
                evidence={"aggregates": broken[:10]},
                action=(
                    "the event log is the authority and it is inconsistent. Restore from a "
                    "snapshot; do not patch the gap."
                ),
            )
        )


def _rules_recovery(store: EventStore, limits: AlertThresholds, alerts: list[Alert]) -> None:
    report = recover_workspace(store=store, apply=False)
    unrepairable = report.unrepairable
    if unrepairable:
        alerts.append(
            Alert(
                rule="workspace_unrepairable",
                severity=Severity.CRITICAL,
                summary=(
                    f"{len(unrepairable)} workspace finding(s) cannot be repaired automatically"
                ),
                evidence={"findings": [item.describe() for item in unrepairable[:10]]},
                action=(
                    "these mean inconsistent history or a lost worktree. Inspect with `daedalus "
                    "recover`, and restore from a snapshot if the log is damaged."
                ),
            )
        )
    orphans = [item for item in report.items if item.finding.value == "orphan_run"]
    if len(orphans) > limits.max_orphan_runs:
        alerts.append(
            Alert(
                rule="orphan_runs",
                severity=Severity.WARNING,
                summary=f"{len(orphans)} run(s) are not in a terminal state",
                evidence={"runs": [item.subject for item in orphans[:10]]},
                action=(
                    "a parked run needs an owner decision (`daedalus escalations`); an "
                    "interrupted run needs `daedalus resume` or `daedalus rollback`."
                ),
            )
        )
