"""Alerting rules (Spec §15, §25).

Each rule is tested by *provoking* it, so a rule that can never fire is caught here rather than
during an incident. The threshold edge cases matter as much as the firing: a rule that fires on
insufficient data is noise, and noise is how real alerts get ignored.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from daedalus.application.alerting import (
    AlertThresholds,
    Severity,
    evaluate_alerts,
)
from daedalus.application.backup import create_backup
from daedalus.application.fsm_service import StateMachineService
from daedalus.config import WorkspaceSettings, load_settings
from daedalus.domain.fsm import StepState
from daedalus.infrastructure.store import EventStore


def _settings(tmp_path: Path, **overrides) -> object:
    settings = load_settings(None, workspace_root=str(tmp_path / "ws"), **overrides)
    settings.ensure_directories()
    return settings


def _store(settings) -> EventStore:  # noqa: ANN001
    return EventStore(settings.workspace.database_path)


def _rules(report) -> set[str]:  # noqa: ANN001
    return {alert.rule for alert in report.alerts}


def _project_run(store: EventStore, *, run_id: str, status: str, updated_at: str = "") -> None:
    stamp = updated_at or datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    store.project_run(
        {
            "run_id": run_id,
            "goal_id": "G",
            "execution_id": f"exec-{run_id}",
            "spec_digest": "spec",
            "status": status,
            "created_at": stamp,
            "updated_at": stamp,
        }
    )


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def test_a_fresh_workspace_with_a_backup_is_healthy(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    create_backup(settings.workspace, label="baseline")

    report = evaluate_alerts(store=store, settings=settings)
    assert report.healthy, report.describe()
    assert report.worst is None
    # Every rule must be accounted for: silently skipped rules look like passing ones.
    assert "step_success_rate" in report.evaluated
    assert "backup_recency" in report.evaluated
    store.close()


def test_no_data_is_not_treated_as_failure(tmp_path: Path) -> None:
    """A metric that was never recorded must not fire a rate rule."""
    settings = _settings(tmp_path)
    store = _store(settings)
    create_backup(settings.workspace)
    report = evaluate_alerts(store=store, settings=settings)
    assert "step_success_rate_low" not in _rules(report)
    assert "retry_rate_high" not in _rules(report)
    assert "token_budget_nearly_exhausted" not in _rules(report)
    store.close()


# ---------------------------------------------------------------------------
# Metric rules
# ---------------------------------------------------------------------------


def _with_steps(store: EventStore, *, committed: int, failed: int, retried: int = 0) -> None:
    _project_run(store, run_id="run-metrics", status="COMPLETED")
    index = 0
    for _ in range(committed):
        store.project_step(
            {
                "step_id": f"s-ok-{index}",
                "run_id": "run-metrics",
                "execution_id": "exec-run-metrics",
                "node_id": f"n-ok-{index}",
                "spec_digest": "spec",
                "state": StepState.COMMITTED.value,
                "attempt": 2 if index < retried else 1,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        )
        index += 1
    for _ in range(failed):
        store.project_step(
            {
                "step_id": f"s-bad-{index}",
                "run_id": "run-metrics",
                "execution_id": "exec-run-metrics",
                "node_id": f"n-bad-{index}",
                "spec_digest": "spec",
                "state": StepState.FAILED.value,
                "attempt": 1,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        )
        index += 1


def test_a_low_success_rate_fires(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    create_backup(settings.workspace)
    _with_steps(store, committed=1, failed=9)

    report = evaluate_alerts(store=store, settings=settings)
    assert "step_success_rate_low" in _rules(report)
    alert = next(a for a in report.alerts if a.rule == "step_success_rate_low")
    assert alert.severity is Severity.WARNING
    assert alert.evidence["step_total"] == 10
    assert alert.action
    store.close()


def test_a_high_retry_rate_fires(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    create_backup(settings.workspace)
    _with_steps(store, committed=4, failed=0, retried=4)

    report = evaluate_alerts(store=store, settings=settings)
    assert "retry_rate_high" in _rules(report)
    store.close()


def test_the_gate_rejection_rule_ignores_small_samples(tmp_path: Path) -> None:
    """Two rejections out of two is not a 100% problem, it is two data points."""
    settings = _settings(tmp_path)
    store = _store(settings)
    create_backup(settings.workspace)
    for index in range(2):
        store.record_gate_result(
            gate_result_id=f"g-{index}",
            step_id="s1",
            execution_id="e1",
            artifact_digest="a",
            tier=1,
            decision="REVISE",
            subject_digest="spec",
            reasons=["nope"],
            violations=[],
            confidence=None,
            evidence={},
        )
    assert "gate_reject_rate_high" not in _rules(
        evaluate_alerts(store=store, settings=settings)
    )

    for index in range(2, 10):
        store.record_gate_result(
            gate_result_id=f"g-{index}",
            step_id="s1",
            execution_id="e1",
            artifact_digest="a",
            tier=1,
            decision="REVISE",
            subject_digest="spec",
            reasons=["nope"],
            violations=[],
            confidence=None,
            evidence={},
        )
    assert "gate_reject_rate_high" in _rules(evaluate_alerts(store=store, settings=settings))
    store.close()


def test_the_gate_rejection_rule_respects_a_custom_threshold(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    create_backup(settings.workspace)
    for index in range(6):
        store.record_gate_result(
            gate_result_id=f"g-{index}",
            step_id="s1",
            execution_id="e1",
            artifact_digest="a",
            tier=1,
            decision="REVISE" if index < 3 else "PASS",
            subject_digest="spec",
            reasons=[],
            violations=[],
            confidence=None,
            evidence={},
        )
    strict = AlertThresholds(max_gate_reject_rate=0.4)
    lax = AlertThresholds(max_gate_reject_rate=0.6)
    assert "gate_reject_rate_high" in _rules(
        evaluate_alerts(store=store, settings=settings, thresholds=strict)
    )
    assert "gate_reject_rate_high" not in _rules(
        evaluate_alerts(store=store, settings=settings, thresholds=lax)
    )
    store.close()


def test_the_token_rule_fires_when_a_run_approaches_its_budget(tmp_path: Path) -> None:
    settings = _settings(tmp_path, max_tokens_per_run=1_000)
    store = _store(settings)
    create_backup(settings.workspace)
    _project_run(store, run_id="run-tokens", status="COMPLETED")
    store.record_metric(name="llm_tokens", value=900, run_id="run-tokens")

    report = evaluate_alerts(store=store, settings=settings)
    assert "token_budget_nearly_exhausted" in _rules(report)
    alert = next(a for a in report.alerts if a.rule == "token_budget_nearly_exhausted")
    assert alert.evidence["budget_per_run"] == 1_000
    store.close()


# ---------------------------------------------------------------------------
# Operational rules
# ---------------------------------------------------------------------------


def _escalate(store: EventStore, fsm: StateMachineService, *, run_id: str, step_id: str) -> None:
    fsm.declare_step(
        step_id=step_id,
        run_id=run_id,
        execution_id=f"exec-{run_id}",
        node_id="n1",
        spec_digest="spec",
        expected_artifacts=("a.py",),
    )
    fsm.transition_step(step_id=step_id, event_type="StepActivated", actor="t")
    fsm.transition_step(
        step_id=step_id,
        event_type="StepExecutionFailed",
        actor="t",
        outcome="escalate",
        execution_id=f"exec-{run_id}",
    )
    assert store.get_step(step_id)["state"] == StepState.ESCALATED.value


def test_a_pending_escalation_fires(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    create_backup(settings.workspace)
    fsm = StateMachineService(store)
    _project_run(store, run_id="run-esc", status="AWAITING_APPROVAL")
    _escalate(store, fsm, run_id="run-esc", step_id="run-esc:n1")

    report = evaluate_alerts(store=store, settings=settings)
    assert "escalations_pending" in _rules(report)
    alert = next(a for a in report.alerts if a.rule == "escalations_pending")
    assert alert.evidence["escalations"][0]["node"] == "n1"
    store.close()


def test_a_stale_parked_run_fires(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    create_backup(settings.workspace)
    old = (datetime.now(UTC) - timedelta(hours=10)).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    _project_run(store, run_id="run-parked", status="AWAITING_APPROVAL", updated_at=old)

    report = evaluate_alerts(store=store, settings=settings)
    assert "parked_runs_stale" in _rules(report)
    store.close()


def test_a_missing_backup_is_critical(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    report = evaluate_alerts(store=store, settings=settings)
    assert "no_backup" in _rules(report)
    assert report.worst is Severity.CRITICAL
    assert not report.healthy
    store.close()


def test_a_stale_backup_fires(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    backup = create_backup(settings.workspace)
    # Age the manifest rather than waiting two days.
    import json

    manifest = Path(backup.manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["created_at"] = (
        datetime.now(UTC) - timedelta(days=5)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    report = evaluate_alerts(store=store, settings=settings)
    assert "backup_stale" in _rules(report)
    store.close()


def test_an_event_sequence_gap_is_critical(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    create_backup(settings.workspace)
    for _ in range(2):
        store.append(
            aggregate_id="step:x",
            execution_id="e",
            event_type="AuditNote",
            actor="t",
            payload={},
        )
    store.connection.execute("UPDATE events SET sequence = 9 WHERE sequence = 2")

    report = evaluate_alerts(store=store, settings=settings)
    assert "event_sequence_gap" in _rules(report)
    assert report.worst is Severity.CRITICAL
    # And the recovery rules do not duplicate it as an unrepairable finding message.
    assert any(a.rule == "workspace_unrepairable" for a in report.alerts)
    store.close()


def test_the_report_serialises_for_a_monitoring_system(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    payload = evaluate_alerts(store=store, settings=settings).describe()
    assert set(payload) >= {"healthy", "worst", "count", "alerts", "evaluated"}
    assert isinstance(payload["alerts"], list)
    for alert in payload["alerts"]:
        assert set(alert) == {"rule", "severity", "summary", "evidence", "action"}
    store.close()
