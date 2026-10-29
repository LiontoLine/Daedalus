"""The release gate (Spec §22, §25, §28).

The gate exists because a checklist in a document is a list people tick without running. These
tests provoke each failure mode, so a gate that can never say no is caught here rather than at a
release.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from daedalus.application.backup import create_backup
from daedalus.application.release_gate import (
    CHECKLIST_COVERAGE,
    CheckStatus,
    checklist_coverage,
    run_release_gate,
)
from daedalus.config import EXAMPLE_CONFIG, load_settings, write_example_config
from daedalus.infrastructure.store import EventStore


def _settings(tmp_path: Path, **overrides):  # noqa: ANN202
    settings = load_settings(None, workspace_root=str(tmp_path / "ws"), **overrides)
    settings.ensure_directories()
    return settings


def _by_name(report, name: str):  # noqa: ANN001, ANN202
    return next(check for check in report.checks if check.name == name)


def _prepared(tmp_path: Path, **overrides) -> tuple[object, EventStore]:
    """A workspace with a live database and a verified snapshot.

    The store must exist before a backup can be taken: the database file is created when the
    store opens, not when the workspace directory is made.
    """
    settings = _settings(tmp_path, **overrides)
    store = EventStore(settings.workspace.database_path)
    create_backup(settings.workspace, label="test")
    return settings, store


def test_the_gate_fails_without_a_verified_snapshot(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with EventStore(settings.workspace.database_path) as store:
        report = run_release_gate(settings=settings, store=store, run_tests=False)
    assert not report.go
    check = _by_name(report, "verified_snapshot_exists")
    assert check.status is CheckStatus.FAIL
    assert check.remediation


def test_the_gate_passes_once_a_snapshot_exists(tmp_path: Path) -> None:
    settings, store = _prepared(tmp_path)
    with store:
        report = run_release_gate(settings=settings, store=store, run_tests=False)
    assert _by_name(report, "verified_snapshot_exists").status is CheckStatus.PASS
    assert _by_name(report, "event_log_integrity").status is CheckStatus.PASS
    assert _by_name(report, "self_modification_boundary").status is CheckStatus.PASS
    assert _by_name(report, "high_risk_requires_approval").status is CheckStatus.PASS
    assert _by_name(report, "network_default_deny").status is CheckStatus.PASS
    dependency = _by_name(report, "dependency_runtime_evidence")
    assert dependency.status is CheckStatus.SKIP
    assert "not attested" in dependency.detail
    assert not report.go


def test_the_gate_refuses_a_policy_that_would_auto_merge_critical(tmp_path: Path) -> None:
    settings = load_settings(None, workspace_root=str(tmp_path / "ws"))
    settings.ensure_directories()
    crippled = settings.__class__(
        workspace=settings.workspace,
        quota=settings.quota,
        execution=settings.execution,
        policy=settings.policy.__class__(manual_review_levels=("high",)),
        service=settings.service,
        providers=settings.providers,
    )
    store = EventStore(crippled.workspace.database_path)
    create_backup(crippled.workspace, label="test")
    with store:
        report = run_release_gate(settings=crippled, store=store, run_tests=False)
    check = _by_name(report, "high_risk_requires_approval")
    assert check.status is CheckStatus.FAIL
    assert "critical" in check.detail


def test_a_credential_in_a_model_field_is_refused_at_load_time(tmp_path: Path) -> None:
    """The first line of defence: the loader refuses it before anything runs."""
    from daedalus.config import ConfigError

    config = write_example_config(tmp_path / "daedalus.toml")
    text = config.read_text(encoding="utf-8")
    config.write_text(
        text.replace('model = "gpt-4o-mini"', 'model = "sk-abcdefghijklmnopqrstuvwxyz012345"'),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="looks like a credential"):
        load_settings(config, workspace_root=str(tmp_path / "ws"))


def test_the_gate_flags_a_suspicious_value_the_loader_accepted(tmp_path: Path) -> None:
    """The second line of defence: a value that is not obviously a key but looks like one.

    The loader cannot recognise every shape, so the gate also scans the file it loaded from.
    """
    config = tmp_path / "daedalus.toml"
    token = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
    # The value is valid for this field, so the loader accepts it — which is exactly why the
    # gate also scans the file it loaded from.
    config.write_text(
        f'[workspace]\nroot = "{tmp_path}/ws"\ntarget_branch = "{token}"\n',
        encoding="utf-8",
    )
    settings = load_settings(config)
    settings.ensure_directories()
    store = EventStore(settings.workspace.database_path)
    create_backup(settings.workspace, label="test")
    with store:
        report = run_release_gate(settings=settings, store=store, run_tests=False)
    check = _by_name(report, "no_credential_in_config")
    assert check.status is CheckStatus.FAIL
    assert "environment variable" in check.remediation


def test_the_gate_warns_about_the_isolation_gap_rather_than_passing_silently(
    tmp_path: Path,
) -> None:
    """Where the strongest isolation is unavailable, the gate must say so."""
    settings, store = _prepared(tmp_path)
    with store:
        report = run_release_gate(settings=settings, store=store, run_tests=False)
    check = _by_name(report, "process_isolation_available")
    assert check.status in {CheckStatus.PASS, CheckStatus.WARN}
    if check.status is CheckStatus.WARN:
        assert "process isolation" in check.detail
        assert check.remediation


def test_the_gate_fails_on_a_corrupt_event_log(tmp_path: Path) -> None:
    settings, store = _prepared(tmp_path)
    with store:
        for _ in range(2):
            store.append(
                aggregate_id="step:x",
                execution_id="e",
                event_type="AuditNote",
                actor="t",
                payload={},
            )
        store.connection.execute("UPDATE events SET sequence = 9 WHERE sequence = 2")
        report = run_release_gate(settings=settings, store=store, run_tests=False)
    # The backup was taken before the corruption, so the snapshot check still passes; the
    # integrity check must not.
    assert _by_name(report, "event_log_integrity").status is CheckStatus.FAIL
    assert not report.go


def test_skipping_the_tests_is_visible_and_not_silent(tmp_path: Path) -> None:
    settings, store = _prepared(tmp_path)
    with store:
        report = run_release_gate(settings=settings, store=store, run_tests=False)
    check = _by_name(report, "behavioural_test_suite")
    assert check.status is CheckStatus.SKIP
    assert "did not run" in check.detail
    assert check.remediation


def test_every_checklist_item_maps_to_an_executable_check() -> None:
    """An item with no mapping is an unverified claim."""
    coverage = checklist_coverage()
    assert set(coverage["checklist"]) == set(CHECKLIST_COVERAGE)
    for item, where in CHECKLIST_COVERAGE.items():
        assert where.strip(), f"{item} has no verification target"
    assert len(CHECKLIST_COVERAGE) >= 9


def test_the_report_serialises_with_remediation(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with EventStore(settings.workspace.database_path) as store:
        payload = run_release_gate(settings=settings, store=store, run_tests=False).describe()
    rendered = json.dumps(payload)
    assert set(payload) >= {"go", "version", "checks", "failures", "warnings", "skipped"}
    assert payload["go"] is False
    for check in payload["checks"]:
        assert set(check) == {
            "name", "category", "status", "detail", "evidence", "remediation"
        }
    assert "sk-" not in rendered


def test_production_cannot_go_with_warnings_or_skipped_checks(tmp_path):
    settings, store = _prepared(tmp_path)
    with store:
        report = run_release_gate(settings=settings, store=store, run_tests=False)
        diagnostic = run_release_gate(settings=settings, store=store, run_tests=False, mode="development")
    assert not report.go
    assert not report.describe()["production_ready"]
    assert "behavioural_test_suite" in report.describe()["blocking_checks"]
    assert "runtime_security_evidence" in report.describe()["blocking_checks"]
    assert diagnostic.mode == "development"
    assert not diagnostic.describe()["production_ready"]


def test_production_rejects_missing_check_names_even_when_all_present_checks_pass():
    from daedalus.application.release_gate import ReleaseGateReport, CheckResult
    assert not ReleaseGateReport(checks=()).go
    assert not ReleaseGateReport(checks=(CheckResult(name="anything", category="test", status=CheckStatus.PASS),)).go


def test_suite_with_skips_is_not_a_production_pass(tmp_path, monkeypatch):
    import subprocess
    from daedalus.application.release_gate import _check_test_suite
    (tmp_path / "tests").mkdir()
    def run(command, **kwargs):
        xml = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--junitxml=")))
        xml.write_text('<testsuites><testsuite><testcase name="runtime"><skipped/></testcase></testsuite></testsuites>')
        return subprocess.CompletedProcess(command, 0, stdout="1 skipped", stderr="")
    monkeypatch.setattr(subprocess, "run", run)
    report = _check_test_suite(tmp_path, timeout_sec=10)
    assert report.status is CheckStatus.WARN
    assert report.evidence["skipped"] == 1
