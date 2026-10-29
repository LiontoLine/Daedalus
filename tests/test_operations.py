"""Operator surfaces: recovery, backup/restore, configuration (Spec §15, §28).

These are the tests that separate "runs" from "operable". A control plane whose recovery
path is untested is a control plane whose recovery path does not work.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from daedalus.application.backup import (
    BackupError,
    create_backup,
    list_backups,
    restore_backup,
)
from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.fsm_service import StateMachineService
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.recovery import Finding, recover_workspace
from daedalus.application.scheduler import Quota
from daedalus.config import (
    ConfigError,
    EXAMPLE_CONFIG,
    Settings,
    load_settings,
    write_example_config,
)
from daedalus.domain.fsm import StepState
from daedalus.domain.spec import NetworkPolicy, RiskLevel
from daedalus.infrastructure.store import EventStore
from daedalus.infrastructure.store.schema import initialize_schema
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _completed_run(git_repo, tmp_path, *, db: Path | None = None):
    store = EventStore(db or (tmp_path / "ops.db"))
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="REQ-OPS",
            goal_id="GOAL-OPS",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),), worker_id="w-ops"
        ),
        quota=Quota(max_parallel_steps=1),
    )
    orchestrator.register_spec()
    return store, orchestrator.run(), bundle


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_defaults_are_usable_without_a_config_file() -> None:
    settings = load_settings(None, environ={})
    assert settings.workspace.target_branch == "main"
    assert settings.execution.park_on_escalation is True
    assert settings.policy.network_policy == "deny"


def test_example_config_round_trips(tmp_path: Path) -> None:
    path = write_example_config(tmp_path / "daedalus.toml")
    settings = load_settings(path, environ={})
    assert settings.quota.max_parallel_steps == 2
    assert settings.execution.max_attempts == 3
    assert sorted(settings.providers) == ["coder", "planner", "reviewer"]
    assert settings.provider("coder").api_key_env == "DAEDALUS_MODEL_API_KEY"
    # The shipped example must never contain a credential.
    assert "sk-" not in EXAMPLE_CONFIG
    assert "api_key = " not in EXAMPLE_CONFIG


def test_environment_beats_the_file(tmp_path: Path) -> None:
    path = write_example_config(tmp_path / "daedalus.toml")
    settings = load_settings(
        path,
        environ={"DAEDALUS_MAX_PARALLEL_STEPS": "5", "DAEDALUS_MODEL_NAME": "local-model"},
    )
    assert settings.quota.max_parallel_steps == 5
    assert settings.provider("coder").model == "local-model"


def test_explicit_argument_beats_the_environment(tmp_path: Path) -> None:
    path = write_example_config(tmp_path / "daedalus.toml")
    settings = load_settings(
        path, environ={"DAEDALUS_MAX_PARALLEL_STEPS": "5"}, max_parallel_steps=3
    )
    assert settings.quota.max_parallel_steps == 3


def test_unknown_keys_are_refused_not_ignored(tmp_path: Path) -> None:
    path = tmp_path / "daedalus.toml"
    path.write_text("[quota]\nmax_paralel_steps = 4\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown key"):
        load_settings(path, environ={})


def test_a_credential_in_the_config_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "daedalus.toml"
    path.write_text(
        '[model.coder]\nmodel = "sk-abcdefghijklmnopqrstuvwxyz012345"\n', encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="looks like a credential"):
        load_settings(path, environ={})


def test_bad_environment_values_fail_loudly(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="must be an integer"):
        load_settings(None, environ={"DAEDALUS_MAX_PARALLEL_STEPS": "lots"})
    with pytest.raises(ConfigError, match="must be a boolean"):
        load_settings(None, environ={"DAEDALUS_PARK_ON_ESCALATION": "maybe"})


def test_limits_are_enforced(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="fan-out"):
        load_settings(None, environ={"DAEDALUS_MAX_PARALLEL_STEPS": "64"})


def test_credential_presence_is_reported_without_echoing_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_example_config(tmp_path / "daedalus.toml")
    monkeypatch.setenv("DAEDALUS_MODEL_API_KEY", "sk-abcdefghijklmnopqrstuvwxyz012345")
    # `describe()` consults the real environment on purpose: it reports what this process
    # will actually be able to resolve, not what some earlier loader was told.
    described = load_settings(path, environ={}).describe()
    rendered = json.dumps(described)
    assert described["providers"]["coder"]["key_present"] is True
    # The value itself must never appear: only whether it is present.
    assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in rendered


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------


def test_recovery_reports_a_healthy_workspace_as_clean(git_repo, tmp_path) -> None:
    store, _result, _bundle = _completed_run(git_repo, tmp_path)
    report = recover_workspace(store=store, apply=False)
    assert not report.has_findings, report.describe()
    store.close()


def test_recovery_detects_and_repairs_a_stale_lease(git_repo, tmp_path) -> None:
    from datetime import UTC, datetime, timedelta

    store = EventStore(tmp_path / "lease.db")
    service = StateMachineService(store)
    store.project_run(
        {
            "run_id": "run-lease",
            "goal_id": "G",
            "execution_id": "exec-lease",
            "spec_digest": "spec",
            "status": "RUNNING",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    )
    service.declare_step(
        step_id="s1",
        run_id="run-lease",
        execution_id="exec-lease",
        node_id="n1",
        spec_digest="spec",
        expected_artifacts=(TARGET,),
    )
    from daedalus.application.scheduler import Scheduler
    from daedalus.domain.spec import BoundarySpec, GoalSpec, PlanNode, PlanSpec, MetaSpec

    plan = PlanSpec(
        plan_id="P",
        goal_id="G",
        nodes=(PlanNode(node_id="n1", expected_artifacts=(TARGET,)),),
    )
    scheduler = Scheduler(
        store=store,
        fsm=service,
        plan=plan,
        execution_id="exec-lease",
        run_id="run-lease",
    )
    scheduler.acquire_lease("s1", worker_id="w")
    past = (datetime.now(UTC) - timedelta(seconds=600)).isoformat().replace("+00:00", "Z")
    store.connection.execute("UPDATE leases SET expire_at = ?", (past,))
    store.connection.execute("UPDATE steps SET lease_expires_at = ?", (past,))

    dry = recover_workspace(store=store, apply=False)
    assert any(item.finding is Finding.STALE_LEASE for item in dry.items)
    assert store.get_step("s1")["state"] == StepState.LEASED.value, "a dry run must not mutate"

    applied = recover_workspace(store=store, apply=True)
    assert any(item.action for item in applied.items)
    assert store.get_step("s1")["state"] == StepState.LOST.value
    store.close()


def test_recovery_reports_a_sequence_gap_and_refuses_to_patch_it(tmp_path) -> None:
    store = EventStore(tmp_path / "gap.db")
    for _ in range(2):
        store.append(
            aggregate_id="step:s1",
            execution_id="exec-1",
            event_type="AuditNote",
            actor="t",
            payload={},
        )
    store.connection.execute("UPDATE events SET sequence = 9 WHERE sequence = 2")

    report = recover_workspace(store=store, apply=True)
    gaps = [item for item in report.items if item.finding is Finding.SEQUENCE_GAP]
    assert gaps
    assert not gaps[0].repairable
    assert not gaps[0].action, "recovery must not invent the missing event"
    assert store.verify_sequences() == ["step:s1"]
    store.close()


def test_recovery_reports_projection_drift_without_guessing(tmp_path) -> None:
    store = EventStore(tmp_path / "drift.db")
    service = StateMachineService(store)
    store.project_run(
        {
            "run_id": "r",
            "goal_id": "G",
            "execution_id": "e",
            "spec_digest": "s",
            "status": "RUNNING",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    )
    service.declare_step(
        step_id="s1", run_id="r", execution_id="e", node_id="n1", spec_digest="s",
        expected_artifacts=(TARGET,),
    )
    service.transition_step(step_id="s1", event_type="StepActivated", actor="t")
    store.update_step_state("s1", state=StepState.COMMITTED.value)

    report = recover_workspace(store=store, apply=True)
    drift = [item for item in report.items if item.finding is Finding.PROJECTION_DRIFT]
    assert drift
    assert not drift[0].repairable
    assert not drift[0].action
    store.close()


def test_recovery_does_not_silently_resume_interrupted_work(git_repo, tmp_path) -> None:
    store, result, _bundle = _completed_run(git_repo, tmp_path)
    store.update_run_status(result.run_id, "RUNNING")
    report = recover_workspace(store=store, apply=True)
    orphans = [item for item in report.items if item.finding is Finding.ORPHAN_RUN]
    assert orphans
    assert "does not resume work" in orphans[0].action or "AWAITING_APPROVAL" in orphans[0].action
    store.close()


# ---------------------------------------------------------------------------
# Backup and restore
# ---------------------------------------------------------------------------


def test_backup_verifies_the_copy_before_claiming_success(git_repo, tmp_path) -> None:
    from daedalus.config import WorkspaceSettings

    store, result, _bundle = _completed_run(git_repo, tmp_path, db=tmp_path / "ws" / "daedalus.db")
    workspace = WorkspaceSettings(root=str(tmp_path / "ws"))
    workspace.root_path.mkdir(parents=True, exist_ok=True)
    events = store.event_count()
    store.close()

    backup = create_backup(workspace, label="nightly")
    assert backup.verified
    assert backup.integrity == "ok"
    assert backup.sequence_ok
    assert backup.events == events
    assert Path(backup.database).is_file()
    assert Path(backup.manifest).is_file()

    listed = list_backups(workspace)
    assert len(listed) == 1
    assert listed[0]["verified"] is True


def test_backup_refuses_when_there_is_nothing_to_back_up(tmp_path) -> None:
    from daedalus.config import WorkspaceSettings

    workspace = WorkspaceSettings(root=str(tmp_path / "empty"))
    workspace.root_path.mkdir(parents=True, exist_ok=True)
    with pytest.raises(BackupError, match="no database"):
        create_backup(workspace)


def test_restore_moves_the_previous_database_aside(git_repo, tmp_path) -> None:
    from daedalus.config import WorkspaceSettings

    root = tmp_path / "ws"
    root.mkdir(parents=True, exist_ok=True)
    store, _result, _bundle = _completed_run(git_repo, tmp_path, db=root / "daedalus.db")
    store.close()
    workspace = WorkspaceSettings(root=str(root))
    backup = create_backup(workspace)

    # Mutate the live database so the restore is observable.
    connection = sqlite3.connect(str(root / "daedalus.db"))
    connection.execute("DELETE FROM events")
    connection.commit()
    connection.close()

    restored = restore_backup(workspace, source=backup.path, force=True)
    assert restored.verified
    assert restored.events > 0
    assert restored.previous_moved_to
    assert Path(restored.previous_moved_to).is_file(), "the old database is kept, not deleted"
    assert not (root / "daedalus.db.replaced-x").exists()


def test_restore_refuses_without_force(tmp_path) -> None:
    from daedalus.config import WorkspaceSettings

    root = tmp_path / "ws"
    root.mkdir(parents=True, exist_ok=True)
    (root / "daedalus.db").write_bytes(b"not a database")
    workspace = WorkspaceSettings(root=str(root))
    snapshot = tmp_path / "snap"
    snapshot.mkdir()
    (snapshot / "daedalus.db").write_bytes(b"also not a database")
    with pytest.raises(BackupError, match="does not verify"):
        restore_backup(workspace, source=str(snapshot), force=True)


def test_restore_refuses_a_corrupt_snapshot(git_repo, tmp_path) -> None:
    from daedalus.config import WorkspaceSettings

    root = tmp_path / "ws"
    root.mkdir(parents=True, exist_ok=True)
    store, _result, _bundle = _completed_run(git_repo, tmp_path, db=root / "daedalus.db")
    store.close()
    workspace = WorkspaceSettings(root=str(root))
    backup = create_backup(workspace)

    # Corrupt the snapshot's copy.
    Path(backup.database).write_bytes(b"garbage")
    with pytest.raises(BackupError, match="does not verify"):
        restore_backup(workspace, source=backup.path, force=True)


def test_a_v2_database_is_migrated_in_place(tmp_path) -> None:
    """An upgrade path must exist, because "recreate the database" loses the event log."""
    import sqlite3

    path = tmp_path / "v2.db"
    connection = sqlite3.connect(str(path))
    # A v2 database. `artifacts` is the table the v2 -> v3 step rewrites; `specs` and
    # `workers` are here because the v3 -> v4 step touches them, and a fixture that omits
    # tables the real v2 schema shipped would test a database nobody ever had.
    connection.execute(
        """
        CREATE TABLE artifacts (
            artifact_digest TEXT PRIMARY KEY, step_id TEXT NOT NULL, execution_id TEXT NOT NULL,
            parent_commit TEXT NOT NULL DEFAULT '', changed_files TEXT NOT NULL DEFAULT '[]',
            patch_digest TEXT NOT NULL DEFAULT '', spec_digest TEXT NOT NULL DEFAULT '',
            dependency_digest TEXT NOT NULL DEFAULT '', toolchain_digest TEXT NOT NULL DEFAULT '',
            code_base_digest TEXT NOT NULL DEFAULT '',
            input_artifact_digest TEXT NOT NULL DEFAULT '',
            execution_log_ref TEXT NOT NULL DEFAULT '', gate_result_ref TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '', worker_id TEXT NOT NULL DEFAULT '',
            sandbox_image TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
            document TEXT NOT NULL, created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE specs (
            spec_digest TEXT PRIMARY KEY, goal_id TEXT NOT NULL, spec_version INTEGER NOT NULL,
            parent_spec_digest TEXT NOT NULL DEFAULT '', owner_id TEXT NOT NULL DEFAULT '',
            risk_level TEXT NOT NULL, document TEXT NOT NULL,
            approved_by TEXT NOT NULL DEFAULT '', approved_at TEXT,
            signature TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE workers (
            worker_id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL,
            current_step_id TEXT, last_heartbeat_at TEXT, started_at TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT ''
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE executions (
            execution_id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
            parent_execution_id TEXT NOT NULL DEFAULT '', replay_from_commit TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL DEFAULT 'run', status TEXT NOT NULL DEFAULT 'PENDING',
            spec_digest TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '', step_total INTEGER NOT NULL DEFAULT 0,
            step_committed INTEGER NOT NULL DEFAULT 0, step_failed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE approvals (
            approval_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, step_id TEXT NOT NULL,
            execution_id TEXT NOT NULL, decision TEXT NOT NULL, approved_by TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '', artifact_digest TEXT NOT NULL DEFAULT '',
            subject_digest TEXT NOT NULL DEFAULT '', granted_attempts INTEGER NOT NULL DEFAULT 0,
            approval_digest TEXT NOT NULL, created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(f"PRAGMA user_version = 2")
    connection.commit()
    connection.close()

    from daedalus.infrastructure.store.schema import SCHEMA_VERSION

    store = EventStore(path)
    version = store.connection.execute("PRAGMA user_version").fetchone()[0]
    # Compared against the constant rather than a literal: a hardcoded number turns every
    # additive migration into a failing test, and the point of the assertion is "migrated
    # fully", not "migrated to whatever the version was when this test was written".
    assert int(version) == SCHEMA_VERSION, "the database must be migrated, not refused"
    columns = [row[1] for row in store.connection.execute("PRAGMA table_info(artifacts)")]
    assert "node_spec_digest" in columns
    spec_columns = [row[1] for row in store.connection.execute("PRAGMA table_info(specs)")]
    assert "approval_verified" in spec_columns
    approval_columns = [
        row[1] for row in store.connection.execute("PRAGMA table_info(approvals)")
    ]
    assert {"verified", "approval_scheme", "key_fingerprint"} <= set(approval_columns)
    tables = {
        row[0]
        for row in store.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"owners", "executions", "intakes"} <= tables
    store.close()
    # Running the migration again must be a no-op rather than a duplicate-column error: an
    # operator who hand-fixed a database must not be wedged by the upgrade path.
    again = sqlite3.connect(str(path))
    initialize_schema(again)
    assert again.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    again.close()


def test_a_newer_database_is_still_refused(tmp_path) -> None:
    """Refusing a newer file is the one case where refusing is right: we cannot guess forward."""
    import sqlite3

    path = tmp_path / "newer.db"
    connection = sqlite3.connect(str(path))
    connection.execute("PRAGMA user_version = 99")
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="newer than supported"):
        EventStore(path)


def test_an_unmigratable_version_names_the_problem(tmp_path) -> None:
    """A pre-migration development database must fail with an actionable message."""
    import sqlite3

    path = tmp_path / "v1.db"
    connection = sqlite3.connect(str(path))
    connection.execute("PRAGMA user_version = 1")
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="no migration path"):
        EventStore(path)


def test_migration_names_the_missing_table_instead_of_failing_obscurely() -> None:
    """A hand-modified database must be told what is wrong, not given `no such table`.

    Each migration step declares the tables its version always had. Discovering a missing one
    from an `OperationalError` raised inside a transaction, three frames down, tells an
    operator neither what is wrong nor what to do about it.
    """
    import sqlite3

    from daedalus.infrastructure.store.schema import initialize_schema

    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE artifacts (artifact_digest TEXT PRIMARY KEY)")
    connection.execute("PRAGMA user_version = 2")
    with pytest.raises(RuntimeError, match="missing") as error:
        initialize_schema(connection)
    message = str(error.value)
    assert "['specs', 'workers']" in message, message
    assert "restore" in message.lower(), message
    # Each migration step commits on its own, so the marker advances past the steps that
    # could be applied and stops at the one that could not — the next attempt resumes from
    # there instead of replaying work. What must not happen is a *half-applied* step, so the
    # assertion is that it stopped rather than reached the current version.
    from daedalus.infrastructure.store.schema import SCHEMA_VERSION

    marker = connection.execute("PRAGMA user_version").fetchone()[0]
    assert 2 <= marker < SCHEMA_VERSION, marker
    columns = [row[1] for row in connection.execute("PRAGMA table_info(artifacts)")]
    assert "node_spec_digest" in columns, "the step that could be applied should have been"
    connection.close()


def test_migration_recognises_a_statement_behind_a_comment() -> None:
    """Idempotency must not depend on a statement having no leading comment.

    The recognition is anchored at the start of the string, so a migration written with an
    explanatory comment first would silently lose idempotency — and the failure would only
    appear later, as a duplicate-column error, on exactly the hand-fixed database that
    idempotency exists to protect.
    """
    from daedalus.infrastructure.store.schema import _without_leading_comments

    statement = (
        "-- v7 adds a column, with a reason worth writing down\n"
        "/* and a block comment too */\n"
        "ALTER TABLE steps ADD COLUMN note TEXT NOT NULL DEFAULT ''"
    )
    assert _without_leading_comments(statement).startswith("ALTER TABLE")
    assert _without_leading_comments("ALTER TABLE steps ADD COLUMN x TEXT").startswith("ALTER")
    assert _without_leading_comments("-- only a comment").strip() == ""


# ---------------------------------------------------------------------------
# Spec §27: the audit must answer "which image?" and the logs must be correlatable
# ---------------------------------------------------------------------------


def test_the_audit_reports_the_sandbox_image(git_repo, tmp_path) -> None:
    """§27 asks "which image?" — the fact was recorded per artifact and reported nowhere.

    An audit that records a fact and never surfaces it answers the question with silence,
    which reads the same as "there was no image".
    """
    import json as _json

    from daedalus.application.coding_worker import FileOp, ScriptedWorker
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from daedalus.domain.spec import NetworkPolicy, RiskLevel
    from daedalus.infrastructure.store import EventStore
    from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

    store = EventStore(tmp_path / "audit.db")
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="REQ-AUD",
            goal_id="GOAL-AUD",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wta",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-aud",
        ),
    )
    orchestrator.register_spec()
    orchestrator.create_run()
    result = orchestrator.run()
    assert result.status == "COMPLETED"

    artifact = store.artifacts_for_step(str(store.list_steps(result.run_id)[0]["step_id"]))[0]
    # Recorded: the isolation driver actually used, named honestly (never a claimed container).
    assert artifact["sandbox_image"], "the artifact must record which image ran the work"
    assert artifact["toolchain_digest"], "and the toolchain it ran under"
    # And every field survives JSON, because that is how the audit and the export carry it.
    assert _json.loads(_json.dumps(dict(artifact)))["sandbox_image"] == artifact["sandbox_image"]
    store.close()


def test_the_logs_carry_every_field_spec_27_requires(git_repo, tmp_path) -> None:
    """§27: execution_id, step_id, event_id, worker_id, timestamp — in the log stream.

    The timeline projection records all of them per event, but an operator tailing logs needs
    the same correlation, and a line emitted while handling a transition is exactly when the
    event id is the thing you want to know.
    """
    import io
    import json as _json
    import logging

    from daedalus.application.coding_worker import FileOp, ScriptedWorker
    from daedalus.application.observability import configure_logging, log_context
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from daedalus.domain.spec import NetworkPolicy, RiskLevel
    from daedalus.infrastructure.store import EventStore
    from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

    buffer = io.StringIO()
    configure_logging(stream=buffer)
    store = EventStore(tmp_path / "logs.db")
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="REQ-LOG",
            goal_id="GOAL-LOG",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wtlg",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-log",
        ),
    )
    orchestrator.register_spec()
    orchestrator.create_run()
    with log_context(run_id=orchestrator.run_id, execution_id=orchestrator.execution_id):
        orchestrator.run()
    store.close()

    keys: set[str] = set()
    transitions: list[dict] = []
    for line in buffer.getvalue().splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = _json.loads(line)
        except ValueError:
            continue
        keys |= set(record)
        if record.get("logger") == "daedalus.fsm":
            transitions.append(record)

    for field in ("ts", "execution_id", "step_id", "event_id", "worker_id"):
        assert field in keys, f"Spec §27 requires {field!r} in the logs; saw {sorted(keys)}"
    assert transitions, "a transition must emit a line, or event_id can never appear"
    assert all(record.get("event_id") for record in transitions)
    logging.getLogger("daedalus").handlers.clear()
