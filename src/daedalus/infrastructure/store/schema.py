"""SQLite schema (Spec §18, §19).

Two classes of table live here and they must never be confused:

* **Event log** — `events`. Append-only, the authoritative record of *what happened*.
* **Projections** — `runs`, `steps`, `leases`, `specs`, `artifacts`, `gate_results`,
  `idempotency`. Derived, rebuildable from the event log, and the fast read path.

`PRAGMA user_version` carries the schema version, as in AgentPanelX. A database
written by a newer Daedalus is refused rather than silently misinterpreted.
"""

from __future__ import annotations

import re
import sqlite3

#: Task intakes: the front door. A row is written when a task is submitted, updated as the
#: operator answers the model's questions, and closed when it freezes a spec or is abandoned.
#: `questions` and `answers` are stored as the payloads the operator actually saw and clicked,
#: not as a re-derivation, because "why is the spec like this?" has to be answerable from the
#: record rather than from re-running a model that may answer differently today.
_INTAKES_TABLE = """
    CREATE TABLE IF NOT EXISTS intakes (
        intake_id TEXT PRIMARY KEY,
        repo_path TEXT NOT NULL,
        objective TEXT NOT NULL,
        model TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'QUESTIONING'
            CHECK (status IN ('QUESTIONING', 'DERIVED', 'FROZEN', 'ABANDONED')),
        questions TEXT NOT NULL DEFAULT '[]',
        answers TEXT NOT NULL DEFAULT '[]',
        rejections TEXT NOT NULL DEFAULT '[]',
        spec_digest TEXT NOT NULL DEFAULT '',
        run_id TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """

_INTAKES_INDEX = "CREATE INDEX IF NOT EXISTS intakes_created_idx ON intakes (created_at)"

SCHEMA_VERSION = 7

# --------------------------------------------------------------------------- v4 tables
# These live at module level and are referenced by *both* the initial schema and the
# migration, so a freshly created database and a migrated one cannot drift apart. A
# migration that rebuilds the event table would be data loss, but adding a new table or an
# additive column is safe and must be spelled once.

#: Owner registry (Spec §3.2). The signing secret is never here — only the name of the
#: environment variable that holds it and a fingerprint identifying which key is enrolled.
_OWNERS_TABLE = """
    CREATE TABLE IF NOT EXISTS owners (
        owner_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL DEFAULT 'viewer'
            CHECK (role IN ('viewer', 'operator', 'reviewer', 'owner')),
        secret_env TEXT NOT NULL DEFAULT '',
        key_fingerprint TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        revoked_at TEXT NOT NULL DEFAULT ''
    )
    """

#: One row per bounded execution (Spec §19). An `execution_id` was previously only a column
#: scattered across other tables, so "what was this execution?" had no single answer.
_EXECUTIONS_TABLE = """
    CREATE TABLE IF NOT EXISTS executions (
        execution_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        parent_execution_id TEXT NOT NULL DEFAULT '',
        replay_from_commit TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT 'run'
            CHECK (kind IN ('run', 'replay', 'resume', 'recovery')),
        status TEXT NOT NULL DEFAULT 'PENDING',
        spec_digest TEXT NOT NULL DEFAULT '',
        started_at TEXT NOT NULL DEFAULT '',
        finished_at TEXT NOT NULL DEFAULT '',
        step_total INTEGER NOT NULL DEFAULT 0,
        step_committed INTEGER NOT NULL DEFAULT 0,
        step_failed INTEGER NOT NULL DEFAULT 0,
        -- Cancelled/superseded/stale steps are neither committed nor failed. Without this the
        -- row could not reconcile: `PARTIAL_FAILURE` with zero failures was reachable.
        step_neutral INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """


_INITIAL_SCHEMA: tuple[str, ...] = (
    _INTAKES_TABLE,
    _INTAKES_INDEX,
    # ------------------------------------------------------------------ runs
    """
    CREATE TABLE runs (
        run_id TEXT PRIMARY KEY,
        goal_id TEXT NOT NULL,
        execution_id TEXT NOT NULL UNIQUE,
        spec_digest TEXT NOT NULL,
        parent_execution_id TEXT,
        replay_from_commit TEXT,
        status TEXT NOT NULL
            CHECK (status IN (
                'PENDING', 'RUNNING', 'AWAITING_APPROVAL', 'COMPLETED',
                'PARTIAL_FAILURE', 'FAILED', 'CANCELLED'
            )),
        base_commit TEXT NOT NULL DEFAULT '',
        worktree_path TEXT NOT NULL DEFAULT '',
        branch TEXT NOT NULL DEFAULT '',
        correlation_id TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX runs_goal_idx ON runs (goal_id, created_at)
    """,
    # ----------------------------------------------------------- spec registry
    """
    CREATE TABLE specs (
        spec_digest TEXT PRIMARY KEY,
        goal_id TEXT NOT NULL,
        spec_version INTEGER NOT NULL,
        parent_spec_digest TEXT NOT NULL DEFAULT '',
        owner_id TEXT NOT NULL DEFAULT '',
        risk_level TEXT NOT NULL
            CHECK (risk_level IN ('low', 'normal', 'high', 'critical')),
        document TEXT NOT NULL,
        approved_by TEXT NOT NULL DEFAULT '',
        approved_at TEXT,
        signature TEXT NOT NULL DEFAULT '',
        -- v4 (Spec §3.2): whether the sign-off was *verified* against a registered owner,
        -- and by which primitive. An approval that predates the machinery is marked 0
        -- rather than assumed good. These four columns are also added by MIGRATIONS[3];
        -- a column cannot be shared between the two paths, unlike a whole table.
        approval_verified INTEGER NOT NULL DEFAULT 0,
        approval_scheme TEXT NOT NULL DEFAULT '',
        approval_role TEXT NOT NULL DEFAULT '',
        approval_fingerprint TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX specs_goal_idx ON specs (goal_id, spec_version)
    """,
    # ------------------------------------------------------------------ steps
    """
    CREATE TABLE steps (
        step_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        objective TEXT NOT NULL DEFAULT '',
        intent TEXT NOT NULL DEFAULT '',
        deps TEXT NOT NULL DEFAULT '[]',
        expected_artifacts TEXT NOT NULL DEFAULT '[]',
        allowed_tools TEXT NOT NULL DEFAULT '[]',
        state TEXT NOT NULL,
        attempt INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 3,
        timeout_sec INTEGER NOT NULL DEFAULT 300,
        spec_digest TEXT NOT NULL,
        base_commit TEXT NOT NULL DEFAULT '',
        lease_id TEXT,
        worker_id TEXT,
        lease_expires_at TEXT,
        revision_of TEXT NOT NULL DEFAULT '',
        last_failure TEXT NOT NULL DEFAULT '',
        granted_attempts INTEGER NOT NULL DEFAULT 0,
        worktree_path TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (run_id, node_id, execution_id)
    )
    """,
    """
    CREATE INDEX steps_run_state_idx ON steps (run_id, state)
    """,
    """
    CREATE INDEX steps_ready_idx ON steps (execution_id, state, step_id)
    """,
    # ----------------------------------------------------------------- events
    """
    CREATE TABLE events (
        global_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        aggregate_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        actor TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        correlation_id TEXT NOT NULL DEFAULT '',
        causation_id TEXT NOT NULL DEFAULT '',
        payload TEXT NOT NULL,
        body_digest TEXT NOT NULL,
        UNIQUE (aggregate_id, sequence)
    )
    """,
    """
    CREATE INDEX events_execution_idx ON events (execution_id, global_sequence)
    """,
    """
    CREATE INDEX events_type_idx ON events (event_type, global_sequence)
    """,
    """
    CREATE INDEX events_correlation_idx ON events (correlation_id)
    """,
    # ----------------------------------------------------------------- leases
    """
    CREATE TABLE leases (
        lease_id TEXT PRIMARY KEY,
        step_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        worker_id TEXT NOT NULL,
        attempt INTEGER NOT NULL,
        acquired_at TEXT NOT NULL,
        expire_at TEXT NOT NULL,
        released_at TEXT,
        outcome TEXT NOT NULL DEFAULT ''
            CHECK (outcome IN ('', 'COMPLETED', 'EXPIRED', 'RELEASED', 'REVOKED'))
    )
    """,
    """
    CREATE INDEX leases_step_idx ON leases (step_id, acquired_at)
    """,
    """
    CREATE INDEX leases_live_idx ON leases (execution_id, expire_at) WHERE released_at IS NULL
    """,
    # -------------------------------------------------------------- artifacts
    """
    CREATE TABLE artifacts (
        artifact_digest TEXT PRIMARY KEY,
        step_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        parent_commit TEXT NOT NULL DEFAULT '',
        changed_files TEXT NOT NULL DEFAULT '[]',
        patch_digest TEXT NOT NULL DEFAULT '',
        spec_digest TEXT NOT NULL DEFAULT '',
        node_spec_digest TEXT NOT NULL DEFAULT '',
        dependency_digest TEXT NOT NULL DEFAULT '',
        toolchain_digest TEXT NOT NULL DEFAULT '',
        code_base_digest TEXT NOT NULL DEFAULT '',
        input_artifact_digest TEXT NOT NULL DEFAULT '',
        execution_log_ref TEXT NOT NULL DEFAULT '',
        gate_result_ref TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        worker_id TEXT NOT NULL DEFAULT '',
        sandbox_image TEXT NOT NULL DEFAULT '',
        model TEXT NOT NULL DEFAULT '',
        document TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX artifacts_step_idx ON artifacts (step_id, created_at)
    """,
    # ----------------------------------------------------------- gate results
    """
    CREATE TABLE gate_results (
        gate_result_id TEXT PRIMARY KEY,
        step_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        artifact_digest TEXT NOT NULL,
        tier INTEGER NOT NULL CHECK (tier IN (1, 2)),
        decision TEXT NOT NULL
            CHECK (decision IN ('PASS', 'APPROVE', 'REVISE', 'FAIL', 'ESCALATE')),
        subject_digest TEXT NOT NULL DEFAULT '',
        reasons TEXT NOT NULL DEFAULT '[]',
        violations TEXT NOT NULL DEFAULT '[]',
        confidence REAL,
        evidence TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX gate_results_step_idx ON gate_results (step_id, tier, created_at)
    """,
    # ------------------------------------------------------------- idempotency
    """
    CREATE TABLE idempotency (
        idempotency_key TEXT PRIMARY KEY,
        execution_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        operation_type TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('IN_PROGRESS', 'COMPLETED')),
        result TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        completed_at TEXT
    )
    """,
    # --------------------------------------------------------------- approvals
    """
    CREATE TABLE approvals (
        approval_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        decision TEXT NOT NULL
            CHECK (decision IN ('proceed', 'retry', 'reject')),
        approved_by TEXT NOT NULL
            CHECK (length(trim(approved_by)) > 0),
        note TEXT NOT NULL DEFAULT '',
        artifact_digest TEXT NOT NULL DEFAULT '',
        subject_digest TEXT NOT NULL DEFAULT '',
        granted_attempts INTEGER NOT NULL DEFAULT 0,
        -- v5 (Spec §3.2 x §10): whether this decision was a signature that verified against
        -- a registered owner. This is the decision that lets a critical change commit after a
        -- gate refused it, so a typed name is not evidence enough once owners are enrolled.
        verified INTEGER NOT NULL DEFAULT 0,
        approval_scheme TEXT NOT NULL DEFAULT '',
        key_fingerprint TEXT NOT NULL DEFAULT '',
        approval_digest TEXT NOT NULL,
        created_at TEXT NOT NULL,
        -- A PROCEED without an artifact would authorise "whatever comes next", which is
        -- exactly the ambiguity the binding exists to remove.
        CHECK (decision != 'proceed' OR length(artifact_digest) > 0)
    )
    """,
    """
    CREATE INDEX approvals_run_idx ON approvals (run_id, created_at)
    """,
    """
    CREATE INDEX approvals_step_idx ON approvals (step_id, created_at)
    """,
    # ----------------------------------------------------------------- workers
    """
    CREATE TABLE workers (
        worker_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        status TEXT NOT NULL
            CHECK (status IN ('IDLE', 'BUSY', 'CRASHED', 'RETIRED')),
        current_step_id TEXT,
        last_heartbeat_at TEXT,
        started_at TEXT NOT NULL,
        notes TEXT NOT NULL DEFAULT ''
    )
    """,
    # --------------------------------------------------------------- timeline
    """
    CREATE TABLE timeline (
        timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        step_id TEXT NOT NULL DEFAULT '',
        event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL DEFAULT '',
        severity TEXT NOT NULL DEFAULT 'info'
            CHECK (severity IN ('debug', 'info', 'warning', 'error', 'critical')),
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX timeline_run_idx ON timeline (run_id, timeline_id)
    """,
    # ---------------------------------------------------------------- metrics
    """
    CREATE TABLE metrics (
        metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        value REAL NOT NULL,
        unit TEXT NOT NULL DEFAULT '',
        run_id TEXT NOT NULL DEFAULT '',
        step_id TEXT NOT NULL DEFAULT '',
        labels TEXT NOT NULL DEFAULT '{}',
        recorded_at TEXT NOT NULL
    )
    """,
    # ------------------------------------------------------- owner registry (v4)
    _OWNERS_TABLE,
    """
    CREATE INDEX owners_role_idx ON owners (role, revoked_at)
    """,
    # ------------------------------------------------------- executions (v4)
    _EXECUTIONS_TABLE,
    """
    CREATE INDEX executions_run_idx ON executions (run_id, started_at)
    """,
    """
    CREATE INDEX workers_heartbeat_idx ON workers (last_heartbeat_at)
    """,
    """
    CREATE INDEX metrics_name_idx ON metrics (name, recorded_at)
    """,
)


#: Ordered, additive migrations: `{from_version: (statements...)}` moves the database to
#: `from_version + 1`. Only additive statements belong here — `ADD COLUMN` and `CREATE TABLE`.
#: Anything that rewrites a table (a changed CHECK constraint, for example) is deliberately not
#: expressible: SQLite would have to rebuild the table, and a migration that silently drops and
#: recreates the event log is not a migration, it is data loss.
MIGRATIONS: dict[int, tuple[str, ...]] = {
    2: (
        # v3 added a node-level subject digest so Spec §13.2's reuse key no longer carries the
        # whole-bundle digest. Existing rows keep an empty value, which the cache treats as an
        # incomplete key and therefore never reuses — conservative, and honest about the fact
        # that their reuse identity was different.
        "ALTER TABLE artifacts ADD COLUMN node_spec_digest TEXT NOT NULL DEFAULT ''",
    ),
    3: (
        # v4: owner identity (§3.2) and the two §19 projections that were declared but never
        # written. All additive. Approvals recorded before v4 are explicitly marked
        # unverified (`approval_verified = 0`) rather than assumed to have been verified —
        # they were not, because the machinery did not exist.
        _OWNERS_TABLE,
        "CREATE INDEX IF NOT EXISTS owners_role_idx ON owners (role, revoked_at)",
        "ALTER TABLE specs ADD COLUMN approval_verified INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE specs ADD COLUMN approval_scheme TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE specs ADD COLUMN approval_role TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE specs ADD COLUMN approval_fingerprint TEXT NOT NULL DEFAULT ''",
        _EXECUTIONS_TABLE,
        "CREATE INDEX IF NOT EXISTS executions_run_idx ON executions (run_id, started_at)",
        # The `workers` table already shipped with the right shape; it was merely never
        # written to. It only needs the index its heartbeat queries want.
        "CREATE INDEX IF NOT EXISTS workers_heartbeat_idx ON workers (last_heartbeat_at)",
    ),
    4: (
        # v5: step-level owner decisions become verifiable, for the same reason spec
        # sign-offs did — a name typed into a form is an approval record, not evidence that
        # the named principal agreed to anything. Existing rows are marked unverified, which
        # is what they were; they are not retroactively trusted.
        "ALTER TABLE approvals ADD COLUMN verified INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE approvals ADD COLUMN approval_scheme TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approvals ADD COLUMN key_fingerprint TEXT NOT NULL DEFAULT ''",
    ),
    5: (
        # v6: the executions row gains the "neither committed nor failed" bucket, so its
        # counters reconcile by construction instead of leaving cancelled/stale steps
        # uncounted.
        "ALTER TABLE executions ADD COLUMN step_neutral INTEGER NOT NULL DEFAULT 0",
    ),
    6: (
        # v7: task intakes. A new table, so this migration is purely additive and an existing
        # workspace simply gains an empty intake history.
        _INTAKES_TABLE,
        _INTAKES_INDEX,
    ),
}

#: Tables each migration step assumes exist. Declared rather than discovered, because the
#: alternative is an `OperationalError: no such table` from three frames deep in a transaction,
#: which tells an operator neither what is wrong nor what to do. These are the tables the
#: shipped schema of that version had; a database missing one has been hand-modified, and
#: saying so is more useful than half-applying a migration.
MIGRATION_REQUIRES: dict[int, tuple[str, ...]] = {
    2: ("artifacts",),
    3: ("specs", "workers"),
    4: ("approvals",),
    5: ("executions",),
    # No entry for 6: the v6 -> v7 step creates a brand new table and touches nothing that
    # already existed, so it requires no prior shape. Declaring tables it does not read made
    # the check refuse a legitimately minimal database.
}


def _missing_tables(connection: sqlite3.Connection, names: tuple[str, ...]) -> list[str]:
    present = {
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    return [name for name in names if name not in present]


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Create the schema, migrate an older one, or refuse a newer one."""
    row = connection.execute("PRAGMA user_version").fetchone()
    current = int(row[0]) if row else 0

    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {current} is newer than supported {SCHEMA_VERSION}; "
            "refusing to open (a newer Daedalus wrote this file)"
        )
    if current == 0:
        for statement in _INITIAL_SCHEMA:
            connection.execute(statement)
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        return
    if current == SCHEMA_VERSION:
        return

    # Older: apply the registered migrations in order, each inside its own transaction so a
    # failure leaves the version marker untouched and the next attempt resumes from there.
    version = current
    while version < SCHEMA_VERSION:
        statements = MIGRATIONS.get(version)
        if statements is None:
            raise RuntimeError(
                f"no migration path from schema version {version} to {version + 1}. "
                "Automatic migration exists only for versions that shipped; an older "
                "development database must be recreated."
            )
        missing = _missing_tables(connection, MIGRATION_REQUIRES.get(version, ()))
        if missing:
            raise RuntimeError(
                f"cannot migrate schema {version} -> {version + 1}: this database is missing "
                f"{missing}, which version {version} always had. It has been modified outside "
                "Daedalus. Restore a backup (`daedalus restore`) or recreate the workspace; "
                "migrating a database whose shape is unknown would guess at the contents."
            )
        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in statements:
                if _column_already_present(connection, statement):
                    continue
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {version + 1}")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        else:
            connection.execute("COMMIT")
        version += 1


#: `ALTER TABLE <table> ADD COLUMN <column> ...` — SQLite has no `IF NOT EXISTS` for this,
#: so it is recognised here and skipped when the column is already there.
_ADD_COLUMN = re.compile(
    r"^\s*ALTER\s+TABLE\s+(?P<table>\w+)\s+ADD\s+COLUMN\s+(?P<column>\w+)",
    re.IGNORECASE,
)
#: Leading `--` and `/* */` comments, which must not defeat the recognition above: a
#: migration written with a comment first would silently lose idempotency, and the failure
#: would appear later as a duplicate-column error on a hand-fixed database.
#: A line comment may end the string, not only a line: a migration written as
#: `"-- note"` alone is still a statement with a leading comment.
_LEADING_COMMENT = re.compile(r"^(?:\s*(?:--[^\n]*(?:\n|$)|/\*.*?\*/))+", re.DOTALL)


def _without_leading_comments(statement: str) -> str:
    """The statement with any leading comments and whitespace removed.

    Repeated because a comment can follow a comment, and `lstrip`ed at the end because a block
    comment leaves its trailing newline behind — which would defeat the anchor just as surely
    as the comment itself.
    """
    previous = statement
    stripped = _LEADING_COMMENT.sub("", statement)
    while stripped != previous:
        previous = stripped
        stripped = _LEADING_COMMENT.sub("", stripped)
    return stripped.lstrip()


def _column_already_present(connection: sqlite3.Connection, statement: str) -> bool:
    """True when an `ADD COLUMN` migration has already been applied.

    Migrations are meant to be re-runnable: an operator who hand-fixed a database, or a
    version marker that lagged a partially applied change, must not be wedged by
    `duplicate column name`. Being idempotent is what makes that a non-event.
    """
    match = _ADD_COLUMN.match(_without_leading_comments(statement))
    if match is None:
        return False
    columns = {
        str(row[1]) for row in connection.execute(f"PRAGMA table_info({match['table']})")
    }
    return match["column"] in columns
