"""SQLite-backed event store and projections (Spec §5, §18).

The contract this class enforces, in order, inside a single transaction:

1. **Precondition** — the caller already resolved the FSM next state.
2. **Sequence** — `MAX(sequence) + 1` for the aggregate, or refuse the write. A gap
   means two writers raced or history was tampered with; either way we stop
   (`SequenceConflict`, Spec §5.3).
3. **Append** — the event row is inserted.
4. **Project** — the derived read model is updated from the same event.
5. **Commit** — one transaction, so a crash can never leave the projection ahead of
   the log (Spec §4.2).

Idempotency (`idempotency` table, Spec §5.2) is claimed *inside the same
transaction* as the effect it guards, so a duplicate request cannot slip between the
claim and the write.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from daedalus.domain.events import Event, append_event_factory
from daedalus.domain.fsm import FAILED_STATES, LEASE_HOLDING_STATES
from daedalus.domain.identity import Owner, Role
from daedalus.domain.ids import utc_now
from daedalus.errors import DaedalusError, SequenceConflict
from daedalus.infrastructure.redact import assert_clean, redact
from daedalus.infrastructure.store.schema import SCHEMA_VERSION, initialize_schema


def _has_column(connection: Any, table: str, column: str) -> bool:
    try:
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
    except Exception:  # noqa: BLE001 - a missing table is a legitimate "no"
        return False
    return any(str(row[1]) == column for row in rows)


def _intake_row(row: Any) -> dict[str, Any]:
    """One intake row, with its JSON columns decoded.

    A row whose stored JSON cannot be parsed is returned with the raw text intact rather than
    replaced by an empty list: a corrupt record that reads as "no questions were asked" would
    look like a legitimate intake, and the operator would have no way to tell.
    """
    payload = dict(row)
    for field_name in ("questions", "answers", "rejections"):
        raw = payload.get(field_name)
        if not isinstance(raw, str):
            continue
        try:
            payload[field_name] = json.loads(raw)
        except ValueError:
            payload[field_name] = []
            payload.setdefault("corrupt_fields", []).append(field_name)
    return payload


def idempotency_key(execution_id: str, step_id: str, operation_type: str) -> str:
    """`execution_id + step_id + operation_type` (Spec §5.2)."""
    return f"{execution_id}:{step_id}:{operation_type}"


class IdempotentReplay(Exception):
    """Raised internally to signal 'already done, here is the stored result'."""

    def __init__(self, key: str, result: dict[str, Any]) -> None:
        super().__init__(f"operation already completed: {key}")
        self.key = key
        self.result = result


class _BufferedCursor:
    """A fully-materialised result set, so a read cannot be interleaved with another thread.

    Locking `execute` alone was not enough, and the failure it produced was subtle: a worker
    thread running a statement between a caller's `execute` and its `fetchone` could invalidate
    the result set, so `fetchone()` returned `None` for a row that certainly exists. A resume
    crashed with `'NoneType' object is not subscriptable` roughly once in twelve runs.

    Materialising inside the lock removes the window entirely, and it needs no change at any
    call site: `execute(...).fetchone()` keeps working and is now atomic. The cost is that a
    SELECT is read in full — acceptable because every projection read here is small and bounded
    by a run or a step.
    """

    __slots__ = ("_rows", "_index", "description", "lastrowid", "rowcount")

    def __init__(
        self,
        rows: list[Any],
        description: Any,
        lastrowid: int | None,
        rowcount: int,
    ) -> None:
        self._rows = rows
        self._index = 0
        self.description = description
        self.lastrowid = lastrowid
        self.rowcount = rowcount

    def fetchone(self) -> Any:
        if self._index >= len(self._rows):
            return None
        row = self._rows[self._index]
        self._index += 1
        return row

    def fetchmany(self, size: int | None = None) -> list[Any]:
        count = len(self._rows) - self._index if size is None else size
        chunk = self._rows[self._index : self._index + max(0, count)]
        self._index += len(chunk)
        return chunk

    def fetchall(self) -> list[Any]:
        remaining = self._rows[self._index :]
        self._index = len(self._rows)
        return remaining

    def __iter__(self) -> Any:
        while self._index < len(self._rows):
            row = self._rows[self._index]
            self._index += 1
            yield row

    def close(self) -> None:
        self._rows = []
        self._index = 0


class _SerializedConnection:
    """Serialises access to one SQLite connection across threads.

    A SQLite connection is bound to the thread that created it, and the service legitimately
    touches the store from the ASGI thread *and* from the dispatcher's worker threads. Rather
    than sprinkle locks through every query, the connection is wrapped once.

    The contract: **a statement and its result set are one atomic unit.** `execute` takes the
    lock, runs the statement, and reads any rows before releasing it. A caller can still hold
    the lock for a whole transaction through `transaction()`, and nested calls work because the
    lock is re-entrant.
    """

    __slots__ = ("_connection", "_lock")

    def __init__(self, connection: sqlite3.Connection, lock: threading.RLock) -> None:
        self._connection = connection
        self._lock = lock

    def execute(self, *args: Any, **kwargs: Any) -> _BufferedCursor:
        with self._lock:
            cursor = self._connection.execute(*args, **kwargs)
            description = cursor.description
            rows = cursor.fetchall() if description is not None else []
            return _BufferedCursor(rows, description, cursor.lastrowid, cursor.rowcount)

    def executemany(self, *args: Any, **kwargs: Any) -> _BufferedCursor:
        with self._lock:
            cursor = self._connection.executemany(*args, **kwargs)
            return _BufferedCursor([], cursor.description, cursor.lastrowid, cursor.rowcount)

    def executescript(self, *args: Any, **kwargs: Any) -> _BufferedCursor:
        with self._lock:
            cursor = self._connection.executescript(*args, **kwargs)
            description = cursor.description
            rows = cursor.fetchall() if description is not None else []
            return _BufferedCursor(rows, description, cursor.lastrowid, cursor.rowcount)

    def commit(self) -> None:
        with self._lock:
            self._connection.commit()

    def rollback(self) -> None:
        with self._lock:
            self._connection.rollback()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @property
    def row_factory(self) -> Any:
        return self._connection.row_factory

    @row_factory.setter
    def row_factory(self, value: Any) -> None:
        self._connection.row_factory = value

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class EventStore:
    """Append-only event log plus its rebuildable projections.

    Safe to share across threads: the service runs several runs concurrently on a bounded
    pool while the console reads projections from the ASGI thread.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # `check_same_thread=False` is required because the connection outlives the thread
        # that opened it; `_SerializedConnection` is what makes that safe.
        self._raw = sqlite3.connect(
            str(self.path), isolation_level=None, check_same_thread=False
        )
        self._raw.row_factory = sqlite3.Row
        self._connection = _SerializedConnection(self._raw, self._lock)
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=FULL",
            "PRAGMA foreign_keys=ON",
            "PRAGMA busy_timeout=5000",
        ):
            with self._lock:
                self._raw.execute(pragma)
        initialize_schema(self._raw)

    # ------------------------------------------------------------------ basics
    @property
    def connection(self) -> Any:
        return self._connection

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        """One atomic unit of work. Holds the store lock for its whole duration.

        Holding the lock across the transaction is what makes `BEGIN IMMEDIATE ... COMMIT`
        meaningful when several threads share the connection: without it, a second thread
        could interleave a statement into someone else's transaction.
        """
        with self._lock:
            self._raw.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._raw.execute("ROLLBACK")
                raise
            else:
                self._raw.execute("COMMIT")

    # ------------------------------------------------------------------ events
    def next_sequence(self, aggregate_id: str) -> int:
        row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) AS seq FROM events WHERE aggregate_id = ?",
            (aggregate_id,),
        ).fetchone()
        return int(row["seq"]) + 1

    def append(
        self,
        *,
        aggregate_id: str,
        execution_id: str,
        event_type: str,
        actor: str,
        payload: dict[str, Any] | None = None,
        correlation_id: str = "",
        causation_id: str = "",
        expected_sequence: int | None = None,
    ) -> Event:
        """Append one event at the next sequence for its aggregate."""
        clean_payload = redact(payload or {})
        assert_clean(clean_payload, where=f"event {event_type} payload")
        with self.transaction() as connection:
            sequence = self._next_sequence_in(connection, aggregate_id)
            if expected_sequence is not None and expected_sequence != sequence:
                raise SequenceConflict(
                    f"aggregate {aggregate_id} expected sequence {expected_sequence} "
                    f"but the log is at {sequence}",
                    aggregate_id=aggregate_id,
                    expected=expected_sequence,
                    actual=sequence,
                )
            event = append_event_factory(
                aggregate_id=aggregate_id,
                execution_id=execution_id,
                sequence=sequence,
                event_type=event_type,
                actor=actor,
                payload=clean_payload,
                correlation_id=correlation_id,
                causation_id=causation_id or self._last_event_id_in(connection, aggregate_id),
            )
            self._insert_event(connection, event)
        return event

    def append_many(
        self,
        specs: Sequence[dict[str, Any]],
    ) -> list[Event]:
        """Append several events atomically, preserving per-aggregate ordering."""
        events: list[Event] = []
        with self.transaction() as connection:
            for spec in specs:
                aggregate_id = str(spec["aggregate_id"])
                clean_payload = redact(spec.get("payload") or {})
                assert_clean(clean_payload, where=f"event {spec['event_type']} payload")
                sequence = self._next_sequence_in(connection, aggregate_id)
                event = append_event_factory(
                    aggregate_id=aggregate_id,
                    execution_id=str(spec["execution_id"]),
                    sequence=sequence,
                    event_type=str(spec["event_type"]),
                    actor=str(spec.get("actor", "system")),
                    payload=clean_payload,
                    correlation_id=str(spec.get("correlation_id", "")),
                    causation_id=str(spec.get("causation_id", ""))
                    or self._last_event_id_in(connection, aggregate_id),
                )
                self._insert_event(connection, event)
                events.append(event)
        return events

    def _next_sequence_in(self, connection: sqlite3.Connection, aggregate_id: str) -> int:
        row = connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) AS seq FROM events WHERE aggregate_id = ?",
            (aggregate_id,),
        ).fetchone()
        return int(row["seq"]) + 1

    def _last_event_id_in(self, connection: sqlite3.Connection, aggregate_id: str) -> str:
        """The most recent event on this aggregate: the cause of the next one."""
        row = connection.execute(
            "SELECT event_id FROM events WHERE aggregate_id = ? ORDER BY sequence DESC LIMIT 1",
            (aggregate_id,),
        ).fetchone()
        return str(row["event_id"]) if row is not None else ""

    def _insert_event(self, connection: sqlite3.Connection, event: Event) -> None:
        connection.execute(
            """
            INSERT INTO events (
                event_id, aggregate_id, execution_id, sequence, event_type,
                schema_version, actor, timestamp, correlation_id, causation_id,
                payload, body_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.aggregate_id,
                event.execution_id,
                event.sequence,
                event.event_type,
                event.schema_version,
                event.actor,
                event.timestamp,
                event.correlation_id,
                event.causation_id,
                json.dumps(dict(event.payload), sort_keys=True, separators=(",", ":")),
                event.digest(),
            ),
        )

    def append_in_transaction(
        self,
        *,
        aggregate_id: str,
        execution_id: str,
        event_type: str,
        actor: str,
        payload: dict[str, Any] | None = None,
        correlation_id: str = "",
        causation_id: str = "",
    ) -> Event:
        """Append inside a caller-managed transaction.

        The caller is responsible for having opened `transaction()`. Sequence is read
        and used inside that same transaction so two writers cannot interleave.
        """
        clean_payload = redact(payload or {})
        assert_clean(clean_payload, where=f"event {event_type} payload")
        sequence = self._next_sequence_in(self._connection, aggregate_id)
        event = append_event_factory(
            aggregate_id=aggregate_id,
            execution_id=execution_id,
            sequence=sequence,
            event_type=event_type,
            actor=actor,
            payload=clean_payload,
            correlation_id=correlation_id,
            # Auto-wired when the caller does not say: an event is caused by the previous event
            # on its own aggregate. Without this, `causation_id` was serialised as "" forever and
            # the causal chain Spec §5.1 asks for did not exist.
            causation_id=causation_id or self._last_event_id_in(self._connection, aggregate_id),
        )
        self._insert_event(self._connection, event)
        return event

    def events_for(
        self,
        aggregate_id: str,
        *,
        after_sequence: int = 0,
    ) -> list[Event]:
        rows = self._connection.execute(
            """
            SELECT * FROM events
            WHERE aggregate_id = ? AND sequence > ?
            ORDER BY sequence ASC
            """,
            (aggregate_id, after_sequence),
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def events_for_execution(self, execution_id: str) -> list[Event]:
        """Every event of one execution, in order.

        An empty id is refused rather than answered: spec-aggregate events carry no execution
        id, so `events_for_execution("")` would silently return spec approvals as though they
        belonged to an execution — the opposite of what the caller asked for.
        """
        if not execution_id:
            raise ValueError("events_for_execution needs an execution id")
        rows = self._connection.execute(
            "SELECT * FROM events WHERE execution_id = ? ORDER BY global_sequence ASC",
            (execution_id,),
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def events_for_spec(self, goal_id: str) -> list[Event]:
        """Spec-aggregate events (registration, sign-off) for one goal, in order."""
        rows = self._connection.execute(
            "SELECT * FROM events WHERE aggregate_id = ? ORDER BY global_sequence ASC",
            (f"spec:{goal_id}",),
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def causal_chain(self, event_id: str, *, limit: int = 100) -> list[Event]:
        """Walk `causation_id` backwards from an event to the start of its chain.

        Answers "what led to this?" — the question Spec §5.1's `causation_id` exists for.
        """
        chain: list[Event] = []
        seen: set[str] = set()
        current = event_id
        while current and current not in seen and len(chain) < limit:
            seen.add(current)
            row = self.connection.execute(
                "SELECT * FROM events WHERE event_id = ?", (current,)
            ).fetchone()
            if row is None:
                break
            event = self._row_to_event(row)
            chain.append(event)
            current = event.causation_id
        chain.reverse()
        return chain

    def all_events(self) -> list[Event]:
        rows = self._connection.execute(
            "SELECT * FROM events ORDER BY global_sequence ASC"
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def event_count(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            event_id=row["event_id"],
            aggregate_id=row["aggregate_id"],
            execution_id=row["execution_id"],
            sequence=int(row["sequence"]),
            event_type=row["event_type"],
            actor=row["actor"],
            payload=json.loads(row["payload"]),
            schema_version=int(row["schema_version"]),
            timestamp=row["timestamp"],
            correlation_id=row["correlation_id"],
            causation_id=row["causation_id"],
        )

    def verify_sequences(self) -> list[str]:
        """Return a list of aggregate ids whose sequence is not 1..n without gaps."""
        broken: list[str] = []
        rows = self._connection.execute(
            """
            SELECT aggregate_id, COUNT(*) AS n, MIN(sequence) AS lo, MAX(sequence) AS hi
            FROM events GROUP BY aggregate_id
            """
        ).fetchall()
        for row in rows:
            count = int(row["n"])
            if int(row["lo"]) != 1 or int(row["hi"]) != count:
                broken.append(str(row["aggregate_id"]))
        return broken

    # ------------------------------------------------------------ idempotency
    def claim_idempotent(
        self,
        key: str,
        *,
        execution_id: str,
        step_id: str,
        operation_type: str,
    ) -> None:
        """Claim an idempotency key, raising `IdempotentReplay` if already completed.

        Must be called inside a `transaction()` block so the claim and the guarded
        effect commit together.
        """
        row = self._connection.execute(
            "SELECT state, result FROM idempotency WHERE idempotency_key = ?",
            (key,),
        ).fetchone()
        if row is not None:
            if row["state"] == "COMPLETED":
                raise IdempotentReplay(key, json.loads(row["result"]))
            raise SequenceConflict(
                f"idempotency key {key} is IN_PROGRESS; refusing a concurrent duplicate"
            )
        self._connection.execute(
            """
            INSERT INTO idempotency (
                idempotency_key, execution_id, step_id, operation_type, state, result,
                created_at
            ) VALUES (?, ?, ?, ?, 'IN_PROGRESS', '{}', ?)
            """,
            (key, execution_id, step_id, operation_type, utc_now()),
        )

    def complete_idempotent(self, key: str, result: dict[str, Any]) -> None:
        self._connection.execute(
            """
            UPDATE idempotency SET state = 'COMPLETED', result = ?, completed_at = ?
            WHERE idempotency_key = ?
            """,
            (json.dumps(result, sort_keys=True, separators=(",", ":")), utc_now(), key),
        )

    def idempotent_result(self, key: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT state, result FROM idempotency WHERE idempotency_key = ?",
            (key,),
        ).fetchone()
        if row is None or row["state"] != "COMPLETED":
            return None
        return json.loads(row["result"])

    def completed_operations(self, execution_id: str) -> list[tuple[str, str, str]]:
        rows = self._connection.execute(
            """
            SELECT step_id, operation_type, result FROM idempotency
            WHERE execution_id = ? AND state = 'COMPLETED'
            ORDER BY completed_at ASC
            """,
            (execution_id,),
        ).fetchall()
        return [(str(r["step_id"]), str(r["operation_type"]), str(r["result"])) for r in rows]

    # ------------------------------------------------------------- projections
    def project_run(self, run: dict[str, Any]) -> None:
        self._connection.execute(
            """
            INSERT INTO runs (
                run_id, goal_id, execution_id, spec_digest, parent_execution_id,
                replay_from_commit, status, base_commit, worktree_path, branch,
                correlation_id, created_at, updated_at
            ) VALUES (
                :run_id, :goal_id, :execution_id, :spec_digest, :parent_execution_id,
                :replay_from_commit, :status, :base_commit, :worktree_path, :branch,
                :correlation_id, :created_at, :updated_at
            )
            ON CONFLICT(run_id) DO UPDATE SET
                status = excluded.status,
                base_commit = excluded.base_commit,
                worktree_path = excluded.worktree_path,
                branch = excluded.branch,
                updated_at = excluded.updated_at
            """,
            {
                "parent_execution_id": None,
                "replay_from_commit": None,
                "base_commit": "",
                "worktree_path": "",
                "branch": "",
                "correlation_id": "",
                **run,
            },
        )

    def update_run_status(self, run_id: str, status: str) -> None:
        self._connection.execute(
            "UPDATE runs SET status = ?, updated_at = ? WHERE run_id = ?",
            (status, utc_now(), run_id),
        )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_runs(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM runs ORDER BY created_at ASC"
        ).fetchall()
        return [dict(row) for row in rows]

    def project_step(self, step: dict[str, Any]) -> None:
        self._connection.execute(
            """
            INSERT INTO steps (
                step_id, run_id, execution_id, node_id, objective, intent, deps,
                expected_artifacts, allowed_tools, state, attempt, max_attempts,
                timeout_sec, spec_digest, base_commit, lease_id, worker_id,
                lease_expires_at, revision_of, last_failure, granted_attempts,
                worktree_path, created_at, updated_at
            ) VALUES (
                :step_id, :run_id, :execution_id, :node_id, :objective, :intent, :deps,
                :expected_artifacts, :allowed_tools, :state, :attempt, :max_attempts,
                :timeout_sec, :spec_digest, :base_commit, :lease_id, :worker_id,
                :lease_expires_at, :revision_of, :last_failure, :granted_attempts,
                :worktree_path, :created_at, :updated_at
            )
            ON CONFLICT(step_id) DO UPDATE SET
                state = excluded.state,
                attempt = excluded.attempt,
                lease_id = excluded.lease_id,
                worker_id = excluded.worker_id,
                lease_expires_at = excluded.lease_expires_at,
                base_commit = excluded.base_commit,
                last_failure = excluded.last_failure,
                updated_at = excluded.updated_at
            """,
            {
                "objective": "",
                "intent": "",
                "deps": "[]",
                "expected_artifacts": "[]",
                "allowed_tools": "[]",
                "attempt": 0,
                "max_attempts": 3,
                "timeout_sec": 300,
                "base_commit": "",
                "lease_id": None,
                "worker_id": None,
                "lease_expires_at": None,
                "revision_of": "",
                "last_failure": "",
                "granted_attempts": 0,
                "worktree_path": "",
                **step,
            },
        )

    def update_step_state(
        self,
        step_id: str,
        *,
        state: str,
        attempt: int | None = None,
        lease_id: str | None = None,
        worker_id: str | None = None,
        lease_expires_at: str | None = None,
        base_commit: str | None = None,
        last_failure: str | None = None,
        granted_attempts: int | None = None,
        worktree_path: str | None = None,
    ) -> None:
        self._connection.execute(
            """
            UPDATE steps SET
                state = ?,
                attempt = COALESCE(?, attempt),
                -- COALESCE, like `attempt` and `base_commit`, so a transition that does not
                -- mention a worker does not erase the one that is already recorded. Without
                -- this, `steps.worker_id` was nulled the moment a step left LEASED — which
                -- made the column, and every query derived from it, permanently empty.
                -- Passing `` clears it deliberately; passing NULL means "leave it alone".
                lease_id = COALESCE(?, lease_id),
                worker_id = COALESCE(?, worker_id),
                -- Guarded like `lease_id`, and for the same reason: a write that does not
                -- mention the lease must not be able to leave the row half-leased. These two
                -- columns are one fact, so they move together or not at all. Passing `""`
                -- clears; passing NULL leaves alone.
                lease_expires_at = COALESCE(?, lease_expires_at),
                base_commit = COALESCE(?, base_commit),
                last_failure = COALESCE(?, last_failure),
                granted_attempts = COALESCE(?, granted_attempts),
                worktree_path = COALESCE(?, worktree_path),
                updated_at = ?
            WHERE step_id = ?
            """,
            (
                state,
                attempt,
                lease_id,
                worker_id,
                lease_expires_at,
                base_commit,
                last_failure,
                granted_attempts,
                worktree_path,
                utc_now(),
                step_id,
            ),
        )

    def get_step(self, step_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT * FROM steps WHERE step_id = ?", (step_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_steps(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM steps WHERE run_id = ? ORDER BY created_at ASC, step_id ASC",
            (run_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def steps_in_state(self, execution_id: str, states: Iterable[str]) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in states)
        rows = self._connection.execute(
            f"""
            SELECT * FROM steps
            WHERE execution_id = ? AND state IN ({placeholders})
            ORDER BY created_at ASC, step_id ASC
            """,
            (execution_id, *tuple(states)),
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------- specs
    def register_spec(
        self,
        *,
        spec_digest: str,
        goal_id: str,
        spec_version: int,
        document: dict[str, Any],
        risk_level: str,
        owner_id: str,
        parent_spec_digest: str = "",
    ) -> bool:
        """Register a frozen spec. Returns False when the digest already exists."""
        existing = self._connection.execute(
            "SELECT spec_digest FROM specs WHERE spec_digest = ?", (spec_digest,)
        ).fetchone()
        if existing is not None:
            return False
        self._connection.execute(
            """
            INSERT INTO specs (
                spec_digest, goal_id, spec_version, parent_spec_digest, owner_id,
                risk_level, document, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                spec_digest,
                goal_id,
                spec_version,
                parent_spec_digest,
                owner_id,
                risk_level,
                json.dumps(document, sort_keys=True, separators=(",", ":")),
                utc_now(),
            ),
        )
        return True

    def approve_spec(
        self,
        spec_digest: str,
        *,
        approved_by: str,
        signature: str = "",
        verified: bool = False,
        scheme: str = "",
        role: str = "",
        fingerprint: str = "",
    ) -> None:
        """Record a sign-off, and whether it was *verified* against a registered owner.

        `verified=False` is not a failure; it is the honest record of an approval given
        before identity verification was configured. `assert_spec_may_run` distinguishes the
        two, so an unverified approval can never pass as a verified one.
        """
        self._connection.execute(
            """
            UPDATE specs
               SET approved_by = ?, approved_at = ?, signature = ?,
                   approval_verified = ?, approval_scheme = ?, approval_role = ?,
                   approval_fingerprint = ?
             WHERE spec_digest = ?
            """,
            (
                approved_by,
                utc_now(),
                signature,
                int(verified),
                scheme,
                role,
                fingerprint,
                spec_digest,
            ),
        )

    def get_spec(self, spec_digest: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT * FROM specs WHERE spec_digest = ?", (spec_digest,)
        ).fetchone()
        return dict(row) if row else None

    def is_spec_approved(self, spec_digest: str, *, verified_only: bool = False) -> bool:
        """Whether an owner has signed off — optionally only a *verified* sign-off.

        The distinction is the whole point of Spec §3.2: a name typed into a form is an
        approval record, but it is not evidence that the named principal agreed to anything.
        """
        row = self._connection.execute(
            "SELECT approved_at, approval_verified FROM specs WHERE spec_digest = ?",
            (spec_digest,),
        ).fetchone()
        if not row or not row["approved_at"]:
            return False
        return bool(int(row["approval_verified"])) if verified_only else True

    # --------------------------------------------------------- owner registry (v4)
    def upsert_owner(self, owner: Owner) -> None:
        self._connection.execute(
            """
            INSERT INTO owners (
                owner_id, display_name, role, secret_env, key_fingerprint, created_at,
                revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_id) DO UPDATE SET
                display_name = excluded.display_name,
                role = excluded.role,
                secret_env = excluded.secret_env,
                key_fingerprint = excluded.key_fingerprint,
                revoked_at = excluded.revoked_at
            """,
            (
                owner.owner_id,
                owner.display_name,
                owner.role.value,
                owner.secret_env,
                owner.key_fingerprint,
                owner.created_at or utc_now(),
                owner.revoked_at,
            ),
        )

    def get_owner(self, owner_id: str) -> Owner | None:
        row = self._connection.execute(
            "SELECT * FROM owners WHERE owner_id = ?", (owner_id,)
        ).fetchone()
        return self._row_to_owner(row) if row else None

    def list_owners(self, *, include_revoked: bool = False) -> list[Owner]:
        sql = "SELECT * FROM owners"
        if not include_revoked:
            sql += " WHERE revoked_at = ''"
        sql += " ORDER BY created_at ASC, owner_id ASC"
        return [self._row_to_owner(row) for row in self._connection.execute(sql)]

    def revoke_owner(self, owner_id: str) -> bool:
        cursor = self._connection.execute(
            "UPDATE owners SET revoked_at = ? WHERE owner_id = ? AND revoked_at = ''",
            (utc_now(), owner_id),
        )
        return bool(cursor.rowcount)

    def owner_count(self, *, include_revoked: bool = False) -> int:
        """How many owners exist. `include_revoked` matters for the enforcement decision:
        revoking the last owner must not look like "this workspace never had a registry"."""
        sql = "SELECT COUNT(*) AS n FROM owners"
        if not include_revoked:
            sql += " WHERE revoked_at = ''"
        row = self._connection.execute(sql).fetchone()
        return int(row["n"]) if row else 0

    @staticmethod
    def _row_to_owner(row: Any) -> Owner:
        return Owner(
            owner_id=str(row["owner_id"]),
            role=Role(str(row["role"])),
            display_name=str(row["display_name"]),
            secret_env=str(row["secret_env"]),
            key_fingerprint=str(row["key_fingerprint"]),
            created_at=str(row["created_at"]),
            revoked_at=str(row["revoked_at"]),
        )

    # ------------------------------------------------------- executions (v4, §19)
    def upsert_execution(self, execution: dict[str, Any]) -> None:
        self._connection.execute(
            """
            INSERT INTO executions (
                execution_id, run_id, parent_execution_id, replay_from_commit, kind, status,
                spec_digest, started_at, finished_at, step_total, step_committed, step_failed,
                step_neutral, created_at
            ) VALUES (
                :execution_id, :run_id, :parent_execution_id, :replay_from_commit, :kind,
                :status, :spec_digest, :started_at, :finished_at, :step_total,
                :step_committed, :step_failed, :step_neutral, :created_at
            )
            ON CONFLICT(execution_id) DO UPDATE SET
                status = excluded.status,
                finished_at = excluded.finished_at,
                step_total = excluded.step_total,
                step_committed = excluded.step_committed,
                step_failed = excluded.step_failed,
                step_neutral = excluded.step_neutral
            """,
            {
                "execution_id": execution["execution_id"],
                "run_id": execution["run_id"],
                "parent_execution_id": execution.get("parent_execution_id") or "",
                "replay_from_commit": execution.get("replay_from_commit") or "",
                "kind": execution.get("kind") or "run",
                "status": execution.get("status") or "PENDING",
                "spec_digest": execution.get("spec_digest") or "",
                "started_at": execution.get("started_at") or "",
                "finished_at": execution.get("finished_at") or "",
                "step_total": int(execution.get("step_total") or 0),
                "step_committed": int(execution.get("step_committed") or 0),
                "step_failed": int(execution.get("step_failed") or 0),
                "step_neutral": int(execution.get("step_neutral") or 0),
                "created_at": execution.get("created_at") or utc_now(),
            },
        )

    def get_execution(self, execution_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_executions(self, run_id: str = "") -> list[dict[str, Any]]:
        if run_id:
            rows = self._connection.execute(
                "SELECT * FROM executions WHERE run_id = ? "
                "ORDER BY started_at ASC, created_at ASC",
                (run_id,),
            )
        else:
            rows = self._connection.execute(
                "SELECT * FROM executions ORDER BY created_at DESC"
            )
        return [dict(row) for row in rows]

    # ---------------------------------------------------------- workers (v4, §19)
    def register_worker(
        self,
        worker_id: str,
        *,
        kind: str = "model",
        status: str = "IDLE",
        current_step_id: str | None = None,
        notes: str = "",
    ) -> None:
        """Upsert a worker's identity and heartbeat.

        The table shipped in the first schema and nothing ever wrote to it, so it documented
        an intention rather than a fact. A worker that has run steps must be visible.
        """
        now = utc_now()
        self._connection.execute(
            """
            INSERT INTO workers (
                worker_id, kind, status, current_step_id, last_heartbeat_at, started_at, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(worker_id) DO UPDATE SET
                status = excluded.status,
                current_step_id = excluded.current_step_id,
                last_heartbeat_at = excluded.last_heartbeat_at,
                notes = excluded.notes
            """,
            (worker_id, kind, status, current_step_id, now, now, notes),
        )

    def list_workers(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM workers ORDER BY last_heartbeat_at DESC, worker_id ASC"
        ).fetchall()
        return [dict(row) for row in rows]

    def workers_with_counts(self) -> list[dict[str, Any]]:
        """Registered workers plus the step counts derived from the log.

        A worker that ran steps but was never registered is included rather than hidden: it
        means the registry missed a beat, and a monitoring view that silently drops that is
        worse than one that shows it.
        """
        counts = self.step_counts_by_worker()
        seen: set[str] = set()
        merged: list[dict[str, Any]] = []
        for row in self.list_workers():
            worker_id = str(row["worker_id"])
            seen.add(worker_id)
            merged.append({**row, **counts.get(worker_id, {})})
        for worker_id, derived in counts.items():
            if worker_id in seen:
                continue
            merged.append(
                {
                    "worker_id": worker_id,
                    "kind": "unregistered",
                    "status": "UNKNOWN",
                    "current_step_id": None,
                    "last_heartbeat_at": "",
                    "started_at": "",
                    "notes": "steps exist for this worker but it was never registered",
                    **derived,
                }
            )
        return merged

    def step_invariant_violations(self) -> list[str]:
        """Projection invariants that must hold for every step, checked against the log.

        These are the rules that were violated in practice, so they are checked rather than
        trusted. Each one is a *consistency* property, not a policy: it can be decided from
        the data alone.

        * the two lease columns are one fact, so a step cannot hold an id without an expiry;
        * a lease exists only while the step is LEASED or RUNNING — a lease on a committed or
          cancelled step is a claim that someone is working on finished work;
        * `worker_id` is provenance, so a step that names a worker must have been leased by
          one. It is not reconstructible from the state alone, which is exactly why a wrong
          value could never be detected before this check existed.
        """
        violations: list[str] = []
        # The *latest* lessee per step, from the log. Not merely "was this step ever leased":
        # that weaker rule accepts any worker name once one lease event exists, so a wrong
        # `worker_id` stayed undetectable — the gap this check exists to close.
        last_lessee: dict[str, str] = {}
        for event in self.all_events():
            if event.event_type == "StepLeaseAcquired" and event.aggregate_id.startswith("step:"):
                last_lessee[event.aggregate_id.removeprefix("step:")] = str(
                    event.payload.get("worker_id", "")
                )

        for row in self._connection.execute("SELECT * FROM steps").fetchall():
            step_id = str(row["step_id"])
            node = str(row["node_id"])
            state = str(row["state"])
            lease_id = str(row["lease_id"] or "")
            expiry = str(row["lease_expires_at"] or "")
            worker_id = str(row["worker_id"] or "")

            if bool(lease_id) != bool(expiry):
                violations.append(
                    f"{node}: lease_id={'set' if lease_id else 'empty'} but "
                    f"lease_expires_at={'set' if expiry else 'empty'} — the lease columns must "
                    "move together"
                )
            if lease_id and state not in LEASE_HOLDING_STATES:
                violations.append(
                    f"{node}: holds lease {lease_id[:12]} while {state}, but only "
                    f"{sorted(LEASE_HOLDING_STATES)} may hold one"
                )
            if worker_id:
                recorded = last_lessee.get(step_id)
                if recorded is None:
                    violations.append(
                        f"{node}: names worker {worker_id!r} but the log contains no "
                        "StepLeaseAcquired for this step"
                    )
                elif recorded and recorded != worker_id:
                    violations.append(
                        f"{node}: names worker {worker_id!r} but the last lease was taken by "
                        f"{recorded!r}"
                    )
        return violations

    def steps_with_inconsistent_lease(self) -> list[dict[str, Any]]:
        """The steps whose lease columns disagree, for recovery to repair."""
        rows = self._connection.execute(
            """
            SELECT * FROM steps
             WHERE (lease_id IS NOT NULL AND lease_id <> '' AND
                    (lease_expires_at IS NULL OR lease_expires_at = ''))
                OR (lease_id IS NULL OR lease_id = '')
                   AND lease_expires_at IS NOT NULL AND lease_expires_at <> ''
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def step_counts_by_worker(self) -> dict[str, dict[str, int]]:
        """Steps started / committed / failed per worker, derived from the projections.

        Derived rather than counted on write: a counter incremented by the control plane can
        drift from the event log, and the log is the authority.
        """
        rows = self._connection.execute(
            """
            SELECT worker_id,
                   COUNT(*) AS started,
                   SUM(CASE WHEN state = 'COMMITTED' THEN 1 ELSE 0 END) AS committed,
                   SUM(CASE WHEN state IN ({placeholders}) THEN 1 ELSE 0 END) AS failed
              FROM steps
             WHERE worker_id IS NOT NULL AND worker_id <> ''
             GROUP BY worker_id
            """.format(placeholders=",".join("?" for _ in FAILED_STATES)),
            # One `params` argument, because the serialized connection wrapper takes exactly
            # (sql, params) and rejects varargs.
            tuple(sorted(FAILED_STATES)),
        ).fetchall()
        return {
            str(row["worker_id"]): {
                "steps_started": int(row["started"] or 0),
                "steps_committed": int(row["committed"] or 0),
                "steps_failed": int(row["failed"] or 0),
            }
            for row in rows
        }

    # ---------------------------------------------------------------- leases
    def record_lease(self, lease: dict[str, Any]) -> None:
        self._connection.execute(
            """
            INSERT INTO leases (
                lease_id, step_id, execution_id, worker_id, attempt, acquired_at,
                expire_at, released_at, outcome
            ) VALUES (
                :lease_id, :step_id, :execution_id, :worker_id, :attempt, :acquired_at,
                :expire_at, NULL, ''
            )
            """,
            lease,
        )

    def release_lease(self, lease_id: str, outcome: str) -> None:
        self._connection.execute(
            "UPDATE leases SET released_at = ?, outcome = ? WHERE lease_id = ?",
            (utc_now(), outcome, lease_id),
        )

    def live_leases(self, execution_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            """
            SELECT * FROM leases
            WHERE execution_id = ? AND released_at IS NULL
            ORDER BY acquired_at ASC
            """,
            (execution_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def expired_leases(self, now_iso: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            """
            SELECT * FROM leases
            WHERE released_at IS NULL AND expire_at <= ?
            ORDER BY expire_at ASC
            """,
            (now_iso,),
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------- approvals
    def record_approval(self, approval: dict[str, Any]) -> None:
        columns = (
            "approval_id", "run_id", "step_id", "execution_id", "decision",
            "approved_by", "note", "artifact_digest", "subject_digest",
            "granted_attempts", "verified", "approval_scheme", "key_fingerprint",
            "approval_digest", "created_at",
        )
        payload = {column: approval.get(column, "") for column in columns}
        payload["verified"] = int(bool(approval.get("verified", False)))
        self._connection.execute(
            """
            INSERT INTO approvals (
                approval_id, run_id, step_id, execution_id, decision, approved_by, note,
                artifact_digest, subject_digest, granted_attempts, verified,
                approval_scheme, key_fingerprint, approval_digest, created_at
            ) VALUES (
                :approval_id, :run_id, :step_id, :execution_id, :decision, :approved_by,
                :note, :artifact_digest, :subject_digest, :granted_attempts, :verified,
                :approval_scheme, :key_fingerprint, :approval_digest, :created_at
            )
            """,
            payload,
        )

    def approvals_for_run(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM approvals WHERE run_id = ? ORDER BY created_at ASC",
            (run_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def approvals_for_step(self, step_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM approvals WHERE step_id = ? ORDER BY created_at ASC",
            (step_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def latest_approval(self, step_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT * FROM approvals WHERE step_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (step_id,),
        ).fetchone()
        return dict(row) if row else None

    def find_approval_authorising(
        self, step_id: str, artifact_digest: str, *, subject_digest: str = ""
    ) -> dict[str, Any] | None:
        """The newest PROCEED approval that names exactly this artifact.

        `subject_digest` is compared when supplied, so an approval given under one frozen spec
        cannot authorise a commit under another. That check is also in
        `Approval.authorises()`, which is the predicate the commit path now consults — this
        query is a lookup, not the policy, and it used to be mistaken for one.
        """
        if subject_digest:
            row = self._connection.execute(
                """
                SELECT * FROM approvals
                WHERE step_id = ? AND decision = 'proceed' AND artifact_digest = ?
                  AND subject_digest = ?
                ORDER BY created_at DESC, rowid DESC LIMIT 1
                """,
                (step_id, artifact_digest, subject_digest),
            ).fetchone()
        else:
            row = self._connection.execute(
                """
                SELECT * FROM approvals
                WHERE step_id = ? AND decision = 'proceed' AND artifact_digest = ?
                ORDER BY created_at DESC, rowid DESC LIMIT 1
                """,
                (step_id, artifact_digest),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------- artifacts
    def record_artifact(self, document: dict[str, Any]) -> None:
        """Persist one artifact row. `document` carries the explicit columns."""
        columns = (
            "artifact_digest",
            "step_id",
            "execution_id",
            "parent_commit",
            "changed_files",
            "patch_digest",
            "spec_digest",
            "node_spec_digest",
            "dependency_digest",
            "toolchain_digest",
            "code_base_digest",
            "input_artifact_digest",
            "execution_log_ref",
            "gate_result_ref",
            "status",
            "worker_id",
            "sandbox_image",
            "model",
            "document",
            "created_at",
        )
        payload = {column: document.get(column, "") for column in columns}
        self._connection.execute(
            """
            INSERT INTO artifacts (
                artifact_digest, step_id, execution_id, parent_commit, changed_files,
                patch_digest, spec_digest, node_spec_digest, dependency_digest,
                toolchain_digest, code_base_digest, input_artifact_digest, execution_log_ref,
                gate_result_ref, status, worker_id, sandbox_image, model, document,
                created_at
            ) VALUES (
                :artifact_digest, :step_id, :execution_id, :parent_commit, :changed_files,
                :patch_digest, :spec_digest, :node_spec_digest, :dependency_digest,
                :toolchain_digest, :code_base_digest, :input_artifact_digest,
                :execution_log_ref, :gate_result_ref, :status, :worker_id, :sandbox_image,
                :model, :document, :created_at
            )
            ON CONFLICT(artifact_digest) DO UPDATE SET
                status = excluded.status,
                gate_result_ref = excluded.gate_result_ref,
                document = excluded.document
            """,
            payload,
        )

    def update_artifact_status(
        self,
        artifact_digest: str,
        *,
        status: str,
        gate_result_ref: str = "",
    ) -> None:
        self._connection.execute(
            """
            UPDATE artifacts SET status = ?, gate_result_ref = ?
            WHERE artifact_digest = ?
            """,
            (status, gate_result_ref, artifact_digest),
        )

    def get_artifact(self, artifact_digest: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT * FROM artifacts WHERE artifact_digest = ?", (artifact_digest,)
        ).fetchone()
        return dict(row) if row else None

    def artifacts_for_step(self, step_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM artifacts WHERE step_id = ? ORDER BY created_at ASC",
            (step_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    # ----------------------------------------------------------- gate results
    def record_gate_result(
        self,
        *,
        gate_result_id: str,
        step_id: str,
        execution_id: str,
        artifact_digest: str,
        tier: int,
        decision: str,
        subject_digest: str,
        reasons: list[str],
        violations: list[str],
        confidence: float | None,
        evidence: dict[str, Any],
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO gate_results (
                gate_result_id, step_id, execution_id, artifact_digest, tier, decision,
                subject_digest, reasons, violations, confidence, evidence, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                gate_result_id,
                step_id,
                execution_id,
                artifact_digest,
                tier,
                decision,
                subject_digest,
                json.dumps(redact(reasons), sort_keys=True),
                json.dumps(redact(violations), sort_keys=True),
                confidence,
                json.dumps(redact(evidence), sort_keys=True, separators=(",", ":")),
                utc_now(),
            ),
        )

    def gate_results_for_step(self, step_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM gate_results WHERE step_id = ? ORDER BY tier ASC, created_at ASC",
            (step_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def latest_gate_results(self, execution_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            """
            SELECT * FROM gate_results WHERE execution_id = ?
            ORDER BY created_at ASC
            """,
            (execution_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    # -------------------------------------------------------------- timeline
    def append_timeline(
        self,
        *,
        run_id: str,
        execution_id: str,
        step_id: str,
        event_id: str,
        event_type: str,
        actor: str,
        summary: str,
        severity: str = "info",
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO timeline (
                run_id, execution_id, step_id, event_id, event_type, actor, summary,
                severity, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                execution_id,
                step_id,
                event_id,
                event_type,
                actor,
                summary,
                severity,
                utc_now(),
            ),
        )

    def timeline_for_run(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM timeline WHERE run_id = ? ORDER BY timeline_id ASC",
            (run_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    # --------------------------------------------------------------- metrics
    def record_metric(
        self,
        *,
        name: str,
        value: float,
        unit: str = "",
        run_id: str = "",
        step_id: str = "",
        labels: dict[str, Any] | None = None,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO metrics (name, value, unit, run_id, step_id, labels, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                float(value),
                unit,
                run_id,
                step_id,
                json.dumps(redact(labels or {}), sort_keys=True, separators=(",", ":")),
                utc_now(),
            ),
        )

    def metric_summary(self) -> dict[str, Any]:
        """The Spec §15 metric set, computed from the projections we keep."""
        def scalar(sql: str, *params: object) -> float:
            row = self._connection.execute(sql, params).fetchone()
            value = row[0] if row is not None else 0
            return float(value or 0)

        total_steps = scalar("SELECT COUNT(*) FROM steps")
        committed = scalar("SELECT COUNT(*) FROM steps WHERE state = 'COMMITTED'")
        # The buckets come from domain/fsm.py so this cannot disagree with the executions
        # projection or the per-worker counts about what "failed" means.
        placeholders = ",".join("?" for _ in FAILED_STATES)
        failed = scalar(
            f"SELECT COUNT(*) FROM steps WHERE state IN ({placeholders})",
            *sorted(FAILED_STATES),
        )
        retried = scalar("SELECT COUNT(*) FROM steps WHERE attempt > 1")
        gate_rejects = scalar(
            "SELECT COUNT(*) FROM gate_results WHERE decision IN ('FAIL','REVISE','ESCALATE')"
        )
        gate_total = scalar("SELECT COUNT(*) FROM gate_results")
        tokens = scalar("SELECT COALESCE(SUM(value),0) FROM metrics WHERE name = 'llm_tokens'")
        llm_calls = scalar("SELECT COUNT(*) FROM metrics WHERE name = 'llm_calls'")
        llm_latency = scalar(
            "SELECT COALESCE(SUM(value),0) FROM metrics WHERE name = 'llm_latency_ms'"
        )
        sandbox_ms = scalar(
            "SELECT COALESCE(SUM(value),0) FROM metrics WHERE name = 'sandbox_runtime_ms'"
        )
        total_runs = scalar("SELECT COUNT(*) FROM runs")
        completed_runs = scalar(
            "SELECT COUNT(*) FROM runs WHERE status = 'COMPLETED'"
        )
        partial_runs = scalar(
            "SELECT COUNT(*) FROM runs WHERE status = 'PARTIAL_FAILURE'"
        )
        rolled_back = scalar(
            "SELECT COUNT(*) FROM events WHERE event_type = 'RunRolledBack'"
        )
        queue_latency = scalar(
            "SELECT COALESCE(AVG(value),0) FROM metrics WHERE name = 'queue_latency_ms'"
        )
        # CPU-seconds is the honest aggregate available without a container: wall time in the
        # sandbox multiplied by the CPU the boundary allowed for it.
        cpu_seconds = scalar(
            """
            SELECT COALESCE(SUM(m.value / 1000.0 * COALESCE(
                (SELECT MAX(s.cpu_limit) FROM steps st WHERE st.step_id = m.step_id), 1.0
            )), 0)
            FROM metrics m WHERE m.name = 'sandbox_runtime_ms'
            """
        ) if _has_column(self._connection, "steps", "cpu_limit") else sandbox_ms / 1000.0
        peak_parallel = scalar(
            "SELECT COALESCE(MAX(value),0) FROM metrics WHERE name = 'peak_parallel_steps'"
        )
        return {
            "step_total": int(total_steps),
            "step_committed": int(committed),
            "step_failed": int(failed),
            "step_success_rate": (committed / total_steps) if total_steps else 0.0,
            "retry_rate": (retried / total_steps) if total_steps else 0.0,
            "gate_reject_rate": (gate_rejects / gate_total) if gate_total else 0.0,
            "gate_decisions": int(gate_total),
            "llm_calls": int(llm_calls),
            "llm_latency_ms": int(llm_latency),
            "llm_calls_per_run": (llm_calls / max(1, total_runs)),
            "llm_token_usage": int(tokens),
            "sandbox_runtime_ms": int(sandbox_ms),
            # Spec §15 asks for these four and they were missing.
            "run_total": int(total_runs),
            # Computed since the beginning and never reported. A run that committed some
            # steps and failed others is neither a success nor a total failure, and lumping
            # it into either rate hides the outcome an operator most needs to see.
            "run_partial_failure": int(partial_runs),
            "task_success_rate": (completed_runs / total_runs) if total_runs else 0.0,
            "rollback_rate": (rolled_back / total_runs) if total_runs else 0.0,
            "queue_latency_ms": int(queue_latency),
            "resource_usage_cpu_seconds": round(cpu_seconds, 3),
            "peak_parallel_steps": int(peak_parallel),
            "event_count": self.event_count(),
        }

    # ------------------------------------------------------------------ intakes
    # A task intake is the front door: a task, the questions a model asked about it, the
    # answers a human clicked, and the spec those answers froze. It is stored rather than
    # recomputed because "why is this spec like this?" has to be answerable from the record —
    # re-running the model today gives a different answer, which is not evidence about what
    # happened yesterday.

    def save_intake(self, intake: dict[str, Any]) -> None:
        payload = dict(intake)
        for field_name in ("questions", "answers", "rejections"):
            value = payload.get(field_name, [])
            payload[field_name] = json.dumps(value, ensure_ascii=False, sort_keys=True)
        now = utc_now()
        payload.setdefault("created_at", now)
        payload["updated_at"] = now
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO intakes (
                    intake_id, repo_path, objective, model, status, questions, answers,
                    rejections, spec_digest, run_id, created_at, updated_at
                ) VALUES (
                    :intake_id, :repo_path, :objective, :model, :status, :questions, :answers,
                    :rejections, :spec_digest, :run_id, :created_at, :updated_at
                )
                ON CONFLICT(intake_id) DO UPDATE SET
                    status = excluded.status,
                    questions = excluded.questions,
                    answers = excluded.answers,
                    rejections = excluded.rejections,
                    spec_digest = excluded.spec_digest,
                    run_id = excluded.run_id,
                    updated_at = excluded.updated_at
                """,
                payload,
            )

    def get_intake(self, intake_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT * FROM intakes WHERE intake_id = ?", (intake_id,)
        ).fetchone()
        return _intake_row(row) if row else None

    def list_intakes(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM intakes ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_intake_row(row) for row in rows]
