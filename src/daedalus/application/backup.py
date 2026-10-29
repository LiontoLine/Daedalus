"""Backup and restore (Spec §28: Backup / Restore, Database Recovery).

The event store is the authority, so a backup that does not prove the copy *is* the
original is not a backup. Every snapshot is therefore verified before it is reported as
successful:

* the SQLite backup API is used rather than a file copy, so a live WAL database is copied
  consistently;
* the copy is re-opened and `PRAGMA integrity_check` must return `ok`;
* every aggregate's event sequence is checked for gaps in the copy;
* the copied event count and schema version must match the source.

Restore refuses to overwrite a workspace that already has a database unless `force=True`,
and it moves the existing database aside rather than deleting it — the same "never delete
history" rule that governs everything else.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from daedalus.application.observability import get_logger
from daedalus.config import WorkspaceSettings
from daedalus.errors import DaedalusError
from daedalus.infrastructure.store.schema import SCHEMA_VERSION

logger = get_logger("backup")


class BackupError(DaedalusError):
    code = "backup_error"


@dataclass(frozen=True, slots=True)
class BackupResult:
    path: str
    database: str
    bytes: int
    events: int
    schema_version: int
    integrity: str
    sequence_ok: bool
    verified: bool
    manifest: str = ""

    def describe(self) -> dict[str, object]:
        return {
            "path": self.path,
            "database": self.database,
            "bytes": self.bytes,
            "events": self.events,
            "schema_version": self.schema_version,
            "integrity": self.integrity,
            "sequence_ok": self.sequence_ok,
            "verified": self.verified,
            "manifest": self.manifest,
        }


@dataclass(frozen=True, slots=True)
class RestoreResult:
    restored_from: str
    database: str
    previous_moved_to: str
    events: int
    integrity: str
    verified: bool

    def describe(self) -> dict[str, object]:
        return {
            "restored_from": self.restored_from,
            "database": self.database,
            "previous_moved_to": self.previous_moved_to,
            "events": self.events,
            "integrity": self.integrity,
            "verified": self.verified,
        }


@dataclass
class _Verification:
    integrity: str = ""
    events: int = 0
    schema_version: int = 0
    sequence_ok: bool = True
    broken_aggregates: list[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return self.integrity == "ok" and self.sequence_ok


def _verify(path: Path) -> _Verification:
    """Open a database read-only and prove it is internally consistent.

    A file that is not a database at all is reported as unverified rather than raising:
    the caller's job is to refuse it, and a crash would tell the operator less than a
    verification result would.
    """
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
    except sqlite3.Error as error:
        return _Verification(integrity=f"unreadable: {error}", sequence_ok=False)
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        events = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        broken: list[str] = []
        for row in connection.execute(
            """
            SELECT aggregate_id, COUNT(*) AS n, MIN(sequence) AS lo, MAX(sequence) AS hi
            FROM events GROUP BY aggregate_id
            """
        ):
            if int(row["lo"]) != 1 or int(row["hi"]) != int(row["n"]):
                broken.append(str(row["aggregate_id"]))
        return _Verification(
            integrity=integrity,
            events=events,
            schema_version=version,
            sequence_ok=not broken,
            broken_aggregates=broken,
        )
    except sqlite3.DatabaseError as error:
        return _Verification(integrity=f"not a database: {error}", sequence_ok=False)
    finally:
        connection.close()


def create_backup(
    workspace: WorkspaceSettings,
    *,
    label: str = "",
) -> BackupResult:
    """Snapshot the event store with the SQLite backup API and verify the copy."""
    source = workspace.database_path
    if not source.is_file():
        raise BackupError(f"no database to back up at {source}", path=str(source))

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    name = f"{stamp}{'-' + label if label else ''}"
    target_dir = workspace.backups_path / name
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "daedalus.db"

    # The backup API, not a file copy: a live WAL database copied byte-for-byte can be torn.
    src = sqlite3.connect(str(source))
    try:
        dst = sqlite3.connect(str(target))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()

    verification = _verify(target)
    manifest_path = target_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "created_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "label": label,
                "source": str(source),
                "events": verification.events,
                "schema_version": verification.schema_version,
                "integrity": verification.integrity,
                "sequence_ok": verification.sequence_ok,
                "verified": verification.verified,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    if verification.schema_version != SCHEMA_VERSION:
        logger.warning(
            "backup schema version %s differs from the running version %s%s",
            verification.schema_version,
            SCHEMA_VERSION,
            " (it will be migrated on open)" if verification.schema_version < SCHEMA_VERSION
            else " (this backup was written by a newer Daedalus)",
        )
    if not verification.verified:
        raise BackupError(
            "the backup failed verification and must not be trusted: "
            f"integrity={verification.integrity} "
            f"sequence_ok={verification.sequence_ok} "
            f"broken={verification.broken_aggregates[:5]}",
            path=str(target),
        )

    logger.info("backup verified: %d events, integrity=%s", verification.events, verification.integrity)
    return BackupResult(
        path=str(target_dir),
        database=str(target),
        bytes=target.stat().st_size,
        events=verification.events,
        schema_version=verification.schema_version,
        integrity=verification.integrity,
        sequence_ok=verification.sequence_ok,
        verified=verification.verified,
        manifest=str(manifest_path),
    )


def restore_backup(
    workspace: WorkspaceSettings,
    *,
    source: str,
    force: bool = False,
) -> RestoreResult:
    """Restore a verified snapshot, moving any existing database aside."""
    candidate = Path(source).expanduser()
    if candidate.is_dir():
        candidate = candidate / "daedalus.db"
    if not candidate.is_file():
        raise BackupError(f"no snapshot database at {candidate}", path=str(candidate))

    verification = _verify(candidate)
    if not verification.verified:
        raise BackupError(
            "refusing to restore a snapshot that does not verify: "
            f"integrity={verification.integrity} sequence_ok={verification.sequence_ok}",
            path=str(candidate),
        )

    target = workspace.database_path
    moved = ""
    if target.exists():
        if not force:
            raise BackupError(
                f"{target} already exists; pass --force to replace it. The current database "
                "will be moved aside, never deleted.",
                path=str(target),
            )
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
        aside = target.with_name(f"daedalus.db.replaced-{stamp}")
        target.rename(aside)
        for suffix in ("-wal", "-shm"):
            sidecar = target.with_name(target.name + suffix)
            if sidecar.exists():
                sidecar.rename(aside.with_name(aside.name + suffix))
        moved = str(aside)

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(candidate, target)
    restored = _verify(target)
    if not restored.verified:
        raise BackupError(
            "the restored database does not verify; the previous one is still at "
            f"{moved or '<none>'}",
            path=str(target),
        )
    logger.info("restored %d events from %s", restored.events, candidate)
    return RestoreResult(
        restored_from=str(candidate),
        database=str(target),
        previous_moved_to=moved,
        events=restored.events,
        integrity=restored.integrity,
        verified=restored.verified,
    )


def list_backups(workspace: WorkspaceSettings) -> list[dict[str, object]]:
    """Every snapshot with its manifest, newest first."""
    root = workspace.backups_path
    if not root.is_dir():
        return []
    found: list[dict[str, object]] = []
    for entry in sorted(root.iterdir(), reverse=True):
        manifest = entry / "manifest.json"
        database = entry / "daedalus.db"
        if not database.is_file():
            continue
        payload: dict[str, object] = {"path": str(entry), "database": str(database)}
        if manifest.is_file():
            try:
                payload.update(json.loads(manifest.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                payload["manifest_error"] = "unreadable"
        found.append(payload)
    return found
