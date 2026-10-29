"""Repository-scoped, removable user knowledge, separate from authoritative events."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import new_id, utc_now
from daedalus.errors import DaedalusError
from daedalus.security.outbound import assert_outbound_clean


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + new_id("write"))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output, ensure_ascii=False, allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class KnowledgeStore:
    def __init__(self, root: Path):
        self.root = root
        self._lock = threading.RLock()

    @staticmethod
    def repository(repo: str) -> str:
        path = Path(repo).expanduser().resolve()
        if not (path / ".git").exists():
            raise DaedalusError("knowledge requires a Git repository")
        return str(path)

    def directory(self, repo: str) -> Path:
        return self.root / digest_of(self.repository(repo))

    def records(self, repo: str) -> list[dict]:
        with self._lock:
            path = self.directory(repo) / "records.json"
            if not path.exists():
                return []
            try:
                records = json.loads(path.read_text())["records"]
                if not isinstance(records, list):
                    raise ValueError("invalid records")
                for record in records:
                    expected = digest_of({k: record[k] for k in ("kind", "title", "text")})
                    if record["digest"] != expected:
                        raise ValueError("knowledge digest mismatch")
                return records
            except (ValueError, KeyError, TypeError) as error:
                raise DaedalusError("knowledge storage is invalid; repair or remove it") from error

    def add(self, repo: str, *, kind: str, title: str, text: str, confirmed: bool) -> dict:
        if kind not in {"document", "preference"} or not confirmed:
            raise DaedalusError("knowledge must be explicitly confirmed as document or preference")
        if not title.strip() or not text.strip() or len(title) > 160 or len(text) > 24_000:
            raise DaedalusError("knowledge needs a title (160 chars) and text (24000 chars)")
        body = {"kind": kind, "title": title.strip(), "text": text.strip()}
        assert_outbound_clean(json.dumps(body), where="saved project knowledge")
        with self._lock:
            records = self.records(repo)
            if len(records) >= 100:
                raise DaedalusError("project knowledge limit reached (100 records)")
            record = {
                **body,
                "id": new_id("knowledge"),
                "digest": digest_of(body),
                "confirmed": True,
                "created_at": utc_now(),
            }
            records.append(record)
            atomic_json(self.directory(repo) / "records.json", {"records": records})
            return record

    def delete(self, repo: str, record_id: str) -> bool:
        with self._lock:
            records = self.records(repo)
            remaining = [r for r in records if r["id"] != record_id]
            if len(remaining) == len(records):
                return False
            atomic_json(self.directory(repo) / "records.json", {"records": remaining})
            return True

    def save_trace(self, repo: str, trace: dict) -> None:
        with self._lock:
            directory = self.directory(repo) / "traces"
            atomic_json(directory / (trace["trace_id"] + ".json"), trace)
            # Bounded projection, never used to decide a gate or recover a task.
            for path in sorted(
                directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
            )[100:]:
                path.unlink(missing_ok=True)

    def traces(self, repo: str, limit: int = 10) -> list[dict]:
        with self._lock:
            directory = self.directory(repo) / "traces"
            paths = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[
                :limit
            ]
            return [json.loads(path.read_text()) for path in paths]
