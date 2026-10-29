# ruff: noqa: RUF001
"""A rebuildable, repository-scoped vector index; never an authority for task state.

The bounded local corpus uses exact cosine search over persisted float32 vectors.
This is deliberately not advertised as an ANN engine or a Qdrant deployment.
"""

from __future__ import annotations

import importlib.util
import math
import os
import sqlite3
import struct
import threading
from contextlib import closing
from importlib.metadata import version
from pathlib import Path

from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import utc_now
from daedalus.errors import DaedalusError
from daedalus.infrastructure.knowledge import atomic_json
from daedalus.security.outbound import assert_outbound_clean

DEFAULT_EMBEDDING = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


class EmbeddingUnavailable(DaedalusError):
    code = "retrieval_embedding_unavailable"


def normalized(values) -> list[float]:
    vector = [float(value) for value in values]
    if not vector or len(vector) > 8192 or not all(math.isfinite(v) for v in vector):
        raise ValueError("invalid embedding vector")
    norm = math.sqrt(math.fsum(v * v for v in vector))
    if not math.isfinite(norm) or norm == 0:
        raise ValueError("invalid embedding norm")
    return [v / norm for v in vector]


class FastEmbedEncoder:
    """Optional local inference. Normal task execution never downloads weights."""

    def __init__(self, cache: Path, *, download: bool = False):
        try:
            from fastembed import TextEmbedding
        except ImportError:
            raise EmbeddingUnavailable(
                "缺少本地 embedding 依赖，请先安装项目的 retrieval 可选依赖"
            ) from None
        self.model_id = f"fastembed:{version('fastembed')}:{DEFAULT_EMBEDDING}"
        try:
            self.model = TextEmbedding(
                model_name=DEFAULT_EMBEDDING,
                cache_dir=str(cache),
                threads=2,
                local_files_only=not download,
            )
        except Exception:  # noqa: BLE001 - don't echo third-party paths, URLs or credentials
            raise EmbeddingUnavailable("本地语义模型尚未准备好，请先准备模型文件") from None

    def documents(self, texts: list[str]) -> list[list[float]]:
        return [normalized(vector) for vector in self.model.passage_embed(texts, batch_size=16)]

    def query(self, text: str) -> list[float]:
        return normalized(next(self.model.query_embed(text)))


class SQLiteVectorIndex:
    """Atomic snapshot replacement plus incremental embedding reuse, at <=1000 chunks."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        connection = sqlite3.connect(self.path, timeout=20)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS embeddings (
                scope TEXT NOT NULL, model TEXT NOT NULL, content_digest TEXT NOT NULL,
                dimension INTEGER NOT NULL, vector BLOB NOT NULL,
                PRIMARY KEY(scope, model, content_digest));
            CREATE TABLE IF NOT EXISTS entries (
                scope TEXT NOT NULL, model TEXT NOT NULL, citation_id TEXT NOT NULL,
                content_digest TEXT NOT NULL, snapshot TEXT NOT NULL,
                PRIMARY KEY(scope, model, citation_id),
                FOREIGN KEY(scope, model, content_digest)
                    REFERENCES embeddings(scope, model, content_digest));
            CREATE TABLE IF NOT EXISTS epochs (scope TEXT PRIMARY KEY,generation INTEGER NOT NULL);
        """)
        return connection

    def retrieve(
        self,
        repo: str,
        corpus: list[dict],
        query: str,
        encoder,
        *,
        kind: str = "",
        limit: int = 30,
        expected_epoch: int | None = None,
    ) -> tuple[list[dict], dict]:
        if len(corpus) > 1000:
            raise ValueError("local vector corpus exceeds 1000 chunks")
        assert_outbound_clean(query, where="embedding query")
        scope = digest_of(str(Path(repo).resolve()))
        documents = {}
        for row in corpus:
            text = row["title"] + "\n" + row["text"]
            assert_outbound_clean(text, where="embedding source")
            documents[row["id"]] = (digest_of(text), text)
        snapshot = digest_of(sorted((key, value[0]) for key, value in documents.items()))
        with self._lock, closing(self._connect()) as connection:
            actual_epoch = connection.execute(
                "SELECT generation FROM epochs WHERE scope=?", (scope,)
            ).fetchone()
            actual_epoch = actual_epoch[0] if actual_epoch else 0
            if expected_epoch is None:
                expected_epoch = actual_epoch
            cached = {
                row[0]: (row[1], row[2])
                for row in connection.execute(
                    "SELECT content_digest,dimension,vector FROM embeddings "
                    "WHERE scope=? AND model=?",
                    (scope, encoder.model_id),
                )
            }
            unique = dict(value for value in documents.values())
            missing = {key: text for key, text in unique.items() if key not in cached}
            generated = encoder.documents(list(missing.values())) if missing else []
            if len(generated) != len(missing):
                raise ValueError("embedding response count mismatch")
            query_vector = normalized(encoder.query(query))
            dimension = len(query_vector)
            fresh = {}
            for key, raw in zip(missing, generated, strict=True):
                vector = normalized(raw)
                if len(vector) != dimension:
                    raise ValueError("embedding dimension mismatch")
                fresh[key] = (dimension, struct.pack(f"<{dimension}f", *vector))
            if any(cached[key][0] != dimension for key in unique if key in cached):
                raise ValueError("cached embedding model dimension changed")
            previous = connection.execute(
                "SELECT COUNT(*) FROM entries WHERE scope=? AND model=?", (scope, encoder.model_id)
            ).fetchone()[0]
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                generation = connection.execute(
                    "SELECT generation FROM epochs WHERE scope=?", (scope,)
                ).fetchone()
                if (generation[0] if generation else 0) != expected_epoch:
                    raise EmbeddingUnavailable("项目资料已变化，请重新检索当前版本")
                connection.executemany(
                    "INSERT OR IGNORE INTO embeddings VALUES (?,?,?,?,?)",
                    [
                        (scope, encoder.model_id, key, dims, vector)
                        for key, (dims, vector) in fresh.items()
                    ],
                )
                connection.execute(
                    "DELETE FROM entries WHERE scope=? AND model=?", (scope, encoder.model_id)
                )
                connection.executemany(
                    "INSERT INTO entries VALUES (?,?,?,?,?)",
                    [
                        (scope, encoder.model_id, key, content, snapshot)
                        for key, (content, _) in documents.items()
                    ],
                )
                connection.execute(
                    """DELETE FROM embeddings WHERE scope=? AND model=?
                    AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.scope=embeddings.scope
                    AND e.model=embeddings.model AND e.content_digest=embeddings.content_digest)""",
                    (scope, encoder.model_id),
                )
                snapshot_rows = connection.execute(
                    """SELECT e.citation_id,v.dimension,v.vector
                    FROM entries e JOIN embeddings v USING(scope,model,content_digest)
                    WHERE e.scope=? AND e.model=?""",
                    (scope, encoder.model_id),
                ).fetchall()
                if any(dims != dimension for _, dims, _ in snapshot_rows):
                    raise ValueError("concurrent embedding dimension mismatch")
            scored = []
            current = {row["id"]: row for row in corpus if not kind or row["kind"] == kind}
            for key, dims, raw in snapshot_rows:
                if key not in current:
                    continue
                vector = struct.unpack(f"<{dims}f", raw)
                score = math.fsum(a * b for a, b in zip(query_vector, vector, strict=True))
                scored.append({**current[key], "vector_score": round(score, 7)})
            return sorted(scored, key=lambda row: (-row["vector_score"], row["id"]))[:limit], {
                "backend": "sqlite_exact_cosine",
                "model": encoder.model_id,
                "snapshot": snapshot,
                "indexed_chunks": len(documents),
                "new_embeddings": len(fresh),
                "reused_embeddings": len(unique) - len(fresh),
                "previous_entries": previous,
                "dimension": dimension,
            }

    def invalidate(self, repo: str) -> None:
        scope = digest_of(str(Path(repo).resolve()))
        with self._lock, closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM entries WHERE scope=?", (scope,))
            connection.execute("DELETE FROM embeddings WHERE scope=?", (scope,))
            connection.execute(
                """INSERT INTO epochs VALUES (?,1) ON CONFLICT(scope)
                               DO UPDATE SET generation=generation+1""",
                (scope,),
            )

    def epoch(self, repo: str) -> int:
        if not self.path.exists():
            return 0
        scope = digest_of(str(Path(repo).resolve()))
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT generation FROM epochs WHERE scope=?", (scope,)
            ).fetchone()
            return row[0] if row else 0


class LocalRetrievalRuntime:
    """Workspace-local setup, lazy loading and honest readiness reporting."""

    def __init__(self, root: Path, *, encoder_factory=FastEmbedEncoder):
        self.root = root
        self.index = SQLiteVectorIndex(root / "vectors.sqlite")
        self.factory = encoder_factory
        self.encoder = None
        self.error_code = ""
        self._lock = threading.RLock()

    @property
    def enabled(self) -> bool:
        path = self.root / "settings.json"
        if not path.exists():
            return False
        try:
            import json

            return json.loads(path.read_text()).get("enabled") is True
        except (OSError, ValueError, AttributeError):
            return False

    def status(self) -> dict:
        installed = importlib.util.find_spec("fastembed") is not None
        enabled = self.enabled
        if self.error_code and enabled:
            state = "error"
        elif self.encoder is not None and enabled:
            state = "ready"
        elif not installed:
            state = "missing_dependency"
        else:
            state = "configured" if enabled else "disabled"
        return {
            "enabled": enabled,
            "dependency_installed": installed,
            "model_loaded": self.encoder is not None,
            "embedding_model": DEFAULT_EMBEDDING,
            "backend": "sqlite_exact_cosine",
            "max_chunks": 1000,
            "state": state,
            "error_code": self.error_code,
            "setup_command": "python3 -m pip install -e '.[retrieval]'",
        }

    def prepare(self, *, download: bool = False, enabled: bool = True) -> dict:
        with self._lock:
            if not enabled:
                self.encoder = None
                self.error_code = ""
                atomic_json(self.root / "settings.json", {"enabled": False})
                return self.status()
            try:
                encoder = self.factory(self.root / "models", download=download)
                dimension = len(normalized(encoder.query("semantic retrieval readiness")))
            except Exception as error:  # noqa: BLE001 - optional inference has no authority
                self.error_code = getattr(error, "code", "retrieval_model_setup_failed")
                raise EmbeddingUnavailable("本地语义模型准备失败，请检查依赖和模型文件") from None
            self.encoder, self.error_code = encoder, ""
            atomic_json(
                self.root / "settings.json",
                {
                    "enabled": True,
                    "model": encoder.model_id,
                    "dimension": dimension,
                    "prepared_at": utc_now(),
                },
            )
            return self.status()

    def search(self, repo, corpus, query, *, kind="", limit=30, expected_epoch=None):
        if not self.enabled:
            raise EmbeddingUnavailable("本地语义检索尚未启用")
        with self._lock:
            if not self.enabled:
                raise EmbeddingUnavailable("本地语义检索尚未启用")
            try:
                if self.encoder is None:
                    self.encoder = self.factory(self.root / "models", download=False)
                result = self.index.retrieve(
                    repo,
                    corpus,
                    query,
                    self.encoder,
                    kind=kind,
                    limit=limit,
                    expected_epoch=expected_epoch,
                )
                self.error_code = ""
                return result
            except Exception as error:
                self.error_code = getattr(error, "code", "retrieval_vector_failed")
                raise
