"""Real SQLite persistence with controlled vectors, not a semantic-quality benchmark."""

import json
import sqlite3
import sys
import types
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

import pytest
from fastapi.testclient import TestClient

from daedalus.application.agentic_rag import citation
from daedalus.config import Settings, WorkspaceSettings
from daedalus.infrastructure.vector_index import (
    EmbeddingUnavailable,
    FastEmbedEncoder,
    LocalRetrievalRuntime,
    SQLiteVectorIndex,
)
from daedalus.security.outbound import SecretInPayload
from daedalus.service.app import create_app


class ControlledEncoder:
    """Known test geometry. Never used by the production runtime."""

    model_id = "controlled-test-vectors-v1"

    def __init__(self):
        self.encoded = []
        self.queries = []

    def documents(self, texts):
        self.encoded.extend(texts)
        return [[1.0, 0.0] if "checkpoint" in text else [0.0, 1.0] for text in texts]

    def query(self, text):
        self.queries.append(text)
        return [1.0, 0.0]


def document(text, *, source="git:commit:README.md", kind="document"):
    return citation({"kind": kind, "source": source, "title": "Reference", "text": text})


def rows(path, table):
    with sqlite3.connect(path) as connection:
        return connection.execute(f"SELECT * FROM {table}").fetchall()


def test_vectors_survive_reopen_and_changed_commit_reuses_content(tmp_path):
    path = tmp_path / "index.sqlite"
    encoder = ControlledEncoder()
    first = [document("checkpoint recovery"), document("UI theme", source="git:commit:ui.md")]
    hits, receipt = SQLiteVectorIndex(path).retrieve(str(tmp_path), first, "recover", encoder)
    assert hits[0]["text"] == "checkpoint recovery" and receipt["new_embeddings"] == 2
    assert path.stat().st_mode & 0o777 == 0o600
    assert b"checkpoint" not in path.read_bytes()  # no document plaintext in vector storage

    second = [document("checkpoint recovery", source="git:new-head:README.md")]
    hits, receipt = SQLiteVectorIndex(path).retrieve(str(tmp_path), second, "recover", encoder)
    assert receipt["new_embeddings"] == 0 and receipt["reused_embeddings"] == 1
    assert hits[0]["source"] == "git:new-head:README.md"
    assert len(encoder.encoded) == 2 and len(rows(path, "entries")) == 1
    assert len(rows(path, "embeddings")) == 1  # removed document vectors purged


def test_repository_and_model_spaces_are_isolated(tmp_path):
    path = tmp_path / "index.sqlite"
    index = SQLiteVectorIndex(path)
    encoder = ControlledEncoder()
    alpha = [document("checkpoint alpha")]
    beta = [document("UI beta", kind="preference")]
    index.retrieve(str(tmp_path / "alpha"), alpha, "recover", encoder)
    hits, _ = index.retrieve(str(tmp_path / "beta"), beta, "recover", encoder, kind="document")
    assert hits == []
    assert len(rows(path, "entries")) == 2
    index.invalidate(str(tmp_path / "alpha"))
    assert len(rows(path, "entries")) == len(rows(path, "embeddings")) == 1
    assert rows(path, "entries")[0][2] == beta[0]["id"]
    encoder.model_id = "new-test-model"
    _, receipt = index.retrieve(str(tmp_path / "beta"), beta, "recover", encoder)
    assert receipt["new_embeddings"] == 1


@pytest.mark.parametrize(
    "invalid", [[], [0.0, 0.0], [float("nan"), 1.0], [float("inf"), 1.0], [1.0, 0.0, 0.0]]
)
def test_invalid_embeddings_do_not_replace_a_good_snapshot(tmp_path, invalid):
    index = SQLiteVectorIndex(tmp_path / "vectors.sqlite")
    encoder = ControlledEncoder()
    index.retrieve(str(tmp_path), [document("checkpoint")], "recover", encoder)
    before = rows(index.path, "entries"), rows(index.path, "embeddings")
    encoder.documents = lambda texts: [invalid for _ in texts]
    with pytest.raises(ValueError):
        index.retrieve(str(tmp_path), [document("a changed source")], "recover", encoder)
    assert (rows(index.path, "entries"), rows(index.path, "embeddings")) == before


def test_secret_never_reaches_embedding_inference_or_disk(tmp_path):
    encoder = ControlledEncoder()
    index = SQLiteVectorIndex(tmp_path / "vectors.sqlite")
    with pytest.raises(SecretInPayload):
        index.retrieve(str(tmp_path), [document("sk-" + "a" * 30)], "recover", encoder)
    assert not encoder.encoded and not index.path.exists()


def test_two_index_instances_return_their_own_atomic_snapshot(tmp_path):
    path = tmp_path / "vectors.sqlite"
    barrier = Barrier(2)

    class ConcurrentEncoder(ControlledEncoder):
        def documents(self, texts):
            barrier.wait(timeout=5)
            return super().documents(texts)

    def query(name):
        current = [document("checkpoint " + name)]
        hits, _ = SQLiteVectorIndex(path).retrieve(
            str(tmp_path), current, "recover", ConcurrentEncoder()
        )
        return hits[0]["text"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(query, ["alpha", "beta"]))
    assert results == ["checkpoint alpha", "checkpoint beta"]
    assert len(rows(path, "entries")) == len(rows(path, "embeddings")) == 1


def test_inflight_embedding_cannot_resurrect_a_deleted_project_snapshot(tmp_path):
    path = tmp_path / "vectors.sqlite"
    began, proceed = Event(), Event()

    class PausedEncoder(ControlledEncoder):
        def documents(self, texts):
            began.set()
            assert proceed.wait(timeout=5)
            return super().documents(texts)

    index = SQLiteVectorIndex(path)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            index.retrieve,
            str(tmp_path),
            [document("checkpoint private")],
            "recover",
            PausedEncoder(),
        )
        assert began.wait(timeout=5)
        SQLiteVectorIndex(path).invalidate(str(tmp_path))
        proceed.set()
        with pytest.raises(EmbeddingUnavailable):
            future.result(timeout=5)
    assert rows(path, "entries") == rows(path, "embeddings") == []


def test_stale_corpus_epoch_is_refused_even_when_search_starts_after_deletion(tmp_path):
    index = SQLiteVectorIndex(tmp_path / "vectors.sqlite")
    epoch = index.epoch(str(tmp_path))
    index.invalidate(str(tmp_path))
    with pytest.raises(EmbeddingUnavailable):
        index.retrieve(
            str(tmp_path),
            [document("checkpoint private")],
            "recover",
            ControlledEncoder(),
            expected_epoch=epoch,
        )
    assert rows(index.path, "entries") == []


def test_normal_startup_never_downloads_and_reopens_offline(tmp_path):
    calls = []
    encoder = ControlledEncoder()

    def factory(cache, *, download):
        calls.append(download)
        return encoder

    runtime = LocalRetrievalRuntime(tmp_path / "retrieval", encoder_factory=factory)
    assert not calls and not runtime.enabled
    runtime.prepare(download=True)
    assert calls == [True]
    reopened = LocalRetrievalRuntime(runtime.root, encoder_factory=factory)
    reopened.search(str(tmp_path), [document("checkpoint")], "recover")
    assert calls == [True, False]
    reopened.prepare(enabled=False)
    with pytest.raises(EmbeddingUnavailable):
        reopened.search(str(tmp_path), [document("checkpoint")], "recover")
    assert calls == [True, False]


def test_cold_load_failure_is_visible_in_readiness_instead_of_claiming_ready(tmp_path):
    runtime = LocalRetrievalRuntime(
        tmp_path / "retrieval", encoder_factory=lambda *a, **k: ControlledEncoder()
    )
    runtime.prepare()

    def unavailable(*args, **kwargs):
        raise EmbeddingUnavailable("model cache was removed")

    reopened = LocalRetrievalRuntime(runtime.root, encoder_factory=unavailable)
    with pytest.raises(EmbeddingUnavailable):
        reopened.search(str(tmp_path), [document("checkpoint")], "recover")
    assert reopened.status()["state"] == "error"
    assert reopened.status()["model_loaded"] is False
    reopened.prepare(enabled=False)
    assert not reopened.enabled and reopened.status()["state"] != "error"


def test_asgi_setup_index_query_and_delete_are_consistent(git_repo, tmp_path):
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    state = app.state.daedalus
    encoder = ControlledEncoder()
    state.retrieval.factory = lambda cache, download=False: encoder
    with TestClient(app) as client:
        assert client.get("/api/knowledge/retrieval/status").json()["enabled"] is False
        assert (
            client.post("/api/knowledge/retrieval/setup", json={"enabled": True}).status_code == 200
        )
        record = client.post(
            "/api/knowledge",
            json={
                "repo_path": str(git_repo),
                "kind": "preference",
                "title": "Recovery",
                "text": "checkpoint recovery",
                "confirmed": True,
            },
        ).json()["record"]
        response = client.post("/api/knowledge/retrieval/index", json={"repo_path": str(git_repo)})
        assert response.status_code == 200, response.text
        assert response.json()["indexed_chunks"] > 0
        response = client.post(
            "/api/knowledge/retrieve",
            json={
                "repo_path": str(git_repo),
                "query": "checkpoint",
                "mode": "hybrid",
                "use_model": False,
            },
        )
        assert response.status_code == 200, response.text
        trace = response.json()
        assert trace["capabilities"] == {"vector_recall": True, "semantic_reranker": False}
        assert trace["actions"][0]["channels"]["vector"] > 0
        assert (
            client.delete(
                f"/api/knowledge/{record['id']}", params={"repo_path": str(git_repo)}
            ).status_code
            == 200
        )
        assert rows(state.retrieval.index.path, "entries") == []
        assert rows(state.retrieval.index.path, "embeddings") == []


def test_setup_failure_is_honest_and_does_not_echo_private_error(git_repo, tmp_path):
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))

    def broken(*args, **kwargs):
        raise RuntimeError("private transport detail")

    app.state.daedalus.retrieval.factory = broken
    with TestClient(app) as client:
        response = client.post("/api/knowledge/retrieval/setup", json={"enabled": True})
        assert response.status_code == 409 and "private" not in response.text
        assert response.json()["detail"]["status"]["enabled"] is False


def test_direct_search_does_not_require_unused_model_configuration(git_repo, tmp_path):
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    app.state.daedalus.build_model_client = lambda *a: pytest.fail("local search requested a model")
    with TestClient(app) as client:
        response = client.post(
            "/api/knowledge/retrieve",
            json={
                "repo_path": str(git_repo),
                "query": "summarize",
                "mode": "grep",
                "use_model": True,
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["route"] == "grep"


def test_fastembed_adapter_uses_document_query_encoders_and_explicit_download_flag(
    tmp_path, monkeypatch
):
    created = []

    class Model:
        def __init__(self, **kwargs):
            created.append(kwargs)

        def passage_embed(self, texts, *, batch_size):
            assert batch_size == 16
            return iter([[3.0, 4.0] for _ in texts])

        def query_embed(self, text):
            return iter([[3.0, 4.0]])

    module = types.ModuleType("fastembed")
    module.TextEmbedding = Model
    monkeypatch.setitem(sys.modules, "fastembed", module)
    monkeypatch.setattr("daedalus.infrastructure.vector_index.version", lambda name: "test-version")
    offline = FastEmbedEncoder(tmp_path)
    assert offline.documents(["text"]) == [[0.6, 0.8]]
    assert offline.query("query") == [0.6, 0.8]
    FastEmbedEncoder(tmp_path, download=True)
    assert [row["local_files_only"] for row in created] == [True, False]


def test_fastembed_failure_does_not_echo_third_party_exception(tmp_path, monkeypatch):
    module = types.ModuleType("fastembed")

    def broken(**kwargs):
        raise RuntimeError("private library failure")

    module.TextEmbedding = broken
    monkeypatch.setitem(sys.modules, "fastembed", module)
    monkeypatch.setattr("daedalus.infrastructure.vector_index.version", lambda name: "test-version")
    with pytest.raises(EmbeddingUnavailable) as failure:
        FastEmbedEncoder(tmp_path)
    assert "private" not in str(failure.value)
