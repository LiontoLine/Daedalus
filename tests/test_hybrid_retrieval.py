"""Hybrid stage attribution, bounded reranking and tool-based investigation."""

import json

import pytest

from daedalus.application.agentic_rag import AgenticRAG, citation, search
from daedalus.application.hybrid_retrieval import HybridRetriever, reciprocal_rank_fusion
from daedalus.infrastructure.knowledge import KnowledgeStore
from daedalus.infrastructure.retrieval_tools import RepositorySearch
from daedalus.infrastructure.store import EventStore
from daedalus.infrastructure.vector_index import LocalRetrievalRuntime
from daedalus.model.base import Completion, TokenBudget
from tests.test_retrieval_tools import commit
from tests.test_vector_retrieval import ControlledEncoder, document


class NoCode:
    def grep(self, *args, **kwargs):
        return []


class Ranker:
    def __init__(self, ids=None):
        self.ids = ids
        self.calls = []

    def complete(self, messages, **kwargs):
        self.calls.append(messages)
        candidates = json.loads(messages[-1].content)["candidates"]
        ids = self.ids if self.ids is not None else [candidates[-1]["id"]]
        return Completion(json.dumps({"ranked_ids": ids}), prompt_tokens=80, completion_tokens=20)


def ready(tmp_path):
    runtime = LocalRetrievalRuntime(
        tmp_path / "retrieval", encoder_factory=lambda *a, **k: ControlledEncoder()
    )
    runtime.prepare()
    return runtime


def test_rrf_merges_rank_positions_and_deduplicates_same_source_text():
    alpha, beta = document("checkpoint"), document("theme")
    duplicate = {**alpha, "id": "another-window-id"}
    fused = reciprocal_rank_fusion(
        {"lexical": [alpha, beta], "vector": [beta, alpha], "code": [duplicate, duplicate]}
    )
    assert len(fused) == 2 and fused[0]["text"] == "checkpoint"
    assert fused[0]["channel_ranks"] == {"lexical": 1, "vector": 2, "code": 1}


def test_reranking_uses_only_actual_candidates_and_charges_budget(tmp_path):
    runtime = ready(tmp_path)
    corpus = [document("checkpoint"), document("UI theme")]
    pipeline = HybridRetriever(runtime, lexical_search=search, make_citation=citation)
    model, budget = Ranker(), TokenBudget()
    ranked, receipt = pipeline.retrieve(
        str(tmp_path), corpus, "checkpoint", NoCode(), client=model, budget=budget
    )
    assert receipt["vector"] and receipt["rerank"]["used"]
    assert ranked[0]["id"] == json.loads(model.calls[0][-1].content)["candidates"][-1]["id"]
    assert budget.run_used == 100 and budget.calls == 1
    assert set(r["id"] for r in ranked) <= {r["id"] for r in corpus}
    assert receipt["channels"] == {"lexical": 1, "code": 0, "vector": 2}


@pytest.mark.parametrize("ids", [["invented"], ["same", "same"], "not a list"])
def test_invalid_ranker_cannot_invent_or_remove_coarse_evidence(tmp_path, ids):
    pipeline = HybridRetriever(ready(tmp_path), lexical_search=search, make_citation=citation)
    model, budget = Ranker(ids), TokenBudget()
    corpus = [document("checkpoint"), document("UI theme")]
    ranked, receipt = pipeline.retrieve(
        str(tmp_path), corpus, "checkpoint", NoCode(), client=model, budget=budget
    )
    assert not receipt["rerank"]["used"] and ranked
    assert set(r["id"] for r in ranked) <= {r["id"] for r in corpus}
    assert budget.run_used == 100


def test_rerank_budget_and_call_limit_preserve_coarse_results(tmp_path):
    pipeline = HybridRetriever(ready(tmp_path), lexical_search=search, make_citation=citation)
    corpus = [document("checkpoint"), document("UI theme")]
    model = Ranker()
    ranked, receipt = pipeline.retrieve(
        str(tmp_path),
        corpus,
        "checkpoint",
        NoCode(),
        client=model,
        budget=TokenBudget(max_tokens_per_step=1),
    )
    assert ranked and receipt["rerank"]["reason"] == "budget_limit" and not model.calls
    for _ in range(3):
        ranked, receipt = pipeline.retrieve(
            str(tmp_path), corpus, "checkpoint", NoCode(), client=model
        )
    assert len(model.calls) == 2 and receipt["rerank"]["reason"] == "rerank_call_limit"


def test_vector_unavailability_is_recorded_without_claiming_it_was_used(tmp_path):
    runtime = LocalRetrievalRuntime(tmp_path / "retrieval")
    pipeline = HybridRetriever(runtime, lexical_search=search, make_citation=citation)
    ranked, receipt = pipeline.retrieve(
        str(tmp_path), [document("checkpoint")], "checkpoint", NoCode()
    )
    assert ranked and receipt["vector"] is None
    assert receipt["vector_error"] == "retrieval_embedding_unavailable"
    assert "vector" not in receipt["channels"]


def test_vector_payload_cannot_inject_foreign_or_forged_citation_text(tmp_path):
    legitimate = document("checkpoint")

    class PoisonedStore:
        def search(self, *args, **kwargs):
            return [
                {**legitimate, "text": "FOREIGN PRIVATE CONTENT"},
                {"id": "forged", "text": "ANOTHER PROJECT"},
            ], {"backend": "test-double"}

    pipeline = HybridRetriever(PoisonedStore(), lexical_search=search, make_citation=citation)
    ranked, receipt = pipeline.retrieve(str(tmp_path), [legitimate], "checkpoint", NoCode())
    assert len(ranked) == 1 and ranked[0]["text"] == "checkpoint"
    assert receipt["channels"]["vector"] == 1


def test_simple_task_does_not_open_enabled_vector_index_or_call_ranker(git_repo, tmp_path):
    commit(git_repo, **{"engine.py": "def advance_cursor():\n    return 7\n"})
    runtime = ready(tmp_path)
    runtime.search = lambda *a, **k: pytest.fail("simple task entered vector stage")
    with EventStore(tmp_path / "events.db") as store:
        model, budget = Ranker(), TokenBudget()
        rag = AgenticRAG(KnowledgeStore(tmp_path / "knowledge"), store, retrieval=runtime)
        trace = rag.retrieve(
            str(git_repo),
            "advance_cursor",
            mode="auto",
            phase="execution",
            target_paths=("engine.py",),
            client=model,
            budget=budget,
        )
        assert trace["route"] == "grep" and trace["citations"]
        assert not model.calls and budget.calls == 0
        assert trace["capabilities"] == {"vector_recall": False, "semantic_reranker": False}


def test_ast_symbols_and_local_markdown_links_are_real_read_only_context(git_repo, tmp_path):
    commit(
        git_repo,
        **{
            "engine.py": "def advance_cursor():\n    return 7\n",
            "consumer.py": "from engine import advance_cursor\nanswer = advance_cursor()\n",
            "README.md": "# Entry\n[Design](docs/design.md#checkpoint) [remote](https://example.com) [escape](../../outside.md)\n",
            "docs/design.md": "# Design\nintro\n## Checkpoint\nPersist cursor before restart.\n",
        },
    )
    tools = RepositorySearch(str(git_repo))
    hits = tools.symbol("advance_cursor")
    assert {row["relation"] for row in hits} == {"definition", "caller"}
    origin = tools.read("README.md")
    linked = tools.follow_link(origin)
    assert linked["path"] == "docs/design.md" and linked["line_start"] == 3
    assert tools.follow_link(origin, 1) is tools.follow_link(origin, 2) is None
    chunks = tools.code_chunks()
    assert any(row["symbol"] == "advance_cursor" and "return 7" in row["text"] for row in chunks)


def test_empty_tool_result_can_be_followed_by_a_different_investigation(git_repo, tmp_path):
    from tests.test_agentic_rag import Controller

    commit(
        git_repo,
        **{
            "README.md": "# Cursor\nInvestigate cursor storage.\n",
            "engine.py": "def advance_cursor():\n    return 7\n",
        },
    )
    with EventStore(tmp_path / "events.db") as store:
        rag = AgenticRAG(KnowledgeStore(tmp_path / "knowledge"), store)
        model = Controller(
            [
                {"action": "read", "path": "missing.py"},
                {"action": "symbol", "name": "advance_cursor"},
                {"action": "finish", "note": "definition found"},
            ]
        )
        trace = rag.retrieve(str(git_repo), "cursor storage", client=model)
        assert trace["stop_reason"] == "agent_finished" and len(model.calls) == 3
        assert trace["actions"][1]["hits"] == 0 and trace["actions"][2]["hits"] > 0
        assert '"hits": 0' in model.calls[1][-1].content


def test_hybrid_recall_rank_and_multi_hop_tools_form_one_observable_loop(git_repo, tmp_path):
    commit(
        git_repo,
        **{
            "README.md": "# Checkpoint\nRead [design](docs/design.md#checkpoint).\n",
            "docs/design.md": "# Design\n## Checkpoint\nPersist state with save_checkpoint().\n",
            "engine.py": "def save_checkpoint():\n    return 'persisted'\n",
            "consumer.py": "from engine import save_checkpoint\nstate = save_checkpoint()\n",
        },
    )

    class Investigator:
        def __init__(self):
            self.roles = []
            self.round = 0

        def complete(self, messages, **kwargs):
            payload = json.loads(messages[-1].content)
            if "You rank retrieved evidence" in messages[0].content:
                self.roles.append("rank")
                candidates = sorted(
                    payload["candidates"], key=lambda row: not row["title"].startswith("README")
                )
                result = {"ranked_ids": [row["id"] for row in candidates[:8]]}
            else:
                self.roles.append("investigate")
                self.round += 1
                if self.round == 1:
                    origin = next(row for row in payload["evidence"] if row["title"] == "README.md")
                    result = {"action": "follow_link", "citation_id": origin["id"], "link_index": 0}
                elif self.round == 2:
                    result = {"action": "symbol", "name": "save_checkpoint"}
                else:
                    result = {"action": "finish", "note": "design and implementation traced"}
            return Completion(json.dumps(result), prompt_tokens=10, completion_tokens=2)

    with EventStore(tmp_path / "events.db") as store:
        rag = AgenticRAG(KnowledgeStore(tmp_path / "knowledge"), store, retrieval=ready(tmp_path))
        model, budget = Investigator(), TokenBudget()
        trace = rag.retrieve(str(git_repo), "checkpoint", mode="deep", client=model, budget=budget)
        assert trace["stop_reason"] == "agent_finished"
        assert trace["capabilities"] == {"vector_recall": True, "semantic_reranker": True}
        assert [a["action"] for a in trace["actions"]] == [
            "hybrid_retrieve",
            "follow_link",
            "symbol",
            "finish",
        ]
        assert model.roles == ["rank", "investigate", "investigate", "investigate"]
        assert budget.calls == 4 and budget.run_used == 48
        assert trace["actions"][1]["hits"] > 0 and trace["actions"][2]["hits"] > 0
