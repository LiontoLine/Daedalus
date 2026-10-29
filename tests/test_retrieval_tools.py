"""Direct search must be cheap; investigation tools return verifiable source context."""

import json

import pytest

from daedalus.application.agentic_rag import AgenticRAG, route_query
from daedalus.infrastructure.git_sandbox import _git
from daedalus.infrastructure.knowledge import KnowledgeStore
from daedalus.infrastructure.retrieval_tools import RepositorySearch, sections
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import TokenBudget
from tests.test_agentic_rag import Controller


def commit(repo, **files):
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text)
    _git(repo, ["add", "."], check=True)
    _git(repo, ["commit", "-m", "retrieval fixtures"], check=True)


def test_structured_chunks_preserve_headings_fences_and_source_lines():
    text = "# Alpha\n\nFirst paragraph.\n\n## Beta\n```python\n# not a heading\nx = 1\n```\n"
    result = sections(text)
    assert len(result) == 2
    assert result[0]["section"] == "Alpha" and result[1]["section"] == "Beta"
    assert "# not a heading" in result[1]["text"]
    for row in result:
        assert row["text"] == "".join(
            text.splitlines(keepends=True)[row["line_start"] - 1 : row["line_end"]]
        )


def test_grep_reads_committed_code_with_real_line_ranges(git_repo, tmp_path):
    commit(git_repo, **{"engine.py": "def advance_cursor():\n    return 7\n"})
    (git_repo / "engine.py").write_text("UNCOMMITTED PRIVATE OVERRIDE")
    search = RepositorySearch(str(git_repo))
    hits = search.grep("advance_cursor")
    assert len(hits) == 1
    assert hits[0]["path"] == "engine.py" and "return 7" in hits[0]["text"]
    assert "UNCOMMITTED" not in json.dumps(hits)
    assert search.read("../outside.py") is None
    assert search.read("engine.py", -1) is None


def test_secret_files_and_symlinks_never_supply_partial_snippets(git_repo, tmp_path):
    secret = "sk-" + "a" * 30
    commit(git_repo, **{"bad.py": "def advance_cursor():\n    pass\n" + "\n" * 100 + repr(secret)})
    outside = tmp_path / "outside.py"
    outside.write_text("advance_cursor OUTSIDE")
    (git_repo / "linked.py").symlink_to(outside)
    _git(git_repo, ["add", "linked.py"], check=True)
    _git(git_repo, ["commit", "-m", "link"], check=True)
    search = RepositorySearch(str(git_repo))
    assert search.grep("advance_cursor") == []
    assert search.read("linked.py") is None


@pytest.mark.parametrize(
    "phase,paths,query,expected",
    [
        ("planning", ("engine.py",), "fix advance_cursor", "grep"),
        ("execution", ("engine.py",), "change one function", "grep"),
        ("planning", ("a.py", "b.py"), "change API", "deep"),
        ("planning", (), "追踪跨文件调用链", "deep"),
        ("regression", ("engine.py",), "prior failure", "deep"),
    ],
)
def test_router_does_not_require_an_llm(phase, paths, query, expected):
    assert route_query(query, phase=phase, target_paths=paths)[0] == expected


def test_simple_task_spends_zero_retrieval_calls(git_repo, tmp_path):
    commit(git_repo, **{"engine.py": "def advance_cursor():\n    return 7\n"})
    with EventStore(tmp_path / "events.db") as store:
        rag = AgenticRAG(KnowledgeStore(tmp_path / "knowledge"), store)
        model, budget = Controller([]), TokenBudget()
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
        assert not model.calls and budget.calls == budget.run_used == 0
        assert trace["capabilities"] == {"vector_recall": False, "semantic_reranker": False}


def test_investigation_connects_document_to_code_then_expands_context(git_repo, tmp_path):
    lines = ["# Operations\n", "Cursor handling lives in engine.py.\n"]
    code = ["# preamble\n"] * 20 + ["def advance_cursor():\n", "    return 7\n"] + ["# tail\n"] * 40
    commit(git_repo, **{"README.md": "".join(lines), "engine.py": "".join(code)})
    with EventStore(tmp_path / "events.db") as store:
        rag = AgenticRAG(KnowledgeStore(tmp_path / "knowledge"), store)
        model = Controller(
            [
                {"action": "grep", "query": "advance_cursor", "note": "locate implementation"},
                {"action": "read", "path": "engine.py", "line": 15, "note": "read caller context"},
                {"action": "finish", "note": "implementation and context found"},
            ]
        )
        budget = TokenBudget()
        trace = rag.retrieve(str(git_repo), "Cursor handling", client=model, budget=budget)
        assert trace["stop_reason"] == "agent_finished" and len(model.calls) == 3
        assert budget.calls == 3 and budget.run_used == 300
        assert [a["action"] for a in trace["actions"]] == ["search", "grep", "read", "finish"]
        assert "advance_cursor" in model.calls[1][-1].content
        assert any(c["kind"] == "code" for c in trace["citations"])
        assert not rag.knowledge.records(str(git_repo))


def test_unresolvable_path_stops_without_supplying_fabricated_content(git_repo, tmp_path):
    commit(git_repo, **{"README.md": "# Cursor\nCursor design details.\n"})
    with EventStore(tmp_path / "events.db") as store:
        rag = AgenticRAG(KnowledgeStore(tmp_path / "knowledge"), store)
        model = Controller(
            [
                {"action": "read", "path": "../../etc/passwd"},
                {"action": "finish", "note": "requested source is unavailable"},
            ]
        )
        trace = rag.retrieve(str(git_repo), "Cursor", client=model)
        assert trace["stop_reason"] == "agent_finished"
        assert trace["citations"] and len(model.calls) == 2
        assert trace["actions"][1]["hits"] == 0


def test_regression_retrieval_charges_the_adopted_worker_budget(git_repo, tmp_path):
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from daedalus.application.worker import WorkerContext
    from daedalus.config import Settings, WorkspaceSettings
    from daedalus.service.app import create_app
    from tests.conftest import TARGET, TEST_COMMAND

    commit(git_repo, **{"README.md": "# Failure\nPrior failure in word counting.\n"})
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    state = app.state.daedalus
    model = Controller([{"action": "finish"}])
    state.build_model_client = lambda role="": model
    worker, _ = state.build_worker(use_model=True, enable_review=True, repo_path=str(git_repo))
    original = worker.budget
    worker.budget = TokenBudget()
    bundle = DeterministicPlanner().plan(
        PlanRequest("r", "g", "word counting", (TARGET,), TEST_COMMAND)
    )
    context = WorkerContext(
        step_id="step",
        execution_id="exec",
        node=bundle.plan.nodes[0],
        bundle=bundle,
        base_commit="unused",
        attempt=2,
        revision_feedback="prior failure in word counting",
    )
    try:
        assert worker.reference_context(context)
        assert original.calls == 0 and worker.budget.calls == 1
    finally:
        state.close()
