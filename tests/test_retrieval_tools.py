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
    assert search.related("bad.py", 2) == []
    assert search.source_status("bad.py") == "blocked_sensitive"
    assert search.source_status("linked.py") == "not_found"


def test_tree_snapshot_reads_searches_and_symbols_stay_pinned_after_later_edits(git_repo):
    commit(
        git_repo,
        **{
            "engine.py": "def old_cursor():\n    return 7\n",
            "README.md": "# Cursor\n[Implementation](engine.py)\n",
        },
    )
    head = _git(git_repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
    snapshot_source = "def advance_cursor():\n    return 11\n\nadvance_cursor()\n"
    (git_repo / "engine.py").write_text(snapshot_source)
    _git(git_repo, ["add", "engine.py"], check=True)
    tree = _git(git_repo, ["write-tree"], check=True).stdout.strip()
    snapshot = RepositorySearch(
        str(git_repo), revision=tree, allowed_paths={"engine.py", "README.md"}
    )
    committed = RepositorySearch(str(git_repo))
    (git_repo / "engine.py").write_text("def later_cursor():\n    return 99\n")

    assert snapshot.head == committed.head == head
    assert committed.read("engine.py")["source"] == f"git:{head}:engine.py"
    assert "old_cursor" in committed.read("engine.py")["text"]
    assert committed.grep("advance_cursor") == []
    assert snapshot.read("engine.py")["text"] == snapshot_source
    assert snapshot.grep("old_cursor") == []
    hits = snapshot.grep("advance_cursor")
    symbols = snapshot.symbol("advance_cursor")
    assert {row["relation"] for row in symbols} == {"definition", "caller"}
    assert {row["source"] for row in hits + symbols + snapshot.code_chunks()} == {
        f"git:{tree}:engine.py"
    }
    assert snapshot.follow_link(snapshot.read("README.md"))["text"] == snapshot_source
    assert committed.follow_link(snapshot.read("README.md")) is None


@pytest.mark.parametrize("revision", ["HEAD", "HEAD^{tree}", "--all", "a" * 12, "f" * 40, 7])
def test_explicit_revision_rejects_refs_options_abbreviations_and_missing_objects(git_repo, revision):
    with pytest.raises(ValueError):
        RepositorySearch(str(git_repo), revision=revision)


def test_explicit_revision_accepts_commits_but_not_blob_objects(git_repo):
    commit(git_repo, **{"engine.py": "def advance_cursor():\n    return 7\n"})
    head = _git(git_repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
    blob = _git(git_repo, ["rev-parse", "HEAD:engine.py"], check=True).stdout.strip()
    assert RepositorySearch(str(git_repo), revision=head).read("engine.py")["source"] == (
        f"git:{head}:engine.py"
    )
    with pytest.raises(ValueError):
        RepositorySearch(str(git_repo), revision=blob)


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


@pytest.mark.parametrize("name", ["Target.resolve", "pkg.engine.Target.resolve"])
def test_qualified_symbol_selects_correct_owner_not_same_named_method(git_repo, name):
    source = (
        "class Decoy:\n    def resolve(self):\n        return 'wrong-owner'\n"
        + "\n" * 35
        + "class Target:\n    def resolve(self):\n        return 'correct-owner'\n"
    )
    commit(git_repo, **{"pkg/engine.py": source})
    found = RepositorySearch(str(git_repo)).symbol(name, paths=("pkg/engine.py",))
    assert [(row["relation"], row["symbol"], row["path"]) for row in found] == [
        ("definition", name, "pkg/engine.py")]
    assert "return 'correct-owner'" in found[0]["text"]
    assert "wrong-owner" not in found[0]["text"]


def test_scoped_grep_keeps_separate_matches_in_one_file_under_result_cap(git_repo):
    source = ("def first_hook():\n    return 'first'\n" + "\n" * 40
              + "def second_hook():\n    return 'second'\n" + "\n" * 40
              + "def third_hook():\n    return 'third'\n")
    commit(git_repo, **{"hooks.py": source})
    search = RepositorySearch(str(git_repo))
    found = search.grep("first_hook second_hook third_hook", paths=("hooks.py",),
                        scoped=True, limit=2)
    assert "def first_hook" in found[0]["text"] and "def second_hook" in found[1]["text"]
    assert all("def third_hook" not in row["text"] for row in found)
    for row in found:
        assert row["text"] == "".join(source.splitlines(keepends=True)[
            row["line_start"] - 1:row["line_end"]])


def test_related_method_finds_actual_override_not_unrelated_same_name(git_repo):
    source = (
        "class Parent:\n"
        "    def resolve(self):\n        return 'parent'\n\n"
        "class Unrelated:\n"
        "    def resolve(self):\n        return 'unrelated'\n\n"
        "class Child(Parent):\n"
        "    def resolve(self):\n        return 'child'\n"
    )
    commit(git_repo, **{"engine.py": source})
    search = RepositorySearch(str(git_repo))
    related = search.related("engine.py", 3)
    assert [(row["symbol"], row["relation"]) for row in related] == [
        ("Child.resolve", "overriding_definition"),
    ]
    assert "return 'child'" in related[0]["text"]
    assert "return 'unrelated'" not in related[0]["text"]


def test_related_consumer_traces_argument_producer_not_constructor_or_decoy(git_repo):
    source = (
        "class Engine:\n"
        "    def setup(self):\n"
        "        value = self.produce()\n"
        "        return self.consume(value)\n"
        "    def consume(self, value):\n        return value\n"
        "    def produce(self):\n        return self.current_value\n"
        "class Decoy:\n"
        "    def produce(self):\n        return 'wrong owner'\n"
    )
    commit(git_repo, **{"engine.py": source})
    related = RepositorySearch(str(git_repo)).related("engine.py", 5)
    assert related[0]["symbol"] == "Engine.produce"
    assert related[0]["relation"] == "argument_producer"
    assert "return self.current_value" in related[0]["text"]
    assert "wrong owner" not in related[0]["text"]


def test_related_consumer_does_not_claim_stale_producer_after_conditional_write(git_repo):
    source = (
        "class Engine:\n"
        "    def setup(self, flag):\n"
        "        value = self.old()\n"
        "        if flag:\n"
        "            value = self.new()\n"
        "            return self.consume(value)\n"
        "    def consume(self, value):\n        return value\n"
        "    def old(self):\n        return 'old'\n"
        "    def new(self):\n        return 'new'\n"
    )
    commit(git_repo, **{"engine.py": source})
    related = RepositorySearch(str(git_repo)).related("engine.py", 7, limit=2)
    assert all(row["symbol"] != "Engine.old" for row in related)
    assert related[0]["symbol"] == "Engine.setup" and related[0]["relation"] == "local_caller"


def test_setup_variant_does_not_merge_different_factories_or_rebound_factory(git_repo):
    source = (
        "class Contract:\n"
        "    def test_default(self):\n"
        "        Case = factory('first')\n"
        "        value = Case()\n"
        "    def test_different(self):\n"
        "        Case = factory('second')\n"
        "        value = Case({'data': 1})\n"
        "    def test_rebound(self):\n"
        "        Case = factory('first')\n"
        "        Case = other_factory()\n"
        "        value = Case({'data': 1})\n"
    )
    commit(git_repo, **{"contracts.py": source})
    search = RepositorySearch(str(git_repo))
    assert search.enclosing_symbol("contracts.py", 4) == "Contract.test_default"
    assert all(row["relation"] != "setup_variant" for row in search.related("contracts.py", 2))
