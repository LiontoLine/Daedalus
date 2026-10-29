"""An explanation is not a new read; distinct evidence windows remain available."""

import pytest

from daedalus.application.agentic_rag import _tool_identity
from daedalus.infrastructure.retrieval_tools import RepositorySearch
from tests import test_agentic_rag as rag_tests
from tests.test_retrieval_tools import commit

rag = rag_tests.rag
Controller = rag_tests.Controller


@pytest.mark.parametrize(
    "action,args,defaults",
    [
        ("grep", {"query": "needle"}, {}),
        ("read", {"path": "README.md"}, {"line": 1}),
        ("symbol", {"name": "advance_cursor"}, {}),
        ("expand", {"citation_id": "observed"}, {}),
        ("follow_link", {"citation_id": "observed"}, {"link_index": 0}),
    ],
)
def test_notes_extras_and_explicit_defaults_do_not_change_identity(action, args, defaults):
    first = {"action": action, **args, "note": "missing context"}
    second = {"action": action, **args, **defaults, "note": "different wording", "unused": "extra"}
    assert _tool_identity(first) == _tool_identity(second)


@pytest.mark.parametrize(
    "first,second",
    [
        ({"action": "grep", "query": "a b"}, {"action": "grep", "query": "a  b"}),
        ({"action": "read", "path": "a.py"}, {"action": "read", "path": "b.py"}),
        ({"action": "read", "path": "a.py"}, {"action": "read", "path": "a.py", "line": 31}),
        (
            {"action": "follow_link", "citation_id": "a"},
            {"action": "follow_link", "citation_id": "a", "link_index": 1},
        ),
        ({"action": "expand", "citation_id": "a"}, {"action": "expand", "citation_id": "b"}),
    ],
)
def test_distinct_arguments_remain_distinct(first, second):
    assert _tool_identity(first) != _tool_identity(second)


@pytest.mark.parametrize(
    "decision",
    [
        {"action": "read", "path": "a.py", "line": True},
        {"action": "read", "path": "a.py", "line": 0},
        {"action": "follow_link", "citation_id": "a", "link_index": -1},
        {"action": "follow_link", "citation_id": ["a"]},
        {"action": "grep", "query": " "},
        {"action": "grep", "query": "a" * 241},
        {"action": "symbol", "name": None},
    ],
)
def test_invalid_arguments_are_refused_before_tool_dispatch(decision):
    with pytest.raises(ValueError):
        _tool_identity(decision)


def test_same_tool_with_changed_explanation_executes_once(rag, git_repo, monkeypatch):
    commit(git_repo, **{"README.md": "# Reference\nadvance_cursor is the target symbol.\n"})
    calls = []
    original = RepositorySearch.grep

    def grep(self, query, **kwargs):
        calls.append(query)
        return original(self, query, **kwargs)

    monkeypatch.setattr(RepositorySearch, "grep", grep)
    client = Controller(
        [
            {"action": "grep", "query": "advance_cursor", "note": "find implementation"},
            {"action": "grep", "query": "advance_cursor", "note": "inspect it again"},
            {"action": "finish"},
        ]
    )
    trace = rag.retrieve(str(git_repo), "unmatched question", mode="deep", client=client)
    assert trace["stop_reason"] == "invalid_or_duplicate_query"
    assert calls == ["advance_cursor"] and len(client.calls) == 2
    assert len([a for a in trace["actions"] if a["action"] == "grep"]) == 1


def test_distinct_windows_still_execute_and_finish(rag, git_repo):
    commit(git_repo, **{"README.md": "".join(f"line {i} carries evidence\n" for i in range(100))})
    client = Controller(
        [
            {"action": "read", "path": "README.md", "line": 1},
            {"action": "read", "path": "README.md", "line": 40},
            {"action": "finish"},
        ]
    )
    trace = rag.retrieve(str(git_repo), "unmatched question", mode="deep", client=client)
    assert trace["stop_reason"] == "agent_finished" and len(client.calls) == 3
    assert len([a for a in trace["actions"] if a["action"] == "read"]) == 2
