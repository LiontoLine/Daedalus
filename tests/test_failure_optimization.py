"""Offline regression of observed failure mechanisms, never model capability scores."""

from dataclasses import replace

import pytest

from daedalus.application.benchmark import _single_loop
from daedalus.application.coding_worker import ModelWorker
from daedalus.application.inspection import InspectionRequest, RepositoryInspector, safe_receipts
from daedalus.application.source_context import failure_excerpt, source_view
from daedalus.application.worker import WorkerResult
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.infrastructure.retrieval_tools import RepositorySearch
from daedalus.infrastructure.store import EventStore
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
from tests.test_agent_investigation import context_for
from tests.test_agentic_rag import Controller
from tests.test_goal_audit import make_owner
from tests.test_retrieval_tools import commit


def test_named_function_past_old_prefix_is_visible_and_source_lines_exact():
    text = "# irrelevant preamble\n" * 900 + "def fix_parser(value):\n    return value.strip()\n"
    view = source_view(text, "fix fix_parser whitespace")
    assert len(view) <= 8000 and "TRUNCATED" in view
    assert "def fix_parser(value):\n    return value.strip()\n" in view
    assert "LINES 899-902" in view
    assert source_view("small\n", "parser") == "small\n"


def test_named_class_includes_behavior_defining_attributes_inside_same_context_limit():
    target = (
        "class String(Token):\n    __slots__ = ('text',)\n"
        "    not_in_args = ['text']\n    def _construct_text(self, text): return text\n"
    )
    text = "# irrelevant preamble\n" * 1000 + target
    view = source_view(text, "Argument invariance of codegen.ast String")
    assert len(view) <= 8000 and "TRUNCATED" in view
    assert target in view and "LINES 999-1004" in view


def test_large_named_class_cannot_displace_the_named_method_and_its_branch_guard():
    method = (
        "    def resolve_lookup_value(self, value):\n"
        "        if isinstance(value, (list, tuple)):\n"
        "            return type(value)(value)\n        return value\n"
    )
    source = "class Query:\n    def unrelated(self):\n" + "        value = 1\n" * 1000 + method
    view = source_view(source, "Query.resolve_lookup_value preserves list inputs", limit=3200)
    assert method in view and len(view) <= 3200


def test_named_subclass_context_includes_local_base_constructor_without_more_budget():
    source = (
        "# unrelated\n" * 1000 + "class Token:\n"
        "    def __new__(cls, text):\n        return make_node(cls, text)\n\n"
        "class String(Token):\n    not_in_args = ['text']\n"
    )
    view = source_view(source, "String argument invariance", limit=3200)
    assert "class String(Token)" in view and "def __new__(cls, text)" in view
    assert len(view) <= 3200


@pytest.mark.parametrize("limit", [1500, 3200, 8000])
@pytest.mark.parametrize("kind", ["def", "async def"])
def test_class_qualified_method_outranks_other_classes_with_the_same_method(limit, kind):
    method = (
        f"    {kind} normalize(self, value):\n"
        "        if value is None:\n"
        "            return 'TARGET_EMPTY'\n"
        "        return value.strip()\n"
    )
    source = "".join(
        f"class Neighbor{i}:\n    {kind} normalize(self, value):\n"
        f"        return 'neighbor-{i}'\n\n"
        for i in range(9)
    ) + "class Target:\n" + method + "# padding\n" * 2000
    view = source_view(source, "Target.normalize", limit=limit)
    assert method in view
    assert len(view) <= limit


def test_named_consumer_and_producer_still_include_their_local_dataflow():
    source = (
        "class Query:\n"
        "    def compile(self):\n"
        "        ordering = self.order()\n"
        "        return self.group(ordering)\n"
        "    def group(self, field):\n"
        + "        candidate = field\n" * 300
        + "        return self.source, candidate\n"
        "    def order(self):\n"
        '        self.source = "meta"\n'
        "        return self.ordering\n"
    )
    view = source_view(source, "Query.group Query.order", limit=3200, include_callers=True)
    assert "ARGUMENT PRODUCER Query.order" in view
    assert 'self.source = "meta"' in view
    assert "ordering = self.order()\n        return self.group(ordering)" in view
    assert len(view) <= 3200


@pytest.mark.parametrize("multiline", [True, False])
def test_compact_method_context_keeps_a_contiguous_post_docstring_edit_anchor(multiline):
    explanation = "Explain the existing behavior without displacing the editable entry. "
    docstring = (
        '        """\n' + ("        " + explanation + "\n") * 20 + '        """\n'
        if multiline else '        """' + explanation * 3 + '"""\n'
    )
    following = "        # Preserve the guard's explanation.\n        if self.ready:\n"
    source = (
        "# unrelated preamble\n" * 1000 + "class Target:\n    def build(self):\n"
        + docstring + following + "            return self.value\n        return None\n"
    )
    view = source_view(source, "Target.build", limit=1400)
    anchor = docstring.splitlines(keepends=True)[-1] + following
    assert anchor in view
    assert len(view) <= 1400


def test_failure_feedback_retains_assertion_after_long_runner_banner():
    output = (
        "environment header\n" * 200
        + "AssertionError: expected -61, observed 61\nFAILED (failures=1)"
    )
    view = failure_excerpt(output)
    assert len(view) <= 1800 and "AssertionError: expected -61, observed 61" in view


def test_definition_grep_and_symbol_reach_large_repositories(git_repo):
    files = {f"a{i:03}.py": "def unrelated():\n    return 1\n" for i in range(90)}
    files.update(
        {
            "z/core.py": "def symbols(value):\n    return value\n",
            "README.md": "def is a common keyword\n",
        }
    )
    commit(git_repo, **files)
    search = RepositorySearch(str(git_repo))
    assert search.grep("def symbols")[0]["path"] == "z/core.py"
    assert search.symbol("symbols")[0]["path"] == "z/core.py"
    assert search.symbol("symbols", paths=("a000.py",)) == []


def test_scoped_observation_is_commit_bound_and_never_falls_back(git_repo, tmp_path):
    commit(
        git_repo,
        **{
            "scope.py": "def symbols(value):\n    return value\n",
            "other.py": "def symbols():\n    return 'wrong file'\n",
        },
    )
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="scope")
    try:
        request = InspectionRequest.parse(
            {"tool": "grep", "query": "def symbols", "path": "scope.py", "gap": "implementation"}
        )
        observation = RepositoryInspector()(box, context_for(box), request)
        assert observation.receipt["sources"] == ["scope.py"]
        assert safe_receipts({"inspection_receipts": [observation.receipt]})
        assert "wrong file" not in observation.content
        missing = replace(request, arguments={"query": "symbols", "path": "absent.py"})
        assert (
            RepositoryInspector()(box, context_for(box), missing).receipt["status"] == "not_found"
        )
    finally:
        box.remove()


@pytest.mark.parametrize("path", ["../private.py", "/etc/passwd", ":(glob)**", "a/*.py"])
def test_scope_does_not_grant_pathspec_or_host_access(path):
    with pytest.raises(ValueError):
        InspectionRequest.parse({"tool": "grep", "query": "symbols", "path": path, "gap": "source"})


def test_secret_beyond_context_window_blocks_before_dispatch(git_repo, tmp_path):
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="secret-tail")
    try:
        box.write_file(TARGET, "# safe context\n" * 1000 + "key = 'sk-" + "a" * 30 + "'\n")
        client = Controller([])
        result = ModelWorker(client).implement(box, context_for(box))
        assert result.error == "secret_in_payload" and not client.calls
    finally:
        box.remove()


def test_model_noop_is_repairable_and_does_not_look_successful(git_repo, tmp_path):
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="noop")
    try:
        source = box.read_file(TARGET)
        client = Controller([{"operations": [{"op": "write", "path": TARGET, "content": source}]}])
        result = ModelWorker(client).implement(box, context_for(box))
        assert not result.ok and result.error == "worker_no_change" and not box.changed_files()
    finally:
        box.remove()


def test_classic_loop_keeps_remaining_attempt_after_noop(git_repo, tmp_path):
    root = tmp_path / "trial"
    root.mkdir()
    # A pass on existing public tests must not attempt an empty commit.
    commit(git_repo, **{"verify_public.py": "raise SystemExit(0)\n"})
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "context", name="context")
    try:
        bundle = context_for(box).bundle
    finally:
        box.remove()

    class Worker:
        calls = 0

        def implement(self, sandbox, context):
            self.calls += 1
            if self.calls == 2:
                sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
            return WorkerResult(ok=True)

    worker = Worker()
    result = _single_loop(git_repo, bundle, worker, root, 30000)
    assert result["delivered"] and worker.calls == 2


def _memory_owner(git_repo, tmp_path, seed=None):
    owner = make_owner(git_repo, tmp_path)
    if seed is not None:
        node = owner.bundle.plan.nodes[0]
        owner.bundle = replace(owner.bundle, plan=replace(owner.bundle.plan, nodes=(
            replace(node, extra={**node.extra, "repair_memory": seed}),)))
        owner.register_spec()
    pool = owner.create_run()
    step_id = owner.scheduler().declare_all_nodes(owner.spec_digest, base_commit=pool.base_commit)[0]
    return owner, step_id


def test_repair_memory_survives_reopen_and_keeps_prior_constraints_without_crossing_nodes(
    git_repo, tmp_path,
):
    owner, step_id = _memory_owner(git_repo, tmp_path)
    node_id = owner.bundle.plan.nodes[0].node_id
    for attempt, node, error in [(1, node_id, "semantic_revision"),
                                 (2, node_id, "invalid_edit_plan"),
                                 (3, "unrelated-node", "semantic_revision")]:
        owner.store.append(aggregate_id=f"run:{owner.run_id}", execution_id=owner.execution_id,
            event_type="TrunkNodeFailed", actor="test", payload={
                "node_id": node, "attempt": attempt, "patch_digest": str(attempt),
                "error_code": error, "detail": "preserve the earlier failure constraint"})
    old_execution = owner.execution_id
    path = owner.store.path
    owner.store.close()
    owner.store = EventStore(path)
    owner.execution_id = "next-explicit-execution"
    try:
        memory = owner._repair_memory(step_id)
        assert [item["attempt"] for item in memory] == ["1", "2"]
        assert {item["source_execution_id"] for item in memory} == {old_execution}
        assert [item["evidence_kind"] for item in memory] == [
            "review_hypothesis", "edit_or_control_failure"]
        memory[0]["observation"] = "caller mutation"
        assert owner._repair_memory(step_id)[0]["observation"] != "caller mutation"
    finally:
        owner.store.close()


@pytest.mark.parametrize("field,invalid", [
    ("goal_id", "unrelated-goal"), ("node_id", "unrelated-node"), ("paths", ["private.py"]),
])
def test_frozen_repair_memory_cannot_leak_across_goal_node_or_artifact_scope(
    git_repo, tmp_path, field, invalid,
):
    node_id = "G-step-01"
    seed = {"goal_id": "G", "node_id": node_id, "paths": [TARGET], "entries": [
        {"source_run_id": "parent-run", "attempt": 1, "patch_digest": "old-patch",
         "reason": "private history belonging to another scope"}]}
    seed[field] = invalid
    owner, step_id = _memory_owner(git_repo, tmp_path, seed)
    try:
        assert owner._repair_memory(step_id) == ()
    finally:
        owner.store.close()


def test_repair_memory_marks_omissions_and_does_not_turn_review_claims_into_execution(
    git_repo, tmp_path,
):
    seed = {"goal_id": "G", "node_id": "G-step-01", "paths": [TARGET], "entries": [
        {"source_run_id": "parent-run", "attempt": attempt, "patch_digest": str(attempt),
         "error_code": "semantic_revision", "reason": "unverified review concern " * 50}
        for attempt in range(30)]}
    owner, step_id = _memory_owner(git_repo, tmp_path, seed)
    try:
        memory = owner._repair_memory(step_id)
        records = [item for item in memory if "attempt" in item]
        assert memory[0]["older_records_omitted"] == 30 - len(records)
        assert records[-1]["attempt"] == "29"
        assert {item["evidence_kind"] for item in records} == {"review_hypothesis"}
        assert all(item["failed_criteria"] == [] for item in records)
        assert len(records) <= 8
    finally:
        owner.store.close()
