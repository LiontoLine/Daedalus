"""The coding observation loop is bounded, versioned, read-only and fully budgeted."""

import json

import pytest

from daedalus.application.coding_worker import ModelWorker
from daedalus.application.inspection import InspectionRequest, RepositoryInspector, safe_receipts
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.model.base import TokenBudget
from tests.conftest import TARGET
from tests.test_agent_investigation import context_for, edit
from tests.test_agentic_rag import Controller
from tests.test_retrieval_tools import commit


@pytest.fixture
def box(git_repo, tmp_path):
    commit(
        git_repo,
        **{"README.md": "# Rules\nEmpty input has zero words.\nRead the existing tests.\n"},
    )
    sandbox = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="inspect")
    try:
        yield sandbox
    finally:
        sandbox.remove()


def inspect(path="README.md", **kwargs):
    return {
        "action": "inspect",
        "tool": "read",
        "path": path,
        "gap": "need the existing contract",
        **kwargs,
    }


def test_read_observe_then_edit_charges_both_calls_and_records_replayable_receipt(box):
    client, budget = Controller([inspect(), edit()]), TokenBudget()
    original = box.read_file(TARGET)
    inspector = RepositoryInspector()

    def observe(sandbox, context, request):
        assert sandbox.read_file(TARGET) == original
        return inspector(sandbox, context, request)

    result = ModelWorker(client, budget=budget, inspection_context=observe).implement(
        box, context_for(box)
    )
    assert result.ok and len(client.calls) == budget.calls == 2 and result.tokens_used == 200
    assert budget.run_used == 200 and "Empty input" in client.calls[-1][-1].content
    receipts = safe_receipts(result.extra)
    assert len(receipts) == 1 and receipts[0]["commit"] == box.base_commit
    request = InspectionRequest.parse(
        {**receipts[0]["arguments"], "tool": receipts[0]["tool"], "gap": "replay"}
    )
    replay = inspector(box, context_for(box), request)
    assert replay.receipt["evidence_digest"] == receipts[0]["evidence_digest"]


def test_changed_explanation_does_not_repeat_identical_tool_arguments(box):
    before = box.read_file(TARGET)
    client = Controller([inspect(), inspect(gap="another explanation")])
    result = ModelWorker(client, inspection_context=RepositoryInspector()).implement(
        box, context_for(box)
    )
    assert result.error == "invalid_edit_plan" and len(client.calls) == 2
    assert len(result.extra["inspection_receipts"]) == 1 and box.read_file(TARGET) == before


def test_single_observation_in_edit_envelope_uses_the_same_bounded_read_path(box):
    nested = {"summary": "read first", "operations": [{"op": "inspect", **inspect()}]}
    nested["operations"][0].pop("action")
    client = Controller([nested, edit()])
    result = ModelWorker(client, inspection_context=RepositoryInspector()).implement(
        box, context_for(box)
    )
    assert result.ok and len(client.calls) == 2
    assert len(safe_receipts(result.extra)) == 1
    assert safe_receipts(result.extra)[0]["arguments"] == {"path": "README.md", "line": 1}


def test_distinct_read_only_batch_uses_one_followup_and_keeps_all_receipts(box):
    batch = {"action":"inspect", "requests":[inspect(line=1),inspect(line=2)]}
    client, budget = Controller([batch, edit()]), TokenBudget()
    result = ModelWorker(client, budget=budget, inspection_context=RepositoryInspector()).implement(
        box, context_for(box)
    )
    assert result.ok and len(client.calls) == budget.calls == 2
    assert result.tokens_used == budget.run_used == 200
    assert len(safe_receipts(result.extra)) == 2
    assert "Empty input" in client.calls[-1][-1].content


@pytest.mark.parametrize("last", [None, inspect(gap=""), inspect(operations=[{"op":"delete","path":TARGET}])])
def test_invalid_later_batch_request_performs_no_earlier_observation(box,last):
    observed=[]
    result = ModelWorker(
        Controller([{"action":"inspect","requests":[inspect(),last]}]),
        inspection_context=lambda *args:observed.append(args),
    ).implement(box,context_for(box))
    assert not result.ok and not observed


@pytest.mark.parametrize("ambiguous", ["mixed_write", "two_reads", "explicit_action"])
def test_observation_alias_never_dispatches_an_ambiguous_or_mixed_batch(box, ambiguous):
    read = {"op": "inspect", **inspect()}
    read.pop("action")
    payload = {"operations": [read]}
    if ambiguous == "mixed_write":
        payload["operations"].append({"op": "write", "path": TARGET, "content": "changed"})
    elif ambiguous == "two_reads":
        payload["operations"].append(dict(read))
    else:
        payload["action"] = "edit"
    observations = []
    before = box.read_file(TARGET)
    result = ModelWorker(
        Controller([payload]), inspection_context=lambda *args: observations.append(args)
    ).implement(box, context_for(box))
    assert not result.ok and result.error == "invalid_edit_plan"
    assert not observations and box.read_file(TARGET) == before


def test_max_three_observations_prevents_open_ended_spending_or_edits(box):
    client = Controller([inspect(line=n) for n in [1, 2, 3, 4]])
    before = box.read_file(TARGET)
    result = ModelWorker(client, inspection_context=RepositoryInspector()).implement(
        box, context_for(box)
    )
    assert result.error == "invalid_edit_plan" and len(client.calls) == 4
    assert len(result.extra["inspection_receipts"]) == 3 and box.read_file(TARGET) == before


def test_observation_cannot_read_symlink_untracked_or_outside_content(box, tmp_path):
    private = tmp_path / "private.txt"
    private.write_text("private marker outside committed repository")
    (box.worktree_path / "link.md").symlink_to(private)
    (box.worktree_path / "untracked.md").write_text("untracked marker")
    for path in [str(private), "../private.txt", "link.md", "untracked.md"]:
        observation = RepositoryInspector()(
            box, context_for(box), InspectionRequest.parse(inspect(path))
        )
        assert json.loads(observation.content)["status"] == "not_found"
        assert (
            "private marker" not in observation.content
            and "untracked marker" not in observation.content
        )


@pytest.mark.parametrize(
    "payload",
    [
        inspect(line=True),
        inspect(line=0),
        inspect(tool="shell"),
        inspect(operations=[{"op": "delete", "path": TARGET}]),
        inspect(gap=""),
        inspect(path=""),
    ],
)
def test_invalid_observations_are_rejected_before_tool_dispatch(box, payload):
    def unavailable(*args):
        pytest.fail("invalid request reached repository tools")

    result = ModelWorker(Controller([payload]), inspection_context=unavailable).implement(
        box, context_for(box)
    )
    assert result.error == "invalid_edit_plan"


def test_observation_budget_failure_stops_before_second_completion(box):
    # First request fits; inject a known spend during the local observation to leave no
    # room for the continuation. No hidden model retry is permitted.
    from daedalus.model.base import Completion

    budget = TokenBudget()
    client = Controller([inspect()])

    def observe(*args):
        budget.record(Completion("", prompt_tokens=19000))
        return RepositoryInspector()(*args)

    result = ModelWorker(client, budget=budget, inspection_context=observe).implement(
        box, context_for(box)
    )
    assert result.error == "model_budget_exceeded" and len(client.calls) == 1


def test_worker_metadata_whitelisting_ignores_arbitrary_extras(box):
    observation = RepositoryInspector()(box, context_for(box), InspectionRequest.parse(inspect()))
    row = {
        **observation.receipt,
        "raw_prompt": "must not persist",
        "arguments": {**observation.receipt["arguments"], "unused": "must not persist"},
    }
    saved = safe_receipts({"inspection_receipts": [row]})
    assert (
        len(saved) == 1 and "raw_prompt" not in saved[0] and "unused" not in saved[0]["arguments"]
    )
    assert (
        safe_receipts({"inspection_receipts": [{"tool": []}, {"tool": "read", "status": []}]}) == []
    )
