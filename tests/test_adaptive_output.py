"""Truncation consumes usage, applies no edits, and only grows a declared retry."""

import json
from dataclasses import replace

import pytest

from daedalus.application.coding_worker import ModelWorker
from daedalus.application.gatekeeper.tier2 import ClientReviewer
from daedalus.errors import ModelResponseIncomplete
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.model.base import Completion, TokenBudget
from tests import test_agentic_rag as rag_tests
from tests.conftest import TARGET
from tests.test_agent_investigation import context_for

rag = rag_tests.rag


class Responses:
    model = "offline"

    def __init__(self, *responses):
        self.responses = iter(responses)
        self.limits = []

    def complete(self, messages, **kwargs):
        self.limits.append(kwargs["max_tokens"])
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture
def box(git_repo, tmp_path):
    sandbox = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="adaptive")
    try:
        yield sandbox
    finally:
        sandbox.remove()


def complete(*, reason="", text=None):
    return Completion(
        text=json.dumps({"operations": [{"op": "write", "path": TARGET, "content": "changed"}]})
        if text is None
        else text,
        model="offline",
        prompt_tokens=30,
        completion_tokens=70,
        stopped_reason=reason,
    )


def test_declared_next_attempt_grows_without_an_internal_model_retry(box):
    error = ModelResponseIncomplete(
        "incomplete", model="offline", usage={"prompt_tokens": 100, "completion_tokens": 8192}
    )
    client = Responses(error, complete(), complete(text=json.dumps({"operations":[
        {"op":"write","path":TARGET,"content":"a different substantive change"}
    ]})))
    budget = TokenBudget(max_tokens_per_step=40000)
    worker = ModelWorker(client, budget=budget)
    ctx = context_for(box)
    before = box.read_file(TARGET)
    first = worker.implement(box, ctx)
    assert first.error == "model_output_incomplete" and first.tokens_used == 8292
    assert len(client.limits) == 1 and box.read_file(TARGET) == before
    assert budget.calls == 1 and budget.run_used == 8292
    assert worker.desired_output_tokens(replace(ctx, attempt=2)) == 16384
    assert worker.desired_output_tokens(ctx) == 8192
    assert worker.desired_output_tokens(replace(ctx, step_id="other", attempt=2)) == 8192
    budget.reset_step()
    second = worker.implement(box, replace(ctx, attempt=2))
    assert second.ok and client.limits == [8192, 16384]
    assert worker.desired_output_tokens(replace(ctx, attempt=3)) == 8192
    assert worker.implement(box, replace(ctx, step_id="other", attempt=1)).ok
    assert client.limits[-1] == 8192


@pytest.mark.parametrize("failure", ["stale", "no_change", "invalid_json"])
def test_grown_allowance_survives_an_unapplied_edit_plan(box, failure):
    current = box.read_file(TARGET)
    payload = {"operations":[{"op":"write","path":TARGET,"content":current}]}
    if failure == "stale":
        payload = {"operations":[{"op":"replace","path":TARGET,
                                  "old_text":"not the current source","new_text":"changed"}]}
    response = "not JSON" if failure == "invalid_json" else json.dumps(payload)
    client = Responses(
        ModelResponseIncomplete("length",usage={"prompt_tokens":30,"completion_tokens":2048}),
        complete(text=response),complete(),
    )
    budget = TokenBudget(max_tokens_per_step=40000,max_tokens_per_run=50000)
    worker = ModelWorker(client,budget=budget,initial_output_tokens=2048)
    ctx = context_for(box)
    assert worker.implement(box,ctx).error == "model_output_incomplete"
    assert not worker.implement(box,replace(ctx,attempt=2)).ok
    assert box.read_file(TARGET) == current
    assert worker.desired_output_tokens(replace(ctx,attempt=3)) == 4096
    assert worker.implement(box,replace(ctx,attempt=3)).ok
    assert client.limits == [2048,4096,4096]
    assert worker.desired_output_tokens(replace(ctx,attempt=4)) == 2048


@pytest.mark.parametrize("reason,text", [("length", None), ("max_tokens", None), ("", "  ")])
def test_incomplete_custom_client_cannot_apply_valid_json(box, reason, text):
    before = box.read_file(TARGET)
    budget = TokenBudget()
    client = Responses(complete(reason=reason, text=text))
    result = ModelWorker(client, budget=budget).implement(box, context_for(box))
    assert result.error == "model_output_incomplete" and box.read_file(TARGET) == before
    assert budget.run_used == 100 and budget.calls == 1


def test_retry_cap_is_limited_by_remaining_run_budget_and_review_reserve(box):
    budget = TokenBudget(max_tokens_per_step=40000, max_tokens_per_run=20000)
    client = Responses(ModelResponseIncomplete("incomplete"), complete())
    worker = ModelWorker(client, budget=budget)
    ctx = context_for(box)
    assert not worker.implement(box, ctx).ok
    # Unknown usage stays unknown, while an already recorded spend limits the retry.
    assert budget.run_used == 0 and budget.calls == 0
    budget.record(Completion("", prompt_tokens=4000))
    budget.reset_step()
    retry = replace(ctx, attempt=2)
    estimate = worker._estimate(worker._render(box, retry), 0)
    assert worker.implement(box, retry).ok
    assert client.limits[-1] == 16000 - estimate - 2048 < 16384
    assert budget.run_used == 4100


def test_tiny_budget_blocks_before_dispatch(box):
    client = Responses(complete())
    result = ModelWorker(client, budget=TokenBudget(max_tokens_per_step=1000)).implement(
        box, context_for(box)
    )
    assert result.error == "model_budget_exceeded" and client.limits == []


def test_nontruncation_failure_does_not_grow_next_attempt(box):
    worker = ModelWorker(Responses(RuntimeError("offline failure")))
    ctx = context_for(box)
    assert worker.implement(box, ctx).error == "model_call_failed"
    assert worker.desired_output_tokens(replace(ctx, attempt=2)) == 8192


def test_review_retry_uses_only_affordable_output_on_the_same_subject():
    budget = TokenBudget(max_tokens_per_step=7000)
    client = Responses(
        ModelResponseIncomplete(
            "incomplete", usage={"prompt_tokens": 10, "completion_tokens": 2048}
        ),
        Completion('{"decision":"ESCALATE"}', prompt_tokens=10, completion_tokens=20),
    )
    prompt = "unchanged subject"
    text = ClientReviewer(client, budget=budget).complete(prompt, subject_digest="digest")
    assert json.loads(text)["decision"] == "ESCALATE"
    assert client.limits == [2048, 7000 - 2058 - len(prompt) // 3 - 64]
    assert budget.run_used == 2088


def test_two_incomplete_reviews_remain_a_failure_with_no_third_call():
    client = Responses(ModelResponseIncomplete("first"), ModelResponseIncomplete("second"))
    with pytest.raises(ModelResponseIncomplete):
        ClientReviewer(client).complete("subject", subject_digest="digest")
    assert client.limits == [2048, 8192]


@pytest.mark.parametrize("phase", ["execution", "regression", "investigation"])
def test_retrieval_preserves_the_selected_retry_output_reserve(rag, git_repo, monkeypatch, phase):
    observed = []

    def retrieve(*args, **kwargs):
        observed.append(kwargs["reserve_tokens"])
        return {"citations": []}

    monkeypatch.setattr(rag, "retrieve", retrieve)
    rag.context(str(git_repo), "query", phase=phase, budget=TokenBudget(), output_tokens=16384)
    rag.context(str(git_repo), "query", phase=phase, budget=TokenBudget())
    assert observed == [19408, 11216]
