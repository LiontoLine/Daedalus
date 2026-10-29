"""Concurrent admission, attempt isolation and exact settlement without a real gateway."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.scheduler import Quota
from daedalus.application.worker import WorkerResult
from daedalus.errors import ModelBudgetExceeded, ModelError, ModelResponseIncomplete
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Completion, Message, TokenBudget, budgeted_completion
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
from tests.test_parallel_and_rebase import (
    EXTRA,
    EXTRA_FIXED,
    _bundle,
    _nodes,
    _prepare_two_module_repo,
)

MESSAGES = [Message("user", "controlled offline request")]


class Client:
    def __init__(self, response=None):
        self.calls = 0
        self.response = response if response is not None else Completion("{}", prompt_tokens=400)

    def complete(self, *args, **kwargs):
        self.calls += 1
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def call(budget, client, *, step="A", attempt=1, estimated=600, headroom=0):
    with budget.step_scope(step, attempt):
        return budgeted_completion(
            client, MESSAGES, budget=budget, estimated=estimated, headroom=headroom, max_tokens=512
        )


def test_inflight_reservation_blocks_a_second_request_before_transport():
    budget = TokenBudget(max_tokens_per_step=1000, max_tokens_per_run=1000)
    entered, release = threading.Event(), threading.Event()

    class Blocking(Client):
        def complete(self, *args, **kwargs):
            entered.set()
            assert release.wait(5), "test failed to release the first request"
            return super().complete(*args, **kwargs)

    first, second = Blocking(), Client()
    with ThreadPoolExecutor(max_workers=2) as pool:
        running = pool.submit(call, budget, first)
        try:
            assert entered.wait(5)
            assert budget.describe()["run_reserved"] == 600
            denied = pool.submit(call, budget, second, step="B")
            with pytest.raises(ModelBudgetExceeded) as error:
                denied.result(timeout=5)
            assert error.value.context["scope"] == "run" and second.calls == 0
        finally:
            release.set()
        assert running.result(timeout=5).total_tokens == 400
    assert budget.describe()["run_reserved"] == 0
    assert call(budget, second, step="B").total_tokens == 400
    assert budget.run_used == 800 and budget.calls == 2


def test_attempts_have_independent_limits_and_one_cumulative_run_budget():
    budget = TokenBudget(max_tokens_per_step=600, max_tokens_per_run=1200)
    client = Client(Completion("{}", completion_tokens=550))
    assert call(budget, client).total_tokens == 550
    assert call(budget, client, step="B").total_tokens == 550
    for step in ["A", "B"]:
        with budget.step_scope(step, 1):
            assert budget.step_used == 550
            budget.check()
            with pytest.raises(ModelBudgetExceeded):
                budget.check(estimated=51)
    with budget.step_scope("A", 2):
        assert budget.step_used == 0
        with pytest.raises(ModelBudgetExceeded):
            budget.check(estimated=101)
    assert budget.step_used == 0 and budget.run_used == 1100


def test_resetting_default_scope_cannot_erase_another_steps_usage():
    budget = TokenBudget()
    call(budget, Client())
    budget.reset_step()
    with budget.step_scope("A", 1):
        assert budget.step_used == 400
        with budget.reservation(100), pytest.raises(RuntimeError, match="in-flight"):
            budget.reset_step()
    assert budget.describe()["run_reserved"] == 0


@pytest.mark.parametrize("transport_error", [False, True])
def test_incomplete_response_is_charged_once_and_reservation_is_released(transport_error):
    error = ModelResponseIncomplete(
        "incomplete", model="offline", usage={"prompt_tokens": 20, "completion_tokens": 800}
    )
    client = Client(
        error
        if transport_error
        else Completion(
            '{"operations":[]}',
            model="offline",
            prompt_tokens=20,
            completion_tokens=800,
            stopped_reason="length",
        )
    )
    budget = TokenBudget(max_tokens_per_step=1000)
    with pytest.raises(ModelResponseIncomplete):
        call(budget, client, estimated=900)
    assert budget.run_used == 820 and budget.calls == 1
    assert budget.describe()["run_reserved"] == 0
    assert budget.usage_history[0].text == "" and budget.usage_history[0].raw["failed_response"]
    with pytest.raises(ModelBudgetExceeded):
        call(budget, client)
    assert client.calls == 1


def test_unknown_usage_does_not_become_a_fabricated_token_charge():
    budget = TokenBudget()
    with pytest.raises(OSError):
        call(budget, Client(OSError("offline")))
    assert budget.run_used == budget.calls == 0
    assert budget.describe()["run_reserved"] == 0


def test_actual_usage_over_estimate_blocks_subsequent_calls():
    budget = TokenBudget(max_tokens_per_step=1000, max_tokens_per_run=1000)
    client = Client(Completion("{}", prompt_tokens=1100))
    call(budget, client, estimated=400)
    assert budget.run_used == 1100 and budget.describe()["run_reserved"] == 0
    with pytest.raises(ModelBudgetExceeded):
        budget.check()
    with pytest.raises(ModelBudgetExceeded):
        call(budget, client, step="B")
    assert client.calls == 1


@pytest.mark.parametrize("estimate,headroom", [(-1, 0), (1, -1), (True, 0), (1.2, 0)])
def test_invalid_reservation_cannot_create_more_spending_room(estimate, headroom):
    budget, client = TokenBudget(), Client()
    with pytest.raises(ValueError):
        call(budget, client, estimated=estimate, headroom=headroom)
    assert client.calls == 0 and budget.describe()["run_reserved"] == 0


def test_callback_failure_does_not_leak_reservation_or_repeat_the_request():
    def unavailable(completion):
        raise OSError("metric sink unavailable")

    budget = TokenBudget(on_record=unavailable)
    client = Client()
    call(budget, client)
    assert budget.run_used == 400 and client.calls == 1 and budget.describe()["run_reserved"] == 0


@pytest.mark.parametrize("value", [-1, 1.5, True, "500"])
def test_invalid_usage_cannot_refund_or_expand_the_allowance(value):
    budget = TokenBudget()
    with pytest.raises(ModelError, match="nonnegative integers"):
        call(budget, Client(Completion("{}", prompt_tokens=value)))
    assert budget.run_used == budget.calls == 0
    assert budget.describe()["run_reserved"] == 0


def test_parallel_control_plane_preserves_step_cost_and_metric_identity(git_repo, tmp_path):
    repo = _prepare_two_module_repo(tmp_path, git_repo)
    bundle = _bundle(_nodes(), whitelist=(TARGET, EXTRA))
    bundle = replace(bundle, boundary=replace(bundle.boundary, max_tokens_per_step=600))
    barrier = threading.Barrier(2)

    class Worker:
        name = worker_id = "offline-budget-worker"
        budget = None

        def implement(self, sandbox, context):
            barrier.wait(timeout=10)
            completion = budgeted_completion(
                Client(Completion("{}", model="offline", prompt_tokens=550)),
                MESSAGES,
                budget=self.budget,
                estimated=600,
                max_tokens=100,
            )
            path = context.node.expected_artifacts[0]
            sandbox.write_file(path, CORRECT_IMPLEMENTATION if path == TARGET else EXTRA_FIXED)
            return WorkerResult(
                ok=True,
                summary="controlled offline edit",
                changed_files=(path,),
                tokens_used=completion.total_tokens,
            )

    with EventStore(tmp_path / "concurrent.db") as store:
        owner = RunOrchestrator(
            store=store,
            repo_path=repo,
            run_root=tmp_path / "trees",
            bundle=bundle,
            worker=Worker(),
            quota=Quota(max_parallel_steps=2),
        )
        owner.register_spec()
        result = owner.run()
        assert result.status == "COMPLETED", result.describe()
        assert result.tokens_used == 1100
        for node in bundle.plan.nodes:
            step_id = f"{owner.run_id}:{node.node_id}"
            rows = store.connection.execute(
                "SELECT value,labels FROM metrics WHERE run_id=? AND step_id=? AND name='llm_tokens'",
                (owner.run_id, step_id),
            ).fetchall()
            assert len(rows) == 1 and rows[0]["value"] == 550
            assert json.loads(rows[0]["labels"])["attempt"] == 1
            with owner.budget.step_scope(step_id, 1):
                assert owner.budget.step_used == 550
        restored = RunOrchestrator(
            store=store,
            repo_path=repo,
            run_root=tmp_path / "resume",
            bundle=bundle,
            worker=Worker(),
            run_id=owner.run_id,
        )
        restored._restore_model_budget()
        assert restored.budget.run_used == 1100 and restored.budget.step_used == 0
        for node in bundle.plan.nodes:
            with restored.budget.step_scope(f"{owner.run_id}:{node.node_id}", 1):
                assert restored.budget.step_used == 550
        # Legacy metrics have no attempt label. Preserve them conservatively against
        # the recorded current attempt instead of dropping their known usage on resume.
        first_id = f"{owner.run_id}:{bundle.plan.nodes[0].node_id}"
        store.record_metric(
            name="llm_tokens", value=50, unit="tokens", run_id=owner.run_id, step_id=first_id
        )
        restored._restore_model_budget()
        assert restored.budget.run_used == 1150
        with restored.budget.step_scope(first_id, 1):
            assert restored.budget.step_used == 600
            with pytest.raises(ModelBudgetExceeded):
                restored.budget.check(estimated=1)
        with restored.budget.step_scope(first_id, 2):
            assert restored.budget.step_used == 0
