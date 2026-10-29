"""Regressions from live DeepSeek delivery failures, with no provider calls."""

import errno
import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.gatekeeper.tier1 import Tier1Gate
from daedalus.application.gatekeeper.tier2 import ClientReviewer
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import (
    DeterministicPlanner,
    ModelPlanner,
    PlanRequest,
    ResourceBounds,
    SpecHardening,
)
from daedalus.application.scheduler import Quota
from daedalus.config import QuotaSettings
from daedalus.errors import DaedalusError, ModelBudgetExceeded, ModelResponseIncomplete
from daedalus.infrastructure.git_sandbox import CommandResult
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Completion, TokenBudget
from daedalus.model.mock import MockModelClient
from daedalus.model.multi_provider import MultiProviderClient
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND
from tests.test_intake import _http_app, intake_env


@pytest.mark.parametrize("mode", ["deterministic", "model", "fallback"])
def test_both_planners_obey_the_configured_memory_ceiling(mode):
    quota = QuotaSettings(max_memory_mb=2048, max_cpu=1)
    bounds = ResourceBounds.for_quota(quota)
    request = PlanRequest("r", "g", "fix", (TARGET,), TEST_COMMAND)
    deterministic = DeterministicPlanner(bounds=bounds)
    if mode == "fallback":
        planner = ModelPlanner(
            client=MockModelClient(responder=lambda messages: "not JSON"),
            hardening=SpecHardening(bounds=bounds),
        )
    elif mode == "model":
        payload = DeterministicPlanner().plan(request).to_dict()
        payload["spec_03_boundary"].update(memory_mb=999999, cpu_limit=99)
        planner = ModelPlanner(
            client=MockModelClient(responder=lambda prompt: json.dumps(payload)),
            hardening=SpecHardening(bounds=bounds),
        )
    else:
        planner = deterministic
    bundle = planner.plan(request)
    assert bundle.boundary.memory_mb == 2048 and bundle.boundary.cpu_limit == 1
    from daedalus.domain.spec import SpecBundle

    assert SpecBundle.from_dict(bundle.to_dict()).digest() == bundle.digest()


def test_missing_or_stale_confirmation_is_refused_without_a_new_model_call(git_repo, tmp_path):
    client, model = _http_app(tmp_path)
    with client:
        item = client.post(
            "/api/intakes", json={"repo_path": str(git_repo), "objective": "fix"}
        ).json()["intake"]
        for question in item["questions"]:
            client.post(
                f"/api/intakes/{item['intake_id']}/answers",
                json={"question_id": question["id"], "option_id": question["options"][0]["id"]},
            )
        assert client.post(f"/api/intakes/{item['intake_id']}/spec").status_code == 200
        digest = client.get(f"/api/intakes/{item['intake_id']}").json()["intake"]["spec_digest"]
        count = len(model.calls)
        for body in ({}, {"spec_digest": "0" * 64}):
            response = client.post(f"/api/intakes/{item['intake_id']}/freeze", json=body)
            assert response.status_code == 409
        assert digest and len(model.calls) == count


def test_reviewed_snapshot_tampering_is_refused(git_repo, tmp_path):
    service, _model, _ = intake_env(git_repo, tmp_path)
    session = service.start(str(git_repo), "fix").session
    for question in session.questions:
        service.answer(session.intake_id, question_id=question.id, option_id=question.options[0].id)
    _, bundle, _ = service.derive(session.intake_id)
    path = service.store.path.parent / "intake-specs" / (bundle.digest() + ".json")
    data = json.loads(path.read_text())
    data["spec_01_goal"]["objective"] = "a different goal"
    path.write_text(json.dumps(data))
    with pytest.raises(DaedalusError):
        service.reviewed_bundle(session.intake_id, bundle.digest())
    service.store.close()


def test_answer_change_invalidates_the_reviewed_digest(git_repo, tmp_path):
    service, _model, _ = intake_env(git_repo, tmp_path)
    session = service.start(str(git_repo), "fix").session
    for question in session.questions:
        service.answer(session.intake_id, question_id=question.id, option_id=question.options[0].id)
    _, bundle, _ = service.derive(session.intake_id)
    question = session.questions[0]
    service.answer(session.intake_id, question_id=question.id, option_id=question.options[1].id)
    with pytest.raises(DaedalusError):
        service.reviewed_bundle(session.intake_id, bundle.digest())
    assert not service.load(session.intake_id).spec_digest
    service.store.close()


def test_shell_infrastructure_fault_stops_after_one_candidate(git_repo, tmp_path, monkeypatch):
    calls = []

    class Worker:
        worker_id = "w"
        name = "w"

        def implement(self, sandbox, context):
            calls.append(1)
            return ScriptedWorker(ops=(FileOp("write", TARGET, CORRECT_IMPLEMENTATION),)).implement(
                sandbox, context
            )

    monkeypatch.setattr(
        Tier1Gate,
        "_run",
        lambda *args, **kwargs: CommandResult(
            "bash check", 128, "", "bash: fork: Resource temporarily unavailable", 1
        ),
    )
    bundle = DeterministicPlanner().plan(PlanRequest("r", "G", "fix", (TARGET,), TEST_COMMAND))
    with EventStore(tmp_path / "run.db") as store:
        owner = RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "wt",
            bundle=bundle,
            worker=Worker(),
            quota=Quota(),
        )
        owner.register_spec()
        result = owner.run()
        assert result.status == "AWAITING_APPROVAL", [(s.feedback, s.reasons) for s in result.steps]
        assert len(calls) == 1 and result.steps[0].attempt == 1
        assert not result.commits
        assert not any(
            e.event_type == "StepTier2Decided"
            for e in store.events_for_execution(result.execution_id)
        )


def test_spawn_resource_error_is_classified_before_gate_feedback(git_repo, tmp_path, monkeypatch):
    from types import SimpleNamespace

    bundle = DeterministicPlanner().plan(PlanRequest("r", "G", "fix", (TARGET,), TEST_COMMAND))
    gate = Tier1Gate(
        goal=bundle.goal, plan_node=bundle.plan.nodes[0], boundary=bundle.boundary, meta=bundle.meta
    )

    def unavailable(*args, **kwargs):
        raise OSError(errno.EAGAIN, "cannot spawn")

    result = gate._run(SimpleNamespace(run=unavailable), ["true"], timeout_sec=1)
    assert result.failure_code == "execution_environment_unavailable"


def test_incomplete_review_retries_same_subject_once_and_accounts_failed_usage():
    class Client:
        def __init__(self):
            self.calls = []

        def complete(self, messages, **kwargs):
            self.calls.append((messages, kwargs))
            if len(self.calls) == 1:
                raise ModelResponseIncomplete(
                    "empty", usage={"prompt_tokens": 10, "completion_tokens": 2048}, model="m"
                )
            return Completion(
                '{"decision":"ESCALATE"}', model="m", prompt_tokens=10, completion_tokens=20
            )

    client = Client()
    budget = TokenBudget()
    answer = ClientReviewer(client=client, budget=budget).complete(
        "same subject", subject_digest="d"
    )
    assert json.loads(answer)["decision"] == "ESCALATE"
    assert len(client.calls) == 2 and client.calls[0][0] == client.calls[1][0]
    assert [c[1]["max_tokens"] for c in client.calls] == [2048, 8192]
    assert budget.calls == 2 and budget.run_used == 2088
    assert all(not c.text for c in budget.usage_history)


def test_review_does_not_retry_a_valid_negative_verdict():
    client = MockModelClient(responder=lambda messages: '{"decision":"REVISE"}')
    reviewer = ClientReviewer(client=client)
    assert reviewer.complete("p", subject_digest="d") == '{"decision":"REVISE"}'
    assert len(client.calls) == 1


def test_failed_usage_can_exhaust_the_retry_budget_before_second_call():
    class Client:
        calls = 0

        def complete(self, *args, **kwargs):
            self.calls += 1
            raise ModelResponseIncomplete(
                "empty", usage={"prompt_tokens": 10, "completion_tokens": 2048}
            )

    client = Client()
    reviewer = ClientReviewer(client=client, budget=TokenBudget(max_tokens_per_run=3000))
    with pytest.raises(ModelBudgetExceeded):
        reviewer.complete("p", subject_digest="d")
    assert client.calls == 1


def test_native_empty_response_preserves_only_safe_usage_metadata(monkeypatch):
    payload = {
        "model": "deepseek-flash",
        "choices": [
            {
                "message": {"content": "", "reasoning_content": "private reasoning"},
                "finish_reason": "length",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2048},
    }
    monkeypatch.setattr(MultiProviderClient, "_json", lambda *args: (payload, str, False))
    with pytest.raises(ModelResponseIncomplete) as caught:
        MultiProviderClient().complete([])
    assert caught.value.context["finish_reason"] == "length"
    assert caught.value.context["usage"]["completion_tokens"] == 2048
    assert "private reasoning" not in json.dumps(caught.value.to_payload())


def test_pre_execution_planning_usage_is_not_lost(git_repo, tmp_path):
    from daedalus.application.coding_worker import ModelWorker

    budget = TokenBudget()
    budget.record(
        Completion("sensitive generated answer", model="m", prompt_tokens=80, completion_tokens=20)
    )
    worker = ModelWorker(client=MockModelClient(), budget=budget)
    bundle = DeterministicPlanner().plan(PlanRequest("r", "G", "fix", (TARGET,), TEST_COMMAND))
    with EventStore(tmp_path / "usage.db") as store:
        owner = RunOrchestrator(
            store=store, repo_path=git_repo, run_root=tmp_path / "wt", bundle=bundle, worker=worker
        )
        owner.register_spec()
        owner.create_run()
        owner._adopt_worker_budget()
        owner._adopt_worker_budget()
        assert owner.budget.run_used == 100 and owner.budget.calls == 1
        assert owner.budget.step_used == 0
        assert worker.budget is owner.budget
        assert not budget.usage_history[0].text


def test_observation_covers_failures_without_inventing_unknown_usage():
    from daedalus.errors import ModelUnavailable
    from daedalus.model.observed import ObservedClient

    rows = []

    class Client:
        calls = 0

        def complete(self, messages, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return Completion("private response", prompt_tokens=10, completion_tokens=2)
            if self.calls == 2:
                raise ModelResponseIncomplete(
                    "empty", usage={"prompt_tokens": 10, "completion_tokens": 20}
                )
            raise ModelUnavailable("no response")

    client = ObservedClient(Client(), rows.append)
    client.complete(["private input"])
    for _ in range(2):
        with pytest.raises(DaedalusError):
            client.complete(["private input"])
    assert [r["usage_known"] for r in rows] == [True, True, False]
    assert [r["tokens"] for r in rows] == [12, 30, None]
    assert "private" not in json.dumps(rows)


def test_cache_usage_is_preserved_without_provider_text_or_credentials():
    from daedalus.model.base import token_usage_details
    from daedalus.model.observed import ObservedClient

    usage = {"prompt_tokens": 100, "completion_tokens": 12, "prompt_cache_hit_tokens": 80,
             "prompt_cache_miss_tokens": 20, "completion_tokens_details": {"reasoning_tokens": 3,
             "private_response": "must not persist"}, "authorization": "must not persist"}

    class Client:
        def complete(self, messages, **kwargs):
            return Completion("private response", prompt_tokens=100, completion_tokens=12,
                              raw={"usage_reported": True, "usage": usage})

    rows = []
    ObservedClient(Client(), rows.append).complete([])
    assert rows[0]["tokens"] == 112 and rows[0]["prompt_tokens"] == 100
    assert rows[0]["completion_tokens"] == 12
    assert rows[0]["usage_details"]["prompt_cache_hit_tokens"] == 80
    assert rows[0]["usage_details"]["completion_tokens_details"] == {"reasoning_tokens": 3}
    assert "private" not in json.dumps(rows) and "authorization" not in json.dumps(rows)
    assert token_usage_details({"prompt_tokens": -1, "input_tokens": True, "output_tokens": "12"}) == {}


def test_front_door_freeze_with_model_enabled_reaches_real_gates_and_delivery(git_repo, tmp_path):
    """Exercise the actual intake/worker/reviewer wiring, without a socket or provider."""
    import re

    from daedalus.config import Settings, WorkspaceSettings
    from daedalus.service.app import create_app
    from tests.test_intake import _questions_payload
    from tests.test_service import _wait_for

    bundle = DeterministicPlanner().plan(
        PlanRequest("r", "GOAL-001", "fix word counting", (TARGET,), TEST_COMMAND)
    )

    class Client:
        model = "offline-integration"

        def __init__(self):
            self.stages = []

        def complete(self, messages, **kwargs):
            prompt = "\n".join(m.content for m in messages)
            if "You investigate missing evidence" in prompt:
                stage, payload = "retrieve", {"action": "finish"}
            elif "intake 环节" in prompt:
                stage, payload = "questions", _questions_payload()
            elif "You are the Planner" in prompt:
                stage, payload = "planner", bundle.to_dict()
            elif "You are the Coding worker" in prompt:
                stage, payload = (
                    "coder",
                    {
                        "operations": [
                            {"op": "write", "path": TARGET, "content": CORRECT_IMPLEMENTATION}
                        ]
                    },
                )
            else:
                stage = "goal" if "FINAL GOAL audit" in prompt else "review"
                payload = {
                    "decision": "APPROVE",
                    "subject_digest": re.search(r"SUBJECT_DIGEST: ([0-9a-f]{64})", prompt).group(1),
                    "reasons": ["validated diff and deterministic evidence"],
                    "violations": [],
                    "confidence": 0.99,
                }
                if stage == "goal":
                    payload["criterion_results"] = [
                        {
                            "criterion_id": c.criterion_id,
                            "status": "MET",
                            "evidence": "exact tree passed executable criterion",
                        }
                        for c in bundle.goal.acceptance_criteria
                    ]
            self.stages.append(stage)
            return Completion(
                json.dumps(payload), model=self.model, prompt_tokens=10, completion_tokens=20
            )

    model = Client()
    settings = Settings(
        workspace=WorkspaceSettings(root=str(tmp_path / "ws")),
        quota=QuotaSettings(max_memory_mb=2048, max_cpu=1),
    )
    app = create_app(settings)
    app.state.daedalus.build_model_client = lambda role="": model
    app.state.daedalus.knowledge.add(
        str(git_repo),
        kind="preference",
        title="Project preference",
        text="Keep the public API stable and validate word counting regressions.",
        confirmed=True,
    )
    with TestClient(app) as client:
        session = client.post(
            "/api/intakes", json={"repo_path": str(git_repo), "objective": "fix word counting"}
        ).json()["intake"]
        intake_id = session["intake_id"]
        for question in session["questions"]:
            response = client.post(
                f"/api/intakes/{intake_id}/answers",
                json={"question_id": question["id"], "option_id": question["options"][0]["id"]},
            )
            assert response.status_code == 200
        planned = client.post(f"/api/intakes/{intake_id}/spec").json()
        assert planned["document"]["spec_03_boundary"]["memory_mb"] == 2048
        frozen = client.post(
            f"/api/intakes/{intake_id}/freeze",
            json={"spec_digest": planned["spec_digest"], "use_model": True, "enable_review": True},
        )
        assert frozen.status_code == 202, frozen.text
        status = _wait_for(
            client,
            frozen.json()["run_id"],
            terminal={"COMPLETED", "FAILED", "AWAITING_APPROVAL"},
            timeout=30,
        )
        assert status == "COMPLETED"
        assert model.stages == [
            "questions",
            "retrieve",
            "planner",
            "coder",
            "review",
            "goal",
        ]
        traces = app.state.daedalus.knowledge.traces(str(git_repo))
        assert {t["phase"] for t in traces} == {"planning", "execution"}
        assert all(t["citations"] for t in traces)
        run_id = frozen.json()["run_id"]
        metrics = app.state.daedalus.store.connection.execute(
            "SELECT SUM(value) FROM metrics WHERE run_id=? AND name='llm_calls'", (run_id,)
        ).fetchone()[0]
        # Simple tasks use direct search, with no retrieval-controller call.
        # Intake planning is pre-run; coding and both reviews belong to this run.
        assert metrics == 3
        # Intake's broad selected boundary merits investigation; the frozen coding
        # node has one concrete artifact and uses direct search.
        assert {t["phase"]:t["route"] for t in traces} == {"planning":"deep", "execution":"grep"}


@pytest.mark.parametrize("defect", ["report_label", "read_only"])
def test_unexecutable_verification_nodes_are_repaired_before_intake_freeze(defect):
    request = PlanRequest("r", "g", "fix", (TARGET,), TEST_COMMAND)
    valid = DeterministicPlanner().plan(request).to_dict()
    broken = json.loads(json.dumps(valid))
    node = broken["spec_02_plan"]["nodes"][0]
    if defect == "report_label":
        node["expected_artifacts"] = ["test_results"]
    else:
        node["allowed_tools"] = ["read", "test"]
    responses = iter([broken, valid])
    client = MockModelClient(responder=lambda messages: json.dumps(next(responses)))
    planner = ModelPlanner(client=client, require_model=True)
    result = planner.plan(request)
    assert planner.repaired and len(client.calls) == 2
    assert result.plan.nodes[0].expected_artifacts == (TARGET,)
    assert "write" in result.plan.nodes[0].allowed_tools


@pytest.mark.parametrize("has_local_check", [False, True])
def test_upstream_candidates_need_independent_checks_or_an_atomic_fallback(has_local_check):
    from daedalus.domain.spec import AcceptanceCriterion, AssertionKind

    request = PlanRequest("r", "g", "coupled API", (TARGET,), TEST_COMMAND)
    original = DeterministicPlanner().plan(request)
    local = (AcceptanceCriterion(
        criterion_id="node-check", kind=AssertionKind.EXIT_CODE,
        statement="validate this module independently", command="python3 -c 'assert True'",
    ),) if has_local_check else ()
    first = replace(original.plan.nodes[0], node_id="first",
                    extra={"acceptance_criteria": [c.to_dict() for c in local]})
    second = replace(original.plan.nodes[0], node_id="second", deps=("first",),
                     extra={"acceptance_criteria": [c.to_dict() for c in original.goal.acceptance_criteria]}
                     if has_local_check else {})
    candidate = replace(original, plan=replace(original.plan, nodes=(first, second)))
    client = MockModelClient(responder=lambda messages: json.dumps(candidate.to_dict()))
    result = ModelPlanner(client=client).plan(request)
    assert len(result.plan.nodes) == (2 if has_local_check else 1)
    assert result.goal.acceptance_criteria == original.goal.acceptance_criteria
    assert result.boundary.fs_whitelist == original.boundary.fs_whitelist


@pytest.mark.parametrize("expression", ["self._peek()", "self.tokens[self.pos]", "next_token()"])
def test_parser_token_assignments_are_preserved_and_safe_to_retrieve(expression):
    from daedalus.infrastructure.redact import redact_text
    from daedalus.security.outbound import assert_outbound_clean

    source = f"def parse(self):\n    token = {expression}\n    return token\n"
    assert redact_text(source) == source
    assert_outbound_clean(source, where="parser source")
    client = MultiProviderClient(base_url="https://api.deepseek.com", model="deepseek-flash",
                                 api_key_resolver=lambda: "")
    # The transport's actual inbound sanitizer must not rewrite candidate code.
    client._json = lambda path, body: (
        {"choices": [{"message": {"content": json.dumps({"operations": [
            {"op": "write", "path": "parser.py", "content": source}
        ]})}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1,"completion_tokens": 1}},
        redact_text,
        False,
    )
    completion = client.complete([])
    assert json.loads(completion.text)["operations"][0]["content"] == source


@pytest.mark.parametrize("assignment", [
    'token = "secret(value)12345"', "token=opaque-long-credential", 
    "password='p@ss(word)12345'", "api_key=opaque@credential/value123",
])
def test_literal_credentials_are_still_rejected_after_parser_false_positive_fix(assignment):
    from daedalus.infrastructure.redact import REDACTED, redact_text
    from daedalus.security.outbound import SecretInPayload, assert_outbound_clean

    assert REDACTED in redact_text(assignment)
    with pytest.raises(SecretInPayload):
        assert_outbound_clean(assignment, where="unsafe source")
