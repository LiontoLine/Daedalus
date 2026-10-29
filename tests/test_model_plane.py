"""The model plane, executed for real (Spec §1.2, §8, §9.2).

Before this file existed, `OpenAICompatibleClient`, `ModelPlanner`, `ModelWorker` and the
Tier-2 reviewer had **zero** test coverage: the system's central claim — that uncertain
model capability is confined by a deterministic control plane — had never been executed.

These tests drive a real HTTP server over a real socket. Nothing is mocked except the
intelligence: the request shaping, the auth header, the token accounting, the redaction and
every refusal are all the production code paths.

Four properties are the point:

1. a model can produce a plan and a change, and the pipeline accepts them;
2. a model that proposes an out-of-bounds write is refused by the boundary, not by a prompt;
3. a model that returns an unusable plan fails without corrupting anything;
4. a reviewer that misbehaves fails closed, and the credential never leaks.
"""

from __future__ import annotations

import json

import pytest

from daedalus.application.coding_worker import ModelWorker
from daedalus.application.gatekeeper.decision import GateDecision
from daedalus.application.gatekeeper.tier2 import (
    ClientReviewer,
    SemanticReviewRequest,
    Tier2Gate,
)
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import (
    ModelPlanner,
    PlanRequest,
    SpecHardening,
)
from daedalus.application.scheduler import Quota
from daedalus.domain.spec import MetaSpec, NetworkPolicy, RiskLevel
from daedalus.errors import ModelError
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Message, TokenBudget
from daedalus.model.openai_compatible import OpenAICompatibleClient
from daedalus.security.secrets import SecretBroker
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND
from tests.fake_gateway import (
    FakeGateway,
    Reply,
    coder_escape_reply,
    coder_reply,
    planner_reply,
)

FAKE_KEY = "sk-fake-key-abcdefghijklmnopqrstuvwxyz012345"


def _client(gateway: FakeGateway, *, budget: TokenBudget | None = None, broker: SecretBroker | None = None):
    """The production client, wired to the loopback gateway through the real broker."""
    broker = broker or SecretBroker()
    return OpenAICompatibleClient(
        name="fake-gateway-client",
        model="fake-gpt",
        base_url=gateway.base_url,
        timeout_sec=20,
        api_key_resolver=lambda: broker.redeem(broker.request("model.api_key")),
    )


@pytest.fixture()
def api_key(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("DAEDALUS_MODEL_API_KEY", FAKE_KEY)
    return FAKE_KEY


def _request() -> PlanRequest:
    return PlanRequest(
        request_id="REQ-FAKE",
        goal_id="GOAL-FAKE",
        objective="fix the word counter",
        target_paths=(TARGET,),
        test_command=TEST_COMMAND,
        risk_level=RiskLevel.NORMAL,
        network_policy=NetworkPolicy.DENY,
    )


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


def test_the_client_speaks_the_openai_wire_protocol(api_key) -> None:
    with FakeGateway(replies=[Reply(content='{"ok":true}')], require_auth=FAKE_KEY) as gateway:
        completion = _client(gateway).complete(
            [Message(role="user", content="hello")], response_format_json=True
        )
    assert completion.text == '{"ok":true}'
    assert completion.total_tokens == 18
    sent = gateway.requests[0]
    assert sent["model"] == "fake-gpt"
    assert sent["response_format"] == {"type": "json_object"}
    assert sent["messages"][0]["content"] == "hello"
    # The credential is sent as a bearer header and nowhere else.
    assert gateway.headers[0]["Authorization"] == f"Bearer {FAKE_KEY}"


def test_a_401_is_a_terminal_model_error_not_a_retry(api_key) -> None:
    with FakeGateway(replies=[Reply(content="", status=401)], require_auth="a-different-key") as gw:
        with pytest.raises(ModelError):
            _client(gw).complete([Message(role="user", content="hello")])


def test_a_500_is_a_retryable_infrastructure_error(api_key) -> None:
    from daedalus.errors import ErrorClass, RetryableInfrastructureError

    with FakeGateway(replies=[Reply(content="", status=503)]) as gateway:
        with pytest.raises(RetryableInfrastructureError) as error:
            _client(gateway).complete([Message(role="user", content="hello")])
    assert error.value.error_class is ErrorClass.RETRYABLE


def test_a_malformed_response_shape_is_reported(api_key) -> None:
    with FakeGateway(responder=lambda payload: Reply(error_body={"unexpected": True})) as gateway:
        with pytest.raises(ModelError, match="unexpected model response shape"):
            _client(gateway).complete([Message(role="user", content="hello")])


@pytest.mark.parametrize("adapter", ["chat", "multi"])
@pytest.mark.parametrize("complete_json", [True, False])
def test_real_http_chunk_termination_loss_never_replays(adapter, complete_json):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from daedalus.model.multi_provider import MultiProviderClient

    calls = []
    body = json.dumps({
        "choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":12,"completion_tokens":3},
    }).encode()
    if not complete_json:
        body = body[:35]

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            calls.append(1)
            self.send_response(200)
            self.send_header("Transfer-Encoding","chunked")
            self.end_headers()
            self.wfile.write(f"{len(body):x}\r\n".encode()+body+b"\r\n")
            self.wfile.flush()
            self.close_connection = True  # Deliberately omit the final zero chunk.

        def log_message(self,*args):
            pass

    with ThreadingHTTPServer(("127.0.0.1",0),Handler) as server:
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        cls = MultiProviderClient if adapter == "multi" else OpenAICompatibleClient
        client = cls(base_url=f"http://127.0.0.1:{server.server_port}",
                     api_key_resolver=lambda:"synthetic-offline-credential",timeout_sec=5)
        try:
            if complete_json:
                result = client.complete([Message("user","hello")])
                assert result.text == "ok" and result.total_tokens == 15
                assert result.raw["http_framing_recovered"]
            else:
                with pytest.raises(ModelError):
                    client.complete([Message("user","hello")])
            assert calls == [1]
        finally:
            server.shutdown()
            thread.join(timeout=5)


def test_the_credential_never_appears_in_a_returned_completion(api_key) -> None:
    """Even when the model echoes the key back, the client must redact it."""
    leaky = f"here is the key: {FAKE_KEY}"
    with FakeGateway(replies=[Reply(content=leaky)], require_auth=FAKE_KEY) as gateway:
        completion = _client(gateway).complete([Message(role="user", content="hello")])
    assert FAKE_KEY not in completion.text
    assert "REDACTED" in completion.text


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


def test_the_model_planner_produces_a_usable_spec(api_key) -> None:
    with FakeGateway(
        replies=[planner_reply(node_ids=["fix-counter"], tree=TARGET)]
    ) as gateway:
        bundle = ModelPlanner(client=_client(gateway), budget=TokenBudget()).plan(_request())

    assert bundle.goal.goal_id == "GOAL-FAKE"
    assert bundle.plan.nodes[0].expected_artifacts == (TARGET,)
    assert bundle.boundary.fs_whitelist == (TARGET,)
    assert bundle.digest()
    assert gateway.request_count == 1


def test_a_model_plan_that_whitelists_the_gatekeeper_is_clamped(api_key) -> None:
    """The model proposes; the Meta-Spec disposes. This is the whole design in one test."""
    hostile = planner_reply(node_ids=["rewrite-gate"], tree="src/daedalus/application/gatekeeper/tier1.py")
    with FakeGateway(replies=[hostile]) as gateway:
        bundle = ModelPlanner(client=_client(gateway)).plan(_request())

    # The forbidden path is gone from both the boundary and the plan, replaced by the
    # planner's deterministic fallback rather than emitted as an unenforceable task.
    assert "src/daedalus/application/gatekeeper/tier1.py" not in bundle.boundary.fs_whitelist
    assert all(
        "gatekeeper" not in artifact
        for node in bundle.plan.nodes
        for artifact in node.expected_artifacts
    )
    assert bundle.goal.acceptance_criteria


def test_a_useless_model_plan_falls_back_instead_of_failing_the_run(api_key) -> None:
    with FakeGateway(replies=[Reply(content="I think you should just fix it yourself.")]) as gw:
        bundle = ModelPlanner(client=_client(gw), fallback=_fallback()).plan(_request())
    assert bundle.goal.goal_id == "GOAL-FAKE"
    assert bundle.boundary.fs_whitelist  # the fallback produced something runnable


def _fallback():
    from daedalus.application.planner import DeterministicPlanner

    return DeterministicPlanner()


def test_an_unreachable_planner_falls_back(api_key) -> None:
    gateway = FakeGateway().start()
    base_url = gateway.base_url
    gateway.stop()  # nothing is listening now
    client = OpenAICompatibleClient(model="fake-gpt", base_url=base_url, api_key_resolver=lambda: FAKE_KEY)
    bundle = ModelPlanner(client=client, fallback=_fallback()).plan(_request())
    assert bundle.boundary.fs_whitelist


# ---------------------------------------------------------------------------
# Coding worker, in a real run
# ---------------------------------------------------------------------------


def _run_with_model(git_repo, tmp_path, gateway: FakeGateway, *, budget: TokenBudget | None = None):
    store = EventStore(tmp_path / "model-run.db")
    bundle = ModelPlanner(client=_client(gateway), fallback=_fallback()).plan(_request())
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=ModelWorker(client=_client(gateway), budget=budget or TokenBudget()),
        quota=Quota(max_parallel_steps=1),
        park_on_escalation=False,
    )
    orchestrator.register_spec()
    return store, orchestrator, orchestrator.run()


def test_a_model_generated_change_passes_the_gate_and_commits(
    git_repo, tmp_path, api_key
) -> None:
    """The full chain against the real transport: plan -> worktree -> gate -> commit."""
    gateway = FakeGateway(
        replies=[
            planner_reply(node_ids=["fix-counter"], tree=TARGET),
            coder_reply(path=TARGET, content=CORRECT_IMPLEMENTATION),
        ]
    ).start()
    try:
        store, _orchestrator, result = _run_with_model(git_repo, tmp_path, gateway)
    finally:
        gateway.stop()

    assert result.status == "COMPLETED", result.describe()
    assert result.commits
    assert gateway.request_count == 2, "one planning call and one coding call"
    # The artifact records which model produced it, for the audit.
    step = store.list_steps(result.run_id)[0]
    artifact = store.artifacts_for_step(str(step["step_id"]))[-1]
    assert artifact["model"] == "fake-gpt"
    store.close()


def test_a_model_that_escapes_the_boundary_is_refused(git_repo, tmp_path, api_key) -> None:
    """The refusal comes from the boundary guard, not from asking the model nicely."""
    gateway = FakeGateway(
        replies=[
            planner_reply(node_ids=["fix-counter"], tree=TARGET),
            coder_escape_reply(
                path=TARGET,
                content=CORRECT_IMPLEMENTATION,
                escape_path="src/example_project/model_added_module.py",
            ),
        ]
    ).start()
    try:
        store, _orchestrator, result = _run_with_model(git_repo, tmp_path, gateway)
    finally:
        gateway.stop()

    assert result.status != "COMPLETED"
    assert not result.commits
    # Nothing from the refused batch was written, including the whitelisted part.
    assert not (git_repo / "src" / "example_project" / "model_added_module.py").exists()
    failures = store.connection.execute(
        "SELECT labels FROM metrics WHERE name = 'step_failures'"
    ).fetchall()
    assert failures
    store.close()


def test_an_unusable_model_edit_plan_fails_cleanly(git_repo, tmp_path, api_key) -> None:
    gateway = FakeGateway(
        replies=[
            planner_reply(node_ids=["fix-counter"], tree=TARGET),
            Reply(content="Sure! Here is my plan: just change the file."),
        ]
    ).start()
    try:
        store, _orchestrator, result = _run_with_model(git_repo, tmp_path, gateway)
    finally:
        gateway.stop()
    assert result.status != "COMPLETED"
    assert not result.commits
    assert any("unusable" in step.feedback or "plan" in step.feedback for step in result.steps)
    store.close()


def test_a_model_cannot_raise_its_own_resource_ceiling(api_key) -> None:
    """The model authors SPEC-03, so an operator ceiling must clamp the numbers too."""
    from daedalus.application.planner import ResourceBounds
    from daedalus.domain.spec import BoundarySpec, GoalSpec, PlanSpec

    greedy = Reply(
        content=json.dumps(
            {
                "spec_01_goal": {
                    "goal_id": "GOAL-GREEDY",
                    "objective": "fix the counter",
                    "acceptance_criteria": [
                        {"criterion_id": "AC-1", "kind": "exit_code", "command": "true"}
                    ],
                    "risk_level": "normal",
                },
                "spec_02_plan": {
                    "plan_id": "P",
                    "goal_id": "GOAL-GREEDY",
                    "nodes": [
                        {
                            "node_id": "n1",
                            "deps": [],
                            "expected_artifacts": [TARGET],
                            "timeout_sec": 86_400,
                        }
                    ],
                },
                "spec_03_boundary": {
                    "boundary_id": "B",
                    "goal_id": "GOAL-GREEDY",
                    "fs_whitelist": [TARGET],
                    "network_policy": "deny",
                    "max_tokens_per_step": 99_000_000,
                    "max_runtime_sec": 86_400,
                    "memory_mb": 999_999,
                    "cpu_limit": 512,
                    "process_limit": 100_000,
                },
            }
        )
    )
    bounds = ResourceBounds(max_tokens_per_step=50_000, max_runtime_sec=600, memory_mb=4096,
                            cpu_limit=4.0, process_limit=256)
    with FakeGateway(replies=[greedy]) as gateway:
        planner = ModelPlanner(
            client=_client(gateway), fallback=_fallback(),
            hardening=SpecHardening(bounds=bounds),
        )
        bundle = planner.plan(_request())

    assert bundle.boundary.max_tokens_per_step == 50_000
    assert bundle.boundary.max_runtime_sec == 600
    assert bundle.boundary.memory_mb == 4096
    assert bundle.boundary.cpu_limit == 4.0
    assert bundle.boundary.process_limit == 256
    assert planner.last_adjustments, "the clamps must be reported, not silently applied"


def test_the_spec_token_limit_alone_stops_the_run(git_repo, tmp_path, api_key) -> None:
    """SPEC-03's max_tokens_per_step must bind even with no worker-side budget."""
    from dataclasses import replace as _replace

    gateway = FakeGateway(
        replies=[coder_reply(path=TARGET, content=CORRECT_IMPLEMENTATION) for _ in range(4)]
    ).start()
    try:
        store = EventStore(tmp_path / "tight.db")
        request = _replace(_request(), goal_id="GOAL-TIGHT", max_tokens_per_step=40)
        bundle = _fallback().plan(request)
        assert bundle.boundary.max_tokens_per_step == 40
        orchestrator = RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "wtt",
            bundle=bundle,
            worker=ModelWorker(client=_client(gateway)),
            quota=Quota(max_parallel_steps=1),
            park_on_escalation=False,
        )
        orchestrator.register_spec()
        result = orchestrator.run()
    finally:
        gateway.stop()
    assert result.status != "COMPLETED"
    assert not result.commits
    assert any("budget" in reason.lower() for step in result.steps for reason in step.reasons)
    store.close()


def test_a_stricter_worker_budget_wins_and_is_shared(git_repo, tmp_path, api_key) -> None:
    """Two independent budgets would let the gate pass a step that already overspent."""
    gateway = FakeGateway(
        replies=[
            planner_reply(node_ids=["fix-counter"], tree=TARGET),
            *[coder_reply(path=TARGET, content=CORRECT_IMPLEMENTATION) for _ in range(5)],
        ]
    ).start()
    try:
        # A budget smaller than one completion must stop the run rather than spend freely.
        budget = TokenBudget(max_tokens_per_step=5, max_tokens_per_run=5)
        store, _orchestrator, result = _run_with_model(
            git_repo, tmp_path, gateway, budget=budget
        )
    finally:
        gateway.stop()
    assert result.status != "COMPLETED"
    assert not result.commits
    store.close()


# ---------------------------------------------------------------------------
# Tier-2 reviewer, over the real transport
# ---------------------------------------------------------------------------


def _review_request() -> SemanticReviewRequest:
    return SemanticReviewRequest(
        step_id="s1",
        execution_id="exec-1",
        artifact_digest="artifact-1",
        goal_intent="fix the counter",
        node_intent="count words with split()",
        acceptance_criteria=("AC-1: tests pass",),
        changed_files=(TARGET,),
        patch="--- a\n+++ b\n",
        tier1_summary="01_path_whitelist=pass",
    )


def test_the_reviewer_approves_over_the_real_transport(api_key) -> None:
    request = _review_request()

    def responder(payload: dict) -> Reply:
        return Reply(
            content=json.dumps(
                {
                    "decision": "APPROVE",
                    "subject_digest": request.subject_digest(),
                    "reasons": ["matches the stated intent"],
                    "violations": [],
                    "confidence": 0.9,
                }
            )
        )

    with FakeGateway(responder=responder) as gateway:
        result = Tier2Gate(reviewer=ClientReviewer(client=_client(gateway))).review(request)
    assert result.decision is GateDecision.APPROVE
    assert not result.fail_closed


def test_a_reviewer_that_answers_about_another_subject_fails_closed(api_key) -> None:
    with FakeGateway(
        responder=lambda payload: Reply(
            content=json.dumps(
                {
                    "decision": "APPROVE",
                    "subject_digest": "a-different-subject",
                    "reasons": [],
                    "violations": [],
                    "confidence": 0.99,
                }
            )
        )
    ) as gateway:
        result = Tier2Gate(reviewer=ClientReviewer(client=_client(gateway))).review(_review_request())
    assert result.decision is GateDecision.ESCALATE
    assert result.fail_closed
    assert "different subject" in result.reasons[0]


def test_a_reviewer_that_returns_prose_fails_closed(api_key) -> None:
    with FakeGateway(replies=[Reply(content="Looks fine to me! Ship it.")]) as gateway:
        result = Tier2Gate(reviewer=ClientReviewer(client=_client(gateway))).review(_review_request())
    assert result.decision is GateDecision.ESCALATE
    assert result.fail_closed


def test_a_reviewer_outage_fails_closed_rather_than_approving(api_key) -> None:
    with FakeGateway(replies=[Reply(content="", status=503)]) as gateway:
        result = Tier2Gate(reviewer=ClientReviewer(client=_client(gateway))).review(_review_request())
    assert result.decision is GateDecision.ESCALATE
    assert result.fail_closed
    assert "transport" in result.reasons[0]


def test_the_review_prompt_carries_the_contract_and_not_the_credential(api_key) -> None:
    with FakeGateway(replies=[Reply(content="{}")]) as gateway:
        Tier2Gate(reviewer=ClientReviewer(client=_client(gateway))).review(_review_request())
    prompt = gateway.last_prompt()
    assert "SUBJECT_DIGEST" in prompt
    assert "APPROVE|REVISE|ESCALATE" in prompt
    assert "NOT a formal verifier" in prompt
    assert FAKE_KEY not in prompt
    assert FAKE_KEY not in json.dumps(gateway.requests)
