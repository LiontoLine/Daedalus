"""The Gatekeeper is the point of the whole system, so test it adversarially.

Every test here is an attempt to get something past the gate that should not pass.
Tier-1 tests use a real Git worktree; Tier-2 tests drive the reviewer directly so the
fail-closed rules can be exercised precisely.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from daedalus.application.gatekeeper.decision import GateDecision
from daedalus.application.gatekeeper.tier1 import Tier1Gate
from daedalus.application.gatekeeper.tier2 import (
    SemanticReviewRequest,
    Tier2Gate,
)
from daedalus.domain.artifacts import Artifact
from daedalus.domain.spec import (
    AcceptanceCriterion,
    AssertionKind,
    BoundarySpec,
    GoalSpec,
    MetaSpec,
    NetworkPolicy,
    PlanNode,
    PlanSpec,
    RiskLevel,
)
from daedalus.infrastructure.git_sandbox import GitSandbox
from tests.conftest import CORRECT_IMPLEMENTATION, SYNTAX_ERROR_IMPLEMENTATION, TARGET


@pytest.fixture()
def sandbox(git_repo, tmp_path):
    box = GitSandbox.create(
        repo_path=git_repo, run_root=tmp_path / "wt", name="gate-test", base_ref="HEAD"
    )
    yield box
    box.remove()


def _goal(criteria) -> GoalSpec:
    return GoalSpec(
        goal_id="GOAL-1",
        objective="fix the word counter",
        acceptance_criteria=criteria,
        risk_level=RiskLevel.NORMAL,
    )


def _gate(*, criteria, whitelist=("src/example_project/textstats.py",), node_extra=None) -> Tier1Gate:
    return Tier1Gate(
        goal=_goal(criteria),
        plan_node=PlanNode(
            node_id="n1",
            expected_artifacts=tuple(whitelist),
            extra=node_extra or {},
        ),
        boundary=BoundarySpec(
            boundary_id="B-1",
            goal_id="GOAL-1",
            fs_whitelist=tuple(whitelist),
            network_policy=NetworkPolicy.DENY,
        ),
        meta=MetaSpec.default(),
    )


def _artifact(sandbox: GitSandbox) -> Artifact:
    diff = sandbox.diff()
    return Artifact(
        step_id="s1",
        execution_id="exec-1",
        parent_commit=sandbox.head(),
        changed_files=diff.files,
        patch_digest="patch",
        artifact_digest="artifact",
        spec_digest="spec",
    )


def _tests_criterion() -> AcceptanceCriterion:
    return AcceptanceCriterion(
        criterion_id="AC-tests",
        kind=AssertionKind.EXIT_CODE,
        command="python3 -m pytest tests -q",
    )


def test_tier1_passes_a_correct_change(sandbox) -> None:
    sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
    report = _gate(criteria=(_tests_criterion(),)).run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.decision is GateDecision.PASS, report.revise_feedback()


def test_tier1_rejects_an_out_of_bounds_path(sandbox) -> None:
    sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
    sandbox.write_file("src/example_project/extra.py", "# not whitelisted\n")
    report = _gate(criteria=(_tests_criterion(),)).run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.decision is GateDecision.REVISE
    assert any("fs_whitelist" in reason for reason in report.reasons)


def test_tier1_rejects_a_meta_spec_protected_path(sandbox) -> None:
    """The boundary whitelists it, the Meta-Spec still refuses it."""
    gate = _gate(
        criteria=(AcceptanceCriterion(criterion_id="AC-x", kind=AssertionKind.EXIT_CODE, command="true"),),
        whitelist=("src/daedalus/domain/fsm.py",),
    )
    sandbox.write_file("src/daedalus/domain/fsm.py", "# agent rewrite\n")
    report = gate.run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.decision is GateDecision.REVISE
    assert any("Meta-Spec" in reason for reason in report.reasons)


def test_tier1_rejects_a_credential_file(sandbox) -> None:
    gate = _gate(
        criteria=(AcceptanceCriterion(criterion_id="AC-x", kind=AssertionKind.EXIT_CODE, command="true"),),
        whitelist=(".env",),
    )
    try:
        sandbox.write_file(".env", "OPENAI_API_KEY=sk-realsecretvalue123456\n")
    except Exception:  # noqa: BLE001 - refusing the write is a valid outcome, not a failure
        pytest.skip("worktree refused the write, which is also a valid outcome")
    report = gate.run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.decision is GateDecision.REVISE


def test_tier1_rejects_a_syntax_error(sandbox) -> None:
    sandbox.write_file(TARGET, SYNTAX_ERROR_IMPLEMENTATION)
    report = _gate(criteria=(_tests_criterion(),)).run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.decision is GateDecision.REVISE
    assert any(check.name == "05_ast_syntax" and not check.passed for check in report.checks)


def test_tier1_rejects_a_failing_acceptance_test(sandbox) -> None:
    criterion = AcceptanceCriterion(
        criterion_id="AC-must-fail",
        kind=AssertionKind.EXIT_CODE,
        command="python3 -c 'import sys; sys.exit(3)'",
    )
    sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
    report = _gate(criteria=(criterion,)).run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.decision is GateDecision.REVISE
    assert any(check.name == "11_acceptance_criteria" and not check.passed for check in report.checks)


def test_tier1_rejects_an_empty_diff(sandbox) -> None:
    report = _gate(criteria=(_tests_criterion(),)).run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.decision is GateDecision.REVISE
    assert any(check.name == "02_git_diff" and not check.passed for check in report.checks)


def test_tier1_rejects_a_missing_expected_artifact(sandbox) -> None:
    """The plan promised a file that the worker did not produce."""
    gate = _gate(
        criteria=(_tests_criterion(),),
        whitelist=("src/example_project/textstats.py", "src/example_project/missing.py"),
    )
    sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
    report = gate.run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.decision is GateDecision.REVISE
    assert any(
        check.name == "09_expected_artifacts" and not check.passed for check in report.checks
    )
    assert any("missing.py" in reason for reason in report.reasons)


def test_tier1_rejects_an_ast_property_violation(sandbox) -> None:
    sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
    criterion = AcceptanceCriterion(
        criterion_id="AC-ast",
        kind=AssertionKind.AST_PROPERTY,
        path=TARGET,
        expect={"defines": ["summarize", "count_words"], "forbids": ["eval"]},
    )
    report = _gate(criteria=(criterion,)).run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.decision is GateDecision.REVISE
    assert any("count_words" in reason for reason in report.reasons)


def test_tier1_enforces_the_token_budget(sandbox) -> None:
    sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
    report = _gate(criteria=(_tests_criterion(),)).run(
        step_id="s1",
        execution_id="exec-1",
        sandbox=sandbox,
        artifact=_artifact(sandbox),
        tokens_used=10_000_000,
    )
    assert report.decision is GateDecision.REVISE
    assert any("token budget" in reason for reason in report.reasons)


def test_tier1_flags_network_imports_as_an_advisory(sandbox) -> None:
    source = CORRECT_IMPLEMENTATION.replace("from __future__ import annotations", "import socket")
    sandbox.write_file(TARGET, source)
    report = _gate(criteria=(_tests_criterion(),)).run(
        step_id="s1", execution_id="exec-1", sandbox=sandbox, artifact=_artifact(sandbox)
    )
    assert report.advisories, "a network import under network_policy=deny must be reported"
    assert "socket" in " ".join(report.advisories)


# ---------------------------------------------------------------------------
# Tier-2 fail-closed behaviour
# ---------------------------------------------------------------------------


class _StaticReviewer:
    def __init__(self, payload) -> None:
        self.payload = payload
        self.prompts: list[str] = []

    def complete(self, prompt: str, *, subject_digest: str) -> str:
        self.prompts.append(prompt)
        if callable(self.payload):
            return self.payload(subject_digest)
        return self.payload if isinstance(self.payload, str) else json.dumps(self.payload)


def _request() -> SemanticReviewRequest:
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


def test_tier2_accepts_a_well_formed_approval() -> None:
    request = _request()
    reviewer = _StaticReviewer(
        lambda digest: json.dumps(
            {
                "decision": "APPROVE",
                "subject_digest": digest,
                "reasons": ["matches intent"],
                "violations": [],
                "confidence": 0.9,
            }
        )
    )
    result = Tier2Gate(reviewer=reviewer).review(request)
    assert result.decision is GateDecision.APPROVE
    assert not result.fail_closed


def test_tier2_rejects_a_review_of_a_different_subject() -> None:
    reviewer = _StaticReviewer(
        json.dumps(
            {
                "decision": "APPROVE",
                "subject_digest": "some-other-subject",
                "reasons": [],
                "violations": [],
                "confidence": 0.99,
            }
        )
    )
    result = Tier2Gate(reviewer=reviewer).review(_request())
    assert result.decision is GateDecision.ESCALATE
    assert result.fail_closed


def test_tier2_rejects_approval_bound_to_a_different_execution_log() -> None:
    original = replace(
        _request(), execution_log="start\n" + "observation\n" * 300 + "old detail\nend\n"
    )
    changed = replace(original, execution_log=original.execution_log.replace("old detail", "new detail"))
    reviewer = _StaticReviewer(
        {
            "decision": "APPROVE",
            "subject_digest": original.subject_digest(),
            "reasons": ["approval based on earlier observations"],
            "violations": [],
            "confidence": 1.0,
        }
    )
    result = Tier2Gate(reviewer).review(changed)
    assert result.decision is GateDecision.ESCALATE and result.fail_closed


def test_tier2_checks_secrets_in_the_omitted_middle_of_an_execution_log() -> None:
    log = "safe observation\n" * 200 + "sk-" + "a" * 30 + "\n" + "safe tail\n" * 200
    reviewer = _StaticReviewer("must not be called")
    result = Tier2Gate(reviewer).review(replace(_request(), execution_log=log))
    assert result.decision is GateDecision.ESCALATE and result.fail_closed
    assert result.failure_reason == "secret_in_payload"
    assert reviewer.prompts == []


@pytest.mark.parametrize("patch_chars", [24_000, 24_001])
def test_tier2_never_dispatches_or_approves_a_partially_visible_patch(patch_chars) -> None:
    reviewer = _StaticReviewer(
        lambda digest: json.dumps(
            {
                "decision": "APPROVE",
                "subject_digest": digest,
                "reasons": ["controlled boundary probe"],
                "violations": [],
                "confidence": 1.0,
            }
        )
    )
    result = Tier2Gate(reviewer).review(replace(_request(), patch="+" * patch_chars))
    if patch_chars == 24_000:
        assert result.decision is GateDecision.APPROVE and not result.fail_closed
        assert len(reviewer.prompts) == 1
    else:
        assert result.decision is GateDecision.ESCALATE and result.fail_closed
        assert result.failure_reason == "review_context_overflow"
        assert reviewer.prompts == []


@pytest.mark.parametrize(
    "payload",
    [
        "not json at all",
        json.dumps({"decision": "MAYBE", "subject_digest": "x"}),
        json.dumps({"decision": "APPROVE", "subject_digest": "@digest", "violations": ["nope"]}),
        json.dumps({"decision": "REVISE", "subject_digest": "@digest", "violations": []}),
        json.dumps({"decision": "APPROVE", "subject_digest": "@digest", "confidence": 5}),
        json.dumps({"decision": "APPROVE", "subject_digest": "@digest", "confidence": "high"}),
    ],
)
def test_tier2_fails_closed_on_malformed_output(payload) -> None:
    def render(digest: str) -> str:
        return payload.replace("@digest", digest)

    result = Tier2Gate(reviewer=_StaticReviewer(render)).review(_request())
    assert result.decision is GateDecision.ESCALATE
    assert result.fail_closed
    assert result.reasons


def test_tier2_fails_closed_when_the_reviewer_raises() -> None:
    class _Exploding:
        def complete(self, prompt: str, *, subject_digest: str) -> str:
            raise RuntimeError("gateway unavailable")

    result = Tier2Gate(reviewer=_Exploding()).review(_request())
    assert result.decision is GateDecision.ESCALATE
    assert result.fail_closed


def test_tier2_accepts_a_fenced_json_block() -> None:
    request = _request()
    body = json.dumps(
        {
            "decision": "REVISE",
            "subject_digest": request.subject_digest(),
            "reasons": ["needs work"],
            "violations": ["handle empty input"],
            "confidence": 0.5,
        }
    )
    result = Tier2Gate(reviewer=_StaticReviewer(f"```json\n{body}\n```")).review(request)
    assert result.decision is GateDecision.REVISE
    assert result.violations == ("handle empty input",)


def test_pipeline_never_calls_tier2_after_a_tier1_failure(sandbox) -> None:
    """The expensive tier must not run when the deterministic tier already failed."""
    from daedalus.application.gatekeeper.pipeline import Gatekeeper

    reviewer = _StaticReviewer(
        json.dumps(
            {
                "decision": "APPROVE",
                "subject_digest": "irrelevant",
                "reasons": [],
                "violations": [],
                "confidence": 1.0,
            }
        )
    )
    sandbox.write_file(TARGET, SYNTAX_ERROR_IMPLEMENTATION)
    gatekeeper = Gatekeeper(
        tier1=_gate(criteria=(_tests_criterion(),)),
        tier2=Tier2Gate(reviewer=reviewer),
    )
    outcome = gatekeeper.gate(
        artifact=_artifact(sandbox),
        sandbox=sandbox,
        goal_intent="fix it",
        node_intent="fix it",
        acceptance_criteria=("AC-1",),
        subject_digest="spec",
    )
    assert outcome.decision is GateDecision.REVISE
    assert outcome.skipped_tier2
    assert reviewer.prompts == [], "Tier-2 must not be invoked after a Tier-1 failure"


def test_critical_risk_always_escalates(sandbox) -> None:
    from daedalus.application.gatekeeper.pipeline import Gatekeeper
    from daedalus.application.gatekeeper.tier2 import Tier2Gate as T2

    request_digest = {}

    class _Approve:
        def complete(self, prompt: str, *, subject_digest: str) -> str:
            request_digest["subject"] = subject_digest
            return json.dumps(
                {
                    "decision": "APPROVE",
                    "subject_digest": subject_digest,
                    "reasons": ["fine"],
                    "violations": [],
                    "confidence": 1.0,
                }
            )

    sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
    gatekeeper = Gatekeeper(
        tier1=_gate(criteria=(_tests_criterion(),)),
        tier2=T2(reviewer=_Approve()),
        risk_level="critical",
    )
    outcome = gatekeeper.gate(
        artifact=_artifact(sandbox),
        sandbox=sandbox,
        goal_intent="fix it",
        node_intent="fix it",
        acceptance_criteria=("AC-1",),
        subject_digest="spec",
    )
    assert outcome.decision is GateDecision.ESCALATE
    assert not outcome.allows_commit
