"""An exact commit needs fresh executable evidence and a different signed principal."""

from __future__ import annotations

from dataclasses import replace
import json
from datetime import datetime, timedelta, UTC

import pytest

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.gatekeeper.tier2 import Tier2Gate
from daedalus.application.identity import OwnerRegistry
from daedalus.application.independent_validation import (
    IndependentValidationService,
    pending_validation,
)
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.resume import resume_run
from daedalus.domain.identity import Role, SignatureMismatch, OwnerRevoked, InsufficientAuthority
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, RiskLevel
from daedalus.domain.validation import ValidationError, compute_validation_signature
from daedalus.domain.canonical import digest_of
from daedalus.infrastructure.git_sandbox import _git
from daedalus.infrastructure.store import EventStore
from tests.conftest import TARGET, TEST_COMMAND, CORRECT_IMPLEMENTATION
from tests.test_goal_audit import GoalReviewer

OWNER_KEY = "test-only-owner-secret-for-validation"
REVIEWER_KEY = "test-only-reviewer-secret-for-validation"


def make_validation_run(
    repo, tmp_path, *, natural=False, store=None, identity=None, risk=RiskLevel.HIGH
):
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="validation-test",
            goal_id="V",
            objective="fix word counting",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=risk,
            owner_id="alice",
        )
    )
    if natural:
        bundle = replace(
            bundle,
            goal=replace(
                bundle.goal,
                acceptance_criteria=(
                    *bundle.goal.acceptance_criteria,
                    AcceptanceCriterion(
                        "NL",
                        AssertionKind.NATURAL_LANGUAGE,
                        statement="the implementation is clear",
                    ),
                ),
            ),
        )
    store = store or EventStore(tmp_path / "validation.db")
    identity = identity or OwnerRegistry(
        store, environ={"TEST_OWNER": OWNER_KEY, "TEST_REVIEWER": REVIEWER_KEY}
    )
    identity.enroll("alice", role=Role.OWNER, secret_env="TEST_OWNER")
    identity.enroll("bob", role=Role.REVIEWER, secret_env="TEST_REVIEWER")
    reviewer = GoalReviewer(["APPROVE"])
    reviewer.criteria = [c.criterion_id for c in bundle.goal.acceptance_criteria]
    owner = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "worktrees" / "run-validation",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp("write", TARGET, CORRECT_IMPLEMENTATION),), worker_id="coder"
        ),
        tier2=Tier2Gate(reviewer=reviewer),
        identity=identity,
        goal_audit_enabled=True,
        independent_validation_levels=("high", "critical"),
        retry_backoff_sec=0,
        run_id="run-validation",
    )
    owner.register_spec()
    owner.approve_spec(approved_by="alice", signature=identity.sign("alice", bundle.digest()))
    base = _git(repo, ["rev-parse", "main"], check=True).stdout.strip()
    result = owner.run()
    if risk is RiskLevel.CRITICAL:
        from daedalus.application.approvals import ApprovalService

        step = store.list_steps(owner.run_id)[0]
        assert step["state"] == "ESCALATED"
        artifact = store.artifacts_for_step(step["step_id"])[-1]["artifact_digest"]
        signature = identity.sign_step(
            "alice", owner.run_id, step["step_id"], "proceed", artifact, int(step["attempt"])
        )
        ApprovalService(store, owner.fsm, identity=identity).approve(
            run_id=owner.run_id,
            step_id=step["step_id"],
            decision="proceed",
            approved_by="alice",
            artifact_digest=artifact,
            signature=signature,
        )
        result = resume_run(
            store=store,
            run_id=owner.run_id,
            workspace=str(tmp_path),
            identity=identity,
            tier2=owner.tier2,
        )
    assert result.status == "AWAITING_APPROVAL", result.describe()
    assert _git(repo, ["rev-parse", "main"], check=True).stdout.strip() == base
    assert all(s["state"] == "COMMITTED" for s in store.list_steps(owner.run_id))
    return owner, IndependentValidationService(store, identity), reviewer


def attest(service, owner, report, *, by="bob", decision="APPROVE", assessments=None):
    claim = service.claim(
        owner.run_id,
        report["validation_id"],
        decision=decision,
        review_notes="Reviewed original goal, diff and fresh acceptance evidence.",
        assessments=assessments,
    )
    return service.attest(
        owner.run_id,
        report["validation_id"],
        validator_id=by,
        signature=owner.identity.sign_validation(by, claim.digest()),
        decision=decision,
        review_notes=claim.review_notes,
        assessments=assessments,
    )


@pytest.fixture
def parked(git_repo, tmp_path):
    owner, service, reviewer = make_validation_run(git_repo, tmp_path)
    yield owner, service, reviewer
    owner.store.close()


def test_fresh_review_then_resume_publishes_once_without_new_stage_or_worker(parked, tmp_path):
    owner, service, reviewer = parked
    before = len(owner.store.events_for_execution(owner.execution_id))
    with pytest.raises(ValidationError, match="incomplete"):
        resume_run(
            store=owner.store, run_id=owner.run_id, workspace=str(tmp_path), identity=owner.identity
        )
    assert owner.store.get_run(owner.run_id)["status"] == "AWAITING_APPROVAL"
    report = service.evaluate(owner.run_id)
    assert report["checks_passed"] and report["tree_unchanged"]
    assert report["execution_context"] == "fresh_worktree_same_controller"
    assert report["criteria"]["evidence"]["criteria_source"] == "goal"
    receipt = attest(service, owner, report)
    assert service.view(owner.run_id)["ready"]

    class MustNotRun:
        def implement(self, *args, **kwargs):
            raise AssertionError("independent delivery must not execute a new stage")

    result = resume_run(
        store=owner.store,
        run_id=owner.run_id,
        workspace=str(tmp_path),
        worker=MustNotRun(),
        identity=owner.identity,
    )
    assert result.status == "COMPLETED" and result.promoted_commit == report["commit"]
    assert service.view(owner.run_id)["status"] == "DELIVERED"
    assert reviewer.goals == 1
    events = owner.store.events_for_execution(owner.execution_id)
    assert sum(e.event_type == "StepCommitted" for e in events) == 1
    assert sum(e.event_type == "RunCompleted" for e in events) == 1
    assert not owner.store.verify_sequences()
    assert len(events) > before and receipt["verified"]


@pytest.mark.parametrize("alias", [False, True])
def test_same_author_identity_or_key_cannot_validate(parked, alias):
    owner, service, _ = parked
    report = service.evaluate(owner.run_id)
    by = "alice"
    if alias:
        owner.identity.enroll("alias", role=Role.REVIEWER, secret_env="TEST_OWNER")
        by = "alias"
    with pytest.raises(ValidationError, match="differ"):
        attest(service, owner, report, by=by)
    assert not service.view(owner.run_id)["ready"]


def test_cross_purpose_signature_and_changed_notes_are_rejected(parked):
    owner, service, _ = parked
    report = service.evaluate(owner.run_id)
    claim = service.claim(
        owner.run_id, report["validation_id"], decision="APPROVE", review_notes="checked"
    )
    # A spec signature over the SAME digest is not a validation signature.
    sig = owner.identity.sign("bob", claim.digest())
    with pytest.raises(SignatureMismatch):
        service.attest(
            owner.run_id,
            report["validation_id"],
            validator_id="bob",
            signature=sig,
            review_notes="checked",
        )
    sig = owner.identity.sign_validation("bob", claim.digest())
    with pytest.raises(SignatureMismatch):
        service.attest(
            owner.run_id,
            report["validation_id"],
            validator_id="bob",
            signature=sig,
            review_notes="different",
        )


@pytest.mark.parametrize("role", [Role.VIEWER, Role.OPERATOR])
def test_insufficient_role_cannot_attest(parked, role):
    owner, service, _ = parked
    report = service.evaluate(owner.run_id)
    owner.identity.enroll("observer", role=role, secret_env="TEST_REVIEWER")
    with pytest.raises(InsufficientAuthority):
        attest(service, owner, report, by="observer")


def test_new_evaluation_invalidates_old_attestation_and_revocation_blocks_new_signing(parked):
    owner, service, _ = parked
    first = service.evaluate(owner.run_id)
    attest(service, owner, first)
    second = service.evaluate(owner.run_id)
    assert not service.view(owner.run_id)["ready"]
    with pytest.raises(ValidationError, match="superseded"):
        attest(service, owner, first)
    owner.identity.revoke("bob")
    with pytest.raises(OwnerRevoked):
        attest(service, owner, second)


def test_revocation_does_not_rewrite_already_verified_attestation(parked):
    owner, service, _ = parked
    report = service.evaluate(owner.run_id)
    attest(service, owner, report)
    owner.identity.revoke("bob")
    assert service.authorise_delivery(owner.run_id, report["commit"])["verified"]


def test_natural_language_requires_complete_independent_evidence(git_repo, tmp_path):
    owner, service, reviewer = make_validation_run(git_repo, tmp_path, natural=True)
    try:
        report = service.evaluate(owner.run_id)
        assert report["natural_language_criteria"] == ["NL"]
        for rows in (
            [],
            [{"criterion_id": "NL", "status": "UNKNOWN", "evidence": "uncertain"}],
            [{"criterion_id": "NL", "status": "UNMET", "evidence": "not met"}],
        ):
            with pytest.raises(ValidationError):
                attest(service, owner, report, assessments=rows)
        attest(
            service,
            owner,
            report,
            assessments=[
                {
                    "criterion_id": "NL",
                    "status": "MET",
                    "evidence": "inspected word splitting and edge cases",
                }
            ],
        )
        assert service.view(owner.run_id)["ready"]
    finally:
        owner.store.close()


def test_rejection_keeps_delivery_parked(parked):
    owner, service, _ = parked
    report = service.evaluate(owner.run_id)
    attest(service, owner, report, decision="REJECT")
    assert not service.view(owner.run_id)["ready"]
    with pytest.raises(ValidationError, match="did not approve"):
        service.authorise_delivery(owner.run_id, report["commit"])


def append_report(owner, report):
    owner.store.append(
        aggregate_id="validation:" + owner.run_id,
        execution_id=owner.execution_id,
        event_type="IndependentValidationEvaluated",
        actor="test-evidence-corruption",
        payload=report,
    )


@pytest.mark.parametrize("mode", ["expired", "tampered", "failed"])
def test_expired_tampered_or_failed_evidence_cannot_be_signed(parked, mode):
    owner, service, _ = parked
    report = service.evaluate(owner.run_id)
    if mode == "expired":
        report["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    elif mode == "tampered":
        report["commit"] = "0" * 40
    else:
        report["checks_passed"] = False
    if mode != "tampered":
        report["report_digest"] = digest_of(
            {k: v for k, v in report.items() if k != "report_digest"}
        )
    append_report(owner, report)
    with pytest.raises(ValidationError):
        attest(service, owner, report)
    assert not service.view(owner.run_id)["ready"]


def test_fresh_worktree_really_executes_acceptance_and_detects_mutation(parked, monkeypatch):
    owner, service, _ = parked
    from daedalus.application.gatekeeper.tier1 import Tier1Gate, CheckResult

    paths = []

    def mutate(self, box, *, acceptance_overrides):
        paths.append(box.worktree_path)
        (box.worktree_path / TARGET).write_text(
            CORRECT_IMPLEMENTATION + "\n# mutation during independent checks\n"
        )
        return CheckResult(name="acceptance", passed=True)

    monkeypatch.setattr(Tier1Gate, "_check_acceptance", mutate)
    report = service.evaluate(owner.run_id)
    assert not report["checks_passed"] and not report["tree_unchanged"]
    assert paths and not paths[0].exists()
    assert paths[0].is_relative_to(owner.run_root)
    with pytest.raises(ValidationError, match="cannot be overridden"):
        attest(service, owner, report)


def test_new_spec_signoff_after_evaluation_requires_fresh_evidence(parked):
    owner, service, _ = parked
    report = service.evaluate(owner.run_id)
    owner.approve_spec(approved_by="bob", signature=owner.identity.sign("bob", owner.spec_digest))
    with pytest.raises(ValidationError, match="approvals changed"):
        attest(service, owner, report)


def test_delivery_recovery_uses_validation_evidence_at_publication_time(
    parked, monkeypatch, tmp_path
):
    owner, service, _ = parked
    from daedalus.application.commit_recovery import reconcile_commits

    report = service.evaluate(owner.run_id)
    attest(service, owner, report)
    from daedalus.application.worktree_pool import WorktreePool

    promote = WorktreePool.promote_to_target

    def kill_after_publish(self, **kwargs):
        promote(self, **kwargs)
        raise SystemExit("simulated receipt interruption")

    monkeypatch.setattr(WorktreePool, "promote_to_target", kill_after_publish)
    with pytest.raises(SystemExit):
        resume_run(
            store=owner.store, run_id=owner.run_id, workspace=str(tmp_path), identity=owner.identity
        )
    assert owner.store.get_run(owner.run_id)["status"] == "RUNNING"
    checks = reconcile_commits(owner.store, apply=False)
    assert any(c.repairable and c.kind == "incomplete_delivery" for c in checks)
    # Deliberately append an invalid newer report: recovery must not retroactively use it.
    report["checks_passed"] = False
    report["report_digest"] = digest_of({k: v for k, v in report.items() if k != "report_digest"})
    append_report(owner, report)
    checks = reconcile_commits(owner.store, apply=True)
    assert any(c.action and c.kind == "incomplete_delivery" for c in checks)
    assert owner.store.get_run(owner.run_id)["status"] == "COMPLETED"


def test_commit_change_invalidates_pending_review(parked, monkeypatch):
    owner, service, _ = parked
    report = service.evaluate(owner.run_id)
    attest(service, owner, report)
    monkeypatch.setattr("daedalus.application.independent_validation._head", lambda *args: "0" * 40)
    with pytest.raises(ValidationError, match="pending commit changed"):
        service.authorise_delivery(owner.run_id, report["commit"])


def test_http_cli_signing_and_service_resubmission(git_repo, tmp_path, monkeypatch, capsys):
    from fastapi.testclient import TestClient
    from daedalus.cli import main
    from daedalus.config import load_settings
    from daedalus.service.app import create_app
    from daedalus.application.orchestrator import RunResult
    import time

    settings = load_settings(None, workspace_root=str(tmp_path / "ws"))
    app = create_app(settings)
    with TestClient(app) as client:
        state = app.state.daedalus
        state.identity.environ = {"TEST_OWNER": OWNER_KEY, "TEST_REVIEWER": REVIEWER_KEY}
        owner, service, _ = make_validation_run(
            git_repo, settings.workspace.root_path, store=state.store, identity=state.identity
        )
        rid = owner.run_id
        # Keep the first completed dispatch in the job registry: a legitimate second
        # submission after a parked run must be accepted, while in-flight duplicates aren't.
        state.dispatcher.submit(
            rid,
            str(git_repo),
            lambda: RunResult(rid, owner.execution_id, owner.spec_digest, "AWAITING_APPROVAL"),
        )
        state.dispatcher._jobs[rid].future.result(timeout=10)
        refused = client.post(f"/api/runs/{rid}/resume")
        assert (
            refused.status_code == 409 and state.store.get_run(rid)["status"] == "AWAITING_APPROVAL"
        )
        response = client.post(f"/api/runs/{rid}/validations/evaluate")
        assert response.status_code == 200, response.text
        report = response.json()
        review = {
            "decision": "APPROVE",
            "review_notes": "Independently checked diff and fresh tests.",
            "natural_language_assessments": [],
        }
        review_file = tmp_path / "review.json"
        review_file.write_text(json.dumps(review))
        monkeypatch.setenv("TEST_REVIEWER", REVIEWER_KEY)
        capsys.readouterr()
        assert (
            main(
                [
                    "validation",
                    "sign",
                    "--workspace",
                    str(settings.workspace.root_path),
                    "--run-id",
                    rid,
                    "--validation-id",
                    report["validation_id"],
                    "--validator-id",
                    "bob",
                    "--review-file",
                    str(review_file),
                ]
            )
            == 0
        )
        signature = capsys.readouterr().out.strip()
        assert len(signature) == 64 and REVIEWER_KEY not in signature
        invalid = client.post(
            f"/api/runs/{rid}/validations/{report['validation_id']}/attest",
            json={**review, "validator_id": "bob", "signature": signature, "unexpected": "field"},
        )
        assert invalid.status_code == 422
        signed = client.post(
            f"/api/runs/{rid}/validations/{report['validation_id']}/attest",
            json={**review, "validator_id": "bob", "signature": signature},
        )
        assert signed.status_code == 200, signed.text
        assert client.get(f"/api/runs/{rid}/audit").json()["independent_validation"]["ready"]
        result = client.post(f"/api/runs/{rid}/resume")
        assert result.status_code == 202, result.text
        state.dispatcher._jobs[rid].future.result(timeout=15)
        assert state.store.get_run(rid)["status"] == "COMPLETED"
        assert client.get(f"/api/runs/{rid}/validations").json()["status"] == "DELIVERED"
        trail = client.get(f"/api/runs/{rid}/export").text
        assert "IndependentValidationAttested" in trail
        assert OWNER_KEY not in trail and REVIEWER_KEY not in trail
        # Capture actual API/template payloads for the JS renderer, not an invented shape.
        payload = {"view": client.get(f"/api/runs/{rid}/validations").json(), "run_id": rid}
        (tmp_path / "render-validation.json").write_text(json.dumps(payload))


def test_production_requires_policy_and_two_separate_signer_keys(tmp_path):
    from daedalus.config import load_settings
    from daedalus.application.release_gate import _check_independent_validation, CheckStatus

    settings = load_settings(None, workspace_root=str(tmp_path / "ws"))
    with EventStore(tmp_path / "readiness.db") as store:
        registry = OwnerRegistry(store, environ={"A": OWNER_KEY, "B": REVIEWER_KEY})
        registry.enroll("a", role=Role.OWNER, secret_env="A")
        registry.enroll("alias", role=Role.REVIEWER, secret_env="A")
        assert _check_independent_validation(settings, store)[1].status is CheckStatus.FAIL
        registry.enroll("b", role=Role.REVIEWER, secret_env="B")
        assert all(
            c.status is CheckStatus.PASS for c in _check_independent_validation(settings, store)
        )
        weakened = replace(
            settings, policy=replace(settings.policy, independent_validation_levels=())
        )
        assert _check_independent_validation(weakened, store)[0].status is CheckStatus.FAIL
        registry.revoke("b")
        assert _check_independent_validation(settings, store)[1].status is CheckStatus.FAIL


def test_validation_config_roundtrip_and_invalid_risks(tmp_path):
    from daedalus.config import load_settings, write_example_config, ConfigError

    path = write_example_config(tmp_path / "daedalus.toml")
    settings = load_settings(path)
    assert settings.policy.independent_validation_levels == ("high", "critical")
    path.write_text(
        path.read_text().replace(
            'independent_validation_levels = ["high", "critical"]',
            'independent_validation_levels = ["made-up"]',
        )
    )
    with pytest.raises(ConfigError):
        load_settings(path)


def test_critical_step_owner_approval_still_requires_a_different_validator(git_repo, tmp_path):
    owner, service, _ = make_validation_run(git_repo, tmp_path, risk=RiskLevel.CRITICAL)
    try:
        assert pending_validation(owner.store, owner.run_id)
        assert owner.store.approvals_for_run(owner.run_id)[0]["verified"]
        report = service.evaluate(owner.run_id)
        with pytest.raises(ValidationError, match="differ"):
            attest(service, owner, report, by="alice")
        attest(service, owner, report)
        result = resume_run(
            store=owner.store, run_id=owner.run_id, workspace=str(tmp_path), identity=owner.identity
        )
        assert result.status == "COMPLETED" and result.promoted_commit == report["commit"]
    finally:
        owner.store.close()


def test_missing_validation_id_cannot_bypass_recovery_by_omitting_requirement_flag(
    parked, monkeypatch, tmp_path
):
    owner, service, _ = parked
    from daedalus.application.worktree_pool import WorktreePool
    from daedalus.application.commit_recovery import reconcile_commits

    report = service.evaluate(owner.run_id)
    attest(service, owner, report)
    promote = WorktreePool.promote_to_target

    def interrupt(self, **kwargs):
        promote(self, **kwargs)
        raise SystemExit("simulated delivery receipt interruption")

    monkeypatch.setattr(WorktreePool, "promote_to_target", interrupt)
    with pytest.raises(SystemExit):
        resume_run(
            store=owner.store, run_id=owner.run_id, workspace=str(tmp_path), identity=owner.identity
        )
    intent = dict(owner.store.events_for("delivery:" + owner.run_id)[-1].payload)
    intent.pop("independent_validation_required")
    intent.pop("independent_validation_id")
    # Explicitly corrupt the intent through an appended test fixture; never production recovery.
    owner.store.append(
        aggregate_id="delivery:" + owner.run_id,
        execution_id=owner.execution_id,
        event_type="DeliveryRequested",
        actor="test-evidence-corruption",
        payload=intent,
    )
    findings = reconcile_commits(owner.store, apply=True)
    assert any(f.kind == "incomplete_delivery" and not f.repairable for f in findings)
    assert owner.store.get_run(owner.run_id)["status"] == "RUNNING"
    assert not any(
        e.event_type == "RunCompleted" for e in owner.store.events_for_execution(owner.execution_id)
    )


def test_review_notes_cannot_persist_an_enrolled_signing_secret(parked):
    owner, service, _ = parked
    report = service.evaluate(owner.run_id)
    with pytest.raises(ValidationError, match="credentials"):
        service.claim(
            owner.run_id,
            report["validation_id"],
            decision="APPROVE",
            review_notes="checked " + REVIEWER_KEY,
        )
    assert not any(
        e.event_type == "IndependentValidationAttested"
        for e in owner.store.events_for_execution(owner.execution_id)
    )


@pytest.mark.parametrize("signature", ["☃", "not-a-signature", "a" * 63])
def test_malformed_signatures_fail_as_domain_refusals(signature):
    from daedalus.domain.validation import verify_validation_signature

    with pytest.raises(SignatureMismatch):
        verify_validation_signature(REVIEWER_KEY, "digest", signature)


@pytest.mark.parametrize("decision, rows", [([], []), ("APPROVE", {}), ("APPROVE", 0)])
def test_malformed_review_json_has_no_falsey_shortcut(decision, rows):
    from daedalus.domain.validation import ValidationClaim

    with pytest.raises(ValidationError):
        ValidationClaim.build(
            {"report_digest": "digest", "natural_language_criteria": []},
            decision=decision,
            review_notes="checked",
            assessments=rows,
        )
