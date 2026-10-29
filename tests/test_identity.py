"""Owner identity, approval authority and spec sign-off (Spec §3.2).

Before this existed, `approved_by="alice"` was a string that anyone could supply — including
the model plane's own worker. These tests hold the four things §3.2 asks for: signature,
owner identity, permission and approval state.

The tests that matter most here are the adversarial ones. A signature scheme that accepts
everything passes a happy-path test, so the suite checks that a signature for a *different*
spec, a signature from the *wrong* key, and a signature over the *bare digest* (bypassing the
domain separation) are all refused — and that the signing secret reaches neither the database
nor the event log.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from daedalus.application.identity import IdentityRequired, OwnerRegistry
from daedalus.application.spec_approval import SpecApprovalService
from daedalus.domain.identity import (
    ROLE_CEILING,
    InsufficientAuthority,
    OwnerNotRegistered,
    OwnerRevoked,
    Role,
    SignatureMismatch,
    SignatureRequired,
    SigningKeyUnavailable,
    approval_subject,
    compute_signature,
    fingerprint,
    minimum_role_for,
    role_may_approve,
    verify_signature,
)
from daedalus.domain.spec import NetworkPolicy, RiskLevel
from daedalus.infrastructure.store import EventStore
from tests.conftest import TARGET, TEST_COMMAND

SECRET = "alice-signing-secret"


# ---------------------------------------------------------------------------
# The pure contract
# ---------------------------------------------------------------------------


def test_the_role_ceiling_matrix_is_exact() -> None:
    """Authority is per role *and* per risk: the interesting question is never just "may they?"""
    expected = {
        Role.VIEWER: [],
        Role.OPERATOR: [RiskLevel.LOW, RiskLevel.NORMAL],
        Role.REVIEWER: [RiskLevel.LOW, RiskLevel.NORMAL, RiskLevel.HIGH],
        Role.OWNER: [RiskLevel.LOW, RiskLevel.NORMAL, RiskLevel.HIGH, RiskLevel.CRITICAL],
    }
    for role, allowed in expected.items():
        actual = [risk for risk in RiskLevel if role_may_approve(role, risk)]
        assert actual == allowed, role

    assert ROLE_CEILING[Role.VIEWER] is None
    assert minimum_role_for(RiskLevel.LOW) is Role.OPERATOR
    assert minimum_role_for(RiskLevel.CRITICAL) is Role.OWNER


def test_a_signature_verifies_and_a_changed_spec_does_not() -> None:
    signature = compute_signature(SECRET, "digest-a")
    verify_signature(SECRET, "digest-a", signature)
    with pytest.raises(SignatureMismatch):
        verify_signature(SECRET, "digest-b", signature)


def test_the_subject_is_domain_separated() -> None:
    """A bare-digest HMAC must not be accepted: hashes recur, and a signature must not.

    Without the prefix, a spec-approval signature would be a signature over a hash — and this
    system signs and hashes many things. Prefixing the signed bytes means a signature produced
    for one purpose cannot be replayed as another.
    """
    bare = hmac.new(SECRET.encode(), b"digest-a", hashlib.sha256).hexdigest()
    assert bare != compute_signature(SECRET, "digest-a")
    with pytest.raises(SignatureMismatch):
        verify_signature(SECRET, "digest-a", bare)
    assert approval_subject("digest-a") == b"daedalus.spec-approval.v1:digest-a"


def test_an_absent_or_unverifiable_signature_is_never_a_pass() -> None:
    with pytest.raises(SignatureRequired):
        verify_signature(SECRET, "digest-a", "")
    # "Cannot check" and "checked and fine" are different answers, and only one may commit.
    with pytest.raises(SigningKeyUnavailable):
        verify_signature("", "digest-a", compute_signature(SECRET, "digest-a"))
    with pytest.raises(SignatureRequired):
        approval_subject("")


def test_the_fingerprint_identifies_a_key_without_revealing_it() -> None:
    assert fingerprint(SECRET) == fingerprint(SECRET)
    assert fingerprint(SECRET) != fingerprint(SECRET + "x")
    assert SECRET not in fingerprint(SECRET)
    assert fingerprint("") == ""


# ---------------------------------------------------------------------------
# Registry policy
# ---------------------------------------------------------------------------


def _register(store: EventStore, *, digest: str, risk: str) -> None:
    """Put a spec in the registry so there is something to approve."""
    store.register_spec(
        spec_digest=digest,
        goal_id="GOAL-ID",
        spec_version=1,
        document={"goal": "test"},
        risk_level=risk,
        owner_id="owner",
    )


def _registry(tmp_path: Path, *, required: bool = False, environ: dict[str, str] | None = None):
    store = EventStore(tmp_path / "identity.db")
    env = {"DAEDALUS_ALICE_SECRET": SECRET, "DAEDALUS_BOB_SECRET": "bob-secret"}
    env.update(environ or {})
    return store, OwnerRegistry(store=store, required=required, environ=env)


def test_enforcement_is_a_property_of_enrolment(tmp_path) -> None:
    """An empty registry records names; a non-empty one refuses to accept them."""
    store, registry = _registry(tmp_path)
    assert registry.enforced is False
    assert "NOT enforced" in str(registry.describe()["note"])

    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    assert registry.enforced is True
    assert "signed by a registered owner" in str(registry.describe()["note"])
    store.close()


def test_a_config_requirement_enforces_with_no_owners_at_all(tmp_path) -> None:
    """`required = true` must refuse rather than quietly fall back to recording a name."""
    store, registry = _registry(tmp_path, required=True)
    assert registry.enforced is True
    with pytest.raises(OwnerNotRegistered):
        registry.authorise(approved_by="alice", risk=RiskLevel.HIGH, spec_digest="d")
    store.close()


def test_enrolling_with_a_literal_secret_and_no_variable_is_refused(tmp_path) -> None:
    """Enrolment must name where the verifier will look, not just prove the key once."""
    store, registry = _registry(tmp_path)
    with pytest.raises(SigningKeyUnavailable, match="environment variable"):
        registry.enroll("alice", role=Role.OWNER, secret=SECRET)
    store.close()


def test_an_unverified_approval_is_recorded_as_unverified(tmp_path) -> None:
    store, registry = _registry(tmp_path)
    service = SpecApprovalService(store=store, identity=registry)
    _register(store, digest="d1", risk="critical")
    outcome = service.record(spec_digest="d1", approved_by="alice")
    assert outcome.verified is False
    assert store.is_spec_approved("d1") is True
    # The distinction IS the control: a recorded name is not a verified signature.
    assert store.is_spec_approved("d1", verified_only=True) is False
    assert "unverified" in str(service.approval_view("d1")["statement"])
    store.close()


def test_a_verified_approval_reports_exactly_what_was_checked(tmp_path) -> None:
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    service = SpecApprovalService(store=store, identity=registry)
    _register(store, digest="d1", risk="critical")
    outcome = service.record(
        spec_digest="d1",
        approved_by="alice",
        signature=registry.sign("alice", "d1"),
    )
    assert outcome.verified is True
    assert outcome.scheme == "hmac-sha256"
    assert outcome.role == "owner"
    assert outcome.fingerprint == fingerprint(SECRET)
    assert store.is_spec_approved("d1", verified_only=True) is True
    view = service.approval_view("d1")
    assert view["verified"] is True
    assert "verified hmac-sha256 signature by alice" in str(view["statement"])
    store.close()


# ---------------------------------------------------------------------------
# Adversarial: every way an approval can be wrong
# ---------------------------------------------------------------------------


def test_an_unregistered_owner_is_refused(tmp_path) -> None:
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    # The classic: type a name that was never enrolled.
    with pytest.raises(OwnerNotRegistered, match="mallory"):
        registry.authorise(
            approved_by="mallory",
            risk=RiskLevel.HIGH,
            spec_digest="d1",
            signature=compute_signature(SECRET, "d1"),
        )
    store.close()


def test_revoking_the_last_owner_does_not_switch_enforcement_off(tmp_path) -> None:
    """Or revocation becomes a way to disable the control rather than narrow it.

    Counting only *live* owners made `revoke` return the workspace to the unenrolled state,
    where any name is accepted — so revoking the last owner widened authority instead of
    removing it. Enforcement is keyed on owners ever having been registered.
    """
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    assert registry.enforced is True
    registry.revoke("alice")
    assert registry.enforced is True, "revocation must not disable verification"
    assert registry.enrolled == 0
    assert registry.ever_enrolled == 1
    # A name typed into the gap is still refused.
    with pytest.raises(OwnerNotRegistered):
        registry.authorise(approved_by="anyone", risk=RiskLevel.HIGH, spec_digest="d")
    store.close()


def test_a_revoked_owner_is_refused(tmp_path) -> None:
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    assert registry.revoke("alice") is True
    with pytest.raises(OwnerRevoked):
        registry.authorise(
            approved_by="alice",
            risk=RiskLevel.HIGH,
            spec_digest="d1",
            signature=compute_signature(SECRET, "d1"),
        )
    with pytest.raises(OwnerRevoked):
        registry.sign("alice", "d1")
    store.close()


def test_a_role_below_the_risk_ceiling_is_refused(tmp_path) -> None:
    store, registry = _registry(tmp_path, environ={"DAEDALUS_BOB_SECRET": "bob-secret"})
    registry.enroll("bob", role=Role.REVIEWER, secret_env="DAEDALUS_BOB_SECRET")
    # A reviewer may sign a high-risk spec...
    registry.authorise(
        approved_by="bob",
        risk=RiskLevel.HIGH,
        spec_digest="d1",
        signature=compute_signature("bob-secret", "d1"),
    )
    # ...and may not sign a critical one, no matter how good the signature is.
    with pytest.raises(InsufficientAuthority, match="needs at least 'owner'"):
        registry.authorise(
            approved_by="bob",
            risk=RiskLevel.CRITICAL,
            spec_digest="d1",
            signature=compute_signature("bob-secret", "d1"),
        )
    store.close()


def test_an_enrolled_owner_must_sign(tmp_path) -> None:
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    with pytest.raises(SignatureRequired):
        registry.authorise(approved_by="alice", risk=RiskLevel.HIGH, spec_digest="d1")
    store.close()


def test_a_signature_for_a_different_spec_cannot_be_replayed(tmp_path) -> None:
    """The signed statement is the digest, so an approval cannot move to another contract."""
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    signed = registry.sign("alice", "spec-one")
    with pytest.raises(SignatureMismatch):
        registry.authorise(
            approved_by="alice",
            risk=RiskLevel.HIGH,
            spec_digest="spec-two",
            signature=signed,
        )
    store.close()


def test_a_signature_from_another_key_is_refused(tmp_path) -> None:
    store, registry = _registry(tmp_path, environ={"DAEDALUS_MALLORY_SECRET": "mallory-secret"})
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    registry.enroll("mallory", role=Role.OWNER, secret_env="DAEDALUS_MALLORY_SECRET")
    stolen = compute_signature("mallory-secret", "d1")
    with pytest.raises(SignatureMismatch):
        registry.authorise(
            approved_by="alice", risk=RiskLevel.HIGH, spec_digest="d1", signature=stolen
        )
    store.close()


def test_a_missing_or_rotated_signing_key_is_refused(tmp_path) -> None:
    """An unreadable key is "cannot verify", which must never collapse into "verified"."""
    store, registry = _registry(tmp_path, environ={"DAEDALUS_ALICE_SECRET": SECRET})
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    good = registry.sign("alice", "d1")

    # The variable goes away.
    registry.environ = {}
    with pytest.raises(SigningKeyUnavailable, match="must hold their signing secret"):
        registry.authorise(
            approved_by="alice", risk=RiskLevel.HIGH, spec_digest="d1", signature=good
        )

    # The variable now holds a different key: the fingerprint catches the rotation.
    registry.environ = {"DAEDALUS_ALICE_SECRET": "rotated-secret"}
    with pytest.raises(SigningKeyUnavailable, match="does not match the key enrolled"):
        registry.authorise(
            approved_by="alice", risk=RiskLevel.HIGH, spec_digest="d1", signature=good
        )
    store.close()


def test_an_owner_with_no_enrolled_key_cannot_be_verified(tmp_path) -> None:
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="")
    with pytest.raises(SigningKeyUnavailable, match="no signing key enrolled"):
        registry.authorise(
            approved_by="alice", risk=RiskLevel.HIGH, spec_digest="d1", signature="deadbeef"
        )
    store.close()


def test_a_signature_supplied_while_unenrolled_is_kept_but_marked_unchecked(tmp_path) -> None:
    """Recorded, never *claimed*: refusing to store it would rule out signing elsewhere.

    An organisation that signs with its own PKI still wants the signature kept. What must not
    happen is that the record is mistaken for a verified one, so the scheme says `unverified`
    rather than naming a primitive that was never applied — and run admission still refuses
    it the moment enforcement is on.
    """
    store, registry = _registry(tmp_path)
    outcome = registry.authorise(
        approved_by="alice", risk=RiskLevel.HIGH, spec_digest="d1", signature="deadbeef"
    )
    assert outcome.verified is False
    assert outcome.scheme == "unverified"
    assert outcome.signature == "deadbeef"
    assert outcome.fingerprint == ""

    service = SpecApprovalService(store=store, identity=registry)
    _register(store, digest="d1", risk="high")
    # Recorded through the service, which decides for itself: the outcome above is what the
    # registry returned, and the service is not allowed to be told what to write.
    recorded = service.record(spec_digest="d1", approved_by="alice", signature="deadbeef")
    assert recorded.verified is False
    assert recorded.scheme == "unverified"
    assert store.is_spec_approved("d1") is True
    assert store.is_spec_approved("d1", verified_only=True) is False
    assert "UNVERIFIED approval for alice" in str(service.approval_view("d1")["statement"])
    store.close()


# ---------------------------------------------------------------------------
# The secret must not leak
# ---------------------------------------------------------------------------


def test_the_signing_secret_never_reaches_the_database_or_the_log(tmp_path) -> None:
    """Spec §8: a credential in the store is a credential in every backup and export."""
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    service = SpecApprovalService(store=store, identity=registry)
    _register(store, digest="d1", risk="critical")
    service.record(
        spec_digest="d1", approved_by="alice", signature=registry.sign("alice", "d1")
    )
    store.close()

    raw = (tmp_path / "identity.db").read_bytes()
    assert SECRET.encode() not in raw, "the signing secret must never be written to disk"

    # And the event records the fingerprint, so the key is identifiable without being present.
    reopened = EventStore(tmp_path / "identity.db")
    events = [e for e in reopened.all_events() if e.event_type == "SpecApproved"]
    assert len(events) == 1
    payload = dict(events[0].payload)
    assert payload["verified"] is True
    assert payload["approval_scheme"] == "hmac-sha256"
    assert payload["key_fingerprint"] == fingerprint(SECRET)
    assert SECRET not in str(payload)
    assert SECRET not in json.dumps(payload)
    reopened.close()


def test_the_registry_never_returns_the_secret_in_its_api(tmp_path) -> None:
    """`secret_env` is the *name* of a variable; the value it holds must not appear."""
    store, registry = _registry(tmp_path)
    owner = registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    payload = owner.to_payload()
    rendered = json.dumps(payload)
    assert SECRET not in rendered, rendered
    assert payload["secret_env"] == "DAEDALUS_ALICE_SECRET"
    assert payload["key_fingerprint"] == fingerprint(SECRET)
    assert SECRET not in json.dumps(registry.describe())
    store.close()


# ---------------------------------------------------------------------------
# Run admission (§3.2 x §10 x §11)
# ---------------------------------------------------------------------------


def _orchestrator(tmp_path: Path, store: EventStore, registry: OwnerRegistry, *, risk: RiskLevel):
    """A run whose spec is registered under the real digest the orchestrator computes."""
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from daedalus.infrastructure.git_sandbox import init_repo

    repo = init_repo(tmp_path / "repo")
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="REQ-ID",
            goal_id="GOAL-ID",
            objective="x",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=risk,
            network_policy=NetworkPolicy.DENY,
        )
    )
    orchestrator = RunOrchestrator(
        store=store, repo_path=repo, run_root=tmp_path / "wt", bundle=bundle, identity=registry
    )
    orchestrator.register_spec()
    return orchestrator


def test_a_high_risk_spec_with_only_a_recorded_name_cannot_run(tmp_path) -> None:
    """The composition that matters: registered owners + an unsigned approval = refusal."""
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    orchestrator = _orchestrator(tmp_path, store, registry, risk=RiskLevel.CRITICAL)
    store.approve_spec(orchestrator.spec_digest, approved_by="alice")  # a name, no signature

    with pytest.raises(IdentityRequired, match="was not a verified signature"):
        orchestrator.assert_spec_may_run()
    store.close()


def test_a_verified_signature_admits_the_run(tmp_path) -> None:
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    orchestrator = _orchestrator(tmp_path, store, registry, risk=RiskLevel.CRITICAL)
    digest = orchestrator.spec_digest
    SpecApprovalService(store=store, identity=registry).record(
        spec_digest=digest, approved_by="alice", signature=registry.sign("alice", digest)
    )
    orchestrator.assert_spec_may_run()  # must not raise
    store.close()


def test_without_enrolment_a_high_risk_name_still_admits_the_run(tmp_path) -> None:
    """Single-user offline use is a legitimate deployment, and must keep working."""
    store, registry = _registry(tmp_path)
    orchestrator = _orchestrator(tmp_path, store, registry, risk=RiskLevel.CRITICAL)
    store.approve_spec(orchestrator.spec_digest, approved_by="alice")
    orchestrator.assert_spec_may_run()
    store.close()


def test_a_missing_signature_on_a_high_risk_spec_is_refused_before_work_starts(tmp_path) -> None:
    """No approval at all is still the original §10 refusal, not the §3.2 one."""
    from daedalus.errors import SpecApprovalRequired

    store, registry = _registry(tmp_path)
    orchestrator = _orchestrator(tmp_path, store, registry, risk=RiskLevel.CRITICAL)
    with pytest.raises(SpecApprovalRequired, match="no owner approval"):
        orchestrator.assert_spec_may_run()
    store.close()


def test_a_normal_risk_spec_needs_no_approval_even_when_owners_are_enrolled(tmp_path) -> None:
    """Enrolling owners must not stall every ordinary run in the workspace.

    §3.2 is about high-risk change. Requiring a signature for a low-risk edit too would make
    the control so expensive that operators would disable it.
    """
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    orchestrator = _orchestrator(tmp_path, store, registry, risk=RiskLevel.NORMAL)
    orchestrator.assert_spec_may_run()
    store.close()


def test_revocation_is_not_retroactive_for_an_already_verified_approval(tmp_path) -> None:
    """Verification is an event, not a recurring condition, and that is deliberate.

    Re-deriving authority at commit time would make revocation retroactive: a legitimate
    sign-off would silently stop counting. Revocation prevents *new* approvals; the record of
    the old one stands, with the revocation visible beside it in the registry.
    """
    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    orchestrator = _orchestrator(tmp_path, store, registry, risk=RiskLevel.CRITICAL)
    digest = orchestrator.spec_digest
    SpecApprovalService(store=store, identity=registry).record(
        spec_digest=digest, approved_by="alice", signature=registry.sign("alice", digest)
    )
    registry.revoke("alice")

    orchestrator.assert_spec_may_run()
    # But a *new* sign-off is refused from that moment on.
    with pytest.raises(OwnerRevoked):
        SpecApprovalService(store=store, identity=registry).record(
            spec_digest=digest, approved_by="alice", signature="x"
        )
    store.close()


# ---------------------------------------------------------------------------
# Over HTTP: the surface an operator actually touches
# ---------------------------------------------------------------------------

import shutil as _shutil  # noqa: E402

from daedalus.application.planner import DeterministicPlanner as _Planner  # noqa: E402
from daedalus.application.planner import PlanRequest as _PlanRequest  # noqa: E402
from daedalus.infrastructure.git_sandbox import init_repo as _init_repo  # noqa: E402
from daedalus.infrastructure.git_sandbox import initial_commit as _initial_commit  # noqa: E402
from tests.conftest import DEMO_PROJECT as _DEMO_PROJECT  # noqa: E402


def _http_workspace(tmp_path: Path, *, enrolled: bool):
    """A service with a real repository, and optionally one enrolled owner."""
    from fastapi.testclient import TestClient

    from daedalus.config import load_settings
    from daedalus.service.app import create_app

    repo = _init_repo(tmp_path / "repo")
    ignore = _shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".DS_Store")
    _shutil.copytree(_DEMO_PROJECT / "src", repo / "src", ignore=ignore)
    _shutil.copytree(_DEMO_PROJECT / "tests", repo / "tests", ignore=ignore)
    _shutil.copy2(_DEMO_PROJECT / "pyproject.toml", repo / "pyproject.toml")
    _shutil.copy2(_DEMO_PROJECT / ".gitignore", repo / ".gitignore")
    _initial_commit(repo, "chore: import the demo project")

    settings = load_settings(None, workspace_root=str(tmp_path / "ws"))
    app = create_app(settings)
    client = TestClient(app)
    client.__enter__()
    state = app.state.daedalus
    state.identity.environ = {"DAEDALUS_ALICE_SECRET": SECRET}
    if enrolled:
        state.identity.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    return client, state, repo


def _critical_spec_digest() -> str:
    bundle = _Planner().plan(
        _PlanRequest(
            request_id="REQ-API",
            goal_id="GOAL-RISK",
            objective="risky change",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.CRITICAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    return bundle.digest()


def test_over_http_a_high_risk_run_needs_a_signature_once_owners_exist(tmp_path) -> None:
    """The refusal must come *synchronously*, before anything is created."""
    client, state, repo = _http_workspace(tmp_path, enrolled=True)
    payload = {
        "repo_path": str(repo),
        "objective": "risky change",
        "goal_id": "GOAL-RISK",
        "target_paths": [TARGET],
        "test_command": TEST_COMMAND,
        "risk_level": "critical",
        "approve_spec_by": "alice",
    }
    refused = client.post("/api/runs", json=payload)
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"]["code"] == "signature_required"
    assert client.get("/api/runs").json()["runs"] == [], "a refused run must not be created"

    payload["spec_signature"] = state.identity.sign("alice", _critical_spec_digest())
    accepted = client.post("/api/runs", json=payload)
    assert accepted.status_code == 202, accepted.text
    detail = client.get(f"/api/runs/{accepted.json()['run_id']}").json()
    assert detail["spec"]["approval_verified"] is True
    assert "verified hmac-sha256 signature by alice" in detail["spec"]["approval_statement"]
    client.__exit__(None, None, None)


def test_new_high_risk_http_run_refuses_unverified_legacy_approval(tmp_path) -> None:
    """New high-risk delivery policy requires a verified initial signer."""
    client, _state, repo = _http_workspace(tmp_path, enrolled=False)
    accepted = client.post(
        "/api/runs",
        json={
            "repo_path": str(repo),
            "objective": "risky change",
            "goal_id": "GOAL-RISK",
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
            "risk_level": "critical",
            "approve_spec_by": "alice",
        },
    )
    assert accepted.status_code == 409, accepted.text
    assert accepted.json()["error"]["code"] == "identity_required"
    assert client.get("/api/runs").json()["runs"] == []
    client.__exit__(None, None, None)


def test_over_http_the_owners_endpoint_states_the_policy(tmp_path) -> None:
    client, _state, _repo = _http_workspace(tmp_path, enrolled=False)
    before = client.get("/api/owners").json()
    assert before["enforced"] is False
    assert "NOT enforced" in before["note"]
    assert before["owners"] == []
    client.__exit__(None, None, None)


def test_over_http_approving_a_spec_records_whether_it_was_verified(tmp_path) -> None:
    """The endpoint used to write the approval straight to the projection.

    It never consulted the registry, so a signature supplied here was stored and never
    checked — and in fact the call raised outright, because the event it appended had no
    execution id. Both are covered by asserting the *verified* flag and the statement.
    """
    client, state, _repo = _http_workspace(tmp_path, enrolled=True)
    state.store.register_spec(
        spec_digest="s" * 64,
        goal_id="GOAL-X",
        spec_version=1,
        document={"x": 1},
        risk_level="critical",
        owner_id="o",
    )
    unsigned = client.post("/api/specs/" + "s" * 64 + "/approve", json={"approved_by": "alice"})
    assert unsigned.status_code == 409, unsigned.text

    wrong = client.post(
        "/api/specs/" + "s" * 64 + "/approve",
        json={"approved_by": "alice", "signature": "00" * 32},
    )
    assert wrong.status_code == 409
    assert wrong.json()["error"]["code"] == "signature_mismatch"

    signed = client.post(
        "/api/specs/" + "s" * 64 + "/approve",
        json={"approved_by": "alice", "signature": state.identity.sign("alice", "s" * 64)},
    )
    assert signed.status_code == 200, signed.text
    body = signed.json()
    assert body["verified"] is True
    assert body["approval_scheme"] == "hmac-sha256"
    assert "verified hmac-sha256 signature by alice" in body["statement"]
    client.__exit__(None, None, None)


def test_over_http_the_signature_never_appears_in_the_run_view_as_a_secret(tmp_path) -> None:
    client, state, _repo = _http_workspace(tmp_path, enrolled=True)
    state.store.register_spec(
        spec_digest="t" * 64,
        goal_id="GOAL-Y",
        spec_version=1,
        document={"x": 1},
        risk_level="critical",
        owner_id="o",
    )
    client.post(
        "/api/specs/" + "t" * 64 + "/approve",
        json={"approved_by": "alice", "signature": state.identity.sign("alice", "t" * 64)},
    )
    rendered = str(client.get("/api/specs/" + "t" * 64).json())
    assert SECRET not in rendered, "the signing secret must not be echoed by any view"
    assert "hmac-sha256" in rendered
    client.__exit__(None, None, None)


# ---------------------------------------------------------------------------
# Fail closed by default
#
# Every bypass found in adversarial review had one cause: `identity` was an optional field
# defaulting to None, and the policy was `identity is not None and identity.enforced`. So a
# construction site that forgot the keyword silently disabled the control — which happened at
# `daedalus run`, `daedalus replay` and `resume_run`, and no test failed. These tests hold the
# property that makes that class of bug impossible rather than merely absent.
# ---------------------------------------------------------------------------


def test_an_orchestrator_built_without_a_registry_still_enforces(tmp_path) -> None:
    """The control's state comes from the workspace, not from a keyword argument."""
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from daedalus.infrastructure.git_sandbox import init_repo

    store, registry = _registry(tmp_path)
    # An approval recorded while nothing was enrolled: a name, no signature.
    orchestrator = _orchestrator(tmp_path, store, registry, risk=RiskLevel.CRITICAL)
    store.approve_spec(orchestrator.spec_digest, approved_by="mallory")
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    store.close()

    # A *second* orchestrator, built the way a caller who forgot the kwarg would build it.
    from daedalus.application.fsm_service import StateMachineService

    store = EventStore(tmp_path / "identity.db")
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="REQ-ID2",
            goal_id="GOAL-ID",
            objective="x",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.CRITICAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    naive = RunOrchestrator(
        store=store,
        repo_path=init_repo(tmp_path / "repo2"),
        run_root=tmp_path / "wt2",
        bundle=bundle,
        worker=None,
    )
    assert naive.identity is not None, "the registry must never be left unset"
    assert naive._identity_enforced() is True, (
        "a workspace with an enrolled owner must be enforced even when the caller forgets "
        "to inject the registry"
    )
    with pytest.raises(IdentityRequired):
        naive.assert_spec_may_run()
    assert StateMachineService(store) is not None
    store.close()


def test_an_approval_service_built_without_a_registry_still_enforces(tmp_path) -> None:
    """The same property for the step-level decision, which authorises a critical commit."""
    from daedalus.application.approvals import ApprovalService

    store, registry = _registry(tmp_path)
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    store.close()

    store = EventStore(tmp_path / "identity.db")
    service = ApprovalService(store=store, fsm=None, identity=None)  # type: ignore[arg-type]
    assert service.identity is not None
    assert service.identity.enforced is True, (
        "omitting the registry must not turn a workspace with owners into an unverified one"
    )
    store.close()


def test_no_construction_site_leaves_the_registry_unset() -> None:
    """A source check, because the failure mode is *a new call site forgetting*.

    The fail-closed defaults above mean a forgotten argument is no longer a bypass, but an
    explicitly-injected environment (a test, a caller with a prepared secret map) would still
    be lost, and the omission is invisible in review. This pins the convention.

    `demo.py` is exempt: it builds its own workspaces, so the default registry is the correct
    one there, and its §3.2 scenario enrols an owner explicitly (asserted separately).
    """
    repo = Path(__file__).resolve().parent.parent
    offenders: list[str] = []
    for path in (repo / "src" / "daedalus").rglob("*.py"):
        if path.name == "demo.py":
            continue
        source = path.read_text()
        for name in ("RunOrchestrator", "ApprovalService"):
            for start in _call_starts(source, name):
                call = _balanced_call(source, start)
                if "identity=" not in call:
                    line = source[:start].count("\n") + 1
                    offenders.append(f"{path.relative_to(repo)}:{line} {name}")
    assert not offenders, f"construction sites that do not name the registry: {offenders}"


def _call_starts(source: str, name: str) -> list[int]:
    """Offsets of `name(`, ignoring the bare `-> name:` annotations and imports."""
    import re

    return [
        match.start()
        for match in re.finditer(rf"(?<![\w.]){re.escape(name)}\(", source)
    ]


def _balanced_call(source: str, start: int) -> str:
    """The full text of the call beginning at `start`, by paren depth rather than regex.

    A non-greedy regex stops at the first `)` it sees, which for a call with a nested
    constructor (`Quota(...)` inside) reports a false omission — the exact mistake a check
    like this must not make, because a noisy check gets deleted.
    """
    depth = 0
    for index in range(source.index("(", start), len(source)):
        character = source[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unbalanced call at offset {start}")


def test_the_demo_actually_enrols_an_owner_for_the_approval_scenario() -> None:
    """CI cites the demo as evidence, so its §3.2 scenario must reach the enforced path."""
    repo = Path(__file__).resolve().parent.parent
    source = (repo / "src" / "daedalus" / "demo.py").read_text()
    scenario = source[source.index("def run_approval_scenario") : source.index("def _print_report")]
    assert "identity.enroll(" in scenario, "the demo's approval scenario must enrol an owner"
    assert "sign_step(" in scenario, "it must sign the step decision"
    assert "sign(" in scenario, "and sign the frozen spec"
    assert "Identity" not in scenario or "identity" in scenario
    assert "unsigned_refused" in scenario, "it must also show an unsigned decision refused"


def test_the_identity_required_error_names_the_spec_and_risk(tmp_path) -> None:
    """A refusal an operator cannot act on is a dead end."""
    store, registry = _registry(tmp_path)
    orchestrator = _orchestrator(tmp_path, store, registry, risk=RiskLevel.CRITICAL)
    store.approve_spec(orchestrator.spec_digest, approved_by="alice")
    registry.enroll("alice", role=Role.OWNER, secret_env="DAEDALUS_ALICE_SECRET")
    with pytest.raises(IdentityRequired) as error:
        orchestrator.assert_spec_may_run()
    assert orchestrator.spec_digest[:12] in error.value.message
    assert error.value.context.get("risk_level") == "critical"
    assert "approve-spec" in error.value.message
    store.close()
