"""Owner registry and approval authorisation (Spec §3.2).

This is the layer that turns the pure contracts in `domain/identity.py` into a decision:
*is this sign-off from a principal who exists, has not been revoked, holds enough authority
for this risk level, and produced a signature that verifies?*

Two things are deliberately kept out of the domain object. The registry does I/O (SQLite and
the environment), and the environment is the only place a signing secret is ever read from —
the same rule the model credentials follow. The database stores the *name* of the variable
and a fingerprint of the key, never the key.

**Enforcement is a property of the deployment, not a magic default.** The rule is:

* no owners enrolled, and identity not required  → approvals are recorded but explicitly
  marked unverified, and every interface says so;
* any owner enrolled, or identity required       → *every* approval must be a verified
  sign-off, and an unverifiable one is refused.

The second half matters more than it looks. A half-enrolled registry that silently accepted
unsigned approvals would be worse than no registry, because the deployment would believe it
had a control it did not have. The first half matters too: single-user offline use is a
legitimate deployment, and forcing it to manage keys would push operators toward disabling
the check rather than configuring it.
"""

from __future__ import annotations

import os
from typing import Any
from dataclasses import dataclass, field

from daedalus.domain.identity import (
    SIGNATURE_SCHEME,
    InsufficientAuthority,
    Owner,
    OwnerNotRegistered,
    OwnerRevoked,
    Role,
    SignatureRequired,
    SigningKeyUnavailable,
    compute_signature,
    compute_step_signature,
    fingerprint,
    minimum_role_for,
    verify_signature,
    verify_step_signature,
)
from daedalus.domain.ids import utc_now
from daedalus.domain.spec import RiskLevel
from daedalus.errors import DaedalusError


#: Recorded as the scheme of an approval whose signature could not be checked. Naming a
#: real primitive here would claim a check that never ran.
UNVERIFIED_SCHEME = "unverified"

#: The decisions that let work continue, and therefore need a verified sign-off once owners
#: are enrolled. `reject` is absent on purpose — see `authorise_step_decision`.
_WORK_AUTHORISING_DECISIONS = frozenset({"proceed", "retry"})


def decision_needs_signature(risk: RiskLevel) -> bool:
    """Whether a step-level decision at this risk level must be signature-verified.

    One predicate, consulted by both sides: the service that *verifies* a decision and the
    commit gate that *requires* one. They were written separately and drifted immediately —
    the verifier exempted normal-risk steps while the gate demanded verification for every
    approval, so a legitimate normal-risk approval was recorded unverified and then refused at
    commit time. A rule that two components must agree on has to exist in one place.
    """
    return risk.rank >= RiskLevel.HIGH.rank


class IdentityRequired(DaedalusError):
    """A verified sign-off is required and the spec does not have one (Spec §3.2)."""

    code = "identity_required"


@dataclass(frozen=True, slots=True)
class ApprovalOutcome:
    """What was recorded, and on what basis. Every field is safe to log."""

    owner_id: str
    role: str
    risk_level: str
    verified: bool
    scheme: str
    fingerprint: str
    signature: str

    def to_payload(self) -> dict[str, object]:
        """The payload for the `SpecApproved` event.

        The signature is included on purpose: it is an HMAC over the spec digest, not a
        credential, and reproducing it is what lets an auditor re-check the sign-off later.
        """
        return {
            "owner_id": self.owner_id,
            "role": self.role,
            "risk_level": self.risk_level,
            "verified": self.verified,
            "approval_scheme": self.scheme,
            "key_fingerprint": self.fingerprint,
            "signature": self.signature,
        }


@dataclass
class OwnerRegistry:
    """Enrolment, revocation and verification over the `owners` projection."""

    store: object
    #: When true, a verified sign-off is required even with no owners enrolled. A deployment
    #: sets this to refuse to run high-risk work rather than run it unattributed.
    required: bool = False
    environ: dict[str, str] | None = None
    #: Values read while signing or verifying, so the redactor can mask them everywhere else.
    _seen_secrets: set[str] = field(default_factory=set, repr=False)

    @classmethod
    def for_store(cls, store: Any, *, required: bool = False) -> "OwnerRegistry":
        """The registry for a workspace, with enforcement derived from its enrolment.

        Callers that forget to inject a registry used to disable verification silently, so
        both approval services build one through here when none is supplied. The control's
        state then comes from the workspace rather than from whether a construction site
        remembered a keyword argument — a class of bug that appeared four times.
        """
        return cls(store=store, required=required)

    # ------------------------------------------------------------------ policy
    @property
    def enrolled(self) -> int:
        """Owners with authority right now."""
        return int(self.store.owner_count())  # type: ignore[attr-defined]

    @property
    def ever_enrolled(self) -> int:
        """Owners ever registered, revoked ones included."""
        return int(self.store.owner_count(include_revoked=True))  # type: ignore[attr-defined]

    @property
    def enforced(self) -> bool:
        """True when an approval must be a verified sign-off.

        Keyed on owners *ever* having been enrolled, not on how many are active. Counting
        only live owners made `revoke` a way to switch the control off: revoking the last
        owner returned the workspace to the unenrolled state, where any name is accepted.
        Revocation must narrow authority, never widen it.
        """
        return self.required or self.ever_enrolled > 0

    def describe(self) -> dict[str, object]:
        """The honest state of this control, for `preflight` and the release gate."""
        return {
            "enforced": self.enforced,
            "required_by_config": self.required,
            "owners_enrolled": self.enrolled,
            "owners_ever_registered": self.ever_enrolled,
            "scheme": SIGNATURE_SCHEME,
            "note": (
                "approvals must be signed by a registered owner"
                if self.enforced
                else "identity verification is NOT enforced: no owners are enrolled. "
                "Approvals are recorded but marked unverified."
            ),
        }

    # -------------------------------------------------------------- enrolment
    def enroll(
        self,
        owner_id: str,
        *,
        role: Role,
        secret: str = "",
        secret_env: str = "",
        display_name: str = "",
    ) -> Owner:
        """Register an owner.

        The secret may be supplied directly (the CLI reads it from the environment and passes
        it here) or named by environment variable for later verification. Whichever path is
        used, only the fingerprint is persisted.
        """
        owner_id = owner_id.strip()
        if not owner_id:
            raise OwnerNotRegistered("an owner must have an id")
        resolved = secret or (self._env().get(secret_env, "") if secret_env else "")
        if secret and not secret_env:
            # Record where the verifier will look, so verification does not depend on the
            # enrolling process still being alive.
            raise SigningKeyUnavailable(
                "enrolling an owner from a literal secret is refused: name the environment "
                "variable that will hold it (--secret-env), so verification can happen in a "
                "different process from enrolment"
            )
        owner = Owner(
            owner_id=owner_id,
            role=role,
            display_name=display_name or owner_id,
            secret_env=secret_env,
            key_fingerprint=fingerprint(resolved),
            created_at=utc_now(),
            revoked_at="",
        )
        self.store.upsert_owner(owner)  # type: ignore[attr-defined]
        if resolved:
            self._seen_secrets.add(resolved)
        return owner

    def revoke(self, owner_id: str) -> bool:
        return bool(self.store.revoke_owner(owner_id))  # type: ignore[attr-defined]

    def get(self, owner_id: str) -> Owner | None:
        return self.store.get_owner(owner_id)  # type: ignore[attr-defined]

    def list(self, *, include_revoked: bool = False) -> list[Owner]:
        return list(self.store.list_owners(include_revoked=include_revoked))  # type: ignore[attr-defined]

    # ----------------------------------------------------------------- signing
    def sign(self, owner_id: str, spec_digest: str) -> str:
        """Produce a signature as the named owner.

        This is the *signer's* side. It reads the secret from the environment named in the
        enrolment, so a deployment can keep signing material out of the daemon entirely.
        """
        owner = self.get(owner_id)
        if owner is None:
            raise OwnerNotRegistered(f"owner {owner_id!r} is not registered")
        if owner.revoked:
            raise OwnerRevoked(f"owner {owner_id!r} was revoked at {owner.revoked_at}")
        secret = self._secret_for(owner)
        self._seen_secrets.add(secret)
        return compute_signature(secret, spec_digest)

    # ------------------------------------------------------------- authorising
    def authorise(
        self,
        *,
        approved_by: str,
        risk: RiskLevel,
        spec_digest: str,
        signature: str = "",
    ) -> ApprovalOutcome:
        """Verify a sign-off, or refuse it.

        Fails closed on every axis: unknown owner, revoked owner, role below the risk
        ceiling, absent signature, unreadable key, and mismatched signature all raise. The
        only way through is a signature that verifies against a registered principal with
        the authority to give it.
        """
        owner_id = approved_by.strip()
        if not owner_id:
            raise SignatureRequired("an approval must name who gave it (Spec §27)")

        if not self.enforced:
            # No owners are enrolled, so nothing here can be checked. The sign-off is still
            # *recorded* — refusing to store it would make the tool useless to an
            # organisation that signs with its own PKI and wants the signature kept — but it
            # is recorded as unverified, and the scheme says so rather than naming a
            # primitive that was never applied.
            #
            # What must not happen is *acting* on it: `assert_spec_may_run` asks for a
            # verified sign-off the moment enforcement is on, so this record cannot admit a
            # high-risk run.
            return ApprovalOutcome(
                owner_id=owner_id,
                role="",
                risk_level=risk.value,
                verified=False,
                scheme=UNVERIFIED_SCHEME if signature else "",
                fingerprint="",
                signature=signature.strip(),
            )

        owner = self.get(owner_id)
        if owner is None:
            raise OwnerNotRegistered(
                f"owner {owner_id!r} is not registered, and this workspace verifies "
                "approvals. Register them: "
                "`daedalus owners add --owner-id "
                f"{owner_id} --role reviewer --secret-env DAEDALUS_{owner_id.upper()}_SECRET`"
            )
        if owner.revoked:
            raise OwnerRevoked(f"owner {owner_id!r} was revoked at {owner.revoked_at}")
        if not owner.may_approve(risk):
            raise InsufficientAuthority(
                f"{owner_id!r} holds role {owner.role.value!r}, which may not approve "
                f"risk={risk.value}. Risk {risk.value} needs at least "
                f"{minimum_role_for(risk).value!r}."
            )
        if not signature:
            raise SignatureRequired(
                f"risk={risk.value} requires a signature from {owner_id!r}. Sign the spec "
                "digest and pass it with --signature, or sign locally with "
                f"`daedalus sign-spec --spec {spec_digest} --owner-id {owner_id}`"
            )

        secret = self._secret_for(owner, verifier=True)
        self._seen_secrets.add(secret)
        verify_signature(secret, spec_digest, signature)
        return ApprovalOutcome(
            owner_id=owner.owner_id,
            role=owner.role.value,
            risk_level=risk.value,
            verified=True,
            scheme=SIGNATURE_SCHEME,
            fingerprint=owner.key_fingerprint,
            signature=signature.strip().lower(),
        )

    # ------------------------------------------------------- step-level decisions
    def authorise_step_decision(
        self,
        *,
        run_id: str,
        step_id: str,
        decision: str,
        approved_by: str,
        risk: RiskLevel,
        artifact_digest: str = "",
        signature: str = "",
        attempt: int = 0,
    ) -> ApprovalOutcome:
        """Verify a step-level owner decision (Spec §10 x §3.2).

        This is the decision that lets a CRITICAL change commit after a gate refused it, so
        it is at least as consequential as the spec sign-off — and until this existed it
        accepted a typed name. The signed bytes cover the run, the step, the decision and the
        artifact, so a signature cannot be moved between any of them.

        Only decisions that *authorise work* are verified. A REJECT stops the step, and
        putting a signature requirement in front of the safe answer would push operators
        toward approving instead of rejecting.

        Registry membership is still required for *any* decision once enforcement is on,
        including a rejection. That is deliberate rather than an oversight: an unregistered
        principal must not be able to stop a run either, so the refusal above applies before
        the decision is examined. The only thing a REJECT does not need is a *signature*.
        """
        owner_id = approved_by.strip()
        if not owner_id:
            raise SignatureRequired(
                "an owner decision must name who gave it (Spec §27: the audit has to answer "
                "'who approved')"
            )
        if not self.enforced:
            return ApprovalOutcome(
                owner_id=owner_id,
                role="",
                risk_level=risk.value,
                verified=False,
                scheme=UNVERIFIED_SCHEME if signature else "",
                fingerprint="",
                signature=signature.strip(),
            )

        owner = self.get(owner_id)
        if owner is None:
            raise OwnerNotRegistered(
                f"owner {owner_id!r} is not registered, and this workspace verifies owner "
                "decisions. Register them with `daedalus owners add`."
            )
        if owner.revoked:
            raise OwnerRevoked(f"owner {owner_id!r} was revoked at {owner.revoked_at}")
        # Checked *before* the risk gate, and deliberately: a REJECT stops the step. Putting a
        # signature requirement in front of the safe answer would push an operator toward
        # approving instead of rejecting — the control would make the system less safe.
        if decision not in _WORK_AUTHORISING_DECISIONS:
            return ApprovalOutcome(
                owner_id=owner.owner_id,
                role=owner.role.value,
                risk_level=risk.value,
                verified=False,
                scheme="",
                fingerprint="",
                signature="",
            )
        # Nor does an escalation on a low-risk step need owner authority: §10 is about
        # high-risk change, and requiring a key for every routine escalation would make the
        # control expensive enough to disable.
        if not decision_needs_signature(risk):
            return ApprovalOutcome(
                owner_id=owner.owner_id,
                role=owner.role.value,
                risk_level=risk.value,
                verified=False,
                scheme="",
                fingerprint="",
                signature="",
            )
        if not owner.may_approve(risk):
            raise InsufficientAuthority(
                f"{owner_id!r} holds role {owner.role.value!r}, which may not decide on "
                f"risk={risk.value}. Risk {risk.value} needs at least "
                f"{minimum_role_for(risk).value!r}."
            )
        if not signature:
            raise SignatureRequired(
                f"risk={risk.value} requires a signature for the {decision} decision on "
                f"{step_id}. Sign it with `daedalus sign-step --run-id {run_id} "
                f"--step {step_id} --decision {decision} --owner-id {owner_id}`."
            )

        secret = self._secret_for(owner, verifier=True)
        self._seen_secrets.add(secret)
        verify_step_signature(
            secret, run_id, step_id, decision, artifact_digest, signature, attempt
        )
        return ApprovalOutcome(
            owner_id=owner.owner_id,
            role=owner.role.value,
            risk_level=risk.value,
            verified=True,
            scheme=SIGNATURE_SCHEME,
            fingerprint=owner.key_fingerprint,
            signature=signature.strip().lower(),
        )

    def sign_step(
        self,
        owner_id: str,
        run_id: str,
        step_id: str,
        decision: str,
        artifact_digest: str,
        attempt: int = 0,
    ) -> str:
        """Produce a step-decision signature as the named owner."""
        owner = self.get(owner_id)
        if owner is None:
            raise OwnerNotRegistered(f"owner {owner_id!r} is not registered")
        if owner.revoked:
            raise OwnerRevoked(f"owner {owner_id!r} was revoked at {owner.revoked_at}")
        secret = self._secret_for(owner)
        self._seen_secrets.add(secret)
        return compute_step_signature(secret, run_id, step_id, decision, artifact_digest, attempt)

    def _validation_principal(self, owner_id: str):
        owner = self.get(owner_id)
        if owner is None:
            raise OwnerNotRegistered("independent validator must be a registered principal")
        if owner.revoked:
            raise OwnerRevoked("independent validator has been revoked")
        if owner.role not in {Role.REVIEWER, Role.OWNER}:
            raise InsufficientAuthority("independent validation requires reviewer or owner role")
        return owner

    def sign_validation(self, owner_id: str, claim_digest: str) -> str:
        from daedalus.domain.validation import compute_validation_signature

        owner = self._validation_principal(owner_id)
        secret = self._secret_for(owner)
        self._seen_secrets.add(secret)
        return compute_validation_signature(secret, claim_digest)

    def authorise_validation(self, owner_id: str, claim_digest: str, signature: str, *, risk: str):
        from daedalus.domain.validation import (
            VALIDATION_SIGNATURE_SCHEME,
            verify_validation_signature,
        )

        owner = self._validation_principal(owner_id)
        secret = self._secret_for(owner, verifier=True)
        self._seen_secrets.add(secret)
        verify_validation_signature(secret, claim_digest, signature)
        return ApprovalOutcome(
            owner_id=owner.owner_id,
            role=owner.role.value,
            risk_level=risk,
            verified=True,
            scheme=VALIDATION_SIGNATURE_SCHEME,
            fingerprint=owner.key_fingerprint,
            signature=signature.strip().lower(),
        )

    # ------------------------------------------------------------------ secrets
    def _env(self) -> dict[str, str]:
        return dict(os.environ if self.environ is None else self.environ)

    def _secret_for(self, owner: Owner, *, verifier: bool = False) -> str:
        """Read the owner's signing secret from the environment variable they enrolled with."""
        if owner.revoked:
            raise OwnerRevoked(f"owner {owner.owner_id!r} was revoked at {owner.revoked_at}")
        if not owner.secret_env:
            raise SigningKeyUnavailable(
                f"owner {owner.owner_id!r} has no signing key enrolled, so their approvals "
                "cannot be verified. Re-enrol them with --secret-env."
            )
        secret = self._env().get(owner.secret_env, "")
        if not secret:
            role = "verify" if verifier else "sign"
            raise SigningKeyUnavailable(
                f"to {role} as {owner.owner_id!r}, the environment variable "
                f"{owner.secret_env} must hold their signing secret, and it is unset. A "
                "signature that cannot be checked is not a verified signature."
            )
        expected = owner.key_fingerprint
        if expected and fingerprint(secret) != expected:
            raise SigningKeyUnavailable(
                f"{owner.secret_env} does not match the key enrolled for "
                f"{owner.owner_id!r}; it may have been rotated. Re-enrol the owner to "
                "accept the new key."
            )
        return secret

    def known_secret_values(self) -> frozenset[str]:
        """Signing secrets seen this session, for the redactor to mask."""
        env = self._env()
        present = {
            env.get(owner.secret_env, "")
            for owner in self.list(include_revoked=True)
            if owner.secret_env
        }
        return frozenset(self._seen_secrets | (present - {""}))
