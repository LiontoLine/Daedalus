"""Owner identity, approval authority and spec sign-off (Spec §3.2).

Spec §3.2 requires four things before a high-risk spec may run: **signature**, **owner
identity**, **permission** and **approval state**. Approval state existed from the start;
the other three did not, which made `approved_by="alice"` a string anyone — including the
model plane's own worker — could satisfy. This module supplies them.

Three decisions shape it.

**The signed statement is the spec digest, and nothing else.** The digest already covers
SPEC-01, SPEC-02, SPEC-03 and the Meta-Spec (see `SpecBundle.digest()`), so it pins the
objective, the plan, the boundary *and* the risk level. Signing anything more would add
fields that are not independently meaningful; signing anything less would let a signature
be replayed onto a different contract.

**The subject is domain-separated** (`_SUBJECT_PREFIX`). A bare digest signature is a
signature over a hash, and hashes recur in this system; prefixing the signed bytes means a
spec-approval signature can never be confused with, or reused as, any other signature.

**The primitive is HMAC-SHA256, and that has a stated limit.** It is symmetric: the control
plane holds the same secret it verifies with, so it could in principle forge an approval.
The threat this closes is the one that matters — the untrusted side (a model, a worker
process, a sandboxed command with a scrubbed environment) cannot mint an approval, because
it never sees the secret. It is deliberately not claimed to provide third-party
non-repudiation. `approval_scheme` is recorded with every approval so that a later move to
an asymmetric primitive is a visible, per-row fact rather than a silent change of meaning.

Nothing here performs I/O: the secret is passed in, and the caller decides where it comes
from.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum

from daedalus.domain.spec import RiskLevel
from daedalus.errors import DaedalusError

#: Recorded on every verified approval so the primitive is auditable per row.
SIGNATURE_SCHEME = "hmac-sha256"

#: Domain separation. Changing this invalidates every existing signature, on purpose.
_SUBJECT_PREFIX = "daedalus.spec-approval.v1:"


# --------------------------------------------------------------------------- errors
class IdentityError(DaedalusError):
    """Base class for every identity or approval-authority failure."""

    code = "identity_error"


class OwnerNotRegistered(IdentityError):
    code = "owner_not_registered"


class OwnerRevoked(IdentityError):
    code = "owner_revoked"


class InsufficientAuthority(IdentityError):
    code = "insufficient_authority"


class SignatureRequired(IdentityError):
    code = "signature_required"


class SignatureMismatch(IdentityError):
    code = "signature_mismatch"


class SigningKeyUnavailable(IdentityError):
    """The secret needed to sign or verify is not present.

    A missing key is never treated as a satisfied check: "cannot verify" and "verified" are
    different answers, and only one of them may authorise a commit.
    """

    code = "signing_key_unavailable"


# ---------------------------------------------------------------------------- roles
class Role(str, Enum):
    """What an owner is allowed to do.

    Ordered by authority, and the ceiling is per role rather than per boolean because the
    interesting question is never "may this person approve?" but "may this person approve
    *this*?"
    """

    VIEWER = "viewer"
    OPERATOR = "operator"
    REVIEWER = "reviewer"
    OWNER = "owner"


#: The highest risk level each role may sign off. `None` means "nothing at all".
#: `RiskLevel.rank` supplies the ordering, so this stays a single source of truth.
ROLE_CEILING: dict[Role, RiskLevel | None] = {
    Role.VIEWER: None,
    Role.OPERATOR: RiskLevel.NORMAL,
    Role.REVIEWER: RiskLevel.HIGH,
    Role.OWNER: RiskLevel.CRITICAL,
}


def role_may_approve(role: Role, risk: RiskLevel) -> bool:
    ceiling = ROLE_CEILING[role]
    return ceiling is not None and risk.rank <= ceiling.rank


#: The lowest role that may sign off a given risk level — for error messages that say what
#: the caller would have needed, rather than only that they were refused.
def minimum_role_for(risk: RiskLevel) -> Role:
    for role in (Role.OPERATOR, Role.REVIEWER, Role.OWNER):
        if role_may_approve(role, risk):
            return role
    return Role.OWNER


# -------------------------------------------------------------------------- signing
def approval_subject(spec_digest: str) -> bytes:
    """The exact bytes a spec-approval signature covers."""
    if not spec_digest:
        raise SignatureRequired("a spec approval signature needs a spec digest to cover")
    return f"{_SUBJECT_PREFIX}{spec_digest}".encode()


def compute_signature(secret: str, spec_digest: str) -> str:
    """Hex HMAC-SHA256 over the domain-separated spec digest."""
    if not secret:
        raise SigningKeyUnavailable("cannot sign without a secret")
    return hmac.new(
        secret.encode(), approval_subject(spec_digest), hashlib.sha256
    ).hexdigest()


def verify_signature(secret: str, spec_digest: str, provided: str) -> None:
    """Raise unless `provided` is this owner's signature over this spec digest."""
    if not provided:
        raise SignatureRequired(
            f"spec {spec_digest[:12]} requires a signature from a registered owner"
        )
    if not secret:
        raise SigningKeyUnavailable(
            "the owner's signing secret is not available to the verifier, so the signature "
            "cannot be checked. An unverifiable signature is not a verified one."
        )
    expected = compute_signature(secret, spec_digest)
    # compare_digest, not `==`: a comparison that returns early leaks the prefix length.
    if not hmac.compare_digest(expected, provided.strip().lower()):
        raise SignatureMismatch(
            f"the signature does not match spec {spec_digest[:12]} for this owner. Either "
            "the spec changed after signing, or the signature came from a different key."
        )


def fingerprint(secret: str) -> str:
    """A stable, non-reversible identifier for a signing key.

    Stored instead of the secret so the registry can say *which* key is enrolled and detect
    that an environment variable now holds a different one, without the database ever
    holding a credential.
    """
    if not secret:
        return ""
    return hashlib.sha256(f"daedalus.owner-key.v1:{secret}".encode()).hexdigest()[:32]


# --------------------------------------------------------- step-level approval
#: A second, separate domain separator. A step approval authorises a *specific artifact*;
#: a spec approval authorises a *contract*. Signing one must never be usable as the other,
#: and two distinct prefixes is what makes that structural rather than a matter of care.
_STEP_SUBJECT_PREFIX = "daedalus.step-approval.v1:"


def step_approval_subject(
    run_id: str, step_id: str, decision: str, artifact_digest: str, attempt: int = 0
) -> bytes:
    """The exact bytes a step-level owner decision covers.

    Everything that makes the decision what it is goes in: which run, which step, what was
    decided, the artifact it authorises, and the attempt it was given at. Omitting any of
    them would let a signature be replayed as another — a `retry` signature presented as a
    `proceed`, an approval for one run's artifact reused on a different run's, or (without
    the attempt) one `retry` signature authorising every subsequent retry on that step for
    the life of the run, since a retry authorises no artifact and so would otherwise sign
    the identical bytes each time.
    """
    if not run_id or not step_id or not decision:
        raise SignatureRequired("a step approval signature needs a run, a step and a decision")
    return (
        f"{_STEP_SUBJECT_PREFIX}{run_id}:{step_id}:{decision}:{artifact_digest}:{int(attempt)}"
    ).encode()


def compute_step_signature(
    secret: str,
    run_id: str,
    step_id: str,
    decision: str,
    artifact_digest: str,
    attempt: int = 0,
) -> str:
    if not secret:
        raise SigningKeyUnavailable("cannot sign without a secret")
    return hmac.new(
        secret.encode(),
        step_approval_subject(run_id, step_id, decision, artifact_digest, attempt),
        hashlib.sha256,
    ).hexdigest()


def verify_step_signature(
    secret: str,
    run_id: str,
    step_id: str,
    decision: str,
    artifact_digest: str,
    provided: str,
    attempt: int = 0,
) -> None:
    if not provided:
        raise SignatureRequired(
            f"the {decision} decision on {step_id} requires a signature from a registered owner"
        )
    if not secret:
        raise SigningKeyUnavailable(
            "the owner's signing secret is not available to the verifier, so the decision "
            "signature cannot be checked. An unverifiable signature is not a verified one."
        )
    expected = compute_step_signature(
        secret, run_id, step_id, decision, artifact_digest, attempt
    )
    if not hmac.compare_digest(expected, provided.strip().lower()):
        raise SignatureMismatch(
            "the signature does not match this decision. It covers the run, the step, the "
            "decision, the artifact and the attempt, so any of them changing invalidates it. "
            f"For this decision the attempt is {int(attempt)}."
        )


# --------------------------------------------------------------------------- owners
@dataclass(frozen=True, slots=True)
class Owner:
    """A registered principal who may sign off specs."""

    owner_id: str
    role: Role = Role.VIEWER
    display_name: str = ""
    secret_env: str = ""
    key_fingerprint: str = ""
    created_at: str = ""
    revoked_at: str = ""

    @property
    def revoked(self) -> bool:
        return bool(self.revoked_at)

    @property
    def can_sign(self) -> bool:
        return bool(self.secret_env) and not self.revoked

    def may_approve(self, risk: RiskLevel) -> bool:
        return not self.revoked and role_may_approve(self.role, risk)

    def to_payload(self) -> dict[str, object]:
        """Safe to record in an event: never contains the secret, only its fingerprint."""
        return {
            "owner_id": self.owner_id,
            "role": self.role.value,
            "display_name": self.display_name,
            "secret_env": self.secret_env,
            "key_fingerprint": self.key_fingerprint,
            "created_at": self.created_at,
            "revoked_at": self.revoked_at,
        }
