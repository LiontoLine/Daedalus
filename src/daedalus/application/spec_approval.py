"""Spec sign-off, recorded in one place (Spec §3.2, §10, §27).

There were two ways to approve a spec — the orchestrator's and the HTTP endpoint's — and
they did different things. The endpoint wrote `approved_by` straight to the projection and
appended its own event, which meant it could not have verified a signature even if it had
wanted to: it never consulted the registry at all. A second write path is a second policy,
and in an authorisation path that is the whole bug.

So the authorisation-then-record sequence lives here and both callers use it. The service
does not decide *whether* identity is enforced; `OwnerRegistry` does. It decides only what a
successful approval looks like on the record, which must be identical no matter who asked.
"""

from __future__ import annotations

from dataclasses import dataclass

from daedalus.application.identity import ApprovalOutcome, OwnerRegistry
from daedalus.domain.spec import RiskLevel
from daedalus.errors import DaedalusError
from daedalus.infrastructure.store.event_store import EventStore


class SpecNotRegistered(DaedalusError):
    code = "spec_not_registered"


@dataclass(frozen=True, slots=True)
class SpecApprovalService:
    """Verify a spec sign-off, then persist it and its event."""

    store: EventStore
    identity: OwnerRegistry

    def authorise(
        self,
        *,
        spec_digest: str,
        approved_by: str,
        signature: str = "",
    ) -> ApprovalOutcome:
        """Verify without recording. Read-only: a refused sign-off leaves no trace."""
        spec = self.store.get_spec(spec_digest)
        if spec is None:
            raise SpecNotRegistered(
                f"spec {spec_digest[:12]} is not registered, so there is nothing to approve"
            )
        return self.identity.authorise(
            approved_by=approved_by,
            risk=RiskLevel(str(spec["risk_level"])),
            spec_digest=spec_digest,
            signature=signature,
        )

    def record(
        self,
        *,
        spec_digest: str,
        approved_by: str,
        signature: str = "",
        execution_id: str = "",
        correlation_id: str = "",
    ) -> ApprovalOutcome:
        """Verify, then persist the approval and append `SpecApproved`.

        The event carries the verification result, including which primitive and which key
        fingerprint produced it. An auditor must be able to tell a verified sign-off from a
        recorded name by reading the log alone, without consulting the current registry —
        which may have changed since.
        """
        spec = self.store.get_spec(spec_digest)
        if spec is None:
            raise SpecNotRegistered(
                f"spec {spec_digest[:12]} is not registered, so there is nothing to approve"
            )
        # Always authorise here. A caller-supplied `outcome` used to be persisted verbatim,
        # which made this the one way to write `approval_verified = 1` without verifying
        # anything — in an API whose entire purpose is to make that impossible. A parameter
        # that can only be misused is a parameter to delete.
        resolved = self.identity.authorise(
            approved_by=approved_by,
            risk=RiskLevel(str(spec["risk_level"])),
            spec_digest=spec_digest,
            signature=signature,
        )
        # A second approval silently replaced the first in the projection, so the log showed
        # two `SpecApproved` events and the record showed only the last writer. Naming the
        # superseded event makes the history answerable instead of ambiguous.
        previous = self.store.get_spec(spec_digest) or {}
        supersedes = ""
        if previous.get("approved_at"):
            for event in reversed(self.store.events_for_spec(str(spec["goal_id"]))):
                if event.event_type == "SpecApproved":
                    supersedes = event.event_id
                    break
        self.store.approve_spec(
            spec_digest,
            approved_by=resolved.owner_id,
            signature=resolved.signature,
            verified=resolved.verified,
            scheme=resolved.scheme,
            role=resolved.role,
            fingerprint=resolved.fingerprint,
        )
        self.store.append(
            aggregate_id=f"spec:{spec['goal_id']}",
            execution_id=execution_id,
            event_type="SpecApproved",
            actor=resolved.owner_id,
            payload={
                "goal_id": str(spec["goal_id"]),
                "spec_digest": spec_digest,
                "supersedes": supersedes,
                **resolved.to_payload(),
            },
            correlation_id=correlation_id,
        )
        return resolved

    def approval_view(self, spec_digest: str) -> dict[str, object]:
        """How an approval should be *reported*: never claim more than was verified."""
        spec = self.store.get_spec(spec_digest)
        if spec is None:
            raise SpecNotRegistered(f"spec {spec_digest[:12]} is not registered")
        verified = bool(int(spec.get("approval_verified") or 0))
        approved_by = str(spec.get("approved_by") or "")
        return {
            "spec_digest": spec_digest,
            "approved_by": approved_by,
            "approved_at": spec.get("approved_at"),
            "verified": verified,
            "scheme": str(spec.get("approval_scheme") or ""),
            "role": str(spec.get("approval_role") or ""),
            "key_fingerprint": str(spec.get("approval_fingerprint") or ""),
            "enforced": self.identity.enforced,
            # Say plainly which of the two things happened. "approved_by=alice" with no
            # signature is not the same claim as "verified signature by alice".
            "statement": (
                f"verified {spec.get('approval_scheme')} signature by {approved_by}"
                if verified
                else (
                    (
                        f"UNVERIFIED approval for {approved_by}: a signature was supplied "
                        "but nothing could check it (no owner identity is enrolled)"
                        if spec.get("signature")
                        else f"unverified approval recorded for {approved_by} "
                        "(no owner identity is enrolled in this workspace)"
                    )
                    if approved_by
                    else "not approved"
                )
            ),
        }
