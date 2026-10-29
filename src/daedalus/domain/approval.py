"""Owner approval (Spec §10, §21).

Escalation is a question, and a system that can ask but never be answered is not
deliverable. This is the record of a human answering.

The binding is what matters: an approval names the **artifact digest** it authorises, not
just the step. A step's content can change between escalations, so approving "step 3"
must not silently authorise a different diff later. `Approval.authorises()` is the single
predicate the commit path consults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from enum import Enum

from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import new_id, utc_now


class ApprovalDecision(str, Enum):
    """What the owner decided."""

    #: Accept this exact artifact despite the escalation; proceed to commit.
    PROCEED = "proceed"
    #: Reject the work and send the step back for another attempt.
    RETRY = "retry"
    #: Stop the step entirely.
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    run_id: str
    step_id: str
    execution_id: str
    decision: ApprovalDecision
    approved_by: str
    note: str = ""
    #: The exact artifact this authorises. Empty for RETRY/REJECT, which authorise nothing.
    artifact_digest: str = ""
    #: The frozen subject digest in force when the approval was given.
    subject_digest: str = ""
    #: Extra attempts granted by a RETRY that follows exhausted retries.
    granted_attempts: int = 0
    #: Spec §3.2. Whether this decision was a signature that verified against a registered
    #: owner, or just a name someone typed. They are different claims and the record must
    #: not let one pass for the other.
    verified: bool = False
    approval_scheme: str = ""
    key_fingerprint: str = ""
    created_at: str = field(default_factory=utc_now)

    def authorises(
        self,
        artifact_digest: str,
        subject_digest: str = "",
        *,
        require_verified: bool = False,
    ) -> bool:
        """True when this approval permits committing exactly this artifact.

        A RETRY or REJECT authorises no commit. A PROCEED authorises one artifact digest
        and, when a subject digest is supplied, only under that frozen spec.

        `require_verified` is the deployment's policy, passed in rather than read from a
        global: a workspace with enrolled owners must not commit on an unverified name, and
        a single-user workspace must still be able to. Keeping it a parameter means the
        decision is visible at the call site instead of hidden in this object.

        This is the predicate the commit path consults. It used to be a docstring claim: the
        commit path asked the store instead, and the store's query omitted the subject check
        below, so the frozen-spec half of the binding was never actually enforced.
        """
        if self.decision is not ApprovalDecision.PROCEED:
            return False
        if not self.artifact_digest or self.artifact_digest != artifact_digest:
            return False
        if self.subject_digest and subject_digest and self.subject_digest != subject_digest:
            return False
        if require_verified and not self.verified:
            return False
        return True

    @classmethod
    def from_row(cls, row: Any) -> "Approval":
        """Rebuild from a store row, so the predicate above operates on real records."""
        return cls(
            approval_id=str(row["approval_id"]),
            run_id=str(row["run_id"]),
            step_id=str(row["step_id"]),
            execution_id=str(row["execution_id"]),
            decision=ApprovalDecision(str(row["decision"])),
            approved_by=str(row["approved_by"]),
            note=str(row["note"]),
            artifact_digest=str(row["artifact_digest"]),
            subject_digest=str(row["subject_digest"]),
            granted_attempts=int(row["granted_attempts"]),
            verified=bool(int(row["verified"])) if "verified" in row.keys() else False,
            approval_scheme=str(row["approval_scheme"]) if "approval_scheme" in row.keys() else "",
            key_fingerprint=(
                str(row["key_fingerprint"]) if "key_fingerprint" in row.keys() else ""
            ),
            created_at=str(row["created_at"]),
        )

    def digest(self) -> str:
        return digest_of(
            {
                "approval_id": self.approval_id,
                "run_id": self.run_id,
                "step_id": self.step_id,
                "decision": self.decision.value,
                "artifact_digest": self.artifact_digest,
                "approved_by": self.approved_by,
                "created_at": self.created_at,
            }
        )

    @property
    def authorises_work(self) -> bool:
        """Whether this decision lets work continue. REJECT does not, and must not need a
        signature: making the safe answer the expensive one would be perverse."""
        return self.decision in (ApprovalDecision.PROCEED, ApprovalDecision.RETRY)

    def to_payload(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "execution_id": self.execution_id,
            "decision": self.decision.value,
            "approved_by": self.approved_by,
            "note": self.note,
            "artifact_digest": self.artifact_digest,
            "subject_digest": self.subject_digest,
            "granted_attempts": self.granted_attempts,
            "verified": self.verified,
            "approval_scheme": self.approval_scheme,
            "key_fingerprint": self.key_fingerprint,
            "created_at": self.created_at,
        }

    @staticmethod
    def issue(
        *,
        run_id: str,
        step_id: str,
        execution_id: str,
        decision: ApprovalDecision,
        approved_by: str,
        note: str = "",
        artifact_digest: str = "",
        subject_digest: str = "",
        granted_attempts: int = 0,
        verified: bool = False,
        approval_scheme: str = "",
        key_fingerprint: str = "",
    ) -> "Approval":
        return Approval(
            approval_id=new_id("approval"),
            run_id=run_id,
            step_id=step_id,
            execution_id=execution_id,
            decision=decision,
            approved_by=approved_by,
            note=note,
            artifact_digest=artifact_digest,
            subject_digest=subject_digest,
            granted_attempts=granted_attempts,
            verified=verified,
            approval_scheme=approval_scheme,
            key_fingerprint=key_fingerprint,
        )


def approval_required(
    *,
    gate_decision: str,
    risk_level: str,
    manual_review_levels: tuple[str, ...],
) -> bool:
    """Whether this gate outcome may only proceed with an explicit human approval.

    Two independent reasons: the gate itself escalated, or the risk level forbids an
    automatic merge no matter what the reviewer said (Spec §10).
    """
    if gate_decision == "ESCALATE":
        return True
    return risk_level in manual_review_levels
