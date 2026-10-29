"""Independent validation claims: frozen subjects and domain-separated signatures."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
from typing import Any

from daedalus.domain.canonical import digest_of
from daedalus.domain.identity import SignatureMismatch, SignatureRequired, SigningKeyUnavailable
from daedalus.errors import DaedalusError

VALIDATION_SIGNATURE_SCHEME = "hmac-sha256:independent-validation-v1"

PREFIX = b"daedalus.independent-validation.v1:"


class ValidationError(DaedalusError):
    code = "independent_validation_error"


@dataclass(frozen=True)
class ValidationClaim:
    report_digest: str
    decision: str
    review_notes: str
    natural_language_assessments: tuple[tuple[str, str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_digest": self.report_digest,
            "decision": self.decision,
            "review_notes": self.review_notes,
            "natural_language_assessments": [
                {"criterion_id": key, "status": status, "evidence": evidence}
                for key, status, evidence in self.natural_language_assessments
            ],
        }

    def digest(self) -> str:
        return digest_of(self.to_dict())

    @classmethod
    def build(
        cls, report: dict, *, decision: str, review_notes: str, assessments: list | None = None
    ):
        if not isinstance(decision, str) or decision not in {"APPROVE", "REJECT"}:
            raise ValidationError("validation decision must be APPROVE or REJECT")
        if (
            not isinstance(review_notes, str)
            or not review_notes.strip()
            or len(review_notes) > 4000
        ):
            raise ValidationError(
                "independent review requires concrete notes within 4000 characters"
            )
        rows = [] if assessments is None else assessments
        if not isinstance(rows, list) or any(
            not isinstance(r, dict)
            or set(r) != {"criterion_id", "status", "evidence"}
            or not all(isinstance(r.get(k), str) for k in ("criterion_id", "status", "evidence"))
            or r["status"] not in {"MET", "UNMET", "UNKNOWN"}
            or not r["evidence"].strip()
            or len(r["evidence"]) > 4000
            for r in rows
        ):
            raise ValidationError("malformed independent criterion assessments")
        required = set(report.get("natural_language_criteria", []))
        keys = [r["criterion_id"] for r in rows]
        if set(keys) != required or len(keys) != len(required):
            raise ValidationError(
                "every non-executable criterion requires exactly one independent assessment"
            )
        if decision == "APPROVE" and any(r["status"] != "MET" for r in rows):
            raise ValidationError("unknown or unmet independent criteria cannot approve delivery")
        return cls(
            report_digest=str(report["report_digest"]),
            decision=decision,
            review_notes=review_notes.strip(),
            natural_language_assessments=tuple(
                sorted((r["criterion_id"], r["status"], r["evidence"].strip()) for r in rows)
            ),
        )


def compute_validation_signature(secret: str, claim_digest: str) -> str:
    if not secret:
        raise SigningKeyUnavailable("validation signing key is unavailable")
    if not claim_digest:
        raise SignatureRequired("validation signature requires a claim digest")
    return hmac.new(secret.encode(), PREFIX + claim_digest.encode(), hashlib.sha256).hexdigest()


def verify_validation_signature(secret: str, claim_digest: str, signature: str) -> None:
    if not signature:
        raise SignatureRequired("independent validation requires a signature")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", signature.strip()):
        raise SignatureMismatch(
            "independent validation signature must be 64 hexadecimal characters"
        )
    if not hmac.compare_digest(
        compute_validation_signature(secret, claim_digest), signature.strip().lower()
    ):
        raise SignatureMismatch(
            "independent validation signature does not match this report and claim"
        )
