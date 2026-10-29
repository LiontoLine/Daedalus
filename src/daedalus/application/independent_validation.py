"""Fresh acceptance evidence and a separate principal's signed delivery review.

Evaluation runs on a clean checkout of the exact pending commit. The registered
reviewer signs the immutable report plus their criterion assessments. This is a
separate human identity/key, not a claim of independent hardware or formal proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, UTC
import json
from pathlib import Path
from typing import Any

from daedalus.application.gatekeeper.tier1 import Tier1Gate
from daedalus.application.identity import OwnerRegistry
from daedalus.application.replay import run_repo_path
from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import new_id, utc_now
from daedalus.domain.spec import AssertionKind, PlanNode, SpecBundle
from daedalus.domain.validation import VALIDATION_SIGNATURE_SCHEME, ValidationClaim, ValidationError
from daedalus.infrastructure.git_sandbox import GitSandbox, _git
from daedalus.infrastructure.redact import redact
from daedalus.infrastructure.repository_lock import repository_lock
from daedalus.infrastructure.sandbox import DriverRegistry


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _head(repo: Path, branch: str) -> str:
    return _git(repo, ["rev-parse", "refs/heads/" + branch], check=True).stdout.strip()


def validation_events(store, run_id):
    return store.events_for("validation:" + run_id)


def pending_validation(store, run_id):
    return next(
        (
            dict(e.payload)
            for e in reversed(validation_events(store, run_id))
            if e.event_type == "IndependentValidationRequired"
        ),
        None,
    )


@dataclass
class IndependentValidationService:
    store: Any
    identity: OwnerRegistry | None = None

    def __post_init__(self):
        self.identity = self.identity or OwnerRegistry.for_store(self.store, required=True)

    def _context(self, run_id):
        run = self.store.get_run(run_id)
        _require(run, "unknown validation run")
        spec = self.store.get_spec(run["spec_digest"])
        _require(spec, "validation requires the frozen spec")
        bundle = SpecBundle.from_dict(json.loads(spec["document"]))
        repo = Path(run_repo_path(self.store, run_id))
        return run, spec, bundle, repo

    def _separation(self, run_id):
        run, spec, bundle, repo = self._context(run_id)
        ids = {str(bundle.owner_id), str(bundle.goal.owner_id)}
        fingerprints = set()
        runs = [run]
        for event in self.store.events_for("goal:" + run_id):
            if event.event_type == "GoalStageStarted":
                child = self.store.get_run(event.payload["run_id"])
                if child:
                    runs.append(child)
        for current in runs:
            approval = self.store.get_spec(current["spec_digest"])
            _require(
                approval
                and approval.get("approved_by")
                and int(approval.get("approval_verified") or 0),
                "independent delivery requires verified spec approvals",
            )
            # All historical verified approvers remain excluded after re-approval.
            for event in self.store.events_for_spec(approval["goal_id"]):
                if (
                    event.event_type == "SpecApproved"
                    and event.payload.get("spec_digest") == current["spec_digest"]
                    and event.payload.get("verified") is True
                ):
                    ids.add(str(event.payload["owner_id"]))
                    fingerprints.add(str(event.payload["key_fingerprint"]))
            ids.add(str(approval["approved_by"]))
            _require(
                approval.get("approval_fingerprint"), "verified spec approval has no signing key"
            )
            fingerprints.add(str(approval["approval_fingerprint"]))
            for row in self.store.approvals_for_run(current["run_id"]):
                if row["decision"] in {"proceed", "retry"}:
                    _require(
                        row.get("verified") and row.get("key_fingerprint"),
                        "independent delivery requires verified step approvals",
                    )
                    ids.add(str(row["approved_by"]))
                    fingerprints.add(str(row.get("key_fingerprint") or ""))
            ids.update(
                str(s["worker_id"])
                for s in self.store.list_steps(current["run_id"])
                if s.get("worker_id")
            )
        return ids, fingerprints

    def _check_request(self, run_id):
        run, spec, bundle, repo = self._context(run_id)
        request = pending_validation(self.store, run_id)
        _require(request, "this run has no independent validation request")
        _require(
            run["status"] == "AWAITING_APPROVAL",
            "independent validation requires the parked delivery",
        )
        _require(
            request["execution_id"] == run["execution_id"]
            and request["spec_digest"] == run["spec_digest"],
            "validation request subject changed",
        )
        _require(
            _head(repo, run["branch"]) == request["commit"],
            "the pending commit changed; a new goal review is required",
        )
        self._separation(run_id)
        return run, spec, bundle, repo, request

    def evaluate(self, run_id):
        run, spec, bundle, repo = self._context(run_id)
        with repository_lock(repo):
            run, spec, bundle, repo, request = self._check_request(run_id)
            _require(run.get("worktree_path"), "validation requires the recorded worktree root")
            box = GitSandbox.create_from(
                repo_path=repo,
                run_root=Path(run["worktree_path"]) / "independent",
                name=new_id("validation"),
                base_commit=request["commit"],
            )
            try:
                before = box.tree_digest()
                choice = DriverRegistry.default().select(
                    bundle.boundary, requested=bundle.boundary.isolation
                )
                gate = Tier1Gate(
                    goal=bundle.goal,
                    plan_node=PlanNode(node_id="independent-validation"),
                    boundary=bundle.boundary,
                    meta=bundle.meta,
                    driver=choice.driver,
                    dependency_cache=self.store.path.parent / "dependency-cache",
                )
                dependency = gate._check_dependency_integrity(box, ())
                from daedalus.application.gatekeeper.tier1 import CheckResult
                check = gate._check_acceptance(box, acceptance_overrides=None) if dependency.passed else CheckResult(
                    name="acceptance_blocked_by_dependencies",passed=False,detail=dependency.detail)

                unchanged = box.head() == request["commit"] and box.tree_digest() == before
                now = datetime.now(UTC)
                expires = now + timedelta(hours=1)
                started = next(
                    e.payload
                    for e in self.store.events_for_execution(run["execution_id"])
                    if e.event_type == "RunStarted"
                )
                ttl = int(started.get("execution_ttl_sec", 86400))
                if ttl > 0:
                    expires = min(
                        expires,
                        datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
                        + timedelta(seconds=ttl),
                    )
                authors, keys = self._separation(run_id)
                report = redact(
                    {
                        "validation_id": new_id("validation"),
                        "run_id": run_id,
                        "execution_id": run["execution_id"],
                        "request_id": request["request_id"],
                        "spec_digest": run["spec_digest"],
                        "commit": request["commit"],
                        "tree": before,
                        "authors": sorted(authors),
                        "author_key_fingerprints": sorted(keys),
                        "created_at": utc_now(),
                        "expires_at": expires.isoformat(),
                        "checks_passed": check.passed and unchanged and expires > now,
                        "tree_unchanged": unchanged,
                        "criteria": check.to_payload(),
                        "dependency_validation": dependency.to_payload(),
                        "goal": bundle.goal.to_dict(),
                        "natural_language_criteria": [
                            c.criterion_id
                            for c in bundle.goal.acceptance_criteria
                            if c.kind is AssertionKind.NATURAL_LANGUAGE
                        ],
                        "execution_context": "fresh_worktree_same_controller",
                        "isolation": choice.report.describe(),
                    }
                )
                report["report_digest"] = digest_of(report)
                self.store.append(
                    aggregate_id="validation:" + run_id,
                    execution_id=run["execution_id"],
                    event_type="IndependentValidationEvaluated",
                    actor="validation-controller",
                    payload=report,
                    correlation_id=run["correlation_id"],
                )
                return report
            finally:
                box.remove()

    def report(self, run_id, validation_id):
        report = next(
            (
                dict(e.payload)
                for e in reversed(validation_events(self.store, run_id))
                if e.event_type == "IndependentValidationEvaluated"
                and e.payload["validation_id"] == validation_id
            ),
            None,
        )
        _require(report, "unknown validation report")
        body = {k: v for k, v in report.items() if k != "report_digest"}
        _require(
            digest_of(body) == report["report_digest"],
            "validation evidence no longer matches its digest",
        )
        return report

    def claim(self, run_id, validation_id, *, decision, review_notes, assessments=None):
        report = self.report(run_id, validation_id)
        _require(report["checks_passed"], "failed executable acceptance cannot be overridden")
        claim = ValidationClaim.build(
            report, decision=decision, review_notes=review_notes, assessments=assessments
        )
        serialized = json.dumps(claim.to_dict(), ensure_ascii=False)
        _require(
            not any(secret in serialized for secret in self.identity.known_secret_values()),
            "validation notes must not contain signing credentials",
        )
        _require(
            redact(claim.to_dict()) == claim.to_dict(),
            "validation notes must not contain credentials",
        )
        return claim

    def attest(
        self,
        run_id,
        validation_id,
        *,
        validator_id,
        signature,
        decision="APPROVE",
        review_notes,
        assessments=None,
    ):
        run, spec, bundle, repo = self._context(run_id)
        with repository_lock(repo):
            run, spec, bundle, repo, request = self._check_request(run_id)
            report = self.report(run_id, validation_id)
            _require(
                report["request_id"] == request["request_id"]
                and report["commit"] == request["commit"],
                "report is for another delivery",
            )
            _require(
                datetime.now(UTC) < datetime.fromisoformat(report["expires_at"]),
                "independent validation report has expired",
            )
            evaluations = [
                e
                for e in validation_events(self.store, run_id)
                if e.event_type == "IndependentValidationEvaluated"
            ]
            _require(
                evaluations[-1].payload["validation_id"] == validation_id,
                "a newer independent evaluation superseded this report",
            )
            claim = self.claim(
                run_id,
                validation_id,
                decision=decision,
                review_notes=review_notes,
                assessments=assessments,
            )
            verified = self.identity.authorise_validation(
                validator_id, claim.digest(), signature, risk=bundle.goal.risk_level.value
            )
            authors, keys = self._separation(run_id)
            _require(
                sorted(authors) == report["authors"]
                and sorted(keys) == report["author_key_fingerprints"],
                "approvals changed; a fresh independent evaluation is required",
            )
            _require(
                verified.owner_id not in authors and verified.fingerprint not in keys,
                "validator identity and signing key must differ from all authors and approvers",
            )
            receipt = {
                "validation_id": validation_id,
                "report_digest": report["report_digest"],
                "claim": claim.to_dict(),
                "claim_digest": claim.digest(),
                "request_id": request["request_id"],
                "commit": request["commit"],
                "verified": True,
                "validator_id": verified.owner_id,
                "role": verified.role,
                "scheme": verified.scheme,
                "key_fingerprint": verified.fingerprint,
                "signature": verified.signature,
                "created_at": utc_now(),
            }
            self.store.append(
                aggregate_id="validation:" + run_id,
                execution_id=run["execution_id"],
                event_type="IndependentValidationAttested",
                actor=verified.owner_id,
                payload=receipt,
                correlation_id=run["correlation_id"],
            )
            return receipt

    def recorded_delivery(self, run_id, commit, *, at=None, validation_id=""):
        """Verify immutable evidence as of publication; never run Git or acceptance here.

        A verified attestation survives later key revocation, like spec approval. It
        authorizes only this report/commit, and must have been current at delivery.
        """
        run, spec, bundle, repo = self._context(run_id)
        cutoff = at or datetime.now(UTC).isoformat()
        cutoff_dt = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
        events = [
            e
            for e in validation_events(self.store, run_id)
            if datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")) <= cutoff_dt
        ]
        request = next(
            (e for e in reversed(events) if e.event_type == "IndependentValidationRequired"), None
        )
        report_event = next(
            (e for e in reversed(events) if e.event_type == "IndependentValidationEvaluated"), None
        )
        attested = next(
            (e for e in reversed(events) if e.event_type == "IndependentValidationAttested"), None
        )
        _require(
            request and report_event and attested, "independent validation evidence is incomplete"
        )
        report, receipt = dict(report_event.payload), dict(attested.payload)
        expected_natural = [
            c.criterion_id
            for c in bundle.goal.acceptance_criteria
            if c.kind is AssertionKind.NATURAL_LANGUAGE
        ]
        _require(
            report["natural_language_criteria"] == expected_natural,
            "independent criteria do not match the original goal",
        )
        _require(
            all(e.execution_id == run["execution_id"] for e in (request, report_event, attested)),
            "independent validation execution mismatch",
        )
        _require(
            request.sequence < report_event.sequence < attested.sequence,
            "independent validation evidence is out of order",
        )
        _require(
            digest_of({k: v for k, v in report.items() if k != "report_digest"})
            == report["report_digest"],
            "validation evidence no longer matches its digest",
        )
        _require(
            report["run_id"] == run_id
            and report["execution_id"] == run["execution_id"]
            and report["spec_digest"] == run["spec_digest"]
            and report["goal"] == bundle.goal.to_dict()
            and report["request_id"] == request.payload["request_id"] == receipt["request_id"]
            and report["commit"] == request.payload["commit"] == receipt["commit"] == commit,
            "independent validation subject changed",
        )
        _require(
            report["checks_passed"] is True and report["tree_unchanged"] is True,
            "failed independent executable acceptance cannot authorize delivery",
        )
        _require(
            datetime.fromisoformat(report["expires_at"]) > cutoff_dt,
            "independent validation report has expired",
        )
        _require(
            receipt.get("verified") is True
            and receipt["role"] in {"reviewer", "owner"}
            and receipt["scheme"] == VALIDATION_SIGNATURE_SCHEME
            and bool(receipt["signature"])
            and receipt["validation_id"] == report["validation_id"]
            and receipt["report_digest"] == report["report_digest"]
            and (not validation_id or validation_id == report["validation_id"]),
            "the latest validation report has no verified attestation",
        )
        claim = ValidationClaim.build(
            report,
            decision=receipt["claim"]["decision"],
            review_notes=receipt["claim"]["review_notes"],
            assessments=receipt["claim"]["natural_language_assessments"],
        )
        _require(
            claim.to_dict() == receipt["claim"]
            and claim.digest() == receipt["claim_digest"]
            and claim.decision == "APPROVE",
            "independent reviewer did not approve this delivery",
        )
        _require(
            receipt["validator_id"] not in report["authors"]
            and receipt["key_fingerprint"]
            and receipt["key_fingerprint"] not in report["author_key_fingerprints"],
            "reviewer separation does not hold",
        )
        return receipt

    def authorise_delivery(self, run_id, commit):
        run, spec, bundle, repo, request = self._check_request(run_id)
        _require(commit == request["commit"], "independent review does not authorize this commit")
        receipt = self.recorded_delivery(run_id, commit)
        report = self.report(run_id, receipt["validation_id"])
        authors, keys = self._separation(run_id)
        _require(
            sorted(authors) == report["authors"]
            and sorted(keys) == report["author_key_fingerprints"],
            "approvals changed; a fresh independent evaluation is required",
        )
        _require(
            _git(repo, ["rev-parse", commit + "^{tree}"], check=True).stdout.strip()
            == report["tree"],
            "independent validation tree mismatch",
        )
        return receipt

    def view(self, run_id):
        run, spec, bundle, repo = self._context(run_id)
        started = next(
            (
                e.payload
                for e in self.store.events_for_execution(run["execution_id"])
                if e.event_type == "RunStarted"
            ),
            {},
        )
        required = bundle.goal.risk_level.value in started.get("independent_validation_levels", [])
        request = pending_validation(self.store, run_id)
        reports = [
            dict(e.payload)
            for e in validation_events(self.store, run_id)
            if e.event_type == "IndependentValidationEvaluated"
        ]
        attestations = [
            dict(e.payload)
            for e in validation_events(self.store, run_id)
            if e.event_type == "IndependentValidationAttested"
        ]
        ready = False
        reason = ""
        if request and run["status"] == "AWAITING_APPROVAL":
            try:
                self.authorise_delivery(run_id, request["commit"])
                ready = True
            except Exception as error:
                reason = str(error)
        delivered = False
        delivery = next(
            (
                e
                for e in reversed(self.store.events_for("delivery:" + run_id))
                if e.event_type == "DeliveryRequested"
            ),
            None,
        )
        if required and delivery and run["status"] == "COMPLETED":
            try:
                self.recorded_delivery(
                    run_id,
                    delivery.payload["commit"],
                    at=delivery.timestamp,
                    validation_id=delivery.payload.get("independent_validation_id", ""),
                )
                delivered = True
            except Exception as error:
                reason = str(error)
        return {
            "required": required,
            "request": request,
            "reports": reports,
            "attestations": attestations,
            "ready": ready,
            "reason": reason,
            "status": "DELIVERED"
            if delivered
            else "READY"
            if ready
            else "PENDING"
            if request
            else "NOT_REQUESTED"
            if required
            else "NOT_REQUIRED",
        }
