"""Owner approval: answering an escalation (Spec §10, §16, §21).

Three decisions, three futures:

    PROCEED  the owner accepts THIS artifact; it goes to commit
    RETRY    the work is not acceptable but the step is worth another attempt
    REJECT   the step stops

The binding that makes this safe: a PROCEED names the artifact digest it authorises. The
commit path re-reads that digest and refuses to proceed without a matching approval, so
approving "step 3" cannot silently authorise a different diff later.

Two invariants this module enforces rather than documents:

* An approval may only be given for a step that is actually ESCALATED. Approving a step
  that is running, or already committed, is a mistake the API refuses instead of happily
  recording.
* A rebase invalidates an approval. Rebasing changes the tree, so the artifact the owner
  approved is no longer the artifact that would land. The approval is not transferable and
  the step is parked again for a fresh decision.
"""

from __future__ import annotations

from typing import Any
from dataclasses import dataclass

from daedalus.application.fsm_service import StateMachineService
from daedalus.application.identity import ApprovalOutcome, OwnerRegistry
from daedalus.domain.approval import Approval, ApprovalDecision
from daedalus.domain.fsm import StepState
from daedalus.domain.spec import RiskLevel
from daedalus.errors import DaedalusError
from daedalus.infrastructure.store.event_store import EventStore


class ApprovalError(DaedalusError):
    code = "approval_error"


class NotEscalated(ApprovalError):
    code = "not_escalated"


@dataclass(frozen=True, slots=True)
class ApprovalResult:
    approval_id: str
    run_id: str
    step_id: str
    decision: str
    approved_by: str
    artifact_digest: str
    granted_attempts: int
    run_status: str
    note: str = ""
    #: Spec §3.2: what this record actually claims. A typed name and a verified signature are
    #: different answers, and only one of them may unblock a critical commit.
    verified: bool = False
    approval_scheme: str = ""

    def describe(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "decision": self.decision,
            "approved_by": self.approved_by,
            "artifact_digest": self.artifact_digest,
            "granted_attempts": self.granted_attempts,
            "run_status": self.run_status,
            "note": self.note,
            "verified": self.verified,
            "approval_scheme": self.approval_scheme,
        }


@dataclass
class ApprovalService:
    """Records the owner's answer. It never executes or commits anything itself."""

    store: EventStore
    fsm: StateMachineService
    #: Extra attempts granted by a RETRY. A retry after exhausted retries is pointless
    #: without new budget, so a RETRY always grants at least one.
    default_granted_attempts: int = 1
    actor: str = "owner"
    #: Spec §3.2. Filled in `__post_init__` from the workspace when not injected, so a caller
    #: that forgets it cannot silently disable verification: the enforcement state comes from
    #: the enrolment that exists, not from the argument that was passed.
    identity: OwnerRegistry | None = None

    def __post_init__(self) -> None:
        if self.identity is None:
            self.identity = OwnerRegistry.for_store(self.store)

    # -------------------------------------------------------------------- decide
    def approve(
        self,
        *,
        run_id: str,
        step_id: str,
        decision: ApprovalDecision | str,
        approved_by: str,
        note: str = "",
        artifact_digest: str = "",
        granted_attempts: int = 0,
        signature: str = "",
    ) -> ApprovalResult:
        """Record an owner decision for one escalated step, verified when policy requires it."""
        chosen = ApprovalDecision(decision)
        if not approved_by.strip():
            raise ApprovalError(
                "an approval must name who gave it (Spec §27: the audit has to answer 'who "
                "approved')"
            )

        run = self.store.get_run(run_id)
        if run is None:
            raise ApprovalError(f"unknown run {run_id}", run_id=run_id)
        step = self.store.get_step(step_id)
        if step is None:
            raise ApprovalError(f"unknown step {step_id}", step_id=step_id)
        if str(step["run_id"]) != run_id:
            raise ApprovalError(
                f"step {step_id} belongs to run {step['run_id']}, not {run_id}",
                step_run_id=str(step["run_id"]),
            )

        state = StepState(step["state"])
        if state is not StepState.ESCALATED:
            raise NotEscalated(
                f"step {step_id} is {state.value}, not ESCALATED; an approval may only "
                "answer an escalation",
                step_id=step_id,
                state=state.value,
            )

        if chosen is ApprovalDecision.PROCEED:
            if not artifact_digest:
                latest = self._latest_artifact_digest(step_id)
                if not latest:
                    raise ApprovalError(
                        f"step {step_id} has no artifact to approve; there is nothing to "
                        "accept"
                    )
                artifact_digest = latest
            else:
                known = self.store.get_artifact(artifact_digest)
                if known is None or str(known["step_id"]) != step_id:
                    raise ApprovalError(
                        f"artifact {artifact_digest[:12]} does not belong to step {step_id}; "
                        "refusing to authorise work the owner was not shown"
                    )
        else:
            artifact_digest = ""

        if chosen is ApprovalDecision.RETRY:
            granted_attempts = max(granted_attempts, self.default_granted_attempts)

        subject_digest = str(step["spec_digest"])
        # Verified BEFORE anything is recorded, so a refused decision leaves no trace and a
        # recorded one is never a half-authorised state.
        outcome = self._authorise(
            run_id=run_id,
            step_id=step_id,
            chosen=chosen,
            approved_by=approved_by.strip(),
            risk=self._risk_of(run, step),
            artifact_digest=artifact_digest,
            signature=signature,
            attempt=int(step.get("attempt") or 0),
        )
        approval = Approval.issue(
            run_id=run_id,
            step_id=step_id,
            execution_id=str(step["execution_id"]),
            decision=chosen,
            approved_by=outcome.owner_id,
            note=note.strip(),
            artifact_digest=artifact_digest,
            subject_digest=subject_digest,
            granted_attempts=granted_attempts,
            verified=outcome.verified,
            approval_scheme=outcome.scheme,
            key_fingerprint=outcome.fingerprint,
        )
        self.store.record_approval(
            {**approval.to_payload(), "approval_digest": approval.digest()}
        )

        # The decision is recorded as a fact in the same event stream as everything else,
        # so the timeline shows the human next to the machine that asked the question.
        self.store.append(
            aggregate_id=f"step:{step_id}",
            execution_id=str(step["execution_id"]),
            event_type="ApprovalRecorded",
            actor=self.actor,
            payload={
                "approval_id": approval.approval_id,
                "decision": chosen.value,
                "approved_by": approval.approved_by,
                "artifact_digest": artifact_digest,
                # §3.2: the audit must be able to tell a verified decision from a typed name
                # without consulting the registry, which may have changed since.
                "verified": outcome.verified,
                "approval_scheme": outcome.scheme,
                "key_fingerprint": outcome.fingerprint,
                "note": approval.note,
            },
        )
        self.store.append_timeline(
            run_id=run_id,
            execution_id=str(step["execution_id"]),
            step_id=step_id,
            event_id=approval.approval_id,
            event_type="ApprovalRecorded",
            actor=self.actor,
            summary=(
                f"owner {approval.approved_by} decided {chosen.value} on "
                f"{step['node_id']}"
                + (f": {approval.note}" if approval.note else "")
            ),
            severity="warning" if chosen is ApprovalDecision.REJECT else "info",
        )

        return ApprovalResult(
            approval_id=approval.approval_id,
            run_id=run_id,
            step_id=step_id,
            decision=chosen.value,
            approved_by=approval.approved_by,
            artifact_digest=artifact_digest,
            granted_attempts=granted_attempts,
            run_status=str(self.store.get_run(run_id)["status"]),
            note=approval.note,
            verified=outcome.verified,
            approval_scheme=outcome.scheme,
        )

    def _risk_of(self, run: dict[str, Any], step: dict[str, Any]) -> RiskLevel:
        """The risk level of the frozen spec this step belongs to.

        Taken from the spec registry, not from the run: `runs` has no risk column, and even if
        it did, the risk of a change is a property of the contract that authorised it. Reading
        a missing key with a default here would quietly downgrade a CRITICAL step to NORMAL
        and skip the signature check entirely.
        """
        for digest in (str(step.get("spec_digest") or ""), str(run.get("spec_digest") or "")):
            if not digest:
                continue
            spec = self.store.get_spec(digest)
            if spec is not None:
                return RiskLevel(str(spec["risk_level"]))
        raise ApprovalError(
            f"no registered spec for step {step.get('step_id')!r}, so the risk of this "
            "decision cannot be established. Refusing rather than assuming it is low."
        )

    def _authorise(
        self,
        *,
        run_id: str,
        step_id: str,
        chosen: ApprovalDecision,
        approved_by: str,
        risk: RiskLevel,
        artifact_digest: str,
        signature: str,
        attempt: int,
    ) -> ApprovalOutcome:
        """Verify the decision, or record an unverified one when nothing is enrolled.

        The policy lives in the registry, not here: this method only supplies the facts the
        decision is about. `identity` is never None after `__post_init__`.
        """
        assert self.identity is not None, "the registry is established in __post_init__"
        return self.identity.authorise_step_decision(
            run_id=run_id,
            step_id=step_id,
            decision=chosen.value,
            approved_by=approved_by,
            risk=risk,
            artifact_digest=artifact_digest,
            signature=signature,
            attempt=attempt,
        )

    # ------------------------------------------------------------------- lookup
    def pending_escalations(self, run_id: str = "") -> list[dict[str, object]]:
        """Every escalated step with no answer yet, for the operator console."""
        pending: list[dict[str, object]] = []
        runs = [self.store.get_run(run_id)] if run_id else self.store.list_runs()
        for run in runs:
            if run is None:
                continue
            for step in self.store.list_steps(str(run["run_id"])):
                if str(step["state"]) != StepState.ESCALATED.value:
                    continue
                approval = self.store.latest_approval(str(step["step_id"]))
                if approval is not None:
                    continue
                artifact = self._latest_artifact(str(step["step_id"]))
                pending.append(
                    {
                        "run_id": str(run["run_id"]),
                        "run_status": str(run["status"]),
                        "step_id": str(step["step_id"]),
                        "node_id": str(step["node_id"]),
                        "attempt": int(step["attempt"]),
                        "last_failure": str(step["last_failure"])[:400],
                        "artifact_digest": str(artifact["artifact_digest"]) if artifact else "",
                        "risk_level": self._risk_level(run),
                        "waiting_since": str(step["updated_at"]),
                    }
                )
        return pending

    def apply_decisions(self, run_id: str) -> dict[str, str]:
        """Move escalated steps according to the latest approval. Called by `resume`.

        Returns `{step_id: action}` describing what was applied, so the caller can report
        exactly which human decisions took effect.
        """
        applied: dict[str, str] = {}
        for step in self.store.list_steps(run_id):
            if str(step["state"]) != StepState.ESCALATED.value:
                continue
            step_id = str(step["step_id"])
            approval = self.store.latest_approval(step_id)
            if approval is None:
                continue
            chosen = ApprovalDecision(str(approval["decision"]))
            if chosen is ApprovalDecision.REJECT:
                self.fsm.transition_step(
                    step_id=step_id,
                    event_type="StepRejected",
                    actor=self.actor,
                    payload={
                        "reason": "owner rejected the work",
                        "approved_by": str(approval["approved_by"]),
                        "note": str(approval["note"]),
                    },
                )
                applied[step_id] = "rejected"
                continue
            if chosen is ApprovalDecision.RETRY:
                granted = int(approval["granted_attempts"]) or self.default_granted_attempts
                # ESCALATED means no worker holds this step, so the whole lease is cleared —
                # both columns, so the row cannot end up holding an id with no expiry.
                self.store.update_step_state(
                    step_id,
                    state=StepState.ESCALATED.value,
                    granted_attempts=granted,
                    lease_id="",
                    lease_expires_at="",
                )
                self.fsm.transition_step(
                    step_id=step_id,
                    event_type="StepRecovered",
                    actor=self.actor,
                    payload={
                        "reason": f"owner granted {granted} further attempt(s)",
                        "approved_by": str(approval["approved_by"]),
                    },
                )
                applied[step_id] = f"retry(+{granted})"
                continue
            # PROCEED stays ESCALATED here: the commit is the orchestrator's job, because
            # only it holds the worktree and can re-verify the tree digest.
            applied[step_id] = "proceed"
        return applied

    # ------------------------------------------------------------------ helpers
    def _latest_artifact(self, step_id: str) -> dict[str, object] | None:
        artifacts = self.store.artifacts_for_step(step_id)
        return artifacts[-1] if artifacts else None

    def _latest_artifact_digest(self, step_id: str) -> str:
        artifact = self._latest_artifact(step_id)
        return str(artifact["artifact_digest"]) if artifact else ""

    def _risk_level(self, run: dict[str, object]) -> str:
        spec = self.store.get_spec(str(run.get("spec_digest", "")))
        return str(spec["risk_level"]) if spec else ""


def summarise_approvals(store: EventStore, run_id: str) -> list[dict[str, object]]:
    """The approval trail for one run, oldest first."""
    return [
        {
            "approval_id": row["approval_id"],
            "step_id": row["step_id"],
            "decision": row["decision"],
            "approved_by": row["approved_by"],
            "artifact_digest": str(row["artifact_digest"])[:12],
            "note": row["note"],
            "created_at": row["created_at"],
        }
        for row in store.approvals_for_run(run_id)
    ]
