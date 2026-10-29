"""Gatekeeper pipeline (Spec §9, §11.1).

Composition rules, in order:

1. Tier-1 always runs. It is deterministic and it is the only tier that can *earn* a
   commit.
2. Tier-2 runs only if Tier-1 passed — a failed deterministic check must never spend
   model budget (Spec §9.1).
3. Tier-2 may only make the outcome more conservative. `APPROVE` yields APPROVE;
   `REVISE`/`ESCALATE` are honoured; a fail-closed review escalates.
4. The outcome records the digest of the exact subject it validated. The commit step
   re-checks that digest, so a gate result can never be replayed onto other work.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from daedalus.application.gatekeeper.decision import GateDecision
from daedalus.application.gatekeeper.tier1 import Tier1Gate, Tier1Report
from daedalus.application.gatekeeper.tier2 import (
    SemanticReviewRequest,
    SemanticReviewResult,
    Tier2Gate,
)
from daedalus.application.review_context import dependency_context
from daedalus.domain.artifacts import Artifact
from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import new_id
from daedalus.infrastructure.git_sandbox import CommandResult, GitSandbox

__all__ = ["GateOutcome", "Gatekeeper"]


@dataclass(frozen=True, slots=True)
class GateOutcome:
    """The complete, auditable result of gating one artifact."""

    step_id: str
    execution_id: str
    artifact_digest: str
    subject_digest: str
    decision: GateDecision
    tier1: Tier1Report
    tier2: SemanticReviewResult | None = None
    tier1_result_id: str = ""
    tier2_result_id: str = ""
    skipped_tier2: bool = False

    @property
    def allows_commit(self) -> bool:
        return self.decision.allows_commit and not self.subject_digest_changed

    @property
    def subject_digest_changed(self) -> bool:
        return bool(self.tier2 and self.tier2.fail_closed and self.tier2.failure_reason == "subject_drift")

    @property
    def reasons(self) -> tuple[str, ...]:
        items = list(self.tier1.reasons)
        if self.tier2 is not None:
            items.extend(self.tier2.reasons)
        return tuple(items)

    @property
    def violations(self) -> tuple[str, ...]:
        return self.tier2.violations if self.tier2 else ()

    def to_payload(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "execution_id": self.execution_id,
            "artifact_digest": self.artifact_digest,
            "subject_digest": self.subject_digest,
            "decision": self.decision.value,
            "tier1": self.tier1.to_payload(),
            "tier2": (
                {
                    "decision": self.tier2.decision.value,
                    "reasons": list(self.tier2.reasons),
                    "violations": list(self.tier2.violations),
                    "confidence": self.tier2.confidence,
                    "fail_closed": self.tier2.fail_closed,
                }
                if self.tier2
                else None
            ),
            "skipped_tier2": self.skipped_tier2,
            "allows_commit": self.allows_commit,
        }


@dataclass
class Gatekeeper:
    tier1: Tier1Gate
    tier2: Tier2Gate | None = None
    risk_level: str = "normal"

    #: Risk levels that may not be auto-merged on Tier-2 approval alone (Spec §10).
    manual_review_levels: frozenset[str] = frozenset({"critical"})

    def gate(
        self,
        *,
        artifact: Artifact,
        sandbox: GitSandbox,
        goal_intent: str,
        node_intent: str,
        acceptance_criteria: tuple[str, ...],
        subject_digest: str,
        execution_log: str = "",
        elapsed_sec: float = 0.0,
        tokens_used: int = 0,
        acceptance_overrides: dict[str, Callable[[GitSandbox], CommandResult]] | None = None,
    ) -> GateOutcome:
        tier1_report = self.tier1.run(
            step_id=artifact.step_id,
            execution_id=artifact.execution_id,
            sandbox=sandbox,
            artifact=artifact,
            subject_digest=subject_digest,
            elapsed_sec=elapsed_sec,
            tokens_used=tokens_used,
            acceptance_overrides=acceptance_overrides,
        )
        tier1_result_id = new_id("gate")

        if tier1_report.decision is not GateDecision.PASS:
            return GateOutcome(
                step_id=artifact.step_id,
                execution_id=artifact.execution_id,
                artifact_digest=artifact.artifact_digest,
                subject_digest=subject_digest,
                decision=tier1_report.decision,
                tier1=tier1_report,
                tier1_result_id=tier1_result_id,
                skipped_tier2=True,
            )

        if self.tier2 is None:
            # A gate with no semantic reviewer is still a gate: Tier-1 passed, and for
            # LOW/NORMAL risk that is sufficient for automatic progression.
            return GateOutcome(
                step_id=artifact.step_id,
                execution_id=artifact.execution_id,
                artifact_digest=artifact.artifact_digest,
                subject_digest=subject_digest,
                decision=GateDecision.APPROVE if self.risk_level in {"low", "normal"} else GateDecision.ESCALATE,
                tier1=tier1_report,
                tier1_result_id=tier1_result_id,
                skipped_tier2=True,
            )

        try:
            reference_context = dependency_context(
                sandbox, artifact.changed_files, query=goal_intent + "\n" + sandbox.diff().patch
            )
        except Exception as error:  # noqa: BLE001 - fail closed before spending on missing evidence
            from daedalus.errors import DaedalusError
            code = error.code if isinstance(error, DaedalusError) else "review_context_unavailable"
            review = SemanticReviewResult(
                decision=GateDecision.ESCALATE, fail_closed=True, failure_reason=code,
                reasons=(f"review evidence unavailable before model dispatch: {code}",),
            )
            return GateOutcome(
                step_id=artifact.step_id, execution_id=artifact.execution_id,
                artifact_digest=artifact.artifact_digest, subject_digest=subject_digest,
                decision=GateDecision.ESCALATE, tier1=tier1_report, tier2=review,
                tier1_result_id=tier1_result_id, tier2_result_id=new_id("gate"),
                skipped_tier2=True,
            )
        behavior = [row["behavior_evidence"] for check in tier1_report.checks
                    for row in check.evidence.get("criteria", []) if row.get("behavior_evidence")]
        request = SemanticReviewRequest(
            step_id=artifact.step_id,
            execution_id=artifact.execution_id,
            artifact_digest=artifact.artifact_digest,
            goal_intent=goal_intent,
            node_intent=node_intent,
            acceptance_criteria=acceptance_criteria,
            changed_files=artifact.changed_files,
            patch=sandbox.diff().patch,
            execution_log=execution_log,
            tier1_summary="; ".join(
                f"{c.name}={'pass' if c.passed else 'FAIL'}" for c in tier1_report.checks
            ) + ("\nFrozen behavior execution evidence: " + json.dumps(behavior, sort_keys=True)
                 if behavior else ""),
            risk_level=self.risk_level,
            reference_context=reference_context,
        )
        review = self.tier2.review(request)
        tier2_result_id = new_id("gate")

        decision = self._combine(tier1_report, review)
        return GateOutcome(
            step_id=artifact.step_id,
            execution_id=artifact.execution_id,
            artifact_digest=artifact.artifact_digest,
            subject_digest=subject_digest,
            decision=decision,
            tier1=tier1_report,
            tier2=review,
            tier1_result_id=tier1_result_id,
            tier2_result_id=tier2_result_id,
            skipped_tier2=False,
        )

    def _combine(
        self,
        tier1_report: Tier1Report,
        review: SemanticReviewResult,
    ) -> GateDecision:
        """Tier-2 may only make the outcome more conservative."""
        if review.decision is GateDecision.APPROVE:
            if self.risk_level in self.manual_review_levels:
                return GateDecision.ESCALATE
            return GateDecision.APPROVE
        if review.decision is GateDecision.REVISE:
            return GateDecision.REVISE
        if review.decision is GateDecision.ESCALATE:
            return GateDecision.ESCALATE
        # Unreachable by construction, but fail-closed if it ever happens.
        return GateDecision.ESCALATE


def gate_result_digest(outcome: GateOutcome) -> str:
    """Stable identity of a gate result, used as the commit precondition."""
    return digest_of(
        {
            "step_id": outcome.step_id,
            "execution_id": outcome.execution_id,
            "artifact_digest": outcome.artifact_digest,
            "subject_digest": outcome.subject_digest,
            "decision": outcome.decision.value,
        }
    )
