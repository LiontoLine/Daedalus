"""Evidence-selected, budget-shared repair branches; only verified heads advance the trunk."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from daedalus.application.goal_audit import MAX_GOAL_STAGES, audit_delivery, goal_audit_view
from daedalus.application.repair_evidence import (
    affected_nodes,
    build_snapshot,
    select_candidates,
    validation_criteria,
)
from daedalus.application.worktree_pool import WorktreePool
from daedalus.domain.ids import new_id
from daedalus.domain.spec import PlanSpec, RetryPolicy, SpecBundle
from daedalus.infrastructure.git_sandbox import GitSandbox, _git


@dataclass
class _ScopedWorker:
    """An existing worker with a narrower write scope, not a new model/scoring role."""

    inner: Any
    paths: tuple[str, ...]

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    @property
    def budget(self):
        return self.inner.budget

    @budget.setter
    def budget(self, value):
        self.inner.budget = value

    def implement(self, sandbox, context):
        boundary = replace(context.bundle.boundary, fs_whitelist=self.paths)
        scoped = replace(context.bundle, boundary=boundary)
        return self.inner.implement(sandbox, replace(context, bundle=scoped))


def repair_bundle(bundle: SpecBundle, candidate: dict, snapshot: dict, stage: int,
                  feedback: str) -> SpecBundle:
    """Project exact frozen checks into a local subtask; never replace the root goal.

    The subtask may publish only to a private staging ref. The parent retains its
    complete original specification and audits it again before real delivery.
    """
    node = bundle.plan.node(candidate["node_id"])
    criteria = validation_criteria(bundle, candidate, snapshot)
    if not criteria or not node.expected_artifacts:
        raise ValueError("repair has no frozen validation or declared output scope")
    repair = replace(
        node,
        deps=(),
        revision_of=node.node_id,
        intent=node.intent + "\nRepair these frozen expectations using the supplied evidence:\n"
        + feedback[:4000],
        retry_policy=RetryPolicy(max_attempts=1),
        extra={
            **node.extra,
            "acceptance_criteria": [item.to_dict() for item in criteria],
            "repair_root_spec_digest": bundle.digest(),
            "repair_base_commit": snapshot["commit"],
            "repair_allowed_paths": list(node.expected_artifacts),
        },
    )
    scoped = replace(
        bundle,
        goal=replace(bundle.goal, acceptance_criteria=criteria),
        plan=PlanSpec(
            plan_id=f"{bundle.plan.plan_id}-repair-{stage}",
            goal_id=bundle.goal.goal_id,
            nodes=(repair,),
        ),
        spec_version=bundle.spec_version + stage - 1,
        parent_spec_digest=bundle.digest(),
    )
    scoped.validate()
    return scoped


def _node_evidence(owner) -> dict[str, list[dict]]:
    evidence = {}
    for event in owner.store.events_for(f"run:{owner.run_id}"):
        if event.event_type != "TrunkNodeValidated":
            continue
        for node_id in event.payload.get("invalidated_nodes", ()):
            evidence.pop(node_id, None)
        evidence[event.payload["node_id"]] = event.payload.get("criteria", [])
    return evidence


def _remaining_ttl(owner) -> int:
    if owner.execution_ttl_sec <= 0:
        return 0
    row = owner.store.get_run(owner.run_id)
    started = datetime.fromisoformat(str(row["created_at"]).replace("Z", "+00:00"))
    remaining = owner.execution_ttl_sec - (datetime.now(UTC) - started).total_seconds()
    return max(1, math.floor(remaining))


def _branch_can_retry(child) -> bool:
    """Only explicit ordinary candidate failures permit another branch selection."""
    events = child.store.events_for_execution(child.execution_id)
    failures = [e for e in events if e.event_type == "StepExecutionFailed"]
    return bool(failures) and all(e.payload.get("branch_retryable") is True for e in failures)


def _failed_validation(child) -> list[dict]:
    return [
        row
        for step in child.store.list_steps(child.run_id)
        for gate in child.store.gate_results_for_step(str(step["step_id"]))
        if gate["tier"] == 1
        for check in json.loads(gate["evidence"]).get("checks", ())
        for row in check.get("evidence", {}).get("criteria", ())
    ]


def repair_branch_count(owner) -> int:
    return sum(event.event_type == "RepairBranchStarted"
               for event in owner.store.events_for_execution(owner.execution_id)
               if event.aggregate_id in {f"run:{owner.run_id}", f"goal:{owner.run_id}"})


def start_step_repair(owner, prepared) -> None:
    """An ordinary REVISE attempt is a real isolated branch, not a new allowance."""
    if not owner.goal_audit_enabled or prepared.attempt <= 1:
        return
    snapshot = build_snapshot(
        owner.bundle, prepared.base_commit, node_evidence=_node_evidence(owner),
    )
    for kind, payload in (
        ("GoalTrunkSnapshot", snapshot),
        ("RepairBranchStarted", {
            "branch_id": new_id("repair"), "phase": "step", "run_id": owner.run_id,
            "step_id": prepared.step_id, "node_id": prepared.node.node_id,
            "attempt": prepared.attempt, "stage": repair_branch_count(owner) + 2,
            "base_commit": prepared.base_commit, "spec_digest": owner.spec_digest,
            "root_spec_digest": owner.spec_digest,
            "worktree": str(prepared.sandbox.worktree_path),
            "affected_node_ids": list(affected_nodes(owner.bundle, prepared.node.node_id)),
            "selection_source": "recorded_step_failure",
        }),
    ):
        owner.store.append(
            aggregate_id=f"run:{owner.run_id}", execution_id=owner.execution_id,
            event_type=kind, actor=owner.actor, payload=payload,
            correlation_id=owner.correlation_id,
        )


def finish_step_repair(owner, outcome) -> None:
    if not owner.goal_audit_enabled or outcome.attempt <= 1:
        return
    if outcome.step_id in owner._approval_step_ids():
        return
    history = owner.store.events_for(f"run:{owner.run_id}")
    branch = next(
        (event.payload for event in reversed(history)
         if event.event_type == "RepairBranchStarted"
         and event.payload.get("step_id") == outcome.step_id
         and event.payload.get("attempt") == outcome.attempt),
        None,
    )
    if branch is None:
        raise ValueError("step repair completed without its branch admission")
    criteria = next(
        (event.payload.get("criteria", []) for event in reversed(history)
         if event.event_type in {"TrunkNodeValidated", "TrunkNodeFailed"}
         and event.payload.get("node_id") == outcome.node_id
         and event.payload.get("attempt") == outcome.attempt
         and event.payload.get("gate_result_id")),
        [],
    )
    validation = {"criteria": criteria}
    if outcome.committed:
        validation["snapshot"] = build_snapshot(
            owner.bundle, outcome.commit, criteria=criteria,
            node_evidence=_node_evidence(owner),
        )
    owner.store.append(
        aggregate_id=f"run:{owner.run_id}", execution_id=owner.execution_id,
        event_type="RepairBranchPromoted" if outcome.committed else "RepairBranchRejected",
        actor=owner.actor, correlation_id=owner.correlation_id,
        payload={**branch, "commit": outcome.commit,
                 "reasons": list(outcome.reasons) or [outcome.feedback],
                 "validation": validation},
    )
    if outcome.committed:
        owner.store.append(
            aggregate_id=f"run:{owner.run_id}", execution_id=owner.execution_id,
            event_type="GoalTrunkSnapshot", actor=owner.actor,
            payload=validation["snapshot"], correlation_id=owner.correlation_id,
        )


def ensure_goal_delivery(owner: Any, pool: Any, result: Any) -> bool:
    """Follow the repair flow without scoring calls or resetting any task allowance."""
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.service_lifecycle import stop_requested

    def record(kind: str, payload: dict) -> None:
        owner.store.append(
            aggregate_id=f"goal:{owner.run_id}", execution_id=owner.execution_id,
            event_type=kind, actor="goal-auditor", payload=payload,
            correlation_id=owner.correlation_id,
        )

    def stop(reason: str) -> bool:
        record("GoalAuditEscalated", {"reason": reason, "max_stages": MAX_GOAL_STAGES,
                                     "approval_required": False})
        result.status = "PARTIAL_FAILURE" if result.committed_count else "FAILED"
        result.notes.append(reason)
        result.tokens_used = owner.budget.run_used
        result.goal_audit = goal_audit_view(owner.store, owner.run_id)
        owner._close_run(result)
        return False

    if owner.store.events_for(f"goal:{owner.run_id}"):
        return stop(
            "goal audit already has history; interrupted branches require explicit recovery")
    if not any(e.event_type == "TrunkExpectationsFrozen"
               for e in owner.store.events_for(f"run:{owner.run_id}")):
        return stop(
            "frozen step expectations are unavailable; start an explicitly reviewed execution")

    reviewed = None
    snapshot = None
    excluded: set[str] = set()
    previous_failures: list[str] = []
    for stage in range(1, MAX_GOAL_STAGES + 1):
        if stop_requested():
            owner._park_for_service_stop(pool, result)
            return False
        if owner._execution_expired():
            return stop("original execution deadline reached before repair")
        if reviewed is None:
            record("GoalAuditStarted", {"stage": stage, "commit": pool.integration_head()})
            reviewed = audit_delivery(owner, pool, stage)
            record("GoalAuditCompleted", reviewed)
            snapshot = build_snapshot(
                owner.bundle, pool.integration_head(), criteria=reviewed.get("criteria", ()),
                semantic_criteria=reviewed.get("semantic_criteria", ()),
                node_evidence=_node_evidence(owner),
            )
            record("GoalTrunkSnapshot", snapshot)
            result.goal_audit = goal_audit_view(owner.store, owner.run_id)
        if reviewed["decision"] == "APPROVE":
            if pool.integration_head() != reviewed["commit"] or owner._execution_expired():
                return stop("audited commit changed or original execution expired before delivery")
            owner._goal_approved_commit = reviewed["commit"]
            return True
        if reviewed["decision"] != "REVISE":
            return stop("goal audit is inconclusive: " + "; ".join(reviewed["reasons"]))
        if stage == MAX_GOAL_STAGES or repair_branch_count(owner) >= MAX_GOAL_STAGES - 1:
            return stop("shared repair branch allowance exhausted; goal remains unmet")
        candidates = select_candidates(owner.bundle, snapshot, excluded=excluded)
        if not candidates:
            return stop("no new evidence-supported repair point remains on the current trunk")
        candidate = candidates[0]
        branch_id = new_id("repair")
        child_id = new_id("run")
        base_commit = pool.integration_head()
        feedback = "\n".join(reviewed.get("required_changes", ()))
        feedback += "\nFrozen failure evidence:\n" + json.dumps(
            [node for node in snapshot["nodes"] if node["node_id"] == candidate["node_id"]],
            ensure_ascii=False,
        )[:5000]
        if previous_failures:
            feedback += (
                "\nPrevious rejected branch evidence:\n" + "\n".join(previous_failures)[-2000:]
            )
        try:
            repair = repair_bundle(owner.bundle, candidate, snapshot, stage + 1, feedback)
            # Existing coder admission still reserves review headroom. This additional
            # reserve retains capacity for the final original-goal review as well.
            owner.budget.reset_step()
            final_reserve = (
                int(reviewed.get("review_reserve_tokens", 0))
                or 2048 + len(json.dumps(owner.bundle.goal.to_dict())) // 3 + 64
            ) if owner.tier2 is not None else 0
            owner.budget.check(estimated=final_reserve)
        except Exception as error:  # noqa: BLE001 - no branch was dispatched
            return stop(f"repair admission refused: {type(error).__name__}: {error}")
        branch = {
            "branch_id": branch_id, "run_id": child_id, "node_id": candidate["node_id"],
            "phase": "goal",
            "base_commit": base_commit, "affected_node_ids": list(candidate["affected_node_ids"]),
            "stage": stage + 1, "spec_digest": repair.digest(),
            "root_spec_digest": owner.spec_digest,
        }
        record("RepairBranchStarted", branch)
        record("GoalStageStarted", {**branch, "feedback": feedback})
        staging = WorktreePool(
            repo_path=owner.repo_path, run_root=owner.run_root, run_id=branch_id,
            base_commit=base_commit, target_branch=pool.run_branch, max_size=1,
        )
        previous_recorder = owner.budget.on_record
        child = None
        try:
            child = RunOrchestrator(
                store=owner.store, repo_path=owner.repo_path, run_root=owner.run_root,
                bundle=repair,
                worker=_ScopedWorker(
                    owner.worker,
                    tuple(owner.bundle.plan.node(candidate["node_id"]).expected_artifacts),
                ),
                tier2=owner.tier2, quota=replace(owner.quota, max_parallel_steps=1),
                target_branch=staging.run_branch, run_id=child_id,
                correlation_id=owner.correlation_id, parent_execution_id=owner.execution_id,
                manual_review_levels=("critical",), park_on_escalation=True,
                require_spec_approval=owner.require_spec_approval, identity=owner.identity,
                sandbox_image=owner.sandbox_image, retry_backoff_sec=0,
                execution_ttl_sec=_remaining_ttl(owner), goal_audit_enabled=False,
                goal_stage_parent=owner.run_id, goal_stage_number=stage + 1,
                stage_feedback=feedback,
            )
            child.budget = owner.budget
            child.budget.on_record = child._record_model_usage
            child.register_spec()
            child.assert_spec_may_run()
            with owner.budget.reservation(0, headroom=final_reserve):
                child.create_run(base_ref=staging.run_branch)
                child_result = child.run()
        except Exception as error:  # noqa: BLE001 - approvals/environment are not repair hypotheses
            record("RepairBranchRejected", {
                **branch, "reasons": [f"{type(error).__name__}: {error}"],
            })
            return stop(f"repair branch could not execute: {type(error).__name__}: {error}")
        finally:
            owner.budget.on_record = previous_recorder
        record("GoalStageFinished", {
            **branch, "status": child_result.status, "commit": child_result.promoted_commit,
        })
        if stop_requested():
            owner._park_for_service_stop(pool, result)
            return False
        if child_result.status != "COMPLETED" or not child_result.promoted_commit:
            reasons = [item.feedback for item in child_result.steps if item.feedback]
            failed_validation = _failed_validation(child)
            record("RepairBranchRejected", {
                **branch, "reasons": reasons, "validation": {"criteria": failed_validation},
            })
            if not _branch_can_retry(child):
                return stop(
                    f"repair branch {branch_id} has an inconclusive or non-retryable failure"
                )
            new_counterexample = any(
                row.get("ok") is False and not row.get("error_code")
                and row["criterion_id"] not in snapshot["failed_criteria"]
                for row in failed_validation
            )
            if not new_counterexample:
                excluded.add(candidate["node_id"])
            previous_failures.extend(reasons)
            continue
        commit = child_result.promoted_commit
        box = GitSandbox.create_from(
            repo_path=owner.repo_path, run_root=owner.run_root,
            name=new_id("repair-promotion"), base_commit=commit,
        )
        try:
            changes = tuple(_git(
                owner.repo_path, ["diff", "--name-only", base_commit, commit, "--"],
                check=True,
            ).stdout.splitlines())
            actual_affected = affected_nodes(owner.bundle, candidate["node_id"], changes)
            if not set(actual_affected) <= set(candidate["affected_node_ids"]):
                raise ValueError("actual changes exceed the frozen validation scope")
            if (
                pool.integration_head() != base_commit
                or owner._execution_expired() or stop_requested()
            ):
                raise ValueError("candidate trunk, original deadline or service state changed")
            if box.head() != commit or box.changed_files():
                raise ValueError("candidate changed after branch validation")
            validation = []
            for step in child.store.list_steps(child.run_id):
                for gate in child.store.gate_results_for_step(str(step["step_id"])):
                    if gate["tier"] == 1 and gate["decision"] == "PASS":
                        for check in json.loads(gate["evidence"])["checks"]:
                            if check["name"].endswith("acceptance_criteria"):
                                validation.extend(check["evidence"].get("criteria", []))
            if {row["criterion_id"] for row in validation} != {
                criterion.criterion_id for criterion in repair.goal.acceptance_criteria
            }:
                raise ValueError("branch validation receipts do not cover the frozen scope")
            promoted_snapshot = build_snapshot(
                owner.bundle, commit, criteria=validation,
                node_evidence=_node_evidence(owner),
                node_states={node_id: "STALE" for node_id in actual_affected},
            )
            # Only now may the isolated branch become the parent candidate trunk.
            pool.integrate(box)
        except Exception as error:  # noqa: BLE001 - never silently rebase an already-gated candidate
            record("RepairBranchRejected", {**branch, "commit": commit, "reasons": [str(error)]})
            return stop(f"repair promotion refused: {type(error).__name__}: {error}")
        finally:
            box.remove()
        record("RepairBranchPromoted", {
            **branch, "commit": commit,
            "validation": {"criteria": validation, "snapshot": promoted_snapshot},
        })
        record("GoalTrunkSnapshot", promoted_snapshot)
        result.commits.extend(child_result.commits)
        reviewed = None
        excluded.clear()
        previous_failures.clear()
    return stop("repair branch allowance exhausted without original-goal approval")
