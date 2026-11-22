"""Evidence-selected, budget-shared repair branches; only verified heads advance the trunk."""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from itertools import chain
from typing import Any

from daedalus.application.goal_audit import MAX_GOAL_STAGES, audit_delivery, goal_audit_view
from daedalus.application.repair_evidence import (
    affected_nodes,
    build_snapshot,
    diagnose_criteria,
    select_candidates,
    settled_acceptance,
    validation_criteria,
)
from daedalus.application.requirement_evidence import behavior_check_results, model_behavior_evidence
from daedalus.application.worker_checks import observed_behavior_paths, safe_check_receipts
from daedalus.application.worktree_pool import WorktreePool
from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import new_id
from daedalus.domain.pathglob import normalize_path
from daedalus.domain.spec import BoundarySpec, PlanSpec, RetryPolicy, SpecBundle
from daedalus.errors import BoundaryViolation
from daedalus.infrastructure.git_sandbox import GitSandbox, _git
from daedalus.infrastructure.redact import redact_text
from daedalus.security.boundary import BoundaryGuard


def repair_boundary(bundle: SpecBundle, paths: tuple[str, ...]) -> BoundarySpec:
    """Narrow concrete repair outputs only after checking the frozen root authority.

    Declared artifacts are not authorization. In particular, treating an artifact
    glob as a literal during admission and as a whitelist pattern during execution
    could grant paths the original boundary never allowed.
    """
    if not paths or any(
        not isinstance(path, str) or not normalize_path(path)
        or "*" in path or "?" in path for path in paths
    ):
        raise BoundaryViolation("repair scope requires nonempty concrete artifact paths")
    paths = tuple(dict.fromkeys(normalize_path(path) for path in paths))
    decision = BoundaryGuard(bundle.boundary, bundle.meta).check_paths(paths)
    if not decision.allowed:
        raise BoundaryViolation(
            "repair scope exceeds the frozen boundary: " + "; ".join(decision.violations),
            violations=list(decision.violations),
        )
    return replace(bundle.boundary, fs_whitelist=paths)


def _trim_rejected_prompt(record: dict, limit: int) -> tuple[dict, int]:
    """Make room for current evidence without changing the archived rejection."""
    projected = {**record, "truncated": True}
    for field in ("patch", "observation"):
        excerpt = projected[field]
        projected[field] = ""
        size = len(json.dumps(projected, ensure_ascii=False))
        if size <= limit:
            room = limit - size
            excerpt = excerpt[:room]
            while (encoded := len(json.dumps(excerpt, ensure_ascii=False)) - 2) > room:
                excerpt = excerpt[:len(excerpt) // 2]
            projected[field] = excerpt
            return projected, size + encoded
    projected["reasons_omitted"] += len(projected["reasons"])
    projected["reasons"] = []
    return projected, len(json.dumps(projected, ensure_ascii=False))


@dataclass
class _ScopedWorker:
    """An existing worker with a narrower write scope, not a new model/scoring role."""

    inner: Any
    paths: tuple[str, ...]
    rejected_evidence: tuple[dict[str, Any], ...] = ()
    trunk_evidence: dict[str, Any] | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    @property
    def budget(self):
        return self.inner.budget

    @budget.setter
    def budget(self, value):
        self.inner.budget = value

    def implement(self, sandbox, context):
        boundary = repair_boundary(context.bundle, self.paths)
        scoped = replace(context.bundle, boundary=boundary)
        memory = []
        used = omitted = 0
        if self.trunk_evidence and self.trunk_evidence["commit"] == context.base_commit:
            size = len(json.dumps(self.trunk_evidence, ensure_ascii=False))
            if size <= 6000:
                memory.append(self.trunk_evidence)
                used = size
            else:
                omitted += 1
        # Prefer the exact fork point plus the latest rejection's receipts over its prose.
        for item in self.rejected_evidence:
            size = len(json.dumps(item, ensure_ascii=False))
            if used + size > 6000:
                item, size = _trim_rejected_prompt(item, 6000 - used)
            if used + size <= 6000:
                memory.append(item)
                used += size
            else:
                omitted += 1
        for item in reversed(context.repair_memory):
            size = len(json.dumps(item, ensure_ascii=False))
            if len(memory) < 8 and used + size <= 6000:
                memory.insert(0, item)
                used += size
            else:
                omitted += 1
        if omitted:
            memory.insert(0, {"older_records_omitted": omitted,
                             "note": "Omitted history is not resolved."})
        return self.inner.implement(sandbox, replace(
            context, bundle=scoped, repair_memory=tuple(memory),
        ))


def repair_bundle(bundle: SpecBundle, candidate: dict, snapshot: dict, stage: int,
                  feedback: str) -> SpecBundle:
    """Project exact frozen checks into a local subtask; never replace the root goal.

    The subtask may publish only to a private staging ref. The parent retains its
    complete original specification and audits it again before real delivery.
    """
    node = bundle.plan.node(candidate["node_id"])
    boundary = repair_boundary(bundle, tuple(node.expected_artifacts))
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
            "repair_allowed_paths": list(boundary.fs_whitelist),
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


def _trunk_path_memory(reviewed: dict, candidate: dict, base_commit: str) -> dict | None:
    """Project actual frozen path outcomes from the exact branch point."""
    if reviewed["commit"] != base_commit:
        return None
    paths = []
    for row in reviewed["criteria"]:
        evidence = row.get("behavior_evidence")
        if (row["criterion_id"] not in candidate["criterion_ids"] or row.get("ok") is not False
                or not evidence or not settled_acceptance(row)):
            continue
        receipt = evidence["receipt"]
        if (receipt.get("reviewed_commit") != base_commit or not receipt.get("reviewed_tree")
                or receipt.get("passed") is not False):
            continue
        public = model_behavior_evidence(evidence).get("behavior_paths")
        if public:
            paths.append({
                "criterion_id": row["criterion_id"],
                "receipt_sha256": receipt["sha256"],
                "reviewed_tree": receipt["reviewed_tree"],
                "paths": public,
            })
    if not paths:
        return None
    return {
        "evidence_kind": "trunk_behavior_failure",
        "commit": base_commit,
        "source_spec_digest": reviewed["spec_digest"],
        "historical_behavior_paths": paths,
    }


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


def _inner_path_failures(child, event, events, base_commit: str) -> list[dict]:
    if event is None:
        return []
    failure = event.payload
    if (failure.get("error_code") != "worker_validation_failed"
            or failure.get("spec_digest") != child.spec_digest
            or failure.get("commit") != base_commit or failure.get("base_commit") != base_commit):
        return []
    node = child.bundle.plan.nodes[0]  # A scoped goal repair has exactly one worker step.
    if failure.get("node_id") != node.node_id:
        return []
    worker_spec = next((
        observed.payload.get("worker_spec_digest") for observed in reversed(events)
        if observed.event_type == "WorkerEngineeringObserved" and observed.sequence < event.sequence
        and observed.payload.get("spec_digest") == child.spec_digest
        and observed.payload.get("node_id") == node.node_id
        and observed.payload.get("step_id") == failure.get("step_id")
        and observed.payload.get("attempt") == failure.get("attempt")
    ), None)
    if not worker_spec:
        return []
    definitions = {criterion.criterion_id: criterion for criterion in node.acceptance_criteria}
    result = []
    for check in safe_check_receipts(failure.get("worker_evidence", {})):
        criterion = definitions.get(check["criterion_id"])
        if (criterion is None or check["passed"]
                or check["execution_id"] != child.execution_id
                or check["step_id"] != failure.get("step_id")
                or check["node_id"] != node.node_id or check["attempt"] != failure.get("attempt")
                or check.get("base_commit") != base_commit):
            continue
        observed = observed_behavior_paths(
            check, criterion, spec_digest=worker_spec, commit=base_commit,
            tree=failure.get("candidate_tree", ""),
        )
        if observed:
            result.append(observed)
    return result


def _new_inner_path_failure(reviewed: dict, inner: list[dict], base_commit: str) -> bool:
    if not inner or reviewed["commit"] != base_commit:
        return False
    unmet = {(row["criterion_id"], path["path_id"]) for row in inner for path in row["paths"]
             if path["status"] == "UNMET"}
    for row in reviewed["criteria"]:
        evidence = row.get("behavior_evidence")
        if (not evidence or not settled_acceptance(row)
                or evidence["receipt"]["reviewed_commit"] != base_commit):
            continue
        if any((row["criterion_id"], path["path_id"]) in unmet and path["status"] == "MET"
               for path in model_behavior_evidence(evidence).get("behavior_paths", ())):
            return True
    return False


def _has_new_counterexample(repair: SpecBundle, snapshot: dict, criteria: list[dict]) -> bool:
    """Compare branch failures to the current trunk, including native subchecks."""
    known = set(snapshot["failed_criteria"])
    definitions = {criterion.criterion_id: criterion for criterion in repair.goal.acceptance_criteria}
    for row in criteria:
        if row.get("ok") is not False or not settled_acceptance(row):
            continue
        criterion_id = row["criterion_id"]
        if criterion_id not in known:
            return True
        if not row.get("behavior_evidence") or criterion_id not in definitions:
            continue
        now_failing = {
            check["test_name"] for check in behavior_check_results(definitions[criterion_id], [row])
            if check["status"] == "UNMET"
        }
        if not now_failing:
            continue
        before = chain(
            snapshot.get("integrated_expectations", ()),
            (expectation for node in snapshot["nodes"] for expectation in node["expectations"]),
        )
        if any(
            check["status"] == "MET" and check["test_name"] in now_failing
            for expectation in before
            if expectation["criterion_id"] == criterion_id and expectation["evidence"]["source"] == "final"
            for check in expectation.get("checks", ())
        ):
            return True
    return False


def rejected_child_evidence(child, branch: dict, criteria: list[dict],
                            reasons: list[str]) -> dict[str, Any]:
    """Project one rejected child into bounded, redacted next-worker context.

    Frozen validation receipts, native error kinds and the rejected patch/tree stay
    structured. No reviewer text becomes an executed fact or a current approval.
    Redaction precedes every excerpt, including metadata and patch content.
    """
    clipped = False

    def text(value: Any, limit: int = 128) -> str:
        nonlocal clipped
        value = redact_text(str(value))
        excerpt = value[:limit]
        while len(json.dumps(excerpt, ensure_ascii=False)) > limit + 2:
            excerpt = excerpt[:len(excerpt) // 2]
        clipped = clipped or excerpt != value
        return excerpt

    events = child.store.events_for_execution(child.execution_id)
    event = next((
        event for event in reversed(events) if event.event_type == "TrunkNodeFailed"
        and event.payload.get("node_id") == branch["node_id"]
        and event.payload.get("patch_digest")
    ), None)
    payload = event.payload if event else {}
    record = {
        "evidence_kind": "rejected_child_failure",
        "historical": True, "approved": False, "branch_status": "REJECTED",
        "source_run_id": text(child.run_id), "source_execution_id": text(child.execution_id),
        "source_spec_digest": text(branch["spec_digest"]),
        "root_spec_digest": text(branch["root_spec_digest"]),
        "source_event_id": text(event.event_id if event else ""),
        "branch_id": text(branch["branch_id"]), "node_id": text(branch["node_id"]),
        "base_commit": text(branch["base_commit"]), "commit": text(payload.get("commit", "")),
        "candidate_tree": text(payload.get("candidate_tree", "")),
        "patch_digest": text(payload.get("patch_digest", "")),
        "error_code": text(payload.get("error_code", "")),
        "attempt": text(payload.get("attempt", "")),
        "observation": text(
            str(payload.get("reason", "")) + "\n" + str(payload.get("detail", "")), 800,
        ),
        "patch": text(payload.get("patch", ""), 1200),
        "reasons": [text(reason, 240) for reason in reasons[:2]],
        "validation": [], "validation_rows_omitted": 0,
        "note": "Rejected, unapproved historical candidate; revalidate on the current tree. "
        "Original acceptance, scope and required reviews remain unchanged.",
    }
    paths = []
    if (gate_id := payload.get("behavior_gate_result_id")) and (
        payload.get("base_commit") == branch["base_commit"]
        and payload.get("spec_digest") == child.spec_digest
    ):
        gate = next((row for row in child.store.gate_results_for_step(payload["step_id"])
                     if row["gate_result_id"] == gate_id), {})
        definitions = {criterion.criterion_id: digest_of(criterion.to_dict())
                       for criterion in child.bundle.plan.nodes[0].acceptance_criteria}
        paths = child._historical_behavior_paths(record, gate, definitions)
    elif not criteria:
        paths = _inner_path_failures(child, event, events, branch["base_commit"])
    if paths:
        record["historical_behavior_paths"] = paths
    projected_ids = {path["criterion_id"] for path in paths}
    for row in sorted(criteria, key=lambda row: not (
        (row.get("ok") is False and settled_acceptance(row))
        or row.get("status") == "UNMET" or row.get("error_code")
    )):
        receipt = {
            key: text(row.get(key, ""), 128)
            for key in ("criterion_id", "kind", "error_code")
        }
        settled = settled_acceptance(row)
        receipt["ok"] = row["ok"] if settled else None
        receipt["executed"] = settled if "behavior_evidence" in row else (
            row.get("executed") if type(row.get("executed")) is bool else None)
        exit_code = row.get("exit_code")
        receipt["exit_code"] = exit_code if type(exit_code) is int and -(2**31) <= exit_code < 2**31 else None
        receipt["status"] = text(row.get("status", ""))
        if row["criterion_id"] not in projected_ids:
            receipt["output"] = text(row.get("output", row.get("evidence", "")), 240)
            if row.get("behavior_evidence"):
                public = model_behavior_evidence(row["behavior_evidence"])
                outcomes = public.get("behavior_paths") or public["requirements"]
                outcomes = sorted(outcomes, key=lambda item: item["status"] == "MET")
                receipt["behavior_outcomes"] = outcomes[:6]
                receipt["behavior_outcomes_omitted"] = max(0, len(outcomes) - 6)
        if len(record["validation"]) < 6 and (
            len(json.dumps(record, ensure_ascii=False))
            + len(json.dumps(receipt, ensure_ascii=False)) <= 4800
        ):
            record["validation"].append(receipt)
        else:
            record["validation_rows_omitted"] += 1
    record["reasons_omitted"] = max(0, len(reasons) - 2)
    # JSON escaping can grow beyond the independent text caps.
    while len(json.dumps(record, ensure_ascii=False)) > 5400:
        clipped = True
        field = max(("patch", "observation"), key=lambda key: len(record[key]))
        if record[field]:
            record[field] = record[field][:len(record[field]) // 2]
        elif record["validation"]:
            record["validation"].pop()
            record["validation_rows_omitted"] += 1
        elif record["reasons"]:
            record["reasons"].pop()
            record["reasons_omitted"] += 1
        elif record.get("historical_behavior_paths"):
            record["historical_behavior_paths"].pop()
        else:
            break
    record["truncated"] = bool(
        clipped or record["validation_rows_omitted"] or record["reasons_omitted"]
    )
    return record


def repair_branch_count(owner) -> int:
    return sum(event.event_type == "RepairBranchStarted"
               for event in owner.store.events_for_execution(owner.execution_id)
               if event.aggregate_id in {f"run:{owner.run_id}", f"goal:{owner.run_id}"})


def start_step_repair(owner, prepared) -> None:
    """An ordinary REVISE attempt is a real isolated branch, not a new allowance."""
    if not owner.goal_audit_enabled or prepared.attempt <= 1:
        return
    repair_boundary(owner.bundle, tuple(prepared.node.expected_artifacts))
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
        from daedalus.application.goal_audit import settled_goal_approval

        commit = pool.integration_head()
        if (owner.resume and result.all_committed and not owner._execution_expired()
                and settled_goal_approval(
                    owner.store, owner.run_id, owner.execution_id, owner.spec_digest, commit,
                )):
            owner._goal_approved_commit = commit
            result.goal_audit = goal_audit_view(owner.store, owner.run_id)
            result.notes.append("resumed delivery from the settled exact-commit goal approval")
            return True
        return stop(
            "goal audit already has history; interrupted branches require explicit recovery")
    if not any(e.event_type == "TrunkExpectationsFrozen"
               for e in owner.store.events_for(f"run:{owner.run_id}")):
        return stop(
            "frozen step expectations are unavailable; start an explicitly reviewed execution")

    reviewed = None
    snapshot = None
    excluded: set[str] = set()
    rejected_by_node: dict[str, dict[str, Any]] = {}
    for stage in range(1, MAX_GOAL_STAGES + 1):
        if stop_requested():
            owner._park_for_service_stop(pool, result)
            return False
        if owner._execution_expired():
            return stop("original execution deadline reached before repair")
        if reviewed is None:
            record("GoalAuditStarted", {"stage": stage, "commit": pool.integration_head()})
            started = time.monotonic()
            reviewed = audit_delivery(owner, pool, stage)
            reviewed["duration_ms"] = round((time.monotonic() - started) * 1000)
            record("GoalAuditCompleted", reviewed)
            snapshot = build_snapshot(
                owner.bundle, pool.integration_head(), criteria=reviewed.get("criteria", ()),
                semantic_criteria=reviewed.get("semantic_criteria", ()),
                node_evidence=_node_evidence(owner),
            )
            diagnosis = diagnose_criteria(owner.bundle, snapshot)
            record("GoalTrunkSnapshot", {**snapshot, "diagnosis": diagnosis})
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
        # Bound original failure text separately: it cannot crowd out the latest
        # rejected child's structured evidence in WorkerContext.repair_memory.
        feedback = redact_text("\n".join(reviewed.get("required_changes", ())))[:1800]
        feedback += "\nFrozen failure evidence:\n" + redact_text(json.dumps(
            [row for row in diagnosis["criteria"]
             if row["criterion_id"] in candidate["criterion_ids"]],
            ensure_ascii=False,
        ))[:2000]
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
        previous_rejection = rejected_by_node.get(candidate["node_id"])
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
                    (previous_rejection,) if previous_rejection else (),
                    trunk_evidence=_trunk_path_memory(reviewed, candidate, base_commit),
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
            rejected_evidence = rejected_child_evidence(
                child, branch, failed_validation, reasons,
            )
            record("RepairBranchRejected", {
                **branch, "reasons": reasons, "validation": {"criteria": failed_validation},
                "historical_child_evidence": rejected_evidence,
            })
            if not _branch_can_retry(child):
                return stop(
                    f"repair branch {branch_id} has an inconclusive or non-retryable failure"
                )
            if (not _has_new_counterexample(repair, snapshot, failed_validation)
                    and not _new_inner_path_failure(
                        reviewed, rejected_evidence.get("historical_behavior_paths", []), base_commit,
                    )):
                excluded.add(candidate["node_id"])
            rejected_by_node[candidate["node_id"]] = rejected_evidence
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
            scope = repair_boundary(
                owner.bundle, tuple(owner.bundle.plan.node(candidate["node_id"]).expected_artifacts),
            )
            decision = BoundaryGuard(scope, owner.bundle.meta).check_paths(changes)
            if not decision.allowed:
                raise BoundaryViolation(
                    "repair changes exceed the frozen boundary: "
                    + "; ".join(decision.violations),
                    violations=list(decision.violations),
                )
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
        record("GoalTrunkSnapshot", {
            **promoted_snapshot,
            "diagnosis": diagnose_criteria(owner.bundle, promoted_snapshot),
        })
        result.commits.extend(child_result.commits)
        reviewed = None
        excluded.clear()
        rejected_by_node.clear()
    return stop("repair branch allowance exhausted without original-goal approval")
