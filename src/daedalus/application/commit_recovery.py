"""Reconcile durable Git effects with their receipts; never execute new work.

Only an already integrated, exact reviewed commit may acquire its missing SQL
receipt. Publication is closed only if the target ALREADY equals the journaled
approved commit. Recovery never creates a commit, rebases or advances any ref.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from daedalus.application.fsm_service import StateMachineService, _commit_step_transaction
from daedalus.application.replay import run_repo_path
from daedalus.domain.canonical import digest_of
from daedalus.domain.fsm import StepState
from daedalus.domain.spec import SpecBundle
from daedalus.infrastructure.git_sandbox import _git
from daedalus.infrastructure.repository_lock import repository_lock, RepositoryBusy
from daedalus.infrastructure.store.event_store import idempotency_key


@dataclass(frozen=True)
class CommitFinding:
    kind: str
    subject: str
    detail: str
    repairable: bool = False
    action: str = ""


def _require(condition: Any, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _git_text(repo: Path, *args: str) -> str:
    return _git(repo, list(args), check=True).stdout.strip()


def _check_step(store, run, step, repo, *, apply):
    sid, execution = str(step["step_id"]), str(run["execution_id"])
    events = store.events_for("step:" + sid)
    intent_event = next(
        (e for e in reversed(events) if e.event_type == "StepCommitRequested"), None
    )
    _require(
        intent_event,
        "no automatic commit intent; owner-approved/legacy commits require manual review",
    )
    intent = intent_event.payload
    required = (
        "artifact_digest",
        "gated_tree",
        "base_commit",
        "spec_digest",
        "gate_result_ids",
        "idempotency_key",
    )
    _require(
        all(intent.get(k) for k in required),
        "legacy or incomplete commit intent lacks review identity",
    )
    _require(
        run["status"] == "RUNNING", "run is not active; do not reopen a terminal or parked run"
    )
    _require(
        intent_event.execution_id == execution == step["execution_id"],
        "execution ownership mismatch",
    )
    _require(
        intent["spec_digest"] == run["spec_digest"] == step["spec_digest"], "frozen spec mismatch"
    )
    _require(intent["run_branch"] == run["branch"], "integration branch mismatch")
    key = idempotency_key(execution, sid, "commit")
    _require(
        intent["idempotency_key"] == key and store.idempotent_result(key) is None,
        "receipt conflicts with unfinished step",
    )
    artifact = store.get_artifact(intent["artifact_digest"])
    _require(
        artifact
        and artifact["step_id"] == sid
        and artifact["execution_id"] == execution
        and artifact["spec_digest"] == run["spec_digest"],
        "artifact does not belong to this frozen step",
    )
    document = json.loads(str(artifact["document"]))
    _require(
        document.get("extra", {}).get("gated_tree") == intent["gated_tree"],
        "artifact tree differs from commit intent",
    )
    rows = {r["gate_result_id"]: r for r in store.gate_results_for_step(sid)}
    latest = {
        int(row["tier"]): row["gate_result_id"]
        for row in store.gate_results_for_step(sid)
        if row["artifact_digest"] == artifact["artifact_digest"]
    }
    _require(
        [latest.get(1, ""), latest.get(2, "")] == intent["gate_result_ids"],
        "commit intent was superseded by newer gate evidence",
    )
    ids = intent["gate_result_ids"]
    _require(
        isinstance(ids, list) and len(ids) == 2 and ids[0] in rows, "deterministic gate is missing"
    )
    for tier, result_id in enumerate(ids, 1):
        if not result_id:
            continue
        gate = rows.get(result_id)
        _require(
            gate
            and int(gate["tier"]) == tier
            and gate["artifact_digest"] == artifact["artifact_digest"]
            and gate["execution_id"] == execution
            and gate["subject_digest"] == run["spec_digest"]
            and gate["decision"] == ("PASS" if tier == 1 else "APPROVE"),
            "gate identity or decision is invalid",
        )
    spec = store.get_spec(str(run["spec_digest"]))
    _require(spec, "frozen spec is missing")
    bundle = SpecBundle.from_dict(json.loads(spec["document"]))
    _require(
        ids[1] or bundle.goal.risk_level.value in {"low", "normal"},
        "risk requires a recorded semantic approval",
    )
    gate_ref = digest_of(
        {
            "step_id": sid,
            "execution_id": execution,
            "artifact_digest": artifact["artifact_digest"],
            "subject_digest": run["spec_digest"],
            "decision": "APPROVE",
        }
    )
    _require(gate_ref == intent.get("gate_result_digest"), "gate result digest differs from intent")
    worktree = Path(str(step["worktree_path"]))
    _require(worktree.is_dir(), "worktree evidence is missing")
    _require(
        _git_text(worktree, "rev-parse", "--path-format=absolute", "--git-common-dir")
        == _git_text(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"),
        "worktree belongs to a different repository",
    )
    _require(
        not _git_text(worktree, "status", "--porcelain"),
        "worktree changed after the reviewed commit",
    )
    commit = _git_text(worktree, "rev-parse", "HEAD")
    _require(
        commit != intent["base_commit"],
        "Git commit has not happened; retain evidence and replay explicitly",
    )
    _require(
        _git_text(worktree, "rev-parse", commit + "^{tree}") == intent["gated_tree"],
        "Git tree is not the reviewed tree",
    )
    _require(
        _git_text(worktree, "rev-parse", commit + "^") == intent["base_commit"],
        "commit base changed; rebases require manual review",
    )
    message = _git_text(worktree, "show", "-s", "--format=%B", commit)
    _require(
        f"execution: {execution}" in message.splitlines(),
        "Git commit provenance names another execution",
    )
    _require(
        _git_text(repo, "rev-parse", "refs/heads/" + str(run["branch"])) == commit,
        "commit is not the integration head; recovery will not modify Git refs",
    )
    action = ""
    if apply:
        _commit_step_transaction(
            StateMachineService(store),
            step_id=sid,
            execution_id=execution,
            actor="recovery",
            payload={
                "commit": commit,
                "artifact_digest": artifact["artifact_digest"],
                "node_id": step["node_id"],
                "attempt": step["attempt"],
                "run_branch": run["branch"],
                "rebased": 0,
                "owner_override": False,
                "recovered": True,
            },
            correlation_id=str(run["correlation_id"]),
            idempotency_key=key,
            idempotency_result={
                "commit": commit,
                "artifact_digest": artifact["artifact_digest"],
                "gate_result_digest": gate_ref,
                "rebased": 0,
            },
            run_id=str(run["run_id"]),
            node_id=str(step["node_id"]),
            commit=commit,
            dependents=tuple(
                (str(run["run_id"]) + ":" + n.node_id, commit)
                for n in bundle.plan.nodes
                if step["node_id"] in n.deps
            ),
            lease_id=str(intent.get("lease_id", "")),
        )
        action = "recorded the already integrated reviewed commit and its atomic receipt; no Git ref changed"
    return CommitFinding(
        "incomplete_commit",
        sid,
        "reviewed Git commit is integrated but its SQL receipt is missing",
        True,
        action,
    )


def _check_delivery(store, run, repo, *, apply):
    rid, execution = str(run["run_id"]), str(run["execution_id"])
    events = store.events_for("delivery:" + rid)
    intent = next((e for e in reversed(events) if e.event_type == "DeliveryRequested"), None)
    if intent is None or run["status"] != "RUNNING":
        return None
    value = intent.payload
    closed = {"RunCompleted", "RunFailed", "RunPartiallyFailed", "RunCancelled", "RunRolledBack"}
    _require(
        not any(e.event_type in closed for e in store.events_for_execution(execution)),
        "run projection conflicts with closing history; do not append another completion",
    )
    _require(
        intent.execution_id == execution and value["spec_digest"] == run["spec_digest"],
        "delivery subject mismatch",
    )
    steps = store.list_steps(rid)
    _require(
        steps and all(s["execution_id"] == execution and s["state"] == "COMMITTED" for s in steps),
        "delivery lacks committed steps",
    )
    _require(
        _git_text(repo, "rev-parse", "refs/heads/" + str(run["branch"])) == value["commit"],
        "integration head changed after delivery intent",
    )
    if value.get("goal_audit_enabled"):
        goals = [
            event for event in store.events_for("goal:" + rid)
            if event.event_type != "GoalTrunkSnapshot"
        ]
        _require(
            goals
            and goals[-1].event_type == "GoalAuditCompleted"
            and goals[-1].payload["decision"] == "APPROVE"
            and goals[-1].payload["commit"] == value["commit"] == value["goal_approved_commit"],
            "goal approval does not authorize this delivery",
        )
    from daedalus.application.independent_validation import IndependentValidationService
    started = next((e.payload for e in store.events_for_execution(execution)
                    if e.event_type == "RunStarted"), {})
    spec = store.get_spec(run["spec_digest"])
    requires_validation = spec["risk_level"] in started.get("independent_validation_levels", [])
    if requires_validation or value.get("independent_validation_required"):
        _require(bool(value.get("independent_validation_id")), "delivery has no independent attestation id")
        IndependentValidationService(store).recorded_delivery(rid, value["commit"],
            at=intent.timestamp, validation_id=value["independent_validation_id"])
    replayed = StateMachineService(store).rebuild_step_states()
    _require(
        all(replayed.get(str(step["step_id"])) is StepState.COMMITTED for step in steps),
        "step projections disagree with authoritative commit history",
    )
    target = _git_text(repo, "rev-parse", "refs/heads/" + value["target_branch"])
    _require(
        target == value["commit"],
        "target has not reached the approved commit; recovery will not publish it",
    )
    action = ""
    if apply:
        if not any(e.event_type == "DeliveryCompleted" and e.payload == value for e in events):
            store.append(
                aggregate_id="delivery:" + rid,
                execution_id=execution,
                event_type="DeliveryCompleted",
                actor="recovery",
                payload=value,
                correlation_id=str(run["correlation_id"]),
            )
        StateMachineService(store).transition_run(
            run_id=rid,
            execution_id=execution,
            event_type="RunCompleted",
            actor="recovery",
            payload={
                "status": "COMPLETED",
                "committed": len(steps),
                "steps": len(steps),
                "commits": [value["commit"]],
                "recovered": True,
            },
            correlation_id=str(run["correlation_id"]),
        )
        action = (
            "recorded completion of the already published approved commit; no publication repeated"
        )
    return CommitFinding(
        "incomplete_delivery",
        rid,
        "approved target commit exists but the run has no closing receipt",
        True,
        action,
    )


def reconcile_commits(store, *, apply=False):
    findings = []
    history_broken = bool(store.verify_sequences())
    replayed = StateMachineService(store).rebuild_step_states()
    for run in store.list_runs():
        candidates = [s for s in store.list_steps(str(run["run_id"])) if s["state"] == "COMMITTING"]
        deliveries = store.events_for("delivery:" + str(run["run_id"]))
        if not candidates and (not deliveries or run["status"] != "RUNNING"):
            continue
        try:
            repo = Path(run_repo_path(store, str(run["run_id"])))
            with repository_lock(repo):
                _require(not history_broken, "event sequence gap forbids reconciliation")
                for step in candidates:
                    try:
                        _require(
                            replayed.get(str(step["step_id"])) is StepState.COMMITTING,
                            "step projection disagrees with history",
                        )
                        findings.append(_check_step(store, run, step, repo, apply=apply))
                    except Exception as error:
                        findings.append(
                            CommitFinding("incomplete_commit", str(step["step_id"]), str(error))
                        )
                try:
                    delivery = _check_delivery(store, run, repo, apply=apply)
                    if delivery:
                        findings.append(delivery)
                except Exception as error:
                    findings.append(
                        CommitFinding("incomplete_delivery", str(run["run_id"]), str(error))
                    )
        except Exception as error:
            findings.append(
                CommitFinding(
                    "repository_active"
                    if isinstance(error, RepositoryBusy)
                    else "incomplete_commit",
                    str(run["run_id"]),
                    str(error),
                )
            )
    return findings
