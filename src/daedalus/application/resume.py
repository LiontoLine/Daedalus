"""Resuming a parked run.

Kept separate from the orchestrator because resuming is an *operator action*: it
reconstructs the run from persisted state, re-attaches the kept worktrees, and hands
control back to the same orchestration loop with the owner's decisions applied.

The reconstruction is deliberately paranoid. A resume that silently starts a fresh run
while claiming to continue the old one would be worse than refusing to resume, so every
mismatch between the record and the disk is a hard failure with an actionable message.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from daedalus.application.fsm_service import StateMachineService
from daedalus.application.identity import OwnerRegistry
from daedalus.application.observability import configure_logging, get_logger, log_context
from daedalus.application.orchestrator import RunOrchestrator, RunResult
from daedalus.application.scheduler import Quota
from daedalus.application.worktree_pool import WorktreePool
from daedalus.domain.fsm import RunState
from daedalus.domain.spec import SpecBundle
from daedalus.errors import DaedalusError
from daedalus.infrastructure.store.event_store import EventStore
from daedalus.application.replay import run_repo_path

logger = get_logger("resume")


class ResumeError(DaedalusError):
    code = "resume_error"


@dataclass(frozen=True, slots=True)
class RunManifest:
    """Everything needed to reconstruct a run from persisted state alone."""

    run_id: str
    execution_id: str
    spec_digest: str
    base_commit: str
    status: str
    run_branch: str
    repo_path: str
    bundle: SpecBundle


def load_manifest(store: EventStore, run_id: str) -> RunManifest:
    run = store.get_run(run_id)
    if run is None:
        raise ResumeError(f"unknown run {run_id}", run_id=run_id)
    repo_path = run_repo_path(store, run_id)
    if not repo_path:
        raise ResumeError(
            f"run {run_id} has no recorded repository path; it cannot be resumed safely",
            run_id=run_id,
        )
    if not (Path(repo_path) / ".git").exists():
        raise ResumeError(
            f"the repository for run {run_id} is not at {repo_path} any more",
            run_id=run_id,
            repo_path=repo_path,
        )
    spec = store.get_spec(str(run["spec_digest"]))
    if spec is None:
        raise ResumeError(
            f"run {run_id} is pinned to spec {run['spec_digest']} which is not in the "
            "registry; refusing to resume against an unknown contract",
            run_id=run_id,
        )
    import json

    bundle = SpecBundle.from_dict(json.loads(str(spec["document"])))
    return RunManifest(
        run_id=run_id,
        execution_id=str(run["execution_id"]),
        spec_digest=str(run["spec_digest"]),
        base_commit=str(run["base_commit"]),
        status=str(run["status"]),
        run_branch=str(run["branch"]),
        repo_path=repo_path,
        bundle=bundle,
    )


def resume_run(
    *,
    store: EventStore,
    run_id: str,
    workspace: str,
    worker=None,
    tier2=None,
    max_parallel_steps: int = 1,
    park_on_escalation: bool = True,
    manual_review_levels: tuple[str, ...] = ("critical",),
    identity: OwnerRegistry | None = None,
) -> RunResult:
    """Continue a run parked in AWAITING_APPROVAL, applying recorded owner decisions."""
    configure_logging()
    manifest = load_manifest(store, run_id)
    if manifest.status not in {RunState.AWAITING_APPROVAL.value, RunState.RUNNING.value}:
        raise ResumeError(
            f"run {run_id} is {manifest.status}; only a parked or running run can be resumed",
            run_id=run_id,
            status=manifest.status,
        )

    from daedalus.application.service_lifecycle import assert_checkpoint_reviewed
    assert_checkpoint_reviewed(store, run_id, identity=identity)

    from daedalus.application.independent_validation import pending_validation
    validation_delivery = pending_validation(store,run_id) is not None
    started = next((event.payload for event in store.events_for_execution(manifest.execution_id)
                    if event.event_type == "RunStarted"), {})
    if (store.events_for(f"goal:{run_id}") or started.get("goal_stage_parent")) and not validation_delivery:
        raise ResumeError(
            "goal-audit stages require manual recovery or an explicitly reviewed new task; "
            "resume cannot reset their iteration budget", run_id=run_id,
        )

    if any(step["state"] == "COMMITTING" for step in store.list_steps(run_id)):
        raise ResumeError("unfinished commit requires reconciliation; inspect `daedalus recover`. If it cannot be reconciled, rollback/replay deliberately", run_id=run_id)
    from daedalus.infrastructure.git_sandbox import _git
    if not _git(Path(manifest.repo_path), ["rev-parse", "--verify", "refs/heads/" + manifest.run_branch], check=False).ok:
        raise ResumeError("the recorded integration branch is missing; refusing to recreate evidence", run_id=run_id)
    saved_quota = dict(started.get("quota", {}))
    saved_quota["max_parallel_steps"] = min(max_parallel_steps, int(saved_quota.get("max_parallel_steps", max_parallel_steps)))

    if worker is None:
        from daedalus.application.cache_worker import CacheMissWorker

        # Without a coder, a resume can still commit an *approved* artifact and can still
        # apply REJECT/RETRY. It cannot produce new work, and it says so by refusing.
        worker = CacheMissWorker()

    orchestrator = RunOrchestrator(
        store=store,
        repo_path=Path(manifest.repo_path),
        run_root=Path(workspace) / "worktrees" / manifest.run_id,
        bundle=manifest.bundle,
        worker=worker,
        tier2=tier2,
        quota=Quota(**saved_quota),
        run_id=manifest.run_id,
        execution_id=manifest.execution_id,
        correlation_id=str(store.get_run(run_id)["correlation_id"]),
        park_on_escalation=park_on_escalation,
        manual_review_levels=tuple(sorted(set(started.get("manual_review_levels", ())) | set(manual_review_levels))),
        execution_ttl_sec=int(started.get("execution_ttl_sec", 3600)),
        # Spec §3.2. Without this the resumed run has no registry, so `assert_spec_may_run`
        # and the commit gate would both treat the workspace as unenrolled and accept a
        # typed name — a resume would silently undo the enforcement that was configured
        # after the run parked.
        identity=identity,
        resume=True,
        target_branch=str(started.get("target_branch") or "main"),
        goal_audit_enabled=bool(started.get("goal_audit_enabled", False)),
        independent_validation_levels=tuple(started.get("independent_validation_levels", ())),
        goal_stage_parent=str(started.get("goal_stage_parent", "")),
        goal_stage_number=int(started.get("goal_stage_number", 1)),
    )
    # The pool already exists on disk from the parked run; reopen rather than create, so the
    # pending changes survive.
    pool = WorktreePool(
        repo_path=Path(manifest.repo_path),
        run_root=orchestrator.run_root,
        run_id=manifest.run_id,
        base_commit=manifest.base_commit,
        target_branch=orchestrator.target_branch,
        max_size=max(1, max_parallel_steps),
    )
    orchestrator.pool = pool

    with log_context(run_id=run_id, execution_id=manifest.execution_id, component="resume"):
        logger.info("resuming run from %s", manifest.status)
        result = orchestrator.complete_validated_delivery() if validation_delivery else orchestrator.run()
        logger.info("resume finished with status %s", result.status)
    return result
