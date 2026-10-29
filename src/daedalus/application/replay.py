"""Rollback, replay and spec-change classification (Spec §12, §13).

The vocabulary here is deliberately narrow, because rollback is where systems usually
start lying. Daedalus rolls back **code and task state**, and nothing else:

* rollback never deletes history — it appends `RunRolledBack`, stops the affected
  execution, marks steps CANCELLED/SUPERSEDED and produces a **new execution id**;
* replay is a *new run* from a target commit, with `parent_execution_id` pointing at the
  run it continues;
* external side effects (a third-party API call, an email that was sent) are explicitly
  **not** rolled back. They are covered by idempotency, compensation or a human, and the
  system says so rather than implying otherwise.

`ChangeKind` implements Spec §13.1's three change classes. Classification decides how much
of a plan is still valid, which in turn decides what a replay may reuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from daedalus.application.fsm_service import StateMachineService
from daedalus.application.gatekeeper.pipeline import GateOutcome
from daedalus.domain.canonical import digest_of
from daedalus.domain.fsm import RunState, StepState
from daedalus.domain.ids import new_id, utc_now
from daedalus.domain.spec import SpecBundle
from daedalus.errors import IllegalTransition, NotRollbackable, RollbackError
from daedalus.infrastructure.store.event_store import EventStore


__all__ = [
    "ChangeKind",
    "ChangeReport",
    "NotRollbackable",
    "ReplayService",
    "RollbackError",
    "RollbackResult",
    "classify_spec_change",
    "run_repo_path",
]


class ChangeKind(str, Enum):
    """Spec §13.1."""

    GOAL_BREAKING = "A_goal_breaking"
    PLAN_LOCAL = "B_plan_local"
    BOUNDARY_ONLY = "C_boundary_only"
    IDENTICAL = "identical"


@dataclass(frozen=True, slots=True)
class ChangeReport:
    """What actually changed between two frozen specs, and what that invalidates."""

    kind: ChangeKind
    changed_node_ids: tuple[str, ...] = ()
    affected_node_ids: tuple[str, ...] = ()
    added_nodes: tuple[str, ...] = ()
    removed_nodes: tuple[str, ...] = ()
    changed_paths: tuple[str, ...] = ()
    network_changed: bool = False
    dependency_changed: bool = False
    toolchain_relevant: bool = False
    reason: str = ""

    @property
    def requires_new_execution(self) -> bool:
        return self.kind in {ChangeKind.GOAL_BREAKING, ChangeKind.PLAN_LOCAL}

    @property
    def reusable_nodes(self) -> tuple[str, ...]:
        """Nodes whose work the change does not invalidate."""
        affected = set(self.affected_node_ids)
        return tuple(
            node_id
            for node_id in sorted(set(self.changed_node_ids) | set(self.added_nodes))
            if node_id not in affected
        )

    def describe(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "changed_nodes": list(self.changed_node_ids),
            "affected_nodes": list(self.affected_node_ids),
            "added_nodes": list(self.added_nodes),
            "removed_nodes": list(self.removed_nodes),
            "changed_paths": list(self.changed_paths),
            "network_changed": self.network_changed,
            "dependency_changed": self.dependency_changed,
            "reason": self.reason,
        }


def classify_spec_change(previous: SpecBundle, current: SpecBundle) -> ChangeReport:
    """Classify a spec change per Spec §13.1 and compute the affected closure.

    Class A (goal-breaking) archives the old run and starts a fresh execution. Class B
    (plan-local) invalidates a node and everything downstream of it — the *downstream
    closure*, not just the edited node. Class C (boundary-only) invalidates by affected
    paths, tools, network and dependencies rather than by graph shape.
    """
    if previous.digest() == current.digest():
        return ChangeReport(kind=ChangeKind.IDENTICAL, reason="the spec digest is unchanged")

    changed_paths: set[str] = set()
    network_changed = False
    dependency_changed = False

    # --- Class A: the goal itself moved, or the invariants changed -----------------
    goal_changed = (
        previous.goal.objective != current.goal.objective
        or previous.goal.invariants != current.goal.invariants
        or previous.goal.goal_id != current.goal.goal_id
    )
    criteria_before = {c.criterion_id: c.to_dict() for c in previous.goal.acceptance_criteria}
    criteria_after = {c.criterion_id: c.to_dict() for c in current.goal.acceptance_criteria}
    criteria_changed = criteria_before != criteria_after

    if goal_changed or criteria_changed:
        return ChangeReport(
            kind=ChangeKind.GOAL_BREAKING,
            changed_node_ids=tuple(sorted(node.node_id for node in current.plan.nodes)),
            affected_node_ids=tuple(sorted(node.node_id for node in current.plan.nodes)),
            reason=(
                "the goal, its invariants or its acceptance criteria changed, so no prior "
                "step result is evidence about the new goal"
            ),
        )

    # --- Class B: the plan graph or a node's definition changed --------------------
    before_nodes = {node.node_id: node for node in previous.plan.nodes}
    after_nodes = {node.node_id: node for node in current.plan.nodes}
    added = tuple(sorted(set(after_nodes) - set(before_nodes)))
    removed = tuple(sorted(set(before_nodes) - set(after_nodes)))
    edited = tuple(
        sorted(
            node_id
            for node_id in set(before_nodes) & set(after_nodes)
            if before_nodes[node_id].to_dict() != after_nodes[node_id].to_dict()
        )
    )
    if added or removed or edited:
        affected = current.plan.downstream_closure((*edited, *added))
        return ChangeReport(
            kind=ChangeKind.PLAN_LOCAL,
            changed_node_ids=tuple(sorted((*edited, *added))),
            affected_node_ids=tuple(sorted(affected)),
            added_nodes=added,
            removed_nodes=removed,
            reason=(
                "the plan changed locally; the changed nodes and their downstream closure "
                "must be invalidated and selectively replayed"
            ),
        )

    # --- Class C: only the boundary moved -----------------------------------------
    boundary = previous.boundary
    updated = current.boundary
    changed_paths.update(set(updated.fs_whitelist) ^ set(boundary.fs_whitelist))
    changed_paths.update(set(updated.fs_denylist) ^ set(boundary.fs_denylist))
    network_changed = (
        boundary.network_policy != updated.network_policy
        or boundary.allowed_domains != updated.allowed_domains
    )
    dependency_changed = (
        boundary.dependency_manifest != updated.dependency_manifest
        or boundary.lock_file != updated.lock_file
    )
    resource_changed = (
        boundary.max_tokens_per_step != updated.max_tokens_per_step
        or boundary.max_runtime_sec != updated.max_runtime_sec
        or boundary.memory_mb != updated.memory_mb
        or boundary.cpu_limit != updated.cpu_limit
    )

    # A boundary change invalidates every node whose artifacts or tools it touches.
    affected: set[str] = set()
    for node in current.plan.nodes:
        touches_changed_path = any(
            _references(changed_paths, artifact) for artifact in node.expected_artifacts
        )
        tools_changed = set(node.allowed_tools) ^ set(
            next(
                (n.allowed_tools for n in previous.plan.nodes if n.node_id == node.node_id),
                (),
            )
        )
        if touches_changed_path or tools_changed or network_changed or dependency_changed:
            affected.add(node.node_id)

    if affected or changed_paths or network_changed or dependency_changed or resource_changed:
        return ChangeReport(
            kind=ChangeKind.BOUNDARY_ONLY,
            changed_node_ids=tuple(sorted(affected)),
            affected_node_ids=tuple(sorted(affected)),
            changed_paths=tuple(sorted(changed_paths)),
            network_changed=network_changed,
            dependency_changed=dependency_changed,
            reason=(
                "only the boundary changed; invalidation is by affected paths, tools, "
                "network and dependencies"
            ),
        )

    return ChangeReport(
        kind=ChangeKind.PLAN_LOCAL,
        changed_node_ids=tuple(sorted(after_nodes)),
        affected_node_ids=tuple(sorted(after_nodes)),
        reason="the specs differ in a way not covered by the goal, plan or boundary fields",
    )


def _references(patterns: set[str], path: str) -> bool:
    from daedalus.domain.pathglob import matches_any

    return matches_any(sorted(patterns), path) if patterns else False


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RollbackResult:
    run_id: str
    execution_id: str
    status: str
    target_commit: str
    stopped_steps: tuple[str, ...] = ()
    superseded_steps: tuple[str, ...] = ()
    new_execution_id: str = ""
    reason: str = ""

    def describe(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "execution_id": self.execution_id,
            "status": self.status,
            "target_commit": self.target_commit,
            "stopped_steps": list(self.stopped_steps),
            "superseded_steps": list(self.superseded_steps),
            "new_execution_id": self.new_execution_id,
            "reason": self.reason,
            "rolled_back": ["git commits", "worktrees", "dag state", "event state"],
            "not_rolled_back": [
                "third-party api calls",
                "external database writes",
                "sent email",
                "uploaded files",
                "created cloud resources",
            ],
        }


@dataclass
class ReplayService:
    """Owns rollback and the replay hand-off. It never executes a DAG itself."""

    store: EventStore
    fsm: StateMachineService
    actor: str = "replay"

    # ------------------------------------------------------------------ rollback
    def rollback(
        self,
        run_id: str,
        *,
        reason: str,
        to_commit: str = "",
        correlation_id: str = "",
    ) -> RollbackResult:
        """Stop a run without deleting anything, and mint the execution id for the replay.

        A rollback of a run whose steps are already committed does **not** revert the target
        branch. Undoing a landed change is a new change (a revert commit) reviewed by the
        same gate — pretending to un-commit history is exactly what Spec §12.1 forbids.
        """
        run = self.store.get_run(run_id)
        if run is None:
            raise RollbackError(f"unknown run {run_id}", run_id=run_id)
        if str(run["status"]) == RunState.CANCELLED.value and not to_commit:
            raise NotRollbackable(
                f"run {run_id} is already cancelled",
                run_id=run_id,
            )

        execution_id = str(run["execution_id"])
        steps = [
            row
            for row in self.store.list_steps(run_id)
            if str(row["execution_id"]) == execution_id
        ]
        stopped: list[str] = []
        superseded: list[str] = []

        for row in steps:
            step_id = str(row["step_id"])
            state = StepState(row["state"])
            if state is StepState.COMMITTED:
                # Committed work is history. It is superseded for the purposes of the new
                # execution, never rewritten.
                try:
                    self.fsm.transition_step(
                        step_id=step_id,
                        event_type="StepSuperseded",
                        actor=self.actor,
                        payload={"reason": reason, "rollback": True},
                        correlation_id=correlation_id,
                    )
                except IllegalTransition:
                    pass
                superseded.append(step_id)
                continue
            if state in {StepState.CANCELLED, StepState.SUPERSEDED, StepState.STALE}:
                continue
            try:
                self.fsm.transition_step(
                    step_id=step_id,
                    event_type="StepCancelled",
                    actor=self.actor,
                    payload={"reason": reason, "rollback": True},
                    correlation_id=correlation_id,
                )
                stopped.append(step_id)
            except IllegalTransition as error:
                raise RollbackError(
                    f"cannot stop step {step_id} in state {state.value}: {error.message}",
                    step_id=step_id,
                    state=state.value,
                ) from error

        try:
            self.fsm.transition_run(
                run_id=run_id,
                execution_id=execution_id,
                event_type="RunRolledBack",
                actor=self.actor,
                payload={
                    "reason": reason,
                    "target_commit": to_commit or str(run["base_commit"]),
                    "stopped_steps": stopped,
                    "superseded_steps": superseded,
                    "replay_execution_id": new_id("exec"),
                },
                correlation_id=correlation_id,
            )
        except IllegalTransition as error:
            raise NotRollbackable(
                f"run {run_id} is {run['status']} and cannot be rolled back: {error.message}",
                run_id=run_id,
                status=str(run["status"]),
            ) from error

        self.fsm.audit_note(
            run_id=run_id,
            execution_id=execution_id,
            actor=self.actor,
            message=(
                f"rollback requested: {reason}. Code and task state only; external side "
                "effects are not reverted."
            ),
            severity="warning",
            payload={"stopped": stopped, "superseded": superseded},
            correlation_id=correlation_id,
        )

        return RollbackResult(
            run_id=run_id,
            execution_id=execution_id,
            status=RunState.CANCELLED.value,
            target_commit=to_commit or str(run["base_commit"]),
            stopped_steps=tuple(stopped),
            superseded_steps=tuple(superseded),
            new_execution_id=new_id("exec"),
            reason=reason,
        )


def fingerprint_gate(gate: GateOutcome) -> str:
    """Digest of a gate outcome, used as the provenance recorded on a cache hit."""
    return digest_of(
        {
            "step_id": gate.step_id,
            "artifact_digest": gate.artifact_digest,
            "decision": gate.decision.value,
            "tier1": [c.to_payload() for c in gate.tier1.checks],
            "tier2": gate.tier2.decision.value if gate.tier2 else None,
        }
    )


def now_iso() -> str:
    return utc_now()


def run_repo_path(store: EventStore, run_id: str) -> str:
    """Recover where a run happened from the event log, not from the projection.

    The event log is the authoritative record, so a replay can find its repository without
    depending on a schema column that a future migration might rename.
    """
    run = store.get_run(run_id)
    if run is None:
        raise RollbackError(f"unknown run {run_id}", run_id=run_id)
    for event in store.events_for_execution(str(run["execution_id"])):
        if event.event_type == "RunStarted":
            return str(event.payload.get("repo_path", ""))
    return ""


# ---------------------------------------------------------------------------
# Selective replay (Spec §13.1 B)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SelectiveReplay:
    """Which nodes a replay must re-execute, and which may be reused.

    `stale_nodes` is the changed set closed over its downstream dependencies: editing one node
    invalidates everything that consumes its artifacts. `reusable_nodes` is everything else,
    and those may be satisfied from the artifact cache because their node-level subject digest
    is unchanged (Spec §13.2).
    """

    change: ChangeReport
    stale_nodes: tuple[str, ...] = ()
    reusable_nodes: tuple[str, ...] = ()

    @property
    def is_fully_reusable(self) -> bool:
        return not self.stale_nodes

    @property
    def must_reexecute_everything(self) -> bool:
        return not self.reusable_nodes and bool(self.stale_nodes)

    def describe(self) -> dict[str, object]:
        return {
            "change": self.change.describe(),
            "stale_nodes": list(self.stale_nodes),
            "reusable_nodes": list(self.reusable_nodes),
            "fully_reusable": self.is_fully_reusable,
        }


def plan_selective_replay(previous: SpecBundle, current: SpecBundle) -> SelectiveReplay:
    """Decide what a replay of `current` may reuse from `previous` (Spec §13.1 B).

    A goal change invalidates everything, because no prior result is evidence about a new
    goal. A plan or boundary change invalidates the changed nodes and their downstream closure,
    and leaves the rest reusable.
    """
    report = classify_spec_change(previous, current)
    if report.kind in {ChangeKind.GOAL_BREAKING, ChangeKind.IDENTICAL}:
        all_nodes = tuple(node.node_id for node in current.plan.nodes)
        if report.kind is ChangeKind.IDENTICAL:
            return SelectiveReplay(change=report, stale_nodes=(), reusable_nodes=all_nodes)
        return SelectiveReplay(change=report, stale_nodes=all_nodes, reusable_nodes=())

    changed = set(report.changed_node_ids)
    if not changed:
        # The specs differ in a way the classifier did not attribute to a node (for example a
        # resource-limit change that reaches nothing). Fail closed: re-execute.
        all_nodes = tuple(node.node_id for node in current.plan.nodes)
        return SelectiveReplay(
            change=report,
            stale_nodes=all_nodes,
            reusable_nodes=(),
        )

    closure = current.plan.downstream_closure(tuple(sorted(changed)))
    stale = tuple(sorted(set(closure) & {node.node_id for node in current.plan.nodes}))
    reusable = tuple(
        sorted(node.node_id for node in current.plan.nodes if node.node_id not in set(stale))
    )
    return SelectiveReplay(change=report, stale_nodes=stale, reusable_nodes=reusable)
