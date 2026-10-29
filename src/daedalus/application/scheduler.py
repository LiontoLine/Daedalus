"""Deterministic scheduler (Spec §6, §16, §17).

Responsibilities, and nothing else:

* compute **ready nodes** from the DAG plus persisted state,
* admit them under a concurrency and resource quota,
* hand out **leases** with a bounded TTL,
* reap **expired leases** into LOST and decide retry vs escalate,
* enforce the **retry policy** so no failure can loop forever,
* propagate failure to the downstream closure.

The scheduler never executes a step. It decides *what may run*, and it does so from
persisted state alone — which is why a process restart can reconstruct the schedule
without replaying any conversation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from daedalus.application.fsm_service import StateMachineService
from daedalus.domain.fsm import StepState
from daedalus.domain.ids import utc_now
from daedalus.domain.lease import Lease
from daedalus.domain.spec import PlanSpec
from daedalus.errors import LeaseError
from daedalus.infrastructure.store.event_store import EventStore

#: States from which a step may become READY once its deps are satisfied.
ACTIVATABLE_STATES = frozenset({StepState.PENDING.value})
#: States that mean "done" for dependency purposes.
SATISFIED_STATES = frozenset({StepState.COMMITTED.value})
#: States that mean "this node will never satisfy its dependents".
DEAD_STATES = frozenset(
    {
        StepState.FAILED.value,
        StepState.TIMEOUT.value,
        StepState.CANCELLED.value,
        StepState.SUPERSEDED.value,
        StepState.ESCALATED.value,
    }
)
#: States a step may leave under the scheduler's control. PENDING is included because
#: activation is itself a scheduler action, not a separate lifecycle phase.
RETRYABLE_STATES = frozenset(
    {
        StepState.PENDING.value,
        StepState.REVISE.value,
        StepState.LOST.value,
        StepState.READY.value,
    }
)


@dataclass(frozen=True, slots=True)
class Quota:
    """Phase-1 quota surface (Spec §6.4 deliberately starts small)."""

    max_parallel_steps: int = 2
    max_cpu: float = 4.0
    max_memory_mb: int = 8192
    max_llm_requests: int = 200
    max_tokens_per_run: int = 200_000

    def describe(self) -> dict[str, float]:
        return {
            "max_parallel_steps": self.max_parallel_steps,
            "max_cpu": self.max_cpu,
            "max_memory_mb": self.max_memory_mb,
            "max_llm_requests": self.max_llm_requests,
            "max_tokens_per_run": self.max_tokens_per_run,
        }


@dataclass(frozen=True, slots=True)
class StepReadiness:
    step_id: str
    node_id: str
    ready: bool
    reason: str
    attempt: int = 0
    max_attempts: int = 3
    spec_digest: str = ""


@dataclass(frozen=True, slots=True)
class ScheduleDecision:
    """What the scheduler decided this round, for audit and for tests."""

    to_activate: tuple[str, ...] = ()
    to_retry: tuple[str, ...] = ()
    to_escalate: tuple[str, ...] = ()
    skipped: tuple[StepReadiness, ...] = ()
    reaped: tuple[str, ...] = ()
    deadlocked: bool = False
    notes: tuple[str, ...] = ()

    def describe(self) -> dict[str, object]:
        return {
            "to_activate": list(self.to_activate),
            "to_retry": list(self.to_retry),
            "to_escalate": list(self.to_escalate),
            "reaped": list(self.reaped),
            "deadlocked": self.deadlocked,
            "notes": list(self.notes),
        }


@dataclass
class Scheduler:
    store: EventStore
    fsm: StateMachineService
    plan: PlanSpec
    execution_id: str
    run_id: str
    quota: Quota = field(default_factory=Quota)
    #: The boundary each step runs under, so its CPU and memory request is known. Without this
    #: the scheduler enforced parallelism only, and two steps each asking for the whole machine
    #: were both admitted.
    boundary: Any = None
    default_lease_ttl_sec: int = 120
    actor: str = "scheduler"
    correlation_id: str = ""
    _notes: list[str] = field(default_factory=list, init=False)

    # ------------------------------------------------------------------ resources
    def step_resource_request(self) -> tuple[float, int]:
        """What one step asks for: (cpu, memory_mb).

        One SPEC-03 bounds a run, so every step in it requests the same envelope. That is a real
        simplification and it is recorded here rather than hidden: a plan whose nodes need very
        different resources cannot be expressed without per-node boundaries.
        """
        if self.boundary is None:
            return (0.0, 0)
        return (float(getattr(self.boundary, "cpu_limit", 0.0) or 0.0),
                int(getattr(self.boundary, "memory_mb", 0) or 0))

    def in_flight_resources(self) -> tuple[float, int, int]:
        """(cpu, memory_mb, count) currently held by LEASED or RUNNING steps."""
        cpu, memory = self.step_resource_request()
        active = self.store.steps_in_state(
            self.execution_id, [StepState.LEASED.value, StepState.RUNNING.value]
        )
        return cpu * len(active), memory * len(active), len(active)

    def resource_headroom(self) -> tuple[float, int, int]:
        """How many more steps fit: (by_cpu, by_memory, by_parallelism).

        A constraint with no known request is reported as the parallelism ceiling rather than as
        a fabricated resource figure, so the entry is never mistaken for a real measurement.
        """
        cpu, memory, count = self.in_flight_resources()
        request_cpu, request_memory = self.step_resource_request()

        def fits(used: float, request: float, limit: float) -> int:
            if request <= 0 or limit <= 0:
                return self.quota.max_parallel_steps
            return max(0, int((limit - used) // request))

        by_cpu = fits(cpu, request_cpu, self.quota.max_cpu)
        by_memory = fits(memory, request_memory, float(self.quota.max_memory_mb))
        by_parallel = max(0, self.quota.max_parallel_steps - count)
        return (by_cpu, by_memory, by_parallel)

    def admission_capacity(self) -> int:
        """Admit no more than the tightest of the three limits."""
        return min(self.resource_headroom())

    def binding_constraint(self) -> tuple[int, str]:
        """Which limit actually bound admission, as `(headroom, name)`.

        Only applicable constraints are considered: with no known resource request, CPU and
        memory are not candidates, because reporting "the cpu quota is saturated" when no CPU
        figure was ever known is a misleading explanation of a parallelism limit.
        """
        by_cpu, by_memory, by_parallel = self.resource_headroom()
        request_cpu, request_memory = self.step_resource_request()

        candidates: list[tuple[int, str]] = [(by_parallel, "max_parallel_steps")]
        if request_cpu > 0 and self.quota.max_cpu > 0:
            candidates.append((by_cpu, "cpu"))
        if request_memory > 0 and self.quota.max_memory_mb > 0:
            candidates.append((by_memory, "memory_mb"))
        # `min` is stable, so an exact tie reports the first candidate: parallelism first, then
        # cpu, then memory. Ties are reported with the full headroom next to them, so a reader is
        # never left guessing.
        return min(candidates, key=lambda item: item[0])

    # ------------------------------------------------------------------ readiness
    def readiness(self) -> list[StepReadiness]:
        """Evaluate every node against the Spec §6.2 ready-node rule."""
        steps = {row["node_id"]: row for row in self.store.list_steps(self.run_id)}
        results: list[StepReadiness] = []

        for node in self.plan.nodes:
            row = steps.get(node.node_id)
            if row is None:
                results.append(
                    StepReadiness(
                        step_id="",
                        node_id=node.node_id,
                        ready=False,
                        reason="not declared yet",
                    )
                )
                continue

            state = str(row["state"])
            if state in SATISFIED_STATES:
                results.append(
                    StepReadiness(
                        step_id=row["step_id"],
                        node_id=node.node_id,
                        ready=False,
                        reason="already committed",
                        attempt=int(row["attempt"]),
                        max_attempts=int(row["max_attempts"]),
                    )
                )
                continue

            if str(row["execution_id"]) != self.execution_id:
                results.append(
                    StepReadiness(
                        step_id=row["step_id"],
                        node_id=node.node_id,
                        ready=False,
                        reason=(
                            f"belongs to execution {row['execution_id']}, "
                            f"not the active execution {self.execution_id}"
                        ),
                        attempt=int(row["attempt"]),
                        max_attempts=int(row["max_attempts"]),
                    )
                )
                continue

            if state in DEAD_STATES:
                results.append(
                    StepReadiness(
                        step_id=row["step_id"],
                        node_id=node.node_id,
                        ready=False,
                        reason=f"terminal state {state}",
                        attempt=int(row["attempt"]),
                        max_attempts=int(row["max_attempts"]),
                    )
                )
                continue

            # active lease => not ready, no matter what else is true
            if row["lease_id"]:
                expires = row["lease_expires_at"]
                if expires and _is_future(str(expires)):
                    results.append(
                        StepReadiness(
                            step_id=row["step_id"],
                            node_id=node.node_id,
                            ready=False,
                            reason=f"active lease until {expires}",
                            attempt=int(row["attempt"]),
                            max_attempts=int(row["max_attempts"]),
                        )
                    )
                    continue

            unsatisfied: list[str] = []
            for dep in node.deps:
                dep_row = steps.get(dep)
                if dep_row is None or str(dep_row["state"]) not in SATISFIED_STATES:
                    unsatisfied.append(dep)
            if unsatisfied:
                results.append(
                    StepReadiness(
                        step_id=row["step_id"],
                        node_id=node.node_id,
                        ready=False,
                        reason=f"waiting on {sorted(unsatisfied)}",
                        attempt=int(row["attempt"]),
                        max_attempts=int(row["max_attempts"]),
                    )
                )
                continue

            if state not in RETRYABLE_STATES:
                results.append(
                    StepReadiness(
                        step_id=row["step_id"],
                        node_id=node.node_id,
                        ready=False,
                        reason=f"state {state} is not activatable",
                        attempt=int(row["attempt"]),
                        max_attempts=int(row["max_attempts"]),
                    )
                )
                continue

            results.append(
                StepReadiness(
                    step_id=row["step_id"],
                    node_id=node.node_id,
                    ready=True,
                    reason="deps satisfied, no active lease, within quota",
                    attempt=int(row["attempt"]),
                    max_attempts=int(row["max_attempts"]),
                    spec_digest=str(row["spec_digest"]),
                )
            )
        return results

    def ready_step_ids(self) -> list[str]:
        return [r.step_id for r in self.readiness() if r.ready]

    def refresh(self, spec_digest: str) -> ScheduleDecision:
        """One scheduling round: reap, activate, retry, escalate, detect deadlock.

        `spec_digest` is the digest of the spec this run is pinned to. Any step whose
        pinned digest differs is marked STALE instead of being run — the plan moved, so
        the old work is no longer evidence about the new goal (Spec §13.1).
        """
        self._notes.clear()
        reaped = self.reap_expired_leases()
        # Called for its effect: steps pinned to a different spec digest become STALE here,
        # which is what keeps a moved plan from being served old evidence (Spec §13.1).
        self.mark_drifted_steps(spec_digest)

        to_activate: list[str] = []
        to_retry: list[str] = []
        to_escalate: list[str] = []
        skipped: list[StepReadiness] = []

        for item in self.readiness():
            if item.ready:
                to_activate.append(item.step_id)
            elif item.step_id and "waiting on" not in item.reason:
                skipped.append(item)

        # Escalate steps that exhausted their retry policy before activating them.
        for row in self.store.list_steps(self.run_id):
            state = str(row["state"])
            if state not in RETRYABLE_STATES:
                continue
            if int(row["attempt"]) >= int(row["max_attempts"]):
                to_escalate.append(str(row["step_id"]))
                to_activate = [sid for sid in to_activate if sid != row["step_id"]]

        capacity = self.admission_capacity()
        admitted = to_activate[:capacity]
        if capacity < len(to_activate):
            by_cpu, by_memory, by_parallel = self.resource_headroom()
            _, binding = self.binding_constraint()
            request_cpu, request_memory = self.step_resource_request()
            for step_id in to_activate[capacity:]:
                self._notes.append(
                    f"step {step_id} withheld: the {binding} quota is saturated "
                    f"(headroom cpu={by_cpu} memory={by_memory} "
                    f"parallel={by_parallel}; per step cpu={request_cpu} "
                    f"memory={request_memory}mb)"
                )

        deadlocked = (
            not admitted
            and not to_escalate
            and not skipped
            and not self._all_satisfied_or_dead()
        )
        if deadlocked:
            self._notes.append(
                "no step is runnable and progress is impossible; the run is deadlocked"
            )

        return ScheduleDecision(
            to_activate=tuple(admitted),
            to_retry=tuple(to_retry),
            to_escalate=tuple(to_escalate),
            skipped=tuple(skipped),
            reaped=tuple(reaped),
            deadlocked=deadlocked,
            notes=tuple(self._notes),
        )

    # --------------------------------------------------------------------- lease
    def acquire_lease(
        self,
        step_id: str,
        *,
        worker_id: str,
        ttl_sec: int | None = None,
    ) -> Lease:
        """READY -> LEASED under a fresh lease, refusing if one is already live."""
        row = self.store.get_step(step_id)
        if row is None:
            raise LeaseError(f"unknown step {step_id}", step_id=step_id)

        state = StepState(row["state"])
        if state is StepState.LEASED and row["lease_id"]:
            if row["lease_expires_at"] and _is_future(str(row["lease_expires_at"])):
                raise LeaseError(
                    f"step {step_id} already holds a live lease until "
                    f"{row['lease_expires_at']}",
                    step_id=step_id,
                    lease_id=str(row["lease_id"]),
                )
            self.reap_expired_leases()

        if state is StepState.PENDING:
            self.fsm.transition_step(
                step_id=step_id,
                event_type="StepActivated",
                actor=self.actor,
                correlation_id=self.correlation_id,
            )
            state = StepState.READY

        if state is StepState.LOST:
            self.fsm.transition_step(
                step_id=step_id,
                event_type="StepRecovered",
                actor=self.actor,
                correlation_id=self.correlation_id,
            )
            state = StepState.READY

        if state is not StepState.READY and state is not StepState.REVISE:
            raise LeaseError(
                f"step {step_id} is {state.value} and cannot be leased", step_id=step_id
            )

        attempt = int(row["attempt"]) + 1
        lease = Lease.issue(
            step_id=step_id,
            execution_id=self.execution_id,
            worker_id=worker_id,
            ttl_sec=ttl_sec or self.default_lease_ttl_sec,
            attempt=attempt,
        )
        # `transition_step` owns its own transaction (event + state + timeline commit
        # together). The lease bookkeeping follows it; a lease row without a LEASED
        # step is inert, whereas a LEASED step without a lease row would be stuck.
        self.fsm.transition_step(
            step_id=step_id,
            event_type="StepLeaseAcquired",
            actor=worker_id,
            execution_id=self.execution_id,
            payload={**lease.to_payload(), "attempt": attempt},
            correlation_id=self.correlation_id,
        )
        self.store.record_lease(lease.to_payload())
        self.store.record_metric(
            name="lease_acquired",
            value=1,
            unit="count",
            run_id=self.run_id,
            step_id=step_id,
            labels={"worker": worker_id, "attempt": attempt},
        )
        return lease

    def release_lease(self, lease: Lease, outcome: str = "RELEASED") -> None:
        self.store.release_lease(lease.lease_id, outcome)

    def release_lease_by_id(self, lease_id: str, outcome: str = "RELEASED") -> None:
        self.store.release_lease(lease_id, outcome)

    def reap_expired_leases(self) -> list[str]:
        """Lease expiry -> LOST (Spec §6.3). Prevents a permanently stuck step."""
        reaped: list[str] = []
        for lease in self.store.expired_leases(utc_now()):
            step = self.store.get_step(str(lease["step_id"]))
            if step is None or str(step["execution_id"]) != self.execution_id:
                continue
            if StepState(step["state"]) is not StepState.LEASED:
                # The step already moved on; only the lease bookkeeping was stale.
                self.store.release_lease(str(lease["lease_id"]), "EXPIRED")
                continue
            self.fsm.transition_step(
                step_id=str(lease["step_id"]),
                event_type="StepLeaseExpired",
                actor=self.actor,
                payload={
                    "lease_id": str(lease["lease_id"]),
                    "worker_id": str(lease["worker_id"]),
                    "expire_at": str(lease["expire_at"]),
                    "reason": "lease expired without a heartbeat",
                },
                correlation_id=self.correlation_id,
            )
            self.store.release_lease(str(lease["lease_id"]), "EXPIRED")
            reaped.append(str(lease["step_id"]))
            self._notes.append(
                f"lease {lease['lease_id']} on {lease['step_id']} expired; step is LOST"
            )
        return reaped

    # -------------------------------------------------------------------- retry
    def decide_after_failure(self, step_id: str) -> str:
        """Return `retry`, `escalate` or `stop` according to the retry policy."""
        row = self.store.get_step(step_id)
        if row is None:
            return "stop"
        if int(row["attempt"]) < int(row["max_attempts"]):
            return "retry"
        return "escalate"

    def prepare_retry(self, step_id: str, *, reason: str) -> None:
        """Move a failed-within-budget step back to READY so it can be re-leased."""
        self.fsm.transition_step(
            step_id=step_id,
            event_type="StepRecovered",
            actor=self.actor,
            payload={"reason": reason},
            correlation_id=self.correlation_id,
        )

    # ------------------------------------------------------------------ drift
    def mark_drifted_steps(
        self, spec_digest: str, *, only_node_ids: tuple[str, ...] | None = None
    ) -> list[str]:
        """Invalidate steps whose pinned spec no longer matches.

        `only_node_ids` restricts this to a subgraph, which is what Spec §13.1 B needs: a
        selective replay must go STALE only on the changed nodes and their downstream closure,
        not on every node in the run.
        """
        drifted: list[str] = []
        scope = set(only_node_ids) if only_node_ids is not None else None
        for row in self.store.list_steps(self.run_id):
            if scope is not None and str(row["node_id"]) not in scope:
                continue
            if str(row["spec_digest"]) == spec_digest:
                continue
            state = StepState(row["state"])
            if state in {StepState.COMMITTED, StepState.SUPERSEDED, StepState.CANCELLED}:
                continue
            if state is StepState.STALE:
                continue
            if state in {StepState.LEASED, StepState.RUNNING}:
                # An in-flight attempt against a superseded spec is abandoned rather
                # than silently allowed to commit: CANCELLED is terminal and honest.
                self.fsm.transition_step(
                    step_id=str(row["step_id"]),
                    event_type="StepCancelled",
                    actor=self.actor,
                    payload={
                        "reason": (
                            f"spec digest drifted from {row['spec_digest'][:12]} to "
                            f"{spec_digest[:12]} while the step was in flight"
                        )
                    },
                    correlation_id=self.correlation_id,
                )
                drifted.append(str(row["step_id"]))
                continue
            self.fsm.transition_step(
                step_id=str(row["step_id"]),
                event_type="StepMarkedStale",
                actor=self.actor,
                # NOTE: the key is `drifted_to`, not `spec_digest`. A `spec_digest` key
                # in an event payload is a *precondition assertion* about the step's
                # pinned spec, so using it to record the new digest would make the
                # event self-contradictory and the transition would be refused.
                payload={"drifted_to": spec_digest, "reason": "spec digest drifted"},
                correlation_id=self.correlation_id,
            )
            drifted.append(str(row["step_id"]))
        return drifted

    def propagate_failure(self, failed_node_id: str) -> list[str]:
        """Mark the downstream closure as unreachable work (Spec §6.1)."""
        closure = self.plan.downstream_closure((failed_node_id,))
        affected: list[str] = []
        steps = {row["node_id"]: row for row in self.store.list_steps(self.run_id)}
        for node_id in closure:
            if node_id == failed_node_id:
                continue
            row = steps.get(node_id)
            if row is None:
                continue
            state = StepState(row["state"])
            if state in {StepState.COMMITTED, StepState.SUPERSEDED, StepState.CANCELLED}:
                continue
            try:
                self.fsm.transition_step(
                    step_id=str(row["step_id"]),
                    event_type="StepSuperseded",
                    actor=self.actor,
                    payload={
                        "reason": f"upstream node {failed_node_id} did not commit",
                        "execution_id": self.execution_id,
                    },
                    correlation_id=self.correlation_id,
                )
            except Exception:  # noqa: BLE001 - best effort; the log records what happened
                continue
            affected.append(str(row["step_id"]))
        return affected

    # ------------------------------------------------------------------ helpers
    def declare_all_nodes(self, spec_digest: str, *, base_commit: str = "") -> list[str]:
        """Declare one step per plan node, in topological order."""
        declared: list[str] = []
        existing = {row["node_id"] for row in self.store.list_steps(self.run_id)}
        for node_id in self.plan.topo_order():
            if node_id in existing:
                continue
            node = self.plan.node(node_id)
            step_id = f"{self.run_id}:{node_id}"
            self.fsm.declare_step(
                step_id=step_id,
                run_id=self.run_id,
                execution_id=self.execution_id,
                node_id=node_id,
                spec_digest=spec_digest,
                objective=node.objective,
                intent=node.intent or node.objective,
                deps=node.deps,
                expected_artifacts=node.expected_artifacts,
                allowed_tools=node.allowed_tools,
                max_attempts=node.retry_policy.max_attempts,
                timeout_sec=node.timeout_sec,
                base_commit=base_commit,
                actor=self.actor,
                correlation_id=self.correlation_id,
            )
            declared.append(step_id)
        return declared

    def _all_satisfied_or_dead(self) -> bool:
        for row in self.store.list_steps(self.run_id):
            if str(row["execution_id"]) != self.execution_id:
                continue
            state = str(row["state"])
            if state not in SATISFIED_STATES and state not in DEAD_STATES:
                return False
        return True

    def backoff_seconds(self, attempt: int, base: float = 1.0, factor: float = 2.0) -> float:
        """Exponential backoff, capped so a demo never sleeps for minutes."""
        return min(base * (factor ** max(0, attempt - 1)), 30.0)


def _is_future(iso_timestamp: str) -> bool:
    try:
        moment = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    return moment > datetime.now(UTC)


def new_lease_deadline(ttl_sec: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=ttl_sec)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def summarize_steps(store: EventStore, run_id: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in store.list_steps(run_id):
        state = str(row["state"])
        counts[state] = counts.get(state, 0) + 1
    return dict(sorted(counts.items()))


def decode_json_list(raw: str) -> list[str]:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return [str(item) for item in value] if isinstance(value, list) else []
