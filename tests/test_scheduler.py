"""Scheduler, lease, retry and recovery (Spec §6, §16, §17).

The tests here are the recovery matrix from Spec §16 in executable form: a lost lease,
a crashed worker and a drifted spec must all resolve deterministically.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from daedalus.application.fsm_service import StateMachineService
from daedalus.application.scheduler import Quota, Scheduler, summarize_steps
from daedalus.domain.fsm import StepState
from daedalus.domain.spec import (
    AcceptanceCriterion,
    AssertionKind,
    BoundarySpec,
    GoalSpec,
    MetaSpec,
    NetworkPolicy,
    PlanNode,
    PlanSpec,
    RetryPolicy,
    RiskLevel,
    SpecBundle,
)
from daedalus.infrastructure.store import EventStore


def _bundle(nodes, *, attempts: int = 3) -> SpecBundle:
    return SpecBundle(
        goal=GoalSpec(
            goal_id="GOAL-1",
            objective="do the thing",
            acceptance_criteria=(
                AcceptanceCriterion(
                    criterion_id="AC-1", kind=AssertionKind.EXIT_CODE, command="true"
                ),
            ),
            risk_level=RiskLevel.NORMAL,
        ),
        plan=PlanSpec(
            plan_id="P-1",
            goal_id="GOAL-1",
            nodes=tuple(
                PlanNode(
                    node_id=node_id,
                    deps=deps,
                    expected_artifacts=(f"src/{node_id}.py",),
                    retry_policy=RetryPolicy(max_attempts=attempts),
                )
                for node_id, deps in nodes
            ),
        ),
        boundary=BoundarySpec(
            boundary_id="B-1",
            goal_id="GOAL-1",
            fs_whitelist=("src/**/*.py",),
            network_policy=NetworkPolicy.DENY,
        ),
        meta=MetaSpec.default(),
    )


def _scheduler(tmp_path, nodes, *, attempts: int = 3, quota: Quota | None = None):
    store = EventStore(tmp_path / "d.db")
    bundle = _bundle(nodes, attempts=attempts)
    # NOTE: `_bundle(...)` is called exactly once per test. Rebuilding an equivalent
    # bundle would produce the same content but the helper's own attempt at a third
    # call site would be a different object; the digest is content-derived so this is
    # safe, but tests below deliberately use `bundle.digest()` to stay honest.
    store.project_run(
        {
            "run_id": "run-1",
            "goal_id": "GOAL-1",
            "execution_id": "exec-1",
            "spec_digest": bundle.digest(),
            "status": "PENDING",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    )
    scheduler = Scheduler(
        store=store,
        fsm=StateMachineService(store),
        plan=bundle.plan,
        execution_id="exec-1",
        run_id="run-1",
        quota=quota or Quota(max_parallel_steps=2),
    )
    scheduler.declare_all_nodes(bundle.digest(), base_commit="base")
    return store, scheduler, bundle


def test_only_root_nodes_are_ready_initially(tmp_path) -> None:
    _store, scheduler, _bundle_ = _scheduler(
        tmp_path, [("a", ()), ("b", ("a",)), ("c", ("b",))]
    )
    ready = scheduler.ready_step_ids()
    assert ready == ["run-1:a"]
    reasons = {item.node_id: item.reason for item in scheduler.readiness()}
    assert "waiting on" in reasons["b"]


def test_dependent_becomes_ready_only_after_commit(tmp_path) -> None:
    store, scheduler, _bundle_ = _scheduler(tmp_path, [("a", ()), ("b", ("a",))])
    scheduler.acquire_lease("run-1:a", worker_id="w1")
    scheduler.fsm.transition_step(
        step_id="run-1:a", event_type="StepStarted", actor="w1", execution_id="exec-1"
    )
    scheduler.fsm.transition_step(
        step_id="run-1:a", event_type="StepGatekeeperEntered", actor="w1", execution_id="exec-1"
    )
    scheduler.fsm.transition_step(
        step_id="run-1:a",
        event_type="StepTier1Decided",
        actor="w1",
        outcome="pass",
        execution_id="exec-1",
    )
    scheduler.fsm.transition_step(
        step_id="run-1:a",
        event_type="StepTier2Decided",
        actor="w1",
        outcome="approve",
        execution_id="exec-1",
    )
    scheduler.fsm.transition_step(
        step_id="run-1:a", event_type="StepCommitRequested", actor="w1", execution_id="exec-1"
    )
    scheduler.fsm.transition_step(
        step_id="run-1:a", event_type="StepCommitted", actor="w1", execution_id="exec-1"
    )
    assert scheduler.ready_step_ids() == ["run-1:b"]


def test_a_live_lease_blocks_readiness(tmp_path) -> None:
    _store, scheduler, _bundle_ = _scheduler(tmp_path, [("a", ())])
    assert scheduler.ready_step_ids() == ["run-1:a"]
    scheduler.acquire_lease("run-1:a", worker_id="w1")
    readiness = scheduler.readiness()[0]
    assert not readiness.ready
    assert "active lease" in readiness.reason


def test_second_lease_on_a_live_step_is_refused(tmp_path) -> None:
    from daedalus.errors import LeaseError

    _store, scheduler, _bundle_ = _scheduler(tmp_path, [("a", ())])
    scheduler.acquire_lease("run-1:a", worker_id="w1")
    with pytest.raises(LeaseError):
        scheduler.acquire_lease("run-1:a", worker_id="w2")


def test_expired_lease_becomes_lost_then_ready(tmp_path) -> None:
    store, scheduler, _bundle_ = _scheduler(tmp_path, [("a", ())])
    scheduler.acquire_lease("run-1:a", worker_id="w1", ttl_sec=1)
    assert store.get_step("run-1:a")["state"] == StepState.LEASED.value

    # Force the lease into the past rather than sleeping in a test.
    past = (datetime.now(UTC) - timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
    store.connection.execute("UPDATE leases SET expire_at = ?", (past,))
    store.connection.execute("UPDATE steps SET lease_expires_at = ?", (past,))

    reaped = scheduler.reap_expired_leases()
    assert reaped == ["run-1:a"]
    assert store.get_step("run-1:a")["state"] == StepState.LOST.value

    # Recovery puts it back in the queue instead of leaving it stuck forever.
    scheduler.fsm.transition_step(
        step_id="run-1:a", event_type="StepRecovered", actor="scheduler", execution_id="exec-1"
    )
    assert store.get_step("run-1:a")["state"] == StepState.READY.value
    assert scheduler.ready_step_ids() == ["run-1:a"]


def test_retry_policy_escalates_after_the_budget(tmp_path) -> None:
    store, scheduler, _bundle_ = _scheduler(tmp_path, [("a", ())], attempts=2)
    for attempt in range(2):
        scheduler.acquire_lease("run-1:a", worker_id="w1")
        scheduler.fsm.transition_step(
            step_id="run-1:a", event_type="StepStarted", actor="w1", execution_id="exec-1"
        )
        scheduler.fsm.transition_step(
            step_id="run-1:a",
            event_type="StepExecutionFailed",
            actor="w1",
            outcome="revise",
            execution_id="exec-1",
        )
        assert scheduler.decide_after_failure("run-1:a") == (
            "retry" if attempt == 0 else "escalate"
        )
    decision = scheduler.refresh(_bundle_.digest())
    assert "run-1:a" in decision.to_escalate


def test_drift_marks_steps_stale_and_cancels_in_flight_work(tmp_path) -> None:
    store, scheduler, _bundle_ = _scheduler(tmp_path, [("a", ()), ("b", ())])
    scheduler.acquire_lease("run-1:a", worker_id="w1")  # in flight
    drifted = scheduler.mark_drifted_steps("0" * 64)
    assert set(drifted) == {"run-1:a", "run-1:b"}
    assert store.get_step("run-1:a")["state"] == StepState.CANCELLED.value
    assert store.get_step("run-1:b")["state"] == StepState.STALE.value


def test_concurrency_quota_withholds_extra_work(tmp_path) -> None:
    _store, scheduler, bundle = _scheduler(
        tmp_path, [("a", ()), ("b", ()), ("c", ())], quota=Quota(max_parallel_steps=1)
    )
    decision = scheduler.refresh(bundle.digest())
    assert len(decision.to_activate) == 1
    # The note names which of the three limits bound the decision, so an operator can tell a
    # parallelism ceiling from a CPU or memory one.
    assert any("quota is saturated" in note for note in decision.notes)
    assert any("max_parallel_steps" in note for note in decision.notes)


def test_a_cpu_quota_binds_before_parallelism(tmp_path) -> None:
    """Spec §6.4 lists CPU as a scheduling resource, not merely a boundary detail.

    Two steps that each ask for the whole machine must not both be admitted just because the
    parallelism ceiling has room.
    """
    store, scheduler, _bundle = _scheduler(
        tmp_path,
        [("a", ()), ("b", ()), ("c", ())],
        quota=Quota(max_parallel_steps=8, max_cpu=4.0, max_memory_mb=8192),
    )
    from daedalus.domain.spec import BoundarySpec, NetworkPolicy

    # Each step asks for 2 CPU and 4096 MB: the CPU ceiling fits exactly 2.
    scheduler.boundary = BoundarySpec(
        boundary_id="B",
        goal_id="G",
        fs_whitelist=("src/**",),
        network_policy=NetworkPolicy.DENY,
        cpu_limit=2.0,
        memory_mb=4096,
    )
    assert scheduler.admission_capacity() == 2
    assert scheduler.resource_headroom() == (2, 2, 8)

    # Fill both slots and confirm the next round admits nothing.
    for step_id in ("run-1:a", "run-1:b"):
        scheduler.acquire_lease(step_id, worker_id="w1")
    assert scheduler.in_flight_resources() == (4.0, 8192, 2)
    assert scheduler.admission_capacity() == 0
    decision = scheduler.refresh(_bundle.digest())
    assert decision.to_activate == ()
    assert any("cpu" in note for note in decision.notes), decision.notes
    store.close()


def test_failure_propagates_to_the_downstream_closure(tmp_path) -> None:
    store, scheduler, _bundle_ = _scheduler(
        tmp_path, [("a", ()), ("b", ("a",)), ("c", ("b",)), ("d", ())]
    )
    affected = scheduler.propagate_failure("a")
    assert set(affected) == {"run-1:b", "run-1:c"}
    assert store.get_step("run-1:b")["state"] == StepState.SUPERSEDED.value
    assert store.get_step("run-1:d")["state"] == StepState.PENDING.value
    counts = summarize_steps(store, "run-1")
    assert counts.get("SUPERSEDED") == 2


def test_backoff_is_bounded() -> None:
    _store, scheduler, _bundle_ = _scheduler_light()
    assert scheduler.backoff_seconds(1) == 1.0
    assert scheduler.backoff_seconds(5) == 16.0
    assert scheduler.backoff_seconds(50) == 30.0


def _scheduler_light():
    """A scheduler used only for pure functions (backoff), with no store access."""
    from daedalus.application.scheduler import Scheduler as S
    from daedalus.domain.spec import PlanSpec as PS

    plan = PS(plan_id="P", goal_id="G", nodes=(PlanNode(node_id="a", expected_artifacts=("x",)),))
    plan.validate()
    return None, S(store=None, fsm=None, plan=plan, execution_id="e", run_id="r"), None
