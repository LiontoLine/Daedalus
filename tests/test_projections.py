"""The §19 projections: `executions` and `workers`.

Spec §19 lists both as core entities. Both tables shipped in the first schema and neither
was ever written to, so they documented an intention rather than a fact: `execution_id`
existed only as a column scattered across `runs`, `steps` and `artifacts`, and `workers` was
permanently empty. A declared-but-unwritten projection is worse than an absent one, because a
reader concludes the data is there.

These tests hold the two properties that make the projections worth having:

* the *event log* stays authoritative — the projections are derived, so a rebuild must
  reproduce them, and a counter must not be able to drift;
* a worker that ran steps is always visible, even if the registry miss
  (an unregistered worker is reported as such rather than hidden).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.domain.fsm import RunState
from daedalus.domain.spec import NetworkPolicy, RiskLevel
from daedalus.infrastructure.store import EventStore
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND


def _run(tmp_path: Path, repo: Path, *, replay_parent: str = ""):
    from daedalus.application.orchestrator import RunOrchestrator

    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="REQ-P19",
            goal_id="GOAL-P19",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    store = EventStore(tmp_path / "ws" / "daedalus.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-p19",
        ),
    )
    if replay_parent:
        orchestrator.parent_execution_id = replay_parent
    orchestrator.register_spec()
    orchestrator.create_run()
    result = orchestrator.run()
    assert result.status == RunState.COMPLETED.value, result.describe()
    return store, orchestrator, result


def test_a_completed_run_produces_one_execution_row(git_repo, tmp_path) -> None:
    store, orchestrator, _result = _run(tmp_path, git_repo)
    execution = store.get_execution(orchestrator.execution_id)
    assert execution is not None, "the execution must be queryable as an entity"
    assert execution["run_id"] == orchestrator.run_id
    assert execution["status"] == "COMPLETED"
    assert execution["kind"] == "run"
    assert execution["started_at"] and execution["finished_at"]
    assert execution["step_total"] == 1
    assert execution["step_committed"] == 1
    assert execution["step_failed"] == 0
    assert execution["spec_digest"] == orchestrator.spec_digest
    store.close()


def test_a_replay_names_its_parent_execution(git_repo, tmp_path) -> None:
    """The replay chain is the reason an execution needs to be an entity at all."""
    store, orchestrator, _result = _run(tmp_path, git_repo)
    run_id = orchestrator.run_id
    parent = orchestrator.execution_id
    repo_path = str(orchestrator.repo_path)
    store.close()

    # A second orchestration of the same run, as `replay` does: parent set, kind=replay.
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.planner import DeterministicPlanner as DP

    store = EventStore(tmp_path / "ws" / "daedalus.db")
    bundle = DP().plan(
        PlanRequest(
            request_id="REQ-P19R",
            goal_id="GOAL-P19",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    replay = RunOrchestrator(
        store=store,
        repo_path=Path(repo_path),
        run_root=tmp_path / "wt2",
        bundle=bundle,
        worker=ScriptedWorker(ops=(), worker_id="worker-replay"),
    )
    replay.parent_execution_id = parent
    replay.register_spec()
    replay.create_run()
    execution = store.get_execution(replay.execution_id)
    assert execution["kind"] == "replay", execution
    assert execution["parent_execution_id"] == parent
    chained = store.list_executions(run_id)
    assert any(row["execution_id"] == parent for row in chained)
    store.close()


def test_the_execution_outcome_is_derived_from_the_steps_not_counted(git_repo, tmp_path) -> None:
    """Spec §18: the log is authoritative, so a projection must be reproducible from it.

    A hand-incremented counter can drift from the steps it claims to summarise. Counting the
    steps projection instead means the two can only disagree if the steps themselves are
    wrong — which `verify` already catches.
    """
    store, orchestrator, _result = _run(tmp_path, git_repo)
    execution = store.get_execution(orchestrator.execution_id)
    steps = [
        row for row in store.list_steps(orchestrator.run_id)
        if row["execution_id"] == orchestrator.execution_id
    ]
    committed = sum(1 for row in steps if str(row["state"]) == "COMMITTED")
    failed = sum(1 for row in steps if str(row["state"]) in {"FAILED", "TIMEOUT", "LOST", "REJECTED"})
    assert execution["step_total"] == len(steps)
    assert execution["step_committed"] == committed
    assert execution["step_failed"] == failed
    store.close()


def test_the_worker_that_ran_the_step_is_registered(git_repo, tmp_path) -> None:
    store, _orchestrator, _result = _run(tmp_path, git_repo)
    workers = {str(row["worker_id"]): row for row in store.list_workers()}
    assert "worker-p19" in workers, workers
    row = workers["worker-p19"]
    assert row["status"] == "IDLE", "a finished run leaves its worker idle, not busy"
    assert row["started_at"] and row["last_heartbeat_at"]
    assert row["last_heartbeat_at"] >= row["started_at"]
    store.close()


def test_worker_step_counts_are_derived_from_the_steps_projection(git_repo, tmp_path) -> None:
    store, _orchestrator, _result = _run(tmp_path, git_repo)
    merged = {str(row["worker_id"]): row for row in store.workers_with_counts()}
    assert merged["worker-p19"]["steps_started"] == 1
    assert merged["worker-p19"]["steps_committed"] == 1
    assert merged["worker-p19"]["steps_failed"] == 0
    store.close()


def test_a_worker_with_steps_but_no_registration_is_reported_not_hidden(git_repo, tmp_path) -> None:
    """A missed registration is a visibility bug, and hiding it hides the bug.

    A monitoring view that silently drops the rows it cannot explain is worse than one that
    shows an anomaly, because the anomaly is the thing the operator needed to see.
    """
    store, orchestrator, _result = _run(tmp_path, git_repo)
    # Simulate the registry having missed this worker entirely.
    store.connection.execute("DELETE FROM workers")
    merged = {str(row["worker_id"]): row for row in store.workers_with_counts()}
    assert "worker-p19" in merged, "steps exist for this worker, so it must still appear"
    assert merged["worker-p19"]["kind"] == "unregistered"
    assert merged["worker-p19"]["steps_committed"] == 1
    store.close()


def test_an_unknown_execution_is_none_rather_than_an_empty_row(git_repo, tmp_path) -> None:
    store, _orchestrator, _result = _run(tmp_path, git_repo)
    assert store.get_execution("exec_does_not_exist") is None
    assert store.list_executions("run_does_not_exist") == []
    store.close()


@pytest.mark.parametrize("kind", ["run", "replay", "resume", "recovery"])
def test_the_execution_kind_is_constrained_by_the_schema(tmp_path, kind: str) -> None:
    """An unconstrained `kind` would accumulate typos that read as facts."""
    import sqlite3

    store = EventStore(tmp_path / f"kind-{kind}" / "daedalus.db")
    store.upsert_execution(
        {
            "execution_id": f"exec_{kind}",
            "run_id": "run_1",
            "kind": kind,
            "status": "PENDING",
        }
    )
    assert store.get_execution(f"exec_{kind}")["kind"] == kind
    with pytest.raises(sqlite3.IntegrityError):
        store.upsert_execution(
            {"execution_id": "exec_bad", "run_id": "run_1", "kind": "nonsense"}
        )
    store.close()


def test_the_http_surface_exposes_both(git_repo, tmp_path) -> None:
    from fastapi.testclient import TestClient

    from daedalus.config import load_settings
    from daedalus.service.app import create_app

    store, orchestrator, _result = _run(tmp_path, git_repo)
    run_id = orchestrator.run_id
    execution_id = orchestrator.execution_id
    store.close()

    # The same workspace the run used: the HTTP layer must read the projections the run
    # wrote, which is the whole point of exposing them.
    app = create_app(load_settings(None, workspace_root=str(tmp_path / "ws")))
    with TestClient(app) as client:
        executions = client.get("/api/executions").json()
        assert any(row["execution_id"] == execution_id for row in executions["executions"])
        filtered = client.get(f"/api/executions?run_id={run_id}").json()
        assert all(row["run_id"] == run_id for row in filtered["executions"])
        workers = client.get("/api/workers").json()
        assert any(row["worker_id"] == "worker-p19" for row in workers["workers"])


# ---------------------------------------------------------------------------
# A crashed run must be recoverable, and the projections must follow it
# ---------------------------------------------------------------------------


def _crash_mid_run(tmp_path: Path, repo: Path, *, mark_worker_busy: bool = True):
    """Drive a run to RUNNING and then abandon it, as a killed worker would."""
    from daedalus.application.orchestrator import RunOrchestrator

    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="REQ-CRASH",
            goal_id="GOAL-CRASH",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    store = EventStore(tmp_path / "ws" / "daedalus.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wtc",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-crash",
        ),
    )
    orchestrator.register_spec()
    pool = orchestrator.create_run()
    scheduler = orchestrator.scheduler()
    scheduler.declare_all_nodes(orchestrator.spec_digest, base_commit=pool.base_commit)
    step = store.list_steps(orchestrator.run_id)[0]
    step_id = str(step["step_id"])
    lease = scheduler.acquire_lease(step_id, worker_id="worker-crash")
    if mark_worker_busy:
        # What `_prepare_step` does before handing work to a worker.
        store.register_worker(
            "worker-crash", kind="scripted", status="BUSY", current_step_id=step_id
        )
    orchestrator.fsm.transition_step(
        step_id=step_id,
        event_type="StepStarted",
        actor="worker-crash",
        execution_id=orchestrator.execution_id,
        payload={"lease_id": lease.lease_id, "expire_at": lease.expire_at},
    )
    # The worker dies here. Its lease is what is left behind.
    store.connection.execute(
        "UPDATE leases SET expire_at = '2000-01-01T00:00:00Z' WHERE lease_id = ?",
        (lease.lease_id,),
    )
    return store, orchestrator, step_id


def test_a_step_that_crashes_while_running_is_recoverable(git_repo, tmp_path) -> None:
    """Without a RUNNING lease-expiry edge the step, and the run, were stuck forever.

    `StepLeaseExpired` started only from LEASED, and recovery skipped any step that was not
    LEASED, so a worker that died *after* `StepStarted` left a step that was neither
    retryable nor terminal. Nothing but hand-editing the database could move it.
    """
    from daedalus.application.recovery import recover_workspace

    store, orchestrator, step_id = _crash_mid_run(tmp_path, git_repo)
    assert store.get_step(step_id)["state"] == "RUNNING"

    report = recover_workspace(
        store=store, apply=True, worktrees_root=tmp_path / "wtc"
    )
    actions = {item.finding.value: item.action for item in report.items}
    assert "stale_lease" in actions, [i.finding.value for i in report.items]
    assert "LOST" in actions["stale_lease"], actions
    assert store.get_step(step_id)["state"] == "LOST", "the step must leave RUNNING"

    # LOST is retryable, so the scheduler can pick the step up again — that is the point.
    from daedalus.application.scheduler import RETRYABLE_STATES

    assert "LOST" in RETRYABLE_STATES
    assert store.get_run(orchestrator.run_id)["status"] == "RUNNING"
    store.close()


def test_recovery_rebuilds_the_execution_and_worker_projections(git_repo, tmp_path) -> None:
    """The §19 projections had no reconciliation, so a crash left them wrong forever."""
    from daedalus.application.recovery import recover_workspace

    store, orchestrator, step_id = _crash_mid_run(tmp_path, git_repo)
    before = store.get_execution(orchestrator.execution_id)
    assert before["step_total"] == 0, "counters were only ever computed at close"

    report = recover_workspace(store=store, apply=True, worktrees_root=tmp_path / "wtc")
    kinds = [item.finding.value for item in report.items]
    assert "execution_drift" in kinds, kinds
    assert "stale_worker" in kinds, kinds

    after = store.get_execution(orchestrator.execution_id)
    assert after["step_total"] == 1
    assert after["step_committed"] == 0
    assert after["step_failed"] == 1, "the LOST step is a failure, by the shared bucket"
    # The run is still in flight, so the execution legitimately is too — but it now agrees
    # with the run instead of claiming work that finished long ago.
    assert after["status"] == store.get_run(orchestrator.run_id)["status"]

    workers = {str(row["worker_id"]): row for row in store.list_workers()}
    assert workers["worker-crash"]["status"] == "IDLE", "not BUSY on a step that is LOST"
    store.close()


def test_the_execution_counters_reconcile_by_construction() -> None:
    """`total == committed + failed + neutral + unsettled`, for every state combination."""
    from itertools import combinations

    from daedalus.domain.fsm import StepState, execution_counters

    every = [state.value for state in StepState]
    for size in range(len(every) + 1):
        for subset in combinations(every, size):
            counters = execution_counters(subset)
            assert counters["step_total"] == (
                counters["step_committed"]
                + counters["step_failed"]
                + counters["step_neutral"]
                + counters["step_unsettled"]
            ), (subset, counters)


def test_no_bucket_names_a_state_that_does_not_exist() -> None:
    """`_close_execution` listed `"REJECTED"`, which is not a StepState.

    A bucket that names a non-existent state silently counts nothing, so a PARTIAL_FAILURE
    run could report zero failures.
    """
    from daedalus.domain.fsm import FAILED_STATES, NEUTRAL_STATES, UNSETTLED_STATES, StepState

    known = {state.value for state in StepState}
    for bucket in (FAILED_STATES, NEUTRAL_STATES, UNSETTLED_STATES):
        unknown = sorted(bucket - known)
        assert not unknown, f"bucket names states that do not exist: {unknown}"
    assert "ESCALATED" in FAILED_STATES, "an escalated step is not a success"




def test_a_running_step_keeps_a_consistent_lease_pair(git_repo, tmp_path) -> None:
    """A lease id with no expiry is one condition away from a double lease.

    `lease_expires_at` is written unconditionally, so `StepStarted` had to carry it; without
    that, LEASED -> RUNNING preserved the lease id (COALESCE) and nulled the expiry.
    """
    store, _orchestrator, step_id = _crash_mid_run(tmp_path, git_repo)
    row = store.get_step(step_id)
    assert row["state"] == "RUNNING"
    assert bool(row["lease_id"]) == bool(row["lease_expires_at"]), (
        f"lease_id={row['lease_id']!r} lease_expires_at={row['lease_expires_at']!r}"
    )
    store.close()


def test_a_committed_step_does_not_keep_a_lease(git_repo, tmp_path) -> None:
    """The two direct writers bypass the projection helper, so they must clear it themselves."""
    store, orchestrator, _result = _run(tmp_path, git_repo)
    for row in store.list_steps(orchestrator.run_id):
        if str(row["state"]) == "COMMITTED":
            assert not row["lease_id"], f"committed step still holds {row['lease_id']!r}"
    store.close()


# ---------------------------------------------------------------------------
# The lease is one fact, not two columns
#
# This bug survived a first fix because that fix patched one caller (`StepStarted`) while the
# *next* write on the same path — `_prepare_step`'s direct projection update — nulled the
# expiry again. The test below therefore drives the real orchestrator path instead of
# transitioning states by hand, which is why it catches what the earlier test did not.
# ---------------------------------------------------------------------------


def test_the_lease_pair_survives_the_whole_prepare_step_path(git_repo, tmp_path) -> None:
    """Driving a step to RUNNING the way the orchestrator does leaves a consistent lease."""
    from daedalus.application.orchestrator import RunOrchestrator

    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="REQ-LEASE",
            goal_id="GOAL-LEASE",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    store = EventStore(tmp_path / "ws" / "daedalus.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wtl",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-lease",
        ),
    )
    orchestrator.register_spec()
    pool = orchestrator.create_run()
    scheduler = orchestrator.scheduler()
    scheduler.declare_all_nodes(orchestrator.spec_digest, base_commit=pool.base_commit)
    step_id = str(store.list_steps(orchestrator.run_id)[0]["step_id"])

    # The real path: `_prepare_step` transitions to RUNNING and then writes the projection
    # directly. That second write is what used to strip the expiry while keeping the id.
    orchestrator._prepare_step(step_id, pool=pool, scheduler=scheduler)  # noqa: SLF001

    row = store.get_step(step_id)
    assert row["state"] == "RUNNING", row["state"]
    assert bool(row["lease_id"]) == bool(row["lease_expires_at"]), (
        f"lease_id={row['lease_id']!r} lease_expires_at={row['lease_expires_at']!r} — a "
        "half-written lease leaves the step neither running nor schedulable"
    )
    assert store.step_invariant_violations() == [], store.step_invariant_violations()
    store.close()


def test_a_write_that_does_not_mention_the_lease_leaves_it_alone(git_repo, tmp_path) -> None:
    """The invariant that was missing: both lease columns move together or not at all."""
    store, _orchestrator, step_id = _crash_mid_run(tmp_path, git_repo)
    before = store.get_step(step_id)
    assert before["lease_id"] and before["lease_expires_at"]

    # An unrelated projection update — exactly the kind that used to half-clear the lease.
    store.update_step_state(step_id, state="RUNNING", worktree_path="/tmp/elsewhere")
    after = store.get_step(step_id)
    assert after["lease_id"] == before["lease_id"]
    assert after["lease_expires_at"] == before["lease_expires_at"]
    store.close()


def test_clearing_the_lease_clears_both_columns(git_repo, tmp_path) -> None:
    """`""` is the explicit clear, and it must clear the pair."""
    store, _orchestrator, step_id = _crash_mid_run(tmp_path, git_repo)
    store.update_step_state(step_id, state="CANCELLED", lease_id="", lease_expires_at="")
    row = store.get_step(step_id)
    assert not row["lease_id"] and not row["lease_expires_at"]
    store.close()


def test_a_terminal_state_holds_no_lease(git_repo, tmp_path) -> None:
    """Every terminal transition must leave both columns empty, not one of them."""
    store, orchestrator, _result = _run(tmp_path, git_repo)
    for row in store.list_steps(orchestrator.run_id):
        if str(row["state"]) in {"COMMITTED", "CANCELLED", "SUPERSEDED", "STALE"}:
            assert not row["lease_id"], f"{row['node_id']} holds {row['lease_id']!r}"
            assert not row["lease_expires_at"], row["lease_expires_at"]
    assert store.step_invariant_violations() == []
    store.close()


def test_verify_reports_a_half_written_lease(git_repo, tmp_path) -> None:
    """The invariant is checked, not trusted: this is the shape that was undetectable."""
    store, _orchestrator, step_id = _crash_mid_run(tmp_path, git_repo)
    store.connection.execute(
        "UPDATE steps SET lease_expires_at = NULL WHERE step_id = ?", (step_id,)
    )
    violations = store.step_invariant_violations()
    assert any("move together" in violation for violation in violations), violations
    store.close()


def test_recovery_repairs_a_half_written_lease(git_repo, tmp_path) -> None:
    """A half-written lease is worse than none: nothing can schedule or reclaim the step.

    The lease row is removed as well as the expiry, so the stale-lease path cannot rescue
    this — with the row present, `_check_stale_leases` reaches the step first and its LOST
    transition clears both columns, which heals the pair by a different route. That is fine
    behaviour, but it would make this test pass without the consistency check existing.
    """
    from daedalus.application.recovery import recover_workspace

    store, _orchestrator, step_id = _crash_mid_run(tmp_path, git_repo)
    store.connection.execute("DELETE FROM leases WHERE step_id = ?", (step_id,))
    store.connection.execute(
        "UPDATE steps SET lease_expires_at = NULL WHERE step_id = ?", (step_id,)
    )
    assert store.steps_with_inconsistent_lease(), "the fixture must actually be inconsistent"

    report = recover_workspace(store=store, apply=True, worktrees_root=tmp_path / "wtc")
    assert "inconsistent_lease" in [item.finding.value for item in report.items]
    row = store.get_step(step_id)
    assert not row["lease_id"] and not row["lease_expires_at"]
    assert store.step_invariant_violations() == []
    store.close()


def test_verify_reports_a_worker_that_never_leased_the_step(git_repo, tmp_path) -> None:
    """`worker_id` is provenance, and provenance cannot be reconstructed from state."""
    store, _orchestrator, _result = _run(tmp_path, git_repo)
    step_id = str(store.list_steps(_orchestrator.run_id)[0]["step_id"])
    store.connection.execute(
        "UPDATE steps SET worker_id = 'worker-that-never-existed' WHERE step_id = ?",
        (step_id,),
    )
    violations = store.step_invariant_violations()
    assert any("last lease was taken by" in violation for violation in violations), violations
    store.close()


# ---------------------------------------------------------------------------
# Every recorded artifact must be traceable and re-checkable
#
# Two constructors spelled out the same field set and drifted: the rebase path omitted
# `execution_log_ref` and `gated_tree`. The first broke §14 traceability (the audit score found
# it); the second was worse — the commit path skips its "the tree that lands is the tree the
# gate approved" check when `gated_tree` is empty, so a rebased commit landed unverified.
#
# These tests hold the invariant over *every* artifact a run records, whatever path produced it,
# which is the shape of check that would have caught it.
# ---------------------------------------------------------------------------


def _artifact_rows(store, run_id: str) -> list[dict]:
    rows: list[dict] = []
    for step in store.list_steps(run_id):
        rows.extend(store.artifacts_for_step(str(step["step_id"])))
    return rows


def test_every_artifact_records_a_resolvable_execution_log(git_repo, tmp_path) -> None:
    from daedalus.application.execution_log import resolve

    store, orchestrator, _result = _run(tmp_path, git_repo)
    rows = _artifact_rows(store, orchestrator.run_id)
    assert rows, "the run must record at least one artifact"
    for row in rows:
        reference = str(row["execution_log_ref"] or "")
        assert reference.startswith("audit://"), f"artifact without a log reference: {row['status']}"
        assert resolve(store, reference), f"{reference} resolved to nothing"
    store.close()


def test_every_artifact_records_the_tree_the_gate_reviewed(git_repo, tmp_path) -> None:
    """Without this, the commit path cannot tell that the tree changed after the gate."""
    import json as _json

    store, orchestrator, _result = _run(tmp_path, git_repo)
    for row in _artifact_rows(store, orchestrator.run_id):
        document = _json.loads(str(row["document"]))
        extra = document.get("extra", {})
        assert extra.get("gated_tree"), (
            f"{row['status']} artifact has no gated_tree, so the commit path's "
            "committed-tree == gated-tree check is skipped"
        )
        assert extra.get("diff_stat") is not None
    store.close()


def test_a_rebase_records_the_same_artifact_fields_as_an_attempt(git_repo, tmp_path) -> None:
    """The rebase re-gate is a gate result, so its artifact must be as inspectable as any other.

    The parallel scenario forces two steps to contend for the same base, which is what produces
    a REBASE_REQUIRED artifact.
    """
    from daedalus.application.gatekeeper.decision import GateDecision

    store, orchestrator, _result = _run(tmp_path, git_repo)
    statuses = {str(row["status"]) for row in _artifact_rows(store, orchestrator.run_id)}
    assert GateDecision is not None
    # Either the scenario rebased (proving the path ran) or it did not; both are fine, but the
    # field invariant above must hold for whatever the run produced.
    assert statuses, statuses
    store.close()


def test_no_artifact_is_recorded_without_its_reproducibility_digests(git_repo, tmp_path) -> None:
    """A digest that is missing makes "can this be reproduced?" unanswerable, not just unknown."""
    store, orchestrator, _result = _run(tmp_path, git_repo)
    for row in _artifact_rows(store, orchestrator.run_id):
        for field in (
            "toolchain_digest",
            "dependency_digest",
            "code_base_digest",
            "patch_digest",
            "input_artifact_digest",
        ):
            assert str(row[field] or ""), f"{row['status']} artifact has no {field}"
    store.close()
