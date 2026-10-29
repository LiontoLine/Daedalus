"""Event store, idempotency and replay (Spec §5, §16, §28).

The central claim under test: the projection is a cache and the event log is the
truth. If they ever disagree, the log wins.
"""

from __future__ import annotations

import pytest

from daedalus.domain.fsm import StepState
from daedalus.application.fsm_service import StateMachineService
from daedalus.errors import SequenceConflict
from daedalus.infrastructure.store import EventStore, IdempotentReplay, idempotency_key


def _store(tmp_path) -> EventStore:
    return EventStore(tmp_path / "events.db")


def test_events_are_sequenced_per_aggregate(tmp_path) -> None:
    with _store(tmp_path) as store:
        for _ in range(3):
            store.append(
                aggregate_id="step:s1",
                execution_id="exec-1",
                event_type="AuditNote",
                actor="test",
                payload={"message": "note"},
            )
        sequences = [event.sequence for event in store.events_for("step:s1")]
        assert sequences == [1, 2, 3]
        assert store.verify_sequences() == []


def test_sequence_gap_is_refused(tmp_path) -> None:
    with _store(tmp_path) as store:
        store.append(
            aggregate_id="step:s1",
            execution_id="exec-1",
            event_type="AuditNote",
            actor="test",
            payload={},
        )
        with pytest.raises(SequenceConflict):
            store.append(
                aggregate_id="step:s1",
                execution_id="exec-1",
                event_type="AuditNote",
                actor="test",
                payload={},
                expected_sequence=5,
            )


def test_verify_sequences_detects_a_planted_gap(tmp_path) -> None:
    with _store(tmp_path) as store:
        for _ in range(2):
            store.append(
                aggregate_id="step:s1",
                execution_id="exec-1",
                event_type="AuditNote",
                actor="test",
                payload={},
            )
        store.connection.execute(
            "UPDATE events SET sequence = 7 WHERE aggregate_id = 'step:s1' AND sequence = 2"
        )
        assert store.verify_sequences() == ["step:s1"]


def test_idempotency_returns_the_original_result(tmp_path) -> None:
    with _store(tmp_path) as store:
        key = idempotency_key("exec-1", "s1", "commit")
        with store.transaction():
            store.claim_idempotent(
                key, execution_id="exec-1", step_id="s1", operation_type="commit"
            )
            store.complete_idempotent(key, {"commit": "abc123"})
        assert store.idempotent_result(key) == {"commit": "abc123"}
        with pytest.raises(IdempotentReplay):
            with store.transaction():
                store.claim_idempotent(
                    key, execution_id="exec-1", step_id="s1", operation_type="commit"
                )


def test_concurrent_duplicate_claim_is_refused(tmp_path) -> None:
    with _store(tmp_path) as store:
        key = idempotency_key("exec-1", "s1", "gate")
        with store.transaction():
            store.claim_idempotent(
                key, execution_id="exec-1", step_id="s1", operation_type="gate"
            )
        # A second claim while the first is still IN_PROGRESS must not proceed.
        with pytest.raises(SequenceConflict):
            with store.transaction():
                store.claim_idempotent(
                    key, execution_id="exec-1", step_id="s1", operation_type="gate"
                )


def test_replay_rebuilds_state_from_the_log_alone(tmp_path, git_repo) -> None:
    from daedalus.application.coding_worker import FileOp, ScriptedWorker
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from daedalus.domain.spec import NetworkPolicy, RiskLevel
    from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

    with _store(tmp_path) as store:
        bundle = DeterministicPlanner().plan(
            PlanRequest(
                request_id="REQ-1",
                goal_id="GOAL-REPLAY",
                objective="fix the word counter",
                target_paths=(TARGET,),
                test_command=TEST_COMMAND,
                risk_level=RiskLevel.NORMAL,
                network_policy=NetworkPolicy.DENY,
            )
        )
        orchestrator = RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "wt",
            bundle=bundle,
            worker=ScriptedWorker(
                ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)
            ),
        )
        orchestrator.register_spec()
        result = orchestrator.run()
        assert result.status == "COMPLETED"

        service = StateMachineService(store)
        replayed = service.rebuild_step_states()
        for row in store.list_steps(result.run_id):
            assert replayed[str(row["step_id"])].value == str(row["state"])


def test_projection_can_be_corrupted_and_the_log_still_knows_the_truth(tmp_path) -> None:
    """Simulates a torn write in the cache and proves the log is unaffected."""
    with _store(tmp_path) as store:
        service = StateMachineService(store)
        store.project_run(
            {
                "run_id": "run-1",
                "goal_id": "G",
                "execution_id": "exec-1",
                "spec_digest": "spec-a",
                "status": "PENDING",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        )
        service.declare_step(
            step_id="s1",
            run_id="run-1",
            execution_id="exec-1",
            node_id="n1",
            spec_digest="spec-a",
            expected_artifacts=("src/x.py",),
        )
        service.transition_step(step_id="s1", event_type="StepActivated", actor="test")

        store.update_step_state("s1", state=StepState.COMMITTED.value)  # deliberate corruption
        replayed = service.rebuild_step_states()
        assert replayed["s1"] is StepState.READY
        assert store.get_step("s1")["state"] == StepState.COMMITTED.value


def test_events_are_redacted_before_they_are_persisted(tmp_path) -> None:
    with _store(tmp_path) as store:
        event = store.append(
            aggregate_id="step:s1",
            execution_id="exec-1",
            event_type="AuditNote",
            actor="test",
            payload={"message": "using sk-abcdefghijklmnopqrstuvwxyz012345", "api_key": "hunter2secret"},
        )
        assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in str(event.payload)
        assert "hunter2secret" not in str(event.payload)


def test_concurrent_reads_never_see_a_missing_row(tmp_path) -> None:
    """A read must be atomic with its result set, not just with its statement.

    The failure this guards against: locking `execute` but not the fetch let a worker thread
    interleave a statement between the two, invalidating the result set so `fetchone()` returned
    `None` for a row that certainly existed. It surfaced as an intermittent crash in the resume
    path — about one run in twelve — and would have looked like "the row is sometimes gone" in
    production.
    """
    import threading
    import time

    with _store(tmp_path) as store:
        store.project_run(
            {
                "run_id": "run-concurrent",
                "goal_id": "G",
                "execution_id": "exec-concurrent",
                "spec_digest": "spec",
                "status": "RUNNING",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        )
        missing: list[str] = []
        stop = threading.Event()

        def reader() -> None:
            while not stop.is_set():
                # Both of these must ALWAYS find the row.
                if store.get_run("run-concurrent") is None:
                    missing.append("get_run returned None")
                row = store.connection.execute(
                    "SELECT status FROM runs WHERE run_id = ?", ("run-concurrent",)
                ).fetchone()
                if row is None:
                    missing.append("raw fetchone returned None")

        def writer() -> None:
            events = 0
            while not stop.is_set():
                events += 1
                store.append(
                    aggregate_id="step:concurrent",
                    execution_id="exec-concurrent",
                    event_type="AuditNote",
                    actor="writer",
                    payload={"n": events},
                )
                store.update_run_status("run-concurrent", "RUNNING")

        readers = [threading.Thread(target=reader, daemon=True) for _ in range(4)]
        writer_thread = threading.Thread(target=writer, daemon=True)
        for thread in readers:
            thread.start()
        writer_thread.start()
        time.sleep(1.5)
        stop.set()
        writer_thread.join(timeout=5)
        for thread in readers:
            thread.join(timeout=5)

        assert not missing, f"{len(missing)} lost read(s): {missing[:5]}"
        assert store.event_count() > 0
        assert store.verify_sequences() == []
