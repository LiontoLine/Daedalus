"""The only sanctioned way to move a step through its lifecycle (Spec §4.2).

Every transition goes through exactly this sequence:

    validate precondition -> append event -> persist state -> emit side effect

The guard that matters most is the **committed-step guard**: a step in a terminal
state can never be moved again inside the same execution id. Re-running work
requires a new execution id and a replay (Spec §4.3, §12.1). This is what stops a
model-driven loop from quietly rewriting history.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from daedalus.application.observability import get_logger, log_context
from daedalus.domain.artifacts import Artifact
from daedalus.domain.canonical import digest_of
from daedalus.domain.events import Event, step_aggregate
from daedalus.domain.fsm import (
    StepState,
    next_step_state,
    resolve_run_transition,
)
from daedalus.domain.ids import utc_now
from daedalus.errors import IllegalTransition, SpecDigestMismatch
from daedalus.infrastructure.store.event_store import EventStore

#: Events that a step may only receive while it still owns a live lease/attempt.
_EVENTS_REQUIRING_MATCHING_EXECUTION = frozenset(
    {
        "StepLeaseAcquired",
        "StepStarted",
        "StepGatekeeperEntered",
        "StepTier1Decided",
        "StepTier2Decided",
        "StepCommitRequested",
        "StepCommitted",
    }
)


@dataclass(frozen=True, slots=True)
class TransitionResult:
    event: Event
    previous_state: StepState
    new_state: StepState
    step_id: str

    @property
    def changed(self) -> bool:
        return self.previous_state is not self.new_state


class StateMachineService:
    """Authoritative FSM over the event store."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    # ------------------------------------------------------------------ steps
    def declare_step(
        self,
        *,
        step_id: str,
        run_id: str,
        execution_id: str,
        node_id: str,
        spec_digest: str,
        objective: str = "",
        intent: str = "",
        deps: tuple[str, ...] = (),
        expected_artifacts: tuple[str, ...] = (),
        allowed_tools: tuple[str, ...] = (),
        max_attempts: int = 3,
        timeout_sec: int = 300,
        base_commit: str = "",
        revision_of: str = "",
        actor: str = "scheduler",
        correlation_id: str = "",
    ) -> Event:
        import json

        with self.store.transaction():
            self.store.project_step(
                {
                    "step_id": step_id,
                    "run_id": run_id,
                    "execution_id": execution_id,
                    "node_id": node_id,
                    "objective": objective,
                    "intent": intent,
                    "deps": json.dumps(sorted(deps)),
                    "expected_artifacts": json.dumps(sorted(expected_artifacts)),
                    "allowed_tools": json.dumps(sorted(allowed_tools)),
                    "state": StepState.PENDING.value,
                    "attempt": 0,
                    "max_attempts": max_attempts,
                    "timeout_sec": timeout_sec,
                    "spec_digest": spec_digest,
                    "base_commit": base_commit,
                    "revision_of": revision_of,
                    "created_at": utc_now(),
                    "updated_at": utc_now(),
                }
            )
        return self.store.append(
            aggregate_id=step_aggregate(step_id),
            execution_id=execution_id,
            event_type="StepDeclared",
            actor=actor,
            payload={
                "step_id": step_id,
                "run_id": run_id,
                "node_id": node_id,
                "spec_digest": spec_digest,
                "deps": sorted(deps),
                "expected_artifacts": sorted(expected_artifacts),
                "revision_of": revision_of,
            },
            correlation_id=correlation_id,
        )

    def transition_step(
        self,
        *,
        step_id: str,
        event_type: str,
        actor: str,
        payload: dict[str, Any] | None = None,
        outcome: str | None = None,
        execution_id: str | None = None,
        correlation_id: str = "",
        causation_id: str = "",
    ) -> TransitionResult:
        """Apply one legal transition to a step, or raise `IllegalTransition`."""
        row = self.store.get_step(step_id)
        if row is None:
            raise IllegalTransition(
                f"unknown step {step_id}",
                aggregate_id=step_aggregate(step_id),
                event_type=event_type,
            )

        current = StepState(row["state"])
        step_execution_id = str(row["execution_id"])

        # --- precondition 1: the declared subject is still the frozen subject --
        # Checked before the FSM so that a drifted spec always reports drift, even
        # when the transition itself would also have been illegal.
        # The resolved outcome is written into the event payload: without it the log
        # would not be self-describing and a replay could not rebuild the state.
        event_payload = dict(payload or {})
        if outcome is not None:
            event_payload["outcome"] = outcome
        declared_digest = str(event_payload.get("spec_digest", ""))
        if declared_digest and declared_digest != row["spec_digest"]:
            raise SpecDigestMismatch(
                f"step {step_id} is pinned to spec {row['spec_digest']} but the event "
                f"carries {declared_digest}; refusing to transition",
                step_spec_digest=row["spec_digest"],
                event_spec_digest=declared_digest,
            )

        # --- precondition 2: a cache hit must name what it reused --------------
        # Landing in COMMITTED without running the gate is only acceptable because the
        # identical content was gated before. That claim has to be in the event, so the
        # audit can follow it to the original gate result instead of taking our word.
        if event_type == "StepCacheHit":
            missing = [
                key
                for key in ("source_artifact_digest", "gate_result_ref", "reuse_key")
                if not event_payload.get(key)
            ]
            if missing:
                raise IllegalTransition(
                    f"StepCacheHit on {step_id} is missing provenance {missing}; a cache "
                    "hit without a named source artifact and gate result would be an "
                    "ungated commit",
                    aggregate_id=step_aggregate(step_id),
                    from_state=current.value,
                    event_type=event_type,
                )

        # --- precondition 3: execution ownership -------------------------------
        if execution_id is not None and execution_id != step_execution_id:
            if event_type in _EVENTS_REQUIRING_MATCHING_EXECUTION:
                raise IllegalTransition(
                    f"step {step_id} belongs to execution {step_execution_id} but the "
                    f"event {event_type} was raised for execution {execution_id}; a "
                    "re-run must create a new step under the new execution id",
                    aggregate_id=step_aggregate(step_id),
                    from_state=current.value,
                    event_type=event_type,
                )

        # --- precondition 4: the FSM itself -----------------------------------
        next_state = next_step_state(current, event_type, outcome)

        # --- append event and persist state in one transaction ----------------
        aggregate_id = step_aggregate(step_id)
        with self.store.transaction():
            event = self.store.append_in_transaction(
                aggregate_id=aggregate_id,
                execution_id=step_execution_id,
                event_type=event_type,
                actor=actor,
                payload=event_payload,
                correlation_id=correlation_id,
                causation_id=causation_id,
            )
            # Spec §27 requires the logs to carry event_id. The timeline projection records
            # it against every event, but a line emitted while projecting a transition — or an
            # exception raised there — could not name the event it belonged to. Bound for the
            # projection phase, which is the part that can log and fail.
            with log_context(event_id=event.event_id):
                # One line per transition, so the operational log stream carries event_id
                # (Spec §27) and can be read on its own to see what changed. The timeline
                # projection remains the authoritative per-event record; this is the same
                # fact in the place an operator tailing logs will look for it.
                get_logger("fsm").info(
                    "step %s -> %s",
                    current.value,
                    next_state.value,
                    extra={"extra_fields": {
                        "event_type": event_type,
                        "node_id": str(row["node_id"]),
                    }},
                )
                self._persist_step_projection(step_id, next_state, event, event_payload)
                if next_state is StepState.COMMITTED:
                    self.store.record_metric(
                        name="steps_committed",
                        value=1,
                        unit="count",
                        run_id=str(row["run_id"]),
                        step_id=step_id,
                    )
                self.store.append_timeline(
                    run_id=str(row["run_id"]),
                    execution_id=step_execution_id,
                    step_id=step_id,
                    event_id=event.event_id,
                    event_type=event_type,
                    actor=actor,
                    summary=_summarise(event_type, row["node_id"], next_state, event_payload),
                    severity=_severity_for(next_state),
                )

        return TransitionResult(
            event=event,
            previous_state=current,
            new_state=next_state,
            step_id=step_id,
        )

    def _append_in_transaction(
        self,
        *,
        aggregate_id: str,
        execution_id: str,
        sequence: int,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        correlation_id: str,
        causation_id: str,
    ) -> Event:
        return self.store.append_in_transaction(
            aggregate_id=aggregate_id,
            execution_id=execution_id,
            event_type=event_type,
            actor=actor,
            payload=payload,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )

    def _persist_step_projection(
        self,
        step_id: str,
        next_state: StepState,
        event: Event,
        payload: dict[str, Any],
    ) -> None:
        attempt = payload.get("attempt")
        lease_id = payload.get("lease_id")
        worker_id = payload.get("worker_id")
        expire_at = payload.get("expire_at")
        base_commit = payload.get("base_commit")
        failure = payload.get("reason") or payload.get("failure")

        # Clearing the lease on terminal/exit states is what makes "no active lease
        # => eligible for READY" (Spec §6.2) true rather than aspirational.
        if next_state in {
            StepState.READY,
            StepState.COMMITTED,
            StepState.CANCELLED,
            StepState.SUPERSEDED,
            StepState.REVISE,
            StepState.FAILED,
            StepState.TIMEOUT,
            StepState.ESCALATED,
            StepState.STALE,
            StepState.LOST,
            StepState.AWAITING_GATEKEEPER,
        }:
            # `""` rather than `None`: the projection COALESCEs these columns so an unrelated
            # transition cannot erase them, which means `None` now reads as "leave alone" and
            # an explicit clear has to be spelled.
            #
            # Only the *lease* is cleared. `worker_id` is provenance, not bookkeeping: a
            # committed step must still be able to answer "which worker produced this?", and
            # clearing it here is what made that column — and every query derived from it —
            # permanently empty.
            lease_id = ""
            expire_at = ""

        self.store.update_step_state(
            step_id,
            state=next_state.value,
            attempt=int(attempt) if attempt is not None else None,
            lease_id=lease_id,
            worker_id=worker_id,
            lease_expires_at=expire_at,
            base_commit=base_commit,
            last_failure=str(failure) if failure else None,
        )

    def _project_timeline(self, row: Any, event: Event, next_state: StepState) -> None:
        """Reserved for future derived projections; metrics only for now."""

    # -------------------------------------------------------------------- runs
    def transition_run(
        self,
        *,
        run_id: str,
        execution_id: str,
        event_type: str,
        actor: str,
        payload: dict[str, Any] | None = None,
        correlation_id: str = "",
    ) -> Event:
        from daedalus.domain.events import run_aggregate

        run = self.store.get_run(run_id)
        if run is None:
            raise IllegalTransition(
                f"unknown run {run_id}",
                aggregate_id=run_aggregate(run_id),
                event_type=event_type,
            )
        next_status = resolve_run_transition(run["status"], event_type)

        aggregate_id = run_aggregate(run_id)
        with self.store.transaction():
            sequence = self.store.next_sequence(aggregate_id)
            event = self._append_in_transaction(
                aggregate_id=aggregate_id,
                execution_id=execution_id,
                sequence=sequence,
                event_type=event_type,
                actor=actor,
                payload=dict(payload or {}),
                correlation_id=correlation_id,
                causation_id="",
            )
            self.store.update_run_status(run_id, next_status.value)
            self.store.append_timeline(
                run_id=run_id,
                execution_id=execution_id,
                step_id="",
                event_id=event.event_id,
                event_type=event_type,
                actor=actor,
                summary=f"run {run_id} -> {next_status.value}",
                severity="error" if next_status.value == "FAILED" else "info",
            )
            self.store.record_metric(
                name="run_transitions",
                value=1,
                unit="count",
                run_id=run_id,
                labels={"to": next_status.value},
            )
        return event

    # ------------------------------------------------------------- audit notes
    def audit_note(
        self,
        *,
        run_id: str,
        execution_id: str,
        actor: str,
        message: str,
        severity: str = "info",
        payload: dict[str, Any] | None = None,
        correlation_id: str = "",
    ) -> Event:
        from daedalus.domain.events import run_aggregate

        event = self.store.append(
            aggregate_id=run_aggregate(run_id),
            execution_id=execution_id,
            event_type="AuditNote",
            actor=actor,
            payload={"message": message, **(payload or {})},
            correlation_id=correlation_id,
        )
        self.store.append_timeline(
            run_id=run_id,
            execution_id=execution_id,
            step_id="",
            event_id=event.event_id,
            event_type="AuditNote",
            actor=actor,
            summary=message,
            severity=severity,
        )
        return event

    # --------------------------------------------------------------- artifacts
    def record_artifact(self, artifact: Artifact) -> str:
        """Record an artifact row and return its content digest.

        The digest covers the identity-bearing fields only. `created_at` and the free
        `extra` blob are excluded so that re-recording identical work is idempotent.
        """
        core = {
            "step_id": artifact.step_id,
            "execution_id": artifact.execution_id,
            "parent_commit": artifact.parent_commit,
            "changed_files": sorted(artifact.changed_files),
            "patch_digest": artifact.patch_digest,
            "spec_digest": artifact.spec_digest,
            "dependency_digest": artifact.dependency_digest,
            "toolchain_digest": artifact.toolchain_digest,
            "code_base_digest": artifact.code_base_digest,
            "input_artifact_digest": artifact.input_artifact_digest,
            "status": artifact.status,
        }
        digest = artifact.artifact_digest or digest_of(core)
        self.store.record_artifact(
            {
                **artifact.to_payload(),
                "artifact_digest": digest,
                "changed_files": _json(list(artifact.changed_files)),
                "document": _json({"changed_files": list(artifact.changed_files), "extra": artifact.extra}),
                "created_at": artifact.created_at or utc_now(),
            }
        )
        return digest

    # ------------------------------------------------------------------ replay
    def rebuild_step_states(self) -> dict[str, StepState]:
        """Recompute every step state purely from the event log.

        Used by the recovery test: if this disagrees with the projection, the
        projection is a cache and the event log is the truth (Spec §16).
        """
        states: dict[str, StepState] = {}
        for event in self.store.all_events():
            if not event.aggregate_id.startswith("step:"):
                continue
            step_id = event.step_id
            if event.event_type == "StepDeclared":
                states[step_id] = StepState.PENDING
                continue
            current = states.get(step_id)
            if current is None:
                continue
            try:
                outcome = event.payload.get("outcome") if event.payload else None
                states[step_id] = next_step_state(
                    current, event.event_type, str(outcome) if outcome else None
                )
            except IllegalTransition:
                # A refusal in the log means the projection never moved either.
                continue
        return states


def _json(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _severity_for(state: StepState) -> str:
    if state in {StepState.FAILED, StepState.TIMEOUT, StepState.CANCELLED}:
        return "error"
    if state in {StepState.REVISE, StepState.ESCALATED, StepState.LOST, StepState.STALE}:
        return "warning"
    if state is StepState.COMMITTED:
        return "info"
    return "debug"


def _summarise(
    event_type: str,
    node_id: str,
    next_state: StepState,
    payload: dict[str, Any],
) -> str:
    detail = (
        payload.get("reason")
        or payload.get("failure")
        or payload.get("summary")
        or payload.get("outcome")
        or ""
    )
    suffix = f" — {detail}" if detail else ""
    return f"{event_type} on {node_id} -> {next_state.value}{suffix}"


def _commit_step_transaction(
    service: "StateMachineService",
    *,
    step_id: str,
    execution_id: str,
    actor: str,
    payload: dict[str, Any],
    correlation_id: str,
    idempotency_key: str,
    idempotency_result: dict[str, Any],
    run_id: str,
    node_id: str,
    commit: str,
    dependents: tuple[tuple[str, str], ...] = (),
    lease_id: str = "",
) -> Event:
    """Atomically: claim idempotency, append StepCommitted, update run, move dependents.

    This is a module-level function rather than a method so it is obvious that it owns
    exactly one transaction — nesting transactions is what turns a recoverable commit
    into an unrecoverable one.
    """
    with service.store.transaction():
        step = service.store.get_step(step_id)
        if step is None or str(step["execution_id"]) != execution_id or str(step["run_id"]) != run_id:
            raise IllegalTransition("commit receipt does not belong to this execution")
        next_step_state(StepState(str(step["state"])), "StepCommitted")
        artifact_digest = str(payload.get("artifact_digest", ""))
        artifact = service.store.get_artifact(artifact_digest)
        if artifact is None or artifact["step_id"] != step_id or artifact["execution_id"] != execution_id or artifact["spec_digest"] != step["spec_digest"]:
            raise SpecDigestMismatch("commit artifact is missing or belongs to another subject")
        service.store.claim_idempotent(
            idempotency_key,
            execution_id=execution_id,
            step_id=step_id,
            operation_type="commit",
        )
        service.store.complete_idempotent(idempotency_key, idempotency_result)
        event = service.store.append_in_transaction(
            aggregate_id=step_aggregate(step_id),
            execution_id=execution_id,
            event_type="StepCommitted",
            actor=actor,
            payload=payload,
            correlation_id=correlation_id,
        )
        # The lease is cleared explicitly. This write bypasses `_persist_step_projection`, so
        # it does not inherit the terminal-state clearing, and leaving a lease id on a
        # committed step would be exactly the stale-lease ambiguity the helper prevents.
        service.store.update_step_state(
            step_id,
            state=StepState.COMMITTED.value,
            lease_id="",
            lease_expires_at="",
        )
        service.store.append_timeline(
            run_id=run_id,
            execution_id=execution_id,
            step_id=step_id,
            event_id=event.event_id,
            event_type="StepCommitted",
            actor=actor,
            summary=f"StepCommitted on {node_id} -> COMMITTED",
            severity="info",
        )
        service.store.record_metric(
            name="steps_committed", value=1, unit="count", run_id=run_id, step_id=step_id
        )
        service.store.append_in_transaction(
            aggregate_id=f"run:{run_id}",
            execution_id=execution_id,
            event_type="RunStepCommitted",
            actor=actor,
            payload={"step_id": step_id, "node_id": node_id, "commit": commit},
            correlation_id=correlation_id,
        )
        for dependent_step_id, base_commit in dependents:
            row = service.store.get_step(dependent_step_id)
            if row is not None:
                service.store.update_step_state(
                    dependent_step_id, state=str(row["state"]), base_commit=base_commit
                )
        # Artifact visibility and cache provenance belong to the SAME receipt.
        # A crash may roll back all of them, never leave COMMITTED with a candidate artifact.
        import json
        gate_ref = str(idempotency_result.get("gate_result_digest", ""))
        service.store.update_artifact_status(artifact_digest, status="COMMITTED", gate_result_ref=gate_ref)
        document = json.loads(str(artifact["document"]))
        document["commit"] = commit
        service.store.record_artifact({**artifact, "status": "COMMITTED", "gate_result_ref": gate_ref,
                                       "document": _json(document)})
        lease_id = lease_id or str(step["lease_id"] or "")
        if lease_id:
            service.store.release_lease(lease_id, "COMPLETED")
    return event


def _cache_hit_transaction(
    service: "StateMachineService",
    *,
    step_id: str,
    execution_id: str,
    actor: str,
    payload: dict[str, Any],
    correlation_id: str,
    run_id: str,
    node_id: str,
    commit: str,
    dependents: tuple[tuple[str, str], ...] = (),
) -> Event:
    """Atomically apply a Spec §13.2 cache hit: the step lands COMMITTED by provenance.

    The payload must name the source artifact and its gate result (enforced as a
    precondition in `transition_step`), so this path can never become an ungated commit.
    """
    with service.store.transaction():
        event = service.store.append_in_transaction(
            aggregate_id=step_aggregate(step_id),
            execution_id=execution_id,
            event_type="StepCacheHit",
            actor=actor,
            payload={**payload, "commit": commit, "node_id": node_id},
            correlation_id=correlation_id,
        )
        # The lease is cleared explicitly. This write bypasses `_persist_step_projection`, so
        # it does not inherit the terminal-state clearing, and leaving a lease id on a
        # committed step would be exactly the stale-lease ambiguity the helper prevents.
        service.store.update_step_state(
            step_id, state=StepState.COMMITTED.value, lease_id=""
        )
        service.store.append_timeline(
            run_id=run_id,
            execution_id=execution_id,
            step_id=step_id,
            event_id=event.event_id,
            event_type="StepCacheHit",
            actor=actor,
            summary=(
                f"StepCacheHit on {node_id} -> COMMITTED from "
                f"{str(payload.get('source_artifact_digest', ''))[:12]}"
            ),
            severity="info",
        )
        service.store.record_metric(
            name="cache_hits", value=1, unit="count", run_id=run_id, step_id=step_id
        )
        service.store.append_in_transaction(
            aggregate_id=f"run:{run_id}",
            execution_id=execution_id,
            event_type="RunStepCommitted",
            actor=actor,
            payload={
                "step_id": step_id,
                "node_id": node_id,
                "commit": commit,
                "reused": True,
            },
            correlation_id=correlation_id,
        )
        for dependent_step_id, base_commit in dependents:
            row = service.store.get_step(dependent_step_id)
            if row is not None:
                service.store.update_step_state(
                    dependent_step_id, state=str(row["state"]), base_commit=base_commit
                )
    return event
