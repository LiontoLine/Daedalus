"""Resolvable references into the execution log (Spec §14).

An artifact carries an `execution_log_ref` so that "what actually happened when this
artifact was produced?" is answerable from the artifact alone. A reference that resolves to
nothing is worse than no reference at all: it looks like provenance and provides none, and
the `memory://` scheme it originally used could not be resolved by any process, including
the one that wrote it.

The log itself is the event log — there is deliberately no second one. Events are keyed by
`execution_id` and the timeline projection carries the `step_id`, so a step's log is the
events of its execution that name that step, in sequence order. That makes the reference a
*query*, not a pointer to mutable state, and it stays resolvable for as long as the event
log does.

Schemes:

* ``audit://<run_id>/step/<step_id>`` — every recorded fact about one step: its events, the
  gate results, the artifacts and the owner decisions, in timestamp order.

Anything else is refused rather than guessed at, because a resolver that silently returns an
empty log would make a missing log indistinguishable from an idle step.
"""

from __future__ import annotations

import json
from typing import Any

from daedalus.errors import DaedalusError

SCHEME = "audit://"


class UnresolvableLogRef(DaedalusError):
    """The reference is malformed or names a scheme this build does not implement."""


def execution_log_ref(run_id: str, step_id: str) -> str:
    """The reference an artifact records for the attempt that produced it."""
    if not run_id or not step_id:
        raise UnresolvableLogRef("a log reference needs both a run and a step")
    return f"{SCHEME}{run_id}/step/{step_id}"


def parse_log_ref(ref: str) -> tuple[str, str]:
    """`audit://run_x/step/run_x:N1` -> `("run_x", "run_x:N1")`.

    Step ids contain a colon (`<run_id>:<node_id>`), so the separator is the `/step/`
    marker rather than a split on punctuation.
    """
    if not ref.startswith(SCHEME):
        raise UnresolvableLogRef(
            f"unsupported log reference scheme in {ref!r}; this build resolves {SCHEME}"
        )
    body = ref[len(SCHEME):]
    run_id, marker, step_id = body.partition("/step/")
    if not marker or not run_id or not step_id:
        raise UnresolvableLogRef(
            f"malformed log reference {ref!r}; expected {SCHEME}<run_id>/step/<step_id>"
        )
    return run_id, step_id


def resolve(store: Any, ref: str) -> list[dict[str, Any]]:
    """Every persisted fact about the referenced step, in timestamp order.

    Reads the projections rather than re-deriving them, and raises if the run or the step
    does not exist — the caller asked a question with a definite answer, and "nothing" is
    not it.
    """
    run_id, step_id = parse_log_ref(ref)
    run = store.get_run(run_id)
    if run is None:
        raise UnresolvableLogRef(f"no run {run_id!r} exists for {ref!r}")
    if store.get_step(step_id) is None:
        raise UnresolvableLogRef(f"no step {step_id!r} exists for {ref!r}")

    entries: list[dict[str, Any]] = []
    for event in store.events_for_execution(str(run["execution_id"])):
        if event.step_id != step_id:
            continue
        entries.append(
            {
                "kind": "event",
                "timestamp": event.timestamp,
                "sequence": event.sequence,
                "actor": event.actor,
                "event_type": event.event_type,
                "causation_id": event.causation_id,
                "payload": dict(event.payload),
            }
        )
    for gate in store.gate_results_for_step(step_id):
        entries.append(
            {
                "kind": "gate",
                "timestamp": str(gate["created_at"]),
                "sequence": 0,
                "actor": "gatekeeper",
                "event_type": f"tier{gate['tier']}:{gate['decision']}",
                "causation_id": "",
                "payload": {
                    "reasons": json.loads(str(gate["reasons"] or "[]")),
                    "violations": json.loads(str(gate["violations"] or "[]")),
                    "confidence": gate["confidence"],
                    "evidence": json.loads(str(gate["evidence"] or "{}")),
                },
            }
        )
    for artifact in store.artifacts_for_step(step_id):
        entries.append(
            {
                "kind": "artifact",
                "timestamp": str(artifact["created_at"]),
                "sequence": 0,
                "actor": str(artifact["worker_id"]),
                "event_type": f"artifact:{artifact['status']}",
                "causation_id": "",
                "payload": {
                    "artifact_digest": str(artifact["artifact_digest"]),
                    "changed_files": json.loads(str(artifact["changed_files"] or "[]")),
                    "model": str(artifact["model"]),
                },
            }
        )
    for approval in store.approvals_for_step(step_id):
        entries.append(
            {
                "kind": "approval",
                "timestamp": str(approval["created_at"]),
                "sequence": 0,
                "actor": str(approval["approved_by"]),
                "event_type": f"approval:{approval['decision']}",
                "causation_id": "",
                "payload": {"note": str(approval["note"])},
            }
        )
    entries.sort(key=lambda entry: (entry["timestamp"], entry["sequence"]))
    return entries
