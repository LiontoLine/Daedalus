"""Read-only expectation evidence and repair lineage, never execution authority."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from daedalus.application.repair_evidence import criterion_status
from daedalus.domain.spec import AcceptanceCriterion

_STATES = frozenset({"MET", "UNMET", "UNKNOWN", "BLOCKED", "STALE"})


def _status(value: Any) -> str:
    return value if isinstance(value, str) and value in _STATES else "UNKNOWN"


def _summarize(node: dict[str, Any]) -> None:
    states = [row["status"] for row in node["expectations"]]
    node["score"] = sum(state == "MET" for state in states) / len(states) if states else 0.0
    node["status"] = next(
        (state for state in ("UNMET", "BLOCKED", "STALE", "UNKNOWN") if state in states),
        "MET" if states else "UNKNOWN",
    )


def _dependencies(nodes: dict[str, dict[str, Any]]) -> None:
    for node in nodes.values():
        blocked = any(nodes[dep]["status"] != "MET" for dep in node.get("deps", []) if dep in nodes)
        for expectation in node["expectations"]:
            evidence = expectation["evidence"]
            if (
                expectation["status"] in {"UNKNOWN", "BLOCKED"}
                and evidence.get("source") in {"node", "none"}
            ):
                status = criterion_status(
                    AcceptanceCriterion.from_dict(expectation), evidence.get("rows", [])
                )
                expectation["status"] = "BLOCKED" if status == "UNKNOWN" and blocked else status
        _summarize(node)


def trunk_view(store: Any, run_id: str) -> dict[str, Any]:
    """Project only recorded root-run evidence; reads never inspect Git or run gates.

    Branch attempts are history, not trunk. Only accepted root node deltas and
    authoritative goal snapshots update evidence. Every returned object is detached
    from event payloads so neither snapshots nor store history can be mutated by a
    consumer.
    """
    result: dict[str, Any] = {
        "enabled": False, "run_id": run_id, "spec_digest": "", "commit": "",
        "digest": "", "contract": None, "nodes": [], "snapshots": [],
        "candidates": [], "branches": [], "failed_criteria": [],
        "coverage_disclaimer": (
            "Evidence coverage only; not correctness probability or permission to deliver."
        ),
    }
    run = store.get_run(run_id)
    if not run:
        return result
    aggregates = {f"run:{run_id}", f"goal:{run_id}"}
    events = [event for event in store.events_for_execution(str(run["execution_id"]))
              if event.aggregate_id in aggregates]
    frozen = next((
        event for event in events if event.event_type == "TrunkExpectationsFrozen"
    ), None)
    if frozen is None:
        return result
    contract = deepcopy(frozen.payload)
    result.update(enabled=True, contract=contract, spec_digest=contract.get("spec_digest", ""))
    nodes: dict[str, dict[str, Any]] = {}
    for definition in contract.get("nodes", []):
        node = deepcopy(definition)
        node.update(commit="", expectations=[
            {**deepcopy(row), "status": "UNKNOWN", "evidence": {"source": "none", "rows": []}}
            for row in definition.get("expectations", [])
        ])
        _summarize(node)
        nodes[str(node["node_id"])] = node
    _dependencies(nodes)
    branches: dict[str, dict[str, Any]] = {}
    seen_freeze = False
    for event in events:
        if event.event_id == frozen.event_id:
            seen_freeze = True
            continue
        if not seen_freeze:
            continue
        payload = deepcopy(event.payload)
        kind = event.event_type
        if kind == "GoalTrunkSnapshot":
            # A goal snapshot supersedes all previous local evidence, including
            # missing rows: absence must never retain a formerly green result.
            result["snapshots"].append(deepcopy(payload))
            result.update(commit=payload.get("commit", ""), digest=payload.get("digest", ""))
            current = {str(row["node_id"]): row for row in payload.get("nodes", [])}
            for node_id, node in nodes.items():
                snapshot_node = current.get(node_id, {})
                rows = {
                    str(row["criterion_id"]): row for row in snapshot_node.get("expectations", [])
                }
                for expectation in node["expectations"]:
                    row = rows.get(str(expectation["criterion_id"]), {})
                    expectation.update(
                        status=_status(row.get("status")),
                        evidence=deepcopy(row.get("evidence", {"source": "none", "rows": []})),
                    )
                node["commit"] = result["commit"]
                _summarize(node)
        elif kind in {"TrunkNodeValidated", "TrunkNodeFailed"}:
            for invalidated_id in payload.get("invalidated_nodes", []):
                invalidated = nodes.get(str(invalidated_id))
                if invalidated is not None:
                    for expectation in invalidated["expectations"]:
                        expectation["status"] = "STALE"
                    _summarize(invalidated)
            node_id = str(payload.get("node_id", ""))
            node = nodes.get(node_id)
            rows = payload.get("criteria", [])
            # A later failure-detail event may carry only the retained patch/reason.
            # It must not erase the criterion evidence recorded before sandbox reset.
            if node is not None and (rows or kind == "TrunkNodeValidated"):
                for expectation in node["expectations"]:
                    matching = [
                        row for row in rows
                        if row.get("criterion_id") == expectation["criterion_id"]
                    ]
                    expectation["status"] = criterion_status(
                        AcceptanceCriterion.from_dict(expectation), matching
                    )
                    expectation["evidence"] = {"source": "node", "rows": matching}
                node["commit"] = str(payload.get("commit", ""))
                _summarize(node)
            _dependencies(nodes)
            if kind == "TrunkNodeValidated":
                result["commit"] = payload.get("commit", result["commit"])
            result["digest"] = ""  # The last immutable snapshot no longer describes these deltas.
        elif kind in {"RepairBranchStarted", "RepairBranchRejected", "RepairBranchPromoted"}:
            branch_id = str(payload.get("branch_id", ""))
            if not branch_id:
                continue
            branch = branches.setdefault(branch_id, {"branch_id": branch_id, "events": []})
            branch.update(payload)
            branch["status"] = {
                "RepairBranchStarted": "STARTED",
                "RepairBranchRejected": "REJECTED",
                "RepairBranchPromoted": "PROMOTED",
            }[kind]
            branch["events"].append({"event_type": kind, "event_id": event.event_id,
                                     "timestamp": event.timestamp, "payload": deepcopy(payload)})
            validation = payload.get("validation")
            if isinstance(validation, dict):
                candidate = validation.get("snapshot")
                if isinstance(candidate, dict):
                    result["candidates"].append({"branch_id": branch_id, "status": branch["status"],
                                                  "snapshot": deepcopy(candidate)})
            if kind == "RepairBranchPromoted" and payload.get("commit"):
                result["commit"] = payload["commit"]
                result["digest"] = ""
                for node_id in payload.get("affected_node_ids", []):
                    node = nodes.get(str(node_id))
                    if node is not None:
                        for expectation in node["expectations"]:
                            expectation["status"] = "STALE"
                        _summarize(node)
    result["nodes"] = list(nodes.values())
    result["branches"] = list(branches.values())
    result["failed_criteria"] = sorted({
        row["criterion_id"] for node in result["nodes"]
        for row in node["expectations"] if row["status"] == "UNMET"
    })
    return result
