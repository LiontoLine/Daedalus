"""Pure evidence projection and bounded repair selection over the original frozen DAG.

Scores measure observed MET coverage only. Neither scores nor this projection authorize
promotion, replace the full goal audit, or change FSM state.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from typing import Any

from daedalus.application.requirement_evidence import behavior_check_results
from daedalus.domain.canonical import digest_of
from daedalus.domain.pathglob import normalize_path, path_matches
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, PlanNode, SpecBundle

_STATES = frozenset({"MET", "UNMET", "UNKNOWN", "BLOCKED", "STALE"})


def _expectations(bundle: SpecBundle, node: PlanNode) -> tuple[AcceptanceCriterion, ...]:
    return node.acceptance_criteria or bundle.goal.acceptance_criteria


def _definitions(bundle: SpecBundle) -> dict[str, AcceptanceCriterion]:
    definitions: dict[str, AcceptanceCriterion] = {}
    for criterion in (
        *bundle.goal.acceptance_criteria,
        *(c for node in bundle.plan.nodes for c in _expectations(bundle, node)),
    ):
        previous = definitions.get(criterion.criterion_id)
        if previous is not None and previous.to_dict() != criterion.to_dict():
            raise ValueError(f"conflicting frozen criterion: {criterion.criterion_id}")
        definitions[criterion.criterion_id] = criterion
    return definitions


def freeze_contract(bundle: SpecBundle) -> dict[str, Any]:
    """Record full original expectations, including the gate's goal inheritance rule."""
    _definitions(bundle)
    return {
        "spec_digest": bundle.digest(),
        "goal_intent": bundle.goal.objective,
        "invariants": list(bundle.goal.invariants),
        "nodes": [
            {
                "node_id": node_id,
                "deps": list(node.deps),
                "objective": node.objective,
                "expected_artifacts": list(node.expected_artifacts),
                "expectations": deepcopy([c.to_dict() for c in _expectations(bundle, node)]),
            }
            for node_id in bundle.plan.topo_order()
            for node in (bundle.plan.node(node_id),)
        ],
    }


def _rows_by_id(rows: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("criterion_id"), str):
            continue
        indexed.setdefault(row["criterion_id"], []).append(deepcopy(dict(row)))
    return indexed


def _row_status(row: Mapping[str, Any], criterion: AcceptanceCriterion) -> str:
    # Execution/infrastructure failures are never evidence of a repairable code defect.
    if row.get("error_code") or row.get("blocked_by"):
        return "BLOCKED"
    status = row.get("status") if isinstance(row.get("status"), str) else None
    if status in {"UNKNOWN", "BLOCKED", "STALE"}:
        return str(status)
    if row.get("executed") is False:
        return "UNKNOWN"
    if isinstance(row.get("ok"), bool):
        if criterion.kind is AssertionKind.NATURAL_LANGUAGE and not row.get("behavior_evidence"):
            return "UNKNOWN"
        return "MET" if row["ok"] else "UNMET"
    if status in {"MET", "UNMET"}:
        evidence = row.get("evidence")
        if isinstance(evidence, str) and evidence.strip():
            return str(status)
    return "UNKNOWN"


def _combined_status(rows: list[dict[str, Any]], criterion: AcceptanceCriterion) -> str:
    statuses = {_row_status(row, criterion) for row in rows}
    # Infrastructure failures block selection even if a reviewer claims a defect.
    # A positive review can never rescue a deterministic failure.
    for status in ("BLOCKED", "UNMET", "STALE", "UNKNOWN", "MET"):
        if status in statuses:
            return status
    return "UNKNOWN"


def _node_status(expectations: list[dict[str, Any]], fallback: str = "UNKNOWN") -> str:
    statuses = {row["status"] for row in expectations}
    for status in ("UNMET", "BLOCKED", "STALE", "UNKNOWN", "MET"):
        if status in statuses:
            return status
    return fallback


def criterion_status(
    criterion: AcceptanceCriterion, rows: Iterable[Mapping[str, Any]]
) -> str:
    """Project raw recorded criterion rows without manufacturing semantic evidence."""
    recorded = [dict(row) for row in rows]
    if criterion.kind is AssertionKind.NATURAL_LANGUAGE and any(
        isinstance(row.get("status"), str)
        and row["status"] in _STATES and row.get("evidence") for row in recorded
    ):
        recorded = [
            row for row in recorded
            if row.get("executed") is not False or row.get("error_code") or row.get("blocked_by")
        ]
    return _combined_status(recorded, criterion)


def build_snapshot(
    bundle: SpecBundle,
    commit: str,
    *,
    criteria: Iterable[Mapping[str, Any]] = (),
    semantic_criteria: Iterable[Mapping[str, Any]] = (),
    node_evidence: Mapping[str, Iterable[Mapping[str, Any]]] | None = None,
    node_states: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Bind current evidence to a commit without inferring satisfaction from execution.

    Current final-audit rows supersede cached node rows by criterion ID. Tier-1
    natural-language placeholders do not veto an actual semantic review; executable
    Tier-1 failures always veto positive review. STALE invalidates only cached rows.
    Node state alone can never establish MET or UNMET. Missing evidence behind an
    unestablished dependency is BLOCKED rather than UNKNOWN.
    """
    _definitions(bundle)
    deterministic = _rows_by_id(criteria)
    semantic = _rows_by_id(semantic_criteria)
    states = node_states or {}
    cached = node_evidence or {}
    nodes: list[dict[str, Any]] = []
    by_node: dict[str, dict[str, Any]] = {}
    failed: set[str] = set()
    for node_id in bundle.plan.topo_order():
        node = bundle.plan.node(node_id)
        previous = _rows_by_id(cached.get(node_id, ()))
        expectations: list[dict[str, Any]] = []
        blocked = any(by_node[dep]["status"] != "MET" for dep in node.deps)
        state = states.get(node_id, "UNKNOWN")
        for criterion in _expectations(bundle, node):
            key = criterion.criterion_id
            final_rows = deterministic.get(key, []) + semantic.get(key, [])
            if final_rows:
                rows = final_rows
                status = criterion_status(criterion, rows)
                source = "final"
            elif state == "STALE":
                rows, status, source = previous.get(key, []), "STALE", "state"
            elif previous.get(key):
                rows = previous[key]
                status, source = criterion_status(criterion, rows), "node"
            else:
                rows, source = [], "state" if state in _STATES - {"UNKNOWN"} else "none"
                status = "BLOCKED" if state == "BLOCKED" or blocked else "UNKNOWN"
            checks = behavior_check_results(criterion, rows)
            if checks and status not in {"STALE", "BLOCKED"}:
                if any(check["status"] == "UNKNOWN" for check in checks):
                    status = "BLOCKED" if rows else "UNKNOWN"
                elif any(check["status"] == "UNMET" for check in checks):
                    status = "UNMET"
            if status == "UNKNOWN" and blocked:
                status = "BLOCKED"
            if status in {"STALE", "BLOCKED"}:
                checks = [{**check, "status": status} for check in checks]
            expectations.append({
                "criterion_id": key,
                "statement": criterion.statement or criterion.command or criterion.path,
                "status": status,
                "evidence": {"source": source, "rows": deepcopy(rows)},
                **({"checks": checks} if checks else {}),
            })
            if status == "UNMET":
                failed.add(key)
        record = {
            "node_id": node_id,
            "status": _node_status(expectations),
            "score": sum(row["status"] == "MET" for row in expectations) / len(expectations)
            if expectations else 0.0,
            "expectations": expectations,
            "deps": list(node.deps),
        }
        nodes.append(record)
        by_node[node_id] = record
    snapshot = {
        "spec_digest": bundle.digest(),
        "commit": commit,
        "nodes": nodes,
        "failed_criteria": sorted(failed),
    }
    return {**snapshot, "digest": digest_of(snapshot)}


def _paths_overlap(left: str, right: str) -> bool:
    left, right = normalize_path(left), normalize_path(right)
    if not left or not right:
        return False
    if path_matches(left, right) or path_matches(right, left):
        return True
    if left.startswith(right + "/") or right.startswith(left + "/"):
        return True
    # Artifact globs can intersect without matching one another as literal strings.
    # Conservatively use their fixed directory prefixes; never invent writable paths.
    if any(char in left + right for char in "*?"):
        def directory_prefix(path: str) -> str:
            segments = []
            for segment in path.split("/"):
                if "*" in segment or "?" in segment:
                    break
                segments.append(segment)
            return "/".join(segments)
        a, b = directory_prefix(left), directory_prefix(right)
        return not a or not b or a == b or a.startswith(b + "/") or b.startswith(a + "/")
    return False


def affected_nodes(
    bundle: SpecBundle, node_id: str, changed_files: Iterable[str] = ()
) -> tuple[str, ...]:
    """Invalidate downstream and shared-artifact owners to a fixed point.

    Actual changed paths add owners even when they were not predicted by the selected
    node. The returned order is the original DAG's deterministic topological order.
    """
    bundle.plan.node(node_id)  # Unknown owners must not silently produce an empty scope.
    changed = tuple(changed_files)
    affected = {node_id}
    for node in bundle.plan.nodes:
        if any(_paths_overlap(path, artifact)
               for path in changed for artifact in node.expected_artifacts):
            affected.add(node.node_id)
    while True:
        before = set(affected)
        artifacts = tuple(path for node in bundle.plan.nodes if node.node_id in affected
                          for path in node.expected_artifacts)
        for node in bundle.plan.nodes:
            if affected.intersection(node.deps) or any(
                _paths_overlap(path, other)
                for path in node.expected_artifacts for other in artifacts
            ):
                affected.add(node.node_id)
        if before == affected:
            break
    return tuple(node_id for node_id in bundle.plan.topo_order() if node_id in affected)


def _snapshot_nodes(bundle: SpecBundle, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    if snapshot.get("spec_digest") != bundle.digest():
        raise ValueError("snapshot does not describe the frozen spec")
    if snapshot.get("digest") != digest_of({k: v for k, v in snapshot.items() if k != "digest"}):
        raise ValueError("snapshot evidence digest mismatch")
    return {row["node_id"]: row for row in snapshot["nodes"]}


def _owners(bundle: SpecBundle, criterion: AcceptanceCriterion) -> set[str]:
    explicit = {node.node_id for node in bundle.plan.nodes
                if any(c.criterion_id == criterion.criterion_id for c in node.acceptance_criteria)}
    if explicit:
        return explicit
    inherited = [node for node in bundle.plan.nodes if not node.acceptance_criteria]
    if criterion.path:
        return {node.node_id for node in inherited if any(
            _paths_overlap(criterion.path, path) for path in node.expected_artifacts
        )}
    # A global command in a multi-owner inherited plan has no concrete attribution.
    return {inherited[0].node_id} if len(inherited) == 1 else set()


def select_candidates(
    bundle: SpecBundle, snapshot: Mapping[str, Any], *, excluded: Iterable[str] = ()
) -> list[dict[str, Any]]:
    """Select concrete original owners, never uncertainty or infrastructure repairs."""
    definitions = _definitions(bundle)
    records = _snapshot_nodes(bundle, snapshot)
    excluded_ids = set(excluded)
    order = bundle.plan.topo_order()
    repairs: dict[str, list[str]] = {}
    for node_id in order:
        node = bundle.plan.node(node_id)
        if not node.expected_artifacts:
            continue
        for row in records[node_id]["expectations"]:
            key = row["criterion_id"]
            if row["status"] != "UNMET" or node_id not in _owners(bundle, definitions[key]):
                continue
            evidence_rows = row.get("evidence", {}).get("rows", [])
            if not evidence_rows or criterion_status(definitions[key], evidence_rows) != "UNMET":
                continue
            repairs.setdefault(node_id, []).append(key)
    ancestors: dict[str, set[str]] = {}
    for node_id in order:
        ancestors[node_id] = set(bundle.plan.node(node_id).deps)
        for dep in bundle.plan.node(node_id).deps:
            ancestors[node_id].update(ancestors[dep])
    candidates = []
    for node_id, criterion_ids in repairs.items():
        # Exclusion does not make a still-broken prerequisite safe to ignore.
        if node_id in excluded_ids or ancestors[node_id].intersection(repairs):
            continue
        candidates.append({
            "node_id": node_id,
            "affected_node_ids": list(affected_nodes(bundle, node_id)),
            "criterion_ids": sorted(set(criterion_ids)),
            "reason": "concrete unmet original expectations: "
            + ", ".join(sorted(set(criterion_ids))),
        })
    rank = {node_id: index for index, node_id in enumerate(order)}
    return sorted(
        candidates, key=lambda row: (len(row["affected_node_ids"]), -rank[row["node_id"]])
    )


def validation_criteria(
    bundle: SpecBundle, candidate: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> tuple[AcceptanceCriterion, ...]:
    """Use exact affected definitions plus already-established original goal checks.

    Unrelated known-UNMET goal assertions are not appended. A node inheriting the
    whole goal still retains that exact frozen gate contract; it is never narrowed.
    """
    _definitions(bundle)
    records = _snapshot_nodes(bundle, snapshot)
    selected = str(candidate["node_id"])
    affected = set(affected_nodes(bundle, selected))
    for node_id in candidate.get("affected_node_ids", ()):
        bundle.plan.node(node_id)
        affected.update(affected_nodes(bundle, node_id))
    criteria: dict[str, AcceptanceCriterion] = {}
    for node_id in bundle.plan.topo_order():
        if node_id in affected:
            for criterion in _expectations(bundle, bundle.plan.node(node_id)):
                criteria.setdefault(criterion.criterion_id, criterion)
    for criterion in bundle.goal.acceptance_criteria:
        statuses = [row["status"] for record in records.values() for row in record["expectations"]
                    if row["criterion_id"] == criterion.criterion_id]
        if statuses and set(statuses) == {"MET"}:
            criteria.setdefault(criterion.criterion_id, criterion)
    return tuple(criteria.values())
