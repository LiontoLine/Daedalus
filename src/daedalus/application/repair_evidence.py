"""Pure evidence projection and bounded repair selection over the original frozen DAG.

Scores measure observed MET coverage only. Neither scores nor this projection authorize
promotion, replace the full goal audit, or change FSM state.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from copy import deepcopy
from typing import Any

from daedalus.application.requirement_evidence import behavior_check_results, is_behavior
from daedalus.domain.canonical import digest_of
from daedalus.domain.pathglob import normalize_path, path_matches
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, PlanNode, SpecBundle
from daedalus.infrastructure.redact import redact_text

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
        if previous is not None and previous is not criterion and previous.to_dict() != criterion.to_dict():
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
        **({"integrated_criteria": deepcopy([c.to_dict() for c in bundle.goal.acceptance_criteria])}
           if bundle.plan.integrated_acceptance else {}),
    }


def normalize_semantic_criterion(row: Mapping[str, Any]) -> dict[str, Any]:
    """Keep reviewer assertions separate from controller execution receipts."""
    return {
        **{key: deepcopy(row[key]) for key in (
            "criterion_id", "status", "evidence", "evidence_refs"
        ) if key in row},
        "evidence_type": "semantic",
    }


def _rows_by_id(
    rows: Iterable[Mapping[str, Any]], *, evidence_type: str | None = None
) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("criterion_id"), str):
            continue
        recorded = (normalize_semantic_criterion(row) if evidence_type == "semantic"
                    else {**deepcopy(dict(row)), **(
                        {"evidence_type": evidence_type} if evidence_type else {}
                    )})
        indexed.setdefault(row["criterion_id"], []).append(recorded)
    return indexed


def _evidence_type(row: Mapping[str, Any]) -> str:
    # Untyped historical reviewer assertions remain semantic, never execution facts.
    return row.get("evidence_type", "semantic" if "status" in row and "evidence" in row
                   else "deterministic")


def settled_acceptance(row: Mapping[str, Any]) -> bool:
    """A binary result requires actual execution and, if frozen, a complete receipt."""
    if (type(row.get("ok")) is not bool or row.get("error_code")
            or row.get("blocked_by") or row.get("executed") is False):
        return False
    behavior = row.get("behavior_evidence")
    if behavior is None:
        return True
    receipt = behavior.get("receipt") if isinstance(behavior, Mapping) else None
    return isinstance(receipt, Mapping) and receipt.get("complete") is True


def _row_status(row: Mapping[str, Any], criterion: AcceptanceCriterion) -> str:
    if _evidence_type(row) == "semantic":
        status, evidence = row.get("status"), row.get("evidence")
        return status if (isinstance(status, str) and status in {"MET", "UNMET", "UNKNOWN"}
                          and isinstance(evidence, str) and evidence.strip()) else "UNKNOWN"
    # Execution/infrastructure failures are never evidence of a repairable code defect.
    if row.get("error_code") or row.get("blocked_by"):
        return "BLOCKED"
    status = row.get("status") if isinstance(row.get("status"), str) else None
    if status in {"UNKNOWN", "BLOCKED", "STALE"}:
        return str(status)
    if settled_acceptance(row):
        if criterion.kind is AssertionKind.NATURAL_LANGUAGE and not row.get("behavior_evidence"):
            return "UNKNOWN"
        return "MET" if row["ok"] else "UNMET"
    # A deterministic row cannot manufacture a reviewer assertion.
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
        _evidence_type(row) == "semantic"
        and _row_status(row, criterion) != "UNKNOWN" for row in recorded
    ):
        recorded = [
            row for row in recorded
            if (_evidence_type(row) == "semantic" or row.get("executed") is not False
                or row.get("error_code") or row.get("blocked_by"))
        ]
    return _combined_status(recorded, criterion)


def _project_expectation(
    criterion: AcceptanceCriterion, rows: list[dict[str, Any]], *,
    source: str, blocked: bool, state: str = "UNKNOWN",
) -> dict[str, Any]:
    if source in {"final", "node"}:
        status = criterion_status(criterion, rows)
    elif state == "STALE":
        status = "STALE"
    else:
        status = "BLOCKED" if state == "BLOCKED" or blocked else "UNKNOWN"
    checks = behavior_check_results(
        criterion, [row for row in rows if _evidence_type(row) == "deterministic"]
    )
    if checks and status not in {"STALE", "BLOCKED"}:
        if any(check["status"] == "UNKNOWN" for check in checks):
            status = "BLOCKED" if rows else "UNKNOWN"
        elif any(check["status"] == "UNMET" for check in checks):
            status = "UNMET"
    if status == "UNKNOWN" and blocked:
        status = "BLOCKED"
    if status in {"STALE", "BLOCKED"}:
        checks = [{**check, "status": status} for check in checks]
    return {
        "criterion_id": criterion.criterion_id,
        "statement": criterion.statement or criterion.command or criterion.path,
        "status": status,
        "evidence": {"source": source, "rows": deepcopy(rows)},
        **({"checks": checks} if checks else {}),
    }


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
    deterministic = _rows_by_id(criteria, evidence_type="deterministic")
    semantic = _rows_by_id(semantic_criteria, evidence_type="semantic")
    states = node_states or {}
    cached = node_evidence or {}
    nodes: list[dict[str, Any]] = []
    by_node: dict[str, dict[str, Any]] = {}
    failed: set[str] = set()
    for node_id in bundle.plan.topo_order():
        node = bundle.plan.node(node_id)
        previous = _rows_by_id(cached.get(node_id, ()), evidence_type="deterministic")
        expectations: list[dict[str, Any]] = []
        blocked = any(by_node[dep]["status"] != "MET" for dep in node.deps)
        state = states.get(node_id, "UNKNOWN")
        for criterion in _expectations(bundle, node):
            key = criterion.criterion_id
            final_rows = deterministic.get(key, []) + semantic.get(key, [])
            if final_rows:
                rows, source = final_rows, "final"
            elif state == "STALE":
                rows, source = previous.get(key, []), "state"
            elif previous.get(key):
                rows, source = previous[key], "node"
            else:
                rows, source = [], "state" if state in _STATES - {"UNKNOWN"} else "none"
            expectation = _project_expectation(
                criterion, rows, source=source, blocked=blocked, state=state
            )
            expectations.append(expectation)
            if expectation["status"] == "UNMET":
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
    integration = []
    if bundle.plan.integrated_acceptance:
        for criterion in bundle.goal.acceptance_criteria:
            key = criterion.criterion_id
            rows = deterministic.get(key, []) + semantic.get(key, [])
            expectation = _project_expectation(
                criterion, rows, source="final" if rows else "none", blocked=False,
            )
            integration.append(expectation)
            if expectation["status"] == "UNMET":
                failed.add(key)
    snapshot = {
        "spec_digest": bundle.digest(),
        "commit": commit,
        "nodes": nodes,
        "failed_criteria": sorted(failed),
        **({"integrated_expectations": integration} if bundle.plan.integrated_acceptance else {}),
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
    """Validate a frozen projection, not authenticate or re-execute its evidence."""
    if not isinstance(snapshot, Mapping) or snapshot.get("spec_digest") != bundle.digest():
        raise ValueError("snapshot does not describe the frozen spec")
    if snapshot.get("digest") != digest_of({k: v for k, v in snapshot.items() if k != "digest"}):
        raise ValueError("snapshot evidence digest mismatch")

    def invalid() -> None:
        raise ValueError("malformed frozen snapshot projection")

    nodes = snapshot.get("nodes")
    if not isinstance(snapshot.get("commit"), str) or not isinstance(nodes, list):
        invalid()
    order = bundle.plan.topo_order()
    if (len(nodes) != len(order) or any(not isinstance(row, dict) for row in nodes)
            or [row.get("node_id") for row in nodes] != list(order)):
        invalid()
    final: dict[str, list[dict[str, Any]]] = {}
    cached: dict[str, list[dict[str, Any]]] = {}
    states: dict[str, str] = {}
    for record in nodes:
        node_id = record["node_id"]
        node = bundle.plan.node(node_id)
        expectations = record.get("expectations")
        if (record.get("deps") != list(node.deps)
                or not isinstance(record.get("status"), str) or record["status"] not in _STATES
                or type(record.get("score")) not in {int, float}
                or not isinstance(expectations, list)
                or any(not isinstance(row, dict) for row in expectations)
                or [row.get("criterion_id") for row in expectations] != [
                    c.criterion_id for c in _expectations(bundle, node)]):
            invalid()
        definitions = {c.criterion_id: c for c in _expectations(bundle, node)}
        if len(definitions) != len(expectations):
            invalid()
        state_observations = []
        for expectation in expectations:
            key = expectation["criterion_id"]
            status, evidence = expectation.get("status"), expectation.get("evidence")
            if (not isinstance(status, str) or status not in _STATES
                    or not isinstance(evidence, dict)):
                invalid()
            source, rows = evidence.get("source"), evidence.get("rows")
            if (not isinstance(source, str) or source not in {"final", "node", "state", "none"}
                    or not isinstance(rows, list)
                    or (source in {"final", "node"} and not rows)
                    or (source == "none" and rows)
                    or (source == "state" and rows and status != "STALE")):
                invalid()
            for row in rows:
                if (not isinstance(row, dict) or row.get("criterion_id") != key
                        or row.get("evidence_type") not in ("deterministic", "semantic")):
                    invalid()
                if row["evidence_type"] == "semantic":
                    if source != "final" or row != normalize_semantic_criterion(row):
                        invalid()
                    if (not isinstance(row.get("status"), str)
                            or row["status"] not in {"MET", "UNMET", "UNKNOWN"}
                            or not isinstance(row.get("evidence"), str)
                            or not row["evidence"].strip()
                            or ("evidence_refs" in row and (
                                not isinstance(row["evidence_refs"], list)
                                or any(not isinstance(ref, str) for ref in row["evidence_refs"])
                            ))):
                        invalid()
                else:
                    criterion = definitions[key]
                    if (("kind" in row and row["kind"] != criterion.kind.value)
                            or ("command" in row
                                and row["command"] != (criterion.command or criterion.path))
                            or ("criterion_digest" in row
                                and row["criterion_digest"] != digest_of(criterion.to_dict()))):
                        invalid()
                    if any(name in row and type(row[name]) is not bool
                           for name in ("ok", "executed")):
                        invalid()
                    if "status" in row and (
                        not isinstance(row["status"], str) or row["status"] not in _STATES
                    ):
                        invalid()
            if source == "final":
                if key in final and final[key] != rows:
                    invalid()
                final[key] = rows
            else:
                cached.setdefault(node_id, []).extend(rows)
            if source == "state":
                state_observations.append(status)
        if state_observations:
            # Only invalidation/blocking may come from node state; MET/UNMET
            # cannot. The full replay below checks this jointly with dependencies.
            states[node_id] = ("STALE" if "STALE" in state_observations else
                               "BLOCKED" if "BLOCKED" in state_observations else "MET")
    if bundle.plan.integrated_acceptance:
        integration = snapshot.get("integrated_expectations")
        expected = {criterion.criterion_id: criterion for criterion in bundle.goal.acceptance_criteria}
        if not isinstance(integration, list) or len(integration) != len(expected):
            invalid()
        for record in integration:
            if (not isinstance(record, dict) or not isinstance(record.get("criterion_id"), str)
                    or record["criterion_id"] not in expected):
                invalid()
            key = record["criterion_id"]
            evidence = record.get("evidence")
            rows = evidence.get("rows") if isinstance(evidence, dict) else None
            if not isinstance(rows, list):
                invalid()
            criterion = expected[key]
            for row in rows:
                if (not isinstance(row, dict) or row.get("criterion_id") != key
                        or row.get("evidence_type") not in {"deterministic", "semantic"}):
                    invalid()
                if row["evidence_type"] == "deterministic" and (
                    row.get("kind", criterion.kind.value) != criterion.kind.value
                    or row.get("command", criterion.command or criterion.path)
                    != (criterion.command or criterion.path)
                    or any(name in row and type(row[name]) is not bool
                           for name in ("ok", "executed"))
                ):
                    invalid()
                if row["evidence_type"] == "semantic" and (
                    row != normalize_semantic_criterion(row)
                    or not isinstance(row.get("status"), str)
                    or row["status"] not in {"MET", "UNMET", "UNKNOWN"}
                    or not isinstance(row.get("evidence"), str) or not row["evidence"].strip()
                ):
                    invalid()
            if rows:
                final[key] = rows
    deterministic = [row for rows in final.values() for row in rows
                     if row["evidence_type"] == "deterministic"]
    semantic = [row for rows in final.values() for row in rows
                if row["evidence_type"] == "semantic"]
    projected = build_snapshot(
        bundle, snapshot["commit"], criteria=deterministic, semantic_criteria=semantic,
        node_evidence=cached, node_states=states,
    )
    if snapshot != projected:
        invalid()
    return {row["node_id"]: row for row in nodes}


def _owners(bundle: SpecBundle, criterion: AcceptanceCriterion) -> set[str]:
    explicit = {node.node_id for node in bundle.plan.nodes
                if any(c.criterion_id == criterion.criterion_id for c in node.acceptance_criteria)}
    if explicit:
        return explicit
    inherited = [node for node in bundle.plan.nodes
                 if bundle.plan.integrated_acceptance or not node.acceptance_criteria]
    if criterion.path:
        if bundle.plan.integrated_acceptance and is_behavior(criterion):
            return {node.node_id for node in inherited if criterion.path in node.expected_artifacts}
        return {node.node_id for node in inherited if any(
            _paths_overlap(criterion.path, path) for path in node.expected_artifacts
        )}
    # A global command in a multi-owner inherited plan has no concrete attribution.
    if bundle.plan.integrated_acceptance:
        return set()
    return {inherited[0].node_id} if len(inherited) == 1 else set()


def _accepts_native_attribution(criterion: AcceptanceCriterion, expectation: Mapping[str, Any]) -> bool:
    return not is_behavior(criterion) or any(
        check["status"] == "UNMET" for check in expectation.get("checks", ())
    )


def select_candidates(
    bundle: SpecBundle, snapshot: Mapping[str, Any], *, excluded: Iterable[str] = ()
) -> list[dict[str, Any]]:
    """Select concrete original owners, never uncertainty or infrastructure repairs."""
    return _select_candidates(bundle, snapshot, _definitions(bundle), _snapshot_nodes(bundle, snapshot), excluded)


def _select_candidates(
    bundle: SpecBundle,
    snapshot: Mapping[str, Any],
    definitions: dict[str, AcceptanceCriterion],
    records: dict[str, Any],
    excluded: Iterable[str],
) -> list[dict[str, Any]]:
    excluded_ids = set(excluded)
    order = tuple(records)
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
    for row in snapshot.get("integrated_expectations", ()):
        key = row["criterion_id"]
        criterion = definitions[key]
        owners = _owners(bundle, criterion)
        if (len(owners) == 1 and row["status"] == "UNMET"
                and _accepts_native_attribution(criterion, row)
                and criterion_status(criterion, row["evidence"]["rows"]) == "UNMET"):
            repairs.setdefault(next(iter(owners)), []).append(key)
    if not repairs:
        return []
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
        selected_criteria = sorted(set(criterion_ids))
        candidates.append({
            "node_id": node_id,
            "affected_node_ids": list(affected_nodes(bundle, node_id)),
            "criterion_ids": selected_criteria,
            "reason": "concrete unmet original expectations: " + ", ".join(selected_criteria),
        })
    rank = {node_id: index for index, node_id in enumerate(order)}
    return sorted(
        candidates, key=lambda row: (len(row["affected_node_ids"]), -rank[row["node_id"]])
    )


def diagnose_criteria(
    bundle: SpecBundle, snapshot: Mapping[str, Any], *, excluded: Iterable[str] = ()
) -> dict[str, Any]:
    """Explain non-MET frozen expectations without adding selection authority.

    Only whitelisted provenance and redacted excerpts leave this projection. Missing,
    stale and blocked evidence is retained as uncertainty, never as a code defect.
    The complete snapshot remains the authority when this bounded view omits rows.
    """
    definitions = _definitions(bundle)
    records = _snapshot_nodes(bundle, snapshot)
    selected = {
        row["node_id"]: set(row["criterion_ids"])
        for row in _select_candidates(bundle, snapshot, definitions, records, excluded)
    }
    order = tuple(records)
    clipped = False

    def text(value: Any, limit: int = 128) -> str:
        nonlocal clipped
        value = redact_text(str(value))
        clipped = clipped or len(value) > limit
        return value[:limit]

    result: dict[str, Any] = {
        "spec_digest": bundle.digest(), "commit": text(snapshot["commit"]),
        "snapshot_digest": snapshot["digest"], "authority": "diagnostic_only",
        "criteria": [], "criteria_omitted": 0,
    }
    used = 0
    observed: dict[str, list[tuple[str, dict]]] = {}
    for node_id, node in records.items():
        for row in node["expectations"]:
            observed.setdefault(row["criterion_id"], []).append((node_id, row))
    integrated = {row["criterion_id"]: row for row in snapshot.get("integrated_expectations", ())}
    for key, row in integrated.items():
        observed.setdefault(key, []).append(("", row))
    inherited = {node.node_id for node in bundle.plan.nodes if not node.acceptance_criteria}
    affected_by_node: dict[str, tuple[str, ...]] = {}
    for key, criterion in definitions.items():
        observations = observed.get(key, ())
        statuses = {row["status"] for _, row in observations}
        if statuses == {"MET"}:
            continue
        status = next((state for state in ("BLOCKED", "UNMET", "STALE", "UNKNOWN")
                       if state in statuses), "UNKNOWN")
        owners = _owners(bundle, criterion)
        ambiguous = not owners and not criterion.path and len(inherited) > 1
        possible = owners or (inherited if ambiguous else ())
        candidates = []
        for node_id in order:
            if node_id not in possible:
                continue
            node = bundle.plan.node(node_id)
            explicit = any(c.criterion_id == key for c in node.acceptance_criteria)
            if node_id not in affected_by_node:
                affected_by_node[node_id] = affected_nodes(bundle, node_id)
            affected = affected_by_node[node_id]
            matched = [path for path in node.expected_artifacts
                       if criterion.path and _paths_overlap(criterion.path, path)]
            candidates.append({
                "node_id": text(node_id),
                "ownership_basis": "explicit_criterion" if explicit else (
                    "inherited_path_overlap" if criterion.path else
                    "ambiguous_inherited_global" if ambiguous else "sole_inherited_owner"
                ),
                "matched_frozen_paths": [text(path, 160) for path in matched[:8]],
                "matched_paths_omitted": max(0, len(matched) - 8),
                "affected_node_ids": [text(item) for item in affected[:16]],
                "affected_nodes_omitted": max(0, len(affected) - 16),
                "selected": key in selected.get(node_id, set()) and node_id in owners,
            })
        provenance = []
        total_rows = 0
        for node_id, observation in observations:
            evidence = observation.get("evidence", {})
            rows = evidence.get("rows", [])
            total_rows += max(1, len(rows))
            for row in rows or [{}]:
                if len(provenance) >= 8:
                    break
                provenance.append({
                    "node_id": text(node_id), "status": observation["status"],
                    "source": text(evidence.get("source", "none")),
                    "row_status": _row_status(row, criterion),
                    "evidence_type": _evidence_type(row) if rows else "none",
                    "executed": row.get("executed") if (
                        _evidence_type(row) == "deterministic"
                        and isinstance(row.get("executed"), bool)
                    ) else None,
                    "error_code": text(row.get("error_code", "")) if (
                        _evidence_type(row) == "deterministic"
                    ) else "",
                    "blocked_by": text(row.get("blocked_by", "")) if (
                        _evidence_type(row) == "deterministic"
                    ) else "",
                    "evidence": text(row.get("evidence", row.get("output", "")), 240),
                })
        reason = (
            "infrastructure_or_dependency_blocked" if status == "BLOCKED" else
            "stale_evidence" if status == "STALE" else
            "missing_or_unknown_evidence" if status == "UNKNOWN" else
            "ambiguous_global_ownership" if ambiguous else
            "integrated_check_has_no_node_owner" if key in integrated and not owners else
            "no_executed_behavior_failure" if key in integrated
            and not _accepts_native_attribution(criterion, integrated[key]) else
            "no_frozen_owner" if not owners else
            "no_declared_output_scope" if not any(bundle.plan.node(n).expected_artifacts for n in owners)
            else "excluded_or_failed_prerequisite"
            if not any(key in selected.get(n, set()) for n in owners) else ""
        )
        entry = {
            "criterion_id": text(key), "status": status,
            "owner_candidates": candidates[:8],
            "owners_omitted": max(0, len(candidates) - 8),
            "evidence_provenance": provenance,
            "evidence_rows_omitted": max(0, total_rows - len(provenance)),
            "ambiguity_reason": "global criterion has multiple inherited owners; no owner selected"
            if ambiguous else "",
            "non_repairable_reason": reason,
        }
        size = len(json.dumps(entry, ensure_ascii=False))
        if len(result["criteria"]) < 24 and used + size <= 12000:
            result["criteria"].append(entry)
            used += size
        else:
            result["criteria_omitted"] += 1
    result["truncated"] = bool(clipped or result["criteria_omitted"] or any(
        row["owners_omitted"] or row["evidence_rows_omitted"]
        or any(owner["matched_paths_omitted"] or owner["affected_nodes_omitted"]
               for owner in row["owner_candidates"])
        for row in result["criteria"]
    ))
    return result


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
    integrated_by_id = {row["criterion_id"]: row for row in snapshot.get("integrated_expectations", ())}
    for criterion in bundle.goal.acceptance_criteria:
        integrated = integrated_by_id.get(criterion.criterion_id)
        if integrated is not None and (
            integrated["status"] == "MET"
            or (criterion.criterion_id in candidate.get("criterion_ids", ())
                and _owners(bundle, criterion) == {selected})
        ):
            criteria.setdefault(criterion.criterion_id, criterion)
        statuses = [row["status"] for record in records.values() for row in record["expectations"]
                    if row["criterion_id"] == criterion.criterion_id]
        if statuses and set(statuses) == {"MET"}:
            criteria.setdefault(criterion.criterion_id, criterion)
    return tuple(criteria.values())
