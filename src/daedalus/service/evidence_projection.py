"""Public summaries of detached controller evidence, not verification inputs."""
from __future__ import annotations

from daedalus.application.requirement_evidence import (
    project_behavior_results,
    public_criterion_preview,
)


def _goal_stage(stage: dict) -> None:
    project_behavior_results(stage)
    project_behavior_results(stage.get("deterministic", {}).get("evidence", {}))


def public_goal_audit(view: dict) -> dict:
    for stage in view.get("stages", ()):
        _goal_stage(stage)
    return view


def public_validation_report(report: dict) -> dict:
    project_behavior_results(report.get("criteria", {}).get("evidence", {}))
    criteria = report.get("goal", {}).get("acceptance_criteria", [])
    criteria[:] = [public_criterion_preview(criterion) for criterion in criteria]
    return report


def public_validation_view(view: dict) -> dict:
    for report in view.get("reports", ()):
        public_validation_report(report)
    return view


def _expectations(rows: list[dict]) -> None:
    for index, row in enumerate(rows):
        rows[index] = public_criterion_preview(row)
        for check in row.get("checks", ()):
            check.pop("test_name", None)
        project_behavior_results({"criteria": row.get("evidence", {}).get("rows", ())})


def _snapshot(snapshot: dict) -> None:
    for node in snapshot.get("nodes", ()):
        _expectations(node.get("expectations", []))
    _expectations(snapshot.get("integrated_expectations", []))


def _branch_validation(branch: dict) -> None:
    validation = branch.get("validation", {})
    project_behavior_results(validation)
    if "snapshot" in validation:
        _snapshot(validation["snapshot"])


def _contract(contract: dict) -> None:
    _snapshot(contract)
    _expectations(contract.get("integrated_criteria", []))


def public_trunk(view: dict) -> dict:
    contract = view.get("contract")
    if contract:
        _contract(contract)
    _snapshot(view)
    for snapshot in view.get("snapshots", ()):
        _snapshot(snapshot)
    for candidate in view.get("candidates", ()):
        _snapshot(candidate["snapshot"])
    for branch in view.get("branches", ()):
        _branch_validation(branch)
        for event in branch.get("events", ()):
            _branch_validation(event["payload"])
    return view


def public_event_payload(kind: str, payload: dict) -> dict:
    if kind == "TrunkExpectationsFrozen":
        _contract(payload)
    elif kind == "GoalTrunkSnapshot":
        _snapshot(payload)
    elif kind == "GoalAuditCompleted":
        _goal_stage(payload)
    elif kind == "IndependentValidationEvaluated":
        public_validation_report(payload)
    elif kind in {"TrunkNodeValidated", "TrunkNodeFailed"}:
        project_behavior_results(payload)
    elif kind in {"RepairBranchStarted", "RepairBranchRejected", "RepairBranchPromoted"}:
        _branch_validation(payload)
    return payload
