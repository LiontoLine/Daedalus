"""One fixed fresh comparison; no monetary ceiling and no reuse of sealed tasks."""
from __future__ import annotations

import hashlib
import json
import re

from daedalus.application.realwork import (
    VALIDATION_ARM_CALLS,
    VALIDATION_ARM_TOKENS,
    VALIDATION_CASES,
    VALIDATION_STUDY,
)
from daedalus.application.upstream_contract import admit_contract
from daedalus.infrastructure.sandbox import SeatbeltDriver
from daedalus.service.capability_budget import json_digest

DIRECTORY = "diagnostics/step-repair-validation-20261030"


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def admit_validation(data, project, root, requested_digest):
    """Check actual inputs and prior reservations before constructing a model client."""
    folder = data / DIRECTORY
    plan = json.loads((folder / "frozen-plan.json").read_text())
    digest = plan.get("sha256")
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or digest != requested_digest
            or json_digest({k: v for k, v in plan.items() if k != "sha256"}) != digest):
        raise ValueError("frozen fresh-batch digest does not match")
    fixed = {
        "version": 1, "study": VALIDATION_STUDY,
        "phase": "fresh-paired-validation", "arms": ["single", "daedalus"],
        "max_tokens_per_arm": VALIDATION_ARM_TOKENS,
        "max_calls_per_arm": VALIDATION_ARM_CALLS,
        "no_automatic_resume": True, "stop_on_unknown_usage": True,
    }
    if any(plan.get(key) != value for key, value in fixed.items()):
        raise ValueError("fresh comparison changes its frozen resource contract")
    authorization = json.loads((folder / "authorization.json").read_text())
    if (plan.get("authorization") != authorization
            or authorization.get("scope") != "fresh-batch-only"
            or "max_cost_cny" not in authorization or authorization["max_cost_cny"] is not None
            or authorization.get("fixed_cases") != VALIDATION_CASES
            or authorization.get("arms") != fixed["arms"]
            or authorization.get("max_tokens_per_arm") != VALIDATION_ARM_TOKENS
            or authorization.get("max_calls_per_arm") != VALIDATION_ARM_CALLS
            or authorization.get("stop_on_unknown_usage") is not True
            or authorization.get("no_automatic_resume") is not True
            or not isinstance(authorization.get("source"), str)
            or not authorization["source"].strip()):
        raise ValueError("fresh-batch authorization is not the explicit no-fee-ceiling scope")
    implementation = {
        str(path.relative_to(project)): _sha256(path)
        for path in (project / "src/daedalus").rglob("*.py")
    }
    if not implementation or plan.get("implementation_sha256") != implementation:
        raise ValueError("implementation differs from the frozen experiment")
    if plan.get("selection_rule_sha256") != _sha256(folder / "selection-rule.json"):
        raise ValueError("outcome-independent task selection changed")
    qualification = json.loads((folder / "qualification.json").read_text())
    selected = [row["case"] for row in qualification if row.get("qualified") is True]
    cases = plan.get("cases", [])
    identities = [row["case"] for row in cases]
    if (len(cases) != VALIDATION_CASES or len(set(identities)) != VALIDATION_CASES
            or identities != selected[:VALIDATION_CASES]):
        raise ValueError("fresh batch must use the first six qualified tasks in frozen order")
    for case in cases:
        admit_contract(case)
        if (case.get("isolation") != "seatbelt"
                or any(proof.get("isolation") != "seatbelt"
                       for proof in case["contract_qualification"].values())
                or not re.fullmatch(r"[0-9a-f]{40}", case.get("initial_tree", ""))):
            raise ValueError("workload lacks a qualified native initial tree")
        task = data / "tasks" / case["case"] / "task.json"
        archive = data / "downloads" / (case["base_commit"] + ".tar.gz")
        if (plan.get("task_sha256", {}).get(case["case"]) != _sha256(task)
                or case["archive_sha256"] != _sha256(archive)):
            raise ValueError("task metadata or upstream archive changed")
    for job_path in root.glob("realwork_*/job.json"):
        old = json.loads(job_path.read_text())
        if old.get("study") == VALIDATION_STUDY:
            raise ValueError("fresh study already has a consumed receipt")
        reserved = set(old.get("planned_case_ids", []))
        protocol_path = job_path.parent / "results/protocol.json"
        report_path = job_path.parent / "results/report.json"
        if protocol_path.exists():
            protocol = json.loads(protocol_path.read_text())
            reserved.update(row["case"] for row in protocol.get("cases", []))
        if report_path.exists():
            report = json.loads(report_path.read_text())
            reserved.update(row["case"] for row in report.get("trials", []))
        if reserved.intersection(identities):
            raise ValueError("fresh batch overlaps a reserved or previously dispatched task")
    if not SeatbeltDriver().probe().available:
        raise ValueError("required native isolation is unavailable")
    return {
        "study": VALIDATION_STUDY, "phase": fixed["phase"], "cases": cases,
        "plan_sha256": digest, "authorization": authorization,
        "monetary_admission": None, "price_checked": plan["price_checked"],
    }
