"""Admission for one explicitly authorized, historical-task development replay."""
from __future__ import annotations

import hashlib
import json
import math
import re

from daedalus.application.realwork_workers import baseline_path
from daedalus.application.upstream_contract import admit_contract
from daedalus.infrastructure.sandbox import SeatbeltDriver
from daedalus.service.capability_budget import amended_parent_cost, json_digest

STUDY = "known-task-development-replay-v1"
PHASE = "known-task-replay"
COMPARISON_JOB = "realwork_cycle_20261027T235935040925_81be3c20"
SELECTION_DIGEST = "5dda683b0553f2bcd30c444b186a13f682da381cc3f459bb5d8d1b89d8ad8eae"
AUTHORIZATION = {
    "scope": "replay-only", "max_cost_cny": 1, "available_balance_cny": 3.68,
    "source": "User explicitly selected 新增上限1元 on 2026-10-30 for latest "
              "three sealed tasks; no automatic expansion",
}
SHARED_STUDIES = {
    "capability-cycle-v1", "capability-cycle-transport-v1",
    "worker-efficiency-v1", "worker-efficiency-v2", STUDY,
}


def _read(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("expected an immutable JSON object")
    return value


def _frozen(path, expected=None):
    value = _read(path)
    digest = value.get("sha256")
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or json_digest({k: v for k, v in value.items() if k != "sha256"}) != digest
            or (expected is not None and digest != expected)):
        raise ValueError("frozen plan digest does not match")
    return value


def _validate_ledger(ledger):
    if not isinstance(ledger, dict) or not isinstance(ledger.get("call_records"), list):
        raise ValueError("parent spend is incomplete")
    for record in ledger["call_records"]:
        if not isinstance(record, dict):
            raise ValueError("invalid provider receipt")
        for name in ("prompt_tokens", "completion_tokens"):
            value = record.get(name, 0)
            if type(value) is not int or value < 0:
                raise ValueError("invalid provider token count")
        for name in ("usage_available", "request_dispatched"):
            if name in record and type(record[name]) is not bool:
                raise ValueError("invalid provider usage state")


def admit_replay(data, project, root, requested_digest):
    """Validate local evidence before constructing any paid model client.

    Only the seven frozen parents may occupy the shared five-CNY study. The
    comparison is historical, not a concurrent baseline or a heldout sample.
    """
    plan = _frozen(data / "diagnostics/known-task-replay-20261030/frozen-plan.json",
                   requested_digest)
    compact = _frozen(data / "diagnostics/worker-efficiency-20261028/compact-plan.json",
                      SELECTION_DIGEST)
    fixed = {
        "version": 1, "study": STUDY, "phase": PHASE, "max_cost_cny": 1,
        "user_authorized_cap_cny": 1, "reserve_cny": 0,
        "authorization": AUTHORIZATION, "comparison_job_id": COMPARISON_JOB,
        "comparison_arm": "optimized", "selection_plan_sha256": compact["sha256"],
    }
    if any(plan.get(key) != value for key, value in fixed.items()):
        raise ValueError(
            "replay exceeds the fixed authorization or changes its historical comparison")
    historical = plan.get("historical_budget")
    historical_fixed = {
        "max_cost_cny": 4.5, "user_authorized_cap_cny": 5,
        "reserve_cny": 0.5, "unknown_reserved_cost_cny": 2.25,
    }
    if (not isinstance(historical, dict)
            or any(historical.get(key) != value for key, value in historical_fixed.items())
            or type(historical.get("occupied_cost_cny")) not in (int, float)
            or not math.isfinite(historical["occupied_cost_cny"])):
        raise ValueError("immutable historical budget provenance is invalid")
    if (compact.get("study") != "worker-efficiency-v2"
            or len(compact.get("batches", [])) != 1):
        raise ValueError("original compact selection is invalid")
    cases = compact["batches"][0]["cases"]
    if (len(cases) != 3 or len({case["case"] for case in cases}) != 3
            or plan.get("cases") != cases):
        raise ValueError("replay must reuse exactly the three original compact tasks in order")
    implementation = {
        str(path.relative_to(project)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (project / "src/daedalus").rglob("*.py")
    }
    if not implementation or plan.get("implementation_sha256") != implementation:
        raise ValueError("implementation no longer matches the frozen replay plan")
    parents = plan.get("parent_jobs")
    original_parents = compact.get("parent_jobs")
    if (not isinstance(parents, dict) or not isinstance(original_parents, dict)
            or len(original_parents) != 6 or len(parents) != 7
            or set(parents) != set(original_parents) | {COMPARISON_JOB}
            or any(parents[job] != source for job, source in original_parents.items())
            or parents[COMPARISON_JOB].get("unknown_reservations") != []):
        raise ValueError("replay must preserve all original parent receipts and reservations")
    baseline = baseline_path(data, "efficiency-v1")
    if hashlib.sha256(baseline.read_bytes()).hexdigest() != compact.get("baseline_worker_sha256"):
        raise ValueError("historical baseline source no longer matches")
    for case in cases:
        admit_contract(case)
        if (case.get("isolation") != "seatbelt"
                or any(proof.get("isolation") != "seatbelt"
                       for proof in case["contract_qualification"].values())):
            raise ValueError("original qualification requires native Seatbelt isolation")
    spent, seen = 0.0, set()
    comparison_protocol = None
    for folder in root.glob("realwork_*"):
        if (folder.is_dir() and folder.name.startswith(("realwork_cycle_", "realwork_replay_"))
                and not (folder / "job.json").is_file()):
            raise ValueError("shared-budget study directory has no accountable receipt")
    for job_path in root.glob("realwork_*/job.json"):
        old = _read(job_path)
        job_id = job_path.parent.name
        if old.get("job_id") != job_id:
            raise ValueError("parent receipt identity does not match its directory")
        protocol_path = job_path.parent / "results/protocol.json"
        protocol = _read(protocol_path) if protocol_path.is_file() else {}
        money = protocol.get("monetary_admission") or old.get("budget_context") or {}
        shared = (old.get("study") in SHARED_STUDIES
                  or protocol.get("study") in SHARED_STUDIES
                  or job_id.startswith(("realwork_cycle_", "realwork_replay_"))
                  or money.get("user_authorized_cap_cny") == 5
                  or money.get("max_total_cost_cny") == 4.5)
        if job_id not in parents:
            if shared:
                raise ValueError("unaccounted shared-budget receipt; no additional replay dispatch")
            continue
        old["series-usage"] = _read(job_path.parent / "results/series-usage.json")
        _validate_ledger(old["series-usage"])
        spent += amended_parent_cost(old, parents[job_id], protocol)
        seen.add(job_id)
        if job_id == COMPARISON_JOB:
            comparison_protocol = protocol
            if (old.get("study") != "worker-efficiency-v2"
                    or old.get("plan_sha256") != compact["sha256"]):
                raise ValueError("historical comparison receipt does not match the compact study")
    if (seen != set(parents) or spent > 4.5
            or not math.isclose(spent, historical["occupied_cost_cny"], rel_tol=0, abs_tol=1e-9)):
        raise ValueError("all seven sealed parents must reconcile with the historical budget")
    projection = [{key: case[key] for key in (
        "case", "base_commit", "targets", "labels", "archive_sha256", "source_chars")}
        for case in cases]
    comparison = comparison_protocol or {}
    if (comparison.get("study") != "worker-efficiency-v2"
            or comparison.get("selection_rule_sha256") != compact["sha256"]
            or comparison.get("cases") != projection
            or comparison.get("arms") != ["baseline", "optimized"]
            or (comparison.get("cycle") or {}).get("baseline_worker_sha256")
            != compact["baseline_worker_sha256"]
            or comparison.get("max_tokens_per_arm") != 30000
            or comparison.get("max_calls_per_arm") != 6):
        raise ValueError("historical comparison protocol or baseline metadata does not match")
    if not SeatbeltDriver().probe().available:
        raise ValueError("required native sandbox is unavailable; no model dispatch")
    return {
        "study": STUDY, "phase": PHASE, "plan_sha256": plan["sha256"],
        "comparison_job_id": COMPARISON_JOB, "comparison_arm": "optimized",
        "cases": cases, "selection_plan_sha256": compact["sha256"],
        "comparison_protocol_sha256": parents[COMPARISON_JOB]["protocol_sha256"],
        "parent_jobs": parents, "implementation_sha256": implementation,
        "baseline_worker_sha256": compact["baseline_worker_sha256"],
        "authorization": dict(AUTHORIZATION), "historical_budget": dict(historical),
        "price_checked": plan.get("price_checked", "2026-10-30"),
        "monetary_admission": {
            "max_total_cost_cny": 1, "prior_cost_upper_cny": 0,
            "user_authorized_cap_cny": 1, "reserve_cny": 0,
            "unknown_reserved_cost_cny": 0,
        },
    }
