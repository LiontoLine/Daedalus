"""API-only, bounded upstream evaluation; no reads launch or resume work."""
from __future__ import annotations

import json
import hashlib
import io
import re
import threading
import zipfile
from types import SimpleNamespace
from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from daedalus.application.realwork import DATA, catalog, run_realwork
from daedalus.application.service_lifecycle import stop_requested
from daedalus.domain.ids import new_id, utc_now
from daedalus.errors import DaedalusError
from daedalus.infrastructure.knowledge import atomic_json
from daedalus.infrastructure.git_sandbox import _git
from daedalus.infrastructure.redact import redact_text


class RealworkRequest(BaseModel):
    model_config = {"extra": "forbid"}
    confirm_paid_calls: bool = False
    max_tokens: int = Field(default=300000, ge=10000, le=300000)
    max_calls: int = Field(default=144, ge=1, le=144)


class CapabilityCycleRequest(BaseModel):
    model_config = {"extra":"forbid"}
    confirm_paid_calls: bool = False
    protocol: Literal["original", "transport-amendment-v1", "worker-efficiency-v1",
                      "worker-efficiency-v2"] = "original"
    batch_index: int = Field(ge=0,le=9)
    max_tokens: int = Field(default=540000,ge=10000,le=540000)
    max_calls: int = Field(default=108,ge=1,le=108)


class DevelopmentReplayRequest(BaseModel):
    model_config = {"extra": "forbid"}
    confirm_paid_calls: bool = Field(default=False, strict=True)
    confirm_known_task_replay: bool = Field(default=False, strict=True)
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    max_tokens: int = Field(default=90000, ge=1, le=90000)
    max_calls: int = Field(default=18, ge=1, le=18)


class FreshValidationRequest(BaseModel):
    model_config = {"extra": "forbid"}
    confirm_paid_calls: bool = Field(default=False, strict=True)
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def realwork_router(state):
    router = APIRouter()
    root = state.settings.workspace.root_path / "realwork-evaluations"
    lock = threading.Lock()

    def directory(job_id):
        if not re.fullmatch(r"realwork_[A-Za-z0-9_]+", job_id):
            raise HTTPException(404, "evaluation not found")
        return root / job_id

    def receipt(job_id):
        target = directory(job_id)
        if not (target/"job.json").exists():
            raise HTTPException(404, "evaluation not found")
        row = json.loads((target/"job.json").read_text())
        if row["status"] in {"QUEUED", "RUNNING"} and row["session_id"] != state.lifecycle.session_id:
            row.update(status="INTERRUPTED", automatic_resume=False)
        for name in ("progress", "report", "series-usage"):
            path = target/"results"/(name+".json")
            if path.exists():
                row[name] = json.loads(path.read_text())
        return row

    @router.get("/api/realwork-evaluations")
    def list_jobs():
        return {"cases":[{"case":r["case"], "targets":r["targets"]} for r in catalog()],
                "jobs":[json.loads(p.read_text()) for p in sorted(root.glob("realwork_*/job.json"))],
                "scope":"native-host upstream issue adaptation; oracle-localized; no official SWE-bench score"}

    @router.post("/api/realwork-evaluations", status_code=202)
    def start(request: RealworkRequest):
        if not request.confirm_paid_calls:
            raise HTTPException(422, "explicit paid calls confirmation required")
        with lock:
            if state.dispatcher.busy_runs():
                raise HTTPException(409, "another job is active")
            if not catalog():
                raise HTTPException(409, "upstream cases are not frozen")
            # A fixed study cannot be launched twice, even after cancellation/restart.
            if any(root.glob("realwork_*/job.json")):
                raise HTTPException(409, "this frozen study already has a receipt; never rerun automatically")
            client = state.build_model_client("coder").for_profile("bounded_json")
            if client.model != "deepseek-flash":
                raise HTTPException(422, "fixed cost protocol requires saved deepseek-flash")
            job_id = new_id("realwork")
            target = directory(job_id)
            target.mkdir(parents=True)
            row = {"job_id":job_id, "status":"QUEUED", "session_id":state.lifecycle.session_id,
                   "created_at":utc_now(), "automatic_resume":False,
                   "request":request.model_dump(), "planned_trials":3*len(catalog())}
            atomic_json(target/"job.json",row)
            response = dict(row)

            def execute():
                row.update(status="RUNNING",started_at=utc_now())
                atomic_json(target/"job.json",row)
                try:
                    report = run_realwork(target/"results",client,
                        stop_requested=lambda:stop_requested() or (target/"cancel.json").exists(),
                        max_tokens=request.max_tokens,max_calls=request.max_calls)
                    row.update(status=report["status"],series_reported_tokens=report["series_reported_tokens"],
                               series_logical_calls=report["series_logical_calls"])
                except Exception as error:
                    row.update(status="ERROR",error_type=type(error).__name__)
                row["finished_at"] = utc_now()
                atomic_json(target/"job.json",row)
                return SimpleNamespace(status=row["status"])

            try:
                state.dispatcher.submit(job_id,str(target),execute)
            except DaedalusError:
                row.update(status="ADMISSION_FAILED",finished_at=utc_now())
                atomic_json(target/"job.json",row)
                raise
            return response

    @router.get("/api/realwork-evaluations/{job_id}")
    def view(job_id:str):
        return receipt(job_id)

    @router.post("/api/realwork-optimization", status_code=202)
    def optimize(request: RealworkRequest):
        from daedalus.application.realwork import PROJECT
        if not request.confirm_paid_calls:
            raise HTTPException(422, "explicit paid calls confirmation required")
        with lock:
            if state.dispatcher.busy_runs():
                raise HTTPException(409, "another job is active")
            if any(root.glob("realwork_opt_*/job.json")):
                raise HTTPException(409, "optimization study already sealed or dispatched; no rerun")
            cases_path = PROJECT / "docs/failure_optimization_2026-10-27/cases.json"
            if not cases_path.is_file():
                raise HTTPException(409, "fresh cases have not been frozen")
            cases = json.loads(cases_path.read_text())
            if not cases or {r["case"] for r in cases} & {r["case"] for r in catalog()}:
                raise HTTPException(409, "study contains a previously dispatched case")
            # Check every persisted earlier experiment, including partially completed ones.
            for report_path in root.glob("realwork_*/results/report.json"):
                prior = json.loads(report_path.read_text())
                if {r["case"] for r in prior.get("trials", [])} & {r["case"] for r in cases}:
                    raise HTTPException(409, "study overlaps a prior receipt")
            client = state.build_model_client("coder").for_profile("bounded_json")
            if client.model != "deepseek-flash":
                raise HTTPException(422, "fixed monetary protocol requires saved deepseek-flash")
            job_id = new_id("realwork_opt")
            target = directory(job_id)
            target.mkdir(parents=True)
            row = {"job_id":job_id, "study":"optimization-v1", "status":"QUEUED",
                   "session_id":state.lifecycle.session_id, "created_at":utc_now(),
                   "automatic_resume":False, "planned_trials":2*len(cases),
                   "request":request.model_dump(), "max_cost_upper_cny":0.65}
            atomic_json(target/"job.json", row)
            response = dict(row)

            def execute():
                row.update(status="RUNNING", started_at=utc_now())
                atomic_json(target/"job.json", row)
                try:
                    report = run_realwork(target/"results", client, optimization=True,
                        max_tokens=request.max_tokens, max_calls=min(112, request.max_calls),
                        stop_requested=lambda:stop_requested() or (target/"cancel.json").exists())
                    row.update(status=report["status"], series_reported_tokens=report["series_reported_tokens"],
                               series_logical_calls=report["series_logical_calls"])
                except Exception as error:
                    row.update(status="ERROR", error_type=type(error).__name__)
                row["finished_at"] = utc_now()
                atomic_json(target/"job.json", row)
                return SimpleNamespace(status=row["status"])

            try:
                state.dispatcher.submit(job_id, str(target), execute)
            except DaedalusError:
                row.update(status="ADMISSION_FAILED", finished_at=utc_now())
                atomic_json(target/"job.json", row)
                raise
            return response

    @router.post("/api/realwork-evaluations/remaining",status_code=202)
    def remaining(request:RealworkRequest):
        if not request.confirm_paid_calls:
            raise HTTPException(422,"explicit paid calls confirmation required")
        with lock:
            if state.dispatcher.busy_runs():
                raise HTTPException(409,"another job is active")
            previous=list(root.glob("realwork_*/job.json"))
            if len(previous)!=1:
                raise HTTPException(409,"exactly one stopped initial study is required; continuation cannot be repeated")
            prior=receipt(previous[0].parent.name)
            if prior["status"] in {"QUEUED","RUNNING"} or "report" not in prior:
                raise HTTPException(409,"initial study has not stopped with a report")
            calls=prior.get("series-usage",{}).get("call_records",[])
            if any(r.get("request_dispatched",True) and not r.get("usage_available",False) for r in calls):
                raise HTTPException(409,"prior provider usage is unknown")
            prior_cost=sum((r.get("prompt_tokens",0)*2+r.get("completion_tokens",0)*8)/1000000 for r in calls)
            if prior_cost>=2.8:
                raise HTTPException(409,"insufficient conservative monetary reserve")
            completed={(r["case"],r["arm"]) for r in prior["report"]["trials"] if r.get("dispatched_model_calls",0)>0}
            keys=[(r["case"],arm) for r in catalog() for arm in ("model","single","daedalus") if (r["case"],arm) not in completed]
            if not keys:
                raise HTTPException(409,"all planned arms already dispatched")
            context={"initial_job_id":prior["job_id"],"initial_protocol_sha256":prior["report"]["protocol_sha256"],
                     "prior_cost_upper_cny":prior_cost,"max_total_cost_cny":3.0,
                     "remaining_keys":keys,"amendment":"after fixed first-series cap; only never-dispatched arms; original results immutable"}
            client=state.build_model_client("coder").for_profile("bounded_json")
            if client.model!="deepseek-flash":
                raise HTTPException(422,"fixed monetary protocol requires saved deepseek-flash")
            job_id=new_id("realwork")
            target=directory(job_id)
            target.mkdir(parents=True)
            row={"job_id":job_id,"status":"QUEUED","session_id":state.lifecycle.session_id,
                 "created_at":utc_now(),"automatic_resume":False,"planned_trials":len(keys),
                 "continuation_of":prior["job_id"],"budget_context":context}
            atomic_json(target/"job.json",row)
            response=dict(row)

            def execute():
                row.update(status="RUNNING",started_at=utc_now())
                atomic_json(target/"job.json",row)
                try:
                    report=run_realwork(target/"results",client,
                        stop_requested=lambda:stop_requested() or (target/"cancel.json").exists(),
                        max_tokens=1000000,max_calls=240-len(calls),continuation=context)
                    row.update(status=report["status"],series_reported_tokens=report["series_reported_tokens"],
                               series_logical_calls=report["series_logical_calls"])
                except Exception as error:
                    row.update(status="ERROR",error_type=type(error).__name__)
                row["finished_at"]=utc_now()
                atomic_json(target/"job.json",row)
                return SimpleNamespace(status=row["status"])

            try:
                state.dispatcher.submit(job_id,str(target),execute)
            except DaedalusError:
                row.update(status="ADMISSION_FAILED",finished_at=utc_now())
                atomic_json(target/"job.json",row)
                raise
            return response

    @router.post("/api/realwork-contract-check", status_code=202)
    def contract_check(request: RealworkRequest):
        from daedalus.application.upstream_contract import admit_contract
        if not request.confirm_paid_calls:
            raise HTTPException(422, "explicit paid calls confirmation required")
        with lock:
            if state.dispatcher.busy_runs() or any(root.glob("realwork_contract_*/job.json")):
                raise HTTPException(409, "busy or contract check already has a sealed receipt")
            prior_paths = list(root.glob("realwork_opt_*/job.json"))
            if len(prior_paths) != 1:
                raise HTTPException(409, "exactly one stopped optimization series is required")
            prior = receipt(prior_paths[0].parent.name)
            calls = prior.get("series-usage", {}).get("call_records", [])
            if prior["status"] in {"QUEUED", "RUNNING"} or not calls or any(
                c.get("request_dispatched",True) and not c.get("usage_available") for c in calls
            ):
                raise HTTPException(409, "prior series is active or has unknown spend")
            spent = sum((c.get("prompt_tokens",0)*2+c.get("completion_tokens",0)*8)/1e6
                        for c in calls if c.get("request_dispatched",True))
            if spent >= .65:
                raise HTTPException(409, "existing 0.65 CNY ceiling has no reserve")
            path = DATA / "diagnostics/fresh-smoke-cases.json"
            if not path.is_file():
                raise HTTPException(409, "fresh qualified contracts are unavailable")
            cases = json.loads(path.read_text())
            if not 1 <= len(cases) <= 2:
                raise HTTPException(409, "fixed check requires one or two fresh cases")
            try:
                for case in cases:
                    admit_contract(case)
            except (ValueError, KeyError, TypeError):
                raise HTTPException(409, "test contract did not pass reference/baseline qualification") from None
            for report_path in root.glob("realwork_*/results/report.json"):
                old = json.loads(report_path.read_text())
                if {r["case"] for r in old.get("trials",[])} & {r["case"] for r in cases}:
                    raise HTTPException(409, "check contains an already dispatched case")
            client = state.build_model_client("coder").for_profile("bounded_json")
            if client.model != "deepseek-flash":
                raise HTTPException(422, "fixed monetary guard requires saved deepseek-flash")
            context = {"max_total_cost_cny":.65,"prior_cost_upper_cny":spent,
                       "prior_job_id":prior["job_id"],"no_budget_increase":True}
            job_id = new_id("realwork_contract")
            target = directory(job_id)
            target.mkdir(parents=True)
            row = {"job_id":job_id,"study":"contract-smoke-v1","status":"QUEUED",
                   "session_id":state.lifecycle.session_id,"created_at":utc_now(),
                   "automatic_resume":False,"planned_trials":len(cases),"budget_context":context}
            atomic_json(target/"job.json",row)
            response = dict(row)

            def execute():
                row.update(status="RUNNING",started_at=utc_now())
                atomic_json(target/"job.json",row)
                try:
                    report = run_realwork(target/"results",client,contract_smoke=context,
                        max_tokens=min(request.max_tokens,60000),max_calls=min(request.max_calls,12),
                        stop_requested=lambda:stop_requested() or (target/"cancel.json").exists())
                    row.update(status=report["status"],series_reported_tokens=report["series_reported_tokens"],
                               series_logical_calls=report["series_logical_calls"])
                except Exception as error:
                    row.update(status="ERROR",error_type=type(error).__name__)
                row["finished_at"] = utc_now()
                atomic_json(target/"job.json",row)
                return SimpleNamespace(status=row["status"])

            try:
                state.dispatcher.submit(job_id,str(target),execute)
            except DaedalusError:
                row.update(status="ADMISSION_FAILED",finished_at=utc_now())
                atomic_json(target/"job.json",row)
                raise
            return response

    @router.post("/api/realwork-cycle", status_code=202)
    def capability_cycle(request: CapabilityCycleRequest):
        from daedalus.application.upstream_contract import admit_contract
        if not request.confirm_paid_calls:
            raise HTTPException(422,"explicit paid calls confirmation required")
        with lock:
            if state.dispatcher.busy_runs():
                raise HTTPException(409,"another job is active")
            compact = request.protocol == "worker-efficiency-v2"
            efficiency = request.protocol in {"worker-efficiency-v1","worker-efficiency-v2"}
            amended = request.protocol != "original"
            study = (request.protocol if efficiency else
                     "capability-cycle-transport-v1" if amended else "capability-cycle-v1")
            path = (DATA / "diagnostics/worker-efficiency-20261028" / (
                    "compact-plan.json" if compact else "frozen-plan.json") if efficiency else
                    DATA / "diagnostics/capability-cycle-20261027" / (
                    "transport-amendment-plan.json" if amended else "frozen-plan.json"))
            if not path.is_file():
                raise HTTPException(409,"fresh study plan is unavailable")
            plan = json.loads(path.read_text())
            digest = plan.pop("sha256","")
            if hashlib.sha256(json.dumps(plan,sort_keys=True).encode()).hexdigest() != digest:
                raise HTTPException(409,"frozen study plan digest does not match")
            if (plan.get("version") != 1 or plan.get("max_cost_cny") != 4.5
                    or request.batch_index >= len(plan.get("batches",[]))):
                raise HTTPException(409,"study plan exceeds the fixed user-authorized cap")
            if efficiency:
                from daedalus.application.realwork_workers import baseline_path
                baseline = baseline_path(DATA,"efficiency-v1" if compact else "poststudy")
                if (request.batch_index != 0 or len(plan["batches"]) != 1
                        or request.max_tokens > (180000 if compact else 360000)
                        or request.max_calls > (36 if compact else 72)
                        or not baseline.is_file() or hashlib.sha256(baseline.read_bytes()).hexdigest()
                        != plan.get("baseline_worker_sha256")):
                    raise HTTPException(409,"paired worker experiment exceeds its frozen bounds")
            batch = plan["batches"][request.batch_index]
            cases = batch["cases"]
            if compact and len(cases)>3:
                raise HTTPException(409,"compact worker check contains too many fresh tasks")
            if not 1 <= len(cases) <= 6 or len({r["case"] for r in cases}) != len(cases):
                raise HTTPException(409,"invalid bounded task batch")
            try:
                for case in cases:
                    admit_contract(case)
                    if case.get("isolation") != "seatbelt":
                        raise ValueError("native cycle requires explicit runtime network denial")
                    if any(proof.get("isolation") != "seatbelt"
                           for proof in case["contract_qualification"].values()):
                        raise ValueError("qualification must use the same runtime isolation")
            except (ValueError,TypeError,KeyError):
                raise HTTPException(409,"native workload qualification is invalid") from None
            from daedalus.infrastructure.sandbox import SeatbeltDriver
            if not SeatbeltDriver().probe().available:
                raise HTTPException(409,"required native sandbox is unavailable; no model dispatch")
            parents = plan.get("parent_jobs", {}) if amended else {}
            if amended and (len(parents) != (6 if compact else 5 if efficiency else 2)
                            or plan.get("unknown_reserved_cost_cny") != 2.25):
                raise HTTPException(409,"immutable transport allowance is invalid")
            spent, prior_batches, seen_parents = 0.0, set(), set()
            identities = {r["case"] for r in cases}
            for job_path in root.glob("realwork_*/job.json"):
                old = receipt(job_path.parent.name)
                old_cases = set(old.get("planned_case_ids",[]))
                old_cases |= {r["case"] for r in old.get("report",{}).get("trials",[])}
                if old_cases & identities:
                    raise HTTPException(409,"batch contains a reserved or previously dispatched case")
                if (not amended and old.get("study") == "capability-cycle-transport-v1"
                        or not efficiency and old.get("study") in {"worker-efficiency-v1","worker-efficiency-v2"}
                        or not compact and old.get("study") == "worker-efficiency-v2"):
                    raise HTTPException(409,"original cycle is sealed by an explicit budget amendment")
                if amended and (old.get("study") == "capability-cycle-v1"
                        or efficiency and old.get("study") == "capability-cycle-transport-v1"
                        or compact and old.get("study") == "worker-efficiency-v1"):
                    from daedalus.service.capability_budget import amended_parent_cost
                    try:
                        parent = parents[old["job_id"]]
                        protocol = json.loads((job_path.parent/"results/protocol.json").read_text())
                        spent += amended_parent_cost(old,parent,protocol)
                        seen_parents.add(old["job_id"])
                    except (KeyError,ValueError,TypeError,OSError):
                        raise HTTPException(409,"sealed parent receipt or unknown reserve is invalid") from None
                    continue
                if old.get("study") != study:
                    continue
                if old.get("plan_sha256") != digest:
                    raise HTTPException(409,"another immutable cycle plan already exists")
                prior_batches.add(old["batch_index"])
                records = old.get("series-usage",{}).get("call_records")
                if old["status"] in {"QUEUED","RUNNING","INTERRUPTED"} or records is None:
                    raise HTTPException(409,"earlier batch is active or has unconfirmed spend")
                if any(r.get("request_dispatched",True) and not r.get("usage_available") for r in records):
                    raise HTTPException(409,"prior provider usage is unknown; no additional calls")
                spent += sum((r.get("prompt_tokens",0)*2+r.get("completion_tokens",0)*8)/1e6
                             for r in records if r.get("request_dispatched",True))
            if ((amended and seen_parents != set(parents))
                    or prior_batches != set(range(request.batch_index)) or spent >= 4.5):
                raise HTTPException(409,"batches must run once in order within the shared cap")
            client = state.build_model_client("coder").for_profile("bounded_json")
            if client.model != "deepseek-flash":
                raise HTTPException(422,"fixed monetary guard requires saved deepseek-flash")
            context = {"cases":cases,"phase":batch["phase"],"batch_index":request.batch_index,
                       "plan_sha256":digest,"study":study,
                       "monetary_admission":{"max_total_cost_cny":4.5,"prior_cost_upper_cny":spent,
                                             "user_authorized_cap_cny":5,"reserve_cny":0.5,
                                             "unknown_reserved_cost_cny":2.25 if amended else 0}}
            if efficiency:
                context["baseline_worker_sha256"] = plan["baseline_worker_sha256"]
                context["price_checked"] = plan.get("price_checked","2026-10-28")
            job_id = new_id("realwork_cycle")
            target = directory(job_id)
            target.mkdir(parents=True)
            row = {"job_id":job_id,"study":study,"status":"QUEUED",
                   "session_id":state.lifecycle.session_id,"created_at":utc_now(),
                   "automatic_resume":False,"planned_trials":len(cases)*(2 if efficiency else 3),
                   "planned_case_ids":sorted(identities),"batch_index":request.batch_index,
                   "phase":batch["phase"],"plan_sha256":digest,
                   "budget_context":context["monetary_admission"]}
            atomic_json(target/"job.json",row)
            response = dict(row)

            def execute():
                row.update(status="RUNNING",started_at=utc_now())
                atomic_json(target/"job.json",row)
                try:
                    report = run_realwork(target/"results",client,cycle=context,
                        max_tokens=request.max_tokens,max_calls=request.max_calls,
                        stop_requested=lambda:stop_requested() or (target/"cancel.json").exists())
                    row.update(status=report["status"],series_reported_tokens=report["series_reported_tokens"],
                               series_logical_calls=report["series_logical_calls"])
                except Exception as error:
                    row.update(status="ERROR",error_type=type(error).__name__)
                row["finished_at"] = utc_now()
                atomic_json(target/"job.json",row)
                return SimpleNamespace(status=row["status"])

            try:
                state.dispatcher.submit(job_id,str(target),execute)
            except DaedalusError:
                row.update(status="ADMISSION_FAILED",finished_at=utc_now())
                atomic_json(target/"job.json",row)
                raise
            return response

    @router.post("/api/realwork-development-replays", status_code=202)
    def development_replay(request: DevelopmentReplayRequest):
        from daedalus.application.realwork import PROJECT
        from daedalus.service.replay_admission import STUDY, admit_replay

        if not request.confirm_paid_calls or not request.confirm_known_task_replay:
            raise HTTPException(422, "explicit paid calls and known-task replay confirmations required")
        with lock:
            if state.dispatcher.busy_runs():
                raise HTTPException(409, "another job is active")
            marker = root / "replay-admissions" / (request.plan_sha256 + ".json")
            if (marker.exists() or any((root / "replay-admissions").glob("*.json"))
                    or any(root.glob("realwork_replay_*/job.json"))):
                raise HTTPException(409, "known-task replay plan already admitted; no resume or repeat")
            try:
                context = admit_replay(DATA, PROJECT, root, request.plan_sha256)
            except (ValueError, TypeError, KeyError, OSError, AttributeError, OverflowError):
                raise HTTPException(409, "frozen replay evidence, shared budget, or native sandbox is invalid") from None
            client = state.build_model_client("coder").for_profile("bounded_json")
            if client.model != "deepseek-flash":
                raise HTTPException(422, "fixed monetary guard requires saved deepseek-flash")
            job_id = new_id("realwork_replay")
            target = directory(job_id)
            target.mkdir(parents=True)
            row = {
                "job_id": job_id, "study": STUDY, "status": "QUEUED",
                "session_id": state.lifecycle.session_id, "created_at": utc_now(),
                "automatic_resume": False, "planned_trials": len(context["cases"]),
                "planned_case_ids": [case["case"] for case in context["cases"]],
                "phase": context["phase"], "plan_sha256": request.plan_sha256,
                "comparison_job_id": context["comparison_job_id"], "comparison_arm": "optimized",
                "request": request.model_dump(), "budget_context": context["monetary_admission"],
                "authorization": context["authorization"], "historical_budget": context["historical_budget"],
                "scope": "known tasks reused for development replay; historical baseline only; "
                         "no heldout, generalization, or causal claim",
            }
            # Persist consumption before dispatch, including failed/canceled admissions.
            atomic_json(marker, {"plan_sha256": request.plan_sha256, "job_id": job_id,
                                 "admitted_at": row["created_at"], "automatic_resume": False})
            atomic_json(target / "job.json", row)
            response = dict(row)

            def execute():
                row.update(status="RUNNING", started_at=utc_now())
                atomic_json(target / "job.json", row)
                try:
                    report = run_realwork(
                        target / "results", client, replay=context,
                        max_tokens=request.max_tokens, max_calls=request.max_calls,
                        stop_requested=lambda: stop_requested() or (target / "cancel.json").exists())
                    row.update(status=report["status"],
                               series_reported_tokens=report["series_reported_tokens"],
                               series_logical_calls=report["series_logical_calls"])
                except Exception as error:
                    row.update(status="ERROR", error_type=type(error).__name__)
                row["finished_at"] = utc_now()
                atomic_json(target / "job.json", row)
                return SimpleNamespace(status=row["status"])

            try:
                state.dispatcher.submit(job_id, str(target), execute)
            except DaedalusError:
                row.update(status="ADMISSION_FAILED", finished_at=utc_now())
                atomic_json(target / "job.json", row)
                raise
            return response

    @router.post("/api/realwork-validation-batches", status_code=202)
    def fresh_validation(request: FreshValidationRequest):
        from daedalus.application.realwork import (
            PROJECT, VALIDATION_ARM_CALLS, VALIDATION_ARM_TOKENS, VALIDATION_CASES, VALIDATION_STUDY,
        )
        from daedalus.service.validation_admission import admit_validation

        if not request.confirm_paid_calls:
            raise HTTPException(422, "explicit paid calls confirmation required")
        with lock:
            if state.dispatcher.busy_runs():
                raise HTTPException(409, "another job is active")
            marker = root / "validation-admissions" / (request.plan_sha256 + ".json")
            if (any((root / "validation-admissions").glob("*.json"))
                    or any(root.glob("realwork_validation_*/job.json"))):
                raise HTTPException(409, "fresh batch already consumed; no automatic resume or repeat")
            try:
                context = admit_validation(DATA, PROJECT, root, request.plan_sha256)
            except (ValueError, TypeError, KeyError, OSError, AttributeError):
                raise HTTPException(409, "fresh frozen plan, workload, source or isolation is invalid") from None
            client = state.build_model_client("coder").for_profile("bounded_json")
            if client.model != "deepseek-flash":
                raise HTTPException(422, "paired study requires saved deepseek-flash")
            job_id = new_id("realwork_validation")
            target = directory(job_id)
            target.mkdir(parents=True)
            row = {
                "job_id": job_id, "study": VALIDATION_STUDY, "status": "QUEUED",
                "session_id": state.lifecycle.session_id, "created_at": utc_now(),
                "automatic_resume": False, "planned_trials": 2 * VALIDATION_CASES,
                "planned_case_ids": [case["case"] for case in context["cases"]],
                "phase": context["phase"], "plan_sha256": request.plan_sha256,
                "request": request.model_dump(), "authorization": context["authorization"],
                "budget_context": None, "scope": "fresh single-agent versus current Daedalus; no causal claim",
            }
            atomic_json(marker, {"plan_sha256": request.plan_sha256, "job_id": job_id,
                                 "admitted_at": row["created_at"], "automatic_resume": False})
            atomic_json(target / "job.json", row)
            response = dict(row)

            def execute():
                row.update(status="RUNNING", started_at=utc_now())
                atomic_json(target / "job.json", row)
                try:
                    report = run_realwork(
                        target / "results", client, cycle=context,
                        max_tokens=2 * VALIDATION_CASES * VALIDATION_ARM_TOKENS,
                        max_calls=2 * VALIDATION_CASES * VALIDATION_ARM_CALLS,
                        stop_requested=lambda: stop_requested() or (target / "cancel.json").exists())
                    row.update(status=report["status"],
                               series_reported_tokens=report["series_reported_tokens"],
                               series_logical_calls=report["series_logical_calls"])
                except Exception as error:
                    row.update(status="ERROR", error_type=type(error).__name__)
                row["finished_at"] = utc_now()
                atomic_json(target / "job.json", row)
                return SimpleNamespace(status=row["status"])

            try:
                state.dispatcher.submit(job_id, str(target), execute)
            except DaedalusError:
                row.update(status="ADMISSION_FAILED", finished_at=utc_now())
                atomic_json(target / "job.json", row)
                raise
            return response

    @router.post("/api/realwork-evaluations/{job_id}/cancel",status_code=202)
    def cancel(job_id:str):
        if receipt(job_id)["status"] not in {"QUEUED","RUNNING"}:
            raise HTTPException(409,"job already stopped")
        atomic_json(directory(job_id)/"cancel.json",{"requested_at":utc_now()})
        return {"cancellation_requested":True,"automatic_resume":False}

    @router.get("/api/realwork-evaluations/{job_id}/artifacts/{name}")
    def artifact(job_id:str,name:Literal["report.json","report.html","trials.csv","protocol.json","series-usage.json","evidence.zip","provider-metrics.json"]):
        if name == "provider-metrics.json":
            row=receipt(job_id)
            if row["status"] in {"QUEUED","RUNNING"} or not row.get("started_at") or not row.get("finished_at"):
                raise HTTPException(409,"provider export requires a stopped study interval")
            records=state.store.connection.execute(
                "SELECT name,value,unit,labels,recorded_at FROM metrics WHERE name LIKE 'provider_%' AND recorded_at>=? AND recorded_at<=? ORDER BY recorded_at,metric_id",
                (row["started_at"],row["finished_at"])).fetchall()
            output=[]
            for record in records:
                labels=json.loads(record["labels"])
                output.append({"name":record["name"],"value":record["value"],"unit":record["unit"],
                    "recorded_at":record["recorded_at"],"labels":{k:labels[k] for k in ["role","request_id","ok","error_code","inference_profile","http_status"] if k in labels}})
            return JSONResponse(output)
        if name == "evidence.zip":
            target=directory(job_id)/"results"
            row=receipt(job_id)
            if row["status"] in {"QUEUED","RUNNING"}:
                raise HTTPException(409,"evidence export requires a stopped study")
            report=row.get("report",{})
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,"w",zipfile.ZIP_DEFLATED) as archive:
                for filename in ["report.json","protocol.json","series-usage.json","progress.json",
                                 "worker-control.py"]:
                    path=target/filename
                    if path.is_file():
                        archive.writestr(filename,path.read_bytes())
                for path in (target/"model-calls").glob("call-*.json"):
                    archive.writestr("model-calls/"+path.name,path.read_bytes())
                for path in (target/"monetary-admissions").glob("request-*.json"):
                    archive.writestr("monetary-admissions/"+path.name,path.read_bytes())
                exported_tasks=set()
                for trial in report.get("trials",[]):
                    relative=trial.get("artifact_root","")
                    if not re.fullmatch(r"trial-01-[A-Za-z0-9_-]+",relative):
                        continue
                    folder=target/relative
                    if not folder.resolve().is_relative_to(target.resolve()):
                        continue
                    for filename in ["result.json","single-loop.json","daedalus-events.json","error.json"]:
                        path=folder/filename
                        if path.is_file():
                            archive.writestr(relative+"/"+filename,path.read_bytes())
                    commit=trial.get("candidate_commit","")
                    if re.fullmatch(r"[0-9a-f]{40,64}",commit) and (folder/"repo/.git").exists():
                        repo=folder/"repo"
                        base=_git(repo,["rev-list","--max-parents=0","HEAD"],check=True).stdout.strip()
                        patch=_git(repo,["diff",base,commit,"--"],check=True).stdout
                        archive.writestr(relative+"/candidate.patch",redact_text(patch))
                    case=trial["case"]
                    if case not in exported_tasks and re.fullmatch(r"[A-Za-z0-9_-]+",case):
                        task=DATA/"tasks"/case/"task.json"
                        if task.is_file():
                            archive.writestr("tasks/"+case+".json",task.read_bytes())
                        upstream=DATA/"tasks"/case/"upstream"
                        for license_path in upstream.glob("*/LICENSE*"):
                            if license_path.is_file():
                                archive.writestr("licenses/"+case+"/"+license_path.name,license_path.read_bytes())
                        exported_tasks.add(case)
            return Response(stream.getvalue(),media_type="application/zip",headers={"Content-Disposition":"attachment; filename=evidence.zip"})
        path = directory(job_id)/"results"/name
        if not path.is_file():
            raise HTTPException(404,"artifact not ready")
        return FileResponse(path,filename=name)

    return router
