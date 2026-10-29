"""Fixed engineering evaluations using the saved model, with a shared series cap."""

from __future__ import annotations

import json
import re
import threading
from types import SimpleNamespace
from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from daedalus.application.benchmark import MeteredClient, run_comparison
from daedalus.application.engineering_cases import ENGINEERING_CASES
from daedalus.application.service_lifecycle import stop_requested
from daedalus.domain.ids import new_id, utc_now
from daedalus.errors import DaedalusError, ModelError
from daedalus.infrastructure.knowledge import atomic_json

CaseName = Literal[
    "api_pagination",
    "sqlite_idempotency",
    "manual_checkpoint",
    "versioned_context",
    "usage_export",
    "config_migration",
]


class EngineeringRequest(BaseModel):
    model_config = {"extra": "forbid"}
    cases: list[CaseName] = Field(
        default_factory=lambda: [c.key for c in ENGINEERING_CASES], min_length=1, max_length=6
    )
    max_calls: int = Field(default=8, ge=3, le=10)
    max_tokens: int = Field(default=30000, ge=10000, le=40000)
    series_tokens: int = Field(default=300000, ge=10000, le=300000)
    series_calls: int = Field(default=144, ge=1, le=144)
    inference_profile: Literal["configured", "bounded_json"] = "configured"


def engineering_router(state):
    router = APIRouter()
    root = state.settings.workspace.root_path / "engineering-evaluations"
    launch_lock = threading.Lock()

    def directory(job_id):
        if not re.fullmatch(r"evaluation_[A-Za-z0-9_]+", job_id):
            raise HTTPException(404, detail="evaluation not found")
        return root / job_id

    def receipt(job_id):
        target = directory(job_id) / "job.json"
        if not target.is_file():
            raise HTTPException(404, detail="evaluation not found")
        row = json.loads(target.read_text())
        if (
            row["status"] in {"QUEUED", "RUNNING", "CANCELLING"}
            and row["session_id"] != state.lifecycle.session_id
        ):
            row.update(status="INTERRUPTED", automatic_resume=False)
        for field, filename in [("report", "report.json"), ("progress", "progress.json")]:
            path = target.parent / "results" / filename
            if path.is_file():
                try:
                    row[field] = json.loads(path.read_text())
                except (OSError, ValueError):
                    row[field + "_state"] = "UNREADABLE"
        return row

    @router.get("/api/engineering-evaluations")
    def catalog():
        rows = []
        for path in sorted(root.glob("evaluation_*/job.json"), reverse=True)[:20]:
            row = receipt(path.parent.name)
            row.pop("report", None)
            row.pop("progress", None)
            rows.append(row)
        return {
            "cases": [
                {"key": c.key, "category": c.category, "editable_paths": c.targets}
                for c in ENGINEERING_CASES
            ],
            "jobs": rows,
            "arms": ["model", "single", "daedalus"],
            "scope": "six handcrafted engineering probes; not a product leaderboard",
        }

    @router.post("/api/engineering-evaluations", status_code=202)
    def start(request: EngineeringRequest):
        with launch_lock:
            for path in root.glob("evaluation_*/job.json"):
                if receipt(path.parent.name)["status"] in {"QUEUED", "RUNNING", "CANCELLING"}:
                    raise HTTPException(409, detail="an engineering evaluation is already active")
            return start_job(request)

    def start_job(request: EngineeringRequest):
        if len(set(request.cases)) != len(request.cases):
            raise HTTPException(422, detail="cases must be unique")
        client = state.build_model_client("coder")
        if request.inference_profile != "configured":
            factory = getattr(client, "for_profile", None)
            if not callable(factory):
                raise HTTPException(422, detail="当前接口不支持该任务推理模式; 请选择保持配置")
            try:
                client = factory(request.inference_profile)
            except ModelError as error:
                raise HTTPException(422, detail=error.message) from error
        job_id = new_id("evaluation")
        target = directory(job_id)
        target.mkdir(parents=True)
        row = {
            "job_id": job_id,
            "status": "QUEUED",
            "created_at": utc_now(),
            "session_id": state.lifecycle.session_id,
            "request": request.model_dump(),
            "model": client.model,
            "automatic_resume": False,
            "planned_trials": 3 * len(request.cases),
            "arms": ["model", "single", "daedalus"],
            "effective_inference_profile": getattr(client, "inference_profile", "configured"),
        }
        atomic_json(target / "job.json", row)
        response = dict(row)
        cancel_path = target / "cancel-request.json"

        def should_stop():
            return stop_requested() or cancel_path.exists()

        class Interruptible:
            name = getattr(client, "name", "saved-service-profile")
            model = client.model
            inference_profile = getattr(client, "inference_profile", "configured")

            def complete(self, messages, **options):
                if should_stop():
                    raise ModelError(
                        "service stop requested; no model call dispatched",
                        request_not_dispatched=True,
                    )
                return client.complete(messages, **options)

        def execute():
            row.update(status="RUNNING", started_at=utc_now())
            atomic_json(target / "job.json", row)
            series = MeteredClient(
                Interruptible(),
                max_calls=min(3 * len(request.cases) * request.max_calls, request.series_calls),
                max_tokens=request.series_tokens,
            )
            try:
                report = run_comparison(
                    target / "results",
                    mode="model",
                    repeats=1,
                    model=client.model,
                    base_url=getattr(client, "base_url", "saved-service-profile"),
                    max_calls=request.max_calls,
                    max_tokens=request.max_tokens,
                    timeout=getattr(client, "timeout_sec", 120),
                    cases=tuple(c for c in ENGINEERING_CASES if c.key in request.cases),
                    arms=("model", "single", "daedalus"),
                    client_factory=lambda: series,
                    stop_requested=should_stop,
                    series_limits={
                        "max_tokens": request.series_tokens,
                        "max_calls": min(
                            3 * len(request.cases) * request.max_calls, request.series_calls
                        ),
                        "inference_profile": request.inference_profile,
                    },
                )
                row.update(status=report["status"])
            except Exception as error:  # noqa: BLE001 - preserve a failed job, never fake results
                row.update(status="ERROR", error_type=type(error).__name__)
            finally:
                atomic_json(
                    target / "series-usage.json",
                    {
                        "reported_tokens": series.total,
                        "logical_calls": len(series.records),
                        "call_records": series.records,
                        "usage_unknown_calls": sum(
                            not r.get("usage_available", False)
                            and r.get("request_dispatched", True)
                            for r in series.records
                        ),
                        "calls_not_dispatched": sum(
                            r.get("request_dispatched") is False for r in series.records
                        ),
                    },
                )
                row.update(
                    finished_at=utc_now(),
                    series_reported_tokens=series.total,
                    series_logical_calls=len(series.records),
                    cancellation_requested=cancel_path.exists(),
                )
                atomic_json(target / "job.json", row)
            return SimpleNamespace(status=row["status"])

        try:
            state.dispatcher.submit(job_id, str(target), execute)
        except DaedalusError:
            row.update(status="ADMISSION_FAILED", finished_at=utc_now())
            atomic_json(target / "job.json", row)
            raise
        return response

    @router.get("/api/engineering-evaluations/{job_id}")
    def view(job_id: str):
        return receipt(job_id)

    @router.post("/api/engineering-evaluations/{job_id}/cancel", status_code=202)
    def cancel(job_id: str):
        row = receipt(job_id)
        if row["status"] not in {"QUEUED", "RUNNING", "CANCELLING"}:
            raise HTTPException(409, detail="该实验已结束; 不会重新启动")
        target = directory(job_id)
        atomic_json(
            target / "cancel-request.json",
            {
                "requested_at": utc_now(),
                "note": "explicit cancellation; current request may settle; no new dispatch",
            },
        )
        row.pop("report", None)
        row.pop("progress", None)
        row.update(status="CANCELLING", automatic_resume=False)
        atomic_json(target / "job.json", row)
        return {"job_id": job_id, "status": "CANCELLING", "automatic_resume": False}

    @router.get("/api/engineering-evaluations/{job_id}/artifacts/{name}")
    def artifact(
        job_id: str, name: Literal["report.html", "report.json", "trials.csv", "protocol.json"]
    ):
        path = directory(job_id) / "results" / name
        if not path.is_file():
            raise HTTPException(404, detail="artifact not ready")
        return FileResponse(path)

    return router
