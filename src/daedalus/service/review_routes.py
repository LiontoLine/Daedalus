"""Explicit, bounded calibration of the saved reviewer; reads never dispatch models."""

from __future__ import annotations

import json
import re
import threading
from types import SimpleNamespace

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from daedalus.application.benchmark import MeteredClient
from daedalus.application.review_probes import run_review_comparison
from daedalus.application.service_lifecycle import stop_requested
from daedalus.domain.ids import new_id, utc_now
from daedalus.errors import DaedalusError, ModelError
from daedalus.infrastructure.knowledge import atomic_json


class ReviewEvaluationRequest(BaseModel):
    model_config = {"extra": "forbid"}
    confirm_paid_calls: bool = False


def review_router(state):
    router = APIRouter()
    root = state.settings.workspace.root_path / "review-evaluations"
    lock = threading.Lock()

    def directory(job_id):
        if not re.fullmatch(r"review_eval_[A-Za-z0-9_]+", job_id):
            raise HTTPException(404, "review evaluation not found")
        return root / job_id

    def receipt(job_id):
        target = directory(job_id)
        if not (target / "job.json").is_file():
            raise HTTPException(404, "review evaluation not found")
        row = json.loads((target / "job.json").read_text())
        if (
            row["status"] in {"QUEUED", "RUNNING"}
            and row["session_id"] != state.lifecycle.session_id
        ):
            row.update(status="INTERRUPTED", automatic_resume=False)
        for key in ("report", "progress"):
            path = target / "results" / (key + ".json")
            if path.is_file():
                row[key] = json.loads(path.read_text())
        return row

    @router.get("/api/review-evaluations")
    def catalog():
        rows = []
        for path in sorted(root.glob("review_eval_*/job.json"), reverse=True)[:20]:
            row = receipt(path.parent.name)
            row.pop("report", None)
            row.pop("progress", None)
            rows.append(row)
        return {
            "jobs": rows,
            "planned_reviews": 40,
            "fixed_subjects": 20,
            "max_reported_tokens": 100000,
            "max_calls": 48,
            "scope": "review component context ablation; not agent coding ability",
        }

    @router.post("/api/review-evaluations", status_code=202)
    def start(request: ReviewEvaluationRequest):
        if not request.confirm_paid_calls:
            raise HTTPException(422, "需要明确确认真实模型调用")
        with lock:
            if state.dispatcher.busy_runs():
                raise HTTPException(409, "请等待当前运行结束; 本实验独占启动")
            client = state.build_model_client("reviewer")
            if callable(getattr(client, "for_task", None)):
                client = client.for_task("structured_review")
            job_id = new_id("review_eval")
            target = directory(job_id)
            target.mkdir(parents=True)
            row = {
                "job_id": job_id,
                "status": "QUEUED",
                "created_at": utc_now(),
                "session_id": state.lifecycle.session_id,
                "model": client.model,
                "planned_reviews": 40,
                "max_reported_tokens": 100000,
                "max_calls": 48,
                "automatic_resume": False,
                "inference_profile": getattr(client, "inference_profile", "configured"),
            }
            atomic_json(target / "job.json", row)
            response = dict(row)

            def should_stop():
                return stop_requested() or (target / "cancel-request.json").exists()

            class Interruptible:
                name = getattr(client, "name", "saved-reviewer")
                model = client.model
                inference_profile = getattr(client, "inference_profile", "configured")

                def complete(self, messages, **options):
                    if should_stop():
                        raise ModelError(
                            "review evaluation stopped before dispatch", request_not_dispatched=True
                        )
                    return client.complete(messages, **options)

            def execute():
                row.update(status="RUNNING", started_at=utc_now())
                atomic_json(target / "job.json", row)
                series = MeteredClient(Interruptible(), max_calls=48, max_tokens=100000)
                try:
                    report = run_review_comparison(
                        target / "results", series, stop_requested=should_stop
                    )
                    row.update(status=report["status"])
                except Exception as error:  # noqa: BLE001 - durable failed receipt
                    row.update(status="ERROR", error_type=type(error).__name__)
                finally:
                    atomic_json(
                        target / "series-usage.json",
                        {
                            "reported_tokens": series.total,
                            "logical_calls": len(series.records),
                            "call_records": series.records,
                            "usage_unknown_calls": sum(
                                c.get("request_dispatched", True)
                                and not c.get("usage_available", False)
                                for c in series.records
                            ),
                        },
                    )
                    row.update(
                        finished_at=utc_now(),
                        reported_tokens=series.total,
                        logical_calls=len(series.records),
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

    @router.get("/api/review-evaluations/{job_id}")
    def view(job_id: str):
        return receipt(job_id)

    @router.post("/api/review-evaluations/{job_id}/cancel", status_code=202)
    def cancel(job_id: str):
        if receipt(job_id)["status"] not in {"QUEUED", "RUNNING"}:
            raise HTTPException(409, "实验已结束, 不会重新启动")
        atomic_json(directory(job_id) / "cancel-request.json", {"requested_at": utc_now()})
        return {"cancellation_requested": True, "automatic_resume": False}

    @router.get("/api/review-evaluations/{job_id}/artifacts/{name}")
    def artifact(job_id: str, name: str):
        if name not in {
            "protocol.json",
            "protocol-sha256.json",
            "report.json",
            "progress.json",
            "series-usage.json",
        }:
            raise HTTPException(404, "artifact not found")
        target = directory(job_id)
        path = target / name if name == "series-usage.json" else target / "results" / name
        if not path.is_file():
            raise HTTPException(404, "artifact not ready")
        return FileResponse(path, filename=name)

    return router
