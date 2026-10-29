"""Bounded comparison jobs using the effective model profile, without exporting keys."""

from __future__ import annotations

import json
import re
from types import SimpleNamespace
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from daedalus.application.benchmark import run_comparison
from daedalus.application.benchmark_cases import MODEL_CASES
from daedalus.domain.ids import new_id, utc_now
from daedalus.errors import DaedalusError
from daedalus.infrastructure.knowledge import atomic_json


class ComparisonRequest(BaseModel):
    model_config = {"extra": "forbid"}
    cases: list[Literal["words", "intervals", "topology"]] = Field(
        default_factory=lambda: ["words", "intervals", "topology"], min_length=1, max_length=3
    )
    repeats: int = Field(default=1, ge=1, le=3)
    max_calls: int = Field(default=8, ge=1, le=16)
    max_tokens: int = Field(default=30000, ge=1000, le=100000)


def benchmark_router(state):
    router = APIRouter()
    root = state.settings.workspace.root_path / "comparisons"

    def path_for(job_id):
        if not re.fullmatch(r"comparison_[A-Za-z0-9_]+", job_id):
            raise HTTPException(404, detail="comparison not found")
        return root / job_id

    @router.post("/api/comparisons", status_code=202)
    def start(request: ComparisonRequest):
        if len(set(request.cases)) != len(request.cases):
            raise HTTPException(422, detail="comparison cases must be unique")
        # Capture the same effective client for both arms. No key leaves the broker/client.
        client = state.build_model_client("coder")
        job_id = new_id("comparison")
        directory = path_for(job_id)
        directory.mkdir(parents=True)
        receipt = {
            "job_id": job_id, "status": "QUEUED", "created_at": utc_now(),
            "session_id": state.lifecycle.session_id, "request": request.model_dump(),
            "model": client.model,
            "scope": "three small fixed-task model pairs; not a product leaderboard",
            "timeout_sec": getattr(client, "timeout_sec", 120),
        }
        atomic_json(directory / "job.json", receipt)
        response = dict(receipt)

        def execute():
            receipt.update(status="RUNNING", started_at=utc_now())
            atomic_json(directory / "job.json", receipt)
            try:
                report = run_comparison(
                    directory / "results", mode="model", model=client.model,
                    base_url=getattr(client, "base_url", "service-profile"),
                    repeats=request.repeats, max_calls=request.max_calls,
                    max_tokens=request.max_tokens, timeout=receipt["timeout_sec"],
                    cases=tuple(case for case in MODEL_CASES if case.key in request.cases),
                    client_factory=lambda: client,
                )
                receipt.update(status=report["status"], finished_at=utc_now())
            except Exception as error:  # noqa: BLE001 - persist failure, not provider text
                receipt.update(
                    status="ERROR", error_type=type(error).__name__, finished_at=utc_now()
                )
            atomic_json(directory / "job.json", receipt)
            return SimpleNamespace(status=receipt["status"])

        try:
            state.dispatcher.submit(job_id, str(directory), execute)
        except DaedalusError:
            receipt.update(status="ADMISSION_FAILED", finished_at=utc_now())
            atomic_json(directory / "job.json", receipt)
            raise
        return response

    @router.get("/api/comparisons/{job_id}")
    def view(job_id: str):
        directory = path_for(job_id)
        path = directory / "job.json"
        if not path.is_file():
            raise HTTPException(404, detail="comparison not found")
        result = json.loads(path.read_text())
        if (
            result["status"] in {"QUEUED", "RUNNING"}
            and result["session_id"] != state.lifecycle.session_id
        ):
            result.update(status="INTERRUPTED", automatic_resume=False)
        report = directory / "results/report.json"
        if report.is_file():
            try:
                result["report"] = json.loads(report.read_text())
            except (OSError, ValueError):
                # Older writers could expose a half-written file during a poll.
                result["report_state"] = "UNREADABLE"
        return result

    return router
