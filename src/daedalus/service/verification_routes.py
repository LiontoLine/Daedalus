"""Local, bounded operator verification; no arbitrary prompts, paths or credentials."""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

from fastapi import APIRouter, HTTPException, Request

from daedalus.application.planner import ResourceBounds
from daedalus.application.verification_probes import recovery_fixture, run_goal_probes
from daedalus.domain.ids import new_id, utc_now
from daedalus.infrastructure.knowledge import atomic_json
from daedalus.service.dispatcher import build_orchestrator


def verification_router(state):
    router = APIRouter()
    root = state.settings.workspace.root_path / "verification"

    def guard(request):
        if state.settings.service.host not in {"localhost", "127.0.0.1", "::1", "[::1]"}:
            raise HTTPException(403, detail="verification requires a loopback service")
        if request.headers.get("x-daedalus-verification") != "1":
            raise HTTPException(403, detail="explicit local verification action required")
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            raise HTTPException(403, detail="cross-origin verification refused")

    @router.post("/api/verification/goal-loops", status_code=202)
    def goals(request: Request):
        guard(request)
        client = state.build_model_client("reviewer")
        job_id = new_id("verification")
        directory = root / job_id
        receipt = {
            "job_id": job_id,
            "status": "QUEUED",
            "created_at": utc_now(),
            "session_id": state.lifecycle.session_id,
            "scope": "controlled fault candidates/step reviews; real goal model",
            "max_goal_model_calls": 8,
            "max_reported_tokens": 50000,
            "model": client.model,
        }
        atomic_json(directory / "job.json", receipt)
        response = dict(receipt)

        def execute():
            receipt.update(status="RUNNING", started_at=utc_now())
            atomic_json(directory / "job.json", receipt)
            try:
                report = run_goal_probes(
                    directory, client, ResourceBounds.for_quota(state.settings.quota)
                )
                receipt.update(status="PASSED" if report["passed"] else "CHECK_FAILED")
            except Exception as error:  # noqa: BLE001 - do not persist transport bodies
                receipt.update(status="ERROR", error_type=type(error).__name__)
            receipt["finished_at"] = utc_now()
            atomic_json(directory / "job.json", receipt)
            return SimpleNamespace(status=receipt["status"])

        state.dispatcher.submit(job_id, str(directory), execute)
        return response

    @router.get("/api/verification/{job_id}")
    def view(job_id: str):
        if not re.fullmatch(r"verification_[A-Za-z0-9_]+", job_id):
            raise HTTPException(404, detail="verification not found")
        directory = root / job_id
        if not (directory / "job.json").is_file():
            raise HTTPException(404, detail="verification not found")
        result = json.loads((directory / "job.json").read_text())
        if (
            result["status"] in {"QUEUED", "RUNNING"}
            and result["session_id"] != state.lifecycle.session_id
        ):
            result.update(status="INTERRUPTED", automatic_resume=False)
        if (directory / "report.json").is_file():
            result["report"] = json.loads((directory / "report.json").read_text())
        return result

    @router.post("/api/verification/recovery", status_code=202)
    def recovery(request: Request):
        guard(request)
        probe_id = new_id("recovery")
        directory = root / probe_id
        repo, original, bundle = recovery_fixture(
            directory, ResourceBounds.for_quota(state.settings.quota)
        )
        worker, tier2 = state.build_worker(use_model=True, enable_review=True)
        owner = build_orchestrator(
            settings=state.settings,
            store=state.store,
            bundle=bundle,
            repo_path=str(repo),
            worker=worker,
            tier2=tier2,
            identity=state.identity,
        )
        owner.register_spec()
        owner.assert_spec_may_run()
        owner.create_run()
        receipt = {
            "probe_id": probe_id,
            "run_id": owner.run_id,
            "repo_path": str(repo),
            "original_commit": original,
            "scope": "real model workers and normal gates; 12-second first-node verification delay",
            "session_id": state.lifecycle.session_id,
            "created_at": utc_now(),
        }
        atomic_json(directory / "protocol.json", receipt)
        state.dispatcher.submit(owner.run_id, str(repo), owner.run)
        return receipt

    return router
