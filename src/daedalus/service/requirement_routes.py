"""Explicit operator-owned requirement checks; no model clients or automatic work."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from daedalus.application.requirement_evidence import (
    qualify,
    seal,
    validate_contract,
    validate_qualification,
)
from daedalus.domain.ids import new_id, utc_now
from daedalus.domain.spec import BoundarySpec
from daedalus.infrastructure.git_sandbox import GitSandbox, _git
from daedalus.infrastructure.knowledge import atomic_json
from daedalus.infrastructure.repository_lock import repository_lock
from daedalus.infrastructure.sandbox import SeatbeltDriver
from daedalus.security.outbound import SecretInPayload


class Requirement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=64)
    statement: str = Field(min_length=1, max_length=1200)


class BehaviorCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    test_name: str = Field(min_length=1, max_length=85)
    requirement_id: str = Field(min_length=1, max_length=64)
    role: str = Field(pattern=r"^(change|invariant)$")


class RequirementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo_path: str = Field(min_length=1, max_length=1000)
    objective: str = Field(min_length=1, max_length=10000)
    target_paths: list[str] = Field(min_length=1, max_length=12)
    requirements: list[Requirement] = Field(min_length=1, max_length=12)
    checks: list[BehaviorCheck] = Field(min_length=1, max_length=12)
    source: str = Field(min_length=1, max_length=16000)
    open_questions: list[str] = Field(default_factory=list, max_length=5)
    confirm_operator_tests: StrictBool = False


def directory(state, check_id):
    if not re.fullmatch(r"requirement_[A-Za-z0-9_]+", check_id):
        raise HTTPException(404, "requirement check not found")
    return state.settings.workspace.root_path / "requirement-checks" / check_id


def load_ready(state, check_id, repo, objective, targets):
    target = directory(state, check_id)
    try:
        job = json.loads((target / "job.json").read_text())
        proof = json.loads((target / "report.json").read_text())
        contract = json.loads((target / "contract.json").read_text())
        if job["status"] != "READY":
            raise ValueError("requirement check is not ready for repair")
        validate_qualification(contract, proof)
        if (proof["repo_path"] != str(repo.resolve()) or contract["objective"] != objective
                or set(proof["target_paths"]) != set(targets)
                or GitSandbox.main_commit(repo) != proof["base_commit"]
                or _git(repo, ["status", "--porcelain", "--untracked-files=all"], check=True)
                .stdout.strip()):
            raise ValueError("requirement check is stale or belongs to another request")
        return contract, proof
    except (OSError, ValueError, KeyError, TypeError):
        raise HTTPException(409, "a matching READY requirement check on the current clean base "
                            "is required") from None


def requirement_router(state):
    router = APIRouter()

    @router.post("/api/requirement-checks", status_code=202)
    def create(request: Request, body: RequirementRequest):
        if (state.settings.service.host not in {"localhost", "127.0.0.1", "::1", "[::1]"}
                or request.headers.get("x-daedalus-requirements") != "1"):
            raise HTTPException(403, "requirement checks need an explicit local operator action")
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            raise HTTPException(403, "cross-origin requirement check refused")
        if not body.confirm_operator_tests:
            raise HTTPException(422, "operator-frozen tests must be explicitly confirmed")
        contract = seal({"version": 1, "objective": body.objective,
                         "requirements": [r.model_dump() for r in body.requirements],
                         "checks": [c.model_dump() for c in body.checks], "source": body.source,
                         "open_questions": body.open_questions})
        try:
            validate_contract(contract)
        except (ValueError, TypeError, SyntaxError, SecretInPayload):
            raise HTTPException(422, "behavior contract is invalid; "
                                "input source is not echoed") from None
        repo = Path(body.repo_path).expanduser().resolve()
        if not (repo / ".git").exists():
            raise HTTPException(400, "requirement checks need a committed Git repository")
        driver = SeatbeltDriver()
        if not driver.probe().available:
            raise HTTPException(409, "required Seatbelt isolation unavailable; "
                                "no tests or models run")
        check_id = new_id("requirement")
        target = directory(state, check_id)
        boundary = BoundarySpec(check_id, check_id, fs_whitelist=tuple(body.target_paths),
                                isolation="seatbelt", max_runtime_sec=30)
        job = {"check_id": check_id, "status": "QUEUED", "created_at": utc_now(),
               "session_id": state.lifecycle.session_id, "automatic_resume": False,
               "model_calls": 0,
               "contract_sha256": contract["sha256"]}
        atomic_json(target / "contract.json", contract)
        atomic_json(target / "job.json", job)

        def execute():
            job.update(status="RUNNING", started_at=utc_now())
            atomic_json(target / "job.json", job)
            try:
                with repository_lock(repo):
                    report = qualify(repo, contract, body.target_paths, boundary,
                                     target / "worktrees", driver=driver)
                atomic_json(target / "report.json", report)
                job["status"] = report["decision"]
            except Exception as error:  # noqa: BLE001 - never persist code or raw exception text
                job.update(status="EVIDENCE_UNAVAILABLE", error_type=type(error).__name__)
            job["finished_at"] = utc_now()
            atomic_json(target / "job.json", job)
            return SimpleNamespace(status=job["status"])

        try:
            state.dispatcher.submit(check_id, str(repo), execute)
        except Exception:
            job.update(status="ADMISSION_FAILED", finished_at=utc_now())
            atomic_json(target / "job.json", job)
            raise
        return dict(job)

    @router.get("/api/requirement-checks/{check_id}")
    def view(check_id: str):
        target = directory(state, check_id)
        if not (target / "job.json").is_file():
            raise HTTPException(404, "requirement check not found")
        job = json.loads((target / "job.json").read_text())
        if (job["status"] in {"QUEUED", "RUNNING"}
                and job["session_id"] != state.lifecycle.session_id):
            job.update(status="INTERRUPTED", automatic_resume=False)
        if (target / "report.json").is_file():
            job["report"] = json.loads((target / "report.json").read_text())
        return job

    @router.get("/api/requirement-checks/{check_id}/artifacts/{name}")
    def artifact(check_id: str, name: Literal["report.json", "contract.json"]):
        target = directory(state, check_id) / name
        if not target.is_file():
            raise HTTPException(404, "requirement artifact not found")
        return FileResponse(target, media_type="application/json", filename=name)

    return router
