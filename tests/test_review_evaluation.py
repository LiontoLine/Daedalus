"""Calibration labels, paired inputs, fail-closed scoring and paid-call admission."""

import hashlib
import json
import re
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from daedalus.application import review_probes as probes
from daedalus.application.benchmark import MeteredClient
from daedalus.config import Settings, WorkspaceSettings
from daedalus.model.base import Completion
from daedalus.service.app import create_app


@pytest.fixture(scope="module")
def subjects(tmp_path_factory):
    return probes.prepare(tmp_path_factory.mktemp("review-oracles"))


class FixedReviewer:
    name = model = "offline-fixed-reviewer"
    inference_profile = "offline"

    def __init__(self, root, *, valid=True, known=True):
        self.root, self.valid, self.known = root, valid, known

    def complete(self, messages, **_):
        protocol = self.root / "protocol.json"
        assert protocol.is_file()
        frozen = json.loads((self.root / "protocol-sha256.json").read_text())["sha256"]
        assert hashlib.sha256(protocol.read_bytes()).hexdigest() == frozen
        prompt = messages[0].content
        assert "expected_approve" not in prompt and "oracle_exit_code" not in prompt
        subject = re.search(r"SUBJECT_DIGEST: (\w+)", prompt)[1]
        reply = {
            "decision": "APPROVE",
            "subject_digest": subject,
            "reasons": ["fixed offline reply"],
            "violations": [],
            "confidence": 0.8,
        }
        if self.valid:
            reply["criterion_results"] = [
                {
                    "criterion_id": "contract",
                    "status": "MET",
                    "evidence": "fixed response, not model evidence",
                }
            ]
        return Completion(
            json.dumps(reply),
            self.model,
            10 if self.known else 0,
            5 if self.known else 0,
            1,
            raw={"usage_reported": self.known},
        )


def test_all_twenty_oracles_and_context_are_checked_before_dispatch(subjects):
    assert len(subjects) == 20 and sum(s["expected_approve"] for s in subjects) == 10
    for s in subjects:
        assert (s["oracle_exit_code"] == 0) == s["expected_approve"]
        assert s["import_smoke_exit_code"] == 0
        assert "helpers.py" in s["request"]["reference_context"]
        assert len(set(s["rendered_request_sha256"].values())) == 2


def test_paired_denominators_and_false_approvals_are_not_hidden(tmp_path, subjects, monkeypatch):
    monkeypatch.setattr(probes, "prepare", lambda _: subjects)
    client = MeteredClient(FixedReviewer(tmp_path), 48, 100000)
    report = probes.run_review_comparison(tmp_path, client)
    assert report["status"] == "COMPLETE" and len(report["reviews"]) == 40
    assert report["reported_tokens"] == 600 and report["logical_calls"] == 40
    for summary in report["summary"].values():
        assert summary["correct_candidates_approved"] == 10
        assert summary["faulty_candidates_approved"] == 10
    for s in subjects:
        pair = [r for r in report["reviews"] if r["subject"] == s["id"]]
        assert len({r["candidate_commit"] for r in pair}) == 1
        assert len({r["subject_digest"] for r in pair}) == 2
    assert report["agent_superiority_claim"] is False


def test_missing_goal_criteria_cannot_count_as_approval_and_unknown_usage_stops(
    tmp_path, subjects, monkeypatch
):
    monkeypatch.setattr(probes, "prepare", lambda _: subjects)
    client = MeteredClient(FixedReviewer(tmp_path, valid=False, known=False), 48, 100000)
    report = probes.run_review_comparison(tmp_path, client)
    assert report["status"] == "INTERRUPTED" and report["logical_calls"] == 1
    row = report["reviews"][0]
    assert not row["approved"] and not row["model_response_valid"]
    assert not row["call_records"][0]["usage_available"]


def test_reads_and_unconfirmed_posts_never_resolve_saved_model(tmp_path, monkeypatch):
    import daedalus.service.review_routes as routes

    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "workspace"))))
    calls = []
    monkeypatch.setattr(
        app.state.daedalus,
        "build_model_client",
        lambda role: calls.append(role) or SimpleNamespace(model="offline", name="offline"),
    )

    def fake(root, client, **_):
        assert client.max_calls == 48 and client.max_tokens == 100000
        return {"status": "COMPLETE"}

    monkeypatch.setattr(routes, "run_review_comparison", fake)
    with TestClient(app) as api:
        assert api.get("/api/review-evaluations").json()["jobs"] == []
        for body in ({}, {"confirm_paid_calls": False}, {"max_calls": 100}):
            assert api.post("/api/review-evaluations", json=body).status_code == 422
        assert calls == []
        response = api.post("/api/review-evaluations", json={"confirm_paid_calls": True})
        assert response.status_code == 202 and calls == ["reviewer"]
        job_id = response.json()["job_id"]
        for _ in range(100):
            row = api.get("/api/review-evaluations/" + job_id).json()
            if row["status"] == "COMPLETE":
                break
            time.sleep(0.01)
        assert row["status"] == "COMPLETE" and not row["automatic_resume"]
        assert (
            api.get(f"/api/review-evaluations/{job_id}/artifacts/keychain.json").status_code == 404
        )
        assert api.post(f"/api/review-evaluations/{job_id}/cancel").status_code == 409
