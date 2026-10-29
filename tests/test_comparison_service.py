"""Offline comparison admission and persistence; no provider or model credential."""

import json
import time

from fastapi.testclient import TestClient

from daedalus.config import Settings, WorkspaceSettings
from daedalus.service.app import create_app


def test_bounded_comparison_job_and_interrupted_receipt(tmp_path, monkeypatch):
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    state = app.state.daedalus

    class ExistingProfile:
        model = "controlled-existing-profile"
        timeout_sec = 37
        base_url = "https://example.invalid"

    profile = ExistingProfile()
    state.build_model_client = lambda role: profile

    def compare(destination, **kwargs):
        assert kwargs["client_factory"]() is profile
        assert kwargs["timeout"] == 37
        assert [case.key for case in kwargs["cases"]] == ["words"]
        destination.mkdir()
        report = {"status": "COMPLETE", "scope": "controlled route test, no model call"}
        (destination / "report.json").write_text(json.dumps(report))
        return report

    monkeypatch.setattr("daedalus.service.benchmark_routes.run_comparison", compare)
    with TestClient(app) as api:
        invalid = api.post("/api/comparisons", json={"api_key": "private-value"})
        assert invalid.status_code == 422 and "private-value" not in invalid.text
        assert api.post("/api/comparisons", json={"max_tokens": 100001}).status_code == 422
        assert api.post("/api/comparisons", json={"cases": ["words", "words"]}).status_code == 422
        assert api.get("/api/comparisons/not-a-job").status_code == 404
        response = api.post("/api/comparisons", json={"cases": ["words"]})
        assert response.status_code == 202
        assert response.json()["status"] == "QUEUED"
        job = response.json()["job_id"]
        for _ in range(200):
            result = api.get("/api/comparisons/" + job).json()
            if result["status"] == "COMPLETE":
                break
            time.sleep(.01)
        assert result["status"] == "COMPLETE" and result["report"]["scope"].startswith("controlled")
        receipt = tmp_path / "ws/comparisons" / job / "job.json"
        data = json.loads(receipt.read_text())
        data.update(status="RUNNING", session_id="previous-session")
        receipt.write_text(json.dumps(data))
        result = api.get("/api/comparisons/" + job).json()
        assert result["status"] == "INTERRUPTED" and not result["automatic_resume"]
        report = receipt.parent / "results/report.json"
        complete = report.read_text()
        report.write_text('{"status":')
        partial = api.get("/api/comparisons/" + job)
        assert partial.status_code == 200
        assert partial.json()["report_state"] == "UNREADABLE"
        assert "report" not in partial.json()
        report.write_text(complete)
        assert api.get("/api/comparisons/" + job).json()["report"]["status"] == "COMPLETE"
