"""Isolated fixture, stage-cap and local-route verification without real model calls."""

import json
import re

import pytest
from fastapi.testclient import TestClient

from daedalus.application.planner import ResourceBounds
from daedalus.application.verification_probes import recovery_fixture, run_goal_probes
from daedalus.config import ServiceSettings, Settings, WorkspaceSettings
from daedalus.model.base import Completion
from daedalus.service.app import create_app
from daedalus.service.access import AccessControl, owner_headers


class OfflineGoalClient:
    name = model = "controlled-goal-transport"

    def complete(self, messages, **kwargs):
        text = "\n".join(m.content for m in messages)
        assert "FINAL GOAL audit" in text
        digest = re.search(r"SUBJECT_DIGEST: ([a-f0-9]+)", text)[1]
        criteria = re.findall(r"^  - (AC-[^:]+):", text, re.M)
        fixed = "+    return x * 2" in text
        return Completion(
            json.dumps(
                {
                    "subject_digest": digest,
                    "decision": "APPROVE" if fixed else "REVISE",
                    "reasons": ["evaluated whole-goal double invariant"],
                    "confidence": 0.99,
                    "violations": [] if fixed else ["double must return 2*x"],
                    "criterion_results": [
                        {
                            "criterion_id": c,
                            "status": "MET",
                            "evidence": "public test and artifact are present",
                        }
                        for c in criteria
                    ],
                }
            ),
            model=self.model,
            prompt_tokens=10,
            completion_tokens=20,
        )


def test_fault_candidates_and_stage_cap_use_normal_events_and_keep_failed_main(tmp_path):
    report = run_goal_probes(tmp_path, OfflineGoalClient(), ResourceBounds())
    assert report["passed"]
    drift, cap = report["outcomes"]
    assert [s["decision"] for s in drift["goal_audit"]["stages"]] == ["REVISE", "APPROVE"]
    assert [s["decision"] for s in cap["goal_audit"]["stages"]] == ["REVISE"] * 3
    assert cap["original_commit"] == cap["final_main_commit"]
    assert drift["reported_tokens"] == 60 and cap["reported_tokens"] == 90
    assert drift["scripted_step_reviews"] == 2 and cap["scripted_step_reviews"] == 3
    with pytest.raises(ValueError, match="must be new"):
        run_goal_probes(tmp_path, OfflineGoalClient(), ResourceBounds())


def test_recovery_fixture_has_dependent_nodes_and_complete_criterion_coverage(tmp_path):
    repo, initial, bundle = recovery_fixture(tmp_path, ResourceBounds())
    bundle.validate()
    a, b = bundle.plan.nodes
    assert a.node_id == "first" and b.deps == ("first",)
    assert set(c.criterion_id for n in (a, b) for c in n.acceptance_criteria) == {
        c.criterion_id for c in bundle.goal.acceptance_criteria
    }
    assert len(initial) == 40 and (repo / "verify_first.py").is_file()
    assert bundle.boundary.network_policy.value == "deny"


def test_verification_routes_refuse_implicit_remote_and_cross_origin_actions(tmp_path):
    for host in ("127.0.0.1", "0.0.0.0"):
        settings = Settings(
            workspace=WorkspaceSettings(root=str(tmp_path / host)),
            service=ServiceSettings(host=host, auth_required=host == "0.0.0.0"),
        )
        if settings.service.auth_required:
            AccessControl(settings).save_password("synthetic-test-password-only")
        app = create_app(settings)
        with TestClient(
            app,
            base_url="http://127.0.0.1",
            client=("127.0.0.1", 1234),
            headers=owner_headers(settings),
        ) as api:
            assert api.post("/api/verification/goal-loops").status_code == 403
            assert (
                api.post(
                    "/api/verification/recovery",
                    headers={"X-Daedalus-Verification": "1", "Origin": "https://unrelated.invalid"},
                ).status_code
                == 403
            )
            assert api.get("/api/verification/../../escape").status_code == 404
            assert not app.state.daedalus.dispatcher.busy_runs()
            if host == "0.0.0.0":
                assert (
                    api.post(
                        "/api/verification/goal-loops", headers={"X-Daedalus-Verification": "1"}
                    ).status_code
                    == 403
                )
