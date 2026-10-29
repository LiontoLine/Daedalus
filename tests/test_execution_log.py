"""Artifact traceability (Spec §14).

An artifact records `execution_log_ref` so that "what happened when this artifact was
produced?" is answerable from the artifact. The original value was `memory://<run>/<step>`,
a scheme nothing could resolve — including the process that wrote it — which is worse than
no reference at all, because it looks like provenance and provides none.

These tests hold the property that actually matters: **every reference the system writes
resolves to the recorded facts of that step**. A scheme change is fine; a dangling
reference is not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.execution_log import (
    UnresolvableLogRef,
    execution_log_ref,
    parse_log_ref,
    resolve,
)
from daedalus.config import load_settings
from daedalus.infrastructure.git_sandbox import init_repo, initial_commit
from daedalus.service.app import create_app
from tests.conftest import CORRECT_IMPLEMENTATION, DEMO_PROJECT, TARGET, TEST_COMMAND


def _repo(root: Path) -> Path:
    import shutil

    repo = init_repo(root / "repo")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".DS_Store")
    shutil.copytree(DEMO_PROJECT / "src", repo / "src", ignore=ignore)
    shutil.copytree(DEMO_PROJECT / "tests", repo / "tests", ignore=ignore)
    shutil.copy2(DEMO_PROJECT / "pyproject.toml", repo / "pyproject.toml")
    shutil.copy2(DEMO_PROJECT / ".gitignore", repo / ".gitignore")
    initial_commit(repo, "chore: import the demo project")
    return repo


@pytest.fixture()
def completed_run(tmp_path: Path):
    """A real completed run, plus the app state that produced it."""
    from daedalus.application.fsm_service import StateMachineService

    settings = load_settings(None, workspace_root=str(tmp_path / "ws"))
    app = create_app(settings)
    with TestClient(app) as client:
        app.state.daedalus.build_worker = lambda **_: (  # type: ignore[assignment]
            ScriptedWorker(
                ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
                worker_id="trace-check",
            ),
            None,
        )
        receipt = client.post(
            "/api/runs",
            json={
                "repo_path": str(_repo(tmp_path)),
                "objective": "fix the word counter",
                "target_paths": [TARGET],
                "test_command": TEST_COMMAND,
            },
        ).json()
        run_id = receipt["run_id"]
        import time

        deadline = time.time() + 60
        detail = client.get(f"/api/runs/{run_id}").json()
        while detail["run"]["status"] not in {
            "COMPLETED", "FAILED", "CANCELLED", "PARTIAL_FAILURE"
        } and time.time() < deadline:
            time.sleep(0.1)
            detail = client.get(f"/api/runs/{run_id}").json()
        yield client, app.state.daedalus, StateMachineService(app.state.daedalus.store), run_id, detail


# --------------------------------------------------------------- the reference
def test_the_reference_round_trips_including_the_colon_in_a_step_id() -> None:
    """Step ids contain `:`, so a naive split on punctuation would corrupt them."""
    reference = execution_log_ref("run_20260101T000000000000_abc", "run_20260101T000000000000_abc:N1")
    assert reference.startswith("audit://")
    assert parse_log_ref(reference) == (
        "run_20260101T000000000000_abc",
        "run_20260101T000000000000_abc:N1",
    )


@pytest.mark.parametrize(
    "reference",
    [
        "memory://run/step",          # the scheme that used to be written
        "audit://run-without-a-step",
        "audit:///step/N1",
        "audit://run/step/",
        "",
        "not a reference at all",
    ],
)
def test_a_reference_that_cannot_be_resolved_is_refused_not_emptied(reference: str) -> None:
    """Returning `[]` for a bad reference would make a missing log look like an idle step."""
    with pytest.raises(UnresolvableLogRef):
        parse_log_ref(reference)


# ----------------------------------------------------------------- what it means
def test_every_artifact_written_by_a_run_has_a_resolvable_log(completed_run) -> None:
    """The property Spec §14 exists for: provenance that can actually be followed."""
    _client, state, _fsm, run_id, detail = completed_run
    store = state.store
    checked = 0
    for step in store.list_steps(run_id):
        for artifact in store.artifacts_for_step(str(step["step_id"])):
            reference = str(artifact["execution_log_ref"])
            assert reference.startswith("audit://"), reference
            entries = resolve(store, reference)
            checked += 1
            assert entries, f"{reference} resolved to nothing"
            assert any(entry["kind"] == "event" for entry in entries), (
                "a step's log must contain its events"
            )
    assert checked >= 1, "the run should have produced at least one artifact"
    assert detail["steps"][0]["state"] == "COMMITTED"


def test_the_log_contains_the_gate_verdict_and_the_artifact(completed_run) -> None:
    """Following the reference answers 'was it gated, and what was produced?'."""
    _client, state, _fsm, run_id, _detail = completed_run
    store = state.store
    step = store.list_steps(run_id)[0]
    entries = resolve(store, execution_log_ref(run_id, str(step["step_id"])))
    kinds = {entry["kind"] for entry in entries}
    assert "gate" in kinds, "the tier-1 verdict must be in the log"
    assert "artifact" in kinds, "the artifact itself must be named in the log"
    gate = next(entry for entry in entries if entry["kind"] == "gate")
    assert gate["event_type"].startswith("tier1:")
    # The evidence column is where the twelve deterministic checks live.
    assert gate["payload"]["evidence"].get("checks"), "the gate row must carry its checks"


def test_the_log_is_ordered_and_carries_the_causal_chain(completed_run) -> None:
    """An execution log that is not ordered is not a log."""
    _client, state, _fsm, run_id, _detail = completed_run
    store = state.store
    step = store.list_steps(run_id)[0]
    entries = resolve(store, execution_log_ref(run_id, str(step["step_id"])))
    timestamps = [entry["timestamp"] for entry in entries]
    assert timestamps == sorted(timestamps), timestamps
    events = [entry for entry in entries if entry["kind"] == "event"]
    assert events, "the log must contain the step's events"
    # Spec §5.1: a step event must be traceable to what caused it.
    assert all("causation_id" in entry for entry in events)
    assert any(entry["causation_id"] for entry in events[1:]), (
        "step events after the first must name a cause"
    )


def test_an_unknown_run_or_step_is_refused(completed_run) -> None:
    _client, state, _fsm, run_id, _detail = completed_run
    store = state.store
    with pytest.raises(UnresolvableLogRef, match="no run"):
        resolve(store, "audit://run_does_not_exist/step/run_does_not_exist:N1")
    with pytest.raises(UnresolvableLogRef, match="no step"):
        resolve(store, execution_log_ref(run_id, f"{run_id}:NOT-A-NODE"))


def test_a_run_level_event_does_not_claim_a_step(completed_run) -> None:
    """`step_id` on a run-level event must be empty, not the run id.

    Returning the run id made every run-level audit row look like it belonged to a step
    whose id happened to equal the run id, which is precisely what an audit trail cannot do.
    """
    _client, state, _fsm, run_id, _detail = completed_run
    store = state.store
    run_events = [
        event
        for event in store.events_for_execution(str(store.get_run(run_id)["execution_id"]))
        if event.aggregate_id.startswith("run:")
    ]
    assert run_events, "a run produces run-level events"
    assert all(event.step_id == "" for event in run_events)


# ------------------------------------------------------------------- interfaces
def test_the_http_endpoint_resolves_the_reference(completed_run) -> None:
    client, _state, _fsm, run_id, detail = completed_run
    step_id = detail["steps"][0]["step_id"]
    response = client.get(f"/api/runs/{run_id}/steps/{step_id}/log")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["reference"] == execution_log_ref(run_id, step_id)
    assert body["entries"]
    assert any(entry["kind"] == "gate" for entry in body["entries"])

    # A node id is accepted in place of the full step id, as everywhere else in the console.
    by_node = client.get(f"/api/runs/{run_id}/steps/{detail['steps'][0]['node_id']}/log")
    assert by_node.status_code == 200
    assert by_node.json()["entries"] == body["entries"]

    missing = client.get(f"/api/runs/{run_id}/steps/{run_id}:NOPE/log")
    assert missing.status_code == 404


def test_the_verify_command_reports_no_dangling_references(completed_run) -> None:
    """`verify` is the release check; a dangling reference must fail it."""
    from daedalus.cli import cmd_verify

    _client, state, _fsm, _run_id, _detail = completed_run
    args = type("Args", (), {"workspace": str(state.settings.workspace.root)})()
    assert cmd_verify(args) == 0


def test_captured_load_ref_is_json_serialisable(completed_run) -> None:
    """The export path must be able to serialise whatever the resolver returns."""
    _client, state, _fsm, run_id, detail = completed_run
    step_id = detail["steps"][0]["step_id"]
    entries = resolve(state.store, execution_log_ref(run_id, step_id))
    assert json.loads(json.dumps(entries)) == entries
