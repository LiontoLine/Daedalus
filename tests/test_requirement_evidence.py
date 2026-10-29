"""Requirements need a failing baseline and immutable, actually executed checks."""

import json
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from daedalus.application.coding_worker import FileOp, ModelWorker, ScriptedWorker
from daedalus.application.gatekeeper.tier1 import Tier1Gate
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.requirement_evidence import (
    bind_bundle,
    qualify,
    seal,
    validate_contract,
)
from daedalus.config import load_settings
from daedalus.domain.spec import BoundarySpec
from daedalus.infrastructure.git_sandbox import (
    CommandResult,
    GitSandbox,
    _git,
    init_repo,
    initial_commit,
)
from daedalus.infrastructure.sandbox import HostProcessDriver
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Completion
from daedalus.service.app import create_app

OBJECTIVE = "Double positive integers and preserve zero."
BROKEN = "def scale(value):\n    return value\n"
CORRECT = "def scale(value):\n    return value * 2\n"
SOURCE = '''import unittest
from feature import scale
class RequirementTests(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(scale(3), 6)
    def test_zero(self):
        self.assertEqual(scale(0), 0)
'''


def contract(source=SOURCE, **overrides):
    value = {"version": 1, "objective": OBJECTIVE, "source": source,
             "requirements": [{"id": "R1", "statement": "Double integers, including zero"}],
             "checks": [{"test_name": "test_positive", "requirement_id": "R1", "role": "change"},
                        {"test_name": "test_zero", "requirement_id": "R1", "role": "invariant"}],
             "open_questions": []}
    value.update(overrides)
    return seal(value)


@pytest.fixture
def repo(tmp_path):
    root = init_repo(tmp_path / "repo")
    (root / "feature.py").write_text(BROKEN)
    initial_commit(root, "synthetic behavior baseline")
    return root


def qualified(repo, tmp_path, value=None, isolation="host-process"):
    return qualify(repo, value or contract(), ["feature.py"],
                   BoundarySpec("b", "g", fs_whitelist=("feature.py",), isolation=isolation),
                   tmp_path / "qualification", driver=HostProcessDriver())


def bound(repo, tmp_path):
    value = contract()
    proof = qualified(repo, tmp_path, value)
    bundle = DeterministicPlanner().plan(PlanRequest(
        "request", "goal", OBJECTIVE, ("feature.py",), "python3 -c 'assert True'"))
    bundle = replace(bundle, boundary=replace(bundle.boundary, isolation="host-process"))
    return bind_bundle(bundle, value, proof)


def test_failing_baseline_then_frozen_candidate_evidence(repo, tmp_path):
    initial = GitSandbox.main_commit(repo)
    bundle = bound(repo, tmp_path)
    assert GitSandbox.main_commit(repo) == initial
    assert not _git(repo, ["status", "--porcelain"], check=True).stdout.strip()
    box = GitSandbox.create(repo_path=repo, run_root=tmp_path / "trees", name="candidate")
    try:
        gate = Tier1Gate(bundle.goal, bundle.plan.nodes[0], bundle.boundary, bundle.meta)
        behavior = bundle.goal.acceptance_criteria[-1]
        # A fake successful override must never replace the controller-owned suite.
        bad = gate._check_acceptance(box, acceptance_overrides={behavior.criterion_id:
            lambda _: CommandResult("fake", 0, "", "", 0)})
        assert not bad.passed
        item = bad.evidence["criteria"][-1]["behavior_evidence"]
        assert item["receipt"]["complete"] and not item["receipt"]["passed"]
        assert item["baseline_commit"] == initial
        assert item["receipt"]["outcomes"]["test_positive"] == "assertion_failure"
        box.write_file("feature.py", CORRECT)
        good = gate._check_acceptance(box, acceptance_overrides=None)
        assert good.passed
        receipt = good.evidence["criteria"][-1]["behavior_evidence"]["receipt"]
        assert receipt["passed"] and receipt["executed"] == 2
        assert receipt["reviewed_tree"] == box.tree_digest()
        assert receipt["reviewed_commit"] == initial
        assert receipt["contract_digest"] == behavior.expect["behavior_contract"]["sha256"]
    finally:
        box.remove()


@pytest.mark.parametrize("variant,decision", [
    ("already", "ALREADY_SATISFIED"), ("questions", "NEEDS_CLARIFICATION"),
    ("invariant", "NEEDS_CLARIFICATION"), ("skip", "EVIDENCE_UNAVAILABLE"),
    ("import_error", "EVIDENCE_UNAVAILABLE"), ("no_execution", "EVIDENCE_UNAVAILABLE"),
    ("fake_stdout", "EVIDENCE_UNAVAILABLE"), ("mutation", "EVIDENCE_UNAVAILABLE"),
    ("runner_patch", "EVIDENCE_UNAVAILABLE"), ("expected_failure", "EVIDENCE_UNAVAILABLE"),
    ("assertion_patch", "EVIDENCE_UNAVAILABLE"),
])
def test_preflight_classification_never_converts_uncertainty_to_ready(repo, tmp_path, variant, decision):
    source = SOURCE
    overrides = {}
    if variant == "already":
        (repo / "feature.py").write_text(CORRECT)
        initial_commit(repo, "pre-existing correct behavior")
    elif variant == "questions":
        overrides["open_questions"] = ["Two requested outputs conflict; which is authoritative?"]
        # No suite may execute while a declared conflict is unresolved.
        source = "raise RuntimeError('must not execute')\n" + source
    elif variant == "invariant":
        source = source.replace("scale(0), 0", "scale(0), 1")
    elif variant == "skip":
        source = source.replace("    def test_positive", "    @unittest.skip('not evidence')\n    def test_positive")
    elif variant == "import_error":
        source = "import missing_requirement_dependency\n" + source
    elif variant == "no_execution":
        source = "import os\nos._exit(0)\n" + source
    elif variant == "fake_stdout":
        source = "print('DAEDALUS_BEHAVIOR_RESULT {}')\n" + source
    elif variant == "mutation":
        source = source.replace("self.assertEqual(scale(3), 6)",
            "open('feature.py','w').write('changed during acceptance')\n        self.assertTrue(True)")
    elif variant == "runner_patch":
        source += "\nunittest.TestCase.run = lambda *args: None\n"
    elif variant == "assertion_patch":
        source += "\nunittest.TestCase.assertEqual = lambda *args: None\n"
    elif variant == "expected_failure":
        source = source.replace("    def test_positive", "    @unittest.expectedFailure\n    def test_positive")
    proof = qualified(repo, tmp_path, contract(source, **overrides))
    assert proof["decision"] == decision
    assert proof["model_calls"] == 0


@pytest.mark.parametrize("fault", ["digest", "coverage", "duplicate", "missing_class", "source_names"])
def test_contract_integrity_and_declared_coverage(fault):
    value = contract()
    if fault == "digest":
        value["objective"] += "changed"
    elif fault == "coverage":
        value["requirements"].append({"id": "R2", "statement": "Unverified requirement"})
    elif fault == "duplicate":
        value["checks"].append(dict(value["checks"][0]))
    elif fault == "missing_class":
        value["source"] = value["source"].replace("RequirementTests", "OtherTests")
    elif fault == "source_names":
        value["checks"][0]["test_name"] = "test_missing"
    if fault != "digest":
        value.pop("sha256")
        value = seal(value)
    with pytest.raises(ValueError):
        validate_contract(value)


@pytest.mark.parametrize("fault", ["proof_digest", "source_digest", "other_goal", "other_scope", "other_isolation", "natural_language"])
def test_bound_criteria_fail_closed_on_subject_drift(repo, tmp_path, fault):
    bundle = bound(repo, tmp_path)
    criterion = bundle.goal.acceptance_criteria[-1]
    if fault == "proof_digest":
        criterion.expect["baseline_qualification"]["decision"] = "ALREADY_SATISFIED"
    elif fault == "source_digest":
        criterion.expect["behavior_contract"]["source"] += "\n# changed"
    elif fault == "other_goal":
        bundle = replace(bundle, goal=replace(bundle.goal, objective="different request"))
    elif fault == "other_scope":
        bundle = replace(bundle, boundary=replace(bundle.boundary, fs_whitelist=("other.py",)))
    elif fault == "other_isolation":
        bundle = replace(bundle, boundary=replace(bundle.boundary, isolation="seatbelt"))
    elif fault == "natural_language":
        from daedalus.domain.spec import AssertionKind
        criterion = replace(criterion, kind=AssertionKind.NATURAL_LANGUAGE)
        node = bundle.plan.nodes[0]
        checks = (*node.acceptance_criteria[:-1], criterion)
        bundle = replace(bundle, plan=replace(bundle.plan, nodes=(replace(node,
            extra={**node.extra, "acceptance_criteria": [c.to_dict() for c in checks]}),)))
    box = GitSandbox.create(repo_path=repo, run_root=tmp_path / "trees", name="drift")
    try:
        box.write_file("feature.py", CORRECT)
        gate = Tier1Gate(bundle.goal, bundle.plan.nodes[0], bundle.boundary, bundle.meta)
        result = gate._check_acceptance(box, acceptance_overrides=None)
        assert not result.passed
        assert result.evidence["criteria"][-1]["error_code"] == "spec_digest_mismatch"
    finally:
        box.remove()


@pytest.fixture
def api(tmp_path, monkeypatch):
    # Offline ASGI coverage uses a host fake. Actual Seatbelt is checked separately.
    import daedalus.service.requirement_routes as routes
    monkeypatch.setattr(routes, "SeatbeltDriver", HostProcessDriver)
    with TestClient(create_app(load_settings(None, workspace_root=str(tmp_path / "service")))) as client:
        state = client.app.state.daedalus
        monkeypatch.setattr(state, "build_worker", lambda **_: pytest.fail("unexpected model/worker construction"))
        yield client, state


def payload(repo, **overrides):
    value = contract()
    value.pop("sha256")
    value.pop("version")
    value.update(repo_path=str(repo), target_paths=["feature.py"], confirm_operator_tests=True)
    value.update(overrides)
    return value


def submit(client, repo, **overrides):
    response = client.post("/api/requirement-checks", json=payload(repo, **overrides),
                           headers={"x-daedalus-requirements": "1"})
    assert response.status_code == 202, response.text
    check_id = response.json()["check_id"]
    for _ in range(150):
        row = client.get("/api/requirement-checks/" + check_id).json()
        if row["status"] not in {"QUEUED", "RUNNING"}:
            return check_id, row
        time.sleep(.02)
    pytest.fail("synthetic requirement check did not finish")


def test_api_preflight_and_stale_receipt_rejected_before_worker(api, repo):
    client, state = api
    check_id, row = submit(client, repo)
    assert row["status"] == "READY" and row["model_calls"] == 0
    artifact = client.get(f"/api/requirement-checks/{check_id}/artifacts/report.json")
    assert artifact.status_code == 200 and artifact.json() == row["report"]
    (repo / "feature.py").write_text(CORRECT)
    initial_commit(repo, "base changed after qualification")
    response = client.post("/api/runs", json={"repo_path": str(repo), "objective": OBJECTIVE,
        "target_paths": ["feature.py"], "test_command": "true", "use_model": True,
        "requirement_check_id": check_id})
    assert response.status_code == 409
    assert not state.store.list_runs()


@pytest.mark.parametrize("mode", ["already", "questions"])
def test_api_no_repair_run_for_satisfied_or_unclear_inputs(api, repo, mode):
    client, state = api
    options = {}
    if mode == "already":
        (repo / "feature.py").write_text(CORRECT)
        initial_commit(repo, "already implemented")
    else:
        options["open_questions"] = ["Output expectations disagree"]
    check_id, row = submit(client, repo, **options)
    assert row["status"] == ("ALREADY_SATISFIED" if mode == "already" else "NEEDS_CLARIFICATION")
    response = client.post("/api/runs", json={"repo_path": str(repo), "objective": OBJECTIVE,
        "target_paths": ["feature.py"], "test_command": "true", "use_model": True,
        "requirement_check_id": check_id})
    assert response.status_code == 409 and not state.store.list_runs()


def test_api_operator_action_and_no_source_echo(api, repo):
    client, _state = api
    assert client.post("/api/requirement-checks", json=payload(repo)).status_code == 403
    headers = {"x-daedalus-requirements": "1", "origin": "https://untrusted.invalid"}
    assert client.post("/api/requirement-checks", json=payload(repo), headers=headers).status_code == 403
    value = payload(repo, source="private source sentinel", unexpected="invalid field")
    response = client.post("/api/requirement-checks", json=value,
                           headers={"x-daedalus-requirements": "1"})
    assert response.status_code == 422 and "private source sentinel" not in response.text


@pytest.mark.parametrize("correct", [False, True])
def test_real_orchestrator_enforces_behavior_before_review_and_delivery(repo, tmp_path, correct):
    bundle = bound(repo, tmp_path)
    worker = ScriptedWorker(ops=(FileOp("write", "feature.py",
        CORRECT if correct else BROKEN + "\n# cosmetic edit\n"),))
    store = EventStore(tmp_path / "events.db")
    owner = RunOrchestrator(store=store, repo_path=repo, run_root=tmp_path / "run-trees",
        bundle=bundle, worker=worker, goal_audit_enabled=True, retry_backoff_sec=0)
    owner.register_spec()
    original = GitSandbox.main_commit(repo)
    try:
        result = owner.run()
        assert (result.status == "COMPLETED") is correct, result.describe()
        assert (GitSandbox.main_commit(repo) != original) is correct
        events = store.events_for_execution(owner.execution_id)
        if not correct:
            assert not any(e.event_type == "StepTier2Decided" for e in events)
            assert not any(e.event_type == "StepCommitted" for e in events)
        assert not store.verify_sequences()
    finally:
        store.close()


def test_repeated_ineffective_plan_stops_without_spending_the_third_attempt(repo, tmp_path):
    class Client:
        model = "offline-test"
        calls = 0
        def complete(self, *args, **kwargs):
            self.calls += 1
            return Completion('{"operations":[]}', prompt_tokens=10, completion_tokens=5)
    client = Client()
    bundle = bound(repo, tmp_path)
    store = EventStore(tmp_path / "repeat-events.db")
    owner = RunOrchestrator(store=store, repo_path=repo, run_root=tmp_path / "repeat-trees",
        bundle=bundle, worker=ModelWorker(client), goal_audit_enabled=True, retry_backoff_sec=0)
    owner.register_spec()
    try:
        result = owner.run()
        assert result.status == "AWAITING_APPROVAL"
        assert client.calls == 2
        assert result.tokens_used == 30
        steps = store.list_steps(owner.run_id)
        assert len(steps) == 1 and steps[0]["attempt"] == 2
        assert "same ineffective plan failure" in steps[0]["last_failure"]
    finally:
        store.close()


def test_partial_plan_verifies_behavior_only_after_every_terminal_change(repo, tmp_path):
    from daedalus.domain.spec import PlanNode
    value = contract()
    proof = qualified(repo, tmp_path, value)
    bundle = DeterministicPlanner().plan(PlanRequest(
        "request", "goal", OBJECTIVE, ("feature.py",), "true"))
    bundle = replace(bundle, boundary=replace(bundle.boundary, isolation="host-process"),
        plan=replace(bundle.plan, nodes=(PlanNode("part-a", expected_artifacts=("feature.py",)),
                                       PlanNode("part-b", expected_artifacts=("feature.py",)))))
    bundle = bind_bundle(bundle, value, proof)
    bundle.validate()
    first, last = bundle.plan.nodes
    assert first.deps == () and last.deps == ("part-a",)
    assert first.acceptance_criteria == bundle.goal.acceptance_criteria[:-1]
    assert last.acceptance_criteria[-1] == bundle.goal.acceptance_criteria[-1]


def test_api_ready_receipt_is_embedded_in_new_spec_and_run(api, repo, monkeypatch):
    import daedalus.service.requirement_routes as routes
    from daedalus.infrastructure.sandbox import DriverRegistry
    # Both API admission and the orchestrator use the same explicit offline fake.
    def factory():
        return HostProcessDriver(name="seatbelt")
    monkeypatch.setattr(routes, "SeatbeltDriver", factory)
    monkeypatch.setattr(DriverRegistry, "default", staticmethod(
        lambda **_: DriverRegistry(drivers={"seatbelt": factory()})))
    client, state = api
    check_id, row = submit(client, repo)
    assert row["status"] == "READY"
    monkeypatch.setattr(state, "build_worker", lambda **_: (ScriptedWorker(
        ops=(FileOp("write", "feature.py", CORRECT),)), None))
    response = client.post("/api/runs", json={"repo_path": str(repo), "objective": OBJECTIVE,
        "target_paths": ["feature.py"], "test_command": "true", "requirement_check_id": check_id})
    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]
    for _ in range(200):
        row = client.get("/api/runs/" + run_id).json()
        if not row["active"] and row["run"]["status"] == "COMPLETED":
            break
        time.sleep(.02)
    else:
        pytest.fail("verified synthetic API run did not complete")
    document = json.loads(state.store.get_spec(response.json()["spec_digest"])["document"])
    behavior = document["spec_01_goal"]["acceptance_criteria"][-1]
    assert behavior["expect"]["baseline_qualification"]["decision"] == "READY"
    assert behavior["expect"]["baseline_qualification"]["base_commit"] == row["run"]["base_commit"]


@pytest.mark.parametrize("references,accepted", [(["actual-receipt"], True), ([], False),
    (["invented-receipt"], False), (["actual-receipt", "extra"], False), (None, False)])
def test_goal_review_references_must_name_actual_execution_receipt(references, accepted):
    from daedalus.application.requirement_evidence import valid_behavior_references
    criteria = [{"criterion_id": "B1", "behavior_evidence": {"receipt": {
        "sha256": "actual-receipt", "passed": True, "complete": True}}}]
    reviewed = [{"criterion_id": "B1", "status": "MET", "evidence": "I claim it works",
                 "evidence_refs": references}]
    assert valid_behavior_references(criteria, reviewed) is accepted


def test_goal_audit_rejects_unattributed_model_claim_even_when_behavior_passes(repo, tmp_path):
    from daedalus.application.gatekeeper.tier2 import Tier2Gate
    from tests.test_goal_audit import GoalReviewer
    bundle = bound(repo, tmp_path)
    reviewer = GoalReviewer(["APPROVE"])
    reviewer.criteria = [c.criterion_id for c in bundle.goal.acceptance_criteria]
    store = EventStore(tmp_path / "claim-events.db")
    owner = RunOrchestrator(store=store, repo_path=repo, run_root=tmp_path / "claim-trees",
        bundle=bundle, worker=ScriptedWorker(ops=(FileOp("write", "feature.py", CORRECT),)),
        tier2=Tier2Gate(reviewer=reviewer), goal_audit_enabled=True, retry_backoff_sec=0)
    owner.register_spec()
    original = GitSandbox.main_commit(repo)
    try:
        result = owner.run()
        assert result.status == "AWAITING_APPROVAL"
        assert GitSandbox.main_commit(repo) == original
        audits = store.events_for("goal:" + owner.run_id)
        audit = next(e.payload for e in audits if e.event_type == "GoalAuditCompleted")
        assert audit["decision"] == "ESCALATE"
        assert "receipt references" in audit["reasons"][0]
    finally:
        store.close()


def test_no_progress_guard_allows_a_changed_source_tree(repo, tmp_path):
    from daedalus.application.worker import WorkerContext
    class Client:
        model = "offline-test"
        def complete(self, *args, **kwargs):
            return Completion('{"operations":[]}', prompt_tokens=10, completion_tokens=5)
    bundle = bound(repo, tmp_path)
    worker = ModelWorker(Client())
    box = GitSandbox.create(repo_path=repo, run_root=tmp_path / "progress-trees", name="progress")
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle, box.head(), 1)
    try:
        assert worker.implement(box, context).error == "worker_no_change"
        box.write_file("feature.py", "def scale(value):\n    return value + 1\n")
        assert worker.implement(box, replace(context, attempt=2)).error == "worker_no_change"
    finally:
        box.remove()
