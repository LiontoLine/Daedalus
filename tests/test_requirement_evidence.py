"""Requirements need a failing baseline and immutable, actually executed checks."""

import json
import time
from copy import deepcopy
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from daedalus.application.coding_worker import FileOp, ModelWorker, ScriptedWorker
from daedalus.application.gatekeeper.tier1 import Tier1Gate
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.repair_evidence import build_snapshot, select_candidates
from daedalus.application.requirement_evidence import (
    bind_bundle,
    model_behavior_evidence,
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


def bound(repo, tmp_path, value=None):
    value = value or contract()
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
        assert "test_positive" not in bad.detail and "assertEqual(scale(3), 6)" not in bad.detail
        assert '"status": "UNMET"' in bad.detail
        missing = build_snapshot(bundle, initial, criteria=bad.evidence["criteria"])
        expectation = missing["nodes"][0]["expectations"][-1]
        assert {c["test_name"]: c["status"] for c in expectation["checks"]} == {
            "test_positive": "UNMET", "test_zero": "MET"}
        assert {c["requirement_id"] for c in expectation["checks"]} == {"R1"}
        assert select_candidates(bundle, missing)[0]["criterion_ids"] == [behavior.criterion_id]
        box.write_file("feature.py", CORRECT)
        good = gate._check_acceptance(box, acceptance_overrides=None)
        assert good.passed
        receipt = good.evidence["criteria"][-1]["behavior_evidence"]["receipt"]
        assert receipt["passed"] and receipt["executed"] == 2
        assert receipt["reviewed_tree"] == box.tree_digest()
        assert receipt["reviewed_commit"] == initial
        assert receipt["contract_digest"] == behavior.expect["behavior_contract"]["sha256"]
        met = build_snapshot(bundle, initial, criteria=good.evidence["criteria"])
        assert {c["status"] for c in met["nodes"][0]["expectations"][-1]["checks"]} == {"MET"}
        tampered = deepcopy(good.evidence["criteria"])
        tampered[-1]["behavior_evidence"]["receipt"]["outcomes"]["test_positive"] = "assertion_failure"
        invalid = build_snapshot(bundle, initial, criteria=tampered)
        assert invalid["nodes"][0]["expectations"][-1]["status"] == "BLOCKED"
        assert select_candidates(bundle, invalid) == []
    finally:
        box.remove()


def test_incomplete_frozen_behavior_is_unknown_to_the_diagnostic_worker(repo, tmp_path):
    from daedalus.application.worker import WorkerContext
    from daedalus.application.worker_checks import CheckRequest, DeclaredCheckRunner

    bundle = bound(repo, tmp_path)
    node = bundle.plan.nodes[0]
    criterion = bundle.goal.acceptance_criteria[-1]
    box = GitSandbox.create(repo_path=repo, run_root=tmp_path / "trees", name="incomplete")
    try:
        box.write_file("feature.py", "def scale(value):\n    raise RuntimeError('candidate crashed')\n")
        context = WorkerContext("step", "execution", node, bundle, box.base_commit, 1)
        observation = DeclaredCheckRunner()(
            box, context, CheckRequest(criterion.criterion_id, "Read the frozen behavior outcome"),
        )
        assert not observation.receipt["passed"] and not observation.receipt["executed"]
        assert observation.receipt["error_code"] == ""
        output = json.loads(observation.content)["output"]
        public = json.loads(output)
        assert {row["status"] for row in public["requirements"]} == {"UNKNOWN"}
        assert public["execution_reason"] == "incomplete_or_invalid_runner_evidence"
        assert "candidate crashed" not in observation.content
    finally:
        box.remove()


@pytest.mark.parametrize("variant,decision", [
    ("already", "ALREADY_SATISFIED"), ("questions", "NEEDS_CLARIFICATION"),
    ("distinct_invariant", "READY"), ("invariant", "NEEDS_CLARIFICATION"),
    ("skip", "EVIDENCE_UNAVAILABLE"),
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
    elif variant == "distinct_invariant":
        original = contract()
        overrides["requirements"] = [
            *original["requirements"], {"id": "preserve-zero", "statement": "Preserve zero"},
        ]
        overrides["checks"] = [
            original["checks"][0],
            {**original["checks"][1], "requirement_id": "preserve-zero"},
        ]
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


def user_path_fields():
    return {
        "behavior_paths": [
            {"id": "Positive", "requirement_id": "R1", "role": "change",
             "entry": "Submit a positive integer", "steps": ["Apply scale", "Read returned value"],
             "outcome": "Result doubles"},
            {"id": "Zero", "requirement_id": "R1", "role": "invariant",
             "entry": "Submit zero", "steps": ["Apply scale", "Read returned value"],
             "outcome": "Result stays zero"},
        ],
        "checks": [
            {**check, "path_id": path} for check, path in zip(
                contract()["checks"], ("Positive", "Zero"), strict=True,
            )
        ],
    }


@pytest.mark.parametrize("mode", ["baseline", "read_then_edit", "changed_tree", "regressed_invariant"])
def test_worker_uses_native_failed_public_path_to_focus_current_source(repo, tmp_path, mode):
    from daedalus.application.inspection import RepositoryInspector
    from daedalus.application.worker import WorkerContext
    from daedalus.application.worker_checks import DeclaredCheckRunner
    dirty = mode in {"changed_tree", "regressed_invariant"}
    reads = mode == "read_then_edit"

    source = ("def overview():\n" + "    unused = 'unrelated administrative code'\n" * 240
              + "\ndef positive_handler(value):\n    return value\n"
              + "\ndef scale(value):\n    return positive_handler(value) if value > 0 else 0\n")
    revised = source.replace("    return value\n", "    return value * 2\n")
    (repo / "feature.py").write_text(source)
    initial_commit(repo, "separate the public behaviors")
    fields = user_path_fields()
    fields["behavior_paths"][0]["steps"] = ["Apply positive_handler"]
    objective = "Correct the overview results"
    value = contract(version=2, objective=objective, **fields)
    proof = qualified(repo, tmp_path, value)
    bundle = DeterministicPlanner().plan(PlanRequest("r", "g", objective, ("feature.py",), "true"))
    bundle = bind_bundle(replace(bundle, boundary=replace(bundle.boundary, isolation="host-process")),
                         value, proof)
    node = bundle.plan.nodes[0]
    criterion = bundle.goal.acceptance_criteria[-1]

    class Client:
        calls = []

        def complete(self, messages, **kwargs):
            prompt = messages[-1].content
            self.calls.append(prompt)
            if reads and len(self.calls) == 1:
                return Completion(json.dumps({"action": "inspect", "tool": "read", "path": "feature.py",
                                              "line": 1, "gap": "Confirm the unrelated entry point"}))
            if reads and len(self.calls) == 3:
                return Completion(json.dumps({"action": "finish"}))
            if dirty and len(self.calls) == 1:
                return Completion(json.dumps({"action": "check", "criterion_id": criterion.criterion_id,
                                              "gap": "Identify the unmet public behavior path"}))
            if mode == "regressed_invariant":
                if len(self.calls) == 2:
                    return Completion(json.dumps({"action": "edit", "operations": [
                        {"op": "replace", "path": "feature.py", "old_text": "    return value\n",
                         "new_text": "    return value * 2\n"},
                        {"op": "replace", "path": "feature.py", "old_text": "else 0\n",
                         "new_text": "else 1\n"},
                    ]}))
                return Completion(json.dumps({"operations": [
                    {"op": "replace", "path": "feature.py", "old_text": "else 1\n",
                     "new_text": "else 0\n"},
                ]}))
            return Completion(json.dumps({"action": "edit" if reads else "candidate", "operations": [
                {"op": "replace", "path": "feature.py", "old_text": "    return value\n",
                 "new_text": "    return value * 2\n"},
            ]}))

    box = GitSandbox.create(repo_path=repo, run_root=tmp_path / "trees", name="native-focus")
    try:
        if dirty:
            # Same HEAD but a different worktree: the baseline verdict is not current.
            box.write_file("feature.py", source + "\n# candidate differs from the qualified tree\n")
            revised += "\n# candidate differs from the qualified tree\n"
        client = Client()
        worker = ModelWorker(client, check_context=DeclaredCheckRunner(),
                             inspection_context=RepositoryInspector() if reads else None)
        result = worker.implement(box, WorkerContext("step", "execution", node, bundle, box.base_commit, 1))
        assert result.ok, result.execution_log
        source_windows = [prompt.split("CURRENT CONTENT:\n", 1)[1].split("```", 2)[1]
                          for prompt in client.calls]
        assert all("test_positive" not in prompt and "test_zero" not in prompt for prompt in client.calls)
        assert len(source_windows) == {"baseline": 1, "read_then_edit": 3,
                                       "changed_tree": 2, "regressed_invariant": 3}[mode]
        if dirty:
            assert "def positive_handler" not in source_windows[0] and "def overview" in source_windows[0]
        focused = source_windows[1 if dirty else 0]
        assert "def positive_handler" in focused and "def overview" not in focused
        if reads:
            receipt, = result.extra["inspection_receipts"]
            assert receipt["tree_digest"] == proof["base_tree"] != box.tree_digest()
            assert "def positive_handler" in source_windows[1] and "def overview" not in source_windows[1]
            assert "def positive_handler" not in source_windows[2] and "def overview" in source_windows[2]
        checks = result.extra["check_receipts"]
        if mode == "regressed_invariant":
            outputs = [json.loads(line) for line in client.calls[2].splitlines()
                       if line.startswith('{"receipt":') and '"behavior_paths"' in line]
            current = next(row for row in outputs if row["receipt"]["reviewed_tree"] == checks[1]["tree_digest"])
            assert {row["path_id"]: row["status"] for row in current["behavior_paths"]} == {
                "Positive": "MET", "Zero": "UNMET",
            }
            assert [(row["executed"], row["passed"]) for row in checks] == [
                (True, False), (True, False), (True, True),
            ]
            assert len({row["tree_digest"] for row in checks}) == 3
            assert checks[-1]["tree_digest"] == box.tree_digest()
        elif dirty:
            assert [(row["executed"], row["passed"]) for row in checks] == [(True, False), (True, True)]
            assert checks[0]["tree_digest"] != checks[1]["tree_digest"] == box.tree_digest()
        else:
            assert not checks
            gate = Tier1Gate(bundle.goal, node, bundle.boundary, bundle.meta, driver=HostProcessDriver())
            assert gate._check_acceptance(box, acceptance_overrides=None).passed
        assert box.read_file("feature.py") == revised
    finally:
        box.remove()


@pytest.mark.parametrize("moves_failure", [False, True])
def test_worker_distinguishes_repeated_native_criterion_by_failing_paths(repo, tmp_path, moves_failure):
    from daedalus.application.worker import WorkerContext
    from daedalus.application.worker_checks import DeclaredCheckRunner
    from tests.test_agentic_rag import Controller

    value = contract(version=2, **user_path_fields())
    proof = qualified(repo, tmp_path, value)
    bundle = DeterministicPlanner().plan(PlanRequest("r", "g", OBJECTIVE, ("feature.py",), "true"))
    bundle = bind_bundle(replace(bundle, boundary=replace(bundle.boundary, isolation="host-process")),
                         value, proof)
    criterion = bundle.goal.acceptance_criteria[-1]

    def write(content, action="edit"):
        return {"action": action, "operations": [{"op": "write", "path": "feature.py", "content": content}]}

    first = "def scale(value):\n    return value + 1 if value else 0\n"
    second = ("def scale(value):\n    return value * 2 if value else 1\n" if moves_failure
              else "def scale(value):\n    return value + 2 if value else 0\n")
    model = Controller([
        write(first),
        {"action": "check", "criterion_id": criterion.criterion_id, "gap": "Verify the initial edit"},
        write(second),
        write(CORRECT, "candidate"),
    ])
    box = GitSandbox.create(repo_path=repo, run_root=tmp_path / "trees", name="repeated-path")
    try:
        context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle, box.base_commit, 1)
        result = ModelWorker(model, check_context=DeclaredCheckRunner()).implement(box, context)
        checks = result.extra["check_receipts"]
        assert checks[0]["tree_digest"] != checks[1]["tree_digest"]
        assert all(row["executed"] and not row["passed"] for row in checks[:2])
        assert not any("test_positive" in request[-1].content for request in model.calls)
        if moves_failure:
            assert result.ok and len(model.calls) == 4 and len(checks) == 3
            assert checks[2]["passed"] and checks[2]["tree_digest"] == box.tree_digest()
            assert box.read_file("feature.py") == CORRECT
        else:
            assert result.error == "worker_no_progress" and len(model.calls) == 3
            assert len(checks) == 2 and checks[1]["tree_digest"] == box.tree_digest()
            assert box.read_file("feature.py") == second
    finally:
        box.remove()


@pytest.mark.parametrize("same_spec", [True, False])
@pytest.mark.parametrize("inner_check", [False, True])
def test_replay_recalls_native_paths_from_the_exact_failed_gate(repo, tmp_path, same_spec, inner_check):
    from daedalus.application.worker_checks import DeclaredCheckRunner
    from tests.test_agentic_rag import Controller

    fields = user_path_fields()
    fields["behavior_paths"][0]["steps"] = ["Apply positive_handler"]
    fields["behavior_paths"][1]["steps"] = ["Apply zero_handler"]
    baseline_source = (
        "def overview():\n" + "    unused = 'unrelated administrative code'\n" * 240
        + "\n\n\ndef positive_handler(value):\n    return value\n"
        + "\n\n\ndef zero_handler():\n    return 0\n"
        + "\n\n\ndef scale(value):\n    return positive_handler(value) if value else zero_handler()\n"
    )
    (repo / "feature.py").write_text(baseline_source)
    initial_commit(repo, "separate behavior paths in source")
    bundle = bound(repo, tmp_path, contract(version=2, **fields))
    node = bundle.plan.nodes[0]
    node = replace(node, retry_policy=replace(node.retry_policy, max_attempts=1))
    bundle = replace(bundle, plan=replace(bundle.plan, nodes=(node,)))
    rejected_code = baseline_source.replace("    return value\n", "    return value * 2\n").replace(
        "    return 0\n", "    return 1\n",
    )
    final_code = baseline_source.replace("    return value\n", "    return value * 2\n")
    base = GitSandbox.main_commit(repo)
    if inner_check:
        criterion_id = bundle.goal.acceptance_criteria[-1].criterion_id
        failed_worker = ModelWorker(Controller([
            {"action": "edit", "operations": [
                {"op": "write", "path": "feature.py", "content": rejected_code},
            ]},
            {"action": "check", "criterion_id": criterion_id, "gap": "Verify the edited paths"},
            {"action": "finish"},
        ]), check_context=DeclaredCheckRunner())
    else:
        failed_worker = ScriptedWorker((FileOp("write", "feature.py", rejected_code),))
    with EventStore(tmp_path / "native-replay.db") as store:
        first = RunOrchestrator(
            store, repo, tmp_path / "source", bundle,
            worker=failed_worker,
            retry_backoff_sec=0,
        )
        first.register_spec()
        failed = first.run()
        assert failed.status == "FAILED" and GitSandbox.main_commit(repo) == base
        events = store.events_for_execution(failed.execution_id)
        failure, = [event.payload for event in events if event.event_type == "TrunkNodeFailed"]
        gates = store.gate_results_for_step(failure["step_id"])
        if inner_check:
            assert not gates and failure["error_code"] == "worker_validation_failed"
            observed, = [event.payload for event in events if event.event_type == "WorkerEngineeringObserved"]
            checked, = observed["check_receipts"]
            assert checked["executed"] and not checked["passed"]
            assert checked["behavior_path_evidence"]["outcomes"] == {"Positive": True, "Zero": False}
            native = {"reviewed_tree": checked["tree_digest"],
                      "sha256": checked["behavior_path_evidence"]["receipt_sha256"]}
        else:
            gate, = gates
            native, = [row["behavior_evidence"]["receipt"] for check in json.loads(gate["evidence"])["checks"]
                       for row in check["evidence"].get("criteria", ()) if row.get("behavior_evidence")]
        if not same_spec:
            bundle = replace(bundle, plan=replace(bundle.plan, nodes=(replace(node, intent="Updated plan"),)))
        model = Controller([{"operations": [{"op": "write", "path": "feature.py", "content": final_code}]}])
        replay = RunOrchestrator(
            store, repo, tmp_path / "replay", bundle, worker=ModelWorker(model),
            parent_execution_id=failed.execution_id, replay_from_commit=base, retry_backoff_sec=0,
        )
        replay.register_spec()
        delivered = replay.run()
        assert delivered.status == "COMPLETED" and delivered.promoted_commit == GitSandbox.main_commit(repo)
        assert (repo / "feature.py").read_text() == final_code
        assert len(model.calls) == 1
        prompt = model.calls[0][-1].content
        window = prompt.split("CURRENT CONTENT:\n", 1)[1].split("```", 2)[1]
        assert ("def zero_handler" in window) is same_spec
        assert ("def positive_handler" in window) is not same_spec
        assert "test_positive" not in prompt and "test_zero" not in prompt
        if same_spec:
            section = prompt.split("SCOPED REPAIR MEMORY", 1)[1].split("\n", 1)[1]
            records, _ = json.JSONDecoder().raw_decode(section)
            record, = records
            assert record["source_execution_id"] == failed.execution_id
            assert record["candidate_tree"] == native["reviewed_tree"]
            path_result, = record["historical_behavior_paths"]
            assert path_result["receipt_sha256"] == native["sha256"]
            assert {row["path_id"]: row["status"] for row in path_result["paths"]} == {
                "Positive": "MET", "Zero": "UNMET",
            }
        else:
            assert "historical_behavior_paths" not in prompt and failed.execution_id not in prompt


def test_rebase_failure_recalls_paths_from_rebased_tree_not_original_pass(repo, tmp_path):
    from daedalus.application.scheduler import Quota
    from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, PlanNode

    (repo / "settings.py").write_text("ENABLED = False\n")
    baseline = initial_commit(repo, "add independent configuration baseline")
    paths = ("feature.py", "settings.py")
    bundle = DeterministicPlanner().plan(PlanRequest("r", "g", OBJECTIVE, paths, "true"))
    boundary = replace(bundle.boundary, isolation="host-process")
    value = contract(version=2, **user_path_fields())
    proof = qualify(repo, value, list(paths), boundary, tmp_path / "base", driver=HostProcessDriver())
    bundle = bind_bundle(replace(bundle, boundary=boundary), value, proof)
    feature = replace(bundle.plan.nodes[0], expected_artifacts=("feature.py",))
    settings = PlanNode(
        node_id="a-settings", objective="Enable the setting", expected_artifacts=("settings.py",),
        extra={"acceptance_criteria": [
            AcceptanceCriterion("enabled", AssertionKind.FILE_CONTENT, path="settings.py",
                                expect="ENABLED = True").to_dict()
        ]},
    )
    bundle = replace(bundle, plan=replace(bundle.plan, nodes=(settings, feature)))
    retry_contexts = []

    class Worker:
        def implement(self, sandbox, context):
            if context.node.node_id == settings.node_id:
                op = FileOp("write", "settings.py", "ENABLED = True\n")
            elif context.attempt == 1:
                op = FileOp("write", "feature.py", "from settings import ENABLED\n\n"
                            "def scale(value):\n    return value * 2 if value else int(ENABLED)\n")
            else:
                retry_contexts.append((context, GitSandbox.main_commit(repo), sandbox.read_file("settings.py")))
                op = FileOp("write", "feature.py", CORRECT)
            return ScriptedWorker((op,)).implement(sandbox, context)

    with EventStore(tmp_path / "rebase.db") as store:
        owner = RunOrchestrator(store, repo, tmp_path / "trees", bundle, worker=Worker(),
                                quota=Quota(max_parallel_steps=2), retry_backoff_sec=0)
        owner.register_spec()
        result = owner.run()
        assert result.status == "COMPLETED", result.describe()
        (retry, target_during_retry, settings_during_retry), = retry_contexts
        assert retry.base_commit != baseline and target_during_retry == baseline
        assert settings_during_retry == "ENABLED = True\n"
        assert (repo / "feature.py").read_text() == CORRECT
        assert (repo / "settings.py").read_text() == settings_during_retry
        events = store.events_for_execution(result.execution_id)
        assert [event.payload["node_id"] for event in events if event.event_type == "StepCommitted"] == [
            settings.node_id, feature.node_id,
        ]
        rejected, = [event.payload for event in events if event.event_type == "TrunkNodeFailed"]
        assert rejected["base_commit"] == retry.base_commit and rejected["commit"] != retry.base_commit
        assert rejected["error_code"] == "executed_acceptance_failure" and rejected["rejected_by_gate"]
        assert rejected["candidate_tree"] in retry.rejected_candidate_trees
        memory, = retry.repair_memory
        path_result, = memory["historical_behavior_paths"]
        assert memory["base_commit"] == retry.base_commit and memory["candidate_tree"] == rejected["candidate_tree"]
        gates = store.gate_results_for_step(rejected["step_id"])
        assert [gate["decision"] for gate in gates] == ["PASS", "REVISE", "PASS"]
        regate = next(gate for gate in gates if gate["gate_result_id"] == rejected["behavior_gate_result_id"])
        receipt, = [row["behavior_evidence"]["receipt"] for check in json.loads(regate["evidence"])["checks"]
                    for row in check["evidence"].get("criteria", ()) if row.get("behavior_evidence")]
        assert path_result["receipt_sha256"] == receipt["sha256"]
        assert {row["path_id"]: row["status"] for row in path_result["paths"]} == {
            "Positive": "MET", "Zero": "UNMET",
        }


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


@pytest.mark.parametrize("paths", [False, True])
def test_intake_reviewed_proof_is_invalidated_without_starting_worker(api, repo, monkeypatch, paths):
    from daedalus.application.planner import ModelPlanner
    from daedalus.model.mock import MockModelClient
    from tests.test_intake import _questions_payload
    from daedalus.application.intake import ModelQuestioner

    client, state = api
    state.intake.base_request["target_paths"] = ["feature.py"]
    check_id, row = submit(client, repo, **(user_path_fields() if paths else {}))
    assert row["status"] == "READY"
    if paths:
        assert {path["id"]: path["status"] for path in row["behavior_paths"]} == {
            "Positive": "UNMET", "Zero": "MET",
        }
    planned = DeterministicPlanner().plan(
        PlanRequest("request", "goal", OBJECTIVE, ("feature.py",), "true"),
    )
    monkeypatch.setattr(state.intake, "questioner_factory", lambda: ModelQuestioner(
        client=MockModelClient(responder=lambda _: json.dumps(_questions_payload())),
    ))
    monkeypatch.setattr(state.intake, "reference_context_factory", None)
    monkeypatch.setattr(state.intake, "planner_factory", lambda: ModelPlanner(
        client=MockModelClient(responder=lambda _: json.dumps(planned.to_dict())),
        require_model=True,
    ))
    session = client.post("/api/intakes", json={
        "repo_path": str(repo), "objective": OBJECTIVE, "goal_id": "goal",
    }).json()["intake"]
    intake = "/api/intakes/" + session["intake_id"]
    before = client.post(intake + "/spec", json={"require_behavior_paths": True})
    assert before.status_code == 409 and not state.store.list_runs()
    preview = client.post(intake + "/spec", json={
        "requirement_check_id": check_id, "require_behavior_paths": paths,
    })
    assert preview.status_code == 200, preview.text
    assert "test_positive" not in preview.text
    if paths:
        criteria = preview.json()["document"]["spec_01_goal"]["acceptance_criteria"]
        path_criterion, = [criterion for criterion in criteria if "behavior_paths" in criterion]
        assert "expect" not in path_criterion
        assert path_criterion["behavior_paths"] == row["behavior_paths"]
    digest = preview.json()["spec_digest"]
    if not paths:
        strict_freeze = client.post(intake + "/freeze", json={
            "spec_digest": digest, "require_behavior_paths": True, "use_model": True,
        })
        assert strict_freeze.status_code == 409 and not state.store.list_runs()
    (repo / "feature.py").write_text(CORRECT)
    initial_commit(repo, "advance after the operator has reviewed the spec")
    response = client.post(intake + "/freeze", json={
        "spec_digest": digest, "require_behavior_paths": paths, "use_model": True,
    })
    assert response.status_code == 409 and not state.store.list_runs()


def test_api_preflight_and_stale_receipt_rejected_before_worker(api, repo):
    client, state = api
    check_id, row = submit(client, repo)
    assert row["status"] == "READY" and row["model_calls"] == 0
    path = f"/api/requirement-checks/{check_id}/artifacts/report.json"
    assert client.get(path).status_code == 403
    artifact = client.get(path, headers={"x-daedalus-requirements": "1"})
    assert artifact.status_code == 200
    assert artifact.json()["sha256"] == row["report"]["proof_sha256"]
    assert "test_positive" in artifact.json()["baseline"]["outcomes"]
    assert "test_positive" not in json.dumps(row)
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


@pytest.mark.parametrize("fault", ["not_linked", "wrong_role"])
def test_user_path_requirements_need_native_checks_of_matching_role(api, repo, fault):
    client, state = api
    fields = user_path_fields()
    if fault == "not_linked":
        fields["checks"][0].pop("path_id")
    else:
        fields["checks"][0]["path_id"] = "Zero"
    response = client.post("/api/requirement-checks", json=payload(repo, **fields),
                           headers={"x-daedalus-requirements": "1"})
    assert response.status_code == 422 and "test_positive" not in response.text
    assert not state.store.list_runs()


@pytest.mark.parametrize("repair_path,full_paths", [
    ("../feature.py", True), ("*.py", True), ("client.py", True), ("feature.py", False),
])
def test_public_repair_anchor_rejects_unqualified_scope(api, repo, repair_path, full_paths):
    client, state = api
    fields = user_path_fields() if full_paths else {}
    refused = client.post("/api/requirement-checks", json=payload(repo, repair_path=repair_path, **fields),
                          headers={"x-daedalus-requirements": "1"})
    assert refused.status_code == 422 and "RequirementTests" not in refused.text
    assert not (state.settings.workspace.root_path / "requirement-checks").exists()


@pytest.mark.parametrize("mode", ["assertion_failure", "pass", "launch_unavailable", "goal_launch_unavailable"])
def test_real_orchestrator_enforces_behavior_before_review_and_delivery(repo, tmp_path, monkeypatch, mode):
    bundle = bound(repo, tmp_path)
    correct = mode != "assertion_failure"
    launches = 0
    if mode.endswith("launch_unavailable"):
        import sys

        from daedalus.infrastructure.sandbox.base import CommandOutcome

        original_run = HostProcessDriver.run

        def run(driver, *, worktree, command, timeout_sec, boundary):
            nonlocal launches
            if list(command[:4]) == [sys.executable, "-B", "-I", "-c"]:
                launches += 1
                if launches == (2 if mode == "goal_launch_unavailable" else 1):
                    return CommandOutcome("python", 125, "",
                                          "sh: fork: Resource temporarily unavailable", 0)
            return original_run(driver, worktree=worktree, command=command,
                                timeout_sec=timeout_sec, boundary=boundary)

        monkeypatch.setattr(HostProcessDriver, "run", run)
    worker = ScriptedWorker(ops=(FileOp("write", "feature.py",
        CORRECT if correct else BROKEN + "\n# cosmetic edit\n"),))
    store = EventStore(tmp_path / "events.db")
    owner = RunOrchestrator(store=store, repo_path=repo, run_root=tmp_path / "run-trees",
        bundle=bundle, worker=worker, goal_audit_enabled=True, retry_backoff_sec=0)
    owner.register_spec()
    original = GitSandbox.main_commit(repo)
    try:
        result = owner.run()
        published = mode == "pass"
        assert (result.status == "COMPLETED") is published, result.describe()
        assert (GitSandbox.main_commit(repo) != original) is published
        events = store.events_for_execution(owner.execution_id)
        if mode in {"assertion_failure", "launch_unavailable"}:
            assert not any(e.event_type == "StepTier2Decided" for e in events)
            assert not any(e.event_type == "StepCommitted" for e in events)
        if mode == "launch_unavailable":
            recorded = [e for e in events if e.event_type == "StepTier1Decided"]
            assert len(recorded) == 1
            assert recorded[0].payload["error_codes"] == ["execution_environment_unavailable"]
            failed, = [e for e in events if e.event_type == "StepExecutionFailed"]
            assert failed.payload["error_code"] == "execution_environment_unavailable"
            assert failed.payload["branch_retryable"] is False
        if mode == "goal_launch_unavailable":
            assert launches == 2
            committed, = [e.payload for e in events if e.event_type == "StepCommitted"]
            assert committed["attempt"] == 1
            assert _git(repo, ["show", f"{committed['commit']}:feature.py"], check=True).stdout == CORRECT
            audit = result.goal_audit
            stage, = audit["stages"]
            assert stage["decision"] == "ESCALATE" and stage["scope"] == "execution_environment"
            assert stage["error_code"] == "execution_environment_unavailable"
            assert not audit["iterations"]
            public = model_behavior_evidence(stage["criteria"][-1]["behavior_evidence"])
            assert public["receipt"]["executed"] == 0 and not public["receipt"]["complete"]
            assert {row["role"]: row["status"] for row in public["requirements"]} == {
                "change": "UNKNOWN", "invariant": "UNKNOWN",
            }
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
        assert result.status == "FAILED"
        assert client.calls == 2
        assert result.tokens_used == 30
        steps = store.list_steps(owner.run_id)
        assert len(steps) == 1 and steps[0]["attempt"] == 2
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


@pytest.mark.parametrize("mode", [
    "unanchored", "anchored", "semantic_only", "inner_regression", "inner_same", "outer_regression",
    "outer_crowded", "incremental_repair", "incremental_crowded", "incremental_mixed",
])
def test_integrated_native_failure_repairs_only_a_frozen_owner(repo, tmp_path, mode, monkeypatch):
    from daedalus.application import branch_repair
    from daedalus.application.coding_worker import MAX_ENGINEERING_RECORD_CHARS
    from daedalus.application.gatekeeper.tier2 import Tier2Gate
    from daedalus.application.worker_checks import DeclaredCheckRunner
    from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, PlanNode, PlanSpec
    from tests.test_agentic_rag import Controller

    mixed = mode == "incremental_mixed"
    incremental = mixed or mode in {"incremental_repair", "incremental_crowded"}
    repaired = mode in {"anchored", "inner_regression", "outer_regression", "outer_crowded"} or incremental
    crowded = mode in {"outer_crowded", "incremental_crowded"}
    feature_source = (
        "def overview():\n" + "    unused = 'unrelated administrative code'\n" * 240
        + "\n\n\ndef positive_handler(value):\n    return value\n"
        + "\n\n\ndef zero_handler():\n    return 0\n"
        + "\n\n\ndef scale(value):\n    return positive_handler(value) if value > 0 else zero_handler()\n"
    )
    fixed_feature = feature_source.replace("    return value\n", "    return value * 2\n")
    (repo / "feature.py").write_text(feature_source)
    inner = mode in {"inner_regression", "inner_same"}
    first_rejected = inner or mode in {"outer_regression", "outer_crowded"}
    (repo / "client.py").write_text("def scale(value):\n    return max(value, 0)\n" if crowded else BROKEN)
    baseline = initial_commit(repo, "add the consumer baseline")
    targets = ("feature.py", "client.py")
    fields = user_path_fields()
    fields["behavior_paths"][0]["steps"] = ["Apply positive_handler"]
    fields["behavior_paths"][1]["steps"] = ["Apply zero_handler"]
    if mode != "unanchored":
        fields["repair_path"] = "feature.py"
    suite_source = SOURCE.replace("from feature", "from client")
    fork_paths = {"Positive": "UNMET", "Zero": "MET"}
    if crowded:
        requirement_id = "ScaleInputsAcrossTheSupportedIntegerRangeAndPreserveZeroResult"
        fields["requirements"] = [
            {"id": requirement_id, "statement": "Double positive integers, preserve other inputs"},
        ]
        for item in fields["checks"] + fields["behavior_paths"]:
            item["requirement_id"] = requirement_id
        for value_input in (*range(4, 9), *range(-5, 0)):
            change = value_input > 0
            test_name = f"test_range_{value_input + 5}"
            path_id = f"ScaleIntegerRangeInput{value_input + 5:02d}AndObserveTheReturnedScaledValue"
            public_path = fields["behavior_paths"][0 if change else 1]
            path_requirement = requirement_id
            if incremental:
                path_requirement += f"{value_input + 5:02d}"
                fields["requirements"].append({"id": path_requirement, "statement": public_path["outcome"]})
            fields["checks"].append({"test_name": test_name, "requirement_id": path_requirement,
                                     "path_id": path_id, "role": "change" if change else "invariant"})
            fields["behavior_paths"].append({**public_path, "id": path_id,
                                             "requirement_id": path_requirement,
                                             "entry": f"Submit integer {value_input}"})
            expected = value_input * 2 if change else 0
            suite_source += f"    def {test_name}(self):\n        self.assertEqual(scale({value_input}), {expected})\n"
            fork_paths[path_id] = "UNMET" if change else "MET"
    value = contract(suite_source, version=2, **fields)
    bundle = DeterministicPlanner().plan(PlanRequest("r", "g", OBJECTIVE, targets, "true"))
    boundary = replace(bundle.boundary, isolation="host-process")
    local = (
        ("provider", "feature.py", "# local provider ready", ()),
        ("client", "client.py", "from feature import scale", ("provider",)),
    )
    nodes = tuple(
        PlanNode(node_id=name, objective=f"Implement {name}", deps=deps, expected_artifacts=(path,),
                 extra={"acceptance_criteria": [
                     AcceptanceCriterion(f"local-{name}", AssertionKind.FILE_CONTENT,
                                         path=path, expect=marker).to_dict()
                 ]})
        for name, path, marker, deps in local
    )
    bundle = replace(bundle, boundary=boundary, plan=PlanSpec(
        plan_id="integrated", goal_id=bundle.goal.goal_id, nodes=nodes, integrated_acceptance=True,
    ))
    if mixed:
        consumer = AcceptanceCriterion(
            "scale-another-positive", AssertionKind.TEST_RESULT, path="feature.py",
            command="python3 -c 'from client import scale; assert scale(5) == 10'",
        )
        bundle = replace(bundle, goal=replace(
            bundle.goal, acceptance_criteria=(*bundle.goal.acceptance_criteria, consumer),
        ))
    proof = qualify(repo, value, list(targets), boundary, tmp_path / "base", driver=HostProcessDriver())
    bundle = bind_bundle(bundle, value, proof)
    store = EventStore(tmp_path / "integrated.db")
    repairs = []
    repair_checks = []
    first_model = None
    if first_rejected:
        bad = fixed_feature.replace("    return 0\n", "    return 1\n") if repaired else feature_source
        if crowded:
            bad = "# proposed implementation notes\n" * 80 + bad
        operations = [{"op": "write", "path": "feature.py",
                       "content": bad + "# local provider ready\n\n"}]
        first_model = Controller([
            {"action": "edit", "operations": operations},
            {"action": "finish"},
        ] if inner else [{"operations": operations}])
    if incremental:
        repair_model = Controller([
            *([{"action": "check", "criterion_id": consumer.criterion_id,
                "gap": "Confirm the callable result before editing"}] if mixed else []),
            {"action": "edit", "operations": [
                {"op": "write", "path": "feature.py",
                 "content": fixed_feature.replace("    return 0\n", "    return 1\n")
                 + "# local provider ready\n"},
            ]},
            {"operations": [{"op": "replace", "path": "feature.py",
                             "old_text": "    return 1\n", "new_text": "    return 0\n"}]},
        ])
    else:
        repair_model = Controller([{"operations": [
            {"op": "replace", "path": "feature.py", "old_text": "    return value\n",
             "new_text": "    return value * 2\n"},
        ]}])
    if repaired:
        audit = branch_repair.audit_delivery

        def long_feedback(*args, **kwargs):
            report = audit(*args, **kwargs)
            if report["decision"] == "REVISE":
                report["required_changes"] = ["Detailed context about the public goal. " * 100]
            return report

        monkeypatch.setattr(branch_repair, "audit_delivery", long_feedback)

    class Reviewer:
        def complete(self, prompt, *, subject_digest):
            answer = {"decision": "APPROVE", "subject_digest": subject_digest,
                      "reasons": ["Local checks passed"], "violations": [], "confidence": 0.9}
            if "FINAL GOAL audit" in prompt:
                summary = prompt.split("## Deterministic gate summary\n", 1)[1].split("\n\n", 1)[0]
                criteria = json.loads(summary)["evidence"]["criteria"]
                rows = []
                for row in criteria:
                    proof = row.get("behavior_evidence")
                    result = {"criterion_id": row["criterion_id"], "status": "MET",
                              "evidence": "Observed gate coverage"}
                    if proof:
                        result.update(status="UNMET", evidence="Hypothesis outside exercised inputs",
                                      evidence_refs=[proof["receipt"]["sha256"]])
                    rows.append(result)
                answer.update(decision="REVISE", reasons=["Potential untested behavior"],
                              violations=["Check the untested input hypothesis"], criterion_results=rows)
            return json.dumps(answer)

    class Worker:
        def implement(self, sandbox, context):
            if context.node.extra.get("repair_root_spec_digest"):
                repairs.append((context.node.node_id, context.writable_paths, GitSandbox.main_commit(repo)))
                model = first_model if first_rejected and len(repairs) == 1 else repair_model
                check = DeclaredCheckRunner() if (
                    (inner and model is first_model) or incremental or mode == "anchored"
                ) else None
                outcome = ModelWorker(model, budget=owner.budget, check_context=check
                                      ).implement(sandbox, context)
                repair_checks.extend(outcome.extra["check_receipts"])
                return outcome
            elif context.node.node_id == "provider":
                content = fixed_feature if mode == "semantic_only" else feature_source
                item = FileOp("write", "feature.py", content + "# local provider ready\n")
            else:
                item = FileOp("write", "client.py", "from feature import scale\n")
            return ScriptedWorker((item,)).implement(sandbox, context)

    owner = RunOrchestrator(store, repo, tmp_path / "trees", bundle,
                            worker=Worker(), goal_audit_enabled=True, retry_backoff_sec=0,
                            tier2=Tier2Gate(reviewer=Reviewer()) if mode == "semantic_only" else None)
    owner.register_spec()
    try:
        result = owner.run()
        assert result.committed_count == 2, result.describe()
        assert (result.status == "COMPLETED") is repaired
        count = 2 if first_rejected and repaired else int(first_rejected or repaired)
        assert repairs == [("provider", ("feature.py",), baseline)] * count
        assert (GitSandbox.main_commit(repo) != baseline) is repaired
        assert (repo / "feature.py").read_text() == (
            fixed_feature + "# local provider ready\n" if repaired else feature_source
        )
        stages = result.goal_audit["stages"]
        assert [stage["decision"] for stage in stages] == (["REVISE", "APPROVE"] if repaired else ["REVISE"])
        assert all(stage["criteria"][-1]["behavior_evidence"]["receipt"]["complete"] for stage in stages)
        if incremental:
            expected = {path: status == "UNMET" for path, status in fork_paths.items()}
            final_tree = stages[-1]["criteria"][-1]["behavior_evidence"]["receipt"]["reviewed_tree"]
            if mixed:
                assert len(repair_model.calls) == 3
                before, consumer_fixed, failed_check = repair_checks
                assert [(row["criterion_id"], row["passed"]) for row in (before, consumer_fixed)] == [
                    (consumer.criterion_id, False), (consumer.criterion_id, True),
                ]
                assert before["tree_digest"] != consumer_fixed["tree_digest"] == failed_check["tree_digest"]
                assert failed_check["tree_digest"] != final_tree
            else:
                assert len(repair_model.calls) == 2
                failed_check, passed_check = repair_checks
                assert passed_check["behavior_path_evidence"]["outcomes"] == dict.fromkeys(fork_paths, True)
                assert failed_check["tree_digest"] != passed_check["tree_digest"] == final_tree
            assert failed_check["behavior_path_evidence"]["outcomes"] == expected
            prompt = repair_model.calls[-1][-1].content
            report, = [json.loads(line) for line in prompt.splitlines() if line.startswith('{"receipt":')]
            assert report["receipt"]["sha256"] == failed_check["behavior_path_evidence"]["receipt_sha256"]
            assert report["receipt"]["reviewed_tree"] == failed_check["tree_digest"]
            assert {row["path_id"]: row["status"] == "MET" for row in report["behavior_paths"]} == expected
            if crowded:
                assert failed_check["output_chars"] > MAX_ENGINEERING_RECORD_CHARS
                promoted, = [event.payload for event in store.events_for(f"goal:{owner.run_id}")
                             if event.event_type == "RepairBranchPromoted"]
                execution = store.get_run(promoted["run_id"])["execution_id"]
                observed, = [event.payload for event in store.events_for_execution(execution)
                             if event.event_type == "WorkerEngineeringObserved"]
                stored, = [row for row in observed["engineering_observations"]["records"]
                           if row["kind"] == "executed_check_failed"]
                assert not stored["truncated"] and stored["tree_digest"] == failed_check["tree_digest"]
                assert json.loads(json.loads(stored["content"])["output"]) == report
                assert "test_range_" not in prompt
            assert "test_positive" not in prompt and "test_zero" not in prompt
        if mode == "anchored":
            assert len(repair_model.calls) == 1
            assert repair_checks == []
            prompt = repair_model.calls[0][-1].content
            assert "Detailed context about the public goal." in prompt
            assert "test_positive" not in prompt and "test_zero" not in prompt
            body = prompt.split("SCOPED REPAIR MEMORY", 1)[1].split("\n", 1)[1]
            memory, _ = json.JSONDecoder().raw_decode(body)
            record, = memory
            assert record["evidence_kind"] == "trunk_behavior_failure"
            assert record["commit"] == stages[0]["commit"]
            native = stages[0]["criteria"][-1]["behavior_evidence"]["receipt"]
            recovered, = record["historical_behavior_paths"]
            assert recovered["receipt_sha256"] == native["sha256"]
            assert recovered["reviewed_tree"] == native["reviewed_tree"]
            assert {path["path_id"]: path["status"] for path in recovered["paths"]} == {
                "Positive": "UNMET", "Zero": "MET",
            }
        if repaired:
            prompt = repair_model.calls[0][-1].content
            window = prompt.split("CURRENT CONTENT:\n", 1)[1].split("```", 2)[1]
            assert "def positive_handler(" in window and "def zero_handler(" not in window
        if first_rejected:
            rejected, = [event.payload for event in store.events_for(f"goal:{owner.run_id}")
                         if event.event_type == "RepairBranchRejected"]
            child = store.get_run(rejected["run_id"])
            failed, = [event.payload for event in store.events_for_execution(child["execution_id"])
                       if event.event_type == "TrunkNodeFailed" and event.payload.get("patch_digest")]
            if inner:
                assert not rejected["validation"]["criteria"]
                assert failed["error_code"] == "worker_validation_failed"
                checked, = failed["worker_evidence"]["check_receipts"]
                assert checked["tree_digest"] == failed["candidate_tree"]
                receipt_sha = checked["behavior_path_evidence"]["receipt_sha256"]
            else:
                assert failed["error_code"] == "executed_acceptance_failure"
                native, = [row["behavior_evidence"]["receipt"]
                           for row in rejected["validation"]["criteria"] if row.get("behavior_evidence")]
                assert native["reviewed_tree"] == failed["candidate_tree"]
                receipt_sha = native["sha256"]
            path_result, = rejected["historical_child_evidence"]["historical_behavior_paths"]
            assert path_result["receipt_sha256"] == receipt_sha
            assert {path["path_id"]: path["status"] for path in path_result["paths"]} == (
                {path: "MET" if status == "UNMET" else "UNMET" for path, status in fork_paths.items()}
                if repaired else fork_paths
            )
            if repaired:
                prompt = repair_model.calls[0][-1].content
                body = prompt.split("SCOPED REPAIR MEMORY", 1)[1].split("\n", 1)[1]
                memory, _ = json.JSONDecoder().raw_decode(body)
                trunk, previous = memory
                assert trunk["commit"] == previous["base_commit"] == stages[0]["commit"]
                assert trunk["historical_behavior_paths"][0]["reviewed_tree"] != previous["candidate_tree"]
                assert previous["historical_behavior_paths"][0]["receipt_sha256"] == path_result["receipt_sha256"]
                if not inner:
                    criterion = next(row for row in previous["validation"]
                                     if row["criterion_id"] == path_result["criterion_id"])
                    assert "behavior_outcomes" not in criterion and "output" not in criterion
                assert "test_positive" not in prompt and "test_zero" not in prompt
                if crowded:
                    archived = rejected["historical_child_evidence"]
                    assert len(json.dumps(trunk, ensure_ascii=False)) + len(json.dumps(archived, ensure_ascii=False)) > 6000
                    assert len(json.dumps(memory, ensure_ascii=False)) <= 6004
                    assert previous["truncated"] and len(previous["patch"]) < len(archived["patch"])
                    assert previous["patch_digest"] == archived["patch_digest"]
                    assert {path["path_id"]: path["status"]
                            for path in trunk["historical_behavior_paths"][0]["paths"]} == fork_paths
                    assert "test_range_" not in prompt
            else:
                assert not repair_model.calls
        if mode == "semantic_only":
            receipt = stages[0]["criteria"][-1]["behavior_evidence"]["receipt"]
            assert receipt["passed"] and not result.goal_audit["iterations"]
            snapshot = next(event.payload for event in store.events_for(f"goal:{owner.run_id}")
                            if event.event_type == "GoalTrunkSnapshot")
            diagnostic = next(row for row in snapshot["diagnosis"]["criteria"]
                              if row["criterion_id"] == bundle.goal.acceptance_criteria[-1].criterion_id)
            assert diagnostic["non_repairable_reason"] == "no_executed_behavior_failure"
    finally:
        store.close()


@pytest.mark.parametrize("native", [False, True])
def test_api_ready_receipt_is_embedded_in_new_spec_and_run(api, repo, monkeypatch, native):
    import daedalus.service.requirement_routes as routes
    from daedalus.infrastructure.sandbox import DriverRegistry, SeatbeltDriver

    if native:
        if not SeatbeltDriver().probe().available:
            pytest.skip("real Seatbelt is unavailable")
        monkeypatch.setattr(routes, "SeatbeltDriver", SeatbeltDriver)
    else:
        def factory():
            return HostProcessDriver(name="seatbelt")
        monkeypatch.setattr(routes, "SeatbeltDriver", factory)
        monkeypatch.setattr(DriverRegistry, "default", staticmethod(
            lambda **_: DriverRegistry(drivers={"seatbelt": factory()})))
    client, state = api
    base = GitSandbox.main_commit(repo)
    fields = {**user_path_fields(), "repair_path": "feature.py"} if native else {}
    check_id, row = submit(client, repo, **fields)
    assert row["status"] == "READY"
    monkeypatch.setattr(state, "build_worker", lambda **_: (ScriptedWorker(
        ops=(FileOp("write", "feature.py", CORRECT),)), None))
    response = client.post("/api/runs", json={"repo_path": str(repo), "objective": OBJECTIVE,
        "target_paths": ["feature.py"], "test_command": "true", "requirement_check_id": check_id,
        "require_behavior_paths": native})
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
    assert GitSandbox.main_commit(repo) != base and (repo / "feature.py").read_text() == CORRECT
    spec_digest = response.json()["spec_digest"]
    routes = [f"/api/specs/{spec_digest}", *(f"/api/runs/{run_id}/{topic}"
              for topic in ("plan", "trunk", "goal-audit", "audit"))]
    views = {}
    for url in routes:
        public = client.get(url)
        assert public.status_code == 200
        assert "test_positive" not in public.text and "test_zero" not in public.text
        assert "RequirementTests" not in public.text and "test_source_sha256" not in public.text
        views[url.rsplit("/", 1)[-1]] = public.json()
    assert views[spec_digest]["spec_digest"] == spec_digest
    stage, = views["goal-audit"]["stages"]
    assert stage == views["audit"]["goal_audit"]["stages"][0]
    receipt, = [criterion["behavior_evidence"] for criterion in stage["criteria"]
                if "behavior_evidence" in criterion]
    snapshot = views["trunk"]["snapshots"][-1]
    assert snapshot["commit"] == stage["commit"] == GitSandbox.main_commit(repo)
    assert views["plan"]["trunk"]["digest"] == snapshot["digest"]
    canonical, = [event.payload for event in state.store.events_for(f"goal:{run_id}")
                  if event.event_type == "GoalAuditCompleted"]
    original = canonical["criteria"][-1]["behavior_evidence"]["receipt"]
    assert original["outcomes"] == {"test_positive": "pass", "test_zero": "pass"}
    assert receipt["receipt"]["sha256"] == original["sha256"]
    for fmt in ("jsonl", "csv"):
        exported = client.get(f"/api/runs/{run_id}/export?fmt={fmt}")
        assert exported.status_code == 200
        assert "GoalAuditCompleted" in exported.text and "TrunkExpectationsFrozen" in exported.text
        assert "RequirementTests" not in exported.text and "test_positive" not in exported.text
    if native:
        assert behavior["path"] == behavior["expect"]["behavior_contract"]["repair_path"] == "feature.py"
        assert {path["path_id"]: path["status"] for path in receipt["behavior_paths"]} == {
            "Positive": "MET", "Zero": "MET",
        }


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
        assert result.status == "PARTIAL_FAILURE"
        assert GitSandbox.main_commit(repo) == original
        audits = store.events_for("goal:" + owner.run_id)
        audit = next(e.payload for e in audits if e.event_type == "GoalAuditCompleted")
        assert audit["decision"] == "ESCALATE"
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
