"""Executed consumer regressions for bounded diagnostic history; not model scores."""

import hashlib
import json

import pytest

from daedalus.application.gatekeeper.tier2 import Tier2Gate
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.source_context import traceback_locations
from daedalus.application.worker import WorkerContext, WorkerResult
from daedalus.application.worker_factory import build_model_worker
from daedalus.infrastructure.git_sandbox import GitSandbox, _git
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Completion
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
from tests.test_engineering_loop import PARTIAL, bundle_for, check, edit
from tests.test_failure_optimization import _memory_owner
from tests.test_goal_audit import GoalReviewer


class PromptController:
    name = "diagnostic-consumer-controller"
    model = "offline-fixture"

    def __init__(self, choose):
        self.choose = choose
        self.prompts = []

    def complete(self, messages, **options):
        prompt = messages[-1].content
        self.prompts.append(prompt)
        return Completion(json.dumps(self.choose(prompt, len(self.prompts))), self.model, 50, 50)


def test_inspected_contract_survives_attempt_failure_and_enables_real_delivery(
    git_repo, tmp_path, record_property,
):
    notes = "EMPTY_INPUT_SCORE = 0.0\n"
    (git_repo / "contract_notes.py").write_text(notes)
    _git(git_repo, ["add", "contract_notes.py"], check=True)
    _git(git_repo, ["commit", "-m", "freeze read-only consumer contract"], check=True)

    def choose(prompt, index):
        if index == 1:
            return {"action": "inspect", "tool": "read", "path": "contract_notes.py",
                    "line": 1, "gap": "inspect the empty-input consumer contract"}
        if index == 2:
            return {"action": "unsupported"}
        history = prompt.split("SCOPED REPAIR MEMORY", 1)[-1].split("CURRENT CONTENT", 1)[0]
        return edit(CORRECT_IMPLEMENTATION, terminal=True) if notes.strip() in history else {"operations": []}

    model = PromptController(choose)
    bundle = bundle_for()
    reviewer = GoalReviewer(["APPROVE"])
    reviewer.criteria = [criterion.criterion_id for criterion in bundle.goal.acceptance_criteria]
    with EventStore(tmp_path / "memory.db") as store:
        owner = RunOrchestrator(store=store, repo_path=git_repo, run_root=tmp_path / "trees",
            bundle=bundle, worker=build_model_worker(model),
            tier2=Tier2Gate(reviewer), goal_audit_enabled=True, retry_backoff_sec=0)
        owner.register_spec()
        outcome = owner.run()
        assert outcome.status == "COMPLETED" and outcome.promoted_commit
        assert (git_repo / TARGET).read_text() == CORRECT_IMPLEMENTATION
        failures = [e for e in store.events_for(f"run:{owner.run_id}")
                    if e.event_type == "TrunkNodeFailed" and e.payload.get("patch_digest")]
        assert failures[0].payload["error_code"] == "invalid_edit_plan"
        prompt = model.prompts[-1]
        section = prompt.split("SCOPED REPAIR MEMORY", 1)[1].split("\n", 1)[1]
        history, _ = json.JSONDecoder().raw_decode(section)
        record, = history
        assert record["source_event_id"] == failures[0].event_id
        assert record["candidate_tree"] == failures[0].payload["candidate_tree"]
        body = failures[0].payload["reason"] + "\n" + failures[0].payload["detail"]
        assert record["observation_in_previous_attempt_feedback"] is True
        assert "observation" not in record
        assert prompt.split("PREVIOUS ATTEMPT FEEDBACK", 1)[1].count(body) == 1
        original = {key: value for key, value in record.items()
                    if key != "observation_in_previous_attempt_feedback"}
        original["observation"] = body
        before, after = (len(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode())
                         for row in (original, record))
        assert after < before
        record_property("removed_duplicate_prompt_bytes", before - after)
        assert "contract_notes.py" not in owner.bundle.boundary.fs_whitelist


def test_same_attempt_number_in_new_execution_does_not_borrow_old_native_failure(git_repo, tmp_path):
    owner, step_id = _memory_owner(git_repo, tmp_path)
    node = owner.bundle.plan.nodes[0].node_id
    try:
        owner.store.append(aggregate_id=f"run:{owner.run_id}", execution_id=owner.execution_id,
            event_type="TrunkNodeFailed", actor="test", payload={
                "node_id": node, "attempt": 1, "gate_result_id": "old-native-receipt",
                "criteria": [{"criterion_id": "old-failure", "ok": False, "error_code": ""}]})
        owner.store.append(aggregate_id=f"run:{owner.run_id}", execution_id=owner.execution_id,
            event_type="TrunkNodeFailed", actor="test", payload={
                "node_id": node, "attempt": 1, "patch_digest": "old-patch", "error_code": ""})
        owner.store.append(aggregate_id=f"run:{owner.run_id}", execution_id="next-explicit-execution",
            event_type="TrunkNodeFailed", actor="test", payload={
                "node_id": node, "attempt": 1, "patch_digest": "new-patch",
                "error_code": "semantic_revision", "detail": "Unverified empty-input concern"})
        memory = owner._repair_memory(step_id)
        assert memory[0]["failed_criteria"] == ["old-failure"]
        assert memory[-1]["failed_criteria"] == []
        assert memory[-1]["evidence_kind"] == "review_hypothesis"
        assert memory[-1]["source_spec_digest"] == ""
    finally:
        owner.store.close()


@pytest.mark.parametrize("shape", ["valid", "record_cap", "field_cap"])
def test_sensitive_worker_observation_refuses_delivery_without_persisting_secret(git_repo, tmp_path, shape):
    secret = "sk-" + "0123456789abcdef" * 4
    content = "safe context\n" * 1000 + "\n" + secret + "\n"

    class Worker:
        name = "sensitive-observation-fixture"

        def implement(self, sandbox, context):
            sandbox.write_file(TARGET, CORRECT_IMPLEMENTATION)
            record = {"kind": "investigation", "tree_digest": sandbox.tree_digest(),
                "content": content, "content_digest": hashlib.sha256(content.encode()).hexdigest(),
                "truncated": False}
            if shape == "field_cap":
                record.update({f"extra_{index}": "ignored" for index in range(4)})
            records = [{"content": "ignored malformed row"}] * 64 if shape == "record_cap" else []
            records.append(record)
            return WorkerResult(ok=True, extra={"engineering_observations": {
                "records": records, "omitted_records": 0}})

    original = (git_repo / TARGET).read_text()
    with EventStore(tmp_path / "secret.db") as store:
        owner = RunOrchestrator(store=store, repo_path=git_repo, run_root=tmp_path / "trees",
            bundle=bundle_for(), worker=Worker(), tier2=Tier2Gate(GoalReviewer(["APPROVE"])),
            goal_audit_enabled=True, retry_backoff_sec=0)
        owner.register_spec()
        result = owner.run()
        assert result.status == "FAILED" and not result.promoted_commit
        assert (git_repo / TARGET).read_text() == original
        events = store.events_for(f"run:{owner.run_id}")
        assert any(e.event_type == "TrunkNodeFailed" and e.payload.get("error_code") == "secret_in_payload"
                   for e in events)
        assert all(secret not in json.dumps(dict(e.payload)) for e in events)


@pytest.mark.parametrize("history", ["revision", "replay", "hypothesis"])
def test_failure_trace_reads_current_consumer_within_existing_inspection_allowance(
    git_repo, tmp_path, history,
):
    (git_repo / "consumer_contract.py").write_text("EXPECTED_EMPTY_SCORE = 0.0\n")
    _git(git_repo, ["add", "consumer_contract.py"], check=True)
    _git(git_repo, ["commit", "-m", "freeze consumer contract"], check=True)
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="consumer")
    bundle = bundle_for()
    trace = 'Traceback:\n  File "/old/rejected/consumer_contract.py", line 1, in check_empty\nAssertionError: empty input differs'
    kind = "executed_check_failure" if history == "replay" else "review_hypothesis"
    context = WorkerContext(
        "step", "execution", bundle.plan.nodes[0], bundle, box.base_commit,
        2 if history == "revision" else 1,
        revision_feedback=trace if history == "revision" else "",
        repair_memory=() if history == "revision" else ({"evidence_kind": kind, "observation": trace},),
    )
    (box.worktree_path / "consumer_contract.py").write_text("EXPECTED_EMPTY_SCORE = -1.0\n")
    model = PromptController(lambda prompt, _: edit(CORRECT_IMPLEMENTATION, terminal=True)
        if "EXPECTED_EMPTY_SCORE = -1.0" in prompt else {"operations": []})
    try:
        result = build_model_worker(model).implement(box, context)
        if history == "hypothesis":
            assert not result.ok and not result.extra["inspection_receipts"]
            assert "EXPECTED_EMPTY_SCORE = -1.0" not in model.prompts[0]
            return
        assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
        assert len(result.extra["inspection_receipts"]) == 1
        receipt = result.extra["inspection_receipts"][0]
        assert receipt["arguments"]["path"] == "consumer_contract.py"
        assert receipt["tree_digest"] != _git(git_repo, ["rev-parse", "HEAD^{tree}"], check=True).stdout.strip()
    finally:
        box.remove()


def test_traceback_navigation_never_returns_external_or_traversal_paths():
    feedback = ('File "/private/credentials.json", line 3\n'
                'File "/repo/../consumer.py", line 1\n'
                'File "/old/checkout/pkg/consumer.py", line 7\n'
                'File "pkg/consumer.py", line 7\n')
    assert traceback_locations(feedback, {"pkg/consumer.py", "consumer.py"}) == [("pkg/consumer.py", 7)]


@pytest.mark.parametrize("action", ["inspect", "edit"])
def test_late_model_action_cannot_execute_tools_or_write_after_deadline(
    git_repo, tmp_path, monkeypatch, action,
):
    clock = [0.0]
    monkeypatch.setattr("daedalus.application.coding_worker.time.monotonic", lambda: clock[0])
    bundle = bundle_for()
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="late-action")
    original = box.read_file(TARGET)

    def choose(prompt, index):
        clock[0] = 3.0
        return ({"action": "inspect", "tool": "read", "path": TARGET, "line": 1,
                 "gap": "late source request"} if action == "inspect"
                else edit(CORRECT_IMPLEMENTATION))

    model = PromptController(choose)
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle,
                            box.base_commit, 1, deadline_monotonic=2.0)
    try:
        result = build_model_worker(model).implement(box, context)
        assert result.error == "worker_deadline_exceeded"
        assert box.read_file(TARGET) == original
        assert result.extra["inspection_receipts"] == []
        assert result.tokens_used == 100
    finally:
        box.remove()


def test_native_inner_failure_reveals_current_consumer_before_next_edit(git_repo, tmp_path):
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from tests.test_engineering_loop import PARTIAL, check
    from tests.test_worker_checks import python_command

    (git_repo / "consumer_contract.py").write_text(
        "import sys\nsys.path.insert(0, 'src')\n"
        "from example_project.textstats import average_word_length\n"
        "EXPECTED_EMPTY_SCORE = 0.0\n"
        "assert average_word_length('') == EXPECTED_EMPTY_SCORE\n"
    )
    _git(git_repo, ["add", "consumer_contract.py"], check=True)
    _git(git_repo, ["commit", "-m", "freeze native consumer"], check=True)
    command = python_command("import runpy; runpy.run_path('consumer_contract.py', run_name='__main__')")
    bundle = DeterministicPlanner().plan(PlanRequest(
        "native-consumer", "consumer-goal", "fix empty input", (TARGET,), command,
    ))
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="inner-consumer")
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle, box.base_commit, 1)

    def choose(prompt, index):
        if index == 1:
            return edit(PARTIAL)
        if index in {2, 4}:
            return check(bundle)
        if index == 3:
            return (edit(CORRECT_IMPLEMENTATION) if "EXPECTED_EMPTY_SCORE = 0.0" in prompt
                    else {"operations": []})
        return {"action": "finish"}

    model = PromptController(choose)
    try:
        result = build_model_worker(model).implement(box, context)
        assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
        assert [row["passed"] for row in result.extra["check_receipts"]] == [False, True]
        assert len(result.extra["inspection_receipts"]) == 1
        assert result.extra["inspection_receipts"][0]["arguments"]["path"] == "consumer_contract.py"
        assert "EXPECTED_EMPTY_SCORE = 0.0" not in model.prompts[0]
    finally:
        box.remove()


@pytest.mark.parametrize("mode", ["attribute_error", "failed_subtest"])
def test_native_receiver_navigation_avoids_blocked_consumer_and_repairs_real_interface(
    git_repo, tmp_path, mode,
):
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from tests.test_engineering_loop import check
    from tests.test_worker_checks import python_command

    expression = "user.email" if mode == "attribute_error" else "getattr(user, 'email', '')"
    initial = CORRECT_IMPLEMENTATION + "\ndef digest(user):\n    return " + expression + "\n"
    corrected = CORRECT_IMPLEMENTATION + "\ndef digest(user):\n    return getattr(user, user.CONTACT_FIELD)\n"
    secret = "sk-" + "a" * 40
    (git_repo / TARGET).write_text(initial)
    (git_repo / "receiver.py").write_text(
        "class CustomContact:\n    CONTACT_FIELD = 'inbox'\n    inbox = 'initial'\n"
    )
    (git_repo / "consumer_contract.py").write_text(
        "import sys, unittest\nsys.path.insert(0, 'src')\n"
        "from example_project.textstats import digest\nfrom receiver import CustomContact\n"
        "class ContactBehavior(unittest.TestCase):\n"
        "    def test_changes(self):\n"
        "        user = CustomContact()\n"
        "        with self.subTest(receiver=type(user).__name__):\n"
        "            self.assertEqual(digest(user), 'initial')\n"
        "            user.inbox = 'changed'\n"
        "            self.assertEqual(digest(user), 'changed')\n"
        "if __name__ == '__main__':\n    unittest.main()\n"
        + "\n" * 80 + "PRIVATE_FIXTURE = " + repr(secret) + "\n"
    )
    _git(git_repo, ["add", "."], check=True)
    _git(git_repo, ["commit", "-m", "freeze configurable receiver contract"], check=True)
    command = python_command("import runpy; runpy.run_path('consumer_contract.py', run_name='__main__')")
    bundle = DeterministicPlanner().plan(PlanRequest(
        "receiver", "receiver-goal", "follow configurable contact changes", (TARGET,), command,
    ))
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="receiver")
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle, box.base_commit, 1)

    def choose(prompt, index):
        if index in {1, 3}:
            return check(bundle)
        if index == 2:
            return (edit(corrected) if "CONTACT_FIELD = 'inbox'" in prompt
                    else {"operations": []})
        return {"action": "finish"}

    model = PromptController(choose)
    try:
        result = build_model_worker(model).implement(box, context)
        assert result.ok and box.read_file(TARGET) == corrected
        assert [row["passed"] for row in result.extra["check_receipts"]] == [False, True]
        assert result.extra["inspection_receipts"][0]["sources"] == ["receiver.py"]
        assert all(secret not in prompt for prompt in model.prompts)
    finally:
        box.remove()


def test_exact_failed_contract_exposes_same_factory_input_variant_before_repair(git_repo, tmp_path):
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from tests.test_engineering_loop import check
    from tests.test_worker_checks import python_command

    original = CORRECT_IMPLEMENTATION + "\ndef resolve(primary, bound):\n    return None if primary else 42\n"
    corrected = CORRECT_IMPLEMENTATION + "\ndef resolve(primary, bound):\n    return 42 if not primary and bound else None\n"
    wrong_repair = CORRECT_IMPLEMENTATION + "\ndef resolve(primary, bound):\n    return None\n"
    (git_repo / TARGET).write_text(original)
    (git_repo / "case_contract.py").write_text(
        "import sys, unittest\nsys.path.insert(0, 'src')\n"
        "from example_project.textstats import resolve\n"
        "def factory(primary):\n"
        "    return lambda data=None: resolve(primary, data is not None)\n"
        + "\n" * 60
        + "class Contract(unittest.TestCase):\n"
        "    def test_default(self):\n"
        "        Case = factory(False)\n"
        "        actual = Case()\n"
        "        self.assertIsNone(actual)\n"
        + "\n" * 20
        + "    def test_submitted(self):\n"
        "        Case = factory(False)\n"
        "        actual = Case({'payload': 'present'})\n"
        "        self.assertEqual(actual, 42)\n"
    )
    _git(git_repo, ["add", "."], check=True)
    _git(git_repo, ["commit", "-m", "freeze contrasting input contracts"], check=True)
    command = python_command(
        "import unittest; suite=unittest.defaultTestLoader.loadTestsFromName('case_contract'); "
        "result=unittest.TextTestRunner().run(suite); raise SystemExit(not result.wasSuccessful())"
    )
    bundle = DeterministicPlanner().plan(PlanRequest(
        "contrast", "contrast-goal", "preserve default and submitted behavior", (TARGET,), command,
    ))
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="contrast")
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle, box.base_commit, 1)

    def choose(prompt, index):
        if index in {1, 3}:
            return check(bundle)
        if index == 2:
            return edit(corrected if "Case({'payload': 'present'})" in prompt else wrong_repair)
        return {"action": "finish"}

    model = PromptController(choose)
    try:
        result = build_model_worker(model).implement(box, context)
        assert result.ok and box.read_file(TARGET) == corrected
        assert [row["passed"] for row in result.extra["check_receipts"]] == [False, True]
        assert len(result.extra["inspection_receipts"]) == 1
        assert result.extra["inspection_receipts"][0]["tool"] == "symbol"
        assert "Case({'payload': 'present'})" not in model.prompts[0]
    finally:
        box.remove()


def test_truncated_historical_source_secret_is_refused_before_model_projection(git_repo, tmp_path):
    bundle = bundle_for()
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="history-secret")
    secret = "sk-" + "0123456789abcdef" * 4
    memory = ({"historical_engineering_observations": {"records": [{
        "kind": "source_inspection", "tree_digest": box.tree_digest(),
        "content": secret, "content_digest": hashlib.sha256(secret.encode()).hexdigest(),
        "truncated": True,
    }], "omitted_records": 0}},)
    model = PromptController(lambda *_: edit(CORRECT_IMPLEMENTATION, terminal=True))
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle, box.base_commit,
                            2, repair_memory=memory)
    original = box.read_file(TARGET)
    try:
        result = build_model_worker(model).implement(box, context)
        assert not result.ok and result.error == "secret_in_payload"
        assert not model.prompts and box.read_file(TARGET) == original
        assert memory[0]["historical_engineering_observations"]["records"][0]["content"] == secret
    finally:
        box.remove()


@pytest.mark.parametrize("mode", ["repair", "repeated_invalid", "mixed_edit"])
def test_readonly_protocol_correction_retains_native_repair_state(git_repo, tmp_path, mode):
    marker = "CONSUMER_EXPECTATION = 'count words and preserve empty input'\n"
    (git_repo / "consumer_hint.py").write_text(marker)
    _git(git_repo, ["add", "consumer_hint.py"], check=True)
    _git(git_repo, ["commit", "-m", "freeze consumer hint"], check=True)
    bundle = bundle_for()
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="protocol-correction")
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle, box.base_commit, 1)
    invalid = {"action": "inspect", "tool": "read", "path": "consumer_hint.py"}
    if mode == "mixed_edit":
        invalid = {**invalid, "operations": [{"op": "delete", "path": TARGET}]}

    def choose(prompt, index):
        if index == 1:
            return {**invalid, "operations": [], "gap": "need the consumer contract"}
        if index == 2 or mode == "repeated_invalid":
            return invalid
        if index in {3, 5}:
            return check(bundle)
        if index == 4:
            return edit(CORRECT_IMPLEMENTATION if marker.strip() in prompt
                        and "Invalid read-only inspection request" in prompt else PARTIAL)
        return {"action": "finish"}

    model = PromptController(choose)
    original = box.read_file(TARGET)
    try:
        result = build_model_worker(model).implement(box, context)
        assert len(result.extra["inspection_receipts"]) == 1
        if mode == "repair":
            assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
            assert [row["passed"] for row in result.extra["check_receipts"]] == [False, True]
        else:
            assert result.error == ("worker_no_progress" if mode == "repeated_invalid"
                                    else "invalid_edit_plan")
            assert box.read_file(TARGET) == original
            assert len(model.prompts) == (3 if mode == "repeated_invalid" else 2)
    finally:
        box.remove()


def test_stale_refresh_prioritizes_changed_expression_over_broad_goal(git_repo, tmp_path):
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from tests.test_worker_checks import python_command

    original_line = '    return len("".join(tokens)) / len(tokens)'
    changed_line = '    return len("".join(tokens)) / (len(tokens) + 1)'
    correct_line = '    return len("".join(tokens)) / len(tokens) if tokens else 0.0'
    distractor = "\n\n\n\ndef save():\n" + '    unrelated_padding = "preserved report data"\n' * 250
    original = PARTIAL + distractor
    (git_repo / TARGET).write_text(original)
    (git_repo / "verify_measure.py").write_text(
        "import sys\nsys.path.insert(0, 'src')\n"
        "from example_project.textstats import average_word_length as measure\n"
        "assert measure('aa bbbb') == 3.0, 'normal input must use token count'\n"
        "assert measure('') == 0.0, 'empty input must remain valid'\n"
    )
    _git(git_repo, ["add", "."], check=True)
    _git(git_repo, ["commit", "-m", "freeze aliased consumer and unrelated report method"], check=True)
    bundle = DeterministicPlanner().plan(PlanRequest(
        "refresh", "refresh-goal", "save", (TARGET,),
        python_command("import verify_measure"),
    ))
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="refresh")
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle, box.base_commit, 1)

    def replacement(old, new):
        return {"action": "edit", "operations": [
            {"op": "replace", "path": TARGET, "old_text": old, "new_text": new},
        ]}

    def choose(prompt, index):
        if index == 1:
            return replacement(original_line, changed_line)
        if index in {2, 5}:
            return check(bundle)
        if index == 3:
            return replacement(original_line, correct_line)
        if index == 4 and changed_line in prompt:
            return replacement(changed_line, correct_line)
        return {"action": "finish"}

    model = PromptController(choose)
    try:
        result = build_model_worker(model).implement(box, context)
        assert result.ok and box.read_file(TARGET) == original.replace(original_line, correct_line)
        assert [row["passed"] for row in result.extra["check_receipts"]] == [False, True]
    finally:
        box.remove()
