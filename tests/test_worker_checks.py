"""Frozen diagnostic checks are evidence, not a second approval or shell interface."""

import json
import shlex
import time
from dataclasses import replace

import pytest

from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.worker import WorkerContext
from daedalus.application.worker_checks import (
    MAX_CHECK_OUTPUT_CHARS, CheckRequest, DeclaredCheckRunner, safe_check_receipts,
)
from daedalus.domain.canonical import digest_of
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.infrastructure.sandbox import DriverRegistry, HostProcessDriver
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET


def python_command(source):
    return shlex.join(["python3", "-B", "-c", source])


COMMAND = python_command(
    "import sys; sys.path.insert(0, 'src'); "
    "from example_project.textstats import summarize, average_word_length; "
    "assert summarize('two words')['words'] == 2; "
    "assert average_word_length('') == 0.0"
)


class RecordingDriver:
    name = "host-process"

    def __init__(self):
        self.calls = []
        self.delegate = HostProcessDriver()

    def probe(self):
        return self.delegate.probe()

    def run(self, **kwargs):
        self.calls.append(kwargs)
        return self.delegate.run(**kwargs)


@pytest.fixture
def environment(git_repo, tmp_path):
    sandbox = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="checks")
    bundle = DeterministicPlanner().plan(
        PlanRequest("run", "goal", "fix word counting", (TARGET,), COMMAND))
    bundle = replace(bundle, boundary=replace(bundle.boundary, isolation="host-process"))
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle,
                            sandbox.base_commit, 1)
    driver = RecordingDriver()
    runner = DeclaredCheckRunner(registry=DriverRegistry(drivers={driver.name: driver}))
    try:
        yield sandbox, context, runner, driver
    finally:
        sandbox.remove()


def request_for(context, **changes):
    criteria = context.node.acceptance_criteria or context.bundle.goal.acceptance_criteria
    return CheckRequest.parse({"action": "check", "criterion_id": criteria[0].criterion_id,
                               "gap": "does the frozen word-count behavior now pass?", **changes})


def with_criterion(context, criterion):
    node = replace(context.node, extra={**context.node.extra,
                                       "acceptance_criteria": [criterion.to_dict()]})
    return replace(context, node=node)


def test_real_assertion_fails_on_baseline_then_passes_on_edited_tree(environment):
    box, context, runner, driver = environment
    before = runner(box, context, request_for(context))
    assert before.receipt["executed"] and not before.receipt["passed"]
    assert before.receipt["error_code"] == ""
    assert before.receipt["tree_digest"] == before.receipt["after_tree_digest"]
    box.write_file(TARGET, CORRECT_IMPLEMENTATION)
    after = runner(box, context, request_for(context))
    assert after.receipt["executed"] and after.receipt["passed"]
    assert after.receipt["tree_digest"] != before.receipt["tree_digest"]
    assert after.receipt["criterion_digest"] == before.receipt["criterion_digest"]
    assert after.receipt["spec_digest"] == context.bundle.digest()
    assert after.receipt["driver"] == "host-process" and len(driver.calls) == 2
    assert after.receipt["execution_id"] == "execution"
    assert after.receipt["step_id"] == "step" and after.receipt["attempt"] == 1
    assert not after.receipt["approval"] and box.head() == context.base_commit


@pytest.mark.parametrize("changes", [
    {"command": "touch unauthorized"},
    {"operations": [{"op": "delete", "path": TARGET}]},
    {"requests": []}, {"action": "edit"}, {"criterion_id": ""},
    {"gap": " "}, {"gap": "x" * 241},
])
def test_untrusted_check_arguments_are_rejected_before_dispatch(environment, changes):
    box, context, runner, driver = environment
    original = box.read_file(TARGET)
    with pytest.raises(ValueError):
        runner(box, context, request_for(context, **changes))
    assert not driver.calls and box.read_file(TARGET) == original


def test_unknown_or_other_node_ids_execute_nothing(environment):
    box, context, runner, driver = environment
    criterion = AcceptanceCriterion("node-only", AssertionKind.FILE_CONTENT,
                                    path=TARGET, expect="def summarize")
    narrowed = with_criterion(context, criterion)
    inherited_id = request_for(context).criterion_id
    denied = runner(box, narrowed, request_for(narrowed, criterion_id=inherited_id))
    assert not denied.receipt["executed"] and not denied.receipt["passed"]
    assert denied.receipt["error_code"] == "invalid_edit_plan" and not driver.calls
    allowed = runner(box, narrowed, request_for(narrowed))
    assert allowed.receipt["passed"] and allowed.receipt["criteria_source"] == "plan_node"
    assert allowed.receipt["criterion_digest"] == digest_of(criterion.to_dict())


def test_frozen_command_still_obeys_command_policy(environment):
    box, context, runner, driver = environment
    criterion = AcceptanceCriterion("install", AssertionKind.SCRIPT,
                                    command="python3 -m pip install forbidden-package")
    context = with_criterion(context, criterion)
    observed = runner(box, context, request_for(context))
    assert not observed.receipt["executed"] and not driver.calls
    assert observed.receipt["error_code"] == "boundary_violation"


def test_boundary_violation_prevents_even_a_declared_command(environment):
    box, context, runner, driver = environment
    box.write_file("outside.txt", "not an allowed edit")
    observed = runner(box, context, request_for(context))
    assert not observed.receipt["executed"] and not driver.calls
    assert observed.receipt["error_code"] == "boundary_violation"


@pytest.mark.parametrize("paired", [False, True])
def test_dependency_pairing_and_integrity_block_execution(environment, paired):
    box, context, runner, driver = environment
    boundary = replace(context.bundle.boundary,
                       fs_whitelist=(*context.writable_paths, "requirements.txt", "requirements.lock"),
                       dependency_manifest="requirements.txt", lock_file="requirements.lock")
    context = replace(context, bundle=replace(context.bundle, boundary=boundary))
    box.write_file("requirements.txt", "example-package==1.0\n")
    if paired:
        box.write_file("requirements.lock", "example-package==1.0\n")
    observed = runner(box, context, request_for(context))
    assert not observed.receipt["executed"] and not driver.calls
    assert observed.receipt["error_code"] == "dependency_validation_error"
    assert observed.receipt["blocked_by"] == (
        "03b_dependency_integrity" if paired else "03_dependency_pairing")


def test_requested_unavailable_isolation_never_falls_back(environment):
    box, context, _, driver = environment
    boundary = replace(context.bundle.boundary, isolation="seatbelt")
    context = replace(context, bundle=replace(context.bundle, boundary=boundary))
    runner = DeclaredCheckRunner(registry=DriverRegistry(drivers={driver.name: driver}))
    observed = runner(box, context, request_for(context))
    assert not observed.receipt["executed"] and not driver.calls
    assert observed.receipt["error_code"] == "isolation_unavailable"
    assert observed.receipt["driver"] == ""


def test_spawn_failure_is_not_a_code_assertion_failure(environment, monkeypatch):
    box, context, runner, driver = environment

    def unavailable(**kwargs):
        raise OSError("process execution unavailable")

    monkeypatch.setattr(driver, "run", unavailable)
    observed = runner(box, context, request_for(context))
    assert not observed.receipt["passed"] and not observed.receipt["executed"]
    assert observed.receipt["error_code"] == "execution_environment_unavailable"
    assert observed.receipt["driver"] == "host-process"


def test_command_that_mutates_subject_cannot_verify_its_new_tree(environment):
    box, context, runner, driver = environment
    command = python_command("from pathlib import Path; "
                             f"Path({TARGET!r}).write_text('changed by assertion\\n')")
    context = with_criterion(context, AcceptanceCriterion("mutates", AssertionKind.SCRIPT,
                                                         command=command))
    observed = runner(box, context, request_for(context))
    assert observed.receipt["executed"] and not observed.receipt["passed"]
    assert observed.receipt["error_code"] == "spec_digest_mismatch"
    assert observed.receipt["tree_digest"] != observed.receipt["after_tree_digest"]
    assert observed.receipt["subject_changed"] and box.head() == context.base_commit


def test_complete_output_is_scanned_before_any_middle_is_omitted(environment):
    box, context, runner, driver = environment
    command = python_command(
        "print('prefix' * 2000 + '\\n' + 'sk-' + 'a' * 30 + '\\n' + 'suffix' * 2000)"
    )
    context = with_criterion(context, AcceptanceCriterion("sensitive", AssertionKind.SCRIPT,
                                                         command=command))
    observed = runner(box, context, request_for(context))
    assert not observed.receipt["passed"]
    assert observed.receipt["error_code"] == "secret_in_payload"
    assert "sk-" + "a" * 30 not in observed.content


def test_clean_large_output_has_full_digest_and_explicit_bounded_excerpt(environment):
    box, context, runner, driver = environment
    command = python_command("print('prefix' * 2000 + 'suffix' * 2000)")
    context = with_criterion(context, AcceptanceCriterion("large", AssertionKind.SCRIPT,
                                                         command=command))
    observed = runner(box, context, request_for(context))
    full_output = "prefix" * 2000 + "suffix" * 2000 + "\n"
    assert observed.receipt["passed"] and observed.receipt["output_truncated"]
    assert observed.receipt["output_digest"] == digest_of(full_output)
    assert observed.receipt["output_chars"] == len(full_output)
    assert len(json.loads(observed.content)["output"]) <= MAX_CHECK_OUTPUT_CHARS
    assert "output omitted" in observed.content and observed.receipt["evidence_digest"]


def test_file_assertions_cannot_follow_symlinks_outside_repository(environment, tmp_path):
    box, context, runner, driver = environment
    private = tmp_path / "private.txt"
    private.write_text("host private data")
    box.resolve_inside(TARGET).unlink()
    (box.worktree_path / TARGET).symlink_to(private)
    context = with_criterion(context, AcceptanceCriterion("symlink", AssertionKind.FILE_CONTENT,
                                                         path=TARGET, expect="host private data"))
    observed = runner(box, context, request_for(context))
    assert not observed.receipt["passed"] and not observed.receipt["executed"]
    assert observed.receipt["error_code"] in {"boundary_violation", "git_error"}
    assert "host private data" not in observed.content and not driver.calls


def test_expired_shared_deadline_blocks_native_execution(environment):
    box, context, runner, driver = environment
    context = replace(context, deadline_monotonic=time.monotonic() - 1)
    observed = runner(box, context, request_for(context))
    assert not observed.receipt["executed"] and not driver.calls
    assert observed.receipt["error_code"] == "execution_environment_unavailable"


@pytest.mark.parametrize("remaining,node_timeout", [(30.0, 2), (0.5, 30)])
def test_native_timeout_uses_remaining_shared_deadline_and_node_limit(
    environment, remaining, node_timeout
):
    box, context, runner, driver = environment
    context = replace(context, node=replace(context.node, timeout_sec=node_timeout),
                      deadline_monotonic=time.monotonic() + remaining)
    observed = runner(box, context, request_for(context))
    assert observed.receipt["executed"] and len(driver.calls) == 1
    assert 0 < driver.calls[0]["timeout_sec"] <= min(remaining, node_timeout)


def test_operational_base_mutation_invalidates_check_subject(environment, monkeypatch):
    box, context, runner, driver = environment
    original_run = driver.run

    def changes_base(**kwargs):
        result = original_run(**kwargs)
        box.base_commit = "0" * 40
        return result

    monkeypatch.setattr(driver, "run", changes_base)
    observed = runner(box, context, request_for(context))
    assert observed.receipt["executed"] and not observed.receipt["passed"]
    assert observed.receipt["subject_changed"]
    assert observed.receipt["error_code"] == "spec_digest_mismatch"


def test_persisted_check_receipts_exclude_native_output_and_untrusted_fields(environment):
    box, context, runner, driver = environment
    observed = runner(box, context, request_for(context))
    row = {**observed.receipt, "stdout": "do not persist", "command": "do not persist",
           "raw_prompt": "do not persist"}
    saved = safe_check_receipts({"check_receipts": [row]})
    assert len(saved) == 1
    assert saved[0]["tree_digest"] == observed.receipt["tree_digest"]
    assert saved[0]["output_digest"] == observed.receipt["output_digest"]
    assert not {"stdout", "command", "raw_prompt", "isolation"} & saved[0].keys()
    assert safe_check_receipts({"check_receipts": [{**row, "tree_digest": "forged"}]}) == []
    assert safe_check_receipts({"check_receipts": [{**row, "executed": False, "passed": True}]}) == []


@pytest.mark.parametrize("command,executed,error_code", [
    (python_command("raise SystemExit(127)"), True, ""),
    ("daedalus-command-that-does-not-exist", False, "execution_environment_unavailable"),
])
def test_shell_unavailability_is_distinct_from_an_executed_nonzero_assertion(
    environment, command, executed, error_code
):
    box, context, runner, driver = environment
    context = with_criterion(context, AcceptanceCriterion("exit-status", AssertionKind.SCRIPT,
                                                         command=command))
    observed = runner(box, context, request_for(context))
    assert not observed.receipt["passed"] and observed.receipt["executed"] is executed
    assert observed.receipt["error_code"] == error_code
