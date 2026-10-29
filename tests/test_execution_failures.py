"""Execution faults must preserve evidence, stop spend and never fake test success."""

import difflib
import json
import sys

import pytest

from daedalus.application import realwork
from daedalus.application.benchmark import CountedWorker, _daedalus
from daedalus.application.coding_worker import FileOp, ModelWorker, ScriptedWorker
from daedalus.application.inspection import RepositoryInspector, safe_receipts
from daedalus.application.native_verifier import (
    native_result,
    read_native_receipt,
    render_native_verifier,
)
from daedalus.application.upstream_contract import compile_contract
from daedalus.infrastructure.git_sandbox import GitSandbox, _git
from daedalus.model.base import TokenBudget
from tests.conftest import TARGET
from tests.test_agent_investigation import context_for
from tests.test_agentic_rag import Controller


@pytest.fixture
def box(git_repo, tmp_path):
    sandbox = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="faults")
    try:
        yield sandbox
    finally:
        sandbox.remove()


def read(line=1):
    return {"tool": "read", "path": TARGET, "line": line, "gap": "inspect current implementation"}


def test_observation_io_failure_keeps_usage_and_completed_receipts_without_followup(box):
    model = Controller([{"action": "inspect", "requests": [read(), read(2)]}])
    budget = TokenBudget()
    observed = []
    inspector = RepositoryInspector()

    def observe(sandbox, context, request):
        observed.append(request)
        if len(observed) == 2:
            raise OSError("private diagnostic that must not be copied into a prompt")
        return inspector(sandbox, context, request)

    result = ModelWorker(model, budget=budget, inspection_context=observe).implement(
        box, context_for(box)
    )
    assert not result.ok and result.error == "execution_environment_unavailable"
    assert budget.calls == len(model.calls) == 1 and result.tokens_used == budget.run_used == 100
    assert len(safe_receipts(result.extra)) == 1
    assert "private diagnostic" not in result.execution_log and not box.changed_files()


def test_source_read_error_is_reported_before_any_model_spend(box, monkeypatch):
    def unreadable(*args):
        raise PermissionError("host-specific private diagnostic")

    monkeypatch.setattr(box, "read_file", unreadable)
    model = Controller([])
    result = ModelWorker(model).implement(box, context_for(box))
    assert not result.ok and result.error == "execution_environment_unavailable"
    assert not model.calls and "private diagnostic" not in result.execution_log


def test_diff_io_failure_after_edit_preserves_charged_usage(box, monkeypatch):
    model = Controller(
        [{"operations": [{"op": "write", "path": TARGET, "content": "# candidate\n"}]}]
    )

    def unavailable():
        raise PermissionError("private Git diagnostic")

    monkeypatch.setattr(box, "changed_files", unavailable)
    budget = TokenBudget()
    result = ModelWorker(model, budget=budget).implement(box, context_for(box))
    assert result.error == "execution_environment_unavailable" and not result.ok
    assert result.tokens_used == budget.run_used == 100 and len(model.calls) == 1
    assert "private Git diagnostic" not in result.execution_log


def test_stale_edit_feedback_supplies_relevant_current_symbol_without_applying_batch(box):
    source = "# unrelated preamble\n" * 1000 + "def needed(value):\n    return value + 3\n"
    box.write_file(TARGET, source)
    model = Controller(
        [
            {
                "operations": [
                    {"op": "write", "path": "new.py", "content": "must remain absent"},
                    {
                        "op": "replace",
                        "path": TARGET,
                        "old_text": "def needed(value):\n    return value + 1\n",
                        "new_text": "def needed(value):\n    return value + 2\n",
                    },
                ]
            }
        ]
    )
    # Only the normal writable path may be used by the model.
    from dataclasses import replace

    context = context_for(box)
    context = replace(
        context,
        bundle=replace(
            context.bundle,
            boundary=replace(context.bundle.boundary, fs_whitelist=(TARGET, "new.py")),
        ),
    )
    result = ModelWorker(model).implement(box, context)
    assert result.error == "invalid_edit_plan" and not box.exists("new.py")
    assert box.read_file(TARGET) == source
    assert "return value + 3" in result.execution_log and "needed" in result.execution_log
    assert len(result.execution_log) < 2600


def workload(tmp_path, monkeypatch):
    source = tmp_path / "upstream"
    (source / "tests").mkdir(parents=True)
    (source / "solution.py").write_text("def value(): return 1\n")
    old = (
        "import unittest\nfrom solution import value\nclass Checks(unittest.TestCase):\n"
        "    def test_stable(self): self.assertGreater(value(), 0)\n"
    )
    new = old + "    def test_issue(self): self.assertEqual(value(), 2)\n"
    (source / "native_tests.py").write_text(old)
    (source / "tests/runtests.py").write_text(
        "import sys, unittest\nlabels=[]\nfor value in sys.argv[1:]:\n"
        "    if value.startswith('--'): break\n    labels.append(value)\n"
        "suite=unittest.defaultTestLoader.loadTestsFromNames(labels)\n"
        "sys.exit(not unittest.TextTestRunner().run(suite).wasSuccessful())\n"
    )
    task = {
        "repo": "django/django",
        "problem_statement": "Return two and preserve positivity",
        "PASS_TO_PASS": ["test_stable (native_tests.Checks)"],
        "FAIL_TO_PASS": ["test_issue (native_tests.Checks)"],
        "test_patch": "".join(
            difflib.unified_diff(
                old.splitlines(True),
                new.splitlines(True),
                fromfile="a/native_tests.py",
                tofile="b/native_tests.py",
            )
        ),
    }
    data = tmp_path / "data"
    (data / "tasks/issue").mkdir(parents=True)
    (data / "tasks/issue/task.json").write_text(json.dumps(task))
    (data / "env/bin").mkdir(parents=True)
    (data / "env/bin/python").symlink_to(sys.executable)
    monkeypatch.setattr(realwork, "PROJECT", tmp_path)
    monkeypatch.setattr(realwork, "DATA", data)
    row = {
        "case": "issue",
        "repo": "django/django",
        "labels": ["native_tests"],
        "upstream_root": "upstream",
        "targets": ["solution.py"],
        "test_contract": compile_contract(task, ["native_tests"], source),
    }
    root = tmp_path / "trial"
    root.mkdir()
    repo, bundle, _, frozen = realwork._setup(row, root, 30000)
    return repo, bundle, frozen, root


@pytest.mark.parametrize(
    "candidate,expected",
    [
        ("import sys\nsys.exit(0)\n", False),
        ("import sys\nprint('Ran 1 test in 0.001s\\n\\nOK')\nsys.exit(0)\n", False),
        ("import os\nprint('Ran 1 test in 0.001s\\n\\nOK', flush=True)\nos._exit(0)\n", False),
        (
            "import unittest\nunittest.TestCase.run = lambda *a, **k: None\n"
            "def value(): return 2\n",
            False,
        ),
        ("def value(): return 2\n", True),
    ],
)
def test_native_verification_requires_completed_tests_not_only_exit_zero(
    tmp_path, monkeypatch, candidate, expected
):
    repo, bundle, task, root = workload(tmp_path, monkeypatch)
    (repo / "solution.py").write_text(candidate)
    _git(repo, ["add", "solution.py"], check=True)
    _git(repo, ["commit", "-m", "candidate"], check=True)
    commit = _git(repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
    result = realwork._evaluate(repo, bundle, task, root, commit)
    assert result["public_passed"] is expected and result["heldout_passed"] is expected


def test_empty_native_execution_never_spends_on_semantic_review(tmp_path, monkeypatch):
    repo, bundle, _task, root = workload(tmp_path, monkeypatch)
    worker = CountedWorker(
        ScriptedWorker((FileOp("write", "solution.py", "import sys\nsys.exit(0)\n"),))
    )
    reviewer = Controller([])
    result = _daedalus(repo, bundle, worker, reviewer, root, 30000)
    assert not result["delivered"] and result["tier1_decisions"] > 0
    assert result["tier2_decisions"] == result["goal_audits"] == len(reviewer.calls) == 0
    assert result["event_sequence_errors"] == 0


def test_candidate_cannot_rewrite_frozen_verifier_during_test_import(tmp_path, monkeypatch):
    repo, bundle, _task, root = workload(tmp_path, monkeypatch)
    candidate = (
        "from pathlib import Path\n"
        "Path('verify_public.py').write_text('raise SystemExit(0)\\n')\n"
        "def value(): return 2\n"
    )
    worker = CountedWorker(ScriptedWorker((FileOp("write", "solution.py", candidate),)))
    reviewer = Controller([])
    result = _daedalus(repo, bundle, worker, reviewer, root, 30000)
    assert not result["delivered"] and result["tier2_decisions"] == len(reviewer.calls) == 0


def test_classic_loop_stops_after_terminal_environment_fault(tmp_path, monkeypatch):
    from daedalus.application.benchmark import _single_loop
    from daedalus.application.worker import WorkerResult

    repo, bundle, _task, root = workload(tmp_path, monkeypatch)

    class FailedWorker:
        calls = 0

        def implement(self, *args):
            self.calls += 1
            return WorkerResult(ok=False, error="execution_environment_unavailable")

    worker = FailedWorker()
    result = _single_loop(repo, bundle, worker, root, 30000)
    assert worker.calls == 1 and not result["delivered"]


def test_observation_environment_fault_is_terminal_in_real_execution_loop(tmp_path, monkeypatch):
    repo, bundle, _task, root = workload(tmp_path, monkeypatch)
    model = Controller(
        [
            {
                "action": "inspect",
                "tool": "read",
                "path": "solution.py",
                "gap": "inspect current implementation",
            }
        ]
    )

    def unavailable(*args):
        raise PermissionError("private host diagnostic")

    worker = CountedWorker(ModelWorker(model, inspection_context=unavailable))
    reviewer = Controller([])
    result = _daedalus(repo, bundle, worker, reviewer, root, 30000)
    assert not result["delivered"] and worker.calls == len(model.calls) == 1
    assert result["tier1_decisions"] == result["tier2_decisions"] == len(reviewer.calls) == 0
    events = json.loads((root / "daedalus-events.json").read_text())
    failures = [e["payload"] for e in events if e["type"] == "StepExecutionFailed"]
    assert len(failures) == 1 and failures[0]["recoverable"] is False
    assert "execution_environment_unavailable" in failures[0]["detail"]
    assert "private host diagnostic" not in json.dumps(events)
    assert result["event_sequence_errors"] == 0


@pytest.mark.parametrize(
    "project,summary,code,passed,complete",
    [
        ("django/django", "Ran 0 tests in 0.00s\n\nOK\n", 0, False, False),
        ("django/django", "Ran 2 tests in 0.00s\n\nOK (skipped=2)\n", 0, False, False),
        ("django/django", "Ran 2 tests in 0.00s\n\nFAILED (failures=1)\n", 1, False, True),
        ("django/django", "Ran 2 tests in 0.00s\n\nOK\nOK\n", 0, False, False),
        ("sympy/sympy", "===== tests finished: 0 passed =====\n", 0, False, False),
        ("sympy/sympy", "===== tests finished: 3 skipped =====\n", 0, False, False),
        ("sympy/sympy", "===== tests finished: 2 passed, 1 failed =====\n", 1, False, True),
        ("sympy/sympy", "===== tests finished: 2 passed, 1 exceptions =====\n", 0, False, True),
        (
            "sympy/sympy",
            "===== tests finished: 2 passed, 1 expected to fail =====\n",
            0,
            True,
            True,
        ),
    ],
)
def test_native_summaries_require_real_execution_and_consistent_outcome(
    project, summary, code, passed, complete
):
    result = native_result(summary, project, code)
    assert result["passed"] is passed and result["complete"] is complete


@pytest.mark.parametrize(
    "expected,followup,reason",
    [
        (2, None, "test_count_changed"),
        (1, [sys.executable, "-c", "raise SystemExit(9)"], "issue_reproduction_failed"),
    ],
)
def test_frozen_supervisor_enforces_selection_and_additional_issue_check(
    tmp_path, expected, followup, reason
):
    import subprocess

    (tmp_path / "native_tests.py").write_text(
        "import unittest\nclass Checks(unittest.TestCase):\n    def test_ok(self): pass\n"
    )
    supervisor = tmp_path / "verify.py"
    supervisor.write_text(
        render_native_verifier(
            [sys.executable, "-m", "unittest", "native_tests.Checks"],
            "django/django",
            expected_tests=expected,
            followup=followup,
        )
    )
    run = subprocess.run(
        [sys.executable, str(supervisor)], cwd=tmp_path, capture_output=True, text=True
    )
    receipt = read_native_receipt(run.stdout + run.stderr)
    assert run.returncode != 0 and not receipt["passed"] and receipt["complete"]
    assert receipt["reason"] == reason and receipt["executed"] == 1
