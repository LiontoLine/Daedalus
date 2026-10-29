"""Frozen native-test supervision: exit zero alone is never completion evidence."""

from __future__ import annotations

import inspect
import json
import re
import textwrap

RECEIPT_PREFIX = "DAEDALUS_NATIVE_RESULT "


def native_result(text: str, project: str, returncode: int) -> dict:
    # Strip terminal coloring without changing the test counts or outcomes.
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    tests, skipped, passed, complete = 0, 0, False, False
    if project == "django/django":
        counts = re.findall(r"(?m)^Ran (\d+) tests? in [^\n]+$", text)
        verdicts = re.findall(r"(?m)^(OK|FAILED)(?: \(([^\n]*)\))?\s*$", text)
        if len(counts) == len(verdicts) == 1:
            tests = int(counts[0])
            skip = re.search(r"\bskipped=(\d+)", verdicts[0][1])
            skipped = int(skip[1]) if skip else 0
            complete = tests > 0 and 0 <= skipped < tests
            passed = complete and returncode == 0 and verdicts[0][0] == "OK"
    elif project == "sympy/sympy":
        summaries = re.findall(r"(?m)^=+\s*tests finished: ([^\n]+?)\s*=+\s*$", text)
        if len(summaries) == 1:
            counts = re.findall(
                r"(\d+) (passed|failed|exceptions?|expected to fail|skipped)", summaries[0]
            )
            tests = sum(int(n) for n, _ in counts)
            skipped = sum(int(n) for n, kind in counts if kind == "skipped")
            passing = sum(int(n) for n, kind in counts if kind == "passed")
            failures = sum(
                int(n) for n, kind in counts if kind in {"failed", "exception", "exceptions"}
            )
            complete = tests > 0 and skipped < tests
            passed = complete and returncode == 0 and passing > 0 and failures == 0
    return {
        "version": 1,
        "returncode": returncode,
        "tests": tests,
        "skipped": skipped,
        "executed": max(0, tests - skipped),
        "complete": complete,
        "passed": passed,
        "reason": "passed"
        if passed
        else "native_failure"
        if complete
        else "missing_or_empty_test_completion",
    }


def native_child(command, project, descriptor):
    """Observe the runner, separately from its untrusted human-readable output.

    This prevents stdout spoofing, not arbitrary Python introspection. Kernel isolation
    and immutable harness files remain separate requirements.
    """
    import hashlib
    import importlib
    import json
    import os
    import runpy
    import sys
    import unittest

    write, dumps = os.write, json.dumps
    results = []
    code, depth = 1, 0
    original_run = unittest.TextTestRunner.run
    original_case_run = unittest.TestCase.run

    def observed_run(self, suite):
        nonlocal depth
        outer = depth == 0
        depth += 1
        try:
            result = original_run(self, suite)
            if outer:
                tests, skipped = result.testsRun, len(result.skipped)
                results.append(
                    {
                        "tests": tests,
                        "skipped": skipped,
                        "started": tests,
                        "success": result.wasSuccessful(),
                    }
                )
            return result
        finally:
            depth -= 1

    unittest.TextTestRunner.run = observed_run
    runner, observed_finish, original_finish, observed_enter = None, None, None, None
    try:
        if project == "sympy/sympy":
            try:
                runner = importlib.import_module("sympy.testing.runtests")
            except ImportError:
                runner = importlib.import_module("sympy.utilities.runtests")
            original_finish = runner.PyTestReporter.finish
            original_enter = runner.PyTestReporter.entering_test
            identities = []

            def observed_enter(self, function):
                identities.append(function.__name__)
                return original_enter(self, function)

            def observed_finish(self):
                result = original_finish(self)
                passed, skipped = self._passed, self._skipped
                failures = len(self._failed) + len(self._exceptions) + len(self._xpassed)
                tests = passed + skipped + self._xfailed + failures
                results.append(
                    {
                        "tests": tests,
                        "skipped": skipped,
                        "started": len(identities),
                        "success": passed > 0 and failures == 0,
                        "identities_sha256": hashlib.sha256(dumps(identities).encode()).hexdigest(),
                    }
                )
                return result

            runner.PyTestReporter.finish = observed_finish
            runner.PyTestReporter.entering_test = observed_enter
        arguments = list(command[1:])
        # Native bin/test normally reexecutes itself; the observer must remain attached.
        if project == "sympy/sympy" and arguments[0] == "bin/test":
            arguments += ["--no-subprocess", "--no-colors", "--seed", "1729"]
        if arguments[0] == "-m":
            module = arguments[1]
            sys.argv = [module, *arguments[2:]]
            runpy.run_module(module, run_name="__main__", alter_sys=True)
        else:
            sys.argv = arguments
            sys.path.insert(0, os.path.abspath(os.path.dirname(arguments[0])))
            runpy.run_path(arguments[0], run_name="__main__")
        code = 0
    except SystemExit as error:
        code = int(error.code) if isinstance(error.code, int) else int(error.code is not None)
    except BaseException:  # noqa: BLE001 - parent requires an explicit completed runner receipt
        import traceback

        traceback.print_exc()
        code = 1
    intact = (
        unittest.TextTestRunner.run is observed_run and unittest.TestCase.run is original_case_run
    )
    if runner is not None:
        intact = intact and runner.PyTestReporter.finish is observed_finish
        intact = intact and runner.PyTestReporter.entering_test is observed_enter
    write(descriptor, dumps({"version": 1, "results": results, "runner_intact": intact}).encode())
    os.close(descriptor)
    sys.exit(code)


def runner_result(value, returncode):
    """Only native runner counters can establish completion; output is diagnostic."""
    rows = value.get("results", [])
    row = rows[0] if len(rows) == 1 else {}
    tests, skipped, started = (row.get(name, 0) for name in ("tests", "skipped", "started"))
    complete = (
        value.get("version") == 1
        and value.get("runner_intact") is True
        and tests > 0
        and 0 <= skipped < tests
        and started >= tests
    )
    passed = complete and returncode == 0 and row.get("success") is True
    return {
        "version": 1,
        "evidence_kind": "native_runner_counters",
        "returncode": returncode,
        "tests": tests,
        "skipped": skipped,
        "executed": max(0, tests - skipped),
        "complete": complete,
        "passed": passed,
        "reason": "passed"
        if passed
        else "native_failure"
        if complete
        else "missing_or_empty_runner_receipt",
    }


def render_native_verifier(
    command, project, *, expected_tests=None, followup=None, immutable_files=()
) -> str:
    """Embed only our stdlib supervisor; the model cannot edit its frozen file."""
    return (
        "import os, sys\n"
        "root=os.path.dirname(os.path.abspath(__file__))\n"
        "sys.path[:]=[p for p in sys.path if p and os.path.abspath(p)!=root]\n"
        "import hashlib, json, subprocess, tempfile\n"
        + textwrap.dedent(inspect.getsource(runner_result))
        + "\n"
        "env=dict(os.environ)\n"
        "env.update(PYTHONPATH=root,PYTHONDONTWRITEBYTECODE='1')\n"
        f"immutable_files={list(immutable_files)!r}\n"
        "def digest(path):\n"
        "    try:\n"
        "        with open(os.path.join(root,path),'rb') as stream:\n"
        "            return hashlib.sha256(stream.read()).hexdigest()\n"
        "    except OSError: return None\n"
        "before={path:digest(path) for path in immutable_files}\n"
        f"child_source={textwrap.dedent(inspect.getsource(native_child))!r}\n"
        "with tempfile.TemporaryFile() as channel:\n"
        f"    arguments={command!r}\n    project={project!r}\n"
        "    script=child_source+'\\nnative_child('+repr(arguments)+','+repr(project) "
        "+','+str(channel.fileno())+')\\n'\n"
        "    process=subprocess.run([arguments[0],'-c',script],cwd=root,env=env,"
        "pass_fds=(channel.fileno(),),capture_output=True,text=True)\n"
        "    channel.seek(0)\n"
        "    try: value=json.loads(channel.read(65536))\n"
        "    except (ValueError,TypeError): value={}\n"
        "sys.stdout.write(process.stdout)\nsys.stderr.write(process.stderr)\n"
        "receipt=runner_result(value,process.returncode)\n"
        f"expected={expected_tests!r}\n"
        "if receipt['passed'] and expected is not None and receipt['tests']!=expected:\n"
        "    receipt.update(passed=False,reason='test_count_changed')\n"
        f"followup={followup!r}\n"
        "if receipt['passed'] and followup:\n"
        "    extra=subprocess.run(followup,cwd=root,env=env,capture_output=True,text=True)\n"
        "    sys.stdout.write(extra.stdout)\n    sys.stderr.write(extra.stderr)\n"
        "    if extra.returncode: receipt.update(passed=False,reason='issue_reproduction_failed')\n"
        "changed=[path for path,digest_before in before.items() if digest(path)!=digest_before]\n"
        "if changed:\n"
        "    receipt.update(passed=False,reason='immutable_repository_changed',"
        "changed_immutable_files=changed[:20])\n"
        f"sys.stderr.write({RECEIPT_PREFIX!r}+json.dumps(receipt,sort_keys=True)+'\\n')\n"
        "sys.exit(0 if receipt['passed'] else 2)\n"
    )


def read_native_receipt(output: str) -> dict:
    rows = [
        line[len(RECEIPT_PREFIX) :]
        for line in output.splitlines()
        if line.startswith(RECEIPT_PREFIX)
    ]
    if not rows:
        return {
            "passed": False,
            "complete": False,
            "tests": 0,
            "executed": 0,
            "reason": "supervisor_did_not_finish",
        }
    value = json.loads(rows[-1])
    if not isinstance(value, dict) or value.get("version") != 1:
        raise ValueError("native supervisor receipt is invalid")
    return value
