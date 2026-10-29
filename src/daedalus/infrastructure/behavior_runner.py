"""Operator-frozen unittest supervision, separate from candidate stdout.

Like the native runner, counters detect missing execution and ordinary spoofing;
they are not protection against arbitrary Python introspection. The selected
sandbox remains responsible for process and filesystem isolation.
"""

from __future__ import annotations

import inspect
import json
import textwrap

PREFIX = "DAEDALUS_BEHAVIOR_RESULT "


def behavior_child(source, names, descriptor):
    import io
    import json
    import os
    import sys
    import types
    import unittest

    write, dumps = os.write, json.dumps
    original_case_run = unittest.TestCase.run
    original_runner_run = unittest.TextTestRunner.run
    protected = {cls: dict(vars(cls)) for cls in (
        unittest.TestCase, unittest.TestLoader, unittest.TestResult,
        unittest.TextTestResult, unittest.TextTestRunner)}
    observations = {}

    class Observed(unittest.TextTestResult):
        def startTest(self, test):
            name = test._testMethodName
            observations.setdefault(name, []).append("started")
            super().startTest(test)

        def mark(self, test, status):
            observations[test._testMethodName][-1] = status

        def addSuccess(self, test):
            if observations[test._testMethodName][-1] == "started":
                self.mark(test, "pass")
            super().addSuccess(test)

        def addFailure(self, test, error):
            self.mark(test, "assertion_failure")
            super().addFailure(test, error)

        def addError(self, test, error):
            self.mark(test, "error")
            super().addError(test, error)

        def addSkip(self, test, reason):
            self.mark(test, "skip")
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, error):
            self.mark(test, "expected_failure")
            super().addExpectedFailure(test, error)

        def addUnexpectedSuccess(self, test):
            self.mark(test, "unexpected_success")
            super().addUnexpectedSuccess(test)

        def addSubTest(self, test, subtest, error):
            if error is not None:
                self.mark(test, "assertion_failure" if issubclass(error[0], AssertionError)
                          else "error")
            super().addSubTest(test, subtest, error)

    value = {"version": 1, "observations": observations, "runner_intact": False}
    code = 1
    try:
        # Import supervisor dependencies before permitting repository imports.
        sys.path.insert(0, os.getcwd())
        module = types.ModuleType("_operator_behavior_tests")
        exec(compile(source, "<operator-frozen-tests>", "exec"), module.__dict__)
        cls = module.RequirementTests
        suite = unittest.TestLoader().loadTestsFromTestCase(cls)
        discovered = [t._testMethodName for t in suite]
        if sorted(discovered) != sorted(names):
            raise ValueError("discovered tests differ from the frozen declaration")
        stream = io.StringIO()
        runner = unittest.TextTestRunner(stream=stream, resultclass=Observed, verbosity=2)
        result = original_runner_run(runner, suite)
        sys.stderr.write(stream.getvalue())
        value["runner_intact"] = (unittest.TestCase.run is original_case_run
            and unittest.TextTestRunner.run is original_runner_run
            and all(all(vars(cls).get(key) is member for key, member in members.items())
                    for cls, members in protected.items()))
        code = 0 if result.wasSuccessful() else 1
    except BaseException:  # noqa: BLE001 - an interrupted suite cannot qualify a requirement
        value["suite_error"] = True
    write(descriptor, dumps(value).encode())
    os.close(descriptor)
    sys.exit(code)


def behavior_result(value, names, returncode):
    observations = value.get("observations", {})
    valid = (
        value.get("version") == 1
        and value.get("runner_intact") is True
        and not value.get("suite_error")
        and isinstance(observations, dict)
        and set(observations) == set(names)
        and all(isinstance(v, list) and len(v) == 1
                and v[0] in {"pass", "assertion_failure"} for v in observations.values())
        and type(returncode) is int and returncode in {0, 1}
    )
    outcomes = {k: v[0] for k, v in observations.items()} if valid else {}
    passed = valid and returncode == 0 and all(v == "pass" for v in outcomes.values())
    consistent = valid and ((returncode == 0) == all(v == "pass" for v in outcomes.values()))
    return {"version": 1, "complete": consistent, "passed": passed and consistent,
            "executed": len(outcomes) if consistent else 0,
            "outcomes": outcomes if consistent else {},
            "reason": "passed" if passed and consistent else "assertion_failure"
            if consistent else "incomplete_or_invalid_runner_evidence"}


def render_behavior_verifier(source: str, names: list[str], contract_digest: str) -> str:
    """The harness is carried by the controller, never read from candidate files."""
    return (
        "import json, os, subprocess, sys, tempfile\n"
        + textwrap.dedent(inspect.getsource(behavior_result)) + "\n"
        + f"names={names!r}\n"
        + f"child_source={textwrap.dedent(inspect.getsource(behavior_child))!r}\n"
        + "env=dict(os.environ)\nenv['PYTHONDONTWRITEBYTECODE']='1'\n"
        + "with tempfile.TemporaryFile() as channel:\n"
        + f"    script=child_source+'\\nbehavior_child('+repr({source!r})+','+repr(names) "
          "+','+str(channel.fileno())+')\\n'\n"
        + "    process=subprocess.run([sys.executable,'-B','-I','-c',script],env=env,"
          "pass_fds=(channel.fileno(),),capture_output=True,text=True)\n"
        + "    channel.seek(0)\n"
        + "    try: value=json.loads(channel.read(262144))\n"
        + "    except (ValueError,TypeError): value={}\n"
        + "sys.stdout.write(process.stdout)\nsys.stderr.write(process.stderr)\n"
        + "receipt=behavior_result(value,names,process.returncode)\n"
        + f"receipt['contract_digest']={contract_digest!r}\n"
        + f"print({PREFIX!r}+json.dumps(receipt,sort_keys=True))\n"
        + "sys.exit(0 if receipt['passed'] else 1)\n"
    )


def read_behavior_receipt(output: str, contract_digest: str) -> dict:
    rows = [line[len(PREFIX):] for line in output.splitlines() if line.startswith(PREFIX)]
    if len(rows) != 1:
        raise ValueError("missing or duplicate behavior supervisor receipt")
    value = json.loads(rows[0])
    if (not isinstance(value, dict) or value.get("version") != 1
            or value.get("contract_digest") != contract_digest):
        raise ValueError("behavior supervisor receipt does not match the frozen contract")
    return value
