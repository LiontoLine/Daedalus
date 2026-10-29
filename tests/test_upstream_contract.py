"""Preserve passing behavior without requiring a fix to preserve the old bug."""
import json
import sys
from types import SimpleNamespace

import pytest

from daedalus.application import realwork
from daedalus.application.upstream_contract import (
    admit_contract,
    compile_contract,
    validate_contract,
)
from daedalus.infrastructure.git_sandbox import _git


def test_reference_fix_can_pass_public_and_hidden_when_old_expectation_changes(tmp_path, monkeypatch):
    source = tmp_path / "upstream"
    (source / "tests").mkdir(parents=True)
    (source / "solution.py").write_text("def stable(): return 1\ndef changing(): return 'old'\n")
    old = ("import unittest\nfrom solution import stable, changing\n"
           "class Legacy(unittest.TestCase):\n"
           "    def test_stable(self): self.assertEqual(stable(), 1)\n"
           "    def test_changing(self): self.assertEqual(changing(), 'old')\n")
    (source / "mytests.py").write_text(old)
    (source / "tests/runtests.py").write_text(
        "import sys, unittest\n"
        "labels=[]\n"
        "for value in sys.argv[1:]:\n"
        "    if value.startswith('--'): break\n"
        "    labels.append(value)\n"
        "suite=unittest.defaultTestLoader.loadTestsFromNames(labels)\n"
        "sys.exit(not unittest.TextTestRunner().run(suite).wasSuccessful())\n"
    )
    import difflib
    new = old.replace("changing(), 'old'", "changing(), 'new'")
    patch = "".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),
                                      fromfile="a/mytests.py",tofile="b/mytests.py"))
    task = {"repo":"django/django", "problem_statement":"Return new; stable stays one",
            "PASS_TO_PASS":json.dumps(["test_stable (mytests.Legacy)"]),
            "FAIL_TO_PASS":json.dumps(["test_changing (mytests.Legacy)"]), "test_patch":patch}
    data = tmp_path / "data"
    (data / "tasks/issue").mkdir(parents=True)
    (data / "tasks/issue/task.json").write_text(json.dumps(task))
    (data / "env/bin").mkdir(parents=True)
    (data / "env/bin/python").symlink_to(sys.executable)
    monkeypatch.setattr(realwork,"PROJECT",tmp_path)
    monkeypatch.setattr(realwork,"DATA",data)
    contract = compile_contract(task,["mytests"],source)
    row = {"case":"issue", "repo":"django/django", "labels":["mytests"],
           "upstream_root":"upstream", "targets":["solution.py"], "test_contract":contract}
    root = tmp_path / "run"
    root.mkdir()
    repo,bundle,_tree,frozen = realwork._setup(row,root,30000)
    initial = _git(repo,["rev-parse","HEAD"],check=True).stdout.strip()
    baseline = realwork._evaluate(repo,bundle,frozen,root,initial)
    assert baseline["public_passed"] and not baseline["heldout_passed"]
    (repo / "solution.py").write_text("def stable(): return 1\ndef changing(): return 'new'\n")
    _git(repo,["add","solution.py"],check=True)
    _git(repo,["commit","-m","reference behavior change"],check=True)
    candidate = _git(repo,["rev-parse","HEAD"],check=True).stdout.strip()
    # The old unfiltered public suite really rejects this correct behavior change.
    import os
    import subprocess
    env=dict(os.environ, PYTHONPATH=str(repo))
    old_run=subprocess.run([sys.executable,"tests/runtests.py","mytests"],cwd=repo,
                           env=env,capture_output=True)
    assert old_run.returncode != 0
    result = realwork._evaluate(repo,bundle,frozen,tmp_path / "grade",candidate)
    assert result["public_passed"] and result["heldout_passed"] and result["policy_passed"]
    assert "verify_hidden.py" not in bundle.boundary.fs_whitelist


@pytest.mark.parametrize("ids", [[], ["test_one (module.Class); run shell"], ["../bad"]])
def test_invalid_or_empty_regression_selection_cannot_pass(tmp_path, ids):
    task={"repo":"django/django", "PASS_TO_PASS":ids,"FAIL_TO_PASS":["test_other (module.Class)"]}
    with pytest.raises(ValueError):
        compile_contract(task,["module"],tmp_path)


def test_contract_digest_rejects_changed_test_identities(tmp_path):
    (tmp_path / "module.py").write_text("class Class:\n    def test_one(self): pass\n")
    contract=compile_contract({"repo":"django/django", "PASS_TO_PASS":["test_one (module.Class)"],
                               "FAIL_TO_PASS":["test_other (module.Class)"]},["module"],tmp_path)
    validate_contract(contract)
    contract["public_labels"].append("module.Class.test_other")
    with pytest.raises(ValueError, match="digest"):
        validate_contract(contract)


def test_failed_reference_or_missing_qualification_blocks_admission(tmp_path):
    (tmp_path / "module.py").write_text("class Class:\n    def test_one(self): pass\n")
    contract=compile_contract({"repo":"django/django", "PASS_TO_PASS":["test_one (module.Class)"],
                               "FAIL_TO_PASS":["test_other (module.Class)"]},["module"],tmp_path)
    row={"repo":"django/django","labels":["module"],"test_contract":contract}
    with pytest.raises(ValueError,match="qualification"):
        admit_contract(row)
    row["contract_qualification"]={name:{"passed":True,"tests":1,"complete":True,"executed":1,"evidence_kind":"native_runner_counters"}
        for name in ["public_original","public_reference","hidden_reference"]}
    row["contract_qualification"]["hidden_original"]={"passed":False,"complete":True,"executed":1,"evidence_kind":"native_runner_counters"}
    admit_contract(row)
    row["contract_qualification"]["public_reference"]["passed"]=False
    with pytest.raises(ValueError,match="qualification"):
        admit_contract(row)


@pytest.mark.parametrize("discover", [True, False])
def test_native_sympy_selector_is_exact_and_refuses_zero_discovery(tmp_path,monkeypatch,discover):
    (tmp_path / "test_native.py").write_text("def test_stable(): pass\ndef test_stable_more(): pass\n")
    contract=compile_contract({"repo":"sympy/sympy", "PASS_TO_PASS":["test_stable"],
                               "FAIL_TO_PASS":["test_stable_more"]},["test_native.py"],tmp_path)
    class Tests:
        pass
    called=[]
    def test_stable():
        called.append("stable")
    def test_stable_more():
        pytest.fail("substring matching selected a changing assertion")
    def native(*args,**kwargs):
        if discover:
            for function in [test_stable,test_stable_more]:
                if Tests().matches(function):
                    function()
        return 0
    monkeypatch.setitem(sys.modules,"sympy.testing.runtests",SimpleNamespace(SymPyTests=Tests,_test=native))
    with pytest.raises(SystemExit) as status:
        exec(contract["public_runner"],{})
    assert status.value.code == (0 if discover else 2)
    assert called == (["stable"] if discover else [])
