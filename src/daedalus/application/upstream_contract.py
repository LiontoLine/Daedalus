"""Compile immutable PASS_TO_PASS checks separately from hidden issue acceptance.

No model, shell or reference source patch is used to choose public assertions.
The native runner and both reference/baseline qualification remain operator-owned.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path


def _changed_old_lines(patch: str) -> dict[str, set[int]]:
    changed, path, line = {}, "", 0
    for value in patch.splitlines():
        if value.startswith("--- a/"):
            path = value[6:]
            changed.setdefault(path, set())
        elif value.startswith("@@ "):
            match = re.match(r"@@ -(\d+)", value)
            line = int(match[1]) if match else 0
        elif path and value.startswith("+") and not value.startswith("+++"):
            changed[path].add(line)
        elif path and value.startswith("-") and not value.startswith("---"):
            changed[path].add(line)
            line += 1
        elif value.startswith(" "):
            line += 1
    return changed


def _original_method(source: Path, label: str):
    parts = label.split(".")
    for stop in range(len(parts)-2, 0, -1):
        for prefix in (source / "tests", source):
            path = prefix.joinpath(*parts[:stop]).with_suffix(".py")
            if not path.is_file() or path.is_symlink():
                continue
            if not path.resolve().is_relative_to(source.resolve()):
                raise ValueError("test source escapes the upstream repository")
            nodes = ast.parse(path.read_text()).body
            found = None
            for name in parts[stop:]:
                found = next((n for n in nodes if isinstance(n, (ast.ClassDef, ast.FunctionDef))
                              and n.name == name), None)
                if found is None:
                    break
                nodes = found.body
            if isinstance(found, ast.FunctionDef) and found.name == parts[-1]:
                start = min([found.lineno, *(n.lineno for n in found.decorator_list)])
                return path.relative_to(source).as_posix(), start, found.end_lineno
    return None


def _ids(task: dict, name: str) -> list[str]:
    value = task.get(name)
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, list) or not value or any(not isinstance(v, str) for v in value):
        raise ValueError(f"missing or malformed {name} test identities")
    return sorted(set(value))


def compile_contract(task: dict, labels: list[str], source: Path) -> dict:
    passing = _ids(task, "PASS_TO_PASS")
    failing = _ids(task, "FAIL_TO_PASS")
    if set(passing) & set(failing):
        raise ValueError("passing and changing test identities overlap")
    result = {"version":2, "repo":task["repo"], "hidden_labels":list(labels),
              "metadata_sha256":hashlib.sha256(json.dumps(
                  {"PASS_TO_PASS":passing,"FAIL_TO_PASS":failing}, sort_keys=True
              ).encode()).hexdigest(), "omitted_nonselectable":[]}
    if task["repo"] == "django/django":
        selected = []
        changed = _changed_old_lines(task.get("test_patch", ""))
        for identity in passing:
            match = re.fullmatch(r"(test_\w+) \(([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\)", identity)
            if not match:
                result["omitted_nonselectable"].append(identity)
                continue
            label = match[2] if match[2].endswith("." + match[1]) else match[2] + "." + match[1]
            if any(label.startswith(module + ".") for module in labels):
                method = _original_method(source, label)
                if method is None:
                    result["omitted_nonselectable"].append(identity)
                    continue
                path, start, end = method
                if any(start <= line <= end for line in changed.get(path, ())):
                    # A method whose expected result/decorators change belongs to hidden
                    # issue acceptance, even if noisy metadata calls it PASS_TO_PASS.
                    result["omitted_nonselectable"].append(identity)
                    continue
                selected.append(label)
        if not selected:
            raise ValueError("no selectable PASS_TO_PASS regression tests")
        result["public_labels"] = sorted(set(selected))
    elif task["repo"] == "sympy/sympy":
        names = {name for name in passing if re.fullmatch(r"test_\w+", name)}
        changing = {name for name in failing if re.fullmatch(r"test_\w+", name)}
        available = set()
        for label in labels:
            path = source / label
            if (not path.resolve().is_relative_to(source.resolve()) or path.is_symlink()
                    or not path.is_file()):
                raise ValueError("native regression module is not a regular source file")
            tree = ast.parse(path.read_text())
            available.update(n.name for n in tree.body if isinstance(n, ast.FunctionDef))
        names &= available
        if not names or names & changing:
            raise ValueError("native regression identities are unavailable or ambiguous")
        result["public_names"] = sorted(names)
        # Exact identities: native kw= uses substring matching and can include a changing
        # test with a longer name. Never silently treat zero discovered checks as a pass.
        result["public_runner"] = (
            "import importlib, sys\n"
            "try: runner=importlib.import_module('sympy.testing.runtests')\n"
            "except ImportError: runner=importlib.import_module('sympy.utilities.runtests')\n"
            f"allowed=set({sorted(names)!r})\nseen=set()\n"
            "def matches(self, function):\n"
            "    name=function.__name__\n"
            "    if name in allowed:\n        seen.add(name)\n        return True\n"
            "    return False\n"
            "runner.SymPyTests.matches=matches\n"
            f"code=runner._test(*{labels!r}, colors=False, seed=1729)\n"
            "if seen != allowed:\n"
            "    print('REGRESSION_SELECTION_INCOMPLETE', len(seen), len(allowed))\n"
            "    sys.exit(2)\n"
            "sys.exit(int(code))\n"
        )
    else:
        raise ValueError("unsupported native upstream project")
    result["sha256"] = hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()
    return result


def validate_contract(contract: dict) -> None:
    value = dict(contract)
    expected = value.pop("sha256", "")
    if value.get("version") != 2 or hashlib.sha256(
        json.dumps(value,sort_keys=True).encode()
    ).hexdigest() != expected:
        raise ValueError("frozen native test contract digest does not match")


def admit_contract(row: dict) -> None:
    """Refuse model spend unless both public trees and the hidden oracle self-check."""
    contract = row.get("test_contract")
    if not isinstance(contract, dict):
        raise ValueError("native workload has no frozen test contract")
    validate_contract(contract)
    if contract["repo"] != row["repo"] or contract["hidden_labels"] != row["labels"]:
        raise ValueError("native test contract belongs to another workload")
    proof = row.get("contract_qualification", {})
    for name in ("public_original", "public_reference", "hidden_original", "hidden_reference"):
        check = proof.get(name, {})
        if check.get("complete") is not True or check.get("executed", 0) <= 0:
            raise ValueError("native test completion qualification is missing or empty")
        if check.get("evidence_kind") != "native_runner_counters":
            raise ValueError("native qualification must use runner counters, not printed summaries")
    for name in ("public_original", "public_reference", "hidden_reference"):
        check = proof.get(name, {})
        if check.get("passed") is not True or check.get("tests", 0) <= 0:
            raise ValueError("native reference/baseline qualification is incomplete")
    if proof.get("hidden_original", {}).get("passed") is not False:
        raise ValueError("native hidden tests do not detect the original issue")
