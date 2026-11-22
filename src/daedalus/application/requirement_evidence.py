"""Bound requirements to operator-owned behavior tests before model work starts.

These are diagnostic artifacts, not new FSM states. A READY receipt can add a
frozen criterion to a new spec; it never approves a run or changes an old spec.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import new_id
from daedalus.domain.pathglob import normalize_path
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, BoundarySpec, MetaSpec
from daedalus.infrastructure.behavior_runner import (
    read_behavior_receipt,
    render_behavior_verifier,
)
from daedalus.infrastructure.git_sandbox import CommandResult, GitSandbox, _git
from daedalus.infrastructure.redact import redact_text
from daedalus.security.boundary import BoundaryGuard
from daedalus.security.outbound import assert_outbound_clean

COMMAND = "daedalus:behavior-contract-v1"
MAX_CHECKS = 12
MAX_PATH_STEPS = 5
MAX_PATH_TEXT = 4800


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z][\w-]{0,63}", value) is not None


def _path_text(value: object) -> bool:
    return isinstance(value, str) and len(value) <= 240 and bool(value.strip())


def _validate_behavior_paths(contract: dict, requirements: set[str]) -> None:
    paths = contract.get("behavior_paths")
    if not isinstance(paths, list) or not 2 <= len(paths) <= MAX_CHECKS:
        raise ValueError("declare bounded change and invariant paths")
    declared = {}
    text_size = 0
    for path in paths:
        if not isinstance(path, dict):
            raise ValueError("invalid behavior path")
        path_id = path.get("id")
        steps = path.get("steps")
        if (not _valid_id(path_id) or path_id in declared
                or path.get("requirement_id") not in requirements
                or path.get("role") not in {"change", "invariant"}
                or not _path_text(path.get("entry")) or not _path_text(path.get("outcome"))
                or not isinstance(steps, list) or not 1 <= len(steps) <= MAX_PATH_STEPS
                or not all(_path_text(step) for step in steps)):
            raise ValueError("behavior path needs an entry, state transitions and observable outcome")
        declared[path_id] = (path["requirement_id"], path["role"])
        text_size += len(path["entry"]) + len(path["outcome"]) + sum(map(len, steps))
    if {role for _, role in declared.values()} != {"change", "invariant"}:
        raise ValueError("behavior paths must cover both change and preservation")
    if text_size > MAX_PATH_TEXT:
        raise ValueError("behavior path descriptions exceed the shared context allowance")
    coverage = set()
    for check in contract["checks"]:
        path_id = check.get("path_id")
        if not _valid_id(path_id) or declared.get(path_id) != (check["requirement_id"], check["role"]):
            raise ValueError("behavior check must match the path requirement and role")
        coverage.add(path_id)
    if coverage != set(declared):
        raise ValueError("every behavior path needs a frozen check")


def require_path_qualification(contract: dict | None) -> None:
    if not contract or contract["version"] != 2:
        raise ValueError("a READY qualification with change and invariant behavior paths is required")


def seal(value: dict) -> dict:
    return {**value, "sha256": digest_of(value)}


def verify_seal(value: dict) -> None:
    if not isinstance(value, dict):
        raise ValueError("requirement evidence must be an object")
    body = {k: v for k, v in value.items() if k != "sha256"}
    if value.get("sha256") != digest_of(body):
        raise ValueError("requirement evidence digest does not match")


def validate_contract(contract: dict) -> None:
    verify_seal(contract)
    if type(contract.get("version")) is not int or contract["version"] not in {1, 2}:
        raise ValueError("unsupported behavior contract")
    for key in ("objective", "source"):
        if not isinstance(contract.get(key), str) or not contract[key].strip():
            raise ValueError("behavior contract needs an objective and frozen test source")
    if len(contract["objective"]) > 10000 or len(contract["source"]) > 16000:
        raise ValueError("behavior contract exceeds its fixed context limit")
    requirements = contract.get("requirements", [])
    checks = contract.get("checks", [])
    if not (isinstance(requirements, list) and 1 <= len(requirements) <= MAX_CHECKS
            and isinstance(checks, list) and 1 <= len(checks) <= MAX_CHECKS):
        raise ValueError("behavior contract needs bounded requirements and checks")
    identities = []
    for requirement in requirements:
        identity, statement = requirement.get("id"), requirement.get("statement")
        if (not _valid_id(identity)
                or not isinstance(statement, str) or not 1 <= len(statement.strip()) <= 1200):
            raise ValueError("requirement identity or statement is invalid")
        identities.append(identity)
    if len(set(identities)) != len(identities):
        raise ValueError("requirement identities must be unique")
    names, covered = [], set()
    for check in checks:
        name = check.get("test_name")
        if (not isinstance(name, str) or not re.fullmatch(r"test_[A-Za-z0-9_]{1,80}", name)
                or check.get("requirement_id") not in identities
                or check.get("role") not in {"change", "invariant"}):
            raise ValueError("behavior check does not bind a declared requirement")
        names.append(name)
        covered.add(check["requirement_id"])
    if (len(set(names)) != len(names) or covered != set(identities)
            or not any(c["role"] == "change" for c in checks)):
        raise ValueError("each requirement needs a check and the contract needs a change check")
    if contract["version"] == 2:
        _validate_behavior_paths(contract, covered)
    elif "behavior_paths" in contract or any("path_id" in check for check in checks):
        raise ValueError("behavior paths require a version 2 contract")
    if "repair_path" in contract:
        path = contract["repair_path"]
        if (contract["version"] != 2 or not isinstance(path, str)
                or not 1 <= len(path) <= 512 or normalize_path(path) != path
                or any(char in "*?" or ord(char) < 32 or ord(char) == 127 for char in path)):
            raise ValueError("repair_path must be a concrete normalized path in a version 2 contract")
    questions = contract.get("open_questions")
    if (not isinstance(questions, list) or len(questions) > 5
            or any(not isinstance(q, str) or not 1 <= len(q.strip()) <= 500 for q in questions)):
        raise ValueError("unresolved requirement questions are malformed")
    tree = ast.parse(contract["source"])
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "RequirementTests"]
    if len(classes) != 1:
        raise ValueError("frozen tests need one RequirementTests class")
    declared = [n.name for n in classes[0].body if isinstance(n, ast.FunctionDef)
                and n.name.startswith("test_")]
    if sorted(declared) != sorted(names):
        raise ValueError("test source and declared checks differ")
    assert_outbound_clean(json.dumps(contract, ensure_ascii=False),
                          where="operator behavior contract")


def run_checks(sandbox: GitSandbox, contract: dict, boundary: BoundarySpec, *, run) -> tuple:
    """Execute the controller's suite; bind the receipt to the exact tested tree."""
    validate_contract(contract)
    before, head = sandbox.tree_digest(), sandbox.head()
    names = [c["test_name"] for c in contract["checks"]]
    command = [sys.executable, "-B", "-I", "-c", render_behavior_verifier(
        contract["source"], names, contract["sha256"])]
    result = run(sandbox, command, timeout_sec=min(boundary.max_runtime_sec, 30))
    failure_code = result.failure_code
    if failure_code or result.timed_out:
        # A refused or timed-out launch need not have a supervisor transcript.
        # Preserve the execution fact instead of inferring a frozen spec mismatch.
        receipt = {"version": 1, "contract_digest": contract["sha256"], "executed": 0, "outcomes": {},
                   "reason": "behavior_execution_timed_out" if result.timed_out
                   else "behavior_execution_blocked"}
    else:
        receipt = read_behavior_receipt(result.stdout, contract["sha256"])
    outcomes = receipt.get("outcomes", {})
    complete = (receipt.get("complete") is True and type(receipt.get("executed")) is int
                and receipt["executed"] == len(names) and isinstance(outcomes, dict)
                and set(outcomes) == set(names)
                and all(v in {"pass", "assertion_failure"} for v in outcomes.values()))
    if sandbox.head() != head or sandbox.tree_digest() != before:
        complete = False
        receipt.update(reason="behavior_execution_changed_tree")
        failure_code = "spec_digest_mismatch"
    passed = complete and result.ok and all(v == "pass" for v in outcomes.values())
    receipt.update(complete=complete, passed=passed, reviewed_commit=head, reviewed_tree=before,
                   test_source_sha256=hashlib.sha256(contract["source"].encode()).hexdigest())
    return seal(receipt), replace(result, error_code=failure_code) if failure_code else result


def classify(contract: dict, receipt: dict) -> str:
    if contract["open_questions"]:
        return "NEEDS_CLARIFICATION"
    if receipt.get("complete") is not True:
        return "EVIDENCE_UNAVAILABLE"
    outcomes = receipt["outcomes"]
    if any(outcomes[c["test_name"]] != "pass" for c in contract["checks"]
           if c["role"] == "invariant"):
        return "NEEDS_CLARIFICATION"
    change = [outcomes[c["test_name"]] for c in contract["checks"] if c["role"] == "change"]
    return "ALREADY_SATISFIED" if all(v == "pass" for v in change) else "READY"


def qualify(repo: Path, contract: dict, targets: list[str], boundary: BoundarySpec,
            run_root: Path, *, driver) -> dict:
    validate_contract(contract)
    if (path := contract.get("repair_path")) and path not in targets:
        raise ValueError("repair_path must be a frozen target path")
    if not BoundaryGuard(boundary=boundary, meta=MetaSpec.default()).check_paths(targets).allowed:
        raise ValueError("requirement targets violate the frozen write boundary")
    if _git(repo, ["status", "--porcelain", "--untracked-files=all"], check=True).stdout.strip():
        raise ValueError("requirement qualification needs a clean committed repository")
    base = GitSandbox.main_commit(repo)
    tree = _git(repo, ["rev-parse", "HEAD^{tree}"], check=True).stdout.strip()
    result = {"version": 1, "contract_sha256": contract["sha256"], "repo_path": str(repo.resolve()),
              "check_id": boundary.boundary_id,
              "base_commit": base, "base_tree": tree, "target_paths": targets,
              "isolation": boundary.isolation, "automatic_resume": False,
              "network_policy": boundary.network_policy.value,
              "model_calls": 0, "decision": "NEEDS_CLARIFICATION", "baseline": {}}
    if not contract["open_questions"]:
        box = GitSandbox.create_from(repo_path=repo, run_root=run_root,
                                     name=new_id("requirement_base"), base_commit=base)
        try:
            def run(sandbox, command, *, timeout_sec):
                return driver.run(worktree=sandbox.worktree_path, command=command,
                    boundary=boundary, timeout_sec=timeout_sec).to_command_result()
            receipt, execution = run_checks(box, contract, boundary, run=run)
            result.update(baseline=receipt, decision=classify(contract, receipt),
                          diagnostic=redact_text(execution.combined(1800)))
        except (OSError, ValueError, KeyError, TypeError):
            result.update(decision="EVIDENCE_UNAVAILABLE",
                          diagnostic="behavior evidence unavailable")
        finally:
            box.remove()
    return seal(result)


def validate_qualification(contract: dict, proof: dict) -> None:
    validate_contract(contract)
    verify_seal(proof)
    baseline = proof.get("baseline", {})
    verify_seal(baseline)
    if (proof.get("version") != 1 or proof.get("decision") != "READY"
            or proof.get("contract_sha256") != contract["sha256"]
            or (contract.get("repair_path") and contract["repair_path"] not in proof.get("target_paths", ()))
            or baseline.get("contract_digest") != contract["sha256"]
            or classify(contract, baseline) != "READY"
            or baseline.get("reviewed_commit") != proof.get("base_commit")
            or baseline.get("reviewed_tree") != proof.get("base_tree")
            or baseline.get("executed") != len(contract["checks"])
            or type(baseline.get("executed")) is not int
            or set(baseline.get("outcomes", {})) != {c["test_name"] for c in contract["checks"]}
            or baseline.get("test_source_sha256") != hashlib.sha256(
                contract["source"].encode()).hexdigest()
            or not re.fullmatch(r"[0-9a-f]{40,64}", proof.get("base_commit", ""))):
        raise ValueError("behavior contract has no valid failing baseline qualification")


def assert_qualification_base(repo: Path, proof: dict) -> None:
    """Refuse dirty or advanced inputs before starting a new qualified execution."""
    if (proof["repo_path"] != str(repo.resolve())
            or GitSandbox.main_commit(repo) != proof["base_commit"]
            or _git(repo, ["status", "--porcelain", "--untracked-files=all"], check=True).stdout.strip()):
        raise ValueError("requirement check needs the original clean qualified repository")


def load_qualification(
    workspace: Path, check_id: str, repo: Path, objective: str, targets,
) -> tuple[dict, dict]:
    if not re.fullmatch(r"requirement_[A-Za-z0-9_]+", check_id):
        raise ValueError("invalid requirement check identity")
    directory = workspace / "requirement-checks" / check_id
    job = json.loads((directory / "job.json").read_text())
    proof = json.loads((directory / "report.json").read_text())
    contract = json.loads((directory / "contract.json").read_text())
    if job["status"] != "READY" or proof["check_id"] != check_id:
        raise ValueError("requirement check is not ready")
    validate_qualification(contract, proof)
    if contract["objective"] != objective or set(proof["target_paths"]) != set(targets):
        raise ValueError("requirement check belongs to another request")
    assert_qualification_base(repo, proof)
    return contract, proof


def preview_qualified_bundle(bundle) -> dict:
    """Show the public plan while keeping the signed document private to the controller."""
    from copy import deepcopy

    document = deepcopy(bundle.to_dict())
    return project_behavior_previews(document)


def project_behavior_previews(document: dict) -> dict:
    groups = (
        document.get("spec_01_goal", {}).get("acceptance_criteria", []),
        *(node.get("extra", {}).get("acceptance_criteria", [])
          for node in document.get("spec_02_plan", {}).get("nodes", [])),
    )
    for criteria in groups:
        criteria[:] = [public_criterion_preview(criterion) for criterion in criteria]
    return document


def public_criterion_preview(criterion: dict) -> dict:
    if criterion.get("command") != COMMAND:
        return criterion
    evidence = criterion["expect"]
    paths = public_behavior_paths(
        evidence["behavior_contract"], evidence["baseline_qualification"]["baseline"],
    )
    return {
        **{key: value for key, value in criterion.items() if key != "expect"},
        **({"behavior_paths": paths} if paths else {}),
    }


def project_behavior_results(evidence: dict) -> None:
    """Strip controller-only receipt detail from a single decoded check's evidence."""
    for row in evidence.get("criteria", []):
        if row.get("behavior_evidence"):
            row["behavior_evidence"] = model_behavior_evidence(row["behavior_evidence"])


def bind_qualified_bundle(bundle, contract: dict, proof: dict):
    """Use the proof's actual isolation choice before binding the reviewed goal."""
    return bind_bundle(
        replace(bundle, boundary=replace(bundle.boundary, isolation=proof["isolation"])),
        contract, proof,
    )


def bound_qualification(bundle) -> dict | None:
    """Recover the proof from the frozen goal, never from fresh submission input."""
    criteria = [c for c in bundle.goal.acceptance_criteria if is_behavior(c)]
    if not criteria:
        return None
    if len(criteria) != 1:
        raise ValueError("the qualified goal must have exactly one controller-owned contract")
    criterion = criteria[0]
    contract = criterion.expect["behavior_contract"]
    proof = criterion.expect["baseline_qualification"]
    validate_qualification(contract, proof)
    if (criterion.command != COMMAND or criterion.kind is not AssertionKind.SCRIPT
            or criterion.path != contract.get("repair_path", "")
            or contract["objective"] != bundle.goal.objective
            or set(proof["target_paths"]) != set(bundle.boundary.fs_whitelist)
            or proof["isolation"] != bundle.boundary.isolation
            or proof["network_policy"] != bundle.boundary.network_policy.value):
        raise ValueError("the qualified contract no longer matches the reviewed goal")
    return proof


def bind_bundle(bundle, contract: dict, proof: dict):
    validate_qualification(contract, proof)
    if bundle.goal.objective != contract["objective"]:
        raise ValueError("behavior qualification belongs to another objective")
    if set(proof["target_paths"]) != set(bundle.boundary.fs_whitelist):
        raise ValueError("behavior qualification belongs to another writable scope")
    if bundle.boundary.isolation != proof["isolation"]:
        raise ValueError("behavior qualification belongs to another isolation policy")
    if bundle.boundary.network_policy.value != proof["network_policy"]:
        raise ValueError("behavior qualification belongs to another network policy")
    criterion = AcceptanceCriterion(
        "behavior-" + contract["sha256"][:16], AssertionKind.SCRIPT,
        statement="Operator-frozen behavior checks: " + "; ".join(
            r["id"] + ": " + r["statement"] for r in contract["requirements"]),
        command=COMMAND, path=contract.get("repair_path", ""),
        expect={"behavior_contract": contract, "baseline_qualification": proof})
    if any(c.criterion_id == criterion.criterion_id for c in bundle.goal.acceptance_criteria):
        raise ValueError("behavior criterion is already bound")
    if bundle.plan.integrated_acceptance:
        # All roots still remain independent; the mandatory goal audit runs this once
        # on the integrated candidate rather than on any partial worktree.
        bound = replace(bundle, goal=replace(bundle.goal, acceptance_criteria=(
            *bundle.goal.acceptance_criteria, criterion)))
        bound.validate()
        return bound
    # One existing terminal node waits for every other terminal. It can then verify
    # the complete feature before Tier-2 without imposing that on partial nodes.
    dependencies = {dep for n in bundle.plan.nodes for dep in n.deps}
    sinks = [n.node_id for n in bundle.plan.nodes if n.node_id not in dependencies]
    final = sinks[-1]
    nodes = []
    for node in bundle.plan.nodes:
        checks = tuple(node.acceptance_criteria or bundle.goal.acceptance_criteria)
        deps = node.deps
        if node.node_id == final:
            checks += (criterion,)
            deps = tuple(dict.fromkeys((*deps, *(sink for sink in sinks if sink != final))))
        nodes.append(replace(node, deps=deps, extra={**node.extra,
            "acceptance_criteria": [c.to_dict() for c in checks]}))
    bound = replace(bundle, goal=replace(bundle.goal, acceptance_criteria=(
        *bundle.goal.acceptance_criteria, criterion)),
        plan=replace(bundle.plan, nodes=tuple(nodes)))
    bound.validate()
    return bound


def is_behavior(criterion: AcceptanceCriterion) -> bool:
    return criterion.command == COMMAND or (
        isinstance(criterion.expect, dict) and "behavior_contract" in criterion.expect)


def execute_criterion(sandbox: GitSandbox, criterion: AcceptanceCriterion,
                      boundary: BoundarySpec, objective: str, *, run) -> tuple:
    try:
        contract = criterion.expect["behavior_contract"]
        proof = criterion.expect["baseline_qualification"]
        validate_qualification(contract, proof)
        if (criterion.command != COMMAND or criterion.kind is not AssertionKind.SCRIPT
                or criterion.path != contract.get("repair_path", "")
                or contract["objective"] != objective
                or boundary.isolation != proof["isolation"]
                or boundary.network_policy.value != proof["network_policy"]
                or not set(boundary.fs_whitelist) <= set(proof["target_paths"])):
            raise ValueError("behavior contract does not match the frozen goal")
        if not _git(sandbox.worktree_path, ["merge-base", "--is-ancestor", proof["base_commit"],
                                          sandbox.head()], check=False).ok:
            raise ValueError("candidate is not derived from the qualified baseline")
        receipt, result = run_checks(sandbox, contract, boundary, run=run)
        evidence = {"criterion_digest": digest_of(criterion.to_dict()),
                    "contract_digest": contract["sha256"], "baseline_commit": proof["base_commit"],
                    "requirement_checks": contract["checks"], "receipt": receipt}
        # The native transcript can contain the entire assertion (including values and
        # private test names). Only its public requirement outcomes may reach models.
        return replace(
            result, exit_code=0 if receipt["passed"] else 1, command=COMMAND,
            stdout=json.dumps(model_behavior_evidence(evidence), ensure_ascii=False),
            stderr="",
        ), evidence
    except (ValueError, KeyError, TypeError, OSError):
        return CommandResult(COMMAND, 1, "", "Frozen behavior evidence is unavailable or invalid",
                             0, error_code="spec_digest_mismatch"), {
                                 "behavior_evidence_invalid": True}


def behavior_check_results(criterion: AcceptanceCriterion, rows: list[dict]) -> list[dict]:
    """Localize frozen requirements without treating an incomplete run as a defect."""
    contract = (criterion.expect.get("behavior_contract")
                if isinstance(criterion.expect, dict) else None)
    if not contract:
        return []
    validate_contract(contract)
    statements = {r["id"]: r["statement"] for r in contract["requirements"]}
    receipts = []
    for row in rows:
        evidence = row.get("behavior_evidence", {})
        if not isinstance(evidence, dict):
            continue
        receipt = evidence.get("receipt", {})
        try:
            verify_seal(receipt)
            if (evidence.get("criterion_digest") != digest_of(criterion.to_dict())
                    or evidence.get("contract_digest") != contract["sha256"]
                    or receipt.get("contract_digest") != contract["sha256"]
                    or receipt.get("complete") is not True
                    or receipt.get("executed") != len(contract["checks"])
                    or set(receipt.get("outcomes", {}))
                    != {c["test_name"] for c in contract["checks"]}):
                continue
        except (ValueError, TypeError):
            continue
        receipts.append(receipt)
    checks = []
    for check in contract["checks"]:
        outcomes = [r["outcomes"][check["test_name"]] for r in receipts]
        status = ("UNMET" if "assertion_failure" in outcomes else "MET"
                  if outcomes and all(o == "pass" for o in outcomes) else "UNKNOWN")
        checks.append({**check, "statement": statements[check["requirement_id"]], "status": status})
    return checks


def behavior_context(
    criterion: AcceptanceCriterion, *, source_baseline: tuple[str, str] | None = None,
    historical_failure_paths: frozenset[str] | None = None,
) -> tuple[str, str]:
    """Return public prompt text and a source query, without modifying its baseline labels."""
    contract = (criterion.expect.get("behavior_contract")
                if isinstance(criterion.expect, dict) else None)
    if not contract:
        return "", ""
    proof = criterion.expect.get("baseline_qualification", {})
    validate_qualification(contract, proof)
    paths = public_behavior_paths(contract, proof["baseline"])
    if paths:
        focus = ""
        if historical_failure_paths is not None:
            focus = _behavior_source_hint(path for path in paths if path["id"] in historical_failure_paths)
        elif source_baseline == (proof["base_commit"], proof["base_tree"]):
            focus = failed_behavior_source_hint(paths)
        return (
            "\nFROZEN BEHAVIOR PATHS (public path and baseline only):\n"
            + json.dumps(paths, ensure_ascii=False, separators=(",", ":"))
            + "\nThe controller runs the frozen checks. Test source and inputs are not model context.\n"
        ), focus
    return (
        "\nFROZEN BEHAVIOR REQUIREMENTS (required changes versus invariants):\n"
        + json.dumps({"criterion_id": criterion.criterion_id,
                      "requirements": contract["requirements"],
                      "baseline_requirements": _requirement_outcomes(
                          contract["checks"], proof["baseline"])}, ensure_ascii=False)
        + "\nThe controller runs the frozen checks. Test source and inputs are not model context.\n"
    ), ""


def _requirement_outcomes(checks: list[dict], receipt: dict, *, field: str = "requirement_id") -> list[dict]:
    """Aggregate outcomes by public requirement and role, without test identifiers."""
    groups: dict[tuple[str, str], list[str | None]] = {}
    actual = receipt.get("outcomes", {}) if receipt.get("complete") is True else {}
    for check in checks:
        key = (check[field], check["role"])
        groups.setdefault(key, []).append(actual.get(check["test_name"]))
    return [
        {field: identity, "role": role, "status": (
            "UNMET" if "assertion_failure" in outcomes else
            "MET" if all(result == "pass" for result in outcomes) else "UNKNOWN"
        )}
        for (identity, role), outcomes in groups.items()
    ]

def public_behavior_paths(contract: dict, receipt: dict) -> list[dict]:
    paths = contract.get("behavior_paths", [])
    if not paths:
        return []
    statuses = {row["path_id"]: row["status"] for row in _requirement_outcomes(
        contract["checks"], receipt, field="path_id",
    )}
    return [
        {**{key: path[key] for key in ("id", "requirement_id", "role", "entry", "steps", "outcome")},
         "status": statuses[path["id"]]}
        for path in paths
    ]


def failed_behavior_source_hint(paths: list[dict]) -> str:
    return _behavior_source_hint(path for path in paths if path["status"] == "UNMET")


def _behavior_source_hint(paths: Iterable[dict]) -> str:
    return "\n".join("\n".join((path["entry"], *path["steps"], path["outcome"])) for path in paths)


def with_behavior_path_context(request, qualification: tuple[dict, dict]):
    """Add only already-qualified public behavior to the existing planning request."""
    contract, proof = qualification
    paths = public_behavior_paths(contract, proof["baseline"])
    if not paths:
        return request
    return replace(
        request,
        extra_context=request.extra_context
        + "\nOPERATOR-FROZEN BEHAVIOR PATHS (plan alongside these; use only declared tests; "
        "the controller binds their checks at execution):\n"
        + json.dumps(paths, ensure_ascii=False, separators=(",", ":")),
    )


def model_behavior_evidence(evidence: dict) -> dict:
    """Identity and actual public outcomes only; keep full receipt in the controller."""
    receipt = evidence.get("receipt", {})
    checks = evidence.get("requirement_checks", [])
    return {
        "receipt": {key: receipt[key] for key in (
            "sha256", "complete", "passed", "executed", "reviewed_tree", "reviewed_commit",
        ) if key in receipt},
        **({"execution_reason": receipt["reason"]} if receipt.get("reason") in (
            "behavior_execution_timed_out", "behavior_execution_blocked",
            "behavior_execution_changed_tree", "incomplete_or_invalid_runner_evidence",
        ) else {}),
        "requirements": _requirement_outcomes(checks, receipt),
        **({"behavior_paths": _requirement_outcomes(checks, receipt, field="path_id")}
           if checks and all("path_id" in check for check in checks) else {}),
    }


def valid_behavior_references(criteria: list, reviewed: list) -> bool:
    """A model's evidence reference must name the controller's actual receipt."""
    rows = {r["criterion_id"]: r for r in reviewed}
    for criterion in criteria:
        evidence = criterion.get("behavior_evidence")
        if not evidence:
            continue
        receipt = evidence.get("receipt", {})
        if (receipt.get("passed") is not True or receipt.get("complete") is not True
                or rows.get(criterion["criterion_id"], {}).get("evidence_refs")
                != [receipt.get("sha256")]):
            return False
    return True
