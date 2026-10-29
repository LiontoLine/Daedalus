"""Tier-1: the deterministic gate (Spec §9.1).

Ten checks, all of them code rather than judgement:

  1. path whitelist            (SPEC-03 + Meta-Spec, via BoundaryGuard)
  2. git diff sanity           (non-empty, no binary surprises, no forbidden paths)
  3. schema validation         (spec documents still parse and validate)
  4. AST / syntax              (every changed Python file must compile)
  5. linter                    (if the project declares one)
  6. type check                (if the project declares one)
  7. unit tests                (the SPEC-01 acceptance assertions)
  8. artifact check            (declared expected_artifacts actually exist)
  9. resource usage            (runtime / token budget from SPEC-03)
 10. forbidden file check      (`.env`, keys, `.git` internals, host credential paths)

Everything is explicit about *why* it failed: the report carries per-check detail so
the REVISE feedback given back to the coding model is actionable and so the audit can
answer "why was this rejected" without re-running anything.
"""

from __future__ import annotations

import ast
import errno
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from daedalus.application.gatekeeper.decision import GateDecision
from daedalus.application.source_context import failure_excerpt
from daedalus.domain.artifacts import Artifact
from daedalus.domain.pathglob import normalize_path
from daedalus.domain.spec import (
    AcceptanceCriterion,
    AssertionKind,
    BoundarySpec,
    GoalSpec,
    MetaSpec,
    PlanNode,
)
from daedalus.infrastructure.git_sandbox import CommandResult, GitSandbox
from daedalus.security.boundary import ALWAYS_DENIED_PATHS, BoundaryGuard
from daedalus.security.outbound import describe_findings, scan_added_lines


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    severity: str = "error"  # "error" blocks; "warning" is advisory only

    def to_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "severity": self.severity,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class Tier1Report:
    step_id: str
    subject_digest: str
    checks: tuple[CheckResult, ...]
    decision: GateDecision
    reasons: tuple[str, ...] = ()
    advisories: tuple[str, ...] = ()

    @property
    def failed_checks(self) -> tuple[CheckResult, ...]:
        return tuple(c for c in self.checks if not c.passed and c.severity == "error")

    @property
    def passed(self) -> bool:
        return self.decision is GateDecision.PASS

    @property
    def infrastructure_errors(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(
            str(check.evidence["error_code"]) for check in self.failed_checks
            if check.evidence.get("error_code")
        ))

    def to_payload(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "subject_digest": self.subject_digest,
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "advisories": list(self.advisories),
            "checks": [c.to_payload() for c in self.checks],
        }

    def revise_feedback(self, limit: int = 10) -> str:
        """Compact, actionable feedback handed back to the coding model."""
        lines = [f"- {c.name}: {c.detail}" for c in self.failed_checks[:limit]]
        return "\n".join(lines)


@dataclass
class Tier1Gate:
    """Runs the deterministic checks against one worktree."""

    goal: GoalSpec
    plan_node: PlanNode
    boundary: BoundarySpec
    meta: MetaSpec
    #: The process-isolation mechanism. `None` means "run directly", which keeps the gate
    #: usable in tests that do not care about isolation, but every real run supplies one.
    driver: Any = None

    guard: BoundaryGuard = field(init=False)
    python_executable: str = "python3"
    run_tests: bool = True
    dependency_cache: Path | None = None

    def __post_init__(self) -> None:
        self.guard = BoundaryGuard(boundary=self.boundary, meta=self.meta)

    def _run(
        self, sandbox: GitSandbox, command: list[str], *, timeout_sec: int
    ) -> CommandResult:
        """Run one command under the selected isolation, or directly if none was supplied.

        This is the single place the gate executes anything, so the isolation level applies
        uniformly to linters, type checkers and acceptance tests rather than only to whatever
        the orchestrator happened to wrap.
        """
        try:
            if self.driver is None:
                return sandbox.run(command, timeout_sec=timeout_sec)
            outcome = self.driver.run(
                worktree=sandbox.worktree_path,
                command=command,
                timeout_sec=timeout_sec,
                boundary=self.boundary,
            )
            return outcome.to_command_result()  # type: ignore[return-value]
        except OSError as error:
            if error.errno not in {errno.EAGAIN, errno.ENOMEM, errno.EMFILE, errno.ENFILE}:
                raise
            return CommandResult(
                command=" ".join(command), exit_code=125, stdout="",
                stderr="execution environment cannot allocate process resources", duration_ms=0,
                error_code="execution_environment_unavailable",
            )

    # --------------------------------------------------------------- entry point
    def run(
        self,
        *,
        step_id: str,
        execution_id: str,
        sandbox: GitSandbox,
        artifact: Artifact,
        subject_digest: str = "",
        elapsed_sec: float = 0.0,
        tokens_used: int = 0,
        acceptance_overrides: dict[str, Callable[[GitSandbox], CommandResult]] | None = None,
    ) -> Tier1Report:
        checks: list[CheckResult] = []
        advisories: list[str] = []
        diff = sandbox.diff()

        path_decision = self.guard.check_diff(diff.files, patch=diff.patch)
        checks.append(
            CheckResult(
                name="01_path_whitelist",
                passed=path_decision.allowed,
                detail="; ".join(path_decision.violations),
                evidence={"changed_files": list(diff.files)},
            )
        )
        advisories.extend(path_decision.advisories)

        checks.append(self._check_diff_sanity(diff))
        checks.append(self._check_dependency_pairing(diff.files))
        dependency_check = self._check_dependency_integrity(sandbox, diff.files)
        checks.append(dependency_check)
        checks.append(self._check_forbidden_files(diff.files))
        checks.append(self._check_secret_content(diff.patch))
        checks.append(self._check_schema(artifact))
        checks.extend(self._check_syntax(sandbox, diff.files))
        if dependency_check.passed:
            checks.append(self._check_linter(sandbox, diff.files))
            checks.append(self._check_types(sandbox, diff.files))
        checks.append(self._check_expected_artifacts(sandbox))
        checks.append(self._check_resources(elapsed_sec=elapsed_sec, tokens_used=tokens_used))
        if self.run_tests and not dependency_check.passed:
            checks.append(CheckResult(name="11_acceptance_criteria", passed=False,
                detail="acceptance commands were not run because dependency validation failed",
                evidence={"executed":False,"blocked_by":"03b_dependency_integrity"}))
        if self.run_tests and dependency_check.passed:
            checks.append(
                self._check_acceptance(sandbox, acceptance_overrides=acceptance_overrides)
            )

        failures = tuple(c for c in checks if not c.passed and c.severity == "error")
        decision = GateDecision.REVISE if failures else GateDecision.PASS
        reasons = tuple(f"{c.name}: {c.detail}" for c in failures)
        return Tier1Report(
            step_id=step_id,
            subject_digest=subject_digest,
            checks=tuple(checks),
            decision=decision,
            reasons=reasons,
            advisories=tuple(advisories),
        )

    # ------------------------------------------------------------------- checks
    def _check_diff_sanity(self, diff: Any) -> CheckResult:
        if diff.is_empty:
            return CheckResult(
                name="02_git_diff",
                passed=False,
                detail="the worktree produced no diff; an empty change set cannot be committed",
            )
        if len(diff.patch) > 2_000_000:
            return CheckResult(
                name="02_git_diff",
                passed=False,
                detail=f"patch is implausibly large ({len(diff.patch)} bytes)",
                evidence={"bytes": len(diff.patch)},
            )
        binary = [
            path
            for path in diff.files
            if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".so", ".dylib", ".bin"))
        ]
        if binary:
            return CheckResult(
                name="02_git_diff",
                passed=False,
                detail=f"binary artifacts are not reviewable and are refused: {binary}",
            )
        return CheckResult(
            name="02_git_diff",
            passed=True,
            detail="",
            evidence={
                "files": list(diff.files),
                "insertions": diff.insertions,
                "deletions": diff.deletions,
            },
        )

    def _check_dependency_integrity(self, sandbox: GitSandbox, files: Sequence[str]) -> CheckResult:
        from daedalus.application.dependencies import validate_dependencies, DependencyError
        try:
            evidence = validate_dependencies(boundary=self.boundary, changed_files=files,
                read=sandbox.read_file, cache=self.dependency_cache, worktree=sandbox.worktree_path)
            return CheckResult(name="03b_dependency_integrity", passed=True, evidence=evidence)
        except Exception as error:  # noqa: BLE001 - malformed dependencies must fail closed
            detail = error.message if isinstance(error, DependencyError) else "dependency input or cache is invalid: " + type(error).__name__
            return CheckResult(name="03b_dependency_integrity", passed=False, detail=detail,
                evidence={"downloads":0,"installed":False})

    def _check_dependency_pairing(self, files: Sequence[str]) -> CheckResult:
        decision = self.guard.check_dependency_change(list(files))
        if not decision.allowed:
            return CheckResult(
                name="03_dependency_pairing",
                passed=False,
                detail="; ".join(decision.violations),
            )
        changed_deps = [
            path
            for path in files
            if normalize_path(path).endswith(("requirements.txt", "pyproject.toml", "package.json"))
        ]
        return CheckResult(
            name="03_dependency_pairing",
            passed=True,
            detail="",
            evidence={"dependency_files_touched": changed_deps},
            severity="error",
        )

    def _check_forbidden_files(self, files: Sequence[str]) -> CheckResult:
        from daedalus.domain.pathglob import matches_any

        offenders = [path for path in files if matches_any(ALWAYS_DENIED_PATHS, path)]
        if offenders:
            return CheckResult(
                name="10_forbidden_files",
                passed=False,
                detail=f"forbidden files touched: {offenders}",
            )
        return CheckResult(name="10_forbidden_files", passed=True, detail="")

    def _check_secret_content(self, patch: str) -> CheckResult:
        """A change must not introduce a credential (Spec §8).

        Only the *added* lines are scanned, so a credential that already existed in a file does
        not block every attempt to edit that file. Introducing one is a leak into history, and
        history is not reversible here.
        """
        findings = scan_added_lines(patch)
        if findings:
            return CheckResult(
                name="12_secret_content",
                passed=False,
                detail=(
                    "the change adds what looks like a credential: "
                    + describe_findings(findings)
                    + ". Secrets must come from the environment through a capability grant."
                ),
                evidence={"findings": [f.describe() for f in findings]},
            )
        return CheckResult(name="12_secret_content", passed=True, detail="")

    def _check_schema(self, artifact: Artifact) -> CheckResult:
        try:
            self.goal.validate()
            self.boundary.validate()
            self.meta.validate()
        except Exception as error:  # noqa: BLE001 - reported, never raised
            return CheckResult(
                name="04_schema_validation",
                passed=False,
                detail=f"spec documents no longer validate: {error}",
            )
        return CheckResult(name="04_schema_validation", passed=True, detail="")

    def _check_syntax(self, sandbox: GitSandbox, files: Sequence[str]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for path in files:
            if not path.endswith(".py"):
                continue
            source = sandbox.read_file(path)
            if not source and not sandbox.exists(path):
                continue  # deletion
            try:
                ast.parse(source, filename=path)
            except SyntaxError as error:
                results.append(
                    CheckResult(
                        name="05_ast_syntax",
                        passed=False,
                        detail=f"{path}:{error.lineno}: {error.msg}",
                        evidence={"path": path, "line": error.lineno},
                    )
                )
        if not results:
            results.append(
                CheckResult(
                    name="05_ast_syntax",
                    passed=True,
                    detail="",
                    evidence={"checked": [p for p in files if p.endswith(".py")]},
                )
            )
        return results

    def _check_linter(self, sandbox: GitSandbox, files: Sequence[str]) -> CheckResult:
        declared = self._declared_tool("lint")
        if not declared:
            return CheckResult(
                name="06_linter",
                passed=True,
                detail="no linter declared by the project",
                severity="warning",
            )
        result = self._run(
            sandbox,
            self._tool_command(declared, files),
            timeout_sec=min(self.boundary.max_runtime_sec, 120),
        )
        return CheckResult(
            name="06_linter",
            passed=result.ok,
            detail="" if result.ok else result.combined(2000),
            evidence={"command": result.command, "exit_code": result.exit_code, "error_code": result.failure_code},
        )

    def _check_types(self, sandbox: GitSandbox, files: Sequence[str]) -> CheckResult:
        declared = self._declared_tool("typecheck")
        if not declared:
            return CheckResult(
                name="07_type_check",
                passed=True,
                detail="no type checker declared by the project",
                severity="warning",
            )
        result = self._run(
            sandbox,
            self._tool_command(declared, files),
            timeout_sec=min(self.boundary.max_runtime_sec, 180),
        )
        return CheckResult(
            name="07_type_check",
            passed=result.ok,
            detail="" if result.ok else result.combined(2000),
            evidence={"command": result.command, "exit_code": result.exit_code, "error_code": result.failure_code},
        )

    def _check_expected_artifacts(self, sandbox: GitSandbox) -> CheckResult:
        missing = [path for path in self.plan_node.expected_artifacts if not sandbox.exists(path)]
        if missing:
            return CheckResult(
                name="09_expected_artifacts",
                passed=False,
                detail=f"declared expected_artifacts are missing: {missing}",
                evidence={"missing": missing},
            )
        return CheckResult(
            name="09_expected_artifacts",
            passed=True,
            detail="",
            evidence={"present": list(self.plan_node.expected_artifacts)},
        )

    def _check_resources(self, *, elapsed_sec: float, tokens_used: int) -> CheckResult:
        token_decision = self.guard.check_token_budget(tokens_used)
        runtime_decision = self.guard.check_runtime(elapsed_sec)
        violations = [*token_decision.violations, *runtime_decision.violations]
        return CheckResult(
            name="08_resource_usage",
            passed=not violations,
            detail="; ".join(violations),
            evidence={"elapsed_sec": elapsed_sec, "tokens_used": tokens_used},
        )

    def _criteria(self) -> tuple[tuple[AcceptanceCriterion, ...], str]:
        """Node-scoped criteria when the node declares them, else the goal's set."""
        node_criteria = self.plan_node.acceptance_criteria
        if node_criteria:
            return node_criteria, "plan_node"
        return self.goal.acceptance_criteria, "goal"

    def _check_acceptance(
        self,
        sandbox: GitSandbox,
        *,
        acceptance_overrides: dict[str, Callable[[GitSandbox], CommandResult]] | None,
    ) -> CheckResult:
        overrides = acceptance_overrides or {}
        failed: list[str] = []
        executed: list[dict[str, Any]] = []
        criteria, source = self._criteria()

        for criterion in criteria:
            from daedalus.application.requirement_evidence import (
                execute_criterion,
                is_behavior,
            )
            behavior = is_behavior(criterion)
            if criterion.kind is AssertionKind.NATURAL_LANGUAGE and not behavior:
                executed.append(
                    {"criterion_id": criterion.criterion_id, "kind": "natural_language", "executed": False}
                )
                continue

            behavior_evidence = {}
            runner = overrides.get(criterion.criterion_id)
            if behavior:
                # Controller-owned evidence cannot be replaced by an acceptance override.
                result, behavior_evidence = execute_criterion(
                    sandbox, criterion, self.boundary, self.goal.objective, run=self._run)
            elif runner is not None:
                result = runner(sandbox)
            else:
                result = self._run_criterion(sandbox, criterion)

            executed.append(
                {
                    "criterion_id": criterion.criterion_id,
                    "kind": criterion.kind.value,
                    "command": criterion.command or criterion.path,
                    "exit_code": result.exit_code,
                    "duration_ms": result.duration_ms,
                    "ok": result.ok,
                    "error_code": result.failure_code,
                    **({"behavior_evidence": behavior_evidence} if behavior else {}),
                }
            )
            if not result.ok:
                failed.append(
                    f"{criterion.criterion_id} ({criterion.kind.value}) failed "
                    f"with exit code {result.exit_code}: "
                    f"{failure_excerpt(result.stdout + chr(10) + result.stderr)}"
                )
                if result.failure_code:
                    break

        goal_ids = {c.criterion_id for c in self.goal.acceptance_criteria}
        covered = {c.criterion_id for c in criteria}
        evidence = {
            "criteria": executed,
            "criteria_source": source,
            "goal_criteria_not_checked_here": sorted(goal_ids - covered),
            "error_code": next((item["error_code"] for item in executed if item.get("error_code")), ""),
        }
        if failed:
            return CheckResult(
                name="11_acceptance_criteria",
                passed=False,
                detail=" | ".join(failed),
                evidence=evidence,
            )
        return CheckResult(
            name="11_acceptance_criteria", passed=True, detail="", evidence=evidence
        )

    def _run_criterion(self, sandbox: GitSandbox, criterion: AcceptanceCriterion) -> CommandResult:
        timeout = min(self.boundary.max_runtime_sec, 120)

        if criterion.kind is AssertionKind.EXPECTED_FILE:
            exists = sandbox.exists(criterion.path)
            expect = criterion.expect if criterion.expect is not None else True
            ok = exists == bool(expect)
            return CommandResult(
                command=f"expected_file {criterion.path}",
                exit_code=0 if ok else 1,
                stdout=f"exists={exists}",
                stderr="" if ok else f"expected {criterion.path} to exist={expect}",
                duration_ms=0,
            )

        if criterion.kind is AssertionKind.FILE_CONTENT:
            actual = sandbox.read_file(criterion.path)
            expect = criterion.expect
            if isinstance(expect, list):
                missing = [item for item in expect if str(item) not in actual]
                ok = not missing
                stderr = "" if ok else f"missing expected content: {missing}"
            else:
                ok = str(expect) in actual
                stderr = "" if ok else f"expected content {expect!r} not found in {criterion.path}"
            return CommandResult(
                command=f"file_content {criterion.path}",
                exit_code=0 if ok else 1,
                stdout=f"bytes={len(actual)}",
                stderr=stderr,
                duration_ms=0,
            )

        if criterion.kind is AssertionKind.AST_PROPERTY:
            source = sandbox.read_file(criterion.path)
            try:
                tree = ast.parse(source, filename=criterion.path)
            except SyntaxError as error:
                return CommandResult(
                    command=f"ast_property {criterion.path}",
                    exit_code=1,
                    stdout="",
                    stderr=f"syntax error: {error}",
                    duration_ms=0,
                )
            expect = criterion.expect if isinstance(criterion.expect, dict) else {}
            names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
            problems: list[str] = []
            for required in expect.get("defines", ()):
                if required not in names:
                    problems.append(f"missing definition {required!r}")
            for banned in expect.get("forbids", ()):
                if banned in names:
                    problems.append(f"forbidden definition {banned!r}")
            for module in expect.get("imports", ()):
                if module not in imported:
                    problems.append(f"missing import {module!r}")
            for module in expect.get("imports_forbidden", ()):
                if module in imported:
                    problems.append(f"forbidden import {module!r}")
            return CommandResult(
                command=f"ast_property {criterion.path}",
                exit_code=1 if problems else 0,
                stdout=json.dumps({"definitions": sorted(names), "imports": sorted(imported)}),
                stderr="; ".join(problems),
                duration_ms=0,
            )

        if not criterion.command:
            return CommandResult(
                command=f"{criterion.kind.value} <no command>",
                exit_code=1,
                stdout="",
                stderr=f"{criterion.criterion_id}: no command declared",
                duration_ms=0,
            )

        result = self._run(sandbox, ["/bin/sh", "-c", criterion.command], timeout_sec=timeout)
        if criterion.expect is not None and result.exit_code == 0:
            expected = criterion.expect
            if isinstance(expected, int) and result.exit_code != expected:
                return CommandResult(
                    command=result.command,
                    exit_code=1,
                    stdout=result.stdout,
                    stderr=f"expected exit code {expected}",
                    duration_ms=result.duration_ms,
                )
        return result

    # ------------------------------------------------------------------ helpers
    def _declared_tool(self, kind: str) -> str:
        value = self.plan_node.extra.get(kind) if self.plan_node.extra else None
        return str(value) if value else ""

    def _tool_command(self, declared: str, files: Sequence[str]) -> list[str]:
        parts = declared.split()
        if parts and parts[0] in {"python", "python3"}:
            parts[0] = self.python_executable
        return parts
