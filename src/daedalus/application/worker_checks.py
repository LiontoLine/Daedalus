"""Bounded diagnostic execution of frozen Tier-1 assertions, never approval."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from daedalus.application.gatekeeper.tier1 import Tier1Gate
from daedalus.application.requirement_evidence import (
    MAX_CHECKS,
    failed_behavior_source_hint,
    is_behavior,
    public_behavior_paths,
)
from daedalus.domain.canonical import digest_of
from daedalus.domain.spec import AssertionKind
from daedalus.errors import DaedalusError
from daedalus.infrastructure.process import command_output_excerpt
from daedalus.infrastructure.redact import REDACTED
from daedalus.infrastructure.sandbox import DriverRegistry
from daedalus.security.outbound import SecretInPayload, assert_outbound_clean

MAX_CHECK_OUTPUT_CHARS = 3600
MAX_CHECK_RECEIPTS = 8


@dataclass(frozen=True, slots=True)
class CheckRequest:
    criterion_id: str
    gap: str

    @classmethod
    def parse(cls, payload: dict) -> CheckRequest:
        if not isinstance(payload, dict) or payload.get("action") != "check":
            raise ValueError("check request must be an action=check object")
        if set(payload) - {"action", "criterion_id", "gap", "operations"}:
            raise ValueError("check requests cannot supply commands, edits or other actions")
        if payload.get("operations", []) != []:
            raise ValueError("check requests cannot include edits")
        criterion_id, gap = payload.get("criterion_id"), payload.get("gap")
        if not isinstance(criterion_id, str) or not 0 < len(criterion_id) <= 240:
            raise ValueError("check requires an exact bounded criterion ID")
        if not isinstance(gap, str) or not 0 < len(gap.strip()) <= 240:
            raise ValueError("check requires an evidence gap up to 240 characters")
        assert_outbound_clean(json.dumps(payload, ensure_ascii=False), where="coding check request")
        return cls(criterion_id, gap.strip())

    @property
    def identity(self) -> str:
        # An explanation is not a new check of the same subject.
        return digest_of({"criterion_id": self.criterion_id})


@dataclass(frozen=True, slots=True)
class CheckObservation:
    content: str
    receipt: dict
    behavior_source_hint: str = ""
    failed_behavior_paths: tuple[str, ...] = ()


@dataclass
class DeclaredCheckRunner:
    """Use the normal isolation selector and Tier-1 policy, without running a gate.

    Registry and dependency cache are controller-owned configuration, never model
    arguments. There is no direct-execution fallback when selection fails.
    """

    dependency_cache: Path | None = None
    registry: DriverRegistry | None = None

    def __call__(self, sandbox, context, request: CheckRequest) -> CheckObservation:
        request = CheckRequest.parse({"action": "check", "criterion_id": request.criterion_id,
                                      "gap": request.gap})
        receipt = {
            "version": 1, "execution_id": context.execution_id, "step_id": context.step_id,
            "attempt": context.attempt, "node_id": context.node.node_id,
            "criterion_id": request.criterion_id, "request_digest": request.identity,
            "spec_digest": context.bundle.digest(), "criterion_digest": "",
            "tree_digest": "", "after_tree_digest": "", "commit": "",
            "base_commit": sandbox.base_commit,
            "output_digest_scope": "diagnostic_message",
            "criteria_source": "", "driver": "", "isolation": {},
            "passed": False, "executed": False, "error_code": "",
        }
        output = ""
        try:
            gate = Tier1Gate(goal=context.bundle.goal, plan_node=context.node,
                             boundary=context.bundle.boundary, meta=context.bundle.meta,
                             dependency_cache=self.dependency_cache,
                             deadline_monotonic=getattr(context, "deadline_monotonic", 0.0))
            criteria, source = gate._criteria()
            matches = [c for c in criteria if c.criterion_id == request.criterion_id]
            receipt["criteria_source"] = source
            if len(matches) != 1:
                receipt["error_code"] = "invalid_edit_plan"
                return self._observation(receipt, "criterion ID is not uniquely declared for this node")
            criterion = matches[0]
            definition = criterion.to_dict()
            assert_outbound_clean(json.dumps(definition, ensure_ascii=False),
                                  where="frozen check definition")
            receipt["criterion_digest"] = digest_of(definition)
            receipt["tree_digest"] = sandbox.tree_digest()
            receipt["commit"] = sandbox.head()
            if criterion.kind is AssertionKind.NATURAL_LANGUAGE and not is_behavior(criterion):
                receipt["error_code"] = "invalid_edit_plan"
                return self._observation(receipt, "criterion has no deterministic assertion")
            # File assertions must not turn a repository path into a host read.
            if criterion.path:
                resolved = sandbox.resolve_inside(criterion.path)
                relative = resolved.relative_to(sandbox.worktree_path.resolve()).as_posix()
                if relative != criterion.path or (resolved.exists() and not resolved.is_file()):
                    receipt["error_code"] = "boundary_violation"
                    return self._observation(receipt, "criterion path is not a regular repository file")
            deadline = getattr(context, "deadline_monotonic", 0.0)
            if deadline and deadline <= time.monotonic():
                receipt["error_code"] = "execution_environment_unavailable"
                return self._observation(receipt, "shared node deadline expired before check execution")
            preconditions = gate.declared_check_preconditions(sandbox, criterion)
            failures = [check for check in preconditions if not check.passed]
            if failures:
                check = failures[0]
                receipt["blocked_by"] = check.name
                receipt["error_code"] = check.evidence.get("error_code") or {
                    "03_dependency_pairing": "dependency_validation_error",
                    "03b_dependency_integrity": "dependency_validation_error",
                    "12_secret_content": "secret_in_payload",
                }.get(check.name, "boundary_violation")
                # Scan every prerequisite result, not just the first displayed failure.
                assert_outbound_clean(json.dumps([c.to_payload() for c in preconditions]),
                                      where="check prerequisite evidence")
                return self._observation(receipt, check.detail)
            choice = (self.registry or DriverRegistry.default()).select(
                context.bundle.boundary, requested=context.bundle.boundary.isolation)
            gate.driver = choice.driver
            receipt.update(driver=choice.report.driver, isolation=choice.describe())
            result, evidence = gate.run_declared_criterion(sandbox, criterion)
            complete = not is_behavior(criterion) or evidence.get("receipt", {}).get("complete") is True
            receipt.update(executed=complete, exit_code=result.exit_code, timed_out=result.timed_out,
                           duration_ms=result.duration_ms, error_code=result.failure_code)
            if receipt["error_code"] in {"execution_environment_unavailable", "isolation_unavailable",
                                         "spec_digest_mismatch"}:
                receipt["executed"] = False
            if (not receipt["error_code"] and result.exit_code in {126, 127}
                    and re.search(r"(?im)^(?:[^\n]*[/ ])?(?:sh|bash|dash|zsh):.*"
                                  r"(?:not found|permission denied|cannot execute)", result.stderr)):
                receipt.update(executed=False, error_code="execution_environment_unavailable")
            if result.timed_out and not receipt["error_code"]:
                receipt["error_code"] = "execution_environment_unavailable"
            receipt["after_tree_digest"] = sandbox.tree_digest()
            unchanged = (receipt["tree_digest"] == receipt["after_tree_digest"]
                         and receipt["commit"] == sandbox.head()
                         and receipt["base_commit"] == sandbox.base_commit)
            if not unchanged:
                receipt["error_code"] = "spec_digest_mismatch"
                receipt["subject_changed"] = True
            receipt["passed"] = bool(result.ok and not receipt["error_code"] and unchanged)
            # Drivers redact before returning. Scan the complete returned data,
            # conservatively refusing their marker rather than claiming raw coverage.
            full = {"stdout": result.stdout, "stderr": result.stderr,
                    "command": result.command, "evidence": evidence, "receipt": receipt}
            returned = json.dumps(full, ensure_ascii=False)
            output = result.stdout + ("\n" if result.stdout and result.stderr else "") + result.stderr
            receipt.update(output_digest=digest_of(output), output_chars=len(output),
                           output_truncated=len(output) > MAX_CHECK_OUTPUT_CHARS,
                           output_digest_scope="full_driver_returned_redacted_output",
                           evidence_digest=digest_of(full))
            assert_outbound_clean(returned, where="coding check full returned evidence")
            if REDACTED in returned:
                raise SecretInPayload("check returned a recognized redaction marker")
        except SecretInPayload:
            receipt.update(passed=False, error_code="secret_in_payload")
            output = "check evidence contains sensitive content; no output may be sent"
        except DaedalusError as error:
            receipt.update(passed=False, error_code=error.code)
            output = "check blocked by " + error.code
        except (OSError, RuntimeError):
            receipt.update(passed=False, error_code="execution_environment_unavailable")
            output = "check execution environment is unavailable"
        except (ValueError, KeyError, TypeError):
            receipt.update(passed=False, error_code="spec_digest_mismatch")
            output = "frozen check evidence is unavailable or invalid"
        # Full returned evidence was scanned above; do not scan the same large log twice.
        # Original digest/size/truncation metadata remain in the receipt.
        behavior = (
            evidence.get("receipt")
            if receipt["executed"] and not receipt["error_code"]
            else None
        )
        paths = public_behavior_paths(criterion.expect["behavior_contract"], behavior) if (
            behavior and behavior["reviewed_tree"] == receipt["tree_digest"]
            and behavior["reviewed_commit"] == receipt["commit"]
        ) else []
        if paths:
            receipt["behavior_path_evidence"] = {
                "receipt_sha256": behavior["sha256"],
                "outcomes": {path["id"]: path["status"] == "MET" for path in paths},
            }
            # Requirements and roles are already in the frozen prompt. Keep each
            # measured path and the native receipt together in a bounded JSON value.
            output = json.dumps({
                "receipt": {key: behavior[key] for key in (
                    "sha256", "complete", "passed", "executed", "reviewed_tree", "reviewed_commit",
                )},
                "behavior_paths": [
                    {"path_id": path["id"], "status": path["status"]} for path in paths
                ],
            }, ensure_ascii=False, separators=(",", ":"))
        return self._observation(
            receipt, command_output_excerpt(output, MAX_CHECK_OUTPUT_CHARS),
            behavior_source_hint=failed_behavior_source_hint(paths),
            failed_behavior_paths=tuple(path["id"] for path in paths if path["status"] == "UNMET"),
        )

    @staticmethod
    def _observation(
        receipt: dict, output: str, *, behavior_source_hint: str = "",
        failed_behavior_paths: tuple[str, ...] = (),
    ) -> CheckObservation:
        # Receipt metadata is outbound too, including driver probe diagnostics.
        assert_outbound_clean(json.dumps({"receipt": receipt, "output": output}, ensure_ascii=False),
                              where="coding check observation")
        receipt = {**receipt, "output_digest": receipt.get("output_digest", digest_of(output)),
                   "output_chars": receipt.get("output_chars", len(output)),
                   "output_truncated": receipt.get(
                       "output_truncated", len(output) > MAX_CHECK_OUTPUT_CHARS),
                   "approval": False}
        # The controller keeps the full receipt. The model needs the actual assertion
        # and its binding, not repeated isolation-probe narratives before the failure.
        binding = {key: receipt[key] for key in (
            "criterion_id", "criterion_digest", "spec_digest", "tree_digest",
            "after_tree_digest", "passed", "executed", "error_code", "exit_code",
            "timed_out", "subject_changed", "blocked_by",
        ) if key in receipt}
        content = json.dumps({
            "untrusted_check_observation": True,
            "output": command_output_excerpt(output, MAX_CHECK_OUTPUT_CHARS),
            "receipt": binding,
        }, ensure_ascii=False)
        return CheckObservation(content, receipt, behavior_source_hint, failed_behavior_paths)


def safe_check_receipts(extra: dict) -> list[dict]:
    """Whitelist bounded controller metadata; never persist native output or extras."""
    if not isinstance(extra, dict) or not isinstance(extra.get("check_receipts", []), list):
        return []
    result = []
    text_fields = ("execution_id", "step_id", "node_id", "criterion_id")
    sha_fields = ("request_digest", "spec_digest", "criterion_digest",
                  "output_digest", "evidence_digest")
    tree_fields = ("tree_digest", "after_tree_digest", "commit", "base_commit")
    optional = ("blocked_by", "exit_code", "duration_ms", "timed_out", "subject_changed")
    for row in extra.get("check_receipts", [])[:MAX_CHECK_RECEIPTS]:
        if not isinstance(row, dict) or row.get("version") != 1:
            continue
        if any(not isinstance(row.get(k), str) or not 0 < len(row[k]) <= 240
               for k in text_fields):
            continue
        if type(row.get("attempt")) is not int or row["attempt"] < 1:
            continue
        if any(type(row.get(k)) is not bool for k in ("passed", "executed", "output_truncated")):
            continue
        if row.get("approval") is not False:
            continue
        if any(not isinstance(row.get(k, ""), str)
               or (row.get(k) and not re.fullmatch(r"[0-9a-f]{64}", row[k]))
               for k in sha_fields):
            continue
        if not all(row.get(k) for k in ("request_digest", "spec_digest", "output_digest")):
            continue
        if any(not isinstance(row.get(k, ""), str)
               or (row.get(k) and not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", row[k]))
               for k in tree_fields):
            continue
        if any(not isinstance(row.get(k), str)
               for k in ("driver", "criteria_source", "output_digest_scope")):
            continue
        if (row.get("request_digest") != digest_of({"criterion_id": row["criterion_id"]})
                or row.get("driver") not in {"", "host-process", "seatbelt", "container"}
                or row.get("criteria_source") not in {"goal", "plan_node"}
                or not isinstance(row.get("error_code"), str)
                or not re.fullmatch(r"[a-z_]{0,80}", row["error_code"])
                or type(row.get("output_chars")) is not int or row["output_chars"] < 0
                or row.get("output_digest_scope") not in {
                    "diagnostic_message", "full_driver_returned_redacted_output"}):
            continue
        if row["passed"] and (not row["executed"] or row["error_code"]
                              or not row.get("criterion_digest") or not row.get("tree_digest")
                              or row["tree_digest"] != row.get("after_tree_digest")):
            continue
        if any(k in row and (type(row[k]) is not int) for k in ("exit_code", "duration_ms")):
            continue
        if any(k in row and type(row[k]) is not bool for k in ("timed_out", "subject_changed")):
            continue
        if "blocked_by" in row and (
                not isinstance(row["blocked_by"], str) or len(row["blocked_by"]) > 80):
            continue
        keys = (*text_fields, *sha_fields, *tree_fields, *optional, "version", "attempt",
                "passed", "executed", "error_code", "output_chars", "output_truncated",
                "output_digest_scope", "criteria_source", "driver", "approval")
        value = {key: row[key] for key in keys if key in row}
        behavior = row.get("behavior_path_evidence")
        if (isinstance(behavior, dict) and row["executed"] and not row["error_code"]
                and row["output_digest_scope"] == "full_driver_returned_redacted_output"
                and row.get("evidence_digest") and row.get("criterion_digest")
                and row.get("tree_digest") and row["tree_digest"] == row.get("after_tree_digest")):
            sha, outcomes = behavior.get("receipt_sha256"), behavior.get("outcomes")
            if (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)
                    and isinstance(outcomes, dict) and 1 <= len(outcomes) <= MAX_CHECKS
                    and all(isinstance(key, str) and re.fullmatch(r"[A-Za-z][\w-]{0,63}", key)
                            and type(passed) is bool for key, passed in outcomes.items())
                    and all(outcomes.values()) is row["passed"]):
                value["behavior_path_evidence"] = {"receipt_sha256": sha, "outcomes": dict(outcomes)}
        assert_outbound_clean(json.dumps(value), where="coding check receipt metadata")
        result.append(value)
    return result


def observed_behavior_paths(
    check: dict, criterion, *, spec_digest: str, commit: str, tree: str,
) -> dict | None:
    """Project a sanitized check receipt only for its exact tested subject."""
    observed = check.get("behavior_path_evidence")
    if (not observed or check["criterion_id"] != criterion.criterion_id
            or check["spec_digest"] != spec_digest or check.get("commit") != commit
            or check.get("tree_digest") != tree
            or check.get("criterion_digest") != digest_of(criterion.to_dict())):
        return None
    expect = criterion.expect
    contract = expect.get("behavior_contract") if isinstance(expect, dict) else None
    if not isinstance(contract, dict):
        return None
    declared = contract.get("behavior_paths", ())
    outcomes = observed["outcomes"]
    if outcomes.keys() != {path["id"] for path in declared}:
        return None
    return {
        "criterion_id": criterion.criterion_id,
        "receipt_sha256": observed["receipt_sha256"],
        "paths": [{"path_id": path["id"], "requirement_id": path["requirement_id"],
                   "role": path["role"], "status": "MET" if outcomes[path["id"]] else "UNMET"}
                  for path in declared],
    }
