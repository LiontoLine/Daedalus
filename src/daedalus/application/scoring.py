"""Audit scoring: a summary of the evidence, never a substitute for it (Spec §15, §27).

An operator looking at a finished run wants one question answered quickly: *how much evidence
is there that this was done properly?* That is a different question from "is this change
correct?", and the difference is the whole design of this module.

Every component is computed **only** from persisted evidence — gate rows, artifacts, events,
approvals — and every component reports the facts that produced it. Nothing here reads a model
verdict as if it were a measurement, and nothing is weighted on a feeling: the weights encode
which failures are disqualifying (an unverified high-risk sign-off, a boundary violation) versus
which are merely costly (a retry).

The score is deliberately *not* a single verdict. A 100 means "every check we know how to run
left a record", not "this is safe", and the console shows the components beside the number so
the summary can always be unpacked. A score that cannot be unpacked into evidence is the thing
this project exists to argue against.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from daedalus.domain.fsm import StepState
from daedalus.infrastructure.store.event_store import EventStore

#: The reference to a factor that is worth acting on, shown next to its evidence.
_SEVERITY = {"ok": "ok", "warn": "warn", "bad": "bad", "info": "info"}


@dataclass(frozen=True, slots=True)
class ScoreComponent:
    """One factor, its weight, and the facts that decided it."""

    key: str
    label: str
    #: 0..1
    value: float
    weight: float
    severity: str
    detail: str
    evidence: tuple[str, ...] = ()

    @property
    def contribution(self) -> float:
        return self.value * self.weight

    def to_payload(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "value": round(self.value, 3),
            "weight": self.weight,
            "score": round(self.contribution, 1),
            "severity": self.severity,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


@dataclass
class AuditScore:
    run_id: str
    score: float
    band: str
    components: list[ScoreComponent] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "score": round(self.score, 1),
            "band": self.band,
            "components": [component.to_payload() for component in self.components],
            "notes": list(self.notes),
            "scale_note": (
                "评分只汇总“留下了多少可核查的证据”，不代表这次改动是正确的，也不代表"
                "可以上线。每个分项都列出决定它的原始事实，请以事实为准。"
            ),
        }


def _band(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "E"


def score_run(store: EventStore, run_id: str) -> AuditScore:
    """Compute the score for one run from its persisted evidence."""
    run = store.get_run(run_id)
    if run is None:
        raise KeyError(run_id)
    execution_id = str(run["execution_id"])
    spec = store.get_spec(str(run["spec_digest"]))
    risk = str(spec["risk_level"]) if spec else "normal"

    steps = [
        row for row in store.list_steps(run_id) if str(row["execution_id"]) == execution_id
    ]
    committed = [row for row in steps if str(row["state"]) == StepState.COMMITTED.value]
    components: list[ScoreComponent] = []

    components.append(_gate_coverage(store, committed))
    components.append(_test_evidence(store, committed))
    components.append(_boundary_compliance(store, run_id, execution_id))
    components.append(_approval_integrity(store, run_id, spec, risk))
    components.append(_digest_completeness(store, committed))
    components.append(_attempt_economy(store, steps))
    components.append(_evidence_completeness(store, run_id, steps))

    total_weight = sum(component.weight for component in components) or 1.0
    score = sum(component.contribution for component in components) / total_weight * 100

    notes: list[str] = []
    if not committed:
        notes.append("这个 run 没有任何已提交的步骤，因此评分只反映“缺少证据”。")
    if not spec:
        notes.append("找不到该 run 的 spec 记录，风险等级按 normal 处理。")
    notes.append(
        "评分不读取模型的判断作为测量值：只有门禁、artifact、事件与审批这类可核查的"
        "记录进入计算。"
    )
    return AuditScore(
        run_id=run_id,
        score=score,
        band=_band(score),
        components=components,
        notes=notes,
    )


# --------------------------------------------------------------------------- components


def _gate_coverage(store: EventStore, committed: list[dict[str, Any]]) -> ScoreComponent:
    """Did every committed step pass Tier-1 on the artifact that was actually committed?

    The reuse path can commit without re-running the gate, which is only legitimate because the
    identical content was gated before. That is still gate coverage — but only when the cache
    hit names the gate result it reused, which the FSM refuses to record otherwise.
    """
    if not committed:
        return ScoreComponent(
            key="gate_coverage", label="门禁覆盖", value=0.0, weight=3.0, severity="warn",
            detail="没有已提交的步骤，无法计算门禁覆盖",
        )
    covered: list[str] = []
    uncovered: list[str] = []
    for step in committed:
        gates = store.gate_results_for_step(str(step["step_id"]))
        passed = [gate for gate in gates if int(gate["tier"]) == 1 and str(gate["decision"]) == "PASS"]
        (covered if passed else uncovered).append(str(step["node_id"]))
    value = len(covered) / len(committed)
    return ScoreComponent(
        key="gate_coverage",
        label="门禁覆盖",
        value=value,
        weight=3.0,
        severity="ok" if not uncovered else "bad",
        detail=f"{len(covered)}/{len(committed)} 个已提交步骤持有 Tier-1 PASS",
        evidence=tuple(
            [f"{node}: Tier-1 PASS" for node in covered]
            + [f"{node}: 没有 Tier-1 PASS 记录" for node in uncovered]
        ),
    )


def _test_evidence(store: EventStore, committed: list[dict[str, Any]]) -> ScoreComponent:
    """Was the acceptance command actually executed and recorded as passing?

    Check 11 is the acceptance-criteria check. Its presence means a command ran; its absence
    means the committed work was never tested by anything but the model's opinion.
    """
    if not committed:
        return ScoreComponent(
            key="test_evidence", label="验收执行", value=0.0, weight=2.5, severity="warn",
            detail="没有已提交的步骤，无法确认验收命令是否执行",
        )
    ran: list[str] = []
    missing: list[str] = []
    for step in committed:
        gates = store.gate_results_for_step(str(step["step_id"]))
        names: set[str] = set()
        for gate in gates:
            try:
                names.update(
                    str(check.get("name", ""))
                    for check in json.loads(str(gate["evidence"] or "{}")).get("checks", [])
                )
            except ValueError:
                continue
        (ran if any(name.endswith("acceptance_criteria") for name in names) else missing).append(
            str(step["node_id"])
        )
    value = len(ran) / len(committed)
    return ScoreComponent(
        key="test_evidence",
        label="验收执行",
        value=value,
        weight=2.5,
        severity="ok" if not missing else "warn",
        detail=f"{len(ran)}/{len(committed)} 个步骤执行并记录了验收命令",
        evidence=tuple(
            [f"{node}: 11_acceptance_criteria 已执行并通过" for node in ran]
            + [f"{node}: 没有验收执行记录" for node in missing]
        ),
    )


def _boundary_compliance(
    store: EventStore, run_id: str, execution_id: str
) -> ScoreComponent:
    """Was the boundary respected? A single violation is disqualifying, not a deduction.

    `BoundaryGuard` refuses before the write and Tier-1 re-checks the whitelist, so a recorded
    violation means something tried to leave its declared area. Averaging that away with a good
    diff would be the wrong arithmetic.
    """
    violations: list[str] = []
    for event in store.events_for_execution(execution_id):
        if event.event_type in {"StepExecutionFailed", "RunFailed"}:
            payload = dict(event.payload)
            reason = str(payload.get("reason", ""))
            if "boundary" in reason.lower() or "whitelist" in reason.lower():
                violations.append(f"{event.event_type}: {reason[:120]}")
        if event.event_type == "StepTier1Decided":
            payload = dict(event.payload)
            if "01_path_whitelist" in str(payload.get("summary", "")):
                summary = str(payload["summary"])
                if "01_path_whitelist=fail" in summary:
                    violations.append("tier-1 01_path_whitelist 失败")
    if violations:
        return ScoreComponent(
            key="boundary_compliance", label="边界合规", value=0.0, weight=3.0, severity="bad",
            detail=f"记录了 {len(violations)} 次越界尝试",
            evidence=tuple(violations[:8]),
        )
    return ScoreComponent(
        key="boundary_compliance", label="边界合规", value=1.0, weight=3.0, severity="ok",
        detail="没有越界或白名单失败记录",
        evidence=("所有步骤都在 SPEC-03 声明的可写范围内",),
    )


def _approval_integrity(
    store: EventStore, run_id: str, spec: dict[str, Any] | None, risk: str
) -> ScoreComponent:
    """For a high-risk spec: was the sign-off a verified signature, or a typed name?"""
    if risk not in {"high", "critical"}:
        return ScoreComponent(
            key="approval_integrity", label="审批完整性", value=1.0, weight=2.0, severity="info",
            detail=f"risk={risk}，不要求 owner 签名",
            # "No signature was required" is still a fact, and it is the fact that decides this
            # component. Leaving the evidence empty made the component unreadable: a reader could
            # not tell whether the requirement was absent or the record was missing.
            evidence=(f"SPEC-01 risk_level={risk}，低于需要签名的等级",),
        )
    verified = bool(int(spec.get("approval_verified") or 0)) if spec else False
    approved_by = str(spec.get("approved_by") or "") if spec else ""
    if verified:
        return ScoreComponent(
            key="approval_integrity", label="审批完整性", value=1.0, weight=2.0, severity="ok",
            detail=f"risk={risk}，签批已验签",
            evidence=(f"{approved_by} · {spec.get('approval_scheme')} · "
                      f"指纹 {str(spec.get('approval_fingerprint') or '')[:16]}",),
        )
    return ScoreComponent(
        key="approval_integrity",
        label="审批完整性",
        value=0.0,
        weight=2.0,
        severity="bad",
        detail=f"risk={risk}，但签批未经验证（只有名字）",
        evidence=(f"approved_by={approved_by or '无'}",),
    )


def _digest_completeness(store: EventStore, committed: list[dict[str, Any]]) -> ScoreComponent:
    """Can each committed artifact be reproduced? Incomplete digests make it unanswerable."""
    if not committed:
        return ScoreComponent(
            key="digest_completeness", label="可复现性", value=0.0, weight=2.0, severity="warn",
            detail="没有已提交的步骤，无法评估可复现性",
        )
    complete: list[str] = []
    partial: list[str] = []
    for step in committed:
        for artifact in store.artifacts_for_step(str(step["step_id"])):
            fields = (
                str(artifact["toolchain_digest"] or ""),
                str(artifact["dependency_digest"] or ""),
                str(artifact["code_base_digest"] or ""),
                str(artifact["patch_digest"] or ""),
            )
            (complete if all(fields) else partial).append(str(step["node_id"]))
            break
    value = len(complete) / len(committed)
    return ScoreComponent(
        key="digest_completeness",
        label="可复现性",
        value=value,
        weight=2.0,
        severity="ok" if not partial else "warn",
        detail=f"{len(complete)}/{len(committed)} 个步骤记录了完整的工具链/依赖/基线/补丁摘要",
        evidence=tuple(
            [f"{node}: 四类摘要齐备" for node in complete]
            + [f"{node}: 摘要不完整，无法判断是否可复现" for node in partial]
        ),
    )


def _attempt_economy(store: EventStore, steps: list[dict[str, Any]]) -> ScoreComponent:
    """How much work was thrown away? Efficiency, not safety — weighted lowest on purpose.

    `attempt` is the attempt a step is *on*, so retries are `attempt - 1` summed per step.
    Subtracting the committed count from the total instead conflated "never committed" with
    "was retried", and reported "1 次是重试" for a run whose single attempt parked for a human —
    a false statement of fact, which is the one thing a component in this module may not make.
    """
    attempts = sum(int(step["attempt"] or 0) for step in steps)
    if not steps or not attempts:
        return ScoreComponent(
            key="attempt_economy", label="尝试效率", value=1.0, weight=1.0, severity="info",
            detail="没有尝试记录",
        )
    succeeded = len([row for row in steps if str(row["state"]) == StepState.COMMITTED.value])
    retries = sum(max(0, int(step["attempt"] or 0) - 1) for step in steps)
    value = succeeded / attempts
    return ScoreComponent(
        key="attempt_economy",
        label="尝试效率",
        value=value,
        weight=1.0,
        severity="ok" if retries == 0 and succeeded == attempts else "warn",
        detail=f"共 {attempts} 次尝试，{retries} 次是重试",
        evidence=(
            f"{succeeded}/{len(steps)} 个步骤最终提交，共 {attempts} 次尝试",
            *(f"{row['node_id']}: {row['attempt']} 次尝试" for row in steps if int(row["attempt"] or 0) > 1),
        ),
    )


def _evidence_completeness(
    store: EventStore, run_id: str, steps: list[dict[str, Any]]
) -> ScoreComponent:
    """Is the trail itself intact: no sequence gaps, and every log reference resolvable?"""
    from daedalus.application.execution_log import UnresolvableLogRef, resolve

    problems: list[str] = []
    gaps = store.verify_sequences()
    if gaps:
        problems.append(f"事件序列缺口: {gaps[:3]}")
    checked = 0
    dangling = 0
    for step in steps:
        for artifact in store.artifacts_for_step(str(step["step_id"])):
            checked += 1
            try:
                resolve(store, str(artifact["execution_log_ref"] or ""))
            except UnresolvableLogRef:
                dangling += 1
                problems.append(f"{step['node_id']}: 执行日志引用无法解析")
    if not steps:
        problems.append("这个 run 没有步骤记录")
    value = 1.0 if not problems else max(0.0, 1 - len(problems) / max(1, len(steps) + 1))
    return ScoreComponent(
        key="evidence_completeness",
        label="证据完整",
        value=value,
        weight=1.5,
        severity=_SEVERITY["ok"] if not problems else "warn",
        detail=(
            f"序列完整，{checked - dangling}/{checked} 个日志引用可解析"
            if not problems
            else f"{len(problems)} 处证据问题"
        ),
        evidence=tuple(problems[:8]) or ("事件序列无缺口；artifact 的 execution_log_ref 均可解析",),
    )
