"""Planning: turn a human request into a frozen Tri-Spec (Spec §2, §23).

Two planners exist and they share one output contract:

`DeterministicPlanner` builds the spec from declared facts — target paths, the test
command, the risk level. It has no model in the loop, which is what makes the Phase-1
end-to-end demo reproducible and what makes the gate tests trustworthy.

`ModelPlanner` asks a model for a *candidate* spec. The candidate is parsed into the
same types, validated by the same `SpecBundle.validate()` and then clamped by
`SpecHardening` before it is ever registered. A model may propose a plan; it may not
decide what it is allowed to touch.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol

from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import utc_now
from daedalus.domain.spec import (
    AcceptanceCriterion,
    AssertionKind,
    BoundarySpec,
    GoalSpec,
    MetaSpec,
    NetworkPolicy,
    PlanNode,
    PlanSpec,
    RiskLevel,
    RetryPolicy,
    SpecBundle,
)
from daedalus.errors import ModelError, SpecError
from daedalus.model.base import Message, ModelClient, TokenBudget
from daedalus.security.boundary import ALWAYS_DENIED_PATHS
from daedalus.security.outbound import SecretInPayload, assert_outbound_clean

DEFAULT_PROTECTED = MetaSpec.default().protected_paths

#: Paths the planner is always forbidden from handing to an agent, regardless of what
#: the model asked for. This is the Meta-Spec applied to planning.
NON_NEGOTIABLE_DENY = (
    *ALWAYS_DENIED_PATHS,
    "**/.env*",
    "**/secrets/**",
)


@dataclass(frozen=True, slots=True)
class PlanRequest:
    """Everything the planner needs, with no hidden model context."""

    request_id: str
    goal_id: str
    objective: str
    target_paths: tuple[str, ...]
    test_command: str
    risk_level: RiskLevel = RiskLevel.NORMAL
    invariants: tuple[str, ...] = ()
    acceptance_criteria: tuple[AcceptanceCriterion, ...] = ()
    dependency_manifest: str = ""
    lock_file: str = ""
    network_policy: NetworkPolicy = NetworkPolicy.DENY
    max_runtime_sec: int = 300
    max_tokens_per_step: int = 20_000
    owner_id: str = "owner"
    extra_context: str = ""


class Planner(Protocol):
    name: str

    def plan(self, request: PlanRequest) -> SpecBundle: ...


# ---------------------------------------------------------------------------
# Deterministic planner
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResourceBounds:
    """Operator ceilings that no spec may exceed (Spec §2.3, §6.4).

    SPEC-03 is authored by the model in the `ModelPlanner` path, so without an operator
    ceiling a model could propose `max_tokens_per_step: 10_000_000` and the control plane
    would honour it. "Model proposes, control plane disposes" has to include the numbers,
    not just the paths.
    """

    max_tokens_per_step: int = 100_000
    max_runtime_sec: int = 3600
    memory_mb: int = 16_384
    cpu_limit: float = 8.0
    disk_mb: int = 102_400
    process_limit: int = 1024

    @classmethod
    def for_quota(cls, quota: Any) -> "ResourceBounds":
        defaults = cls()
        return cls(
            memory_mb=min(defaults.memory_mb, quota.max_memory_mb),
            cpu_limit=min(defaults.cpu_limit, quota.max_cpu),
            max_tokens_per_step=min(defaults.max_tokens_per_step, quota.max_tokens_per_run),
        )

    def clamp(self, boundary: BoundarySpec) -> tuple[BoundarySpec, tuple[str, ...]]:
        """Return a boundary inside the ceilings, plus the list of what was reduced."""
        adjustments: list[str] = []

        def tightened(name: str, declared: Any, ceiling: Any) -> Any:
            if declared > ceiling:
                adjustments.append(f"{name}: {declared} -> {ceiling}")
                return ceiling
            return declared

        clamped = BoundarySpec(
            boundary_id=boundary.boundary_id,
            goal_id=boundary.goal_id,
            fs_whitelist=boundary.fs_whitelist,
            fs_denylist=boundary.fs_denylist,
            network_policy=boundary.network_policy,
            allowed_domains=boundary.allowed_domains,
            max_tokens_per_step=tightened(
                "max_tokens_per_step", boundary.max_tokens_per_step, self.max_tokens_per_step
            ),
            max_runtime_sec=tightened(
                "max_runtime_sec", boundary.max_runtime_sec, self.max_runtime_sec
            ),
            cpu_limit=float(tightened("cpu_limit", boundary.cpu_limit, self.cpu_limit)),
            memory_mb=tightened("memory_mb", boundary.memory_mb, self.memory_mb),
            disk_mb=tightened("disk_mb", boundary.disk_mb, self.disk_mb),
            process_limit=tightened(
                "process_limit", boundary.process_limit, self.process_limit
            ),
            allowed_tools=boundary.allowed_tools,
            dependency_manifest=boundary.dependency_manifest,
            lock_file=boundary.lock_file,
            isolation=boundary.isolation,
            version=boundary.version,
            created_at=boundary.created_at,
        )
        return clamped, tuple(adjustments)


@dataclass
class SpecHardening:
    """Clamps any spec to what the Meta-Spec allows, whatever produced it.

    Runs on deterministic *and* model-generated specs. The asymmetry is deliberate:
    the model proposes, this disposes.
    """

    meta: MetaSpec = field(default_factory=MetaSpec.default)
    bounds: ResourceBounds = field(default_factory=ResourceBounds)

    def harden(self, bundle: SpecBundle) -> SpecBundle:
        boundary = bundle.boundary
        whitelist = tuple(
            path
            for path in boundary.fs_whitelist
            if not self._forbidden(path)
        )
        if not whitelist:
            raise SpecError(
                "every declared fs_whitelist entry is forbidden by the Meta-Spec; "
                "refusing to issue an unbounded task"
            )

        denylist = tuple(
            dict.fromkeys((*boundary.fs_denylist, *NON_NEGOTIABLE_DENY, *self.meta.protected_paths))
        )

        nodes: list[PlanNode] = []
        for node in bundle.plan.nodes:
            artifacts = tuple(
                path for path in node.expected_artifacts if not self._forbidden(path)
            )
            if not artifacts:
                raise SpecError(
                    f"plan node {node.node_id} declares no artifact inside the "
                    "hardened boundary"
                )
            nodes.append(
                PlanNode(
                    node_id=node.node_id,
                    objective=node.objective,
                    deps=node.deps,
                    expected_artifacts=artifacts,
                    allowed_tools=node.allowed_tools,
                    retry_policy=node.retry_policy,
                    timeout_sec=min(node.timeout_sec, boundary.max_runtime_sec),
                    intent=node.intent,
                    revision_of=node.revision_of,
                    extra=node.extra,
                )
            )

        # An acceptance criterion that inspects a path outside the hardened boundary
        # could never be satisfied. Drop those criteria (and refuse if that would leave
        # no executable assertion at all) instead of issuing an impossible task.
        kept_criteria = tuple(
            criterion
            for criterion in bundle.goal.acceptance_criteria
            if not criterion.path or criterion.path in whitelist or _covered(whitelist, criterion.path)
        )
        if not kept_criteria:
            raise SpecError(
                "hardening removed every acceptance criterion; refusing to issue a task "
                "whose success cannot be evaluated"
            )
        hardened_goal = GoalSpec(
            goal_id=bundle.goal.goal_id,
            objective=bundle.goal.objective,
            invariants=bundle.goal.invariants,
            acceptance_criteria=kept_criteria,
            risk_level=bundle.goal.risk_level,
            version=bundle.goal.version,
            owner_id=bundle.goal.owner_id,
            created_at=bundle.goal.created_at,
            parent_spec_digest=bundle.goal.parent_spec_digest,
        )

        bounded, adjustments = self.bounds.clamp(
            BoundarySpec(
                boundary_id=boundary.boundary_id,
                goal_id=boundary.goal_id,
                fs_whitelist=whitelist,
                fs_denylist=denylist,
                network_policy=boundary.network_policy,
                allowed_domains=boundary.allowed_domains,
                max_tokens_per_step=boundary.max_tokens_per_step,
                max_runtime_sec=boundary.max_runtime_sec,
                cpu_limit=boundary.cpu_limit,
                memory_mb=boundary.memory_mb,
                disk_mb=boundary.disk_mb,
                process_limit=boundary.process_limit,
                allowed_tools=boundary.allowed_tools,
                dependency_manifest=boundary.dependency_manifest,
                lock_file=boundary.lock_file,
                isolation=boundary.isolation,
                version=boundary.version,
                created_at=boundary.created_at,
            )
        )
        self.last_adjustments = adjustments

        hardened = SpecBundle(
            goal=hardened_goal,
            plan=PlanSpec(
                plan_id=bundle.plan.plan_id,
                goal_id=bundle.plan.goal_id,
                nodes=tuple(nodes),
                version=bundle.plan.version,
                created_at=bundle.plan.created_at,
            ),
            boundary=bounded,
            meta=bundle.meta,
            spec_version=bundle.spec_version,
            owner_id=bundle.owner_id,
            created_at=bundle.created_at,
            parent_spec_digest=bundle.parent_spec_digest,
        )
        hardened.validate()
        return hardened

    #: What the last `harden()` reduced, for the audit. A clamp the operator cannot see is
    #: indistinguishable from a spec that was always that small.
    last_adjustments: tuple[str, ...] = ()

    def _forbidden(self, path: str) -> bool:
        from daedalus.domain.pathglob import matches_any

        return self.meta.is_protected(path) or matches_any(NON_NEGOTIABLE_DENY, path)


@dataclass
class DeterministicPlanner:
    """Builds a validated Tri-Spec from declared facts only."""

    name: str = "deterministic"
    meta: MetaSpec = field(default_factory=MetaSpec.default)
    bounds: ResourceBounds = field(default_factory=ResourceBounds)
    hardening: SpecHardening = field(init=False)
    #: Resource clamps applied to the request, for the audit.
    last_adjustments: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.hardening = SpecHardening(meta=self.meta, bounds=self.bounds)

    def plan(self, request: PlanRequest) -> SpecBundle:
        criteria = request.acceptance_criteria or self._default_criteria(request)

        goal = GoalSpec(
            goal_id=request.goal_id,
            objective=request.objective,
            invariants=request.invariants or ("no change outside the declared paths",),
            acceptance_criteria=criteria,
            risk_level=request.risk_level,
            owner_id=request.owner_id,
        )

        node = PlanNode(
            node_id=f"{request.goal_id}-step-01",
            objective=request.objective,
            deps=(),
            expected_artifacts=tuple(request.target_paths),
            allowed_tools=("read", "write", "test"),
            retry_policy=RetryPolicy(max_attempts=3),
            timeout_sec=request.max_runtime_sec,
            intent=request.objective,
            extra={"lint": "", "typecheck": ""},
        )
        plan = PlanSpec(
            plan_id=f"PLAN-{request.goal_id}",
            goal_id=request.goal_id,
            nodes=(node,),
        )

        boundary = BoundarySpec(
            boundary_id=f"BOUND-{request.goal_id}",
            goal_id=request.goal_id,
            fs_whitelist=tuple(request.target_paths),
            fs_denylist=NON_NEGOTIABLE_DENY,
            network_policy=request.network_policy,
            max_tokens_per_step=request.max_tokens_per_step,
            max_runtime_sec=request.max_runtime_sec,
            dependency_manifest=request.dependency_manifest,
            lock_file=request.lock_file,
            allowed_tools=("read", "write", "test"),
        )

        bundle = SpecBundle(
            goal=goal,
            plan=plan,
            boundary=boundary,
            meta=self.meta,
            owner_id=request.owner_id,
        )
        hardened = self.hardening.harden(bundle)
        self.last_adjustments = self.hardening.last_adjustments
        return hardened

    def _default_criteria(self, request: PlanRequest) -> tuple[AcceptanceCriterion, ...]:
        criteria: list[AcceptanceCriterion] = [
            AcceptanceCriterion(
                criterion_id="AC-01-tests",
                kind=AssertionKind.EXIT_CODE,
                statement="the project test command exits zero",
                command=request.test_command,
            )
        ]
        for index, path in enumerate(request.target_paths, start=1):
            # Criteria are emitted for every requested path; hardening removes the ones
            # that fall outside the final boundary, so the planner does not need to
            # duplicate the Meta-Spec's decision here.
            criteria.append(
                AcceptanceCriterion(
                    criterion_id=f"AC-{index + 1:02d}-exists",
                    kind=AssertionKind.EXPECTED_FILE,
                    statement=f"{path} exists after the change",
                    path=path,
                    expect=True,
                )
            )
        return tuple(criteria)


# ---------------------------------------------------------------------------
# Model planner
# ---------------------------------------------------------------------------

_PLANNER_SYSTEM = (
    "You are the Planner inside Daedalus, a deterministic control plane.\n"
    "You produce a formal Tri-Spec as JSON. You never execute anything.\n"
    "Hard rules:\n"
    "  - Every acceptance criterion must be executable by a machine.\n"
    "  - The DAG must be acyclic; node ids are unique.\n"
    "  - fs_whitelist entries are glob paths relative to the repository root.\n"
    "  - You may not whitelist security policy, credentials, or control-plane code.\n"
    "  - This executor runs file-change nodes only; each node must produce a real diff.\n"
    "  - Do not add read-only/testing-only nodes; tests run automatically in the gates.\n"
    "  - expected_artifacts are concrete file paths within fs_whitelist, never labels "
    "such as test_results. Declare write capability for file-change nodes.\n"
    "  - In a multi-node DAG, every node with downstream dependents must declare "
    "executable node-local acceptance_criteria that can pass before downstream code exists.\n"
    "  - Put node checks in extra.acceptance_criteria. Their union must include every "
    "original goal criterion; assign the full goal checks to the final integration node.\n"
    "  - If the files form one coupled API, prefer one atomic file-change node covering "
    "all those files; the unchanged full goal tests still gate integrated delivery.\n"
    "Answer with a single JSON object and nothing else."
)


@dataclass
class ModelPlanner:
    """Asks a model for a candidate spec, then validates and hardens it.

    A model failure is not fatal: `fallback` is used, because a plan that cannot be
    produced is an infrastructure problem, not a reason to invent permissions.
    """

    client: ModelClient
    fallback: Planner = field(default_factory=DeterministicPlanner)
    hardening: SpecHardening = field(default_factory=SpecHardening)
    budget: TokenBudget | None = None
    name: str = "model"
    last_raw: str = ""
    #: Resource clamps applied to the model's proposal, so the caller can report them.
    last_adjustments: tuple[str, ...] = ()
    #: Refuse instead of falling back. The fallback is right for a run — an infrastructure
    #: problem should not stop work that was already authorised. It is wrong for the intake,
    #: where the operator was told the model would read their task; quietly substituting a
    #: rule-based plan would make the review screen describe a decision process that did not
    #: happen. `require_model=True` makes that failure loud instead.
    require_model: bool = False
    #: The request being planned, kept so `_give_up` can hand it to the fallback.
    _last_request: PlanRequest | None = field(default=None, repr=False, compare=False)
    #: True when the first candidate was rejected and a second, structure-corrected one was used.
    repaired: bool = False

    def _give_up(self, reason: str) -> SpecBundle:
        if self.require_model:
            raise ModelError(f"model planning is required here but failed: {reason}")
        # A fallback is still subject to the same operator ceilings as a model plan.
        bundle = self.hardening.harden(self.fallback.plan(self._last_request))
        self.last_adjustments = self.hardening.last_adjustments
        return bundle

    def plan(self, request: PlanRequest) -> SpecBundle:
        self._last_request = request
        prompt = self._render(request)
        try:
            # The extra context a caller supplies could carry a credential.
            assert_outbound_clean(prompt, where="the planning prompt")
        except SecretInPayload:
            return self._give_up("the prompt carried a credential shape")
        try:
            from daedalus.model.base import budgeted_completion
            completion = budgeted_completion(
                self.client,
                [
                    Message(role="system", content=_PLANNER_SYSTEM),
                    Message(role="user", content=prompt),
                ],
                budget=self.budget, estimated=len(_PLANNER_SYSTEM) + len(prompt) + 4096,
                temperature=0.0,
                max_tokens=4096,
                response_format_json=True,
            )
        except Exception as error:  # noqa: BLE001 - usually a fallback, never a crash
            return self._give_up(f"the model call failed: {error}")

        self.last_raw = completion.text

        try:
            bundle = self._parse(completion.text, request)
        except (SpecError, ValueError, KeyError, TypeError) as error:
            bundle = self._repair(prompt, request, f"the spec did not parse: {error}")
            if bundle is None:
                return self._give_up(f"the model's spec did not parse: {error}")
        try:
            hardened = self.hardening.harden(bundle)
        except SpecError as error:
            repaired = self._repair(prompt, request, f"the spec failed validation: {error}")
            if repaired is None:
                return self._give_up(f"the model's spec failed validation: {error}")
            try:
                hardened = self.hardening.harden(repaired)
            except SpecError as second:
                return self._give_up(f"the model's spec failed validation twice: {second}")
        self.last_adjustments = self.hardening.last_adjustments
        return hardened

    def _repair(
        self, prompt: str, request: PlanRequest, reason: str
    ) -> SpecBundle | None:
        """One second attempt, quoting the validator's own words.

        A small local model gets the shape of a Tri-Spec almost right and then declares an empty
        `expected_artifacts`, which the control plane refuses — correctly. Refusing and stopping
        there makes the whole intake unusable with such a model for a reason the model could fix
        if it were told. The validator already produced a precise sentence, so it is quoted back
        and one more candidate is requested.

        Only the structure is corrected. Nothing is filled in on the model's behalf, the repair
        is not repeated, and a second failure refuses with both reasons.
        """
        if not self.require_model:
            return None
        try:
            from daedalus.model.base import budgeted_completion
            completion = budgeted_completion(
                self.client,
                [
                    Message(role="system", content=_PLANNER_SYSTEM),
                    Message(role="user", content=prompt),
                    Message(
                        role="user",
                        content=(
                            "你上一次的 JSON 被控制面拒绝了，原因：\n"
                            f"{reason}\n"
                            "请重新输出完整的 JSON。注意：每个 node 的 expected_artifacts "
                            "必须是非空的路径数组（用给出的 TARGET_PATHS），"
                            "acceptance_criteria 至少一条，且都必须落在 fs_whitelist 内。"
                        ),
                    ),
                ],
                budget=self.budget,
                estimated=len(_PLANNER_SYSTEM) + len(prompt) + len(reason) + 4608,
                temperature=0.0,
                max_tokens=4096,
                response_format_json=True,
            )
        except Exception:  # noqa: BLE001 - a failed repair is the same as no repair
            return None
        self.last_raw = completion.text
        try:
            bundle = self._parse(completion.text, request)
        except (SpecError, ValueError, KeyError, TypeError):
            return None
        self.repaired = True
        return bundle

    def _render(self, request: PlanRequest) -> str:
        return (
            f"GOAL_ID: {request.goal_id}\n"
            f"OBJECTIVE: {request.objective}\n"
            f"TARGET_PATHS: {json.dumps(list(request.target_paths))}\n"
            f"TEST_COMMAND: {request.test_command}\n"
            f"RISK_LEVEL: {request.risk_level.value}\n"
            f"NETWORK_POLICY: {request.network_policy.value}\n"
            f"MAX_RUNTIME_SEC: {request.max_runtime_sec}\n"
            f"MAX_TOKENS_PER_STEP: {request.max_tokens_per_step}\n\n"
            "Return JSON with this shape:\n"
            '{"spec_01_goal":{"goal_id":"...","objective":"...","invariants":["..."],'
            '"acceptance_criteria":[{"criterion_id":"...","kind":"exit_code",'
            '"command":"...","statement":"..."}],"risk_level":"normal"},'
            '"spec_02_plan":{"plan_id":"...","goal_id":"...","nodes":[{"node_id":"...",'
            '"objective":"...","deps":[],"expected_artifacts":["..."],'
            '"allowed_tools":["read","write"],"retry_policy":{"max_attempts":3},'
            '"timeout_sec":300}]},'
            '"spec_03_boundary":{"boundary_id":"...","goal_id":"...",'
            '"fs_whitelist":["..."],"network_policy":"deny","max_tokens_per_step":20000,'
            '"max_runtime_sec":300}}\n\n'
            f"EXTRA_CONTEXT:\n{request.extra_context}"
        )

    def _parse(self, raw: str, request: PlanRequest) -> SpecBundle:
        payload = json.loads(_strip_fence(raw))
        goal = GoalSpec.from_dict(payload["spec_01_goal"])
        plan = PlanSpec.from_dict(payload["spec_02_plan"])
        boundary = BoundarySpec.from_dict(payload["spec_03_boundary"])
        bundle = SpecBundle(
            goal=goal,
            plan=plan,
            boundary=boundary,
            meta=self.hardening.meta,
            owner_id=request.owner_id,
        )
        bundle.validate()
        upstream_ids = {dep for node in plan.nodes for dep in node.deps}
        for node in plan.nodes:
            if node.node_id in upstream_ids and not any(
                criterion.kind is not AssertionKind.NATURAL_LANGUAGE
                for criterion in node.acceptance_criteria
            ):
                raise SpecError(
                    f"upstream node {node.node_id} has no executable extra.acceptance_criteria; "
                    "whole-goal tests may depend on unfinished downstream code. Declare "
                    "independent node checks or group coupled file changes into one atomic node"
                )
            if node.allowed_tools and "write" not in node.allowed_tools:
                raise SpecError(
                    f"node {node.node_id} is read-only; this executor requires file changes; "
                    "put verification commands in acceptance criteria instead"
                )
            for path in node.expected_artifacts:
                if not _covered(boundary.fs_whitelist, path):
                    raise SpecError(
                        f"node {node.node_id} artifact {path!r} is outside fs_whitelist; "
                        "expected_artifacts must name writable files, not report labels"
                    )
        return bundle


def _covered(whitelist: tuple[str, ...], path: str) -> bool:
    from daedalus.domain.pathglob import matches_any

    return matches_any(whitelist, path)


def _strip_fence(text: str) -> str:
    stripped = (text or "").strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3:
            return "\n".join(lines[1:-1]).strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end > start:
        return stripped[start : end + 1]
    return stripped


def spec_fingerprint(request: PlanRequest, bundle: SpecBundle) -> str:
    """Digest linking a request to the spec it produced, for the audit trail."""
    return digest_of(
        {
            "request_id": request.request_id,
            "goal_id": request.goal_id,
            "objective": request.objective,
            "target_paths": list(request.target_paths),
            "spec_digest": bundle.digest(),
        }
    )


def bundle_created_at() -> str:
    return utc_now()
