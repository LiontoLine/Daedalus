"""Tri-Spec formal contract system (Spec §2, §3).

Four frozen documents, one digest over all four:

    SPEC-01 Goal Contract        what "done" means, as executable assertions
    SPEC-02 DAG Execution Plan   the node graph, validated as a DAG
    SPEC-03 Boundary Contract    filesystem / network / resource limits
    Meta-Spec                    what the system itself may never self-modify

The digest is an *integrity and version-linkage* mechanism. It is explicitly not an
identity or authorization mechanism (Spec §0.1, §3.1) — approval and signature are a
separate layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import utc_now
from daedalus.domain.pathglob import matches_any, normalize_path
from daedalus.errors import PlanGraphError, SpecError

SPEC_SCHEMA_VERSION = 1


class RiskLevel(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]


_RISK_RANK = {
    RiskLevel.LOW: 0,
    RiskLevel.NORMAL: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

HIGH_RISK_PATH_HINTS = (
    "src/daedalus/domain/fsm",
    "src/daedalus/infrastructure/store",
    "src/daedalus/application/scheduler",
    "src/daedalus/application/gatekeeper",
    "src/daedalus/boundary",
    "specs/meta",
    "secrets",
    ".env",
)


class AssertionKind(str, Enum):
    """Acceptance criteria must be executable, not prose (Spec §2.1)."""

    EXIT_CODE = "exit_code"
    TEST_RESULT = "test_result"
    EXPECTED_FILE = "expected_file"
    FILE_CONTENT = "file_content"
    AST_PROPERTY = "ast_property"
    SCHEMA_VALIDATION = "schema_validation"
    TYPE_CHECK = "type_check"
    SCRIPT = "script"
    NATURAL_LANGUAGE = "natural_language"


#: Assertion kinds that a deterministic Tier-1 gate can actually execute.
EXECUTABLE_KINDS = frozenset(
    {
        AssertionKind.EXIT_CODE,
        AssertionKind.TEST_RESULT,
        AssertionKind.EXPECTED_FILE,
        AssertionKind.FILE_CONTENT,
        AssertionKind.AST_PROPERTY,
        AssertionKind.SCHEMA_VALIDATION,
        AssertionKind.TYPE_CHECK,
        AssertionKind.SCRIPT,
    }
)


@dataclass(frozen=True, slots=True)
class AcceptanceCriterion:
    criterion_id: str
    kind: AssertionKind
    statement: str = ""
    command: str = ""
    path: str = ""
    expect: Any = None
    weight: float = 1.0

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "AcceptanceCriterion":
        try:
            kind = AssertionKind(raw["kind"])
        except (KeyError, ValueError) as error:
            raise SpecError(
                f"acceptance_criteria entry needs a valid 'kind': {raw!r}"
            ) from error
        criterion = AcceptanceCriterion(
            criterion_id=str(raw.get("criterion_id") or raw.get("id") or ""),
            kind=kind,
            statement=str(raw.get("statement", "")),
            command=str(raw.get("command", "")),
            path=normalize_path(str(raw.get("path", ""))),
            expect=raw.get("expect"),
            weight=float(raw.get("weight", 1.0)),
        )
        if not criterion.criterion_id:
            raise SpecError(f"acceptance criterion without criterion_id: {raw!r}")
        if kind is AssertionKind.NATURAL_LANGUAGE and not criterion.statement:
            raise SpecError(f"{criterion.criterion_id}: natural_language needs a statement")
        if kind in EXECUTABLE_KINDS and not criterion.command and not criterion.path:
            raise SpecError(
                f"{criterion.criterion_id}: executable assertion {kind.value} requires "
                "'command' or 'path'"
            )
        return criterion

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "criterion_id": self.criterion_id,
            "kind": self.kind.value,
        }
        if self.statement:
            payload["statement"] = self.statement
        if self.command:
            payload["command"] = self.command
        if self.path:
            payload["path"] = self.path
        if self.expect is not None:
            payload["expect"] = self.expect
        if self.weight != 1.0:
            payload["weight"] = self.weight
        return payload


@dataclass(frozen=True, slots=True)
class GoalSpec:
    """SPEC-01."""

    goal_id: str
    objective: str = ""
    invariants: tuple[str, ...] = ()
    acceptance_criteria: tuple[AcceptanceCriterion, ...] = ()
    risk_level: RiskLevel = RiskLevel.NORMAL
    schema_version: int = SPEC_SCHEMA_VERSION
    version: int = 1
    owner_id: str = "owner"
    created_at: str = field(default_factory=utc_now)
    parent_spec_digest: str = ""

    @property
    def spec_type(self) -> str:
        return "goal"

    def validate(self) -> None:
        if not self.goal_id:
            raise SpecError("SPEC-01 requires a unique goal_id")
        if self.schema_version != SPEC_SCHEMA_VERSION:
            raise SpecError(
                f"SPEC-01 schema_version must be {SPEC_SCHEMA_VERSION}, "
                f"got {self.schema_version}"
            )
        if not self.acceptance_criteria:
            raise SpecError("SPEC-01 requires at least one acceptance criterion")
        if not any(c.kind in EXECUTABLE_KINDS for c in self.acceptance_criteria):
            raise SpecError(
                "SPEC-01 acceptance_criteria must contain at least one executable "
                "assertion; prose alone may not be the only acceptance basis"
            )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "spec_type": self.spec_type,
            "schema_version": self.schema_version,
            "spec_version": self.version,
            "goal_id": self.goal_id,
            "objective": self.objective,
            "invariants": list(self.invariants),
            "acceptance_criteria": [c.to_dict() for c in self.acceptance_criteria],
            "risk_level": self.risk_level.value,
            "owner_id": self.owner_id,
            "created_at": self.created_at,
        }
        if self.parent_spec_digest:
            payload["parent_spec_digest"] = self.parent_spec_digest
        return payload

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "GoalSpec":
        spec = GoalSpec(
            goal_id=str(raw.get("goal_id", "")),
            objective=str(raw.get("objective", "")),
            invariants=tuple(str(item) for item in raw.get("invariants", ())),
            acceptance_criteria=tuple(
                AcceptanceCriterion.from_dict(item)
                for item in raw.get("acceptance_criteria", ())
            ),
            risk_level=RiskLevel(str(raw.get("risk_level", "normal"))),
            schema_version=int(raw.get("schema_version", SPEC_SCHEMA_VERSION)),
            version=int(raw.get("spec_version", 1)),
            owner_id=str(raw.get("owner_id", "owner")),
            created_at=str(raw.get("created_at") or utc_now()),
            parent_spec_digest=str(raw.get("parent_spec_digest", "")),
        )
        spec.validate()
        return spec


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    backoff_sec: float = 1.0
    backoff_factor: float = 2.0

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "RetryPolicy":
        data = raw or {}
        policy = RetryPolicy(
            max_attempts=int(data.get("max_attempts", 3)),
            backoff_sec=float(data.get("backoff_sec", 1.0)),
            backoff_factor=float(data.get("backoff_factor", 2.0)),
        )
        if policy.max_attempts < 1 or policy.max_attempts > 10:
            raise SpecError(
                f"retry_policy.max_attempts must be within 1..10 (no infinite retry), "
                f"got {policy.max_attempts}"
            )
        return policy

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_attempts": self.max_attempts,
            "backoff_sec": self.backoff_sec,
            "backoff_factor": self.backoff_factor,
        }


@dataclass(frozen=True, slots=True)
class PlanNode:
    """One DAG node (Spec §2.2)."""

    node_id: str
    objective: str = ""
    deps: tuple[str, ...] = ()
    expected_artifacts: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    timeout_sec: int = 300
    intent: str = ""
    revision_of: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "PlanNode":
        return PlanNode(
            node_id=str(raw.get("node_id", "")),
            objective=str(raw.get("objective", "")),
            deps=tuple(str(item) for item in raw.get("deps", ())),
            expected_artifacts=tuple(
                normalize_path(str(item)) for item in raw.get("expected_artifacts", ())
            ),
            allowed_tools=tuple(str(item) for item in raw.get("allowed_tools", ())),
            retry_policy=RetryPolicy.from_dict(raw.get("retry_policy")),
            timeout_sec=int(raw.get("timeout_sec", 300)),
            intent=str(raw.get("intent", "")),
            revision_of=str(raw.get("revision_of", "")),
            extra=dict(raw.get("extra", {})),
        )

    @property
    def acceptance_criteria(self) -> tuple[AcceptanceCriterion, ...]:
        """Node-scoped criteria from `extra`, or empty to inherit the goal's set.

        A DAG node often verifies only part of the goal. Letting a node declare its own
        assertions is what makes a multi-node plan gateable at all — otherwise every node
        would have to satisfy the entire acceptance set on its own. `SpecBundle.validate`
        then requires the union of node criteria to cover every goal criterion, so
        splitting the work can never be used to skip verification.
        """
        raw = self.extra.get("acceptance_criteria") if self.extra else None
        if not raw:
            return ()
        return tuple(AcceptanceCriterion.from_dict(item) for item in raw)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "node_id": self.node_id,
            "deps": list(self.deps),
            "expected_artifacts": list(self.expected_artifacts),
            "allowed_tools": list(self.allowed_tools),
            "retry_policy": self.retry_policy.to_dict(),
            "timeout_sec": self.timeout_sec,
        }
        if self.objective:
            payload["objective"] = self.objective
        if self.intent:
            payload["intent"] = self.intent
        if self.revision_of:
            payload["revision_of"] = self.revision_of
        if self.extra:
            payload["extra"] = self.extra
        return payload


@dataclass(frozen=True, slots=True)
class PlanSpec:
    """SPEC-02."""

    plan_id: str
    goal_id: str
    nodes: tuple[PlanNode, ...] = ()
    schema_version: int = SPEC_SCHEMA_VERSION
    version: int = 1
    created_at: str = field(default_factory=utc_now)

    @property
    def spec_type(self) -> str:
        return "plan"

    def validate(self) -> None:
        if not self.plan_id:
            raise SpecError("SPEC-02 requires a plan_id")
        if not self.goal_id:
            raise SpecError("SPEC-02 requires the goal_id it implements")
        if not self.nodes:
            raise SpecError("SPEC-02 requires at least one node")
        if self.schema_version != SPEC_SCHEMA_VERSION:
            raise SpecError(f"SPEC-02 schema_version must be {SPEC_SCHEMA_VERSION}")

        seen: set[str] = set()
        for node in self.nodes:
            if not node.node_id:
                raise SpecError("SPEC-02 node without node_id")
            if node.node_id in seen:
                raise SpecError(f"SPEC-02 node_id must be globally unique: {node.node_id}")
            seen.add(node.node_id)
            if node.timeout_sec <= 0:
                raise SpecError(
                    f"node {node.node_id}: timeout_sec must be finite and positive "
                    f"(got {node.timeout_sec})"
                )
            if not node.expected_artifacts:
                raise SpecError(
                    f"node {node.node_id}: expected_artifacts must be verifiable, i.e. "
                    "at least one declared artifact"
                )

        for node in self.nodes:
            for dep in node.deps:
                if dep not in seen:
                    raise PlanGraphError(
                        f"node {node.node_id} depends on unknown node {dep}"
                    )
                if dep == node.node_id:
                    raise PlanGraphError(f"node {node.node_id} depends on itself")
        self.topo_order()

    def topo_order(self) -> tuple[str, ...]:
        """Kahn topological order; raises on a cycle (Spec §2.2)."""
        indegree = {node.node_id: 0 for node in self.nodes}
        adjacency: dict[str, list[str]] = {node.node_id: [] for node in self.nodes}
        for node in self.nodes:
            for dep in node.deps:
                indegree[node.node_id] += 1
                adjacency[dep].append(node.node_id)

        ready = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
        order: list[str] = []
        while ready:
            current = ready.pop(0)
            order.append(current)
            for downstream in sorted(adjacency[current]):
                indegree[downstream] -= 1
                if indegree[downstream] == 0:
                    ready.append(downstream)
                    ready.sort()

        if len(order) != len(self.nodes):
            cyclic = sorted(set(indegree) - set(order))
            raise PlanGraphError(f"SPEC-02 DAG contains a cycle among {cyclic}")
        return tuple(order)

    def node(self, node_id: str) -> PlanNode:
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        raise SpecError(f"unknown node_id: {node_id}")

    def downstream_closure(self, node_ids: tuple[str, ...]) -> tuple[str, ...]:
        """Everything transitively affected by the given nodes (Spec §13.1 B)."""
        affected = set(node_ids)
        changed = True
        while changed:
            changed = False
            for node in self.nodes:
                if node.node_id not in affected and affected.intersection(node.deps):
                    affected.add(node.node_id)
                    changed = True
        return tuple(sorted(affected))

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_type": self.spec_type,
            "schema_version": self.schema_version,
            "spec_version": self.version,
            "plan_id": self.plan_id,
            "goal_id": self.goal_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "PlanSpec":
        spec = PlanSpec(
            plan_id=str(raw.get("plan_id", "")),
            goal_id=str(raw.get("goal_id", "")),
            nodes=tuple(PlanNode.from_dict(item) for item in raw.get("nodes", ())),
            schema_version=int(raw.get("schema_version", SPEC_SCHEMA_VERSION)),
            version=int(raw.get("spec_version", 1)),
            created_at=str(raw.get("created_at") or utc_now()),
        )
        spec.validate()
        return spec


class NetworkPolicy(str, Enum):
    DENY = "deny"
    ALLOWLIST = "allowlist"


@dataclass(frozen=True, slots=True)
class BoundarySpec:
    """SPEC-03."""

    boundary_id: str
    goal_id: str
    fs_whitelist: tuple[str, ...] = ()
    fs_denylist: tuple[str, ...] = ()
    network_policy: NetworkPolicy = NetworkPolicy.DENY
    allowed_domains: tuple[str, ...] = ()
    max_tokens_per_step: int = 20_000
    max_runtime_sec: int = 300
    cpu_limit: float = 2.0
    memory_mb: int = 4096
    disk_mb: int = 20_480
    process_limit: int = 128
    allowed_tools: tuple[str, ...] = ()
    dependency_manifest: str = ""
    lock_file: str = ""
    #: Spec §7.1: which process-isolation mechanism this task requires.
    #: "auto" takes the strongest available; an explicit level that is unavailable is refused.
    isolation: str = "auto"
    schema_version: int = SPEC_SCHEMA_VERSION
    version: int = 1
    created_at: str = field(default_factory=utc_now)

    @property
    def spec_type(self) -> str:
        return "boundary"

    def validate(self) -> None:
        if not self.boundary_id:
            raise SpecError("SPEC-03 requires a boundary_id")
        if not self.goal_id:
            raise SpecError("SPEC-03 requires the goal_id it bounds")
        if not self.fs_whitelist:
            raise SpecError(
                "SPEC-03 requires a non-empty fs_whitelist; an unbounded default is "
                "not an acceptable security posture"
            )
        if self.network_policy is NetworkPolicy.DENY and self.allowed_domains:
            raise SpecError(
                "SPEC-03 declares network_policy=deny but lists allowed_domains"
            )
        if self.network_policy is NetworkPolicy.ALLOWLIST and not self.allowed_domains:
            raise SpecError(
                "SPEC-03 declares network_policy=allowlist without allowed_domains"
            )
        if self.max_runtime_sec <= 0 or self.max_runtime_sec > 86_400:
            raise SpecError(
                f"SPEC-03 max_runtime_sec must be within 1..86400, got {self.max_runtime_sec}"
            )
        for name in ("max_tokens_per_step", "memory_mb", "disk_mb", "process_limit"):
            if int(getattr(self, name)) <= 0:
                raise SpecError(f"SPEC-03 {name} must be positive")
        if self.cpu_limit <= 0:
            raise SpecError("SPEC-03 cpu_limit must be positive")
        if self.isolation not in {"auto", "host-process", "seatbelt", "container"}:
            raise SpecError(
                "SPEC-03 isolation must be one of auto, host-process, seatbelt, container; "
                f"got {self.isolation!r}"
            )

    def allows_path(self, path: str) -> bool:
        normalised = normalize_path(path)
        if not normalised:
            return False
        if self.fs_denylist and matches_any(self.fs_denylist, normalised):
            return False
        return matches_any(self.fs_whitelist, normalised)

    def offending_paths(self, paths: list[str]) -> tuple[str, ...]:
        return tuple(path for path in paths if not self.allows_path(path))

    def allows_tool(self, tool: str) -> bool:
        return not self.allowed_tools or tool in self.allowed_tools

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_type": self.spec_type,
            "schema_version": self.schema_version,
            "spec_version": self.version,
            "boundary_id": self.boundary_id,
            "goal_id": self.goal_id,
            "fs_whitelist": list(self.fs_whitelist),
            "fs_denylist": list(self.fs_denylist),
            "network_policy": self.network_policy.value,
            "allowed_domains": list(self.allowed_domains),
            "max_tokens_per_step": self.max_tokens_per_step,
            "max_runtime_sec": self.max_runtime_sec,
            "cpu_limit": self.cpu_limit,
            "memory_mb": self.memory_mb,
            "disk_mb": self.disk_mb,
            "process_limit": self.process_limit,
            "allowed_tools": list(self.allowed_tools),
            "dependency_manifest": self.dependency_manifest,
            "lock_file": self.lock_file,
            "isolation": self.isolation,
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "BoundarySpec":
        spec = BoundarySpec(
            boundary_id=str(raw.get("boundary_id", "")),
            goal_id=str(raw.get("goal_id", "")),
            fs_whitelist=tuple(str(item) for item in raw.get("fs_whitelist", ())),
            fs_denylist=tuple(str(item) for item in raw.get("fs_denylist", ())),
            network_policy=NetworkPolicy(str(raw.get("network_policy", "deny"))),
            allowed_domains=tuple(str(item) for item in raw.get("allowed_domains", ())),
            max_tokens_per_step=int(raw.get("max_tokens_per_step", 20_000)),
            max_runtime_sec=int(raw.get("max_runtime_sec", 300)),
            cpu_limit=float(raw.get("cpu_limit", 2)),
            memory_mb=int(raw.get("memory_mb", 4096)),
            disk_mb=int(raw.get("disk_mb", 20_480)),
            process_limit=int(raw.get("process_limit", 128)),
            allowed_tools=tuple(str(item) for item in raw.get("allowed_tools", ())),
            dependency_manifest=str(raw.get("dependency_manifest", "")),
            lock_file=str(raw.get("lock_file", "")),
            isolation=str(raw.get("isolation", "auto")),
            schema_version=int(raw.get("schema_version", SPEC_SCHEMA_VERSION)),
            version=int(raw.get("spec_version", 1)),
            created_at=str(raw.get("created_at") or utc_now()),
        )
        spec.validate()
        return spec


@dataclass(frozen=True, slots=True)
class MetaSpec:
    """System-level contract: what Daedalus may never do to itself (Spec §2.4, §21)."""

    meta_id: str = "META-001"
    agent_writable_paths: tuple[str, ...] = ()
    protected_paths: tuple[str, ...] = ()
    human_approval_required: tuple[str, ...] = (
        "gatekeeper",
        "security_policy",
        "meta_spec",
        "event_store",
        "fsm",
        "scheduler",
        "secret_broker",
        "network_policy",
    )
    allow_gatekeeper_self_modification: bool = False
    allow_control_plane_self_modification: bool = False
    require_redeploy_for_protected: bool = True
    self_evolution_level: int = 0
    schema_version: int = SPEC_SCHEMA_VERSION
    version: int = 1
    created_at: str = field(default_factory=utc_now)

    @property
    def spec_type(self) -> str:
        return "meta"

    def validate(self) -> None:
        if not self.protected_paths:
            raise SpecError(
                "Meta-Spec must declare protected_paths; an empty protection set means "
                "the system could self-modify its own regulators"
            )
        for capability in (
            "gatekeeper",
            "security_policy",
            "meta_spec",
            "event_store",
        ):
            if capability not in self.human_approval_required:
                raise SpecError(
                    f"Meta-Spec must require human approval for {capability!r}"
                )
        if self.allow_gatekeeper_self_modification:
            raise SpecError("Meta-Spec may not allow Gatekeeper self-modification")
        if self.allow_control_plane_self_modification:
            raise SpecError("Meta-Spec may not allow control-plane self-modification")

    def is_protected(self, path: str) -> bool:
        return matches_any(self.protected_paths, path)

    def is_agent_writable(self, path: str) -> bool:
        normalised = normalize_path(path)
        if self.is_protected(normalised):
            return False
        if not self.agent_writable_paths:
            return True
        return matches_any(self.agent_writable_paths, normalised)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_type": self.spec_type,
            "schema_version": self.schema_version,
            "spec_version": self.version,
            "meta_id": self.meta_id,
            "agent_writable_paths": list(self.agent_writable_paths),
            "protected_paths": list(self.protected_paths),
            "human_approval_required": list(self.human_approval_required),
            "allow_gatekeeper_self_modification": self.allow_gatekeeper_self_modification,
            "allow_control_plane_self_modification": (
                self.allow_control_plane_self_modification
            ),
            "require_redeploy_for_protected": self.require_redeploy_for_protected,
            "self_evolution_level": self.self_evolution_level,
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "MetaSpec":
        spec = MetaSpec(
            meta_id=str(raw.get("meta_id", "META-001")),
            agent_writable_paths=tuple(
                str(item) for item in raw.get("agent_writable_paths", ())
            ),
            protected_paths=tuple(str(item) for item in raw.get("protected_paths", ())),
            human_approval_required=tuple(
                str(item) for item in raw.get("human_approval_required", ())
            ),
            allow_gatekeeper_self_modification=bool(
                raw.get("allow_gatekeeper_self_modification", False)
            ),
            allow_control_plane_self_modification=bool(
                raw.get("allow_control_plane_self_modification", False)
            ),
            require_redeploy_for_protected=bool(
                raw.get("require_redeploy_for_protected", True)
            ),
            self_evolution_level=int(raw.get("self_evolution_level", 0)),
            schema_version=int(raw.get("schema_version", SPEC_SCHEMA_VERSION)),
            version=int(raw.get("spec_version", 1)),
            created_at=str(raw.get("created_at") or utc_now()),
        )
        spec.validate()
        return spec

    @staticmethod
    def default() -> "MetaSpec":
        """The shipped Meta-Spec: the regulator that guards the regulators."""
        return MetaSpec(
            protected_paths=(
                # Protect the full policy interpreter and its dependencies, not just
                # the FSM declaration. UI assets remain ordinary application changes.
                "src/daedalus/domain/**",
                "src/daedalus/application/**",
                "src/daedalus/infrastructure/**",
                "src/daedalus/security/**",
                "src/daedalus/model/**",
                "src/daedalus/service/*.py",
                "src/daedalus/config.py",
                "src/daedalus/cli.py",
                "src/daedalus/errors.py",
                "src/daedalus/__init__.py",
                "src/daedalus/__main__.py",
                "tests/gatekeeper/**",
            )
        )


def node_subject_digest(bundle: "SpecBundle", node: PlanNode) -> str:
    """Digest of everything that determines ONE node's work (Spec §13.1 B, §13.2).

    The reuse key cannot carry the whole-bundle digest, because then any change anywhere
    invalidates everything and Spec §13.1's "selective replay" becomes impossible to implement.
    This digest covers exactly what the node's work depends on:

    * the goal it serves (objective, invariants, acceptance criteria it is judged by);
    * the node's own definition (intent, deps, expected artifacts, tools, retry, timeout);
    * the boundary fields that reach this node — its network posture, its tool allowance, the
      resource limits, its isolation level, and only the whitelist entries that actually cover
      its own artifacts;
    * the denylist and Meta-Spec protected paths, because those can change what is forbidden.

    Deliberately excluded: other nodes, whitelist entries for paths this node never touches,
    timestamps and owner metadata. Those are precisely the changes §13.1 B says should not
    invalidate unrelated work.
    """
    from daedalus.domain.pathglob import matches_any

    boundary = bundle.boundary
    criteria = node.acceptance_criteria or bundle.goal.acceptance_criteria
    relevant_whitelist = tuple(
        sorted(
            pattern
            for pattern in boundary.fs_whitelist
            if any(matches_any((pattern,), artifact) for artifact in node.expected_artifacts)
        )
    )
    return digest_of(
        {
            "goal_id": bundle.goal.goal_id,
            "objective": bundle.goal.objective,
            "invariants": list(bundle.goal.invariants),
            "risk_level": bundle.goal.risk_level.value,
            "node": node.to_dict(),
            "criteria": [criterion.to_dict() for criterion in criteria],
            "relevant_whitelist": list(relevant_whitelist),
            "denylist": sorted(boundary.fs_denylist),
            "network_policy": boundary.network_policy.value,
            "allowed_domains": sorted(boundary.allowed_domains),
            "boundary_tools": sorted(boundary.allowed_tools),
            "dependency": [boundary.dependency_manifest, boundary.lock_file],
            "limits": [
                boundary.max_tokens_per_step,
                boundary.max_runtime_sec,
                boundary.cpu_limit,
                boundary.memory_mb,
                boundary.disk_mb,
                boundary.process_limit,
            ],
            "isolation": boundary.isolation,
            "meta_protected": sorted(bundle.meta.protected_paths),
        }
    )


@dataclass(frozen=True, slots=True)
class SpecBundle:
    """The four frozen documents plus their combined digest."""

    goal: GoalSpec
    plan: PlanSpec
    boundary: BoundarySpec
    meta: MetaSpec
    spec_version: int = 1
    owner_id: str = "owner"
    created_at: str = field(default_factory=utc_now)
    parent_spec_digest: str = ""

    def validate(self) -> None:
        self.goal.validate()
        self.plan.validate()
        self.boundary.validate()
        self.meta.validate()

        if self.plan.goal_id != self.goal.goal_id:
            raise SpecError(
                f"SPEC-02 implements {self.plan.goal_id} but SPEC-01 declares "
                f"{self.goal.goal_id}"
            )
        if self.boundary.goal_id != self.goal.goal_id:
            raise SpecError(
                f"SPEC-03 bounds {self.boundary.goal_id} but SPEC-01 declares "
                f"{self.goal.goal_id}"
            )

        # Acceptance criteria that name a path must be inside the declared boundary,
        # otherwise the task can never satisfy itself.
        for criterion in self.goal.acceptance_criteria:
            if criterion.path and not self.boundary.allows_path(criterion.path):
                raise SpecError(
                    f"acceptance criterion {criterion.criterion_id} inspects "
                    f"{criterion.path!r}, which SPEC-03 does not whitelist"
                )

        # If any node narrows acceptance to itself, the union must still cover the whole
        # goal. Without this, a plan could assign each node a trivially true assertion and
        # the goal would never actually be verified.
        node_criteria = {
            criterion.criterion_id: criterion
            for node in self.plan.nodes
            for criterion in node.acceptance_criteria
        }
        if node_criteria:
            missing = [
                criterion.criterion_id
                for criterion in self.goal.acceptance_criteria
                if criterion.criterion_id not in node_criteria
            ]
            if missing:
                raise SpecError(
                    "node-scoped acceptance criteria do not cover the goal: "
                    f"{sorted(missing)} would never be verified by any node"
                )

        # Meta-Spec may never be looser than SPEC-03: a protected path must not be
        # declared writable by the very boundary the agent controls.
        for node in self.plan.nodes:
            for artifact in node.expected_artifacts:
                if self.meta.is_protected(artifact):
                    raise SpecError(
                        f"plan node {node.node_id} claims an expected artifact "
                        f"{artifact!r} that Meta-Spec protects from agent writes"
                    )

    def canonical_form(self) -> dict[str, Any]:
        return {
            "spec_01_goal": self.goal.to_dict(),
            "spec_02_plan": self.plan.to_dict(),
            "spec_03_boundary": self.boundary.to_dict(),
            "meta_spec": self.meta.to_dict(),
        }

    def digest(self) -> str:
        """SPEC_DIGEST = SHA256(canonical(spec1 + spec2 + spec3 + metaspec)).

        Timestamps and owner metadata are excluded so that re-registering identical
        content yields an identical digest; version linkage is carried separately by
        `parent_spec_digest` (Spec §3.1).
        """
        goal = self.goal.to_dict()
        plan = self.plan.to_dict()
        boundary = self.boundary.to_dict()
        meta = self.meta.to_dict()
        for payload in (goal, plan, boundary, meta):
            payload.pop("created_at", None)
            payload.pop("owner_id", None)
        return digest_of(
            {
                "spec_01_goal": goal,
                "spec_02_plan": plan,
                "spec_03_boundary": boundary,
                "meta_spec": meta,
            }
        )

    def digest_short(self) -> str:
        return self.digest()[:12]

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.canonical_form(),
            "spec_version": self.spec_version,
            "owner_id": self.owner_id,
            "created_at": self.created_at,
            "parent_spec_digest": self.parent_spec_digest,
            "spec_digest": self.digest(),
        }

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "SpecBundle":
        bundle = SpecBundle(
            goal=GoalSpec.from_dict(raw["spec_01_goal"]),
            plan=PlanSpec.from_dict(raw["spec_02_plan"]),
            boundary=BoundarySpec.from_dict(raw["spec_03_boundary"]),
            meta=MetaSpec.from_dict(raw["meta_spec"]),
            spec_version=int(raw.get("spec_version", 1)),
            owner_id=str(raw.get("owner_id", "owner")),
            created_at=str(raw.get("created_at") or utc_now()),
            parent_spec_digest=str(raw.get("parent_spec_digest", "")),
        )
        bundle.validate()
        return bundle
