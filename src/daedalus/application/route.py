"""The run route: what actually happened, attempt by attempt (Spec §4, §14, §16).

The console used to draw the *plan* — one box per SPEC-02 node, coloured by the step's current
state. That answers "what is the plan?" and not "what happened?", and the difference matters
exactly when an operator is trying to understand a run that went wrong: a node that was
retried four times, rebased once and parked for an hour looked like a single box.

This module derives the real route from the **event log**, which is the authority. Every
`StepLeaseAcquired` opens an attempt; the events that follow belong to it until the next lease
or until the step settles. Everything else — plans, projections, gate rows — is attached to
those attempts rather than used to invent them.

Two rules shape the model:

* **An attempt is the unit.** A retry is a new box, not a counter on an old one, because a
  retry is a new candidate with its own artifact, its own gate verdict and its own failure.
* **A node only offers actions that would succeed.** The catalog is computed here, next to the
  FSM and approval rules that decide it, rather than in JavaScript where a button that returns
  400 is a normal outcome. An action that is unavailable comes with the reason it is
  unavailable, because "why can I not retry this?" is the question the graph exists to answer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from daedalus.domain.fsm import LEASE_HOLDING_STATES, StepState
from daedalus.infrastructure.store.event_store import EventStore

#: Run-level events that belong on the route as their own node rather than inside an attempt.
#: They are the moments where the control plane did something a step did not ask for.
_STANDALONE_EVENTS: dict[str, str] = {
    "RunCreated": "run",
    "RunStarted": "run",
    "RunRebaseRequired": "rebase",
    "RunEscalated": "park",
    "RunResumed": "resume",
    "RunRolledBack": "rollback",
    "RunCompleted": "end",
    "RunFailed": "end",
    "RunPartiallyFailed": "end",
    "RunCancelled": "end",
    "StepMarkedStale": "stale",
}

#: The events that end an attempt, in the sense that no further work happens under that lease.
_ATTEMPT_CLOSERS = frozenset(
    {
        "StepCommitted",
        "StepExecutionFailed",
        "StepRejected",
        "StepCancelled",
        "StepSuperseded",
        "StepLeaseExpired",
        "StepMarkedStale",
        "StepCacheHit",
    }
)

_SEVERITY = {
    "StepCommitted": "ok",
    "StepCacheHit": "ok",
    "StepTier1Decided": "gate",
    "StepTier2Decided": "gate",
    "StepExecutionFailed": "bad",
    "StepRejected": "bad",
    "StepLeaseExpired": "bad",
    "StepMarkedStale": "warn",
    "StepSuperseded": "warn",
    "ApprovalRecorded": "human",
}


@dataclass
class RouteNode:
    """One box on the route: an attempt, or a control-plane moment."""

    key: str
    kind: str
    lane: int
    order: int
    label: str
    state: str = ""
    detail: str = ""
    step_id: str = ""
    plan_node_id: str = ""
    attempt: int = 0
    actor: str = ""
    worker_id: str = ""
    started_at: str = ""
    ended_at: str = ""
    event_id: str = ""
    event_type: str = ""
    artifact_digest: str = ""
    changed_files: tuple[str, ...] = ()
    patch_digest: str = ""
    gate_tier1: str = ""
    gate_tier2: str = ""
    cache_source: str = ""
    failure: str = ""
    events: tuple[dict[str, Any], ...] = ()
    actions: tuple[dict[str, Any], ...] = ()

    def to_payload(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "lane": self.lane,
            "order": self.order,
            "label": self.label,
            "state": self.state,
            "detail": self.detail,
            "step_id": self.step_id,
            "plan_node_id": self.plan_node_id,
            "attempt": self.attempt,
            "actor": self.actor,
            "worker_id": self.worker_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "artifact_digest": self.artifact_digest,
            "changed_files": list(self.changed_files),
            "patch_digest": self.patch_digest,
            "gate_tier1": self.gate_tier1,
            "gate_tier2": self.gate_tier2,
            "cache_source": self.cache_source,
            "failure": self.failure,
            "events": [dict(event) for event in self.events],
            "actions": [dict(action) for action in self.actions],
        }


@dataclass
class RouteEdge:
    source: str
    target: str
    kind: str
    label: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {"from": self.source, "to": self.target, "kind": self.kind, "label": self.label}


@dataclass
class RunRoute:
    run_id: str
    execution_id: str
    status: str
    nodes: list[RouteNode] = field(default_factory=list)
    edges: list[RouteEdge] = field(default_factory=list)
    lanes: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "execution_id": self.execution_id,
            "status": self.status,
            "nodes": [node.to_payload() for node in self.nodes],
            "edges": [edge.to_payload() for edge in self.edges],
            "lanes": self.lanes,
            "notes": self.notes,
        }


def build_route(store: EventStore, run_id: str) -> RunRoute:
    """Reconstruct the route one run actually took, from the event log."""
    run = store.get_run(run_id)
    if run is None:
        raise KeyError(run_id)
    execution_id = str(run["execution_id"])
    bundle = store.get_spec(str(run["spec_digest"]))

    lane_of, lanes = _lanes(run_id, bundle, store)
    # This run's events, plus the spec events for its goal (which carry no execution id
    # because a sign-off belongs to no execution). `all_events()` is already in global
    # sequence order, which is the only ordering that is meaningful across aggregates —
    # `sequence` restarts at 1 for every aggregate, so sorting on it interleaves runs.
    goal_id = str(bundle["goal_id"]) if bundle is not None else ""
    spec_aggregate = f"spec:{goal_id}" if goal_id else ""
    events = [
        event
        for event in store.all_events()
        if event.execution_id == execution_id
        or (spec_aggregate and event.aggregate_id == spec_aggregate)
    ]

    route = RunRoute(
        run_id=run_id,
        execution_id=execution_id,
        status=str(run["status"]),
    )
    route.lanes = lanes

    attempts: dict[tuple[str, int], RouteNode] = {}
    current: dict[str, RouteNode] = {}
    order = 0
    for event in events:
        order += 1
        node_id = _plan_node_of(event)
        kind = _STANDALONE_EVENTS.get(event.event_type)
        if event.event_type == "StepLeaseAcquired":
            attempt = int(event.payload.get("attempt", 0) or 0)
            node = RouteNode(
                key=f"{node_id}#{attempt}",
                kind="attempt",
                lane=lane_of.get(node_id, 0),
                order=order,
                label=f"{node_id} · try {attempt}",
                plan_node_id=node_id,
                step_id=event.step_id,
                attempt=attempt,
                actor=str(event.actor),
                worker_id=str(event.payload.get("worker_id", "") or event.actor),
                started_at=event.timestamp,
                event_id=event.event_id,
            )
            attempts[(node_id, attempt)] = node
            route.nodes.append(node)
            current[node_id] = node
            continue

        if kind is not None and not event.aggregate_id.startswith("step:"):
            route.nodes.append(
                RouteNode(
                    key=f"{kind}-{order}",
                    kind="event",
                    lane=-1,
                    order=order,
                    label=_label_for(event.event_type, event.payload),
                    state=kind,
                    detail=_detail_for(event.event_type, event.payload),
                    actor=str(event.actor),
                    started_at=event.timestamp,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    events=(_event_row(event),),
                )
            )
            continue

        node = current.get(node_id) if node_id else None
        if node is None:
            # A step event with no lease (declaration, staleness before any attempt). Shown so
            # the route does not silently drop a fact, but not as an attempt.
            if event.aggregate_id.startswith("step:"):
                route.nodes.append(
                    RouteNode(
                        key=f"{event.event_type}-{order}",
                        kind="event",
                        lane=lane_of.get(node_id, 0),
                        order=order,
                        label=_label_for(event.event_type, event.payload),
                        state=_SEVERITY.get(event.event_type, "info"),
                        plan_node_id=node_id,
                        step_id=event.step_id,
                        actor=str(event.actor),
                        started_at=event.timestamp,
                        event_id=event.event_id,
                        event_type=event.event_type,
                        events=(_event_row(event),),
                    )
                )
            continue

        _absorb(node, event)
        if event.event_type == "ApprovalRecorded":
            # The human answer belongs to the attempt it answered, and is worth its own box so
            # "who unblocked this, and when" is visible on the route rather than only in a list.
            route.nodes.append(
                RouteNode(
                    key=f"approval-{order}",
                    kind="event",
                    lane=node.lane,
                    order=order,
                    label=f"owner {event.payload.get('decision', '?')}",
                    state="human",
                    detail=str(event.payload.get("approved_by", "")),
                    plan_node_id=node_id,
                    step_id=node.step_id,
                    actor=str(event.payload.get("approved_by", "")),
                    started_at=event.timestamp,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    events=(_event_row(event),),
                )
            )
        if event.event_type in _ATTEMPT_CLOSERS:
            node.ended_at = event.timestamp
            current.pop(node_id, None)

    _attach_edges(route, attempts, store, run_id)
    # Outcomes first: whether a rollback is offered depends on whether the attempt produced an
    # artifact, so the catalog has to be computed after the artifacts are attached.
    _attach_outcomes(store, route, attempts, run_id)
    _attach_actions(route, attempts, store, run_id, str(run["status"]))
    if not any(node.kind == "attempt" for node in route.nodes):
        route.notes.append(
            "no step has been attempted yet, so the route has no execution boxes. "
            "The run has been accepted; the first attempt appears here when it starts."
        )
    return route


def _lanes(run_id: str, bundle: Any, store: EventStore) -> tuple[dict[str, int], list[dict]]:
    """One lane per plan node, in plan order, plus a lane for control-plane moments.

    Lanes are what make a retry readable: successive attempts of one step stay on the same
    row and extend to the right, so "how many times did this step run, and how did each end"
    is a glance rather than a search.
    """
    lane_of: dict[str, int] = {}
    #: The control-plane track is lane -1, which is what the event nodes carry. Labelling it 0
    #: made the console draw an empty step row for it and leave the track unlabelled.
    lanes: list[dict] = [{"index": -1, "node_id": "", "label": "控制面"}]
    nodes = []
    if bundle is not None:
        import json as _json

        document = bundle.get("document") or "{}"
        try:
            parsed = _json.loads(str(document))
            nodes = list((parsed.get("spec_02_plan") or {}).get("nodes") or [])
        except ValueError:
            nodes = []
    if not nodes:
        nodes = [
            {"node_id": str(row["node_id"]), "objective": str(row.get("objective", ""))}
            for row in store.list_steps(run_id)
        ]
    for index, node in enumerate(nodes, start=1):
        node_id = str(node.get("node_id", ""))
        lane_of[node_id] = index
        objective = str(node.get("objective", "") or "")
        lanes.append(
            {
                "index": index,
                "node_id": node_id,
                "label": f"{node_id} · {objective}" if objective else node_id,
            }
        )
    for row in store.list_steps(run_id):
        node_id = str(row["node_id"])
        if node_id not in lane_of:
            lane_of[node_id] = len(lanes)
            lanes.append({"index": lane_of[node_id], "node_id": node_id, "label": node_id})
    return lane_of, lanes


def _plan_node_of(event: Any) -> str:
    if not event.aggregate_id.startswith("step:"):
        return ""
    return str(event.payload.get("node_id", "") or event.aggregate_id.removeprefix("step:").split(":")[-1])


def _label_for(event_type: str, payload: dict[str, Any]) -> str:
    """A short human label for a control-plane moment, in the console's language.

    Kept next to the event names rather than in the template: the label is part of what the
    event *means*, and a missing entry here should be visible as the raw event type rather than
    as an empty box.
    """
    return {
        "RunCreated": "已受理",
        "RunStarted": "运行开始",
        "RunRebaseRequired": "需要重基",
        "RunEscalated": "停车等待审批",
        "RunResumed": "续跑",
        "RunRolledBack": "已回滚",
        "RunCompleted": "运行完成",
        "RunFailed": "运行失败",
        "RunPartiallyFailed": "部分失败",
        "RunCancelled": "已取消",
        "StepDeclared": "已声明",
        "StepActivated": "就绪",
        "StepRecovered": "已恢复",
        "StepMarkedStale": "标记失效",
        "ApprovalRecorded": "owner 决定",
    }.get(event_type, event_type)


def _detail_for(event_type: str, payload: dict[str, Any]) -> str:
    for key in ("reason", "status", "note", "summary", "commit", "to_commit"):
        if payload.get(key):
            return str(payload[key])
    return ""


def _event_row(event: Any) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "timestamp": event.timestamp,
        "actor": event.actor,
        "severity": _SEVERITY.get(event.event_type, "info"),
        "summary": _summarise(event),
    }


#: What a gate decision or a failure outcome means as a step state.
_OUTCOME_STATES: dict[str, str] = {
    "PASS": StepState.TIER1_PASSED.value,
    "APPROVE": StepState.APPROVED.value,
    "REVISE": StepState.REVISE.value,
    "ESCALATE": StepState.ESCALATED.value,
    "FAILED": StepState.FAILED.value,
    "FAIL": StepState.FAILED.value,
    "TIMEOUT": StepState.TIMEOUT.value,
    "LOST": StepState.LOST.value,
    "STALE": StepState.STALE.value,
    "CANCELLED": StepState.CANCELLED.value,
    "SUPERSEDED": StepState.SUPERSEDED.value,
    "COMMITTED": StepState.COMMITTED.value,
    "REJECT": StepState.ESCALATED.value,
}


def _verdict(value: Any) -> str:
    return str(value or "").strip().upper()


def _state_from_outcome(value: Any) -> str:
    return _OUTCOME_STATES.get(_verdict(value), StepState.REVISE.value)


def _summarise(event: Any) -> str:
    payload = dict(event.payload)
    for key in ("reason", "detail", "summary", "decision", "status", "commit", "outcome"):
        if payload.get(key):
            return f"{key}={payload[key]}"
    return event.event_type


def _absorb(node: RouteNode, event: Any) -> None:
    """Fold one event into the attempt that was running when it happened."""
    payload = dict(event.payload)
    node.events = (*node.events, _event_row(event))
    node.ended_at = event.timestamp
    if event.event_type == "StepStarted":
        node.state = StepState.RUNNING.value
    elif event.event_type == "StepGatekeeperEntered":
        node.state = StepState.AWAITING_GATEKEEPER.value
    elif event.event_type == "StepTier1Decided":
        # The verdict is `outcome` in the event (lowercase); `decision` is the field name used
        # elsewhere. Normalised to upper case so the console never shows "pass" beside "PASS".
        node.gate_tier1 = _verdict(payload.get("decision") or payload.get("outcome"))
        # A tier-1 REVISE is not "tier-1 passed". The state after the decision is what the gate
        # decided, not the fact that the gate ran.
        if node.gate_tier1 == "PASS":
            node.state = StepState.TIER1_PASSED.value
        else:
            node.state = StepState.REVISE.value
            node.failure = node.failure or str(payload.get("reason", "") or "")
        node.detail = node.detail or str(payload.get("reason", "") or "")
    elif event.event_type == "StepTier2Decided":
        node.gate_tier2 = _verdict(
            payload.get("effective_decision") or payload.get("reviewer_decision")
        )
        if node.gate_tier2 == "APPROVE":
            node.state = StepState.APPROVED.value
        elif node.gate_tier2 == "ESCALATE":
            node.state = StepState.ESCALATED.value
        else:
            node.state = StepState.REVISE.value
        if payload.get("overridden_by_policy"):
            node.detail = node.detail or "policy forced an escalation over the reviewer"
    elif event.event_type == "StepCommitRequested":
        node.state = StepState.COMMITTING.value
    elif event.event_type == "StepCommitted":
        node.state = StepState.COMMITTED.value
        node.detail = str(payload.get("commit", "") or "")
    elif event.event_type == "StepCacheHit":
        node.state = StepState.COMMITTED.value
        node.cache_source = str(payload.get("source_artifact_digest", "") or "")
        node.detail = "reused a verified artifact"
    elif event.event_type == "StepLeaseExpired":
        node.state = StepState.LOST.value
        node.failure = str(payload.get("reason", "") or "lease expired")
    elif event.event_type == "StepMarkedStale":
        node.state = StepState.STALE.value
        node.failure = str(payload.get("reason", "") or "the plan moved")
    elif event.event_type == "StepSuperseded":
        node.state = StepState.SUPERSEDED.value
    elif event.event_type in {"StepExecutionFailed"}:
        # `outcome` is a bare verb ("escalate", "revise"), not a StepState name. Mapping it
        # through one table is what keeps the route's states comparable with the projections.
        node.state = _state_from_outcome(payload.get("outcome"))
        node.failure = str(payload.get("reason", "") or payload.get("failure", "") or "")
    elif event.event_type == "StepRejected":
        node.state = StepState.ESCALATED.value
        node.failure = str(payload.get("reason", "") or "rejected by an owner")
    elif event.event_type == "ApprovalRecorded":
        decision = str(payload.get("decision", ""))
        if decision == "retry":
            node.state = StepState.ESCALATED.value
            node.failure = str(payload.get("note", "") or node.failure)
    elif event.event_type in {"StepApproved", "StepActivated", "StepRecovered"}:
        node.state = node.state or StepState.READY.value


def _attach_edges(
    route: RunRoute,
    attempts: dict[tuple[str, int], RouteNode],
    store: EventStore,
    run_id: str,
) -> None:
    spine = sorted(route.nodes, key=lambda node: node.order)
    for previous, following in zip(spine, spine[1:]):
        route.edges.append(RouteEdge(previous.key, following.key, "route"))

    by_step: dict[str, list[RouteNode]] = {}
    for (node_id, _attempt), node in attempts.items():
        by_step.setdefault(node_id, []).append(node)
    for nodes in by_step.values():
        ordered = sorted(nodes, key=lambda node: node.attempt)
        for previous, following in zip(ordered, ordered[1:]):
            # A second attempt exists because the first was revised, lost or rejected — the
            # edge says *why*, which is the whole reason retries get their own boxes. The
            # gate verdict or the recorded failure is the useful label; the bare state name
            # ("REVISE") only restates that something went wrong.
            reason = previous.gate_tier1 or previous.gate_tier2 or previous.state or "REVISE"
            if previous.failure:
                reason = f"{reason}: {previous.failure[:60]}"
            route.edges.append(RouteEdge(previous.key, following.key, "retry", reason))

    # Dependency edges: the attempt that satisfied a dependency to the first attempt of the
    # node that waited on it.
    bundle = store.get_spec(str(store.get_run(run_id)["spec_digest"]))
    if bundle is None:
        return
    import json as _json

    try:
        document = _json.loads(str(bundle.get("document") or "{}"))
    except ValueError:
        return
    deps = {
        str(node.get("node_id")): [str(dep) for dep in node.get("deps") or []]
        for node in (document.get("spec_02_plan") or {}).get("nodes") or []
    }
    for node_id, parents in deps.items():
        children = by_step.get(node_id)
        if not children:
            continue
        target = min(children, key=lambda node: node.attempt)
        for parent in parents:
            parents_nodes = by_step.get(parent) or []
            committed = [n for n in parents_nodes if n.state == StepState.COMMITTED.value]
            source = (committed or parents_nodes or [None])[-1]
            if source is not None:
                route.edges.append(RouteEdge(source.key, target.key, "dep", parent))


def _attach_outcomes(
    store: EventStore,
    route: RunRoute,
    attempts: dict[tuple[str, int], RouteNode],
    run_id: str,
) -> None:
    """Attach the artifact and gate rows each attempt produced."""
    for row in store.list_steps(run_id):
        step_id = str(row["step_id"])
        artifacts = store.artifacts_for_step(step_id)
        gates = store.gate_results_for_step(step_id)
        for node in [n for n in route.nodes if n.step_id == step_id and n.kind == "attempt"]:
            artifact = _artifact_for_attempt(artifacts, node.attempt)
            if artifact is not None:
                node.artifact_digest = str(artifact["artifact_digest"])
                try:
                    import json as _json

                    node.changed_files = tuple(
                        _json.loads(str(artifact["changed_files"] or "[]"))
                    )
                except ValueError:
                    node.changed_files = ()
                node.patch_digest = str(artifact["patch_digest"] or "")
            tier1 = [g for g in gates if int(g["tier"]) == 1]
            tier2 = [g for g in gates if int(g["tier"]) == 2]
            if tier1 and not node.gate_tier1:
                node.gate_tier1 = str(tier1[-1]["decision"])
            if tier2 and not node.gate_tier2:
                node.gate_tier2 = str(tier2[-1]["decision"])
            if not node.failure and node.state in {
                StepState.FAILED.value,
                StepState.TIMEOUT.value,
                StepState.REVISE.value,
                StepState.LOST.value,
            }:
                node.failure = str(row["last_failure"] or "")


def _artifact_for_attempt(artifacts: list[dict[str, Any]], attempt: int) -> dict[str, Any] | None:
    """The artifact an attempt produced, matched on the attempt recorded inside its document.

    Matching on the attempt rather than on order matters when an attempt produced no artifact
    at all (a boundary refusal): positional matching would then attribute attempt 2's artifact
    to attempt 1.
    """
    import json as _json

    for artifact in artifacts:
        try:
            document = _json.loads(str(artifact["document"]))
        except ValueError:
            continue
        extra = document.get("extra", {}) if isinstance(document, dict) else {}
        if int(extra.get("attempt", 0) or 0) == attempt:
            return artifact
    return artifacts[-1] if artifacts and attempt == len(artifacts) else None


def _attach_actions(
    route: RunRoute,
    attempts: dict[tuple[str, int], RouteNode],
    store: EventStore,
    run_id: str,
    run_status: str,
) -> None:
    """Work out, per node, which actions would actually succeed.

    Computed here because the rules are here: the FSM decides what is retryable, the approval
    service decides what may be approved, and the rollback service decides what may be rolled
    back. A console that guesses produces buttons whose only outcome is an error message.
    """
    steps = {str(row["step_id"]): row for row in store.list_steps(run_id)}
    latest: dict[str, RouteNode] = {}
    for node in route.nodes:
        if node.kind != "attempt":
            continue
        previous = latest.get(node.plan_node_id)
        if previous is None or node.attempt >= previous.attempt:
            latest[node.plan_node_id] = node

    for node in route.nodes:
        if node.kind != "attempt":
            continue
        actions: list[dict[str, Any]] = [
            {
                "id": "detail",
                "label": "查看详细",
                "enabled": True,
                "reason": "",
            }
        ]
        row = steps.get(node.step_id)
        state = str(row["state"]) if row else node.state
        is_latest = latest.get(node.plan_node_id) is node

        retry_reason = ""
        if not is_latest:
            retry_reason = "已被后续尝试取代；只有最新一次尝试可以处置"
        elif state == StepState.ESCALATED.value:
            retry_reason = ""
        elif state in {StepState.LOST.value, StepState.STALE.value}:
            retry_reason = "先运行 recover 修复工作区，再 resume；该步骤会被重新调度"
        elif state in {StepState.FAILED.value, StepState.TIMEOUT.value}:
            retry_reason = "已达尝试上限，属于终态；需要回滚到该节点之前再重放"
        elif state == StepState.COMMITTED.value:
            retry_reason = "已提交；重跑会修改已落地的历史"
        elif state in LEASE_HOLDING_STATES:
            retry_reason = "正在执行中"
        else:
            retry_reason = f"{state} 状态下不可重试"

        actions.append(
            {
                "id": "retry",
                "label": "重试",
                "enabled": not retry_reason,
                "reason": retry_reason,
                "requires_signature": bool(
                    not retry_reason and _needs_signature(store, row)
                ),
            }
        )
        reject_reason = (
            "" if state == StepState.ESCALATED.value and is_latest
            else "只有处于 ESCALATED 的最新尝试可以被打回"
        )
        actions.append(
            {
                "id": "reject",
                "label": "打回",
                "enabled": not reject_reason,
                "reason": reject_reason,
                # Stopping work needs no signature, exactly as in the service: putting a key in
                # front of the safe answer pushes operators toward approving instead.
                "requires_signature": False,
            }
        )

        rollback_reason = ""
        if not node.artifact_digest and state != StepState.COMMITTED.value:
            rollback_reason = "该尝试没有产出 artifact，没有可回滚到的提交点"
        elif run_status in {"CANCELLED"}:
            rollback_reason = "运行已取消"
        actions.append(
            {
                "id": "rollback",
                "label": "回滚到此处",
                "enabled": not rollback_reason,
                "reason": rollback_reason,
                # Rolling back to an attempt means landing on the commit it started from.
                "to_commit": str(row["base_commit"]) if row else "",
            }
        )
        node.actions = tuple(actions)


def _needs_signature(store: EventStore, row: dict[str, Any] | None) -> bool:
    if row is None:
        return False
    spec = store.get_spec(str(row.get("spec_digest") or ""))
    if spec is None:
        return False
    return str(spec["risk_level"]) in {"high", "critical"}
