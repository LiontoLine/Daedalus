# ruff: noqa: RUF001
"""Cooperative stops and restart reminders. Reminders never dispatch work."""

from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from daedalus.domain.canonical import digest_of
from daedalus.domain.ids import new_id, utc_now
from daedalus.errors import DaedalusError
from daedalus.infrastructure.redact import redact_text

_STOP: ContextVar[threading.Event | None] = ContextVar("service_stop", default=None)
TERMINAL_RUNS = {"COMPLETED", "FAILED", "PARTIAL_FAILURE", "CANCELLED", "ROLLED_BACK"}
CHECKPOINT_KIND = "service_checkpoint"


@contextmanager
def cooperative_stop(signal: threading.Event):
    token = _STOP.set(signal)
    try:
        yield
    finally:
        _STOP.reset(token)


def stop_requested() -> bool:
    signal = _STOP.get()
    return signal is not None and signal.is_set()


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + new_id("write"))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output, ensure_ascii=False, allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def checkpoint(store, run_id: str) -> dict:
    """Read the actual DAG frontier. A parallel DAG has no single instruction pointer."""
    from daedalus.application.replay import run_repo_path
    from daedalus.infrastructure.git_sandbox import _git

    run = store.get_run(run_id)
    if run is None:
        raise DaedalusError("任务不存在")
    execution = str(run["execution_id"])
    events = store.events_for_execution(execution)
    steps = [dict(s) for s in store.list_steps(run_id) if str(s["execution_id"]) == execution]
    committed = {str(s["node_id"]) for s in steps if s["state"] == "COMMITTED"}
    receipts = [e for e in events if e.event_type in {"StepCommitted", "StepCacheHit"}]
    frontier = []
    for step in steps:
        deps = json.loads(step["deps"]) if isinstance(step["deps"], str) else step["deps"]
        if step["state"] in {"PENDING", "READY", "REVISE", "LOST"} and set(deps) <= committed:
            frontier.append(
                {
                    "step_id": step["step_id"],
                    "node_id": step["node_id"],
                    "state": step["state"],
                    "objective": step["objective"],
                }
            )
    if not steps:
        # Jobs cancelled before dispatch have a frozen plan but no declared step rows yet.
        # Reading the frontier must not create those rows or silently start the job.
        from daedalus.domain.spec import SpecBundle

        spec = store.get_spec(str(run["spec_digest"]))
        if spec:
            bundle = SpecBundle.from_dict(json.loads(str(spec["document"])))
            frontier = [
                {
                    "step_id": f"{run_id}:{node.node_id}",
                    "node_id": node.node_id,
                    "state": "PENDING",
                    "objective": node.objective,
                }
                for node in bundle.plan.nodes
                if not node.deps
            ]
    blockers = []
    if run["status"] in TERMINAL_RUNS:
        blockers.append("任务已经结束")
    if any(
        s["state"]
        in {
            "LEASED",
            "RUNNING",
            "AWAITING_GATEKEEPER",
            "TIER1_PASSED",
            "TIER2_REVIEWING",
            "APPROVED",
            "COMMITTING",
        }
        for s in steps
    ):
        blockers.append("存在未完成的执行或提交，请先检查恢复证据；不会跳过门禁或提交对账")
    repo = run_repo_path(store, run_id)
    head = ""
    if repo and (Path(repo) / ".git").exists() and run["branch"]:
        head = _git(
            Path(repo), ["rev-parse", "--verify", "refs/heads/" + str(run["branch"])], check=False
        ).stdout.strip()
    if not head:
        blockers.append("原仓库或集成分支不可用，需要人工恢复")
    from daedalus.application.independent_validation import pending_validation

    started = next((event.payload for event in events if event.event_type == "RunStarted"), {})
    if (
        store.events_for(f"goal:{run_id}") or started.get("goal_stage_parent")
    ) and not pending_validation(store, run_id):
        blockers.append(
            "目标审计或修复 stage 已有历史，需人工核对 stage；不会重置最多三轮的迭代预算"
        )
    facts = {
        "run_id": run_id,
        "execution_id": execution,
        "spec_digest": str(run["spec_digest"]),
        "status": str(run["status"]),
        "integration_head": head,
        "steps": [
            {k: s[k] for k in ("step_id", "node_id", "state", "attempt", "base_commit")}
            for s in steps
        ],
        "events": [
            e.event_id
            for e in events
            if not (e.event_type == "AuditNote" and e.payload.get("kind") == "recovery_review")
        ],
    }
    checkpoint_digest = digest_of(facts)
    return {
        "run_id": run_id,
        "execution_id": execution,
        "status": str(run["status"]),
        "checkpoint_digest": checkpoint_digest,
        "review_statement_digest": digest_of(
            {
                "purpose": "daedalus.recovery-review.v1",
                "run_id": run_id,
                "checkpoint": checkpoint_digest,
            }
        ),
        "integration_head": head,
        "last_verified_node": receipts[-1].step_id if receipts else "",
        "verified_nodes": sorted(committed),
        "frontier": frontier,
        "blockers": blockers,
        "review_required": requires_review(store, run_id),
        "automatic_resume": False,
    }


def requires_review(store, run_id: str) -> bool:
    run = store.get_run(run_id)
    if run is None or run["status"] in TERMINAL_RUNS:
        return False
    if run["status"] == "RUNNING":
        return True
    return any(
        e.event_type == "AuditNote" and e.payload.get("kind") == CHECKPOINT_KIND
        for e in store.events_for(f"run:{run_id}")
    )


def review_checkpoint(
    store,
    run_id: str,
    *,
    reviewed_by: str,
    checkpoint_digest: str,
    note: str = "",
    signature: str = "",
    identity=None,
) -> dict:
    from daedalus.application.identity import OwnerRegistry
    from daedalus.application.resume import load_manifest

    current = checkpoint(store, run_id)
    if current["blockers"]:
        raise DaedalusError("；".join(current["blockers"]))
    if not reviewed_by.strip() or len(reviewed_by) > 128:
        raise DaedalusError("请填写人工审查者名称")
    if checkpoint_digest != current["checkpoint_digest"]:
        raise DaedalusError("恢复节点或证据已变化，请刷新后重新审查")
    manifest = load_manifest(store, run_id)
    claim = digest_of(
        {
            "purpose": "daedalus.recovery-review.v1",
            "run_id": run_id,
            "checkpoint": checkpoint_digest,
        }
    )
    registry = identity or OwnerRegistry.for_store(store)
    outcome = registry.authorise(
        approved_by=reviewed_by,
        spec_digest=claim,
        risk=manifest.bundle.goal.risk_level,
        signature=signature,
    )
    payload = {
        "kind": "recovery_review",
        "checkpoint_digest": checkpoint_digest,
        "reviewed_by": outcome.owner_id,
        "note": redact_text(note)[:2000],
        "verified": outcome.verified,
        "statement_digest": claim,
    }
    store.append(
        aggregate_id=f"run:{run_id}",
        execution_id=manifest.execution_id,
        event_type="AuditNote",
        actor=outcome.owner_id,
        payload=payload,
    )
    return {**payload, "automatic_resume": False}


def assert_checkpoint_reviewed(store, run_id: str, *, identity=None) -> None:
    if not requires_review(store, run_id):
        return
    current = checkpoint(store, run_id)
    if current["blockers"]:
        raise DaedalusError("；".join(current["blockers"]))
    reviews = [
        e
        for e in store.events_for(f"run:{run_id}")
        if e.event_type == "AuditNote" and e.payload.get("kind") == "recovery_review"
    ]
    if not reviews or reviews[-1].payload.get("checkpoint_digest") != current["checkpoint_digest"]:
        raise DaedalusError("中断任务需要先人工审查当前恢复节点；启动提醒不会自动恢复任务")
    from daedalus.application.identity import OwnerRegistry

    if (identity or OwnerRegistry.for_store(store)).enforced and not reviews[-1].payload.get(
        "verified"
    ):
        raise DaedalusError("当前工作区要求可核验的人工审查签名，请重新审查")


class ServiceLifecycle:
    def __init__(self, store, workspace: Path):
        self.store = store
        self.path = workspace / ".service" / "session.json"
        self.session_id = new_id("session")
        self.lock = threading.RLock()
        try:
            self.previous = json.loads(self.path.read_text())
        except (OSError, ValueError):
            self.previous = {}
        self.record = {
            "session_id": self.session_id,
            "started_at": utc_now(),
            "status": "running",
            "note": "",
            "automatic_resume": False,
        }
        self.startup_runs = [
            str(r["run_id"]) for r in store.list_runs() if r["status"] not in TERMINAL_RUNS
        ]
        for run_id in self.startup_runs:
            self.mark_checkpoint(run_id, "上次会话未完成；本次启动仅提醒，等待人工审查")
        atomic_json(self.path, self.record)

    def mark_checkpoint(self, run_id: str, note: str):
        run = self.store.get_run(run_id)
        if run and run["status"] not in TERMINAL_RUNS:
            self.store.append(
                aggregate_id=f"run:{run_id}",
                execution_id=str(run["execution_id"]),
                event_type="AuditNote",
                actor="service",
                payload={
                    "kind": CHECKPOINT_KIND,
                    "session_id": self.session_id,
                    "note": redact_text(note)[:2000],
                    "automatic_resume": False,
                },
            )

    def stopping(self, note: str = "用户关闭服务"):
        with self.lock:
            if self.record["status"] != "running":
                return
            self.record.update(
                status="stopping", note=redact_text(note)[:2000], stop_requested_at=utc_now()
            )
            for run in self.store.list_runs():
                self.mark_checkpoint(str(run["run_id"]), self.record["note"])
                if (
                    run["status"] not in TERMINAL_RUNS
                    and str(run["run_id"]) not in self.startup_runs
                ):
                    self.startup_runs.append(str(run["run_id"]))
            atomic_json(self.path, self.record)

    def stopped(self):
        with self.lock:
            self.record["unfinished_runs"] = [
                str(r["run_id"]) for r in self.store.list_runs() if r["status"] not in TERMINAL_RUNS
            ]
            if self.record["unfinished_runs"] or not self.store.path.is_file():
                # Use the LIVE connection: reopening a deleted /tmp pathname caused the
                # old backup endpoint's 409. The snapshot is evidence, never an auto-restore.
                import sqlite3

                from daedalus.application.backup import _verify

                snapshot = self.path.parent / "checkpoints" / (self.session_id + ".sqlite")
                snapshot.parent.mkdir(parents=True, exist_ok=True)
                with sqlite3.connect(snapshot) as destination:
                    self.store.connection.backup(destination)
                snapshot.chmod(0o600)
                if not _verify(snapshot).verified:
                    raise DaedalusError("断点数据库副本未通过一致性检查，不能报告保存成功")
                self.record["checkpoint_snapshot"] = str(snapshot)
            self.record.update(status="stopped", stopped_at=utc_now(), checkpoint_saved=True)
            atomic_json(self.path, self.record)

    def describe(self, active=()) -> dict:
        return {
            **self.record,
            "previous_session": self.previous,
            "reminders": [
                checkpoint(self.store, run_id)
                for run_id in self.startup_runs
                if (run := self.store.get_run(run_id))
                and run["status"] not in TERMINAL_RUNS
                and run_id not in active
            ],
            "policy": "启动仅提醒；中断任务需人工审查后显式继续",
        }
