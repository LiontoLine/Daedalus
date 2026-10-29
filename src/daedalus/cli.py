"""Daedalus command line.

The CLI is an interface to the control plane, not a second implementation of it. Every
subcommand either reads projections or drives the orchestrator; nothing here writes
SQLite or Git directly (the same rule AgentPanelX enforces on its Skills).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from daedalus import __version__
from dataclasses import replace

from daedalus.errors import DaedalusError
from daedalus.config import Settings
from daedalus.domain.approval import ApprovalDecision
from daedalus.application.coding_worker import FileOp, ModelWorker, ScriptedWorker
from daedalus.application.gatekeeper.tier2 import Tier2Gate
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import (
    DeterministicPlanner,
    ModelPlanner,
    PlanRequest,
)
from daedalus.application.scheduler import Quota, summarize_steps
from daedalus.domain.spec import (
    AcceptanceCriterion,
    PlanSpec,
    AssertionKind,
    MetaSpec,
    NetworkPolicy,
    RiskLevel,
    SpecBundle,
)
from daedalus.infrastructure.git_sandbox import GitSandbox, init_repo, initial_commit
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Message, ModelRegistry, TokenBudget
from daedalus.model.mock import ScriptedModelClient
from daedalus.model.openai_compatible import OpenAICompatibleClient
from daedalus.security.secrets import SecretBroker


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="daedalus",
        description=(
            "Deterministic control plane for model-driven delivery. "
            "Uncertain capability goes in; verified, auditable commits come out."
        ),
    )
    parser.add_argument("--version", action="version", version=f"daedalus {__version__}")
    parser.add_argument("--config", dest="console_config", default="", help="terminal console configuration")
    parser.add_argument("--open", dest="console_open", action="store_true", help="also open the web workspace")
    parser.add_argument("--restart", dest="console_restart", action="store_true", help="gracefully restart Daedalus on the same port before entering the console")
    sub = parser.add_subparsers(dest="command", required=False)

    demo = sub.add_parser("demo", help="run the six-scenario Phase-1 closed-loop demo")
    demo.add_argument("scenarios", nargs="*", help="scenario names to run (default: all)")
    demo.add_argument("--keep", action="store_true", help="keep the temporary workspace")

    run = sub.add_parser("run", help="run a task against a Git repository")
    run.add_argument("--repo", required=True, help="path to the target repository")
    run.add_argument("--goal", required=True, help="the objective, in one sentence")
    run.add_argument("--goal-id", default="GOAL-001")
    run.add_argument("--path", action="append", required=True, help="writable path glob")
    run.add_argument("--test-command", required=True, help="the acceptance test command")
    run.add_argument(
        "--workspace",
        default="",
        help="where Daedalus keeps its database and worktrees (default: a temp dir)",
    )
    run.add_argument("--model", default="", help="OpenAI-compatible model name (enables a real coder)")
    run.add_argument("--base-url", default="https://api.openai.com/v1")
    run.add_argument("--review", action="store_true", help="enable Tier-2 semantic review")
    run.add_argument(
        "--risk",
        default="normal",
        choices=[level.value for level in RiskLevel],
    )
    run.add_argument("--max-attempts", type=int, default=3)
    run.add_argument("--max-parallel", type=int, default=2)
    run.add_argument(
        "--spec-signature",
        default="",
        help="hex signature over the frozen spec digest; required for high/critical once "
        "owners are enrolled",
    )
    run.add_argument(
        "--approve-spec-by",
        default="",
        help="sign off this spec as the named owner before running (high/critical risk)",
    )
    run.add_argument(
        "--plan-only",
        action="store_true",
        help="freeze the spec and validate it against the boundary without executing steps",
    )

    specs = sub.add_parser("specs", help="list the frozen specs in the registry")
    specs.add_argument("--workspace", required=True)

    status = sub.add_parser("status", help="show runs and step states from the event store")
    status.add_argument("--workspace", required=True)
    status.add_argument("--run-id", default="")

    timeline = sub.add_parser("timeline", help="print one run's timeline")
    timeline.add_argument("--workspace", required=True)
    timeline.add_argument("--run-id", default="")

    verify = sub.add_parser("verify", help="check sequence integrity and replay agreement")
    verify.add_argument("--workspace", required=True)

    executions = sub.add_parser(
        "executions", help="list executions (Spec §19): one row per bounded unit of work"
    )
    executions.add_argument("--workspace", required=True)
    executions.add_argument("--run-id", default="")

    workers = sub.add_parser("workers", help="list workers and the steps they ran (Spec §19)")
    workers.add_argument("--workspace", required=True)

    metrics = sub.add_parser("metrics", help="print the Spec §15 metric set")
    metrics.add_argument("--workspace", required=True)

    audit = sub.add_parser("audit", help="answer the Spec §27 audit questions for one run")
    audit.add_argument("--workspace", required=True)
    audit.add_argument("--run-id", default="")

    step_log = sub.add_parser(
        "step-log", help="resolve an artifact's execution_log_ref into the events it names"
    )
    step_log.add_argument("--workspace", required=True)
    step_log.add_argument("--run-id", default="")
    step_log.add_argument("--step", required=True, help="step id or node id")
    step_log.add_argument("--json", action="store_true", help="emit JSONL instead of a table")

    rollback = sub.add_parser(
        "rollback", help="stop a run without deleting anything (Spec §12.1)"
    )
    rollback.add_argument("--workspace", required=True)
    rollback.add_argument("--run-id", default="")
    rollback.add_argument("--reason", required=True)
    rollback.add_argument(
        "--to-commit", default="", help="the commit the replay should start from"
    )

    replay = sub.add_parser(
        "replay", help="re-run a frozen spec from a commit, reusing verified artifacts"
    )
    replay.add_argument("--workspace", required=True)
    replay.add_argument("--run-id", default="")
    replay.add_argument("--reason", default="replay requested by the owner")
    replay.add_argument("--model", default="", help="coder for cache misses")
    replay.add_argument("--base-url", default="https://api.openai.com/v1")
    replay.add_argument(
        "--no-reuse",
        action="store_true",
        help="disable artifact reuse and execute every step again",
    )
    replay.add_argument(
        "--rollback-first",
        action="store_true",
        help="roll the source run back before starting the replay",
    )

    init = sub.add_parser("init", help="write a documented daedalus.toml")
    init.add_argument("--path", default="daedalus.toml")
    init.add_argument("--force", action="store_true")
    init.add_argument("--workspace", default="./.daedalus")

    config = sub.add_parser("config", help="show effective configuration and where it came from")
    config.add_argument("--config", default="")
    config.add_argument("--workspace", default="")

    escalate = sub.add_parser(
        "escalations", help="list escalated steps waiting for an owner decision"
    )
    escalate.add_argument("--config", default="")
    escalate.add_argument("--workspace", default="")
    escalate.add_argument("--run-id", default="")

    approve = sub.add_parser("approve", help="answer an escalation (proceed / retry / reject)")
    approve.add_argument("--config", default="")
    approve.add_argument("--workspace", default="")
    approve.add_argument("--run-id", required=True)
    approve.add_argument("--step", required=True, help="step id or node id")
    approve.add_argument(
        "--decision", required=True, choices=[d.value for d in ApprovalDecision]
    )
    approve.add_argument("--by", required=True, help="who is approving (goes in the audit)")
    approve.add_argument("--note", default="")
    approve.add_argument("--artifact", default="", help="artifact digest to authorise")
    approve.add_argument("--grant-attempts", type=int, default=0)
    approve.add_argument(
        "--signature",
        default="",
        help="hex signature over this decision; required for proceed/retry on HIGH or "
        "CRITICAL steps once owners are enrolled",
    )

    approve_spec = sub.add_parser(
        "approve-spec", help="sign off a frozen spec (required for risk=high/critical)"
    )
    approve_spec.add_argument("--config", default="")
    approve_spec.add_argument("--workspace", default="")
    approve_spec.add_argument("--spec", required=True, help="spec digest, or a prefix of it")
    approve_spec.add_argument("--by", required=True)
    approve_spec.add_argument(
        "--signature",
        default="",
        help="hex HMAC signature over the spec digest; required once owners are enrolled",
    )

    sign_spec = sub.add_parser(
        "sign-spec", help="produce the signature for a spec digest, as a registered owner"
    )
    sign_spec.add_argument("--config", default="")
    sign_spec.add_argument("--workspace", default="")
    sign_spec.add_argument("--spec", required=True, help="spec digest, or a prefix of it")
    sign_spec.add_argument("--owner-id", required=True)

    sign_step = sub.add_parser(
        "sign-step", help="produce the signature for a step decision, as a registered owner"
    )
    sign_step.add_argument("--config", default="")
    sign_step.add_argument("--workspace", default="")
    sign_step.add_argument("--run-id", required=True)
    sign_step.add_argument("--step", required=True, help="step id or node id")
    sign_step.add_argument("--owner-id", required=True)
    sign_step.add_argument(
        "--decision", default="proceed", choices=["proceed", "retry", "reject"]
    )
    sign_step.add_argument(
        "--artifact",
        default="",
        help="the artifact digest the decision is about; defaults to the step's newest",
    )
    sign_step.add_argument(
        "--attempt",
        type=int,
        default=-1,
        help="the attempt the decision is about; defaults to the step's current attempt",
    )

    benchmark = sub.add_parser("benchmark", help="paired single-agent loop and Daedalus comparison")
    benchmark.add_argument("--destination", required=True)
    benchmark.add_argument("--mode", choices=["controlled", "model"], default="controlled")
    benchmark.add_argument("--transport", choices=["openai", "codex"], default="openai")
    benchmark.add_argument("--model", default="")
    benchmark.add_argument("--base-url", default="")
    benchmark.add_argument("--api-key-env", default="DAEDALUS_MODEL_API_KEY")
    benchmark.add_argument("--repeats", type=int, default=3)
    benchmark.add_argument("--max-calls", type=int, default=12)
    benchmark.add_argument("--max-tokens", type=int, default=60000)
    benchmark.add_argument("--timeout", type=int, default=90)

    dependencies = sub.add_parser("dependencies", help="operator-provisioned offline dependency cache")
    dep_actions = dependencies.add_subparsers(dest="action", required=True)
    cache_add = dep_actions.add_parser("cache-add", help="verify and import one pure Python wheel; no installation")
    cache_add.add_argument("--workspace", required=True)
    cache_add.add_argument("--wheel", required=True)
    dep_check = dep_actions.add_parser("verify", help="verify manifest, hash lock and cached wheels without executing code")
    dep_check.add_argument("--workspace", required=True)
    dep_check.add_argument("--manifest", required=True)
    dep_check.add_argument("--lock", required=True)

    validation = sub.add_parser("validation", help="fresh acceptance and independent signed delivery review")
    actions = validation.add_subparsers(dest="action", required=True)
    for action in ("evaluate", "show", "sign", "attest"):
        command = actions.add_parser(action)
        command.add_argument("--config", default="")
        command.add_argument("--workspace", default="")
        command.add_argument("--run-id", required=True)
        if action in {"sign", "attest"}:
            command.add_argument("--validation-id", required=True)
            command.add_argument("--validator-id", required=True)
            command.add_argument("--review-file", required=True,
                                 help="JSON: decision, review_notes, natural_language_assessments")
        if action == "attest":
            command.add_argument("--signature", required=True)

    owners = sub.add_parser("owners", help="manage the Spec §3.2 owner registry")
    owner_actions = owners.add_subparsers(dest="action", required=True)
    # `--workspace`/`--config` live on each action, not on `owners`, so the flag can be
    # written where an operator expects it: `daedalus owners add --workspace ... --owner-id ...`
    owner_add = owner_actions.add_parser("add", help="enrol an owner")
    owner_add.add_argument("--config", default="")
    owner_add.add_argument("--workspace", default="")
    owner_add.add_argument("--owner-id", required=True)
    owner_add.add_argument(
        "--role",
        required=True,
        choices=["viewer", "operator", "reviewer", "owner"],
        help="viewer: none; operator: up to normal; reviewer: up to high; owner: critical too",
    )
    owner_add.add_argument(
        "--secret-env",
        required=True,
        help="the environment variable that holds this owner's signing secret",
    )
    owner_add.add_argument("--display-name", default="")
    owner_revoke = owner_actions.add_parser("revoke", help="withdraw an owner's authority")
    owner_revoke.add_argument("--config", default="")
    owner_revoke.add_argument("--workspace", default="")
    owner_revoke.add_argument("--owner-id", required=True)
    owner_list = owner_actions.add_parser("list", help="show the registry and its policy")
    owner_list.add_argument("--config", default="")
    owner_list.add_argument("--workspace", default="")
    owner_list.add_argument("--include-revoked", action="store_true")
    owner_status = owner_actions.add_parser("status", help="the honest state of this control")
    owner_status.add_argument("--config", default="")
    owner_status.add_argument("--workspace", default="")

    resume = sub.add_parser("resume", help="continue a run parked in AWAITING_APPROVAL")
    resume.add_argument("--config", default="")
    resume.add_argument("--workspace", default="")
    resume.add_argument("--run-id", required=True)
    resume.add_argument("--reviewed-by", default="", help="human who reviewed the recovery checkpoint")
    resume.add_argument("--review-note", default="")
    resume.add_argument("--signature", default="")

    recover = sub.add_parser(
        "recover", help="repair a workspace: reap stale leases, report interrupted runs"
    )
    recover.add_argument("--config", default="")
    recover.add_argument("--workspace", default="")
    recover.add_argument("--apply", action="store_true", help="actually mutate (default: report only)")

    backup = sub.add_parser("backup", help="snapshot the event store and verify it")
    backup.add_argument("--config", default="")
    backup.add_argument("--workspace", default="")
    backup.add_argument("--label", default="")

    restore = sub.add_parser("restore", help="restore a workspace snapshot")
    restore.add_argument("--config", default="")
    restore.add_argument("--workspace", default="")
    restore.add_argument("--from", dest="source", required=True)
    restore.add_argument("--force", action="store_true")

    export = sub.add_parser(
        "export-audit", help="export one run's audit trail as jsonl or csv (Spec §25)"
    )
    export.add_argument("--workspace", required=True)
    export.add_argument("--run-id", default="")
    export.add_argument("--format", default="jsonl", choices=["jsonl", "csv"])
    export.add_argument("--out", default="-", help="output path, or - for stdout")

    gate = sub.add_parser(
        "release-gate", help="run the Spec §25 pre-production checks and report go/no-go"
    )
    gate.add_argument("--mode", choices=("production", "development"), default="production",
                      help="production requires every check to pass; development is diagnostic only")
    gate.add_argument("--config", default="")
    gate.add_argument("--workspace", default="")
    gate.add_argument("--repo-root", default="")
    gate.add_argument("--json", action="store_true")
    gate.add_argument(
        "--no-tests",
        action="store_true",
        help="skip the behavioural suite (never use this before an actual release)",
    )
    gate.add_argument("--checklist", action="store_true", help="show where each §25 item is verified")

    alerts = sub.add_parser("alerts", help="evaluate alerting rules over persisted evidence")
    alerts.add_argument("--config", default="")
    alerts.add_argument("--workspace", default="")
    alerts.add_argument(
        "--json", action="store_true", help="machine-readable output for a monitoring system"
    )

    preflight = sub.add_parser(
        "preflight", help="report the isolation actually in force on this host"
    )
    preflight.add_argument("--config", default="")
    preflight.add_argument("--workspace", default="")
    preflight.add_argument(
        "--isolation",
        default="",
        choices=["", "auto", "host-process", "seatbelt", "container"],
        help="check a specific level instead of the configured automatic choice",
    )

    serve = sub.add_parser("serve", help="run the HTTP service and operator console")
    serve.add_argument("--config", default="")
    serve.add_argument("--host", default="")
    serve.add_argument("--port", type=int, default=0)
    serve.add_argument("--log-level", default="info")
    service = sub.add_parser("service", help="one-click local service control; tasks never auto-resume")
    service.add_argument("action", choices=["start", "stop", "restart", "toggle", "status", "supervise"])
    service.add_argument("--config", default="")
    service.add_argument("--open", action="store_true", help="open the console after starting")
    service.add_argument("--wait-lock", type=float, default=0, help=argparse.SUPPRESS)

    meta = sub.add_parser("meta", help="show the Meta-Spec boundary in force")
    meta.set_defaults(meta_only=True)

    return parser


def _resolve_settings(args: argparse.Namespace) -> Settings:
    from daedalus.config import load_settings

    return load_settings(
        getattr(args, "config", "") or None,
        workspace_root=getattr(args, "workspace", "") or None,
    )


def _resolve_workspace(args: argparse.Namespace) -> str:
    """`--workspace` wins, then the config file, then the default."""
    settings = _resolve_settings(args)
    explicit = getattr(args, "workspace", "")
    return explicit or str(settings.workspace.root_path)


def _open_store(workspace: str) -> EventStore:
    root = Path(workspace).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    return EventStore(root / "daedalus.db")


def _resolve_run_id(store: EventStore, run_id: str) -> str:
    if run_id:
        return run_id
    runs = store.list_runs()
    if not runs:
        raise SystemExit("no runs recorded in this workspace")
    return str(runs[-1]["run_id"])


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_demo(args: argparse.Namespace) -> int:
    from daedalus.demo import main as demo_main

    argv = list(args.scenarios)
    if args.keep:
        argv.append("--keep")
    return demo_main(argv)


def cmd_run(args: argparse.Namespace) -> int:
    repo = Path(args.repo).expanduser().resolve()
    if not (repo / ".git").exists():
        raise SystemExit(f"{repo} is not a Git repository")

    risk = RiskLevel(args.risk)
    request = PlanRequest(
        request_id="REQ-CLI",
        goal_id=args.goal_id,
        objective=args.goal,
        target_paths=tuple(args.path),
        test_command=args.test_command,
        risk_level=risk,
        network_policy=NetworkPolicy.DENY,
    )

    planner = DeterministicPlanner(meta=MetaSpec.default())
    tier2: Tier2Gate | None = None
    worker: Any = None
    budget = TokenBudget(max_tokens_per_run=200_000)

    if args.model:
        broker = SecretBroker()
        client = OpenAICompatibleClient(
            name="cli-model",
            model=args.model,
            base_url=args.base_url,
            api_key_resolver=lambda: broker.redeem(broker.request("model.api_key")),
        )
        registry = ModelRegistry()
        registry.register("coder", client)
        registry.register("planner", client)
        planner = ModelPlanner(
            client=client,
            fallback=DeterministicPlanner(),
            budget=budget,
        )
        worker = ModelWorker(client=client, budget=budget)
        if args.review or args.model:
            tier2 = Tier2Gate(reviewer=_SameModelReviewer(client=client, budget=budget))

    bundle: SpecBundle = planner.plan(request)

    workspace = (
        Path(args.workspace).expanduser()
        if args.workspace
        else Path(tempfile.mkdtemp(prefix="daedalus-run-"))
    )
    store = _open_store(str(workspace))

    if worker is None:
        # Without a model there is no coding worker, so the run rehearses planning and
        # boundary enforcement only. It says so explicitly rather than reporting a
        # silent no-op as if it had done work.
        print(
            "no --model supplied: this run validates the frozen spec against the "
            "boundary only and will not produce code"
        )
        orchestrator = RunOrchestrator(
            store=store,
            repo_path=repo,
            run_root=workspace / "worktrees",
            bundle=bundle,
            worker=_NoOpWorker(),
            quota=Quota(max_parallel_steps=args.max_parallel),
            identity=_identity_for(store, args),
        )
    else:
        from daedalus.domain.spec import PlanNode, RetryPolicy

        bundle = SpecBundle(
            goal=bundle.goal,
            plan=PlanSpec(
                plan_id=bundle.plan.plan_id,
                goal_id=bundle.plan.goal_id,
                nodes=tuple(
                    PlanNode(
                        node_id=node.node_id,
                        objective=node.objective,
                        deps=node.deps,
                        expected_artifacts=node.expected_artifacts,
                        allowed_tools=node.allowed_tools,
                        retry_policy=RetryPolicy(
                            max_attempts=min(
                                node.retry_policy.max_attempts, args.max_attempts
                            ),
                            backoff_sec=node.retry_policy.backoff_sec,
                            backoff_factor=node.retry_policy.backoff_factor,
                        ),
                        timeout_sec=node.timeout_sec,
                        intent=node.intent,
                        revision_of=node.revision_of,
                        extra=node.extra,
                    )
                    for node in bundle.plan.nodes
                ),
            ),
            boundary=bundle.boundary,
            meta=bundle.meta,
            owner_id=bundle.owner_id,
        )
        bundle.validate()
        orchestrator = RunOrchestrator(
            store=store,
            repo_path=repo,
            run_root=workspace / "worktrees",
            bundle=bundle,
            worker=worker,
            tier2=tier2,
            goal_audit_enabled=True,
            independent_validation_levels=("high", "critical"),
            quota=Quota(max_parallel_steps=args.max_parallel),
            identity=_identity_for(store, args),
        )

    orchestrator.register_spec()
    if args.approve_spec_by or args.spec_signature:
        # A signature must be accepted here too, or an enrolled workspace could not approve a
        # spec through `daedalus run` at all and would have to make two calls.
        orchestrator.approve_spec(
            approved_by=args.approve_spec_by,
            signature=args.spec_signature,
        )
        print(f"spec approved by: {args.approve_spec_by or '(signature only)'}")
    orchestrator.assert_spec_may_run()
    print(f"spec digest : {bundle.digest()}")
    print(f"risk level  : {bundle.goal.risk_level.value}")
    print(f"whitelist   : {list(bundle.boundary.fs_whitelist)}")
    print(f"denylist    : {len(bundle.boundary.fs_denylist)} entries (incl. Meta-Spec)")
    if args.plan_only:
        print(
            "plan-only: the spec is frozen in the registry and no run was created. "
            "Re-run with --model to execute it."
        )
        print(json.dumps(bundle.to_dict(), indent=2, sort_keys=True)[:4000])
        store.close()
        return 0

    result = orchestrator.run()
    print(json.dumps(result.describe(), indent=2, sort_keys=True))
    store.close()
    return 0 if result.status == "COMPLETED" else 2


class _SameModelReviewer:
    """Tier-2 reviewer backed by the same endpoint, with its own budget accounting."""

    def __init__(self, *, client: OpenAICompatibleClient, budget: TokenBudget) -> None:
        self.client = client
        self.budget = budget

    def complete(self, prompt: str, *, subject_digest: str) -> str:
        completion = self.client.complete(
            [Message(role="user", content=prompt)],
            temperature=0.0,
            response_format_json=True,
        )
        self.budget.record(completion)
        return completion.text


class _NoOpWorker:
    name = "noop"
    worker_id = "worker-noop"

    def implement(self, sandbox, context):  # noqa: ANN001, ANN201
        from daedalus.application.worker import WorkerResult

        return WorkerResult(
            ok=False,
            summary="no coding worker configured",
            execution_log="pass --model to enable a real coding worker",
            worker_id=self.worker_id,
            error="no_worker_configured",
        )


def cmd_specs(args: argparse.Namespace) -> int:
    with _open_store(args.workspace) as store:
        rows = store.connection.execute(
            """
            SELECT spec_digest, goal_id, spec_version, risk_level, owner_id,
                   approved_at, created_at
            FROM specs ORDER BY created_at ASC
            """
        ).fetchall()
        if not rows:
            print("no specs registered")
            return 0
        for row in rows:
            print(
                f"{row['spec_digest'][:12]}  goal={row['goal_id']:<22} "
                f"v{row['spec_version']}  risk={row['risk_level']:<8} "
                f"owner={row['owner_id']:<10} "
                f"approved={row['approved_at'] or 'NO'}  {row['created_at']}"
            )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    with _open_store(args.workspace) as store:
        runs = store.list_runs()
        if not runs:
            print("no runs recorded")
            return 0
        for run in runs:
            print(
                f"{run['run_id']}  {run['status']:<16} goal={run['goal_id']:<20} "
                f"spec={str(run['spec_digest'])[:12]} base={str(run['base_commit'])[:12]}"
            )
            for state, count in summarize_steps(store, str(run["run_id"])).items():
                print(f"    {state:<16} {count}")
            for step in store.list_steps(str(run["run_id"])):
                print(
                    f"      {str(step['node_id']):<26} {str(step['state']):<14} "
                    f"attempt={step['attempt']}/{step['max_attempts']} "
                    f"lease={(step['lease_id'] or '-')[:18]}"
                )
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    with _open_store(args.workspace) as store:
        run_id = _resolve_run_id(store, args.run_id)
        for row in store.timeline_for_run(run_id):
            print(
                f"{row['created_at']}  {row['severity']:<8} {row['event_type']:<22} "
                f"{row['actor']:<14} {row['summary']}"
            )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from daedalus.application.execution_log import UnresolvableLogRef, resolve
    from daedalus.application.fsm_service import StateMachineService

    with _open_store(args.workspace) as store:
        broken = store.verify_sequences()
        replayed = StateMachineService(store).rebuild_step_states()
        mismatches: list[str] = []
        for run in store.list_runs():
            for step in store.list_steps(str(run["run_id"])):
                step_id = str(step["step_id"])
                derived = replayed.get(step_id)
                if derived is None or derived.value != str(step["state"]):
                    mismatches.append(
                        f"{step_id}: projection={step['state']} "
                        f"replay={derived.value if derived else '<absent>'}"
                    )
        # Spec §14 requires an artifact to be traceable to its execution log. A reference
        # that resolves to nothing is not traceability, so it fails verification here rather
        # than surfacing as an empty page for whoever follows it later.
        dangling: list[str] = []
        checked = 0
        for run in store.list_runs():
            for step in store.list_steps(str(run["run_id"])):
                for artifact in store.artifacts_for_step(str(step["step_id"])):
                    reference = str(artifact["execution_log_ref"] or "")
                    checked += 1
                    try:
                        resolve(store, reference)
                    except UnresolvableLogRef as error:
                        dangling.append(f"{artifact['artifact_digest'][:12]}: {error}")
        # Invariants the projections must satisfy. These caught nothing until they existed:
        # a step could hold half a lease, or name a worker that never leased it, and no
        # command would say so.
        violations = store.step_invariant_violations()
        print(f"events                  : {store.event_count()}")
        print(f"aggregates with gaps    : {broken or 'none'}")
        print(f"projection mismatches   : {mismatches or 'none'}")
        print(f"log refs checked        : {checked}")
        print(f"dangling log refs       : {dangling or 'none'}")
        print(f"step invariant breaches : {violations or 'none'}")
        return 1 if broken or mismatches or dangling or violations else 0


def cmd_step_log(args: argparse.Namespace) -> int:
    """Resolve one step's execution log — the other half of Spec §14's traceability."""
    from daedalus.application.execution_log import UnresolvableLogRef, execution_log_ref, resolve

    with _open_store(args.workspace) as store:
        run_id = _resolve_run_id(store, args.run_id)
        step_id = _resolve_step_id(store, run_id, args.step)
        reference = execution_log_ref(run_id, step_id)
        try:
            entries = resolve(store, reference)
        except UnresolvableLogRef as error:
            raise SystemExit(str(error)) from error
        if args.json:
            for entry in entries:
                print(json.dumps(entry, sort_keys=True))
            return 0
        print(f"reference : {reference}")
        print(f"entries   : {len(entries)}")
        for entry in entries:
            print(
                f"{entry['timestamp']}  {entry['kind']:<8} {entry['event_type']:<28} "
                f"{entry['actor']:<16} {json.dumps(entry['payload'], sort_keys=True)[:120]}"
            )
        return 0


def cmd_executions(args: argparse.Namespace) -> int:
    with _open_store(args.workspace) as store:
        rows = store.list_executions(args.run_id)
        print(json.dumps({"executions": rows, "count": len(rows)}, indent=2, sort_keys=True))
    return 0


def cmd_workers(args: argparse.Namespace) -> int:
    with _open_store(args.workspace) as store:
        rows = store.workers_with_counts()
        print(json.dumps({"workers": rows, "count": len(rows)}, indent=2, sort_keys=True))
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    with _open_store(args.workspace) as store:
        print(json.dumps(store.metric_summary(), indent=2, sort_keys=True))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Answer Who / When / Which spec / Which model / What changed / Who approved."""
    with _open_store(args.workspace) as store:
        run_id = _resolve_run_id(store, args.run_id)
        run = store.get_run(run_id)
        if run is None:
            raise SystemExit(f"unknown run {run_id}")
        spec = store.get_spec(str(run["spec_digest"]))
        print(f"run            : {run['run_id']}")
        print(f"status         : {run['status']}")
        print(f"goal           : {run['goal_id']}")
        print(f"spec digest    : {run['spec_digest']}")
        print(f"base commit    : {run['base_commit']}")
        print(f"worktree       : {run['worktree_path']}")
        print(f"correlation id : {run['correlation_id']}")
        if spec:
            print(f"spec owner     : {spec['owner_id']}  risk={spec['risk_level']}")
            approval_state = (
                f"{spec['approved_at']} by {spec['approved_by']}"
                if spec["approved_at"]
                else "NOT APPROVED"
            )
            print(f"spec approved  : {approval_state}")
            if spec["signature"]:
                print(f"spec signature : {spec['signature']}")
        for step in store.list_steps(run_id):
            print(f"\nstep           : {step['node_id']}  [{step['state']}]")
            print(f"  attempt      : {step['attempt']}/{step['max_attempts']}")
            print(f"  spec digest  : {step['spec_digest']}")
            if step["last_failure"]:
                print(f"  last failure : {str(step['last_failure'])[:200]}")
            for artifact in store.artifacts_for_step(str(step["step_id"])):
                print(
                    f"  artifact     : {artifact['artifact_digest'][:12]} "
                    f"status={artifact['status']} model={artifact['model'] or '-'} "
                    f"worker={artifact['worker_id']}"
                )
                print(f"    changed    : {artifact['changed_files']}")
                print(f"    spec       : {str(artifact['spec_digest'])[:12]}")
                print(f"    code base  : {str(artifact['code_base_digest'])[:12]}")
                # Spec §27 asks "which image?" and "with which dependency set?"; both facts
                # were recorded per artifact and reported nowhere.
                print(f"    image      : {artifact['sandbox_image'] or '-'}")
                print(
                    f"    toolchain  : {str(artifact['toolchain_digest'])[:12]} "
                    f"deps {str(artifact['dependency_digest'])[:12]}"
                )
            for gate in store.gate_results_for_step(str(step["step_id"])):
                print(
                    f"  gate tier{gate['tier']}  : {gate['decision']} "
                    f"confidence={gate['confidence'] if gate['confidence'] is not None else '-'}"
                )
                reasons = json.loads(gate["reasons"]) if gate["reasons"] else []
                for reason in reasons[:3]:
                    print(f"    reason     : {str(reason)[:180]}")
            for approval in store.approvals_for_step(str(step["step_id"])):
                print(
                    f"  approval    : {approval['decision']} by {approval['approved_by']} "
                    f"on artifact {str(approval['artifact_digest'])[:12]} "
                    f"({approval['created_at']})"
                )
                if approval["note"]:
                    print(f"    note       : {approval['note']}")
        from daedalus.application.goal_audit import goal_audit_view
        goal_report = goal_audit_view(store, run_id)
        print(f"goal audit     : {goal_report['status']} (max {goal_report['max_stages']} stages, including initial)")
        for stage in goal_report["stages"]:
            print(f"  stage {stage['stage']}      : {stage['decision']} scope={stage['scope']} commit={stage['commit'][:12]}")
            for change in stage.get("required_changes", []):
                print(f"    required   : {change}")
        if goal_report["manual_reason"]:
            print(f"  manual       : {goal_report['manual_reason']}")
        for event in store.events_for_execution(str(run["execution_id"])):
            if event.event_type in {"StepCommitted", "SpecRegistered", "RunCompleted"}:
                print(f"event          : {event.timestamp} {event.event_type} {event.actor}")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    from daedalus.config import write_example_config

    path = write_example_config(args.path, force=args.force)
    print(f"wrote {path}")
    print(
        "Next: set the credential environment variable named by model.<role>.api_key_env "
        "(for example DAEDALUS_MODEL_API_KEY). The key does not belong in this file."
    )
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    settings = _resolve_settings(args)
    settings.ensure_directories()
    from daedalus.application.preflight import run_preflight

    payload = settings.describe()
    payload["isolation"] = run_preflight(settings).describe()["selected"]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_escalations(args: argparse.Namespace) -> int:
    from daedalus.application.approvals import ApprovalService
    from daedalus.application.fsm_service import StateMachineService

    workspace = _resolve_workspace(args)
    with _open_store(workspace) as store:
        service = ApprovalService(
            store=store,
            fsm=StateMachineService(store),
            identity=_identity_for(store, args),
        )
        pending = service.pending_escalations(args.run_id)
        if not pending:
            print("no escalations waiting")
            return 0
        for item in pending:
            print(
                f"{item['run_id']}  step={item['node_id']:<24} "
                f"risk={item['risk_level'] or '-':<8} attempt={item['attempt']} "
                f"artifact={item['artifact_digest'][:12]}"
            )
            if item["last_failure"]:
                print(f"    why: {str(item['last_failure']).splitlines()[0][:160]}")
            print(
                f"    answer with: daedalus approve --run-id {item['run_id']} "
                f"--step {item['step_id']} --decision proceed --by <you>"
            )
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    from daedalus.application.approvals import ApprovalService
    from daedalus.application.fsm_service import StateMachineService

    workspace = _resolve_workspace(args)
    with _open_store(workspace) as store:
        service = ApprovalService(
            store=store,
            fsm=StateMachineService(store),
            identity=_identity_for(store, args),
        )
        step_id = _resolve_step_id(store, args.run_id, args.step)
        result = service.approve(
            run_id=args.run_id,
            step_id=step_id,
            decision=args.decision,
            approved_by=args.by,
            note=args.note,
            artifact_digest=args.artifact,
            granted_attempts=args.grant_attempts,
            signature=getattr(args, "signature", ""),
        )
        print(json.dumps(result.describe(), indent=2, sort_keys=True))
        print("\nNext: daedalus resume --run-id " + args.run_id)
    return 0


def _identity_for(store: EventStore, args: argparse.Namespace):
    """The registry, with enforcement policy taken from configuration like everywhere else."""
    from daedalus.application.identity import OwnerRegistry

    settings = _resolve_settings(args)
    return OwnerRegistry(store=store, required=settings.identity.required)


def cmd_approve_spec(args: argparse.Namespace) -> int:
    from daedalus.application.spec_approval import SpecApprovalService

    workspace = _resolve_workspace(args)
    with _open_store(workspace) as store:
        digest = _resolve_spec_digest(store, args.spec)
        row = store.get_spec(digest)
        service = SpecApprovalService(store=store, identity=_identity_for(store, args))
        outcome = service.record(
            spec_digest=digest, approved_by=args.by.strip(), signature=args.signature
        )
        print(
            json.dumps(
                {
                    "spec_digest": digest,
                    "goal_id": str(row["goal_id"]),
                    "risk_level": str(row["risk_level"]),
                    **outcome.to_payload(),
                    "statement": service.approval_view(digest)["statement"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from daedalus.application.benchmark import run_comparison

    destination = Path(args.destination).expanduser().resolve()
    try:
        result = run_comparison(
            destination, mode=args.mode, repeats=args.repeats, transport=args.transport,
            model=args.model, base_url=args.base_url, api_key_env=args.api_key_env,
            max_calls=args.max_calls, max_tokens=args.max_tokens, timeout=args.timeout,
        )
    except ValueError as error:
        raise DaedalusError(str(error)) from error
    print(json.dumps({
        "status": result["status"], "mode": result["mode"],
        "summary": result.get("summary", {}), "report": str(destination / "report.html"),
        "real_model_completions": result["real_model_completions"],
    }, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "COMPLETE" else 2


def cmd_dependencies(args: argparse.Namespace) -> int:
    from daedalus.application.dependencies import cache_wheel, verify_python, DependencyError

    cache = Path(args.workspace).expanduser().resolve() / "dependency-cache"
    try:
        if args.action == "cache-add":
            result = cache_wheel(cache, Path(args.wheel).expanduser().resolve())
        else:
            manifest = Path(args.manifest)
            result = verify_python(
                manifest.name, manifest.read_text(), Path(args.lock).read_text(), cache
            )
    except DependencyError:
        raise
    except Exception as error:  # noqa: BLE001 - do not echo credentials from malformed input
        raise DependencyError("invalid dependency input or cache: " + type(error).__name__) from error
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_validation(args: argparse.Namespace) -> int:
    from daedalus.application.independent_validation import IndependentValidationService
    from daedalus.domain.validation import ValidationError

    with _open_store(_resolve_workspace(args)) as store:
        registry = _identity_for(store, args)
        service = IndependentValidationService(store, registry)
        if args.action == "show":
            result = service.view(args.run_id)
        elif args.action == "evaluate":
            result = service.evaluate(args.run_id)
        else:
            try:
                review = json.loads(Path(args.review_file).read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise ValidationError("review file must contain valid JSON") from error
            if not isinstance(review, dict) or set(review) != {
                "decision",
                "review_notes",
                "natural_language_assessments",
            }:
                raise ValidationError(
                    "review file requires exactly decision, review_notes, natural_language_assessments"
                )
            kwargs = dict(
                decision=review["decision"],
                review_notes=review["review_notes"],
                assessments=review["natural_language_assessments"],
            )
            if args.action == "sign":
                claim = service.claim(args.run_id, args.validation_id, **kwargs)
                print(registry.sign_validation(args.validator_id, claim.digest()))
                return 0
            result = service.attest(
                args.run_id,
                args.validation_id,
                validator_id=args.validator_id,
                signature=args.signature,
                **kwargs,
            )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0

def cmd_sign_spec(args: argparse.Namespace) -> int:
    """Produce a signature locally. The secret is read from the environment and never printed."""
    workspace = _resolve_workspace(args)
    with _open_store(workspace) as store:
        digest = _resolve_spec_digest(store, args.spec)
        registry = _identity_for(store, args)
        signature = registry.sign(args.owner_id, digest)
        # Only the signature is emitted, so it can be piped straight into `approve-spec`
        # without the secret ever reaching a shell history or a log line.
        print(signature)
    return 0


def cmd_sign_step(args: argparse.Namespace) -> int:
    """Sign one step decision. The signature covers the run, step, decision and artifact."""
    workspace = _resolve_workspace(args)
    with _open_store(workspace) as store:
        step_id = _resolve_step_id(store, args.run_id, args.step)
        row = store.get_step(step_id)
        if row is None:
            raise SystemExit(f"unknown step {args.step!r}")
        artifact = args.artifact
        if args.decision == "proceed" and not artifact:
            # Default to the newest artifact for the step, since that is almost always what
            # is being authorised — but the signature still names it, so a different artifact
            # cannot be substituted afterwards.
            artifacts = store.artifacts_for_step(step_id)
            if not artifacts:
                raise SystemExit(
                    f"step {step_id} has no artifact to sign for; pass --artifact explicitly"
                )
            artifact = str(artifacts[-1]["artifact_digest"])
        # The attempt is part of the signed bytes, and reading it from the step rather than
        # requiring the operator to supply it is the difference between a control that is
        # used and one that is worked around.
        attempt = args.attempt if args.attempt >= 0 else int(row["attempt"])
        signature = _identity_for(store, args).sign_step(
            args.owner_id, args.run_id, step_id, args.decision, artifact, attempt
        )
        print(signature)
    return 0


def cmd_owners(args: argparse.Namespace) -> int:
    from daedalus.domain.identity import Role

    workspace = _resolve_workspace(args)
    with _open_store(workspace) as store:
        registry = _identity_for(store, args)
        if args.action == "add":
            owner = registry.enroll(
                args.owner_id,
                role=Role(args.role),
                secret_env=args.secret_env,
                display_name=args.display_name,
            )
            print(
                json.dumps(
                    {
                        "enrolled": owner.to_payload(),
                        "note": (
                            "the secret itself is never stored; only this fingerprint is. "
                            f"Verification reads {owner.secret_env} from the environment."
                        ),
                        **registry.describe(),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.action == "revoke":
            removed = registry.revoke(args.owner_id)
            print(
                json.dumps(
                    {"revoked": removed, "owner_id": args.owner_id, **registry.describe()},
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if removed else 1
        # list / status
        describe = registry.describe()
        if args.action == "status":
            print(json.dumps(describe, indent=2, sort_keys=True))
            return 0
        owners = registry.list(include_revoked=bool(args.include_revoked))
        print(json.dumps(
            {
                **describe,
                "owners": [owner.to_payload() for owner in owners],
            },
            indent=2,
            sort_keys=True,
        ))
        return 0


def _resolve_spec_digest(store: EventStore, reference: str) -> str:
    """Accept a full digest or an unambiguous prefix, as the console displays."""
    rows = store.connection.execute("SELECT spec_digest FROM specs").fetchall()
    digests = [str(row["spec_digest"]) for row in rows]
    if reference in digests:
        return reference
    matches = [digest for digest in digests if digest.startswith(reference)]
    if not matches:
        raise SystemExit(f"no spec matches {reference!r}")
    if len(matches) > 1:
        raise SystemExit(f"{reference!r} matches {len(matches)} specs; use the full digest")
    return matches[0]


def cmd_resume(args: argparse.Namespace) -> int:
    from daedalus.application.replay import run_repo_path
    from daedalus.application.resume import resume_run

    workspace = _resolve_workspace(args)
    with _open_store(workspace) as store:
        run_id = _resolve_run_id(store, args.run_id)
        if not run_repo_path(store, run_id):
            raise SystemExit(f"run {run_id} does not record a repository path")
        if args.reviewed_by:
            from daedalus.application.service_lifecycle import checkpoint, review_checkpoint
            view = checkpoint(store, run_id)
            review_checkpoint(store, run_id, reviewed_by=args.reviewed_by,
                checkpoint_digest=view["checkpoint_digest"], note=args.review_note,
                signature=args.signature, identity=_identity_for(store, args))
        result = resume_run(
            store=store,
            run_id=run_id,
            workspace=workspace,
            identity=_identity_for(store, args),
        )
        print(json.dumps(result.describe(), indent=2, sort_keys=True))
    return 0 if result.status in {"COMPLETED", "AWAITING_APPROVAL"} else 2


def cmd_recover(args: argparse.Namespace) -> int:
    from daedalus.application.recovery import recover_workspace

    workspace = _resolve_workspace(args)
    settings = _resolve_settings(args)
    with _open_store(workspace) as store:
        report = recover_workspace(
            store=store, apply=args.apply, worktrees_root=settings.workspace.worktrees_path
        )
        print(json.dumps(report.describe(), indent=2, sort_keys=True))
        if not args.apply and report.has_findings:
            print("\nThis was a dry run. Re-run with --apply to repair.")
            return 1
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    from daedalus.application.backup import create_backup

    settings = _resolve_settings(args)
    settings.ensure_directories()
    result = create_backup(settings.workspace, label=args.label)
    print(json.dumps(result.describe(), indent=2, sort_keys=True))
    return 0 if result.verified else 2


def cmd_restore(args: argparse.Namespace) -> int:
    from daedalus.application.backup import restore_backup

    settings = _resolve_settings(args)
    result = restore_backup(settings.workspace, source=args.source, force=args.force)
    print(json.dumps(result.describe(), indent=2, sort_keys=True))
    return 0


def _resolve_step_id(store: EventStore, run_id: str, reference: str) -> str:
    """Accept either a full step id or the human-facing node id."""
    if store.get_step(reference) is not None:
        return reference
    for step in store.list_steps(run_id):
        if str(step["node_id"]) == reference or str(step["step_id"]).endswith(f":{reference}"):
            return str(step["step_id"])
    raise SystemExit(f"no step matches {reference!r} in run {run_id}")


def cmd_rollback(args: argparse.Namespace) -> int:
    from daedalus.application.replay import ReplayService
    from daedalus.application.fsm_service import StateMachineService

    with _open_store(args.workspace) as store:
        run_id = _resolve_run_id(store, args.run_id)
        service = ReplayService(store=store, fsm=StateMachineService(store))
        result = service.rollback(
            run_id, reason=args.reason, to_commit=args.to_commit
        )
        print(json.dumps(result.describe(), indent=2, sort_keys=True))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Re-run a frozen spec, reusing artifacts whose five digests still match."""
    from daedalus.application.cache_worker import CacheMissWorker
    from daedalus.application.fsm_service import StateMachineService
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.replay import ReplayService, run_repo_path
    from daedalus.application.scheduler import Quota
    from daedalus.domain.ids import new_id
    from daedalus.domain.spec import SpecBundle
    from daedalus.model.base import TokenBudget

    with _open_store(args.workspace) as store:
        run_id = _resolve_run_id(store, args.run_id)
        run = store.get_run(run_id)
        if run is None:
            raise SystemExit(f"unknown run {run_id}")
        repo_path = Path(run_repo_path(store, run_id))
        if not repo_path or not (repo_path / ".git").exists():
            raise SystemExit(
                f"the source run does not record a usable repository path: {repo_path!r}"
            )

        spec_row = store.get_spec(str(run["spec_digest"]))
        if spec_row is None:
            raise SystemExit(f"spec {run['spec_digest']} is not in the registry")
        bundle = SpecBundle.from_dict(json.loads(str(spec_row["document"])))

        if args.rollback_first:
            service = ReplayService(store=store, fsm=StateMachineService(store))
            rollback = service.rollback(run_id, reason=args.reason)
            print(
                f"rolled back {run_id}: stopped={len(rollback.stopped_steps)} "
                f"superseded={len(rollback.superseded_steps)}"
            )

        worker: Any = CacheMissWorker()
        if args.model:
            broker = SecretBroker()
            client = OpenAICompatibleClient(
                name="cli-replay",
                model=args.model,
                base_url=args.base_url,
                api_key_resolver=lambda: broker.redeem(broker.request("model.api_key")),
            )
            worker = ModelWorker(client=client, budget=TokenBudget(max_tokens_per_run=200_000))

        orchestrator = RunOrchestrator(
            store=store,
            repo_path=repo_path,
            run_root=Path(args.workspace) / "replays" / new_id("replay"),
            bundle=bundle,
            worker=worker,
            quota=Quota(max_parallel_steps=1),
            reuse_artifacts=not args.no_reuse,
            identity=_identity_for(store, args),
            parent_execution_id=str(run["execution_id"]),
            replay_from_commit=str(run["base_commit"]),
        )
        orchestrator.register_spec()
        result = orchestrator.run()
        reused = [step for step in result.steps if step.decision == "REUSED"]
        print(
            f"replay {result.run_id}: status={result.status} "
            f"steps={len(result.steps)} reused={len(reused)} "
            f"commits={[c[:12] for c in result.commits]}"
        )
        for step in result.steps:
            print(f"  {step.node_id:<24} {step.state:<12} {step.decision:<8} {step.feedback[:80]}")
        for note in result.notes:
            print(f"  note: {note}")
    return 0 if result.status == "COMPLETED" else 2


def cmd_export_audit(args: argparse.Namespace) -> int:
    """Write one run's trail as JSONL or CSV, for a log pipeline or a spreadsheet."""
    import csv
    import io

    with _open_store(args.workspace) as store:
        run_id = _resolve_run_id(store, args.run_id)
        trail = _export_trail(store, run_id)
        if args.format == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(
                ["kind", "timestamp", "actor", "step_id", "event_type", "detail", "reference"]
            )
            for entry in trail:
                writer.writerow([entry[key] for key in (
                    "kind", "timestamp", "actor", "step_id", "event_type", "detail", "reference"
                )])
            text = buffer.getvalue()
        else:
            text = "\n".join(json.dumps(entry, sort_keys=True) for entry in trail) + "\n"

    if args.out == "-":
        sys.stdout.write(text)
    else:
        Path(args.out).expanduser().write_text(text, encoding="utf-8")
        print(f"wrote {len(trail)} row(s) to {args.out}")
    return 0


def _export_trail(store: EventStore, run_id: str) -> list[dict[str, object]]:
    """The same flattening the service does, so the two exports cannot drift apart.

    Kept as one implementation here and reused by the API path would be ideal; the API builds it
    from an in-process store, and the dependency direction is CLI -> service, not the reverse.
    """
    run = store.get_run(run_id)
    if run is None:
        raise SystemExit(f"unknown run {run_id}")
    trail: list[dict[str, object]] = []
    for event in store.events_for_execution(str(run["execution_id"])):
        trail.append(
            {
                "kind": "event",
                "timestamp": event.timestamp,
                "actor": event.actor,
                "step_id": event.step_id,
                "event_type": event.event_type,
                "detail": json.dumps(dict(event.payload), sort_keys=True)[:2000],
                "reference": event.event_id,
            }
        )
    for step in store.list_steps(run_id):
        step_id = str(step["step_id"])
        for gate in store.gate_results_for_step(step_id):
            trail.append(
                {
                    "kind": "gate",
                    "timestamp": str(gate["created_at"]),
                    "actor": "gatekeeper",
                    "step_id": str(step["node_id"]),
                    "event_type": f"tier{gate['tier']}:{gate['decision']}",
                    "detail": str(gate["reasons"])[:2000],
                    "reference": str(gate["gate_result_id"]),
                }
            )
        for artifact in store.artifacts_for_step(step_id):
            trail.append(
                {
                    "kind": "artifact",
                    "timestamp": str(artifact["created_at"]),
                    "actor": str(artifact["worker_id"]),
                    "step_id": str(step["node_id"]),
                    "event_type": f"artifact:{artifact['status']}",
                    "detail": str(artifact["changed_files"])[:2000],
                    "reference": str(artifact["artifact_digest"]),
                }
            )
    for approval in store.approvals_for_run(run_id):
        trail.append(
            {
                "kind": "approval",
                "timestamp": str(approval["created_at"]),
                "actor": str(approval["approved_by"]),
                "step_id": str(approval["step_id"]),
                "event_type": f"approval:{approval['decision']}",
                "detail": str(approval["note"])[:2000],
                "reference": str(approval["approval_id"]),
            }
        )
    trail.sort(key=lambda entry: str(entry["timestamp"]))
    return trail


def cmd_release_gate(args: argparse.Namespace) -> int:
    """Production is fail-closed; development is explicitly diagnostic."""
    from daedalus.application.release_gate import checklist_coverage, run_release_gate

    if args.checklist:
        print(json.dumps(checklist_coverage(), indent=2, sort_keys=True))
        return 0

    settings = _resolve_settings(args)
    workspace = _resolve_workspace(args)
    with _open_store(workspace) as store:
        settings = replace(settings, workspace=replace(settings.workspace, root=workspace))
        report = run_release_gate(
            settings=settings,
            store=store,
            repo_root=Path(args.repo_root).expanduser() if args.repo_root else None,
            run_tests=not args.no_tests,
            mode=getattr(args, "mode", "production"),
        )
        if args.json:
            print(json.dumps(report.describe(), indent=2, sort_keys=True))
            return 0 if report.go else 1

        symbols = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}
        for check in report.checks:
            print(f"[{symbols[check.status.value]}] {check.category:<14} {check.name}")
            if check.detail:
                print(f"        {check.detail}")
            if check.status.value in {"fail", "warn"} and check.remediation:
                print(f"        -> {check.remediation}")
        print()
        if report.go:
            verdict = "GO" if report.mode == "production" else "DIAGNOSTIC OK (not release approval)"
            print(
                f"{verdict}: {len(report.checks) - len(report.failures) - len(report.skipped)} "
                f"check(s) passed, {len(report.warnings)} warning(s), "
                f"{len(report.skipped)} skipped"
            )
            return 0
        print(
            f"NO-GO ({report.mode}): "
            + ", ".join(report.describe()["blocking_checks"] + report.describe()["missing_checks"])
        )
        return 1


def cmd_alerts(args: argparse.Namespace) -> int:
    """Report alerts. Exit status encodes severity so a check script can gate on it."""
    from daedalus.application.alerting import evaluate_alerts

    settings = _resolve_settings(args)
    workspace = _resolve_workspace(args)
    with _open_store(workspace) as store:
        settings = replace(settings, workspace=replace(settings.workspace, root=workspace))
        report = evaluate_alerts(store=store, settings=settings)
        if args.json:
            print(json.dumps(report.describe(), indent=2, sort_keys=True))
            return _alert_exit_code(report)
        if report.healthy:
            print(f"healthy: {len(report.evaluated)} rules evaluated, no active alerts")
            return 0
        for alert in report.alerts:
            marker = {"critical": "!!", "warning": " !", "info": "  "}[alert.severity.value]
            print(f"{marker} [{alert.severity.value}] {alert.rule}: {alert.summary}")
            if alert.action:
                print(f"       -> {alert.action}")
        print()
        print(
            f"{len(report.active)} active alert(s); worst = "
            f"{report.worst.value if report.worst else 'none'}"
        )
        return _alert_exit_code(report)


def _alert_exit_code(report) -> int:  # noqa: ANN001 - AlertReport
    """0 healthy, 1 warning, 2 critical: usable directly in a monitoring check."""
    from daedalus.application.alerting import Severity

    if report.worst is Severity.CRITICAL:
        return 2
    return 0 if report.healthy else 1


def cmd_preflight(args: argparse.Namespace) -> int:
    from daedalus.application.preflight import run_preflight

    settings = _resolve_settings(args)
    with _open_store(str(settings.workspace.root_path)) as store:
        report = run_preflight(settings, requested=args.isolation, store=store)

    print(f"requested : {report.requested}")
    print(f"selected  : {report.selected}")
    print(f"because   : {report.selection_reason}")
    print()
    print("drivers probed (code/proc/fs/net/rlimits/identity):")
    for driver_report in report.drivers:
        print("  " + driver_report.summary_line())
        if not driver_report.available:
            print(f"      {driver_report.detail[:150]}")
    print()
    print("gaps:")
    for gap in report.gaps:
        print(f"  - {gap}")
    print()
    print("notes:")
    for note in report.notes:
        print(f"  - {note}")
    identity = report.identity or {}
    if identity:
        print()
        print("spec approval control (§3.2):")
        print(f"  enforced            : {identity.get('enforced')}")
        print(f"  owners enrolled     : {identity.get('owners_enrolled')}")
        print(f"  ever registered     : {identity.get('owners_ever_registered')}")
        print(f"  signature scheme    : {identity.get('scheme')}")
        print(f"  {identity.get('note')}")
    if report.gaps:
        print()
        print(
            "The control plane's guarantees do not depend on these gaps, but a security "
            "assessment must account for them. See docs/runbook.md section 6."
        )
    return 0 if not [g for g in report.gaps if "no process isolation" in g] else 1


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the same-origin API and console. Delegates to the service entry point."""
    from daedalus.service.app import create_app
    from daedalus.config import ConfigError, load_settings

    try:
        settings = load_settings(
            args.config or None, host=args.host or None, port=args.port or None
        )
    except ConfigError as error:
        raise SystemExit(f"configuration error: {error.message}") from error

    app = create_app(settings)
    import uvicorn

    print(
        f"Daedalus console: http://{settings.service.host}:{settings.service.port}\n"
        f"  workspace: {settings.workspace.root_path}\n"
        f"  database : {settings.workspace.database_path}\n"
        f"  api docs : http://{settings.service.host}:{settings.service.port}/docs"
    )
    uvicorn.run(app, host=settings.service.host, port=settings.service.port,
                log_level=args.log_level, proxy_headers=False)
    return 0


def cmd_service(args: argparse.Namespace) -> int:
    from daedalus.service.control import command, default_config, supervise
    config = Path(args.config).expanduser().resolve() if args.config else default_config()
    if args.action == "supervise":
        return supervise(config, lock_timeout=max(0, min(120, args.wait_lock)))
    result = command(args.action, config, open_browser=args.open)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_console(args: argparse.Namespace) -> int:
    from daedalus.service.terminal import run_console
    options = {"config_path": args.console_config, "open_browser": args.console_open}
    if args.console_restart:
        options["restart"] = True
    return run_console(**options)


def cmd_meta(args: argparse.Namespace) -> int:
    meta = MetaSpec.default()
    print(json.dumps(meta.to_dict(), indent=2, sort_keys=True))
    print("\nThe Gatekeeper, scheduler, FSM and event store are Meta-Spec protected.")
    print("A task may propose changes to them; it may never apply them (Spec §21).")
    return 0


DISPATCH = {
    "demo": cmd_demo,
    "run": cmd_run,
    "specs": cmd_specs,
    "status": cmd_status,
    "timeline": cmd_timeline,
    "verify": cmd_verify,
    "metrics": cmd_metrics,
    "executions": cmd_executions,
    "workers": cmd_workers,
    "audit": cmd_audit,
    "step-log": cmd_step_log,
    "rollback": cmd_rollback,
    "replay": cmd_replay,
    "init": cmd_init,
    "config": cmd_config,
    "escalations": cmd_escalations,
    "approve": cmd_approve,
    "approve-spec": cmd_approve_spec,
    "benchmark": cmd_benchmark,
    "dependencies": cmd_dependencies,
    "validation": cmd_validation,
    "sign-spec": cmd_sign_spec,
    "sign-step": cmd_sign_step,
    "owners": cmd_owners,
    "resume": cmd_resume,
    "recover": cmd_recover,
    "backup": cmd_backup,
    "restore": cmd_restore,
    "serve": cmd_serve,
    "service": cmd_service,
    "preflight": cmd_preflight,
    "alerts": cmd_alerts,
    "release-gate": cmd_release_gate,
    "export-audit": cmd_export_audit,
    "meta": cmd_meta,
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    handler = cmd_console if args.command is None else DISPATCH.get(args.command)
    if handler is None:
        parser.error(f"unknown command {args.command!r}")
    try:
        return int(handler(args))
    except DaedalusError as error:
        # A refusal is a result, not a crash. An operator who approves without a signature
        # needs to read *why* it was refused, and a traceback buries that under frames the
        # operator cannot act on. Exit 1 so a script can still tell refusal from success.
        print(f"error: {error.message}", file=sys.stderr)
        context = getattr(error, "context", {})
        if context:
            print(f"       ({error.code}: {context})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
