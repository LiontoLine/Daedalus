"""HTTP service (Spec §15 observability, §10 owner approval).

One FastAPI process serves the JSON API and the operator console from the same origin, so
there is no CORS surface and no second deployment to keep in sync — the same choice
AgentPanelX made, for the same reason.

The API is a *projection plus commands* surface. Reads come from the event store and its
projections; writes go through the same services the CLI uses (`RunOrchestrator`,
`ApprovalService`, `ReplayService`). Nothing here writes SQLite or Git directly, just as
nothing in the CLI does.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from daedalus import __version__
from daedalus.application.approvals import (
    ApprovalError, ApprovalService, NotEscalated, execution_authorization_required,
)
from daedalus.application.backup import BackupError, create_backup, list_backups, restore_backup
from daedalus.application.coding_worker import ModelWorker
from daedalus.application.execution_log import execution_log_ref
from daedalus.application.inspection import safe_receipts
from daedalus.application.fsm_service import StateMachineService
from daedalus.application.identity import OwnerRegistry
from daedalus.application import model_settings
from daedalus.application.intake import IntakeService, ModelQuestioner
from daedalus.domain.intake import (
    IntakeAnswerRejected,
    IntakeModelUnavailable,
    IntakeQuestionsRejected,
)
from daedalus.application.spec_approval import SpecApprovalService
from daedalus.application.gatekeeper.tier2 import ClientReviewer, Tier2Gate
from daedalus.application.observability import configure_logging, get_logger, log_context
from daedalus.application.planner import DeterministicPlanner, ModelPlanner, PlanRequest, ResourceBounds, SpecHardening
from daedalus.application.recovery import recover_workspace
from daedalus.application.replay import ReplayService, classify_spec_change, run_repo_path
from daedalus.application.resume import ResumeError, load_manifest, resume_run
from daedalus.application.trunk_view import trunk_view
from daedalus.config import ConfigError, Settings, load_settings
from daedalus.domain.approval import ApprovalDecision
from daedalus.domain.spec import MetaSpec, NetworkPolicy, RiskLevel, SpecBundle
from daedalus.errors import (
    DaedalusError,
    ModelError,
    SpecApprovalRequired,
    SpecError,
    SpecValidationError,
)
from daedalus.infrastructure.store.event_store import EventStore
from daedalus.model.base import Message, ModelRegistry, TokenBudget
from daedalus.model.openai_compatible import OpenAICompatibleClient
from daedalus.security.secrets import CapabilityDenied, SecretBroker
from daedalus.service.dispatcher import RunDispatcher, ServiceBusy, ServiceError, build_orchestrator

logger = get_logger("service")

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RunRequest(BaseModel):
    repo_path: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    goal_id: str = "GOAL-001"
    target_paths: list[str] = Field(min_length=1)
    test_command: str = Field(min_length=1)
    risk_level: RiskLevel = RiskLevel.NORMAL
    invariants: list[str] = Field(default_factory=list)
    network_policy: NetworkPolicy = NetworkPolicy.DENY
    use_model: bool = False
    enable_review: bool = False
    approve_spec_by: str = ""
    #: Spec §3.2. The HMAC signature over the spec digest. Required once any owner is
    #: enrolled; without it a high-risk run is refused before it is created.
    spec_signature: str = ""
    requirement_check_id: str = ""


class ApprovalRequest(BaseModel):
    step: str = Field(min_length=1, description="step id or node id")
    decision: ApprovalDecision
    approved_by: str = Field(min_length=1)
    note: str = ""
    artifact_digest: str = ""
    granted_attempts: int = 0
    #: Spec §3.2. Required for proceed/retry on a HIGH or CRITICAL step once owners are
    #: enrolled. Sign it with `daedalus sign-step`.
    signature: str = ""



class SpecApprovalRequest(BaseModel):
    approved_by: str = Field(min_length=1)
    signature: str = ""


class ValidationAssessmentRequest(BaseModel):
    model_config = {"extra": "forbid"}
    criterion_id: str
    status: str
    evidence: str = Field(min_length=1, max_length=4000)


class ValidationAttestationRequest(BaseModel):
    model_config = {"extra": "forbid"}
    validator_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    decision: str = "APPROVE"
    review_notes: str = Field(min_length=1, max_length=4000)
    natural_language_assessments: list[ValidationAssessmentRequest] = Field(default_factory=list)


class RollbackRequest(BaseModel):
    reason: str = Field(min_length=1)
    to_commit: str = ""


class ReplayRequest(BaseModel):
    reason: str = "replay requested through the console"
    rollback_first: bool = False
    use_model: bool = False
    #: Start the new execution at this commit instead of the run's base. The console sets it
    #: when the operator picks a step to replay from. Verified against the repository before
    #: anything is created, because "replay from <typo>" would otherwise produce a run whose
    #: base does not exist and fail deep inside the worktree pool.
    from_commit: str = ""


class ModelOverrideRequest(BaseModel):
    """A console connection; optional persistence uses the OS keychain exclusively."""

    base_url: str = Field(min_length=1)
    model: str = Field(min_length=1)
    api_key: str = ""
    timeout_sec: int = 120
    #: Empty redirects every role; otherwise only that one.
    role: str = ""
    #: Required for a non-loopback endpoint, because that sends repository contents off the
    #: machine on every call.
    acknowledge_remote: bool = False
    api_format: str = ""
    provider: str = "custom"
    api_key_env: str = ""
    request_options: dict[str, Any] = Field(default_factory=dict)
    reuse_existing_key: bool = False
    persist: bool = False


class ModelTestRequest(BaseModel):
    """One real call to prove an endpoint answers before it is relied on."""

    base_url: str = Field(min_length=1)
    model: str = ""
    api_key: str = ""
    timeout_sec: int = 120
    api_format: str = ""
    provider: str = "custom"
    api_key_env: str = ""
    request_options: dict[str, Any] = Field(default_factory=dict)
    role: str = ""
    acknowledge_remote: bool = False
    reuse_existing_key: bool = False


class ModelImportRequest(BaseModel):
    content: str
    format: str = "auto"
    acknowledge_remote: bool = False
    persist: bool = False


class IntakeStartRequest(BaseModel):
    """The task, in the operator's own words, plus which repository it applies to."""

    repo_path: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    goal_id: str = ""


class IntakeAnswerRequest(BaseModel):
    """One click. A question is answered by an option id, a written answer, or skipped."""

    question_id: str = Field(min_length=1)
    option_id: str = ""
    free_text: str = ""
    skip: bool = False


class IntakeFreezeRequest(BaseModel):
    """Freeze the derived spec into a run. §3.2 signatures apply exactly as they do elsewhere."""

    approved_by: str = ""
    spec_signature: str = ""
    use_model: bool = False
    enable_review: bool = False
    spec_digest: str = ""


class RestoreRequest(BaseModel):
    source: str = Field(min_length=1)
    force: bool = False


class ServiceControlRequest(BaseModel):
    action: str
    note: str = Field(default="", max_length=2000)


class RecoveryReviewRequest(BaseModel):
    reviewed_by: str = Field(min_length=1, max_length=128)
    checkpoint_digest: str = Field(min_length=1, max_length=128)
    note: str = Field(default="", max_length=2000)
    signature: str = ""


# ---------------------------------------------------------------------------
# Service container
# ---------------------------------------------------------------------------


class ServiceState:
    """Everything the routes need, built once from configuration."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        settings.ensure_directories()
        self.store = EventStore(settings.workspace.database_path)
        from daedalus.application.agentic_rag import AgenticRAG
        from daedalus.infrastructure.knowledge import KnowledgeStore
        from daedalus.infrastructure.vector_index import LocalRetrievalRuntime
        self.knowledge = KnowledgeStore(settings.workspace.root_path / "knowledge")
        self.retrieval = LocalRetrievalRuntime(self.knowledge.root / ".retrieval")
        self.rag = AgenticRAG(self.knowledge, self.store,retrieval=self.retrieval)
        self.fsm = StateMachineService(self.store)
        # Spec §3.2. Whether this *enforces* anything depends on enrolment: see
        # `OwnerRegistry.enforced`. Built first, because both approval services consult it, so
        # every interface — HTTP, CLI and the orchestrator — shares one policy object instead
        # of each deciding for itself.
        self.identity = OwnerRegistry(store=self.store, required=settings.identity.required)
        self.approvals = ApprovalService(
            store=self.store, fsm=self.fsm, identity=self.identity
        )
        self.spec_approvals = SpecApprovalService(store=self.store, identity=self.identity)
        self.replay = ReplayService(store=self.store, fsm=self.fsm)
        # The front door. The intake is a *pre-run* use case: it asks, records the answers and
        # derives a spec, but it never writes to the FSM — `freeze()` hands back a bundle and
        # run creation stays in the run handler, so the intake cannot become a second write path.
        self.intake = IntakeService(
            store=self.store,
            questioner_factory=lambda: ModelQuestioner(
                client=self.build_task_client("planner", "structured_questions"), budget=None
            ),
            planner_factory=lambda: ModelPlanner(
                client=self.build_task_client("planner", "structured_plan"),
                budget=TokenBudget(max_tokens_per_run=settings.quota.max_tokens_per_run),
                require_model=True,
                hardening=SpecHardening(bounds=ResourceBounds.for_quota(settings.quota)),
            ),
            repo_roots=(settings.workspace.repos_root,)
            if settings.workspace.repos_root
            else (),
            # The values an unanswered field keeps. `network_policy` starts at deny and the
            # review screen names every field the model decided instead of the human.
            base_request={"goal_id": "GOAL-001", "risk_level": "normal",
                          "network_policy": "deny"},
            reference_context_factory=lambda repo, request, budget: self.rag.context(
                repo, request.objective, phase="planning",
                client=self.build_model_client("planner"),
                budget=budget, target_paths=request.target_paths,
            ),
        )
        self.dispatcher = RunDispatcher(
            settings=settings,
            store=self.store,
            max_concurrent_runs=settings.service.max_concurrent_runs,
        )
        self.startup_findings: list[dict[str, Any]] = []
        #: Temporary connections retain a key in memory; saved connections retain only
        #: a keychain reference. Neither puts credentials into workspace files or events.
        self.model_override: model_settings.ModelOverride | None = None
        self.model_overrides: dict[str, model_settings.ModelOverride] = {}
        import threading
        self.model_config_lock = threading.RLock()
        from daedalus.application.saved_models import SavedModelProfiles
        self.saved_models = SavedModelProfiles(settings.workspace.root_path)
        restored = self.saved_models.load()
        self.model_override = restored.get("")
        self.model_overrides.update({role: value for role, value in restored.items() if role})
        from daedalus.application.service_lifecycle import ServiceLifecycle
        self.lifecycle = ServiceLifecycle(self.store, settings.workspace.root_path)
        self._closed = False

    def close(self, *, drain: bool = True) -> None:
        """Stop the dispatcher, then close the store.

        `drain=True` waits for a run to finish its current step. Aborting a step mid-flight
        would leave a lease and a worktree that only `daedalus recover` could explain, so the
        default is to let the step finish and then stop.
        """
        if self._closed:
            return
        from daedalus.service.control import pending_note
        self.lifecycle.record["model_connections_need_reentry"] = any(
            value is not None and not value.persisted
            for value in (self.model_override, *self.model_overrides.values())
        )
        self.lifecycle.stopping(pending_note(self.settings) or "服务退出，保留断点；下次启动等待人工审查")
        self.dispatcher.shutdown(wait=drain)
        if drain:
            self.lifecycle.stopped()
            self.store.close()
            self._closed = True

    # ------------------------------------------------------------------ workers
    def build_task_client(self, role, purpose):
        client = self.build_model_client(role)
        factory = getattr(client, "for_task", None)
        return factory(purpose) if callable(factory) else client

    def observed_client(self, client, role):
        from daedalus.domain.ids import new_id
        from daedalus.model.observed import ObservedClient

        def report(record):
            labels = {"role": role, "request_id": new_id("model-request"),
                      "ok": record["ok"], "error_code": record["error_code"],
                      "inference_profile": record.get("inference_profile", "configured")}
            if "http_status" in record:
                labels["http_status"] = record["http_status"]
            self.store.record_metric(name="provider_attempts", value=1, unit="count", labels=labels)
            self.store.record_metric(name="provider_latency_ms", value=record["latency_ms"], unit="ms", labels=labels)
            if record["usage_known"]:
                self.store.record_metric(name="provider_reported_tokens", value=record["tokens"], unit="tokens", labels=labels)
                for name in ("prompt_tokens", "completion_tokens"):
                    if record.get(name) is not None:
                        self.store.record_metric(name="provider_" + name, value=record[name], unit="tokens", labels=labels)
                usage = record.get("usage_details", {})
                cached = usage.get("prompt_cache_hit_tokens", usage.get("prompt_tokens_details", {}).get("cached_tokens", usage.get("input_tokens_details", {}).get("cached_tokens")))
                uncached = usage.get("prompt_cache_miss_tokens")
                for name, value in (("cached_input_tokens", cached), ("uncached_input_tokens", uncached)):
                    if value is not None:
                        self.store.record_metric(name="provider_" + name, value=value, unit="tokens", labels=labels)
            else:
                self.store.record_metric(name="provider_usage_unknown", value=1, unit="count", labels=labels)

        return ObservedClient(client, report)

    def build_model_client(self, role: str = "") -> OpenAICompatibleClient:
        with self.model_config_lock:
            return self._build_model_client(role)

    def _build_model_client(self, role: str = "") -> OpenAICompatibleClient:
        wanted = role or self.settings.default_role
        override = self.model_overrides.get(wanted) or self.model_override
        # The override is consulted *before* the config, because a workspace with no model
        # configured is exactly when someone reaches for this panel. Resolving the configured
        # provider first raised "no model provider configured" and made the feature unusable in
        # the one situation it exists for.
        if override is not None and override.applies_to(wanted):
            # Inline keys remain in the override; named environment credentials are redeemed
            # only at call time. Local endpoints may legitimately need no credential.
            from daedalus.model.multi_provider import build_client
            # Snapshot at this explicit client's creation, so rotating a saved key does
            # not invalidate an already accepted run. The global override retains a ref only.
            stored_key = self.saved_models.resolve(override) if override.credential_ref else None

            def resolve_override():
                if stored_key:
                    return stored_key
                if override.api_key or not override.api_key_env:
                    return override.api_key
                broker = SecretBroker(fallback_env_names=())
                return broker.redeem(broker.request("model.api_key", scope=override.api_key_env))

            return self.observed_client(build_client(override.as_provider(),
                name=f"console-{wanted}",
                api_key_resolver=resolve_override,
            ), wanted)

        if self.saved_models.restore_error:
            raise DaedalusError(self.saved_models.restore_error)
        provider = self.settings.provider(wanted)
        broker = SecretBroker() if provider.api_format == "openai_chat" and provider.provider == "custom" else SecretBroker(fallback_env_names=())

        def resolve() -> str:
            if not provider.api_key_env:
                return ""
            grant = broker.request("model.api_key", scope=provider.api_key_env)
            try:
                return broker.redeem(grant)
            except CapabilityDenied as error:
                raise DaedalusError(
                    f"no credential available for role {provider.name!r}: set "
                    f"{provider.api_key_env} in the environment before starting the "
                    f"service. {error.message}"
                ) from error

        from daedalus.model.multi_provider import build_client
        return self.observed_client(build_client(provider,
            name=f"service-{provider.name}",
            api_key_resolver=resolve,
        ), wanted)

    def build_worker(
        self, *, use_model: bool, enable_review: bool, budget: TokenBudget | None = None,
        repo_path: str = "",
    ) -> tuple[Any, Tier2Gate | None]:
        """Build the worker and reviewer, sharing one token budget with the planner.

        A per-role budget would let each role spend its own allowance, so the run-level limit
        in the config would bound nothing in particular.
        """
        if not use_model:
            from daedalus.application.cache_worker import CacheMissWorker

            return CacheMissWorker(), None
        shared = budget or TokenBudget()
        registry = ModelRegistry()
        planner_client = self.build_model_client("planner")
        coder_client = self.build_model_client("coder")
        if callable(getattr(coder_client, "for_task", None)):
            coder_client = coder_client.for_task("structured_edit")
        registry.register("planner", planner_client)
        registry.register("coder", coder_client)
        from daedalus.application.inspection import RepositoryInspector
        worker = ModelWorker(client=coder_client, budget=shared,
                             inspection_context=RepositoryInspector())
        if repo_path:
            worker.reference_context = lambda context: self.rag.context(
                repo_path, context.node.objective + "\n" + context.revision_feedback,
                phase="regression" if context.revision_feedback else "execution",
                client=planner_client, budget=worker.budget,
                target_paths=context.node.expected_artifacts,
                output_tokens=worker.desired_output_tokens(context),
            )
            worker.investigate_context = lambda context,query,gap: self.rag.context(
                repo_path,query+"\nEvidence gap: "+gap,phase="investigation",mode="deep",
                client=planner_client,budget=worker.budget,
                target_paths=context.node.expected_artifacts,
                output_tokens=worker.desired_output_tokens(context),
            )
        tier2 = None
        if enable_review or use_model:
            reviewer_client = self.build_model_client("reviewer")
            if callable(getattr(reviewer_client, "for_task", None)):
                reviewer_client = reviewer_client.for_task("structured_review")
            tier2 = Tier2Gate(
                reviewer=ClientReviewer(
                    client=reviewer_client, budget=shared
                )
            )
        return worker, tier2


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


def create_app(
    settings: Settings | None = None,
    *,
    config_path: str = "",
) -> FastAPI:
    configure_logging()
    resolved = settings or load_settings(config_path or None)
    from daedalus.service.access import AccessControl, install_access
    AccessControl(resolved).validate_bind()
    state = ServiceState(resolved)
    state.dispatcher.start()
    # Freeze at startup; recomputing on GET would mislabel an old process after a source edit.
    import hashlib
    package_root = Path(__file__).resolve().parents[1]
    startup_source_sha256 = {
        name: hashlib.sha256((package_root / name).read_bytes()).hexdigest()
        for name in (
            "application/agentic_rag.py", "application/hybrid_retrieval.py",
            "application/benchmark.py", "infrastructure/vector_index.py",
            "model/base.py", "model/observed.py", "model/multi_provider.py", "service/app.py",
            "service/benchmark_routes.py",
            "application/saved_models.py", "application/model_settings.py",
            "infrastructure/keychain.py",
            "application/verification_probes.py", "service/verification_routes.py",
            "application/coding_worker.py", "application/planner.py",
            "application/gatekeeper/tier2.py",
            "application/gatekeeper/tier1.py",
            "application/orchestrator.py", "application/intake.py",
            "application/approvals.py", "application/worktree_pool.py",
            "application/inspection.py", "application/route.py",
            "application/review_context.py", "application/gatekeeper/pipeline.py",
            "application/goal_audit.py",
            "application/repair_evidence.py", "application/trunk_view.py",
            "application/branch_repair.py", "domain/events.py",
            "application/commit_recovery.py",
            "application/engineering_cases.py", "service/engineering_routes.py",
            "service/static/engineering.js", "service/static/engineering.css",
            "service/templates/_engineering_evaluation.html",
            "application/benchmark_cases.py", "service/static/console.js",
            "service/templates/workflow.html", "service/templates/base.html",
            "service/templates/_model_settings.html",
            "service/access.py", "service/access_config.py", "service/autostart.py",
            "service/autostart_probe.py",
            "service/control.py", "service/terminal.py", "config.py", "cli.py",
            "application/review_probes.py", "service/review_routes.py",
            "service/static/review-evaluation.js", "service/static/access-handoff.js",
            "service/templates/_review_evaluation.html",
            "application/realwork.py", "service/realwork_routes.py",
            "service/capability_budget.py", "service/replay_admission.py",
            "service/validation_admission.py",
            "application/source_context.py", "infrastructure/retrieval_tools.py",
            "application/upstream_contract.py",
            "application/native_verifier.py",
            "application/requirement_evidence.py", "infrastructure/behavior_runner.py",
            "service/requirement_routes.py",
        )
    }

    app = FastAPI(
        title="Daedalus",
        version=__version__,
        description=(
            "Deterministic control plane for model-driven delivery. "
            "Reads are projections; writes go through the same services the CLI uses."
        ),
    )
    install_access(app, resolved)
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse

    @app.exception_handler(RequestValidationError)
    async def model_validation_error(request, error):
        if request.url.path.startswith("/api/requirement-checks"):
            return JSONResponse(status_code=422, content={"detail": "需求核对字段无效；输入原文不会回显"})
        if request.url.path.startswith("/api/model"):
            return JSONResponse(status_code=422,content={"detail":"模型配置字段无效，请检查字段类型与必填项；输入原文不会回显"})
        if request.url.path.startswith("/api/knowledge"):
            return JSONResponse(status_code=422, content={"detail": "项目资料字段无效，请检查类型与长度；输入原文不会回显"})
        if request.url.path.startswith("/api/comparisons"):
            return JSONResponse(status_code=422, content={"detail": "对照参数无效，请检查任务与预算；输入原文不会回显"})
        from fastapi.exception_handlers import request_validation_exception_handler
        return await request_validation_exception_handler(request,error)

    app.state.daedalus = state
    from daedalus.service.knowledge_routes import knowledge_router
    app.include_router(knowledge_router(state))
    from daedalus.service.benchmark_routes import benchmark_router
    app.include_router(benchmark_router(state))
    from daedalus.service.engineering_routes import engineering_router
    app.include_router(engineering_router(state))
    from daedalus.service.realwork_routes import realwork_router
    app.include_router(realwork_router(state))
    from daedalus.service.review_routes import review_router
    app.include_router(review_router(state))
    from daedalus.service.verification_routes import verification_router
    app.include_router(verification_router(state))
    from daedalus.service.requirement_routes import requirement_router
    app.include_router(requirement_router(state))
    if TEMPLATES_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR)) if TEMPLATES_DIR.is_dir() else None

    # Report what startup found, without acting on it.
    report = recover_workspace(
        store=state.store, apply=False, worktrees_root=state.settings.workspace.worktrees_path
    )
    state.startup_findings = [item.describe() for item in report.items]
    if state.startup_findings:
        logger.warning(
            "startup found %d workspace finding(s); run `daedalus recover` to inspect",
            len(state.startup_findings),
        )

    @app.on_event("shutdown")
    def _shutdown() -> None:
        state.close()

    # ---------------------------------------------------------------- helpers
    def _store() -> EventStore:
        return state.store

    def _run_or_404(run_id: str) -> dict[str, Any]:
        run = _store().get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"unknown run {run_id}")
        return run

    def _resolve_step_id(run_id: str, reference: str) -> str:
        if _store().get_step(reference) is not None:
            return reference
        for step in _store().list_steps(run_id):
            if str(step["node_id"]) == reference or str(step["step_id"]).endswith(f":{reference}"):
                return str(step["step_id"])
        raise HTTPException(status_code=404, detail=f"no step {reference!r} in run {run_id}")

    def _bundle_for(run_id: str) -> SpecBundle:
        run = _run_or_404(run_id)
        spec = _store().get_spec(str(run["spec_digest"]))
        if spec is None:
            raise HTTPException(status_code=409, detail="the run's spec is not in the registry")
        return SpecBundle.from_dict(json.loads(str(spec["document"])))

    @app.exception_handler(DaedalusError)
    async def _domain_error(request: Request, error: DaedalusError) -> JSONResponse:
        """Domain errors are 4xx with their code, never an opaque 500."""
        payload = {"error": error.to_payload()}
        status = 409
        if isinstance(error, (NotEscalated, ApprovalError, ConfigError)):
            status = 400
        if isinstance(error, ServiceBusy):
            status = 429
        from daedalus.infrastructure.keychain import SecureCredentialError
        if isinstance(error, SecureCredentialError):
            status = 503
        if isinstance(error, SpecApprovalRequired):
            status = 428  # precondition required
        return JSONResponse(status_code=status, content=payload)

    # ---------------------------------------------------------------- meta
    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "workspace": str(state.settings.workspace.root_path),
            "database": str(state.settings.workspace.database_path),
            "dispatcher": state.dispatcher.describe(),
            "startup_findings": len(state.startup_findings),
            "service_session_id": state.lifecycle.session_id,
            "process_id": os.getpid(),
            "startup_source_sha256": startup_source_sha256,
        }

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        return state.settings.describe()

    @app.get("/api/meta-spec")
    def meta_spec() -> dict[str, Any]:
        return MetaSpec.default().to_dict()

    @app.get("/api/alerts")
    def alerts() -> dict[str, Any]:
        """Whether anything needs attention, evaluated from persisted evidence."""
        from daedalus.application.alerting import evaluate_alerts

        return evaluate_alerts(store=state.store, settings=state.settings).describe()

    @app.get("/api/isolation")
    def isolation(isolation_level: str = "") -> dict[str, Any]:
        """The isolation actually in force, with the gaps named (Spec §7, §25).

        Exposed as an endpoint rather than buried in a document because a security reviewer
        should be able to ask the running system what protects it.
        """
        from daedalus.application.preflight import run_preflight

        return run_preflight(
            state.settings, requested=isolation_level, store=state.store
        ).describe()

    # ---------------------------------------------------------------- reads
    @app.get("/api/runs")
    def list_runs() -> dict[str, Any]:
        runs = _store().list_runs()
        return {
            "runs": [
                {
                    **{k: run[k] for k in ("run_id", "goal_id", "status", "base_commit",
                                           "branch", "created_at", "updated_at")},
                    "spec_digest": str(run["spec_digest"])[:12],
                    "objective": _run_objective(run),
                    "active": state.dispatcher.is_active(str(run["run_id"])),
                    "steps": _step_counts(str(run["run_id"])),
                }
                for run in runs
            ]
        }

    def _run_objective(run: dict[str, Any]) -> str:
        """Name tasks using their frozen goal rather than an opaque execution id."""
        spec = _store().get_spec(str(run["spec_digest"]))
        if spec is None:
            return str(run["goal_id"])
        document = json.loads(str(spec["document"]))
        return str((document.get("spec_01_goal") or {}).get("objective") or run["goal_id"])

    def _step_counts(run_id: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for step in _store().list_steps(run_id):
            state_name = str(step["state"])
            counts[state_name] = counts.get(state_name, 0) + 1
        return dict(sorted(counts.items()))

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        run = _run_or_404(run_id)
        spec = _store().get_spec(str(run["spec_digest"]))
        commits = _run_commits(run_id)
        return {
            "run": {**run, "spec_digest": str(run["spec_digest"])},
            "spec": (
                {
                    "goal_id": str(spec["goal_id"]),
                    "risk_level": str(spec["risk_level"]),
                    "approved_at": spec["approved_at"],
                    "approved_by": spec["approved_by"],
                    # §3.2: a recorded name and a verified signature are different claims.
                    "approval_verified": bool(int(spec.get("approval_verified") or 0)),
                    "approval_scheme": str(spec.get("approval_scheme") or ""),
                    "approval_role": str(spec.get("approval_role") or ""),
                    "approval_statement": state.spec_approvals.approval_view(
                        str(run["spec_digest"])
                    )["statement"],
                }
                if spec
                else None
            ),
            "steps": [_step_view(step, commits) for step in _store().list_steps(run_id)],
            "isolation": _isolation_for_run(run_id),
            "approvals": _store().approvals_for_run(run_id),
            "timeline": _store().timeline_for_run(run_id)[-200:],
            "active": state.dispatcher.is_active(run_id),
        }

    def _artifact_snapshot(row: dict[str, Any]) -> dict[str, Any]:
        """The snapshot facts about the tree an artifact describes.

        An "artifact" is a claim about a tree, so the panel shows the tree identity and the size
        of the change rather than only a digest: a digest with nothing beside it tells an
        operator that something was hashed, not what.
        """
        try:
            document = json.loads(str(row["document"]))
        except ValueError:
            document = {}
        extra = document.get("extra", {}) if isinstance(document, dict) else {}
        return {
            "gated_tree": str(extra.get("gated_tree", "")),
            "diff_stat": str(extra.get("diff_stat", "")),
            "patch_bytes": len(str(extra.get("patch_preview", ""))),
            "patch_truncated": bool(extra.get("patch_truncated", False)),
            "inspection_receipts": safe_receipts(extra),
            "worker_summary": str(extra.get("worker_summary", "")),
            "node_id": str(extra.get("node_id", "")),
            "attempt": int(extra.get("attempt", 0) or 0),
        }

    def _isolation_for_run(run_id: str) -> dict[str, Any] | None:
        """Recover the isolation decision recorded when the run started."""
        run = _store().get_run(run_id)
        if run is None:
            return None
        # The sign-off may have been recorded against the *spec* rather than inside this
        # execution: approving a spec separately (`daedalus approve-spec` /
        # `POST /api/specs/{id}/approve`) writes a spec-aggregate event with no execution id.
        # Without folding those in, the most security-relevant fact about a run — who
        # authorised it — was missing from its export whenever it was approved before the run
        # rather than during creation.
        spec_events = _store().events_for_spec(str(run["goal_id"]))
        run_events = _store().events_for_execution(str(run["execution_id"]))
        for event in [*spec_events, *run_events]:
            if event.event_type == "RunStarted":
                recorded = event.payload.get("isolation")
                return dict(recorded) if isinstance(recorded, dict) else None
        return None

    def _spec_cards(document: dict[str, Any], approval: dict[str, Any]) -> list[dict[str, Any]]:
        """One card per spec: the summary that shows collapsed, and the document to expand."""
        goal = document.get("spec_01_goal") or {}
        plan = document.get("spec_02_plan") or {}
        boundary = document.get("spec_03_boundary") or {}
        meta = document.get("meta_spec") or {}
        nodes = plan.get("nodes") or []
        criteria = goal.get("acceptance_criteria") or []
        return [
            {
                "key": "spec_01",
                "title": "SPEC-01 · 目标契约",
                "subtitle": "这次要达成什么，以及凭什么判定达成",
                "summary": [
                    ["Goal id", str(goal.get("goal_id", ""))],
                    ["目标", str(goal.get("objective", ""))],
                    ["风险等级", str(goal.get("risk_level", ""))],
                    ["验收判据", f"{len(criteria)} 条"],
                    ["不变量", f"{len(goal.get('invariants') or [])} 条"],
                ],
                "document": goal,
            },
            {
                "key": "spec_02",
                "title": "SPEC-02 · 执行计划",
                "subtitle": "分成几个节点、谁依赖谁、各自期望产出什么",
                "summary": [
                    ["Plan id", str(plan.get("plan_id", ""))],
                    ["节点数", str(len(nodes))],
                    ["节点", " → ".join(str(node.get("node_id", "")) for node in nodes)],
                    ["最大尝试上限", str(max(
                        (int((node.get("retry_policy") or {}).get("max_attempts", 0) or 0)
                         for node in nodes), default=0))],
                ],
                "document": plan,
            },
            {
                "key": "spec_03",
                "title": "SPEC-03 · 安全与资源边界",
                "subtitle": "允许改哪里、能不能联网、能用多少资源",
                "summary": [
                    ["可写路径", f"{len(boundary.get('fs_whitelist') or [])} 条"],
                    ["网络策略", str(boundary.get("network_policy", ""))],
                    ["隔离级别", str(boundary.get("isolation", "auto"))],
                    ["CPU / 内存", f"{boundary.get('cpu_limit', '—')} / "
                                   f"{boundary.get('memory_mb', '—')} MB"],
                ],
                "document": boundary,
            },
            {
                "key": "meta_spec",
                "title": "Meta-Spec · 系统不可越权边界",
                "subtitle": "哪些文件 Agent 永远不得修改，哪些动作必须人工批准",
                "summary": [
                    ["受保护路径", f"{len(meta.get('protected_paths') or [])} 条"],
                    ["必须人工批准", ", ".join(meta.get("human_approval_required") or []) or "—"],
                    ["自演进等级", str(meta.get("self_evolution_level", 0))],
                    ["签批", str(approval.get("statement", ""))],
                ],
                "document": meta,
            },
        ]

    def _run_commits(run_id: str) -> dict[str, str]:
        """Which commit each plan node committed, read from the event log.

        An artifact records `parent_commit` — the tree its work was based on — and never the
        commit it produced. The only place the result commit exists is the `StepCommitted` event,
        which is why this reads the log rather than the `artifacts` projection. Without it,
        "replay from this step" had no commit to name and `_known_commits` rejected the one an
        operator is most likely to mean.
        """
        run = _store().get_run(run_id)
        if run is None or not run["execution_id"]:
            return {}
        commits: dict[str, str] = {}
        for event in _store().events_for_execution(str(run["execution_id"])):
            if event.event_type != "StepCommitted":
                continue
            node_id = str(event.payload.get("node_id", "") or "")
            commit = str(event.payload.get("commit", "") or "")
            if node_id and commit:
                commits[node_id] = commit
        return commits

    def _step_view(step: dict[str, Any], commits: dict[str, str]) -> dict[str, Any]:
        step_id = str(step["step_id"])
        artifacts = [
            {
                "artifact_digest": str(row["artifact_digest"]),
                "status": str(row["status"]),
                "changed_files": json.loads(str(row["changed_files"] or "[]")),
                "model": str(row["model"]),
                "worker_id": str(row["worker_id"]),
                # The hashes an operator needs to check a claim themselves: which commit the
                # work was based on, which tree the gate reviewed, and the four digests that
                # make "can this be reproduced?" answerable.
                "parent_commit": str(row["parent_commit"] or ""),
                "patch_digest": str(row["patch_digest"] or ""),
                "code_base_digest": str(row["code_base_digest"] or ""),
                "toolchain_digest": str(row["toolchain_digest"] or ""),
                "dependency_digest": str(row["dependency_digest"] or ""),
                "input_artifact_digest": str(row["input_artifact_digest"] or ""),
                "execution_log_ref": str(row["execution_log_ref"] or ""),
                "snapshot": _artifact_snapshot(row),
                # Spec §27 asks the audit to answer "which image?". The column was
                # populated from the start and reported nowhere, so the question had no
                # answer even though the fact was recorded.
                "sandbox_image": str(row["sandbox_image"] or ""),
                "created_at": str(row["created_at"]),
            }
            for row in _store().artifacts_for_step(step_id)
        ]
        # "Replay from this step" needs a commit that this run actually recorded. The result
        # commit is the one an operator means by "from this step": replaying from it reuses the
        # verified work up to and including the step. The base commit only exists as a fallback
        # for a step that never committed, and replaying from it re-executes the step itself.
        result_commit = commits.get(str(step["node_id"]), "")
        return {
            **{k: step[k] for k in ("step_id", "node_id", "state", "attempt", "max_attempts",
                                    "timeout_sec", "spec_digest", "base_commit",
                                    "last_failure", "worktree_path", "created_at",
                                    "updated_at", "granted_attempts", "run_id",
                                    "execution_id")},
            "result_commit": result_commit,
            "execution_authorization_required": execution_authorization_required(_store(), step_id),
            "gates": [
                {
                    "tier": int(row["tier"]),
                    "decision": str(row["decision"]),
                    "confidence": row["confidence"],
                    "reasons": json.loads(str(row["reasons"] or "[]")),
                    "violations": json.loads(str(row["violations"] or "[]")),
                    # The individual deterministic checks, so a reviewer sees which one failed
                    # rather than only that the gate said no.
                    "checks": (
                        json.loads(str(row["evidence"] or "{}")).get("checks", [])
                        if int(row["tier"]) == 1
                        else []
                    ),
                }
                for row in _store().gate_results_for_step(step_id)
            ],
            "artifacts": artifacts,
            "approvals": _store().approvals_for_step(step_id),
        }

    @app.get("/api/runs/{run_id}/trunk")
    def run_trunk(run_id: str) -> dict[str, Any]:
        """Recorded trunk evidence and isolated branch history, without running checks."""
        _run_or_404(run_id)
        return trunk_view(_store(), run_id)

    @app.get("/api/runs/{run_id}/plan")
    def plan_graph(run_id: str) -> dict[str, Any]:
        """The DAG with each node's live state, for the console's graph view."""
        bundle = _bundle_for(run_id)
        steps = {str(step["node_id"]): step for step in _store().list_steps(run_id)}
        trunk = trunk_view(_store(), run_id)
        expectations = {node["node_id"]: node for node in trunk["nodes"]}
        nodes = []
        for node in bundle.plan.nodes:
            step = steps.get(node.node_id)
            evidence = expectations.get(node.node_id, {})
            nodes.append(
                {
                    "node_id": node.node_id,
                    "objective": node.objective,
                    "intent": node.intent,
                    "deps": list(node.deps),
                    "expected_artifacts": list(node.expected_artifacts),
                    "acceptance_criteria": [
                        criterion.to_dict() for criterion in (
                            node.acceptance_criteria or bundle.goal.acceptance_criteria
                        )
                    ],
                    "retry_max_attempts": node.retry_policy.max_attempts,
                    "timeout_sec": node.timeout_sec,
                    "state": str(step["state"]) if step else "NOT_DECLARED",
                    "attempt": int(step["attempt"]) if step else 0,
                    "step_id": str(step["step_id"]) if step else "",
                    "expectation_status": evidence.get("status"),
                    "expectation_score": evidence.get("score"),
                    "expectations": evidence.get("expectations", []),
                    "expectation_commit": evidence.get("commit", ""),
                }
            )
        return {
            "goal_id": bundle.goal.goal_id,
            "objective": bundle.goal.objective,
            "risk_level": bundle.goal.risk_level.value,
            "topological_order": list(bundle.plan.topo_order()),
            "nodes": nodes,
            "trunk": trunk,
            "edges": [
                {"from": dep, "to": node.node_id}
                for node in bundle.plan.nodes
                for dep in node.deps
            ],
        }

    @app.get("/api/runs/{run_id}/route")
    def run_route(run_id: str) -> dict[str, Any]:
        """What the run actually did, attempt by attempt — the console's execution timeline.

        Derived from the event log, because that is the authority: the plan says what should
        happen, and this says what did. Each `StepLeaseAcquired` opens an attempt, so a retry
        is its own box rather than a counter on a box — which is the difference between
        "this step is fine now" and "this step failed four times before it was fine".

        Every node carries the actions that would actually succeed, with the reason when they
        would not. The console must not offer a button whose only outcome is an error.
        """
        from daedalus.application.route import build_route

        _run_or_404(run_id)
        return build_route(_store(), run_id).to_payload()

    def _validation_service():
        from daedalus.application.independent_validation import IndependentValidationService

        return IndependentValidationService(_store(), state.identity)


    @app.get("/api/runs/{run_id}/validations")
    def run_validations(run_id: str) -> dict[str, Any]:
        _run_or_404(run_id)
        return _validation_service().view(run_id)


    @app.post("/api/runs/{run_id}/validations/evaluate")
    def evaluate_validation(run_id: str) -> dict[str, Any]:
        _run_or_404(run_id)
        return _validation_service().evaluate(run_id)


    @app.post("/api/runs/{run_id}/validations/{validation_id}/attest")
    def attest_validation(
        run_id: str, validation_id: str, request: ValidationAttestationRequest
    ) -> dict[str, Any]:
        _run_or_404(run_id)
        return _validation_service().attest(
            run_id,
            validation_id,
            validator_id=request.validator_id,
            signature=request.signature,
            decision=request.decision,
            review_notes=request.review_notes,
            assessments=[row.model_dump() for row in request.natural_language_assessments],
        )

    @app.get("/api/runs/{run_id}/goal-audit")
    def run_goal_audit(run_id: str) -> dict[str, Any]:
        from daedalus.application.goal_audit import goal_audit_view
        _run_or_404(run_id)
        return goal_audit_view(_store(), run_id)

    @app.get("/api/runs/{run_id}/score")
    def run_score(run_id: str) -> dict[str, Any]:
        """The audit score: how much checkable evidence this run left behind.

        Deliberately *not* a verdict on the change. Every component is computed from persisted
        evidence and returns the facts that produced it, so the number can always be unpacked —
        a score that cannot be decomposed into evidence is the thing this system argues against.
        """
        from daedalus.application.scoring import score_run

        _run_or_404(run_id)
        return score_run(_store(), run_id).to_payload()

    @app.get("/api/runs/{run_id}/specs")
    def run_specs(run_id: str) -> dict[str, Any]:
        """The frozen contract as four specs, each with a summary and its full document.

        The planning module needs a *summary* to show collapsed and the whole spec to show
        expanded. Returning both in one call lets the panel expand without a second round trip
        and without the console re-deriving a summary from the document by hand — a summary
        computed in two places is a summary that disagrees with itself.
        """
        run = _run_or_404(run_id)
        digest = str(run["spec_digest"])
        row = _store().get_spec(digest)
        if row is None:
            raise HTTPException(status_code=409, detail="this run records no registered spec")
        document = json.loads(str(row["document"]))
        approval = state.spec_approvals.approval_view(digest)
        return {
            "spec_digest": digest,
            "risk_level": str(row["risk_level"]),
            "owner_id": str(row["owner_id"]),
            "spec_version": int(row["spec_version"]),
            "parent_spec_digest": str(row["parent_spec_digest"] or ""),
            "created_at": str(row["created_at"]),
            "approval": approval,
            "specs": _spec_cards(document, approval),
        }

    @app.get("/api/runs/{run_id}/steps/{step_id}/log")
    def step_log(run_id: str, step_id: str) -> dict[str, Any]:
        """Resolve a step's `execution_log_ref` (Spec §14).

        The artifact records `audit://<run>/step/<step>`, and this is what makes that
        reference mean something: every event, gate result, artifact and owner decision
        recorded against the step, in order. An unresolvable reference is refused with a
        status that says so, rather than answered with an empty list.
        """
        from daedalus.application.execution_log import UnresolvableLogRef, resolve

        _run_or_404(run_id)
        resolved = _resolve_step_id(run_id, step_id)
        reference = execution_log_ref(run_id, resolved)
        try:
            entries = resolve(_store(), reference)
        except UnresolvableLogRef as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return {"reference": reference, "step_id": resolved, "entries": entries}

    @app.get("/api/runs/{run_id}/steps/{step_id}/patch")
    def step_patch(run_id: str, step_id: str) -> dict[str, Any]:
        """The diff a step produced, so a reviewer can see the change rather than trust a verdict."""
        _run_or_404(run_id)
        resolved = _resolve_step_id(run_id, step_id)
        artifacts = _store().artifacts_for_step(resolved)
        if not artifacts:
            raise HTTPException(status_code=404, detail="this step produced no artifact")
        latest = artifacts[-1]
        document = json.loads(str(latest["document"]))
        extra = document.get("extra", {}) if isinstance(document, dict) else {}
        return {
            "step_id": resolved,
            "artifact_digest": str(latest["artifact_digest"]),
            "status": str(latest["status"]),
            "changed_files": json.loads(str(latest["changed_files"] or "[]")),
            "diff_stat": extra.get("diff_stat", ""),
            "patch": extra.get("patch_preview", ""),
            "truncated": bool(extra.get("patch_truncated", False)),
        }

    @app.get("/api/specs/{spec_digest}")
    def spec_document(spec_digest: str) -> dict[str, Any]:
        """The frozen contract itself: SPEC-01, SPEC-02, SPEC-03 and the Meta-Spec."""
        rows = _store().connection.execute("SELECT spec_digest FROM specs").fetchall()
        matches = [
            str(row["spec_digest"])
            for row in rows
            if str(row["spec_digest"]) == spec_digest or str(row["spec_digest"]).startswith(spec_digest)
        ]
        if not matches:
            raise HTTPException(status_code=404, detail=f"no spec matches {spec_digest}")
        if len(matches) > 1:
            raise HTTPException(status_code=409, detail="ambiguous spec digest prefix")
        row = _store().get_spec(matches[0])
        return {
            "spec_digest": matches[0],
            "risk_level": str(row["risk_level"]),
            "owner_id": str(row["owner_id"]),
            "approved_at": row["approved_at"],
            "approved_by": row["approved_by"],
            "document": json.loads(str(row["document"])),
            **state.spec_approvals.approval_view(matches[0]),
        }

    @app.get("/api/runs/{run_id}/export")
    def export_audit(run_id: str, fmt: str = "jsonl") -> Any:
        """Spec §25's audit export: the trail in a machine-readable form.

        `jsonl` is one event per line, which is what a log pipeline wants; `csv` is what a
        spreadsheet wants.
        """
        _run_or_404(run_id)
        trail = _audit_trail(run_id)
        if fmt == "csv":
            import csv
            import io

            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(
                ["kind", "timestamp", "actor", "step_id", "event_type", "detail", "reference"]
            )
            for entry in trail:
                writer.writerow(
                    [
                        entry["kind"], entry["timestamp"], entry["actor"], entry["step_id"],
                        entry["event_type"], entry["detail"], entry["reference"],
                    ]
                )
            return Response(
                content=buffer.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="{run_id}-audit.csv"'},
            )
        body = "\n".join(json.dumps(entry, sort_keys=True) for entry in trail)
        return Response(
            content=body + "\n",
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="{run_id}-audit.jsonl"'},
        )

    @app.get("/api/runs/{run_id}/timeline")
    def timeline(run_id: str, after: int = Query(default=0, ge=0)) -> dict[str, Any]:
        _run_or_404(run_id)
        rows = _store().timeline_for_run(run_id)
        return {"timeline": [row for row in rows if int(row["timeline_id"]) > after]}

    @app.get("/api/escalations")
    def escalations(run_id: str = "") -> dict[str, Any]:
        return {"escalations": state.approvals.pending_escalations(run_id)}

    @app.get("/api/specs")
    def specs() -> dict[str, Any]:
        rows = _store().connection.execute(
            """
            SELECT spec_digest, goal_id, spec_version, risk_level, owner_id, approved_at,
                   approved_by, created_at
            FROM specs ORDER BY created_at ASC
            """
        ).fetchall()
        return {"specs": [dict(row) for row in rows]}

    @app.get("/api/executions")
    def executions(run_id: str = "") -> dict[str, Any]:
        """Spec §19: one row per bounded execution, with its outcome.

        An `execution_id` used to exist only as a column scattered across `runs`, `steps` and
        `artifacts`, so "what did this execution produce?" had no single answer. Replay chains
        are visible here as `parent_execution_id`.
        """
        rows = _store().list_executions(run_id)
        return {"executions": rows, "count": len(rows)}

    @app.get("/api/workers")
    def workers() -> dict[str, Any]:
        """Spec §19: who executed the work, and what they did."""
        rows = _store().workers_with_counts()
        return {"workers": rows, "count": len(rows)}

    @app.get("/api/owners")
    def owners() -> dict[str, Any]:
        """Spec §3.2: who may sign off, and whether verification is in force.

        The registry is reported with the *policy* it implies, because "3 owners enrolled"
        means nothing without knowing whether approvals now have to be signed.
        """
        registry = state.identity
        return {
            **registry.describe(),
            "owners": [
                {
                    "owner_id": owner.owner_id,
                    "role": owner.role.value,
                    "display_name": owner.display_name,
                    "secret_env": owner.secret_env,
                    "key_fingerprint": owner.key_fingerprint,
                    "created_at": owner.created_at,
                    "revoked_at": owner.revoked_at,
                }
                for owner in registry.list(include_revoked=True)
            ],
        }

    @app.get("/api/metrics")
    def metrics() -> dict[str, Any]:
        return _store().metric_summary()

    @app.get("/api/runs/{run_id}/audit")
    def audit(run_id: str) -> dict[str, Any]:
        """The Spec §27 questions, answered from persisted evidence."""
        run = _run_or_404(run_id)
        spec = _store().get_spec(str(run["spec_digest"]))
        commits = _run_commits(run_id)
        steps = []
        for step in _store().list_steps(run_id):
            view = _step_view(step, commits)
            steps.append(
                {
                    "node_id": view["node_id"],
                    "state": view["state"],
                    "attempt": view["attempt"],
                    "spec_digest": view["spec_digest"],
                    "gates": view["gates"],
                    "artifacts": view["artifacts"],
                    "approvals": view["approvals"],
                }
            )
        commits = [
            event.payload
            for event in _store().events_for_execution(str(run["execution_id"]))
            if event.event_type == "StepCommitted"
        ]
        from daedalus.application.goal_audit import goal_audit_view

        return {
            "run": {
                "run_id": run["run_id"],
                "goal_id": run["goal_id"],
                "status": run["status"],
                "base_commit": run["base_commit"],
                "branch": run["branch"],
                "correlation_id": run["correlation_id"],
                "created_at": run["created_at"],
            },
            "spec": (
                {
                    "digest": run["spec_digest"],
                    "risk_level": spec["risk_level"],
                    "owner_id": spec["owner_id"],
                    "approved_at": spec["approved_at"],
                    "approved_by": spec["approved_by"],
                    "signature": spec["signature"],
                }
                if spec
                else None
            ),
            "steps": steps,
            "goal_audit": goal_audit_view(_store(), run_id),
            "independent_validation": _validation_service().view(run_id),
            "commits": commits,
            "approvals": _store().approvals_for_run(run_id),
        }

    @app.get("/api/backups")
    def backups() -> dict[str, Any]:
        return {"backups": list_backups(state.settings.workspace)}

    def _audit_trail(run_id: str) -> list[dict[str, Any]]:
        """One flat, exportable row per fact: events, gates, approvals and commits."""
        run = _run_or_404(run_id)
        trail: list[dict[str, Any]] = []
        for event in _store().events_for_execution(str(run["execution_id"])):
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
        for step in _store().list_steps(run_id):
            for gate in _store().gate_results_for_step(str(step["step_id"])):
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
            for artifact in _store().artifacts_for_step(str(step["step_id"])):
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
        for approval in _store().approvals_for_run(run_id):
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
        trail.sort(key=lambda entry: entry["timestamp"])
        return trail

    # ---------------------------------------------------------------- model endpoint
    # The console can point Daedalus at a different model without editing the config and
    # restarting. Saved credentials use the OS keychain; remote endpoints require
    # acknowledgement, and the panel reports the effective provider and storage source.

    def model_report():
        with state.model_config_lock:
            result = model_settings.report(state.settings, state.model_override, state.model_overrides)
            result["credential_store"] = state.saved_models.describe()
            result["task_inference_policy"] = "Short structured actions use bounded JSON on supported endpoints; explicit thinking/effort settings are preserved; saved connections are unchanged."
            return result

    @app.get("/api/service")
    def service_status():
        from daedalus.service.control import managed_control
        return {**state.lifecycle.describe(state.dispatcher.busy_runs()),
                "control": managed_control(state.settings), "busy_runs": state.dispatcher.busy_runs()}

    @app.post("/api/service/control", status_code=202)
    def control_service(request: Request, command: ServiceControlRequest):
        # Custom header prevents cross-origin HTML forms from stopping a local service.
        if request.headers.get("x-daedalus-control") != "1":
            raise HTTPException(status_code=403, detail="服务控制需要来自工作台的明确操作")
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            raise HTTPException(status_code=403, detail="不接受来自其他站点的服务控制")
        from daedalus.service.control import managed_control, request_control
        if not managed_control(state.settings)["managed"]:
            raise HTTPException(status_code=409, detail="当前是旧启动方式，请先在终端运行 daedalus 开启托管服务")
        if command.action not in {"stop", "restart"}:
            raise HTTPException(status_code=422, detail="只支持停止或重启")
        state.lifecycle.stopping(command.note or ("用户重启服务" if command.action == "restart" else "用户关闭服务"))
        state.dispatcher.request_stop()
        return request_control(state.settings, command.action, command.note)

    @app.get("/api/runs/{run_id}/recovery")
    def recovery_checkpoint(run_id: str):
        from daedalus.application.service_lifecycle import checkpoint
        _run_or_404(run_id)
        return {**checkpoint(state.store, run_id), "busy": run_id in state.dispatcher.busy_runs()}

    @app.post("/api/runs/{run_id}/recovery-review")
    def review_recovery(run_id: str, request: RecoveryReviewRequest):
        from daedalus.application.service_lifecycle import review_checkpoint
        from daedalus.infrastructure.repository_lock import repository_lock
        _run_or_404(run_id)
        if run_id in state.dispatcher.busy_runs():
            raise HTTPException(status_code=409, detail="任务仍在执行或排队，请等待它停止")
        repo = run_repo_path(state.store, run_id)
        if not repo:
            raise HTTPException(status_code=409, detail="任务未记录原仓库")
        with repository_lock(Path(repo)):
            return review_checkpoint(state.store, run_id, identity=state.identity, **request.model_dump())

    def make_candidate(request, *, probe=False, require_model=True):
        candidate = model_settings.build(
            base_url=request.base_url, model=request.model or ("model-list" if not require_model else ""),
            api_key=request.api_key, timeout_sec=min(request.timeout_sec, 120) if probe else request.timeout_sec,
            role=request.role, acknowledged_remote=True if probe else request.acknowledge_remote,
            api_format=request.api_format, provider=request.provider, api_key_env=request.api_key_env,
            request_options=request.request_options,
        )
        with state.model_config_lock:
            existing = state.model_overrides.get(request.role) or state.model_override
            if request.reuse_existing_key and not candidate.api_key and not candidate.api_key_env and existing:
                if existing.base_url == candidate.base_url and existing.api_format == candidate.api_format and existing.applies_to(request.role or state.settings.default_role):
                    from dataclasses import replace
                    key = state.saved_models.resolve(existing) if existing.credential_ref else existing.api_key
                    candidate = replace(candidate, api_key=key, api_key_env=existing.api_key_env)
        return candidate

    def candidate_client(candidate):
        from daedalus.model.multi_provider import build_client

        def resolve():
            if candidate.api_key or not candidate.api_key_env:
                return candidate.api_key
            broker = SecretBroker(fallback_env_names=())
            return broker.redeem(broker.request("model.api_key", scope=candidate.api_key_env))

        return state.observed_client(build_client(candidate.as_provider(), name="console-model-test", api_key_resolver=resolve), "probe")

    def apply_candidates(candidates, *, persist=False):
        with state.model_config_lock:
            known = {"planner", "coder", "reviewer", *state.settings.providers}
            if any(role and role not in known for role in candidates):
                raise model_settings.ModelOverrideRejected("角色需要是 planner、coder、reviewer 或配置中已存在的角色")
            if persist:
                candidates = state.saved_models.save(candidates)
            if "" in candidates:
                state.model_override = candidates[""]
                state.model_overrides.clear()
            state.model_overrides.update({role:value for role,value in candidates.items() if role})

    @app.get("/api/model/catalog")
    def model_catalog():
        from daedalus.model.catalog import catalog
        return catalog()

    @app.get("/api/model/template")
    def model_template():
        return {"version":1,"roles": {role: {"provider":"deepseek", "api_format":"openai_chat", "base_url":"https://api.deepseek.com", "model":"填写你的模型ID", "api_key_env":"DEEPSEEK_API_KEY"} for role in ("planner", "coder", "reviewer")}}

    @app.get("/api/model/export")
    def export_models():
        from daedalus.application.model_profiles import export
        return export(state.settings, state.model_override, state.model_overrides)

    @app.get("/api/model")
    def get_model() -> dict[str, Any]:
        return model_report()

    @app.post("/api/model")
    def set_model(request: ModelOverrideRequest) -> dict[str, Any]:
        try:
            apply_candidates({request.role:make_candidate(request)}, persist=request.persist)
        except model_settings.ModelOverrideRejected as error:
            raise HTTPException(status_code=422, detail=error.message) from None
        logger.info("model connection updated", extra={"role": request.role or "*"})
        return model_report()

    @app.delete("/api/model")
    def clear_model(role: str = "") -> dict[str, Any]:
        with state.model_config_lock:
            state.saved_models.forget(role)
            if role:
                state.model_overrides.pop(role, None)
            else:
                state.model_override = None
                state.model_overrides.clear()
        return model_report()

    @app.post("/api/model/import/preview")
    def preview_models(request: ModelImportRequest):
        from daedalus.application.model_profiles import parse
        try:
            candidates = parse(request.content, request.format)
        except model_settings.ModelOverrideRejected as error:
            raise HTTPException(status_code=422, detail=error.message) from None
        return {"profiles":[value.describe() for value in candidates.values()],
                "remote_hosts":sorted({value.host for value in candidates.values() if not value.is_loopback}),
                "persisted":False}

    @app.post("/api/model/import")
    def import_models(request: ModelImportRequest):
        from daedalus.application.model_profiles import parse
        try:
            candidates = parse(request.content, request.format)
            if any(not value.is_loopback for value in candidates.values()) and not request.acknowledge_remote:
                raise model_settings.ModelOverrideRejected("导入包含非本机接口，请确认仓库内容会发送到这些接口后再应用")
            apply_candidates(candidates, persist=request.persist)
        except model_settings.ModelOverrideRejected as error:
            raise HTTPException(status_code=422, detail=error.message) from None
        return model_report()

    @app.post("/api/model/models")
    def discover_models(request: ModelTestRequest):
        try:
            candidate = make_candidate(request, probe=True, require_model=False)
            return {"ok":True, "models":candidate_client(candidate).list_models()}
        except DaedalusError as error:
            from daedalus.model.tls import connection_hint
            return {"ok":False,"models":[],"error":error.message,"error_code":error.code,
                    "hint":connection_hint(error, discovery=True)}

    @app.post("/api/model/test")
    def test_model(request: ModelTestRequest) -> dict[str, Any]:
        try:
            candidate = make_candidate(request, probe=True)
        except model_settings.ModelOverrideRejected as error:
            raise HTTPException(status_code=422, detail=error.message) from None
        except DaedalusError as error:
            return {"ok": False, "error": error.message, "error_code": error.code}
        started = time.monotonic()
        try:
            completion = candidate_client(candidate).complete(
                [Message(role="user",content="Reply with the single word: ok")],
                temperature=0.0,max_tokens=512,
            )
        except DaedalusError as error:
            from daedalus.model.tls import connection_hint
            return {"ok":False,"base_url":candidate.base_url,"model":candidate.model,
                    "loopback":candidate.is_loopback,"api_format":candidate.api_format,
                    "error":error.message,"error_code":error.code,"hint":connection_hint(error)}
        return {"ok":True,"base_url":candidate.base_url,"model":candidate.model,
                "loopback":candidate.is_loopback,"api_format":candidate.api_format,
                "latency_ms":int((time.monotonic()-started)*1000),"reply":completion.text.strip()[:200],
                "reported_model":completion.model,"tokens":completion.total_tokens}

    # ------------------------------------------------------------- intake (提任务)
    # The front door. Three steps: submit a task, click through the model's questions, freeze
    # the spec it derives. Nothing here writes to the FSM: `freeze` builds the same
    # `SpecBundle` the run handler would, registers it and then delegates to the ordinary run
    # creation path, so the intake cannot become a second way to start work.

    def _intake_or_404(intake_id: str):
        try:
            return state.intake.load(intake_id)
        except DaedalusError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.get("/api/repos")
    def list_repos() -> dict[str, Any]:
        """Repositories the intake can offer, each with where it came from.

        Two sources, both traceable: repositories past runs recorded, and the immediate
        subdirectories of the configured `workspace.repos_root`. Nothing is guessed, and the
        console still offers a path field for anything not listed.
        """
        return {
            "repos": state.intake.known_repos(),
            "roots": [state.settings.workspace.repos_root]
            if state.settings.workspace.repos_root
            else [],
        }

    @app.post("/api/intakes", status_code=201)
    def start_intake(request: IntakeStartRequest) -> dict[str, Any]:
        """Ask the model what it needs to know. A model failure is a 503, never a silent plan."""
        try:
            outcome = state.intake.start(
                request.repo_path, request.objective, goal_id=request.goal_id
            )
        except IntakeModelUnavailable as error:
            # 503, not 500: this is a dependency being down, and it is retryable once the
            # operator fixes their model config.
            raise HTTPException(status_code=503, detail=str(error)) from error
        except IntakeQuestionsRejected as error:
            raise HTTPException(
                status_code=422,
                detail={"message": str(error), "rejections": list(error.rejections)},
            ) from error
        except DaedalusError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return {
            "intake": outcome.session.to_payload(),
            "facts": outcome.facts.to_payload(),
        }

    @app.get("/api/intakes")
    def list_intakes(limit: int = 20) -> dict[str, Any]:
        return {"intakes": [item.to_payload() for item in state.intake.recent(limit)]}

    @app.get("/api/intakes/{intake_id}")
    def get_intake(intake_id: str) -> dict[str, Any]:
        session = _intake_or_404(intake_id)
        return {"intake": session.to_payload()}

    @app.post("/api/intakes/{intake_id}/answers")
    def answer_intake(intake_id: str, request: IntakeAnswerRequest) -> dict[str, Any]:
        try:
            session = state.intake.answer(
                intake_id,
                request.question_id,
                option_id=request.option_id,
                free_text=request.free_text,
                skip=request.skip,
            )
        except IntakeAnswerRejected as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except DaedalusError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return {"intake": session.to_payload()}

    @app.post("/api/intakes/{intake_id}/spec")
    def derive_intake_spec(intake_id: str) -> dict[str, Any]:
        """Derive the spec from the answers. This does not start anything."""
        session = _intake_or_404(intake_id)
        try:
            _, bundle, adjustments = state.intake.derive(session.intake_id)
        except IntakeModelUnavailable as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        except ModelError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        except (SpecError, SpecValidationError) as error:
            # The model proposed a spec the control plane refuses. That is a 422 with the
            # reason, not a silent repair: the operator is about to freeze this contract.
            raise HTTPException(status_code=422, detail=str(error)) from error
        document = bundle.to_dict()
        return {
            "intake": session.to_payload(with_document=document),
            "document": document,
            "spec_digest": bundle.digest(),
            "adjustments": list(adjustments),
            # The same card summaries the 规划 panel shows, built by the same server-side
            # function. A review screen that summarised the spec its own way would eventually
            # describe a different contract than the one being frozen.
            "specs": _spec_cards(document, {}),
        }

    @app.post("/api/intakes/{intake_id}/freeze", status_code=202)
    def freeze_intake(intake_id: str, request: IntakeFreezeRequest) -> dict[str, Any]:
        """Turn the reviewed spec into a run.

        Deliberately the same code path as `POST /api/runs` from `register_spec` onward:
        approval, the synchronous sign-off refusal and the dispatcher submit are not
        re-implemented, because a second path into the FSM is a second set of invariants.
        """
        session = _intake_or_404(intake_id)
        if not session.spec_digest:
            raise HTTPException(
                status_code=409,
                detail="这次提任务还没有得出 spec；先调用 /spec 生成并复核它",
            )
        try:
            bundle = state.intake.reviewed_bundle(session.intake_id, request.spec_digest)
        except IntakeModelUnavailable as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        except ModelError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        except (SpecError, SpecValidationError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except DaedalusError as error:
            raise HTTPException(status_code=409, detail=error.message) from None

        budget = TokenBudget(max_tokens_per_run=state.settings.quota.max_tokens_per_run)
        worker, tier2 = state.build_worker(
            use_model=request.use_model, enable_review=request.enable_review, budget=budget,
            repo_path=session.repo_path,
        )
        orchestrator = build_orchestrator(
            settings=state.settings,
            store=state.store,
            bundle=bundle,
            repo_path=session.repo_path,
            worker=worker,
            tier2=tier2,
            identity=state.identity,
        )
        orchestrator.register_spec()
        if request.approved_by or request.spec_signature:
            orchestrator.approve_spec(
                approved_by=request.approved_by, signature=request.spec_signature
            )
        try:
            orchestrator.assert_spec_may_run()
        except SpecApprovalRequired as error:
            raise HTTPException(status_code=428, detail=str(error)) from error

        # The receipt must already be readable when the browser follows its run id.
        orchestrator.create_run()
        receipt = state.dispatcher.submit(
            orchestrator.run_id, session.repo_path, orchestrator.run
        )
        state.intake.mark_frozen(
            session.intake_id, run_id=orchestrator.run_id, spec_digest=bundle.digest()
        )
        return {
            **receipt.describe(),
            "intake_id": session.intake_id,
            "run_id": orchestrator.run_id,
            "spec_digest": bundle.digest(),
        }

    @app.post("/api/intakes/{intake_id}/abandon")
    def abandon_intake(intake_id: str) -> dict[str, Any]:
        session = _intake_or_404(intake_id)
        return {"intake": state.intake.abandon(session.intake_id).to_payload()}

    # --------------------------------------------------------------- commands
    @app.post("/api/runs", status_code=202)
    def create_run(request: RunRequest) -> dict[str, Any]:
        repo = Path(request.repo_path).expanduser().resolve()
        if not (repo / ".git").exists():
            raise HTTPException(status_code=400, detail=f"{repo} is not a Git repository")
        if request.requirement_check_id:
            from daedalus.infrastructure.repository_lock import repository_lock
            from daedalus.service.requirement_routes import load_ready
            with repository_lock(repo):
                checked = load_ready(state, request.requirement_check_id, repo,
                                     request.objective, request.target_paths)
                return _accept_run(request, repo, checked)
        return _accept_run(request, repo)

    def _accept_run(request: RunRequest, repo: Path, checked=None) -> dict[str, Any]:
        planner_request = PlanRequest(
            request_id="REQ-API",
            goal_id=request.goal_id,
            objective=request.objective,
            target_paths=tuple(request.target_paths),
            test_command=request.test_command,
            invariants=tuple(request.invariants),
            risk_level=request.risk_level,
            network_policy=request.network_policy,
        )
        budget = TokenBudget(max_tokens_per_run=state.settings.quota.max_tokens_per_run)
        worker, tier2 = state.build_worker(
            use_model=request.use_model, enable_review=request.enable_review, budget=budget,
            repo_path=str(repo),
        )
        if request.use_model:
            from dataclasses import replace
            planner_request = replace(planner_request, extra_context=state.rag.context(
                str(repo), request.objective, phase="planning",
                client=state.build_task_client("planner", "structured_plan"), budget=budget,
                target_paths=tuple(request.target_paths),
            ))
        if request.use_model:
            planner: Any = ModelPlanner(
                client=state.build_task_client("planner", "structured_plan"),
                fallback=DeterministicPlanner(bounds=ResourceBounds.for_quota(state.settings.quota)),
                hardening=SpecHardening(bounds=ResourceBounds.for_quota(state.settings.quota)),
                budget=budget,
            )
        else:
            planner = DeterministicPlanner(bounds=ResourceBounds.for_quota(state.settings.quota))
        bundle = planner.plan(planner_request)
        if checked:
            from dataclasses import replace
            from daedalus.application.requirement_evidence import bind_bundle
            # The qualified run uses the same kernel policy as its baseline check.
            bundle = replace(bundle, boundary=replace(bundle.boundary, isolation="seatbelt"))
            try:
                bundle = bind_bundle(bundle, *checked)
            except ValueError:
                raise HTTPException(409, "the plan no longer matches the qualified requirement "
                                    "scope or goal") from None

        orchestrator = build_orchestrator(
            settings=state.settings,
            store=state.store,
            bundle=bundle,
            repo_path=str(repo),
            worker=worker,
            tier2=tier2,
            identity=state.identity,
        )
        orchestrator.register_spec()
        if request.approve_spec_by or request.spec_signature:
            orchestrator.approve_spec(
                approved_by=request.approve_spec_by,
                signature=request.spec_signature,
            )
        # Refuse synchronously, before anything is created. A 202 that later turns out to have
        # been unsignable is worse than a 428 now.
        orchestrator.assert_spec_may_run()
        # Create the run on the REQUEST thread, not the dispatcher thread. The receipt is
        # supposed to be durable, and it is not durable if following it 404s until the
        # background worker happens to reach `create_run`.
        orchestrator.create_run(base_ref=checked[1]["base_commit"] if checked else "HEAD")

        receipt = state.dispatcher.submit(
            orchestrator.run_id, str(repo), orchestrator.run
        )
        logger.info(
            "accepted run for %s (goal=%s, risk=%s)",
            repo,
            request.goal_id,
            request.risk_level.value,
        )
        return {
            **receipt.describe(),
            "execution_id": orchestrator.execution_id,
            "spec_digest": bundle.digest(),
            "risk_level": bundle.goal.risk_level.value,
            "whitelist": list(bundle.boundary.fs_whitelist),
            **({"requirement_check_id": request.requirement_check_id} if checked else {}),
        }

    @app.post("/api/runs/{run_id}/approve")
    def approve(run_id: str, request: ApprovalRequest) -> dict[str, Any]:
        _run_or_404(run_id)
        step_id = _resolve_step_id(run_id, request.step)
        result = state.approvals.approve(
            run_id=run_id,
            step_id=step_id,
            decision=request.decision,
            approved_by=request.approved_by,
            note=request.note,
            artifact_digest=request.artifact_digest,
            granted_attempts=request.granted_attempts,
            signature=request.signature,
        )
        return result.describe()

    @app.post("/api/runs/{run_id}/resume", status_code=202)
    def resume(run_id: str) -> dict[str, Any]:
        run = _run_or_404(run_id)
        repo_path = run_repo_path(_store(), run_id)
        if not repo_path:
            raise HTTPException(status_code=409, detail="the run records no repository path")
        from daedalus.application.service_lifecycle import assert_checkpoint_reviewed, checkpoint
        try:
            assert_checkpoint_reviewed(state.store, run_id, identity=state.identity)
        except DaedalusError as error:
            raise HTTPException(status_code=409, detail={"message": error.message, "recovery_required": True}) from None

        from daedalus.application.independent_validation import pending_validation
        request = pending_validation(_store(), run_id)
        if request:
            # A refusal leaves the run parked; never enqueue a known-invalid delivery.
            _validation_service().authorise_delivery(run_id, request["commit"])

        worker, tier2 = (None, None)
        if checkpoint(state.store, run_id)["frontier"]:
            worker, tier2 = state.build_worker(use_model=True, enable_review=True,
                                              repo_path=repo_path)

        def invoke():
            return resume_run(
                store=state.store,
                run_id=run_id,
                workspace=str(state.settings.workspace.root_path),
                park_on_escalation=state.settings.execution.park_on_escalation,
                manual_review_levels=tuple(state.settings.policy.manual_review_levels),
                max_parallel_steps=state.settings.quota.max_parallel_steps,
                worker=worker,
                tier2=tier2,
                # Without this a resume would have no registry and would treat the workspace
                # as unenrolled, silently undoing enforcement configured after the run parked.
                identity=state.identity,
            )

        receipt = state.dispatcher.submit(run_id, repo_path, invoke)
        return {**receipt.describe(), "status_before": str(run["status"])}

    @app.post("/api/runs/{run_id}/rollback")
    def rollback(run_id: str, request: RollbackRequest) -> dict[str, Any]:
        _run_or_404(run_id)
        result = state.replay.rollback(
            run_id, reason=request.reason, to_commit=request.to_commit
        )
        return result.describe()

    @app.post("/api/runs/{run_id}/replay", status_code=202)
    def replay(run_id: str, request: ReplayRequest) -> dict[str, Any]:
        run = _run_or_404(run_id)
        repo_path = run_repo_path(_store(), run_id)
        if not repo_path:
            raise HTTPException(status_code=409, detail="the run records no repository path")
        bundle = _bundle_for(run_id)
        replay_from = request.from_commit.strip() or str(run["base_commit"])
        if request.from_commit.strip():
            known = _known_commits(run_id)
            if replay_from not in known:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"{replay_from[:12]} is not a commit this run recorded. Replay needs a "
                        "base it can name: pass one of the run's step commits or its own base."
                    ),
                )
        if request.rollback_first:
            state.replay.rollback(
                run_id, reason=request.reason, to_commit=request.from_commit.strip()
            )

        worker, tier2 = state.build_worker(use_model=request.use_model, enable_review=False)
        orchestrator = build_orchestrator(
            settings=state.settings,
            store=state.store,
            bundle=bundle,
            repo_path=repo_path,
            worker=worker,
            tier2=tier2,
            run_root=state.settings.workspace.worktrees_path / "replays",
            identity=state.identity,
        )
        orchestrator.parent_execution_id = str(run["execution_id"])
        orchestrator.replay_from_commit = replay_from
        orchestrator.reuse_artifacts = True
        orchestrator.register_spec()
        orchestrator.create_run()
        receipt = state.dispatcher.submit(orchestrator.run_id, repo_path, orchestrator.run)
        return {
            **receipt.describe(),
            "replayed_execution_id": str(run["execution_id"]),
            "replay_from_commit": replay_from,
        }

    def _known_commits(run_id: str) -> set[str]:
        """Every commit this run can legitimately replay from.

        The set is built from what the run recorded — its own base, each step's base, each
        artifact's parent, and the commit each step committed — so a typo cannot silently become
        a replay of something unrelated, and a caller cannot point a replay at an arbitrary commit
        of the repository.

        The committed commits come from the event log because that is the only place they exist:
        `artifacts` stores the tree a step was based on, not the one it produced. Leaving them out
        made the refusal below reject the single commit an operator is most likely to name.
        """
        run = _store().get_run(run_id)
        if run is None:
            return set()
        commits = {str(run["base_commit"])} if run["base_commit"] else set()
        commits.update(_run_commits(run_id).values())
        for step in _store().list_steps(run_id):
            if step["base_commit"]:
                commits.add(str(step["base_commit"]))
        for step in _store().list_steps(run_id):
            for artifact in _store().artifacts_for_step(str(step["step_id"])):
                if artifact["parent_commit"]:
                    commits.add(str(artifact["parent_commit"]))
        return commits

    @app.post("/api/specs/{spec_digest}/approve")
    def approve_spec(spec_digest: str, request: SpecApprovalRequest) -> dict[str, Any]:
        rows = _store().connection.execute("SELECT spec_digest FROM specs").fetchall()
        digests = [str(row["spec_digest"]) for row in rows]
        matches = [d for d in digests if d == spec_digest or d.startswith(spec_digest)]
        if not matches:
            raise HTTPException(status_code=404, detail=f"no spec matches {spec_digest}")
        if len(matches) > 1:
            raise HTTPException(status_code=409, detail="ambiguous spec digest prefix")
        digest = matches[0]
        # One implementation, shared with the orchestrator. This endpoint used to write the
        # approval straight to the projection, so a signature supplied here was stored and
        # never checked — the one place where that is least acceptable.
        outcome = state.spec_approvals.record(
            spec_digest=digest,
            approved_by=request.approved_by,
            signature=request.signature,
        )
        return {
            "spec_digest": digest,
            "approved_by": outcome.owner_id,
            "verified": outcome.verified,
            "approval_scheme": outcome.scheme,
            "key_fingerprint": outcome.fingerprint,
            "statement": state.spec_approvals.approval_view(digest)["statement"],
        }

    @app.post("/api/recover")
    def recover(apply: bool = False) -> dict[str, Any]:
        if apply and state.dispatcher.active_runs():
            raise HTTPException(status_code=409, detail="正在执行任务，请在任务停止后修复工作区。")
        report = recover_workspace(
            store=_store(),
            apply=apply,
            worktrees_root=state.settings.workspace.worktrees_path,
        )
        return report.describe()

    @app.post("/api/backup")
    def backup(label: str = "") -> dict[str, Any]:
        try:
            result = create_backup(state.settings.workspace, label=label)
        except BackupError as error:
            raise HTTPException(status_code=409, detail=error.message) from error
        return result.describe()

    @app.post("/api/restore")
    def restore(request: RestoreRequest) -> dict[str, Any]:
        try:
            result = restore_backup(
                state.settings.workspace, source=request.source, force=request.force
            )
        except BackupError as error:
            raise HTTPException(status_code=409, detail=error.message) from error
        return result.describe()

    @app.post("/api/classify-change")
    def classify(
        previous_spec: str = Body(...), current_spec: str = Body(...)
    ) -> dict[str, Any]:
        """Spec §13.1 classification, exposed so an operator can predict a replay's scope."""
        before = _store().get_spec(previous_spec)
        after = _store().get_spec(current_spec)
        if before is None or after is None:
            raise HTTPException(status_code=404, detail="one of the specs is not registered")
        report = classify_spec_change(
            SpecBundle.from_dict(json.loads(str(before["document"]))),
            SpecBundle.from_dict(json.loads(str(after["document"]))),
        )
        return report.describe()

    # ---------------------------------------------------------------- console
    if templates is not None:

        def _render(request: Request, template: str, **context: Any) -> HTMLResponse:
            return templates.TemplateResponse(
                request,
                template,
                {
                    "version": __version__,
                    "workspace": str(state.settings.workspace.root_path),
                    "settings": state.settings.describe(),
                    "service_lifecycle": state.lifecycle.describe(state.dispatcher.busy_runs()),
                    **context,
                },
            )

        # The console opens on the work, not on a dashboard. `/` is the intake: one sentence in,
        # a few clicked questions, a reviewed spec, a run. The run list moved to `/runs` because
        # a list of what already happened is not a place to start from.
        @app.get("/", response_class=HTMLResponse)
        def console_intake(request: Request) -> HTMLResponse:
            """提任务 — submit a task and answer the model's questions to derive a spec."""
            with log_context(component="console"):
                return _render(request, "intake.html", page="intake")

        @app.get("/runs", response_class=HTMLResponse)
        def console_landing(request: Request) -> HTMLResponse:
            """The run list and the headline rates."""
            with log_context(component="console"):
                return _render(request, "board.html", page="board")

        @app.get("/planning", response_class=HTMLResponse)
        def console_planning(request: Request, run: str = "") -> HTMLResponse:
            if run:
                _run_or_404(run)
            return _render(request, "planning.html", page="planning", run_id=run)

        @app.get("/planning/{run_id}", response_class=HTMLResponse)
        def console_planning_run(request: Request, run_id: str) -> HTMLResponse:
            _run_or_404(run_id)
            return _render(request, "planning.html", page="planning", run_id=run_id)

        @app.get("/execution", response_class=HTMLResponse)
        def console_execution(request: Request, run: str = "") -> HTMLResponse:
            if run:
                _run_or_404(run)
            return _render(request, "execution.html", page="execution", run_id=run)

        @app.get("/execution/{run_id}", response_class=HTMLResponse)
        def console_execution_run(request: Request, run_id: str) -> HTMLResponse:
            _run_or_404(run_id)
            return _render(request, "execution.html", page="execution", run_id=run_id)

        @app.get("/audit", response_class=HTMLResponse)
        def console_audit_page(request: Request, run: str = "") -> HTMLResponse:
            if run:
                _run_or_404(run)
            return _render(request, "audit.html", page="audit", run_id=run)

        @app.get("/audit/{run_id}", response_class=HTMLResponse)
        def console_audit_run(request: Request, run_id: str) -> HTMLResponse:
            _run_or_404(run_id)
            return _render(request, "audit.html", page="audit", run_id=run_id)

        @app.get("/runs/{run_id}", response_class=HTMLResponse)
        def console_run(request: Request, run_id: str) -> HTMLResponse:
            """A run's own page moved into the execution module; keep the old URL working."""
            _run_or_404(run_id)
            return RedirectResponse(f"/execution/{run_id}", status_code=307)

        @app.get("/escalations", response_class=HTMLResponse)
        def console_escalations(request: Request) -> HTMLResponse:
            return _render(request, "escalations.html", page="escalations")

        @app.get("/operations", response_class=HTMLResponse)
        def console_operations(request: Request) -> HTMLResponse:
            return _render(request, "operations.html", page="operations")

    return app


def main() -> None:  # pragma: no cover - exercised through the console, not unit tests
    """Entry point for `daedalus serve`."""
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(prog="daedalus serve")
    parser.add_argument("--config", default="")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()

    try:
        settings = load_settings(
            args.config or None,
            host=args.host or None,
            port=args.port or None,
        )
    except ConfigError as error:
        raise SystemExit(f"configuration error: {error.message}") from error

    app = create_app(settings)
    print(
        f"Daedalus console on http://{settings.service.host}:{settings.service.port}\n"
        f"  workspace: {settings.workspace.root_path}\n"
        f"  database : {settings.workspace.database_path}"
    )
    uvicorn.run(app, host=settings.service.host, port=settings.service.port,
                log_level=args.log_level, proxy_headers=False)


if __name__ == "__main__":  # pragma: no cover
    main()
