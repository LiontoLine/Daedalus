"""Configuration (file -> environment -> explicit override).

A deliverable system cannot be configured entirely through command-line flags. This module
is the single place settings come from, with a fixed precedence so an operator can always
tell which layer won:

    built-in defaults  <  config file  <  DAEDALUS_* environment  <  explicit argument

Credentials are **never** stored here. A provider declares the *name* of the environment
variable that holds its key, and the key is resolved at call time through the SecretBroker
(Spec §8).
"""

from __future__ import annotations

import os
import math
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from daedalus.errors import DaedalusError
from daedalus.infrastructure.redact import is_secret_key

CONFIG_FILENAME = "daedalus.toml"
ENV_PREFIX = "DAEDALUS_"

EXAMPLE_CONFIG = '''# Daedalus configuration.
# Precedence: these values < DAEDALUS_* environment variables < explicit CLI arguments.
# Credentials are NEVER written here. A provider names the environment variable that
# holds its key; the key is resolved at call time through the SecretBroker.

[workspace]
# Where the event store, worktrees and backups live. One workspace per deployment.
root = "./.daedalus"
# The branch a successful run is fast-forwarded onto.
target_branch = "main"

[quota]
max_parallel_steps = 2
max_cpu = 4.0
max_memory_mb = 8192
max_llm_requests = 200
max_tokens_per_run = 200000

[execution]
# How long a worker lease lives before the step is reclaimed as LOST.
lease_ttl_sec = 120
# Upper bound on attempts per step. The retry policy in SPEC-02 may lower it, never raise it.
max_attempts = 3
# Spec §11.1: a commit requires that the execution has not expired. 0 disables the check.
execution_ttl_sec = 86400
# Spec §17: exponential backoff between infrastructure retries. 0 retries immediately.
retry_backoff_sec = 1.0
retry_backoff_factor = 2.0
# Park the run in AWAITING_APPROVAL when a step escalates, instead of ending it.
# Leave this true in production: an escalation is a question for a human.
park_on_escalation = true

[policy]
# Risk levels that may never auto-merge on a semantic review alone.
manual_review_levels = ["critical"]
independent_validation_levels = ["high", "critical"]
# Default network posture; SPEC-03 may only narrow it.
network_policy = "deny"

[identity]
# Spec §3.2. Owners are registered with `daedalus owners add`; their signing secrets live in
# the environment variable named at enrolment and are NEVER written here or in the database.
# Once any owner is enrolled, every spec approval must be a signature that verifies.
# `required = true` additionally refuses HIGH/CRITICAL work until such an approval exists,
# which is what a production deployment wants.
required = false

[service]
host = "127.0.0.1"
port = 13475
# Bounded concurrency for runs dispatched through the service.
max_concurrent_runs = 2

[model]
# The role used when a run does not name one.
default_role = "coder"

[model.planner]
base_url = "https://api.openai.com/v1"
model = "gpt-4o-mini"
api_key_env = "DAEDALUS_MODEL_API_KEY"
timeout_sec = 120

[model.coder]
base_url = "https://api.openai.com/v1"
model = "gpt-4o-mini"
api_key_env = "DAEDALUS_MODEL_API_KEY"
timeout_sec = 180

[model.reviewer]
base_url = "https://api.openai.com/v1"
model = "gpt-4o-mini"
api_key_env = "DAEDALUS_MODEL_API_KEY"
timeout_sec = 120
'''


class ConfigError(DaedalusError):
    code = "config_error"


@dataclass(frozen=True, slots=True)
class WorkspaceSettings:
    root: str = "./.daedalus"
    target_branch: str = "main"
    #: Optional directory whose immediate subdirectories are offered as repositories on the
    #: intake screen. Empty means "only repositories past runs recorded", which is the honest
    #: default: this process has no business guessing where someone keeps their code.
    repos_root: str = ""

    @property
    def root_path(self) -> Path:
        return Path(self.root).expanduser()

    @property
    def database_path(self) -> Path:
        return self.root_path / "daedalus.db"

    @property
    def worktrees_path(self) -> Path:
        return self.root_path / "worktrees"

    @property
    def backups_path(self) -> Path:
        return self.root_path / "backups"

    @property
    def logs_path(self) -> Path:
        return self.root_path / "logs"


@dataclass(frozen=True, slots=True)
class QuotaSettings:
    max_parallel_steps: int = 2
    max_cpu: float = 4.0
    max_memory_mb: int = 8192
    max_llm_requests: int = 200
    max_tokens_per_run: int = 200_000

    def validate(self) -> None:
        if not math.isfinite(self.max_cpu) or self.max_cpu <= 0 or self.max_memory_mb <= 0:
            raise ConfigError("quota CPU and memory limits must be positive and finite")
        if self.max_llm_requests <= 0:
            raise ConfigError("quota.max_llm_requests must be positive")
        if self.max_parallel_steps < 1:
            raise ConfigError("quota.max_parallel_steps must be at least 1")
        if self.max_parallel_steps > 16:
            raise ConfigError(
                "quota.max_parallel_steps above 16 is refused: each step costs a full "
                "worktree, and an unbounded fan-out defeats the resource boundary"
            )
        if self.max_tokens_per_run < 1000:
            raise ConfigError("quota.max_tokens_per_run must be at least 1000")


@dataclass(frozen=True, slots=True)
class ExecutionSettings:
    lease_ttl_sec: int = 120
    max_attempts: int = 3
    park_on_escalation: bool = True
    #: Spec §11.1 lists "the execution has not expired" as a commit precondition. 0 disables
    #: the check. A default of 24h means a run left overnight cannot land a commit against a
    #: base that the world has moved past.
    execution_ttl_sec: int = 86_400
    #: Spec §17: exponential backoff for infrastructure retries. Set to 0 to retry immediately.
    retry_backoff_sec: float = 1.0
    retry_backoff_factor: float = 2.0
    retry_backoff_cap_sec: float = 30.0

    def validate(self) -> None:
        if self.lease_ttl_sec < 5:
            raise ConfigError("execution.lease_ttl_sec below 5s would cause spurious LOST steps")
        if self.lease_ttl_sec > 3600:
            raise ConfigError("execution.lease_ttl_sec above 3600s delays crash recovery badly")
        if not 1 <= self.max_attempts <= 10:
            raise ConfigError("execution.max_attempts must be within 1..10 (no infinite retry)")
        if self.execution_ttl_sec < 0:
            raise ConfigError("execution.execution_ttl_sec must not be negative")
        if self.retry_backoff_sec < 0 or self.retry_backoff_factor < 1:
            raise ConfigError(
                "execution.retry_backoff_sec must be >= 0 and retry_backoff_factor >= 1"
            )


@dataclass(frozen=True, slots=True)
class PolicySettings:
    manual_review_levels: tuple[str, ...] = ("critical",)
    independent_validation_levels: tuple[str, ...] = ("high", "critical")
    network_policy: str = "deny"

    def validate(self) -> None:
        allowed = {"low", "normal", "high", "critical"}
        unknown = sorted((set(self.manual_review_levels) | set(self.independent_validation_levels)) - allowed)
        if unknown:
            raise ConfigError(f"policy.manual_review_levels has unknown entries: {unknown}")
        if self.network_policy not in {"deny", "allowlist"}:
            raise ConfigError("policy.network_policy must be 'deny' or 'allowlist'")


@dataclass(frozen=True, slots=True)
class IdentitySettings:
    """Spec §3.2 owner identity and approval authority.

    `required = false` does not mean "identity is off": it means "do not demand enrolment in
    a workspace that has none". Once any owner is enrolled, approvals are verified whether or
    not this flag is set — a half-enrolled registry that still accepted unsigned approvals
    would be worse than no registry, because the deployment would believe it had a control
    it did not have.
    """

    #: Refuse to run HIGH/CRITICAL work at all until a verified sign-off exists.
    required: bool = False

    def validate(self) -> None:
        # No combinations to reject: `required` is a single boolean and the effective policy
        # is derived from it plus the registry. Kept so the section is validated like every
        # other, which is what the config loader and its tests expect.
        return


@dataclass(frozen=True, slots=True)
class ServiceSettings:
    host: str = "127.0.0.1"
    port: int = 13475
    max_concurrent_runs: int = 2
    auth_required: bool = False

    def validate(self) -> None:
        if type(self.auth_required) is not bool:
            raise ConfigError("service.auth_required must be a boolean")
        if not 1 <= self.port <= 65535:
            raise ConfigError("service.port must be within 1..65535")
        if self.max_concurrent_runs < 1:
            raise ConfigError("service.max_concurrent_runs must be at least 1")


@dataclass(frozen=True, slots=True)
class ProviderSettings:
    name: str
    base_url: str = "https://api.openai.com/v1"
    model: str = ""
    api_key_env: str = "DAEDALUS_MODEL_API_KEY"
    timeout_sec: int = 120
    api_format: str = "openai_chat"
    provider: str = "custom"
    request_options: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        from daedalus.model.multi_provider import validate_options
        try:
            validate_options(self.api_format, self.request_options)
        except DaedalusError as error:
            raise ConfigError(error.message) from error
        if not self.model:
            raise ConfigError(f"model.{self.name}.model must name a model")
        if not self.base_url.startswith(("http://", "https://")):
            raise ConfigError(f"model.{self.name}.base_url must be an http(s) URL")
        if not self.api_key_env:
            raise ConfigError(
                f"model.{self.name}.api_key_env must name the environment variable holding "
                "the key; the key itself must never be written into the config file"
            )
        if is_secret_key(self.model) or "sk-" in self.model:
            raise ConfigError(
                f"model.{self.name}.model looks like a credential; put the key in the "
                "environment variable named by api_key_env instead"
            )


@dataclass(frozen=True, slots=True)
class Settings:
    workspace: WorkspaceSettings = field(default_factory=WorkspaceSettings)
    quota: QuotaSettings = field(default_factory=QuotaSettings)
    execution: ExecutionSettings = field(default_factory=ExecutionSettings)
    policy: PolicySettings = field(default_factory=PolicySettings)
    identity: IdentitySettings = field(default_factory=IdentitySettings)
    service: ServiceSettings = field(default_factory=ServiceSettings)
    providers: dict[str, ProviderSettings] = field(default_factory=dict)
    default_role: str = "coder"
    source_path: str = ""

    def validate(self) -> None:
        self.quota.validate()
        self.execution.validate()
        self.policy.validate()
        self.identity.validate()
        self.service.validate()
        for provider in self.providers.values():
            provider.validate()
        if self.providers and self.default_role not in self.providers:
            raise ConfigError(
                f"model.default_role is {self.default_role!r} but no such provider is "
                f"configured (known: {sorted(self.providers)})"
            )
        if not self.workspace.root.strip():
            raise ConfigError("workspace.root must not be empty")

    def provider(self, role: str = "") -> ProviderSettings:
        wanted = role or self.default_role
        if wanted not in self.providers:
            raise ConfigError(
                f"no model provider configured for role {wanted!r} "
                f"(known: {sorted(self.providers)})"
            )
        return self.providers[wanted]

    def ensure_directories(self) -> None:
        for path in (
            self.workspace.root_path,
            self.workspace.worktrees_path,
            self.workspace.backups_path,
            self.workspace.logs_path,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def describe(self) -> dict[str, Any]:
        return {
            "source": self.source_path or "<defaults>",
            "workspace_root": str(self.workspace.root_path),
            "database": str(self.workspace.database_path),
            "target_branch": self.workspace.target_branch,
            "max_parallel_steps": self.quota.max_parallel_steps,
            "lease_ttl_sec": self.execution.lease_ttl_sec,
            "max_attempts": self.execution.max_attempts,
            "park_on_escalation": self.execution.park_on_escalation,
            "execution_ttl_sec": self.execution.execution_ttl_sec,
            "retry_backoff_sec": self.execution.retry_backoff_sec,
            "network_policy": self.policy.network_policy,
            "manual_review_levels": list(self.policy.manual_review_levels),
            "independent_validation_levels": list(self.policy.independent_validation_levels),
            "identity_required": self.identity.required,
            "service": f"{self.service.host}:{self.service.port}",
            "providers": {
                role: {
                    "base_url": provider.base_url,
                    "model": provider.model,
                    "api_format": provider.api_format,
                    "provider": provider.provider,
                    "api_key_env": provider.api_key_env,
                    "key_present": bool(os.environ.get(provider.api_key_env)),
                }
                for role, provider in sorted(self.providers.items())
            },
        }


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_ENV_FIELDS: dict[str, tuple[str, str, type]] = {
    # ENV SUFFIX -> (section, field, type)
    "WORKSPACE_ROOT": ("workspace", "root", str),
    "TARGET_BRANCH": ("workspace", "target_branch", str),
    "MAX_PARALLEL_STEPS": ("quota", "max_parallel_steps", int),
    "MAX_TOKENS_PER_RUN": ("quota", "max_tokens_per_run", int),
    "LEASE_TTL_SEC": ("execution", "lease_ttl_sec", int),
    "MAX_ATTEMPTS": ("execution", "max_attempts", int),
    "PARK_ON_ESCALATION": ("execution", "park_on_escalation", bool),
    "EXECUTION_TTL_SEC": ("execution", "execution_ttl_sec", int),
    "RETRY_BACKOFF_SEC": ("execution", "retry_backoff_sec", float),
    "RETRY_BACKOFF_FACTOR": ("execution", "retry_backoff_factor", float),
    "NETWORK_POLICY": ("policy", "network_policy", str),
    "IDENTITY_REQUIRED": ("identity", "required", bool),
    "SERVICE_HOST": ("service", "host", str),
    "SERVICE_PORT": ("service", "port", int),
    "MAX_CONCURRENT_RUNS": ("service", "max_concurrent_runs", int),
    "MODEL_BASE_URL": ("provider", "base_url", str),
    "MODEL_NAME": ("provider", "model", str),
    "MODEL_API_KEY_ENV": ("provider", "api_key_env", str),
    "MODEL_TIMEOUT_SEC": ("provider", "timeout_sec", int),
    # The credential itself. Never echoed anywhere, only presence is reported.
    "MODEL_API_KEY": ("__credential__", "DAEDALUS_MODEL_API_KEY", str),
}

_SECTION_TYPES: dict[str, type] = {
    "workspace": WorkspaceSettings,
    "quota": QuotaSettings,
    "execution": ExecutionSettings,
    "policy": PolicySettings,
    "identity": IdentitySettings,
    "service": ServiceSettings,
}


def find_config_file(start: str | Path | None = None) -> Path | None:
    """Look for `daedalus.toml` in the given directory, then its parents."""
    current = Path(start or Path.cwd()).expanduser().resolve()
    for candidate in (current, *current.parents):
        path = candidate / CONFIG_FILENAME
        if path.is_file():
            return path
    return None


def load_settings(
    config_path: str | Path | None = None,
    *,
    environ: dict[str, str] | None = None,
    require_config: bool = False,
    **overrides: Any,
) -> Settings:
    """Load settings with a fixed precedence and fail fast on anything ambiguous."""
    env = dict(os.environ if environ is None else environ)
    path: Path | None = None
    if config_path:
        path = Path(config_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
    else:
        path = find_config_file()
        if path is None and require_config:
            raise ConfigError(
                f"no {CONFIG_FILENAME} found in this directory or any parent; run "
                "`daedalus init` to create one"
            )

    raw: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8")) if path else {}
    settings = _from_mapping(raw, source_path=str(path) if path else "")
    settings = _apply_environment(settings, env)
    if overrides:
        settings = _apply_overrides(settings, {k: v for k, v in overrides.items() if v is not None})
    settings.validate()
    return settings


def _from_mapping(raw: dict[str, Any], *, source_path: str) -> Settings:
    sections: dict[str, Any] = {}
    for name, section_type in _SECTION_TYPES.items():
        payload = raw.get(name) or {}
        if not isinstance(payload, dict):
            raise ConfigError(f"[{name}] must be a table")
        known = {f.name for f in fields(section_type)}
        unknown = sorted(set(payload) - known)
        if unknown:
            raise ConfigError(
                f"unknown key(s) in [{name}]: {unknown}. A misspelled setting that is "
                "silently ignored is worse than a startup failure."
            )
        if name == "policy":
            payload = dict(payload)
            for key in ("manual_review_levels", "independent_validation_levels"):
                if key in payload:
                    if not isinstance(payload[key], list):
                        raise ConfigError(f"policy.{key} must be an array of risk levels")
                    payload[key] = tuple(payload[key])
        sections[name] = section_type(**payload)

    model_raw = raw.get("model") or {}
    if not isinstance(model_raw, dict):
        raise ConfigError("[model] must be a table")
    default_role = str(model_raw.get("default_role", "coder"))
    providers: dict[str, ProviderSettings] = {}
    for role, payload in model_raw.items():
        if role == "default_role":
            continue
        if not isinstance(payload, dict):
            raise ConfigError(f"[model.{role}] must be a table")
        known = {f.name for f in fields(ProviderSettings)} - {"name"}
        unknown = sorted(set(payload) - known)
        if unknown:
            raise ConfigError(f"unknown key(s) in [model.{role}]: {unknown}")
        providers[role] = ProviderSettings(name=role, **payload)

    return Settings(
        workspace=sections["workspace"],
        quota=sections["quota"],
        execution=sections["execution"],
        policy=sections["policy"],
        identity=sections["identity"],
        service=sections["service"],
        providers=providers,
        default_role=default_role,
        source_path=source_path,
    )


def _apply_environment(settings: Settings, env: dict[str, str]) -> Settings:
    patches: dict[str, dict[str, Any]] = {}
    for suffix, (section, field_name, caster) in _ENV_FIELDS.items():
        key = f"{ENV_PREFIX}{suffix}"
        if key not in env:
            continue
        if section == "__credential__":
            continue  # read by the SecretBroker, never folded into settings
        if section == "provider":
            # Applied to every configured provider, so a deployment can point all roles at
            # one gateway without repeating itself.
            for role, provider in settings.providers.items():
                patches.setdefault(f"__provider__{role}", {})[field_name] = _cast(
                    key, env[key], caster
                )
            continue
        patches.setdefault(section, {})[field_name] = _cast(key, env[key], caster)

    providers = dict(settings.providers)
    for key, values in list(patches.items()):
        if key.startswith("__provider__"):
            role = key.removeprefix("__provider__")
            providers[role] = replace(providers[role], **_without_name(values))
            del patches[key]

    return replace(
        settings,
        providers=providers,
        **{name: replace(getattr(settings, name), **values) for name, values in patches.items()},
    )


def _apply_overrides(settings: Settings, overrides: dict[str, Any]) -> Settings:
    """Explicit arguments win over everything. Only the flat keys below are honoured."""
    simple = {
        "workspace_root": ("workspace", "root"),
        "target_branch": ("workspace", "target_branch"),
        "max_parallel_steps": ("quota", "max_parallel_steps"),
        "max_tokens_per_run": ("quota", "max_tokens_per_run"),
        "lease_ttl_sec": ("execution", "lease_ttl_sec"),
        "max_attempts": ("execution", "max_attempts"),
        "park_on_escalation": ("execution", "park_on_escalation"),
        "execution_ttl_sec": ("execution", "execution_ttl_sec"),
        "retry_backoff_sec": ("execution", "retry_backoff_sec"),
        "network_policy": ("policy", "network_policy"),
        "host": ("service", "host"),
        "port": ("service", "port"),
        "max_concurrent_runs": ("service", "max_concurrent_runs"),
    }
    patches: dict[str, dict[str, Any]] = {}
    for key, value in overrides.items():
        if key in simple:
            section, field_name = simple[key]
            patches.setdefault(section, {})[field_name] = value
    return replace(
        settings,
        **{name: replace(getattr(settings, name), **values) for name, values in patches.items()},
    )


def _without_name(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if k != "name"}


def _cast(key: str, raw: str, caster: type) -> Any:
    if caster is bool:
        lowered = raw.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
        raise ConfigError(f"{key} must be a boolean, got {raw!r}")
    if caster is int:
        try:
            return int(raw)
        except ValueError:
            raise ConfigError(f"{key} must be an integer, got {raw!r}") from None
    if caster is float:
        try:
            return float(raw)
        except ValueError:
            raise ConfigError(f"{key} must be a number, got {raw!r}") from None
    return raw


def write_example_config(path: str | Path, *, force: bool = False) -> Path:
    target = Path(path).expanduser()
    if target.exists() and not force:
        raise ConfigError(f"{target} already exists; pass force=True to overwrite")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    return target
