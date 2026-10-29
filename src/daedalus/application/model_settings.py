# ruff: noqa: RUF001
"""Validated model connections, editable from the console (Spec §8).

Temporary connections live in memory. With explicit safe-save enabled, SavedModelProfiles
stores credentials and their endpoint bindings in the OS keychain and writes only public
connection settings to the workspace. Responses expose fingerprints, never credentials.
Remote endpoints still require acknowledgement, and the console reports the effective
provider and storage source for every role, including after a restart.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from daedalus.config import ProviderSettings
from daedalus.domain.ids import utc_now
from daedalus.errors import DaedalusError

#: Hosts for which a model call does not leave the machine.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"})


def is_loopback_host(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


MAX_TIMEOUT_SEC = 900
MIN_TIMEOUT_SEC = 5


class ModelOverrideRejected(DaedalusError):
    """The endpoint the operator typed cannot be used, and the reason is theirs to act on."""


@dataclass(frozen=True, slots=True)
class ModelOverride:
    """A validated endpoint with an inline credential or a private keychain reference."""

    base_url: str
    model: str
    api_key: str = field(repr=False)
    timeout_sec: int = 120
    #: Empty means "every role"; otherwise only that role is redirected.
    role: str = ""
    #: True when the operator was told and agreed that a non-loopback endpoint sends their
    #: repository contents off this machine.
    acknowledged_remote: bool = False
    set_at: str = field(default_factory=utc_now)
    api_format: str = "openai_chat"
    provider: str = "custom"
    api_key_env: str = ""
    request_options: dict = field(default_factory=dict)
    persisted: bool = False
    credential_ref: str = field(default="", repr=False)
    credential_fingerprint: str = field(default="", repr=False)

    @property
    def host(self) -> str:
        return (urlparse(self.base_url).hostname or "").lower()

    @property
    def is_loopback(self) -> bool:
        return is_loopback_host(self.host)

    def applies_to(self, role: str) -> bool:
        return not self.role or self.role == role

    def fingerprint(self) -> str:
        """A stable, non-reversible tag for the key, so two keys can be told apart.

        Returned to the console in place of the key. Twelve hex characters of a SHA-256 is not a
        credential and cannot be turned back into one, which is the point.
        """
        if not self.api_key:
            return self.credential_fingerprint
        return hashlib.sha256(self.api_key.encode("utf-8")).hexdigest()[:12]

    def describe(self) -> dict[str, object]:
        """Everything about this override except the key."""
        return {
            "base_url": self.base_url,
            "model": self.model,
            "role": self.role or "全部角色",
            "applies_to_all": not self.role,
            "timeout_sec": self.timeout_sec,
            "host": self.host,
            "loopback": self.is_loopback,
            "key_fingerprint": self.fingerprint(),
            "key_set": bool(self.api_key or self.credential_fingerprint),
            "acknowledged_remote": self.acknowledged_remote,
            "set_at": self.set_at,
            "persisted": self.persisted,
            "credential_storage": "macos_keychain" if self.persisted else "memory",
            "api_format": self.api_format,
            "provider": self.provider,
            "api_key_env": self.api_key_env,
            "request_options": self.request_options,
        }

    def as_provider(self) -> ProviderSettings:
        """The override seen as a provider, so the rest of the code needs no second path."""
        return ProviderSettings(
            name="console-override",
            base_url=self.base_url,
            model=self.model,
            # Not read from anywhere: `build_model_client` takes the key from this object. The
            # field still has to be non-empty because the config validator refuses a provider
            # that does not name where its credential comes from, and that check must stay.
            api_key_env=self.api_key_env or "DAEDALUS_CONSOLE_OVERRIDE_KEY",
            timeout_sec=self.timeout_sec,
            api_format=self.api_format,
            provider=self.provider,
            request_options=self.request_options,
        )


def build(
    *,
    base_url: str,
    model: str,
    api_key: str = "",
    timeout_sec: int = 120,
    role: str = "",
    acknowledged_remote: bool = False,
    api_format: str = "",
    provider: str = "custom",
    api_key_env: str = "",
    request_options: dict | None = None,
) -> ModelOverride:
    """Validate what the operator typed, or explain why it cannot be used.

    The refusals are the interesting part. A base_url that is not http(s) is a typo; a model
    name that looks like a credential is someone pasting their key into the wrong field, which
    would then be sent as a model name and logged as one — so it is refused with that
    explanation rather than accepted and leaked.
    """
    from daedalus.model.catalog import preset
    from daedalus.model.multi_provider import normalize_base_url, validate_options

    try:
        defaults = preset(provider)
        api_format = api_format or defaults["api_format"]
        options = validate_options(api_format, request_options)
        options = validate_options(api_format, {**defaults.get("request_options", {}), **options})
    except (DaedalusError, ValueError) as error:
        raise ModelOverrideRejected(str(error)) from None
    cleaned_url = normalize_base_url(base_url, api_format)
    cleaned_model = model.strip()
    if not cleaned_url:
        raise ModelOverrideRejected("模型接口地址不能为空")
    if not cleaned_url.startswith(("http://", "https://")):
        raise ModelOverrideRejected("模型接口地址必须以 http:// 或 https:// 开头")
    parsed = urlparse(cleaned_url)
    if not parsed.hostname:
        raise ModelOverrideRejected("模型接口地址缺少有效主机名")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ModelOverrideRejected("接口地址请填写 API 根地址；密钥需放在单独字段，不能写入 URL")
    try:
        _ = parsed.port
    except ValueError:
        raise ModelOverrideRejected("接口地址中的端口无效") from None
    if not cleaned_model:
        raise ModelOverrideRejected("模型名不能为空")

    # A key pasted into the model field would be sent as a model name and recorded as one.
    from daedalus.config import is_secret_key

    if is_secret_key(cleaned_model) or cleaned_model.startswith("sk-"):
        raise ModelOverrideRejected(
            "模型名看起来是一把密钥。密钥请填在单独的「API key」栏里，"
            "否则它会被当成模型名发出去并写进记录。"
        )
    if len(cleaned_model) > 200:
        raise ModelOverrideRejected("模型名过长（超过 200 字符）")

    if not MIN_TIMEOUT_SEC <= timeout_sec <= MAX_TIMEOUT_SEC:
        raise ModelOverrideRejected(
            f"超时必须在 {MIN_TIMEOUT_SEC}–{MAX_TIMEOUT_SEC} 秒之间，收到 {timeout_sec}"
        )
    if api_key_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", api_key_env):
        raise ModelOverrideRejected("密钥环境变量名称无效，请仅填写变量名")
    if role and not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", role):
        raise ModelOverrideRejected("模型角色名称无效")

    candidate = ModelOverride(
        base_url=cleaned_url,
        model=cleaned_model,
        api_key=api_key.strip(),
        timeout_sec=timeout_sec,
        role=role.strip(),
        acknowledged_remote=acknowledged_remote,
        api_format=api_format,
        provider=provider,
        api_key_env=api_key_env,
        request_options=options,
    )
    if not candidate.is_loopback and not acknowledged_remote:
        raise ModelOverrideRejected(
            f"{candidate.host} 不是本机地址。指向它意味着每次模型调用都会把仓库内容发到"
            "这台机器之外。确认的话请勾选「我知道内容会离开本机」。"
        )
    return candidate


def report(
    settings, override: ModelOverride | None, overrides: dict | None = None
) -> dict[str, object]:
    """What the console shows: the effective endpoint per role, and where each value came from.

    Reported rather than assumed, because "which model is answering?" has three possible answers
    (the config file, an environment variable named by the config, and an override typed into the
    console) and an operator who cannot tell them apart cannot tell what their repository was sent
    to.
    """
    from daedalus.security.secrets import SecretBroker

    broker = SecretBroker(fallback_env_names=())
    roles: list[dict[str, object]] = []
    overrides = overrides or {}
    names = set(settings.providers) | set(overrides)
    if override is not None:
        names.update(("planner", "coder", "reviewer") if not override.role else (override.role,))
    for name in sorted(names):
        effective = overrides.get(name) or (
            override if override is not None and override.applies_to(name) else None
        )
        if effective is not None:
            roles.append(
                {
                    "role": name,
                    "base_url": effective.base_url,
                    "model": effective.model,
                    "timeout_sec": effective.timeout_sec,
                    "source": "系统钥匙串保存的连接" if effective.persisted else "界面填写（当前会话）",
                    "key": f"{'系统钥匙串' if effective.persisted else '内存密钥'} · 指纹 {effective.fingerprint()}"
                    if effective.api_key or effective.credential_fingerprint
                    else f"环境变量 {effective.api_key_env}"
                    if effective.api_key_env
                    else "未填（该端点不需要密钥）",
                    "loopback": effective.is_loopback,
                    "host": effective.host,
                    "api_format": effective.api_format,
                    "provider": effective.provider,
                    "api_key_env": effective.api_key_env,
                    "request_options": effective.request_options,
                    "key_set": bool(effective.api_key or effective.credential_fingerprint)
                    or (bool(effective.api_key_env) and broker.available(effective.api_key_env)),
                    "persisted": effective.persisted,
                    "credential_storage": "macos_keychain" if effective.persisted else "memory",
                }
            )
            continue
        provider = settings.providers[name]
        configured_broker = (
            SecretBroker()
            if provider.api_format == "openai_chat" and provider.provider == "custom"
            else broker
        )
        has_env = bool(provider.api_key_env) and configured_broker.available(provider.api_key_env)
        roles.append(
            {
                "role": name,
                "base_url": provider.base_url,
                "model": provider.model,
                "timeout_sec": provider.timeout_sec,
                "source": "配置文件",
                "key": f"环境变量 {provider.api_key_env}"
                if has_env
                else f"环境变量 {provider.api_key_env} 未设置",
                "loopback": is_loopback_host((urlparse(provider.base_url).hostname or "").lower()),
                "host": (urlparse(provider.base_url).hostname or "").lower(),
                "api_format": provider.api_format,
                "provider": provider.provider,
                "api_key_env": provider.api_key_env,
                "request_options": provider.request_options,
                "key_set": has_env,
            }
        )
    return {
        "roles": roles,
        "override": override.describe() if override is not None else None,
        "default_role": settings.default_role,
        "persisted": any(row.get("persisted", False) for row in roles),
        "overrides": {name: value.describe() for name, value in overrides.items()},
        "supported_api_formats": ["openai_chat", "openai_responses", "anthropic", "gemini"],
        "missing_roles": [name for name in ("planner", "coder", "reviewer") if name not in names],
        "note": (
            "安全保存的连接会在重启后自动恢复；临时连接只在当前会话生效。"
            "密钥保存在系统钥匙串，不写入连接配置、数据库、事件日志或导出文件。"
        ),
        "remote_warning": (
            "当前生效的接口不是本机地址，每次模型调用都会把仓库内容发到那台机器之外。"
            if override is not None and not override.is_loopback
            else ""
        ),
    }
