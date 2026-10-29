# ruff: noqa: RUF001
"""Parse explicitly supplied JSON/TOML/env model configs, without persisting keys."""

from __future__ import annotations

import json
import re
import shlex
import tomllib

from daedalus.application.model_settings import ModelOverrideRejected, build
from daedalus.model.catalog import preset

MAX_IMPORT = 128 * 1024
ALIASES = {
    "baseURL": "base_url",
    "baseUrl": "base_url",
    "apiKey": "api_key",
    "apiFormat": "api_format",
    "protocol": "api_format",
    "env_key": "api_key_env",
    "wire_api": "api_format",
}
FORMATS = {
    "chat": "openai_chat",
    "openai": "openai_chat",
    "responses": "openai_responses",
    "messages": "anthropic",
    "claude": "anthropic",
    "google": "gemini",
}


def _environment(env):
    if not isinstance(env, dict):
        raise ModelOverrideRejected("env 配置必须是对象")
    families = [
        ("ANTHROPIC", "anthropic"),
        ("GEMINI", "gemini"),
        ("GOOGLE", "gemini"),
        ("DEEPSEEK", "deepseek"),
        ("OPENAI", "openai"),
    ]
    for prefix, provider in families:
        key = env.get(prefix + "_API_KEY", env.get(prefix + "_AUTH_TOKEN", ""))
        model = env.get(prefix + "_MODEL", env.get("MODEL", ""))
        address = env.get(prefix + "_BASE_URL", env.get(prefix + "_API_BASE", ""))
        if key or model or address:
            options = {"auth_mode": "bearer"} if prefix + "_AUTH_TOKEN" in env else {}
            return {
                "provider": provider,
                "base_url": address or preset(provider)["base_url"],
                "model": model,
                "api_key": key,
                "api_format": env.get(
                    prefix + "_API_FORMAT",
                    "openai_chat" if prefix == "OPENAI" else preset(provider)["api_format"],
                ),
                "request_options": options,
            }
    raise ModelOverrideRejected("没有找到支持的模型环境变量；请导入模板中的 JSON 或 TOML 格式")


def _parse(content: str, format="auto"):
    if not isinstance(content, str) or len(content.encode()) > MAX_IMPORT or not content.strip():
        raise ModelOverrideRejected("导入内容不能为空，且不能超过 128 KB")
    try:
        if format in {"json", "auto"} and content.lstrip().startswith(("{", "[")):
            # TOML tables also start with '['; JSON parsing is attempted before TOML.
            try:
                raw = json.loads(content)
            except ValueError:
                raw = tomllib.loads(content)
        elif format == "env" or (format == "auto" and not re.search(r"^\s*\[", content, re.M)):
            try:
                raw = tomllib.loads(content)
            except ValueError:
                values = {}
                for line in content.splitlines():
                    line = line.strip().removeprefix("export ")
                    if not line or line.startswith("#"):
                        continue
                    name, separator, value = line.partition("=")
                    if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name.strip()):
                        raise ValueError("invalid env") from None
                    parsed = shlex.split(value, comments=True)
                    values[name.strip()] = (
                        parsed[0] if len(parsed) == 1 else "" if not parsed else " ".join(parsed)
                    )
                raw = {"env": values}
        elif format in {"toml", "auto", "env"}:
            raw = tomllib.loads(content)
        else:
            raise ValueError("unsupported format")
    except (ValueError, TypeError, RecursionError):
        raise ModelOverrideRejected(
            "配置解析失败，请检查 JSON、TOML 或 .env 格式；原文不会写入错误信息"
        ) from None
    if not isinstance(raw, dict):
        raise ModelOverrideRejected("配置顶层必须是一个对象")
    if "env" in raw:
        raw = _environment(raw["env"])
    elif any(k.endswith(("_API_KEY", "_BASE_URL", "_MODEL")) for k in raw):
        raw = _environment(raw)
    elif "model_providers" in raw:
        name = raw.get("model_provider", "openai")
        selected = raw["model_providers"].get(name)
        if not isinstance(selected, dict):
            raise ModelOverrideRejected("没有找到当前 model_provider 对应的接口配置")
        raw = {**selected, "model": raw.get("model", ""), "provider": "custom"}
        # Human-readable Codex provider names are not Daedalus roles.
        raw.pop("name", None)
        raw.pop("requires_openai_auth", None)
    if isinstance(raw.get("model"), dict):
        raw = {"roles": {k: v for k, v in raw["model"].items() if k != "default_role"}}
    if "roles" in raw:
        entries = raw["roles"]
        if not isinstance(entries, dict) or not 1 <= len(entries) <= 16:
            raise ModelOverrideRejected("roles 需要包含 1–16 个角色配置")
        items = [(role, value) for role, value in entries.items()]
    else:
        items = [(raw.get("role", ""), raw)]
    result = {}
    for role, value in items:
        if not isinstance(value, dict):
            raise ModelOverrideRejected("每个角色的配置必须是对象")
        clean = {}
        for name, item in value.items():
            name = ALIASES.get(name, name)
            if name in clean:
                raise ModelOverrideRejected("同一配置字段出现重复别名")
            clean[name] = item
        clean.pop("version", None)
        clean.pop("role", None)
        allowed = {
            "base_url",
            "model",
            "api_key",
            "timeout_sec",
            "provider",
            "api_format",
            "api_key_env",
            "request_options",
        }
        if set(clean) - allowed:
            raise ModelOverrideRejected("配置含不支持的字段，请参照导入模板；不会执行配置中的命令")
        provider = clean.get("provider", "custom")
        try:
            defaults = preset(provider)
        except ValueError as error:
            raise ModelOverrideRejected(str(error)) from None
        clean.setdefault("base_url", defaults["base_url"])
        clean.setdefault("api_format", defaults["api_format"])
        clean["api_format"] = FORMATS.get(clean["api_format"], clean["api_format"])
        clean.setdefault("api_key", "")
        key = clean["api_key"]
        if isinstance(key, str) and re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", key):
            clean["api_key_env"], clean["api_key"] = key[2:-1], ""
        if not clean["api_key"]:
            clean.setdefault("api_key_env", defaults["api_key_env"])
        try:
            result[role] = build(**clean, role=role, acknowledged_remote=True)
        except (TypeError, ValueError, AttributeError):
            raise ModelOverrideRejected(
                "配置字段类型不正确，请检查模型名、地址、超时与密钥字段"
            ) from None
    return result


def export(settings, override, overrides):
    from daedalus.application.model_settings import report

    roles = {}
    for item in report(settings, override, overrides)["roles"]:
        role = item["role"]
        current = overrides.get(role) or (
            override if override and override.applies_to(role) else None
        )
        original = settings.providers.get(role)
        env = current.api_key_env if current else original.api_key_env
        if current and (current.api_key or current.credential_ref) and not env:
            env = preset(current.provider)["api_key_env"] or "DAEDALUS_MODEL_API_KEY"
        roles[role] = {
            "provider": item["provider"],
            "api_format": item["api_format"],
            "base_url": item["base_url"],
            "model": item["model"],
            "timeout_sec": item["timeout_sec"],
            "api_key_env": env,
            "request_options": current.request_options if current else original.request_options,
        }
    return {"version": 1, "roles": roles}


def parse(content: str, format="auto"):
    try:
        return _parse(content, format)
    except ModelOverrideRejected:
        raise
    except Exception:  # noqa: BLE001 - the import boundary must never echo secret-bearing input
        raise ModelOverrideRejected(
            "模型配置字段无效，请检查格式、模型名与地址；输入原文不会回显"
        ) from None
