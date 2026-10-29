# ruff: noqa: RUF001
"""Text-generation HTTP adapters, using only the standard library.

All protocols return the same Completion contract. Native thinking/tool blocks
are never treated as candidate code. Credentials are resolved at call time.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace

from daedalus.errors import ModelResponseIncomplete
from daedalus.infrastructure.redact import redact_text
from daedalus.model.base import (
    Completion,
    Message,
    ModelError,
    ModelTimeout,
    ModelUnavailable,
    token_usage_details,
)
from daedalus.model.http_response import read_json_response, reported_usage
from daedalus.model.openai_compatible import OpenAICompatibleClient
from daedalus.model.tls import create_tls_context, verification_failure

FORMATS = ("openai_chat", "openai_responses", "anthropic", "gemini")
OPTION_KEYS = {"send_temperature", "send_json_mode", "token_limit_field", "extra_body", "auth_mode"}
EXTRA_KEYS = {
    "thinking",
    "reasoning",
    "reasoning_effort",
    "enable_thinking",
    "top_p",
    "top_k",
    "chat_template_kwargs",
    "enable_enhancement",
    "thinking_config",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_options(api_format: str, options: dict | None) -> dict:
    if api_format not in FORMATS:
        raise ModelError("不支持的模型协议，请选择 Chat Completions、Responses、Claude 或 Gemini")
    if options is not None and not isinstance(options, dict):
        raise ModelError("模型兼容选项必须是 JSON 对象")
    result = dict(options or {})
    if set(result) - OPTION_KEYS:
        raise ModelError("模型兼容选项包含不支持的字段")
    for key in ("send_temperature", "send_json_mode"):
        if key in result and not isinstance(result[key], bool):
            raise ModelError("温度与 JSON 模式开关必须为布尔值")
    if result.get("token_limit_field", "max_tokens") not in {"max_tokens", "max_completion_tokens"}:
        raise ModelError("Token 上限字段只支持 max_tokens 或 max_completion_tokens")
    if result.get("auth_mode", "bearer") not in {
        "bearer",
        "api-key",
        "x-api-key",
        "google-api-key",
    }:
        raise ModelError("不支持的鉴权方式")
    extra = result.get("extra_body", {})
    if not isinstance(extra, dict) or set(extra) - EXTRA_KEYS:
        raise ModelError("额外参数只接受生成与思考选项，不能修改消息、鉴权或工具权限")
    if api_format == "gemini":
        if set(extra) - {"top_p", "top_k", "thinking_config"}:
            raise ModelError("Gemini 原生协议的额外参数仅支持 top_p、top_k、thinking_config")
        thinking = extra.get("thinking_config", {})
        if not isinstance(thinking, dict) or set(thinking) - {
            "thinkingBudget",
            "thinkingLevel",
            "includeThoughts",
        }:
            raise ModelError("thinking_config 需要使用 Gemini 原生思考参数")
    elif "thinking_config" in extra:
        raise ModelError("thinking_config 仅用于 Gemini 原生协议")
    from daedalus.security.outbound import assert_outbound_clean

    try:
        encoded = json.dumps(result, allow_nan=False)
        if len(encoded) > 12000:
            raise ValueError("too large")
        assert_outbound_clean(encoded, where="model compatibility options")
    except Exception as error:  # Never repeat secret-bearing input.
        raise ModelError("模型兼容选项不是有效的非敏感 JSON") from error
    return result


def normalize_base_url(base_url: str, api_format: str) -> str:
    value = base_url.strip().rstrip("/")
    for suffix in ("/chat/completions", "/responses", "/messages"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
            break
    # Users often paste the full native Gemini endpoint.
    if api_format == "gemini" and "/models/" in value:
        value = value.split("/models/", 1)[0]
    return value


@dataclass
class MultiProviderClient(OpenAICompatibleClient):
    api_format: str = "openai_chat"
    request_options: dict = field(default_factory=dict)
    retrieval_profile: str = "configured"
    inference_profile: str = "configured"

    def for_profile(self, profile: str):
        """Derive request-only settings; endpoint, credential resolver and saved data stay bound."""
        if profile == "configured":
            return self
        if profile != "bounded_json":
            raise ModelError("unknown inference profile")
        host = (urllib.parse.urlparse(self.base_url).hostname or "").lower()
        if self.api_format != "openai_chat" or host != "api.deepseek.com":
            raise ModelError("bounded_json is supported only for official DeepSeek Chat")
        options = dict(self.request_options)
        extra = dict(options.get("extra_body", {}))
        extra.pop("reasoning_effort", None)
        extra["thinking"] = {"type": "disabled"}
        options["extra_body"] = extra
        return replace(self, request_options=options, inference_profile="deepseek_bounded_json")

    def for_task(self, purpose: str):
        """Short structured actions use a visible-answer budget; explicit user settings win."""
        if purpose not in {
            "structured_edit",
            "structured_review",
            "structured_plan",
            "structured_questions",
        }:
            return self
        extra = self.request_options.get("extra_body", {})
        if any(
            key in extra or key in self.request_options
            for key in ("thinking", "reasoning_effort", "reasoning")
        ):
            return self
        try:
            return self.for_profile("bounded_json")
        except ModelError:
            return self

    def for_retrieval(self):
        """512-token tool decisions need visible JSON, rather than a reasoning budget.

        Only the official DeepSeek Chat endpoint has this documented override. A derived
        client retains the broker, endpoint and model; normal planning/coding is unchanged.
        """
        host = (urllib.parse.urlparse(self.base_url).hostname or "").lower()
        if self.api_format != "openai_chat" or host != "api.deepseek.com":
            return self
        options = dict(self.request_options)
        options["extra_body"] = {
            **options.get("extra_body", {}),
            "thinking": {"type": "disabled"},
            "reasoning_effort": "none",
        }
        return replace(
            self, request_options=options, retrieval_profile="deepseek_bounded_json_nonthinking"
        )

    @staticmethod
    def _open(request, *, timeout):
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
        if request.type == "https":
            handlers.append(urllib.request.HTTPSHandler(context=create_tls_context()))
        return urllib.request.build_opener(*handlers).open(request, timeout=timeout)

    def _json(self, suffix: str, body: dict | None = None):
        key = self._api_key()

        def safe(value):
            text = str(value)
            if key:
                text = text.replace(key, "[REDACTED]")
            return redact_text(text)

        headers = {"Content-Type": "application/json"}
        if self.api_format == "anthropic":
            headers.update({"anthropic-version": "2023-06-01", "x-api-key": key})
        elif self.api_format == "gemini":
            headers["x-goog-api-key"] = key
        elif key:
            headers["Authorization"] = f"Bearer {key}"
        auth_mode = self.request_options.get("auth_mode")
        if auth_mode:
            for name in ("Authorization", "x-api-key", "x-goog-api-key", "api-key"):
                headers.pop(name, None)
            header = {
                "bearer": "Authorization",
                "api-key": "api-key",
                "x-api-key": "x-api-key",
                "google-api-key": "x-goog-api-key",
            }[auth_mode]
            if key:
                headers[header] = f"Bearer {key}" if auth_mode == "bearer" else key
        request = urllib.request.Request(
            normalize_base_url(self.base_url, self.api_format) + suffix,
            data=json.dumps(body, allow_nan=False).encode() if body is not None else None,
            headers=headers,
            method="POST" if body is not None else "GET",
        )
        try:
            with self._open(request, timeout=self.timeout_sec) as response:
                payload, recovered = read_json_response(response)
            if recovered and reported_usage(payload, self.api_format) is None:
                raise ModelError("incomplete HTTP framing without complete provider usage",
                                 transport_incomplete=True)
            self.requests_made += 1
            return payload, safe, recovered
        except urllib.error.HTTPError as error:
            detail = safe(error.read(2000).decode("utf-8", "replace"))[:700]
            kind = (
                ModelUnavailable
                if error.code in {408, 409, 429} or error.code >= 500
                else ModelError
            )
            raise kind(f"模型接口 HTTP {error.code}: {detail}", status=error.code) from None
        except TimeoutError:
            raise ModelTimeout(f"模型调用超过 {self.timeout_sec} 秒") from None
        except ssl.SSLCertVerificationError:
            raise verification_failure() from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                raise verification_failure() from None
            raise ModelUnavailable("模型接口不可达：" + safe(error.reason)) from None
        except (ValueError, UnicodeError):
            raise ModelError("模型接口返回了无法解析的 JSON，请检查 API 地址与协议") from None

    def complete(
        self,
        messages: list[Message],
        *,
        temperature=0.0,
        max_tokens=4096,
        response_format_json=False,
    ):
        options = validate_options(self.api_format, self.request_options)
        started = time.monotonic()
        extra = options.get("extra_body", {})
        if self.api_format == "openai_chat":
            body = {
                "model": self.model,
                "messages": [m.to_payload() for m in messages],
                options.get("token_limit_field", "max_tokens"): max_tokens,
                **extra,
            }
            if options.get("send_temperature", True):
                body["temperature"] = temperature
            if response_format_json and options.get("send_json_mode", True):
                body["response_format"] = {"type": "json_object"}
            path = "/chat/completions"
        elif self.api_format == "openai_responses":
            body = {
                "model": self.model,
                "input": [m.to_payload() for m in messages],
                "max_output_tokens": max_tokens,
                "store": False,
                **extra,
            }
            if options.get("send_temperature", False):
                body["temperature"] = temperature
            if response_format_json and options.get("send_json_mode", True):
                body["text"] = {"format": {"type": "json_object"}}
            path = "/responses"
        elif self.api_format == "anthropic":
            body = {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": [
                    m.to_payload() for m in messages if m.role not in {"system", "developer"}
                ],
                **extra,
            }
            system = "\n\n".join(m.content for m in messages if m.role in {"system", "developer"})
            if system:
                body["system"] = system
            if options.get("send_temperature", False):
                body["temperature"] = temperature
            path = "/messages"
        else:
            config = {"maxOutputTokens": max_tokens}
            if options.get("send_temperature", False):
                config["temperature"] = temperature
            if response_format_json and options.get("send_json_mode", True):
                config["responseMimeType"] = "application/json"
            if "top_p" in extra:
                config["topP"] = extra["top_p"]
            if "top_k" in extra:
                config["topK"] = extra["top_k"]
            if "thinking_config" in extra:
                config["thinkingConfig"] = extra["thinking_config"]
            body = {
                "contents": [
                    {
                        "role": "model" if m.role == "assistant" else "user",
                        "parts": [{"text": m.content}],
                    }
                    for m in messages
                    if m.role not in {"system", "developer"}
                ],
                "generationConfig": config,
            }
            system = "\n\n".join(m.content for m in messages if m.role in {"system", "developer"})
            if system:
                body["systemInstruction"] = {"parts": [{"text": system}]}
            path = (
                "/models/"
                + urllib.parse.quote(self.model.removeprefix("models/"), safe="-._")
                + ":generateContent"
            )
        payload, safe, recovered = self._json(path, body)
        known_usage = reported_usage(payload, self.api_format)
        if self.api_format == "openai_chat" and payload.get("usage") and known_usage is None:
            raise ModelError("model provider returned malformed token usage")
        latency = int((time.monotonic() - started) * 1000)
        try:
            if self.api_format == "openai_chat":
                choice = payload["choices"][0]
                if choice["message"].get("tool_calls"):
                    raise ValueError("unrequested tools")
                text = choice["message"]["content"]
                if isinstance(text, list):
                    text = "".join(
                        part.get("text", "") for part in text if part.get("type") == "text"
                    )
                usage = payload.get("usage") or {}
                prompt, output = usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
                stop = choice.get("finish_reason", "")
            elif self.api_format == "openai_responses":
                if payload.get("status") not in {None, "completed"} or payload.get("error"):
                    raise ValueError("incomplete response")
                messages_out = [item for item in payload["output"] if item.get("type") == "message"]
                if any(item.get("type", "").endswith("_call") for item in payload["output"]):
                    raise ValueError("unrequested tools")
                text = "".join(
                    part["text"]
                    for item in messages_out
                    for part in item.get("content", [])
                    if part.get("type") == "output_text"
                )
                usage = payload.get("usage") or {}
                prompt, output = usage.get("input_tokens", 0), usage.get("output_tokens", 0)
                stop = payload.get("status", "")
            elif self.api_format == "anthropic":
                if any(part.get("type") == "tool_use" for part in payload["content"]):
                    raise ValueError("unrequested tools")
                text = "".join(
                    part["text"] for part in payload["content"] if part.get("type") == "text"
                )
                usage = payload.get("usage") or {}
                prompt = sum(
                    int(usage.get(k, 0) or 0)
                    for k in (
                        "input_tokens",
                        "cache_creation_input_tokens",
                        "cache_read_input_tokens",
                    )
                )
                output, stop = usage.get("output_tokens", 0), payload.get("stop_reason", "")
            else:
                candidate = payload["candidates"][0]
                parts = candidate["content"]["parts"]
                if any("functionCall" in part for part in parts):
                    raise ValueError("unrequested tools")
                text = "".join(
                    part["text"] for part in parts if "text" in part and not part.get("thought")
                )
                usage = payload.get("usageMetadata") or {}
                prompt = usage.get("promptTokenCount", 0)
                output = int(usage.get("candidatesTokenCount", 0) or 0) + int(
                    usage.get("thoughtsTokenCount", 0) or 0
                )
                stop = candidate.get("finishReason", "")
            if int(prompt or 0) < 0 or int(output or 0) < 0:
                raise ValueError("invalid usage")
            if (
                not isinstance(text, str)
                or not text.strip()
                or str(stop) in {"length", "max_tokens", "MAX_TOKENS"}
            ):
                raise ModelResponseIncomplete(
                    "模型输出未完成或没有可见文本，请增加输出预算后重试",
                    finish_reason="length"
                    if str(stop) in {"length", "max_tokens", "MAX_TOKENS"}
                    else "empty_text",
                    usage={
                        **token_usage_details(usage),
                        "prompt_tokens": int(prompt or 0),
                        "completion_tokens": int(output or 0),
                    }
                    if usage
                    else None,
                    model=safe(payload.get("model", payload.get("modelVersion", self.model))),
                )
        except (KeyError, IndexError, TypeError, ValueError):
            raise ModelError(
                "模型没有返回有效的文本回答；请检查模型是否支持文本生成、协议是否匹配，或增加输出上限",
                usage=known_usage,
                transport_incomplete=recovered,
            ) from None
        return Completion(
            safe(text),
            safe(payload.get("model", payload.get("modelVersion", self.model))),
            int(prompt or 0),
            int(output or 0),
            latency,
            raw={
                "usage_reported": bool(usage),
                "api_format": self.api_format,
                "usage": token_usage_details(usage),
                "http_framing_recovered": recovered,
            },
            stopped_reason="length"
            if str(stop) in {"length", "max_tokens", "MAX_TOKENS"}
            else safe(stop),
        )

    def list_models(self):
        path = (
            "/models?pageSize=100"
            if self.api_format == "gemini"
            else "/models?limit=100"
            if self.api_format == "anthropic"
            else "/models"
        )
        payload, safe, _recovered = self._json(path)
        values = payload.get("models" if self.api_format == "gemini" else "data")
        if not isinstance(values, list):
            raise ModelError("接口没有返回模型列表，请手动填写控制台中的模型 ID")
        models = []
        for value in values[:1000]:
            if not isinstance(value, dict):
                continue
            if self.api_format == "gemini" and "generateContent" not in value.get(
                "supportedGenerationMethods", []
            ):
                continue
            identity = value.get("id", value.get("name", ""))
            if isinstance(identity, str) and identity:
                models.append(
                    {
                        "id": safe(identity.removeprefix("models/")),
                        "name": safe(value.get("display_name", value.get("displayName", identity))),
                    }
                )
        return models


def build_client(provider, *, api_key_resolver, name=""):
    return MultiProviderClient(
        name=name or provider.name,
        model=provider.model,
        base_url=provider.base_url,
        timeout_sec=provider.timeout_sec,
        api_key_resolver=api_key_resolver,
        api_format=provider.api_format,
        request_options=dict(provider.request_options),
    )
