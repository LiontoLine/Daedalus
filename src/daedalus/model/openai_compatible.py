"""An OpenAI-compatible chat client.

Works against any endpoint that speaks `/chat/completions` — OpenAI itself, DeepSeek,
vLLM, Ollama, LiteLLM's proxy — which is why Phase 1 can adopt a real model without
committing to a vendor.

Credential handling (Spec §8): the API key is resolved through the `SecretBroker` at
call time and never stored on the client, never logged, and every response body is
redacted before it is returned.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

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
from daedalus.model.tls import create_tls_context, verification_failure

DEFAULT_BASE_URL = "https://api.openai.com/v1"


@dataclass
class OpenAICompatibleClient:
    """Minimal, dependency-free chat-completions client.

    Uses `urllib` rather than a model SDK. The TLS path can load the certifi CA
    data bundle when Python ships without default roots.
    """

    name: str = "openai-compatible"
    model: str = "gpt-4o-mini"
    base_url: str = DEFAULT_BASE_URL
    timeout_sec: int = 120
    api_key_resolver: Callable[[], str] | None = None
    default_headers: dict[str, str] = field(default_factory=dict)
    requests_made: int = 0

    def _api_key(self) -> str:
        if self.api_key_resolver is None:
            raise ModelError(
                "no credential resolver configured; the API key must be supplied "
                "through the SecretBroker, not read directly"
            )
        return self.api_key_resolver()

    def complete(
        self,
        messages: list[Message],
        *,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format_json: bool = False,
    ) -> Completion:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [message.to_payload() for message in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format_json:
            body["response_format"] = {"type": "json_object"}

        request = urllib.request.Request(
            url=f"{self.base_url.rstrip('/')}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key()}",
                **self.default_headers,
            },
            method="POST",
        )

        started = time.monotonic()
        try:
            options: dict[str, Any] = {"timeout": self.timeout_sec}
            if request.type == "https":
                options["context"] = create_tls_context()
            with urllib.request.urlopen(request, **options) as response:
                payload, recovered = read_json_response(response)
            if recovered and reported_usage(payload) is None:
                raise ModelError("incomplete HTTP framing without complete provider usage",
                                 transport_incomplete=True)
        except urllib.error.HTTPError as error:
            detail = redact_text(error.read().decode("utf-8", "replace"))[:800]
            if error.code in {408, 409, 429} or error.code >= 500:
                raise ModelUnavailable(
                    f"model endpoint returned HTTP {error.code}: {detail}",
                    status=error.code,
                ) from error
            raise ModelError(
                f"model endpoint rejected the request with HTTP {error.code}: {detail}",
                status=error.code,
            ) from error
        except TimeoutError as error:
            raise ModelTimeout(
                f"model call exceeded {self.timeout_sec}s", model=self.model
            ) from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                raise verification_failure() from None
            raise ModelUnavailable(f"model endpoint unreachable: {error.reason}") from error
        except ssl.SSLCertVerificationError:
            raise verification_failure() from None

        self.requests_made += 1
        latency_ms = int((time.monotonic() - started) * 1000)
        completion = self._parse(payload, latency_ms=latency_ms)
        completion.raw["http_framing_recovered"] = recovered
        return completion

    def _parse(self, payload: dict[str, Any], *, latency_ms: int) -> Completion:
        known_usage = reported_usage(payload)
        if payload.get("usage") and known_usage is None:
            raise ModelError("model provider returned malformed token usage")
        try:
            choice = payload["choices"][0]
            text = choice["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as error:
            raise ModelError(
                "unexpected model response shape", usage=known_usage
            ) from error

        usage = payload.get("usage") or {}
        if not text.strip() or choice.get("finish_reason") == "length":
            raise ModelResponseIncomplete(
                "model response has no complete visible answer",
                finish_reason="length" if choice.get("finish_reason") == "length" else "empty_text",
                usage=known_usage,
                model=self.model,
            )
        return Completion(
            text=redact_text(text),
            model=str(payload.get("model", self.model)),
            prompt_tokens=known_usage["prompt_tokens"] if known_usage is not None else 0,
            completion_tokens=known_usage["completion_tokens"] if known_usage is not None else 0,
            latency_ms=latency_ms,
            stopped_reason=str(choice.get("finish_reason", "")),
            raw={"id": payload.get("id", ""), "finish_reason": choice.get("finish_reason"),
                 "usage_reported": known_usage is not None, "usage": token_usage_details(usage)},
        )
