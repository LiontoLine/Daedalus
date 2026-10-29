"""Credential-free telemetry for every service completion attempt, including failures."""

from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import suppress
from typing import Any

from daedalus.model.base import token_usage_details


class ObservedClient:
    def __init__(self, inner: Any, report: Callable[[dict], None]):
        self.inner = inner
        self.report = report

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def for_retrieval(self):
        factory = getattr(self.inner, "for_retrieval", None)
        return ObservedClient(factory() if callable(factory) else self.inner, self.report)

    def for_profile(self, profile):
        factory = getattr(self.inner, "for_profile", None)
        if not callable(factory) and profile != "configured":
            from daedalus.errors import ModelError

            raise ModelError("this provider does not declare the requested inference profile")
        return ObservedClient(factory(profile) if callable(factory) else self.inner, self.report)

    def for_task(self, purpose):
        factory = getattr(self.inner, "for_task", None)
        return ObservedClient(factory(purpose) if callable(factory) else self.inner, self.report)

    def complete(self, messages, **kwargs):
        started = time.monotonic()
        record = {
            "ok": False,
            "usage_known": False,
            "error_code": "",
            "tokens": None,
            "inference_profile": getattr(self.inner, "inference_profile", "configured"),
        }
        try:
            completion = self.inner.complete(messages, **kwargs)
            known = bool(completion.raw.get("usage_reported") or completion.total_tokens)
            record.update(
                ok=True,
                usage_known=known,
                tokens=completion.total_tokens if known else None,
                prompt_tokens=completion.prompt_tokens if known else None,
                completion_tokens=completion.completion_tokens if known else None,
                usage_details=token_usage_details(completion.raw.get("usage")),
            )
            return completion
        except Exception as error:
            record["error_code"] = getattr(error, "code", "model_transport_exception")
            status = getattr(error, "context", {}).get("status")
            if type(status) is int and 100 <= status <= 599:
                record["http_status"] = status
            usage = getattr(error, "context", {}).get("usage")
            if isinstance(usage, dict):
                record.update(
                    usage_known=True,
                    tokens=int(usage.get("prompt_tokens", 0))
                    + int(usage.get("completion_tokens", 0)),
                    prompt_tokens=int(usage.get("prompt_tokens", 0)),
                    completion_tokens=int(usage.get("completion_tokens", 0)),
                    usage_details=token_usage_details(usage),
                )
            raise
        finally:
            record["latency_ms"] = int((time.monotonic() - started) * 1000)
            # Telemetry cannot turn a successful request into a failed model call.
            with suppress(Exception):
                self.report(record)
