"""Bounded JSON reads without replaying a possibly charged HTTP request."""

from __future__ import annotations

import json
from http.client import IncompleteRead

from daedalus.model.base import ModelError, token_usage_details

MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def read_json_response(response):
    recovered = False
    try:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    except IncompleteRead as error:
        # A missing chunk terminator can accompany an otherwise complete JSON body.
        # Never concatenate another request or expose partial response content.
        raw, recovered = error.partial, True
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ModelError("model response exceeds the size limit")
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("not an object")
    except (ValueError, UnicodeError):
        raise ModelError(
            "model HTTP response ended without a complete JSON object",
            transport_incomplete=recovered,
        ) from None
    return payload, recovered


def reported_usage(payload, api_format="openai_chat"):
    """Only complete, nonnegative integer counters qualify as known usage."""
    usage = payload.get("usageMetadata" if api_format == "gemini" else "usage")
    if not isinstance(usage, dict):
        return None
    keys = {
        "openai_chat": ("prompt_tokens", "completion_tokens"),
        "openai_responses": ("input_tokens", "output_tokens"),
        "anthropic": ("input_tokens", "output_tokens"),
        "gemini": ("promptTokenCount", "candidatesTokenCount"),
    }[api_format]
    if any(type(usage.get(key)) is not int or usage[key] < 0 for key in keys):
        return None
    extra = (
        ("cache_creation_input_tokens", "cache_read_input_tokens")
        if api_format == "anthropic" else ()
    )
    output_extra = ("thoughtsTokenCount",) if api_format == "gemini" else ()
    if any(type(usage.get(key, 0)) is not int or usage.get(key, 0) < 0
           for key in (*extra, *output_extra)):
        return None
    return {
        **token_usage_details(usage),
        "prompt_tokens": usage[keys[0]] + sum(usage.get(key, 0) for key in extra),
        "completion_tokens": usage[keys[1]] + sum(usage.get(key, 0) for key in output_extra),
    }
