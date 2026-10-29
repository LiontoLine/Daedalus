"""A broken chunk terminator must not cause a paid retry or lose valid usage."""

import io
import json
from http.client import IncompleteRead

import pytest

from daedalus.model.base import Message, ModelError
from daedalus.model.multi_provider import MultiProviderClient
from daedalus.model.observed import ObservedClient
from daedalus.model.openai_compatible import OpenAICompatibleClient


class BrokenResponse(io.BytesIO):
    def read(self, *args):
        raise IncompleteRead(self.getvalue())


@pytest.mark.parametrize("kind", ["chat", "multi"])
@pytest.mark.parametrize("fault", ["terminator", "truncated", "bad_shape", "missing_usage"])
def test_interrupted_response_is_never_replayed_and_usage_is_preserved(monkeypatch, kind, fault):
    payload = {
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 90, "completion_tokens": 10},
    }
    if fault == "bad_shape":
        payload["choices"] = []
    if fault == "missing_usage":
        payload.pop("usage")
    raw = json.dumps(payload).encode()
    if fault == "truncated":
        raw = raw[:20] + b'opaque-offline-secret'
    opened = []

    def open_response(*args, **kwargs):
        opened.append(1)
        return BrokenResponse(raw)

    client_type = OpenAICompatibleClient if kind == "chat" else MultiProviderClient
    client = client_type(api_key_resolver=lambda: "opaque-offline-secret")
    if kind == "chat":
        monkeypatch.setattr("urllib.request.urlopen", open_response)
    else:
        monkeypatch.setattr(client, "_open", open_response)
    records = []
    observed = ObservedClient(client, records.append)
    if fault == "terminator":
        result = observed.complete([Message("user", "test")])
        assert result.text == "ok" and result.total_tokens == 100
        assert result.raw["http_framing_recovered"] is True
    else:
        with pytest.raises(ModelError) as error:
            observed.complete([Message("user", "test")])
        assert "opaque-offline-secret" not in str(error.value)
    assert opened == [1] and len(records) == 1
    assert records[0]["usage_known"] is (fault in {"terminator", "bad_shape"})
    assert records[0]["tokens"] == (100 if fault in {"terminator", "bad_shape"} else None)
