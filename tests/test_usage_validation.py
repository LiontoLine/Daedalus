"""Malformed provider counters must never become known zero or negative spend."""

import io
import json

import pytest

from daedalus.model.base import Message, ModelError
from daedalus.model.multi_provider import MultiProviderClient
from daedalus.model.observed import ObservedClient
from daedalus.model.openai_compatible import OpenAICompatibleClient


@pytest.mark.parametrize("adapter", ["chat", "multi"])
@pytest.mark.parametrize("usage", [
    {"prompt_tokens":-1000,"completion_tokens":5},
    {"prompt_tokens":10},
    {"prompt_tokens":True,"completion_tokens":5},
    {"prompt_tokens":10,"completion_tokens":"5"},
    {"prompt_tokens":None,"completion_tokens":5},
    {"unrecognized_counter":1},
    "malformed-opaque-offline-secret",
])
def test_malformed_usage_cannot_be_counted_as_known_spend(monkeypatch,adapter,usage):
    payload = {"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":usage}
    calls = []

    def open_response(*args,**kwargs):
        calls.append(1)
        return io.BytesIO(json.dumps(payload).encode())

    cls = MultiProviderClient if adapter == "multi" else OpenAICompatibleClient
    client = cls(api_key_resolver=lambda:"synthetic-offline-credential")
    if adapter == "multi":
        monkeypatch.setattr(client,"_open",open_response)
    else:
        monkeypatch.setattr("urllib.request.urlopen",open_response)
    records = []
    observed = ObservedClient(client,records.append)
    with pytest.raises(ModelError) as caught:
        observed.complete([Message("user","hello")])
    assert "malformed-opaque-offline-secret" not in str(caught.value)
    assert calls == [1]
    assert len(records) == 1 and records[0]["usage_known"] is False
    assert records[0]["tokens"] is None
