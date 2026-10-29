"""Request-scoped structured inference preserves credentials, preferences and telemetry."""

import pytest

from daedalus.model.base import Message, ModelError
from daedalus.model.multi_provider import MultiProviderClient
from daedalus.model.observed import ObservedClient


@pytest.mark.parametrize(
    "purpose", ["structured_questions", "structured_plan", "structured_edit", "structured_review"]
)
def test_automatic_task_profile_keeps_saved_options_and_endpoint_unchanged(purpose):
    client = MultiProviderClient(
        model="deepseek-flash",
        base_url="https://api.deepseek.com",
        request_options={"extra_body": {"top_p": 0.97}},
    )
    derived = client.for_task(purpose)
    assert derived.base_url == client.base_url and derived.model == client.model
    assert client.request_options == {"extra_body": {"top_p": 0.97}}
    assert derived.request_options["extra_body"] == {
        "top_p": 0.97,
        "thinking": {"type": "disabled"},
    }
    assert derived.inference_profile == "deepseek_bounded_json"
    assert client.for_profile("configured") is client


@pytest.mark.parametrize(
    "extra",
    [
        {"thinking": {"type": "enabled"}},
        {"reasoning_effort": "low"},
        {"thinking": {"type": "disabled"}},
    ],
)
def test_explicit_user_thinking_preferences_win_over_automatic_policy(extra):
    client = MultiProviderClient(
        base_url="https://api.deepseek.com", request_options={"extra_body": extra}
    )
    assert client.for_task("structured_edit") is client
    assert client.request_options["extra_body"] == extra


@pytest.mark.parametrize(
    "endpoint,protocol",
    [
        ("https://api.deepseek.com.example.invalid", "openai_chat"),
        ("https://api.openai.com/v1", "openai_chat"),
        ("https://api.deepseek.com", "anthropic"),
    ],
)
def test_unverified_provider_never_receives_deepseek_specific_parameters(endpoint, protocol):
    client = MultiProviderClient(base_url=endpoint, api_format=protocol)
    assert client.for_task("structured_edit") is client
    with pytest.raises(ModelError):
        client.for_profile("bounded_json")


def test_derived_profile_dispatches_visible_json_and_keeps_provider_observation(monkeypatch):
    payloads = []

    def reply(self, path, body=None):
        payloads.append(body)
        return {
            "model": "deepseek-flash",
            "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }, str, False

    monkeypatch.setattr(MultiProviderClient, "_json", reply)
    events = []
    base = MultiProviderClient(model="deepseek-flash", base_url="https://api.deepseek.com")
    client = ObservedClient(base, events.append).for_profile("bounded_json")
    result = client.complete(
        [Message("user", "Return JSON")], max_tokens=8192, response_format_json=True
    )
    assert result.total_tokens == 15 and payloads[0]["thinking"] == {"type": "disabled"}
    assert payloads[0]["response_format"] == {"type": "json_object"}
    assert events[0]["inference_profile"] == "deepseek_bounded_json"
    assert base.request_options == {}
