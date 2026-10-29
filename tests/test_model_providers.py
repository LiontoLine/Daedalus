"""Protocol and import contract checks; no socket or actual model calls."""

import io
import json
import urllib.error

import pytest
from fastapi.testclient import TestClient

from daedalus.application.model_profiles import parse
from daedalus.application.model_settings import ModelOverrideRejected
from daedalus.config import ProviderSettings, Settings, WorkspaceSettings, load_settings
from daedalus.model.base import Message, ModelError, ModelUnavailable
from daedalus.model.catalog import catalog
from daedalus.model.multi_provider import MultiProviderClient
from daedalus.service.app import create_app

SECRET = "opaque-private-credential-for-offline-tests"


def response(payload):
    return io.BytesIO(json.dumps(payload).encode())


def test_bounded_retrieval_profile_is_scoped_and_keeps_observation():
    from daedalus.model.base import Completion
    from daedalus.model.observed import ObservedClient

    client = MultiProviderClient(
        model="deepseek-flash", base_url="https://api.deepseek.com",
        request_options={"extra_body": {"reasoning_effort": "high", "top_p": .97}},
    )
    derived = client.for_retrieval()
    assert derived.model == client.model and derived.base_url == client.base_url
    assert client.request_options == {"extra_body": {"reasoning_effort": "high", "top_p": .97}}
    assert derived.request_options["extra_body"] == {
        "reasoning_effort": "none", "thinking": {"type": "disabled"}, "top_p": .97,
    }
    assert derived.retrieval_profile == "deepseek_bounded_json_nonthinking"
    custom = MultiProviderClient(model="custom", base_url="https://api.deepseek.com.example.invalid")
    assert custom.for_retrieval() is custom

    class Inner:
        retrieval_profile = "controlled-derived-client"

        def for_retrieval(self):
            return self

        def complete(self, messages, **kwargs):
            return Completion('{}', prompt_tokens=4, completion_tokens=2)

    observed = []
    wrapped = ObservedClient(Inner(), observed.append).for_retrieval()
    wrapped.complete([])
    assert wrapped.retrieval_profile == "controlled-derived-client"
    assert len(observed) == 1 and observed[0]["tokens"] == 6


@pytest.mark.parametrize(
    "protocol,payload,input_tokens,output_tokens",
    [
        (
            "openai_chat",
            {
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 2},
            },
            4,
            2,
        ),
        (
            "openai_responses",
            {
                "status": "completed",
                "output": [
                    {"type": "reasoning"},
                    {"type": "message", "content": [{"type": "output_text", "text": "ok"}]},
                ],
                "usage": {"input_tokens": 4, "output_tokens": 7},
            },
            4,
            7,
        ),
        (
            "anthropic",
            {
                "content": [
                    {"type": "thinking", "thinking": "private-thought"},
                    {"type": "text", "text": "ok"},
                ],
                "usage": {
                    "input_tokens": 4,
                    "cache_read_input_tokens": 5,
                    "cache_creation_input_tokens": 3,
                    "output_tokens": 7,
                },
            },
            12,
            7,
        ),
        (
            "gemini",
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [{"thought": True, "text": "private-thought"}, {"text": "ok"}]
                        },
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 4,
                    "candidatesTokenCount": 2,
                    "thoughtsTokenCount": 5,
                },
            },
            4,
            7,
        ),
    ],
)
def test_all_protocols_send_correct_wire_format_and_account_reasoning(
    monkeypatch, protocol, payload, input_tokens, output_tokens
):
    sent = []

    def fake(request, **kwargs):
        sent.append(request)
        return response(payload)

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fake))
    client = MultiProviderClient(
        model="text-model",
        base_url="https://api.example.com/v1",
        api_format=protocol,
        api_key_resolver=lambda: SECRET,
    )
    result = client.complete(
        [Message("system", "system instruction"), Message("user", "hello")],
        max_tokens=512,
        response_format_json=True,
    )
    request = sent[0]
    body = json.loads(request.data)
    headers = {k.lower(): v for k, v in request.header_items()}
    assert (
        result.text == "ok"
        and result.prompt_tokens == input_tokens
        and result.completion_tokens == output_tokens
    )
    assert "private-thought" not in result.text and SECRET not in repr(result)
    assert SECRET not in request.full_url
    if protocol == "anthropic":
        assert request.full_url.endswith("/messages")
        assert body["system"] == "system instruction" and body["messages"][0]["role"] == "user"
        assert headers["x-api-key"] == SECRET and "response_format" not in body
    elif protocol == "gemini":
        assert request.full_url.endswith("/models/text-model:generateContent")
        assert body["systemInstruction"]["parts"][0]["text"] == "system instruction"
        assert body["generationConfig"]["responseMimeType"] == "application/json"
        assert headers["x-goog-api-key"] == SECRET
    elif protocol == "openai_responses":
        assert request.full_url.endswith("/responses") and body["store"] is False
        assert body["max_output_tokens"] == 512 and "temperature" not in body
    else:
        assert body["max_tokens"] == 512 and body["response_format"] == {"type": "json_object"}


@pytest.mark.parametrize(
    "protocol,payload",
    [
        ("anthropic", {"content": [{"type": "tool_use", "name": "execute"}]}),
        (
            "gemini",
            {"candidates": [{"content": {"parts": [{"functionCall": {"name": "execute"}}]}}]},
        ),
        ("openai_responses", {"status": "incomplete", "output": []}),
        ("openai_chat", {"choices": [{"message": {"content": "", "tool_calls": [{}]}}]}),
    ],
)
def test_unrequested_tools_and_empty_or_incomplete_answers_fail_closed(
    monkeypatch, protocol, payload
):
    monkeypatch.setattr(
        MultiProviderClient, "_open", staticmethod(lambda *args, **kwargs: response(payload))
    )
    with pytest.raises(ModelError):
        MultiProviderClient(api_format=protocol, api_key_resolver=lambda: SECRET).complete(
            [Message("user", "test")]
        )


@pytest.mark.parametrize(
    "status,kind", [(401, ModelError), (429, ModelUnavailable), (503, ModelUnavailable)]
)
def test_server_errors_never_echo_the_actual_opaque_key(monkeypatch, status, kind):
    def fail(request, **kwargs):
        raise urllib.error.HTTPError(
            request.full_url, status, "failed", {}, io.BytesIO(("bad key " + SECRET).encode())
        )

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fail))
    with pytest.raises(kind) as caught:
        MultiProviderClient(api_key_resolver=lambda: SECRET).complete([Message("user", "test")])
    assert SECRET not in str(caught.value)


def test_reasoning_chat_options_and_full_endpoint_normalization(monkeypatch):
    sent = []

    def fake(request, **kwargs):
        sent.append(request)
        return response({"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fake))
    client = MultiProviderClient(
        base_url="https://example.com/v1/chat/completions",
        api_key_resolver=lambda: "",
        request_options={
            "send_temperature": False,
            "token_limit_field": "max_completion_tokens",
            "send_json_mode": False,
        },
    )
    client.complete([Message("user", "test")], max_tokens=55, response_format_json=True)
    body = json.loads(sent[0].data)
    assert sent[0].full_url == "https://example.com/v1/chat/completions"
    assert (
        body["max_completion_tokens"] == 55
        and "temperature" not in body
        and "response_format" not in body
    )


@pytest.mark.parametrize(
    "content,protocol",
    [
        ('{"provider":"anthropic","model":"my-claude","apiKey":"' + SECRET + '"}', "anthropic"),
        (
            '[model.coder]\napi_format="gemini"\nmodel="my-gemini"\nbase_url="https://generativelanguage.googleapis.com/v1beta"\napi_key_env="GEMINI_API_KEY"',
            "gemini",
        ),
        (
            "OPENAI_API_KEY="
            + SECRET
            + "\nOPENAI_MODEL=my-model\nOPENAI_BASE_URL=https://example.com/v1",
            "openai_chat",
        ),
        (
            '{"env":{"ANTHROPIC_AUTH_TOKEN":"' + SECRET + '","ANTHROPIC_MODEL":"my-claude"}}',
            "anthropic",
        ),
        (
            'model="my-model"\nmodel_provider="gateway"\n[model_providers.gateway]\nbase_url="https://example.com/v1"\nwire_api="responses"\nenv_key="MY_MODEL_KEY"',
            "openai_responses",
        ),
    ],
)
def test_json_toml_env_claude_and_codex_api_imports(content, protocol):
    values = parse(content)
    first = next(iter(values.values()))
    assert first.api_format == protocol and SECRET not in repr(first)
    assert SECRET not in json.dumps(first.describe())


@pytest.mark.parametrize(
    "content",
    [
        '{"roles":{"coder":{"model":"x","base_url":"https://example.com/v1"},"reviewer":{"api_key":"'
        + SECRET
        + '"}}}',
        '{"model":"x","base_url":"https://user:' + SECRET + '@example.com/v1"}',
        '{"model":"x","base_url":"https://example.com/v1?key=' + SECRET + '"}',
        '{"provider":"unknown","model":"x"}',
        '{"model":"x","request_options":{"extra_body":{"messages":["override"]}}}',
        '{"model":12,"api_key":"' + SECRET + '"}',
    ],
)
def test_invalid_imports_are_rejected_without_repeating_the_source(content):
    with pytest.raises(ModelOverrideRejected) as caught:
        parse(content)
    assert SECRET not in str(caught.value)


def test_batch_import_routes_native_roles_atomically_and_exports_no_keys(tmp_path, monkeypatch):
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    with TestClient(app) as client:
        content = json.dumps(
            {
                "version": 1,
                "roles": {
                    "planner": {"provider": "openai", "model": "planner", "api_key": SECRET},
                    "coder": {"provider": "anthropic", "model": "coder", "api_key": SECRET},
                    "reviewer": {"provider": "gemini", "model": "reviewer", "api_key": SECRET},
                },
            }
        )
        preview = client.post("/api/model/import/preview", json={"content": content})
        assert preview.status_code == 200 and len(preview.json()["profiles"]) == 3
        assert SECRET not in preview.text and client.get("/api/model").json()["roles"] == []
        assert client.post("/api/model/import", json={"content": content}).status_code == 422
        saved = client.post(
            "/api/model/import", json={"content": content, "acknowledge_remote": True}
        )
        assert saved.status_code == 200 and SECRET not in saved.text
        state = app.state.daedalus
        assert [
            state.build_model_client(role).api_format for role in ("planner", "coder", "reviewer")
        ] == ["openai_responses", "anthropic", "gemini"]
        worker, review = state.build_worker(use_model=True, enable_review=True)
        assert (
            worker.client.api_format == "anthropic"
            and review.reviewer.client.api_format == "gemini"
        )
        exported = client.get("/api/model/export")
        assert SECRET not in exported.text and len(exported.json()["roles"]) == 3
        before = client.get("/api/model").json()
        invalid = json.dumps(
            {
                "roles": {
                    "coder": {"provider": "deepseek", "model": "new"},
                    "reviewer": {"model": ""},
                }
            }
        )
        assert (
            client.post(
                "/api/model/import", json={"content": invalid, "acknowledge_remote": True}
            ).status_code
            == 422
        )
        assert client.get("/api/model").json() == before
        assert client.delete("/api/model").json()["roles"] == []


def test_catalog_and_global_dialog_are_available_from_every_page(tmp_path):
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    with TestClient(app) as client:
        data = client.get("/api/model/catalog").json()
        assert len(data["providers"]) == 20
        assert client.get("/static/model-providers.json").json() == data
        for route in ("/", "/execution", "/audit", "/runs", "/operations"):
            page = client.get(route).text
            assert page.count('id="model-settings-dialog"') == 1
            assert "data-model-open" in page and 'id="model-import-file"' in page


def test_bad_request_validation_does_not_echo_imported_secrets(tmp_path):
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    with TestClient(app) as client:
        result = client.post(
            "/api/model",
            json={
                "base_url": "https://example.com",
                "model": {"secret": SECRET},
                "api_key": SECRET,
            },
        )
        assert result.status_code == 422 and SECRET not in result.text


def test_persistent_config_accepts_native_protocol(tmp_path):
    path = tmp_path / "models.toml"
    path.write_text(
        '[model]\ndefault_role="coder"\n[model.coder]\nmodel="my-claude"\nbase_url="https://api.anthropic.com/v1"\napi_format="anthropic"\napi_key_env="ANTHROPIC_API_KEY"\n'
    )
    assert load_settings(path).providers["coder"].api_format == "anthropic"


def test_discovery_works_before_a_model_is_selected(tmp_path, monkeypatch):
    sent = []

    def fake(request, **kwargs):
        sent.append(request)
        return response(
            {
                "models": [
                    {
                        "name": "models/text-model",
                        "supportedGenerationMethods": ["generateContent"],
                    },
                    {"name": "models/embedding", "supportedGenerationMethods": ["embedContent"]},
                ]
            }
        )

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fake))
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    with TestClient(app) as client:
        found = client.post(
            "/api/model/models",
            json={
                "provider": "gemini",
                "base_url": "https://generativelanguage.googleapis.com/v1beta",
                "api_format": "gemini",
                "api_key": SECRET,
            },
        )
        assert found.json()["ok"] is True
        assert [m["id"] for m in found.json()["models"]] == ["text-model"]
        assert sent[0].method == "GET" and SECRET not in found.text
        assert client.get("/api/model").json()["roles"] == []


def test_edit_reuses_key_only_for_the_same_endpoint(tmp_path, monkeypatch):
    sent = []

    def fake(request, **kwargs):
        sent.append(dict((k.lower(), v) for k, v in request.header_items()))
        return response({"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fake))
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    with TestClient(app) as client:
        original = {
            "base_url": "https://example.com/v1",
            "model": "model-a",
            "api_key": SECRET,
            "acknowledge_remote": True,
        }
        assert client.post("/api/model", json=original).status_code == 200
        changed = {**original, "api_key": "", "model": "model-b", "reuse_existing_key": True}
        assert client.post("/api/model/test", json=changed).json()["ok"]
        assert sent[-1]["authorization"] == "Bearer " + SECRET
        assert client.post(
            "/api/model/test", json={**changed, "base_url": "https://other.example/v1"}
        ).json()["ok"]
        assert "authorization" not in sent[-1]
        assert SECRET not in client.get("/api/model").text


def test_local_export_can_be_reimported_without_inventing_a_credential(tmp_path):
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws"))))
    with TestClient(app) as client:
        assert (
            client.post(
                "/api/model",
                json={
                    "base_url": "http://127.0.0.1:11434/v1",
                    "model": "local-model",
                    "provider": "ollama",
                },
            ).status_code
            == 200
        )
        exported = client.get("/api/model/export").json()
        assert all(not value["api_key_env"] for value in exported["roles"].values())
        client.delete("/api/model")
        assert (
            client.post("/api/model/import", json={"content": json.dumps(exported)}).status_code
            == 200
        )
        assert app.state.daedalus.build_model_client("coder")._api_key() == ""


def test_native_credentials_do_not_fall_back_to_another_vendor(tmp_path, monkeypatch):
    from daedalus.errors import DaedalusError

    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    app = create_app(
        Settings(
            workspace=WorkspaceSettings(root=str(tmp_path / "ws")),
            providers={
                "coder": ProviderSettings(
                    name="coder",
                    model="my-claude",
                    provider="anthropic",
                    api_format="anthropic",
                    base_url="https://api.anthropic.com/v1",
                    api_key_env="ANTHROPIC_API_KEY",
                )
            },
        )
    )
    with TestClient(app) as client:
        assert client.get("/api/model").json()["roles"][0]["key_set"] is False
        with pytest.raises(DaedalusError) as caught:
            app.state.daedalus.build_model_client("coder")._api_key()
        assert "ANTHROPIC_API_KEY" in str(caught.value) and SECRET not in str(caught.value)


def test_gemini_thinking_parameters_are_forwarded_and_not_silently_ignored(monkeypatch):
    sent = []

    def fake(request, **kwargs):
        sent.append(json.loads(request.data))
        return response({"candidates": [{"content": {"parts": [{"text": "ok"}]}}]})

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fake))
    client = MultiProviderClient(
        api_format="gemini",
        api_key_resolver=lambda: "",
        request_options={"extra_body": {"thinking_config": {"thinkingBudget": 0}}},
    )
    client.complete([Message("user", "test")])
    assert sent[0]["generationConfig"]["thinkingConfig"] == {"thinkingBudget": 0}
    client.request_options = {"extra_body": {"reasoning_effort": "low"}}
    with pytest.raises(ModelError):
        client.complete([Message("user", "test")])
    assert len(sent) == 1


def test_redirect_cannot_forward_credentials():
    from urllib.request import Request

    from daedalus.model.multi_provider import _NoRedirect

    original = Request("https://first.example/v1", headers={"Authorization": "Bearer " + SECRET})
    assert (
        _NoRedirect().redirect_request(
            original, None, 307, "redirect", {}, "https://other.example/v1"
        )
        is None
    )


@pytest.mark.parametrize("host", ["127.0.0.2", "[::1]", "localhost"])
def test_real_loopback_addresses_can_be_used_without_remote_acknowledgement(host):
    values = parse(json.dumps({"base_url": f"http://{host}:1234/v1", "model": "local"}))
    assert next(iter(values.values())).is_loopback


def test_domain_starting_with_127_still_requires_remote_acknowledgement():
    from daedalus.application.model_settings import build

    with pytest.raises(ModelOverrideRejected):
        build(base_url="https://127.external.example/v1", model="text-model")


def test_azure_preset_sends_api_key_header_instead_of_an_identity_token(monkeypatch):
    sent = []

    def fake(request, **kwargs):
        sent.append(request)
        return response(
            {
                "status": "completed",
                "output": [{"type": "message", "content": [{"type": "output_text", "text": "ok"}]}],
            }
        )

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fake))
    from daedalus.model.multi_provider import build_client

    imported = next(
        iter(
            parse(
                json.dumps(
                    {
                        "provider": "azure",
                        "model": "my-deployment",
                        "base_url": "https://resource.openai.azure.com/openai/v1",
                        "api_key": SECRET,
                    }
                )
            ).values()
        )
    )
    build_client(imported.as_provider(), api_key_resolver=lambda: SECRET).complete(
        [Message("user", "test")]
    )
    headers = {k.lower(): v for k, v in sent[0].header_items()}
    assert headers["api-key"] == SECRET and "authorization" not in headers
