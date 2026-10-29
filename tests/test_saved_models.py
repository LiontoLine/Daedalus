"""Credential persistence contracts; fake vault only, no OS items or network calls."""

import json
import stat

import pytest
from fastapi.testclient import TestClient

from daedalus.application.model_settings import build
from daedalus.application.saved_models import SavedModelProfiles
from daedalus.config import Settings, WorkspaceSettings
from daedalus.infrastructure.keychain import SecureCredentialError
from daedalus.service.app import create_app

SECRET = "opaque-offline-persistence-test-credential"
OTHER = "second-opaque-offline-persistence-credential"


class FakeVault:
    backend = "macos_keychain"
    supported = True

    def __init__(self):
        self.values = {}
        self.gets = 0
        self.writes = 0
        self.fail_write_at = None
        self.locked = False

    def put(self, account, value):
        self.writes += 1
        if self.locked or self.writes == self.fail_write_at:
            raise SecureCredentialError("系统钥匙串操作失败")
        self.values[account] = value

    def get(self, account):
        self.gets += 1
        if self.locked or account not in self.values:
            raise SecureCredentialError("系统钥匙串已锁定或凭证不存在")
        return self.values[account]

    def delete(self, account):
        if self.locked:
            raise SecureCredentialError("系统钥匙串已锁定")
        self.values.pop(account, None)


@pytest.fixture
def vault(monkeypatch):
    value = FakeVault()
    monkeypatch.setattr("daedalus.application.saved_models.MacOSKeychain", lambda service: value)
    return value


def candidate(role="", key=SECRET, **extra):
    return build(
        base_url="https://api.example.invalid/v1",
        model="text-model",
        acknowledged_remote=True,
        api_key=key,
        role=role,
        **extra,
    )


def payload(**extra):
    return {
        "base_url": "https://api.example.invalid/v1",
        "model": "text-model",
        "acknowledge_remote": True,
        "api_key": SECRET,
        "persist": True,
        **extra,
    }


def settings(tmp_path):
    return Settings(workspace=WorkspaceSettings(root=str(tmp_path / "ws")))


def assert_workspace_clean(root):
    for path in root.rglob("*"):
        if path.is_file():
            raw = path.read_bytes()
            assert SECRET.encode() not in raw and OTHER.encode() not in raw, path


def test_saved_profile_restores_lazily_and_uses_private_permissions(tmp_path, vault):
    first = SavedModelProfiles(tmp_path)
    saved = first.save({"": candidate()})[""]
    assert saved.persisted and not saved.api_key
    assert SECRET not in repr(saved) and saved.fingerprint()
    assert stat.S_IMODE(first.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(first.path.stat().st_mode) == 0o600
    second = SavedModelProfiles(tmp_path)
    loaded = second.load()[""]
    assert vault.gets == 0  # startup never unlocks or fetches the credential
    assert loaded.describe() == saved.describe() | {"set_at": loaded.set_at}
    assert second.resolve(loaded) == SECRET
    assert_workspace_clean(tmp_path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("base_url", "https://attacker.invalid/v1"),
        ("model", "other-model"),
        ("api_format", "openai_responses"),
        ("timeout_sec", 121),
        ("request_options", {"extra_body": {"top_p": 0.5}}),
        ("api_key_env", "OTHER_KEY"),
        ("acknowledged_remote", False),
    ],
)
def test_changed_manifest_cannot_send_old_credential(tmp_path, vault, field, value):
    store = SavedModelProfiles(tmp_path)
    store.save({"": candidate()})
    doc = json.loads(store.path.read_text())
    doc["profiles"][""]["settings"][field] = value
    store.path.write_text(json.dumps(doc))
    loaded = store.load()
    if loaded:
        with pytest.raises(SecureCredentialError):
            store.resolve(loaded[""])
    else:
        assert store.restore_error
    assert_workspace_clean(tmp_path)


def test_role_reference_cannot_be_moved_to_another_role(tmp_path, vault):
    store = SavedModelProfiles(tmp_path)
    store.save({"coder": candidate("coder")})
    doc = json.loads(store.path.read_text())
    entry = doc["profiles"].pop("coder")
    entry["settings"]["role"] = "reviewer"
    doc["profiles"]["reviewer"] = entry
    store.path.write_text(json.dumps(doc))
    with pytest.raises(SecureCredentialError):
        store.resolve(store.load()["reviewer"])


def test_batch_vault_failure_and_metadata_failure_keep_previous_profile(
    tmp_path, vault, monkeypatch
):
    store = SavedModelProfiles(tmp_path)
    store.save({"": candidate()})
    before = store.path.read_bytes(), dict(vault.values)
    vault.fail_write_at = vault.writes + 2
    with pytest.raises(SecureCredentialError):
        store.save({"coder": candidate("coder", OTHER), "reviewer": candidate("reviewer")})
    assert (store.path.read_bytes(), vault.values) == before
    vault.fail_write_at = None
    monkeypatch.setattr(store, "_write", lambda doc: (_ for _ in ()).throw(OSError(SECRET)))
    with pytest.raises(SecureCredentialError) as error:
        store.save({"": candidate(key=OTHER)})
    assert SECRET not in str(error.value)
    assert (store.path.read_bytes(), vault.values) == before


def test_global_and_role_updates_match_runtime_precedence(tmp_path, vault):
    store = SavedModelProfiles(tmp_path)
    store.save({"": candidate()})
    store.save({"coder": candidate("coder", OTHER)})
    assert set(store.load()) == {"", "coder"} and len(vault.values) == 2
    store.forget("coder")
    assert set(store.load()) == {""} and len(vault.values) == 1
    store.save({"coder": candidate("coder", OTHER)})
    store.save({"": candidate()})
    assert set(store.load()) == {""} and len(vault.values) == 1
    store.forget()
    assert store.load() == {} and vault.values == {}


def test_locked_delete_can_retry_without_losing_reference(tmp_path, vault):
    store = SavedModelProfiles(tmp_path)
    store.save({"": candidate()})
    before = store.path.read_bytes()
    vault.locked = True
    with pytest.raises(SecureCredentialError):
        store.forget()
    assert store.path.read_bytes() == before
    vault.locked = False
    store.forget()
    assert not store.load() and not vault.values


@pytest.mark.parametrize(
    "bad", ["{broken", '{"version":99,"profiles":{}}', '{"version":1,"profiles":{"coder":12}}']
)
def test_corrupt_metadata_fails_closed_and_can_be_cleared(tmp_path, vault, bad):
    store = SavedModelProfiles(tmp_path)
    store.directory.mkdir()
    store.path.write_text(bad)
    assert store.load() == {} and store.restore_error
    store.forget()
    assert store.load() == {} and not store.restore_error


def test_symlink_metadata_is_rejected(tmp_path, vault):
    store = SavedModelProfiles(tmp_path)
    target = tmp_path / "other.json"
    target.write_text("{}")
    store.directory.mkdir()
    store.path.symlink_to(target)
    with pytest.raises(SecureCredentialError):
        store.save({"": candidate()})
    assert target.read_text() == "{}" and not vault.values


def test_key_copied_into_public_settings_is_rejected(tmp_path, vault):
    store = SavedModelProfiles(tmp_path)
    value = build(
        base_url="https://api.example.invalid/" + SECRET,
        model="text-model",
        api_key=SECRET,
        acknowledged_remote=True,
    )
    with pytest.raises(SecureCredentialError):
        store.save({"": value})
    assert not store.path.exists() and not vault.values


def test_service_restart_restores_roles_without_exporting_or_autorunning(tmp_path, vault, caplog):
    config = settings(tmp_path)
    app = create_app(config)
    with TestClient(app) as client:
        response = client.post("/api/model", json=payload())
        assert response.status_code == 200 and response.json()["persisted"]
        assert SECRET not in response.text
        key_tag = response.json()["override"]["key_fingerprint"]
        assert SECRET not in client.get("/api/model/export").text
        assert app.state.daedalus.build_model_client("coder")._api_key() == SECRET
    app2 = create_app(config)
    calls = vault.gets
    with TestClient(app2) as client:
        result = client.get("/api/model").json()
        assert vault.gets == calls
        assert {r["role"] for r in result["roles"]} == {"planner", "coder", "reviewer"}
        assert all(r["persisted"] and r["key_fingerprint"] == key_tag for r in [result["override"]])
        assert all(r["credential_storage"] == "macos_keychain" for r in result["roles"])
        status = client.get("/api/service").json()
        assert not status["automatic_resume"]
        assert not status["previous_session"]["model_connections_need_reentry"]
        assert not app2.state.daedalus.dispatcher.busy_runs()
        assert app2.state.daedalus.build_model_client("planner")._api_key() == SECRET
        client.delete("/api/model")
    with TestClient(create_app(config)) as client:
        assert client.get("/api/model").json()["roles"] == []
    assert not vault.values and SECRET not in caplog.text
    assert_workspace_clean(config.workspace.root_path)


def test_rotation_keeps_existing_clients_and_empty_key_reuse_is_host_bound(tmp_path, vault):
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        client.post("/api/model", json=payload())
        original = app.state.daedalus.build_model_client("coder")
        assert (
            client.post(
                "/api/model",
                json=payload(api_key="", reuse_existing_key=True, model="updated-model"),
            ).status_code
            == 200
        )
        assert app.state.daedalus.build_model_client("coder")._api_key() == SECRET
        client.post("/api/model", json=payload(api_key=OTHER))
        assert original._api_key() == SECRET
        assert app.state.daedalus.build_model_client("coder")._api_key() == OTHER
        assert len(vault.values) == 1
        client.post(
            "/api/model",
            json=payload(api_key="", reuse_existing_key=True, base_url="https://other.invalid/v1"),
        )
        assert app.state.daedalus.build_model_client("coder")._api_key() == ""
    assert_workspace_clean(app.state.daedalus.settings.workspace.root_path)


@pytest.mark.parametrize("unavailable", ["unsupported", "locked"])
def test_secure_save_failure_keeps_runtime_and_temporary_mode_works(tmp_path, vault, unavailable):
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        client.post("/api/model", json=payload(persist=False))
        before = client.get("/api/model").json()
        if unavailable == "unsupported":
            vault.supported = False
        else:
            vault.locked = True
        response = client.post("/api/model", json=payload(api_key=OTHER))
        assert response.status_code == 503 and OTHER not in response.text
        assert client.get("/api/model").json()["override"] == before["override"]
        assert app.state.daedalus.build_model_client("coder")._api_key() == SECRET
    assert_workspace_clean(app.state.daedalus.settings.workspace.root_path)
    with TestClient(create_app(settings(tmp_path))) as client:
        assert client.get("/api/model").json()["roles"] == []
        assert client.get("/api/service").json()["previous_session"][
            "model_connections_need_reentry"
        ]


def test_import_preview_never_writes_and_persisted_native_roles_restore(tmp_path, vault):
    config = settings(tmp_path)
    content = json.dumps(
        {
            "roles": {
                "planner": {"provider": "deepseek", "model": "planner", "api_key": SECRET},
                "coder": {"provider": "anthropic", "model": "coder", "api_key": OTHER},
                "reviewer": {"provider": "gemini", "model": "reviewer", "api_key": SECRET},
            }
        }
    )
    with TestClient(create_app(config)) as client:
        preview = client.post("/api/model/import/preview", json={"content": content})
        assert preview.status_code == 200 and not vault.values
        assert SECRET not in preview.text and OTHER not in preview.text
        response = client.post(
            "/api/model/import",
            json={"content": content, "persist": True, "acknowledge_remote": True},
        )
        assert response.status_code == 200 and response.json()["persisted"]
        exported = client.get("/api/model/export").text
        assert not any(s in exported for s in [SECRET, OTHER, "credential_ref"])
    app = create_app(config)
    with TestClient(app):
        assert [
            app.state.daedalus.build_model_client(r).api_format
            for r in ("planner", "coder", "reviewer")
        ] == ["openai_chat", "anthropic", "gemini"]
    assert_workspace_clean(config.workspace.root_path)


def test_tampered_profile_blocks_client_construction_before_network(tmp_path, vault):
    config = settings(tmp_path)
    with TestClient(create_app(config)) as client:
        client.post("/api/model", json=payload())
    store = SavedModelProfiles(config.workspace.root_path)
    doc = json.loads(store.path.read_text())
    doc["profiles"][""]["settings"]["base_url"] = "https://attacker.invalid"
    store.path.write_text(json.dumps(doc))
    app = create_app(config)
    with TestClient(app) as client:
        with pytest.raises(SecureCredentialError):
            app.state.daedalus.build_model_client("coder")
        response = client.post(
            "/api/model/test",
            json=payload(api_key="", reuse_existing_key=True, base_url="https://attacker.invalid"),
        )
        assert not response.json()["ok"] and SECRET not in response.text
