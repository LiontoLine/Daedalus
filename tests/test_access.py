"""LAN access is authenticated before any task, model or recovery endpoint runs."""

import json
import re
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from daedalus.config import ConfigError, ServiceSettings, Settings, WorkspaceSettings
from daedalus.service.access import COOKIE, AccessControl, owner_headers
from daedalus.service.app import create_app

PASSWORD = "local-test-password-123"


@pytest.fixture
def configured(tmp_path):
    settings = Settings(workspace=WorkspaceSettings(root=str(tmp_path / "workspace")))
    AccessControl(settings).save_password(PASSWORD)
    return replace(settings, service=ServiceSettings(auth_required=True))


def client(settings, peer="127.0.0.1"):
    return TestClient(create_app(settings), base_url="http://127.0.0.1", client=(peer, 5555))


def test_external_listener_without_login_is_refused_before_creating_runtime(tmp_path):
    settings = Settings(
        workspace=WorkspaceSettings(root=str(tmp_path / "workspace")),
        service=ServiceSettings(host="0.0.0.0"),
    )
    with pytest.raises(ConfigError, match="非本机监听"):
        create_app(settings)
    assert not settings.workspace.database_path.exists()


def test_enabled_login_without_credentials_cannot_start(tmp_path):
    settings = Settings(
        workspace=WorkspaceSettings(root=str(tmp_path / "workspace")),
        service=ServiceSettings(auth_required=True),
    )
    with pytest.raises(ConfigError, match="访问口令"):
        create_app(settings)


def test_all_sensitive_routes_require_authentication_and_health_is_minimal(configured):
    with client(configured) as api:
        for path in ("/api/model", "/api/health", "/api/runs", "/api/service", "/docs"):
            assert api.get(path).status_code == 401
        assert api.post("/api/engineering-evaluations", json={}).status_code == 401
        assert api.post("/api/runs/fake/resume", json={}).status_code == 401
        assert api.get("/healthz").json() == {"status": "ok"}
        assert not api.app.state.daedalus.dispatcher.busy_runs()


def test_cookie_login_and_logout_do_not_start_jobs(configured):
    with client(configured) as api:
        response = api.post("/auth/login", data={"password": PASSWORD}, follow_redirects=False)
        assert response.status_code == 303 and COOKIE in response.cookies
        assert "httponly" in response.headers["set-cookie"].lower()
        assert "samesite=strict" in response.headers["set-cookie"].lower()
        assert api.get("/api/model").status_code == 200
        assert api.get("/api/service").json()["automatic_resume"] is False
        assert api.post("/auth/logout", follow_redirects=False).status_code == 303
        assert api.get("/api/model").status_code == 401
        assert not api.app.state.daedalus.dispatcher.busy_runs()


def test_unknown_passwords_rate_limit_without_echoing_input(configured):
    with client(configured) as api:
        for _ in range(5):
            r = api.post("/auth/login", data={"password": "wrong-private-value"})
            assert r.status_code == 401 and "wrong-private-value" not in r.text
        assert api.post("/auth/login", data={"password": PASSWORD}).status_code == 429


def test_cli_credentials_work_without_disclosing_password_or_resuming_tasks(configured):
    with client(configured) as api:
        headers = owner_headers(configured)
        assert PASSWORD not in repr(headers)
        response = api.get("/api/service", headers=headers)
        assert response.status_code == 200 and not response.json()["automatic_resume"]
        assert not response.json()["busy_runs"]
        assert api.get("/api/model", headers={"Authorization": "Bearer forged"}).status_code == 401


def test_rotation_invalidates_old_sessions_and_only_stores_salted_hashes(configured):
    guard = AccessControl(configured)
    token = guard.token()
    assert guard.valid(token)
    record = configured.workspace.root_path / ".service/access.json"
    assert record.stat().st_mode & 0o777 == 0o600
    assert PASSWORD not in record.read_text()
    guard.save_password(PASSWORD + "-changed")
    assert not guard.valid(token)


def test_authentication_expiry_and_tampering_are_rejected(configured, monkeypatch):
    import daedalus.service.access as access

    guard = AccessControl(configured)
    token = guard.token("cli")
    assert guard.valid(token) and not guard.valid(token + "0")
    now = access.time.time()
    monkeypatch.setattr(access.time, "time", lambda: now + 61)
    assert not guard.valid(token)


def test_public_peer_and_forwarded_loopback_cannot_access_setup_or_api(configured):
    with client(configured, "198.51.100.15") as api:
        assert api.get("/healthz").status_code == 403
        assert (
            api.get(
                "/api/model", headers={**owner_headers(configured), "X-Forwarded-For": "127.0.0.1"}
            ).status_code
            == 403
        )
    with client(configured, "192.168.1.5") as api:
        assert api.get("/auth/setup", headers=owner_headers(configured)).status_code == 403


def test_cross_origin_changes_are_rejected_even_with_valid_cookie(configured):
    with client(configured) as api:
        api.post("/auth/login", data={"password": PASSWORD})
        assert (
            api.post(
                "/api/engineering-evaluations", json={}, headers={"Origin": "https://evil.invalid"}
            ).status_code
            == 403
        )


def test_setup_requires_local_origin_nonce_and_confirmation(tmp_path):
    settings = Settings(workspace=WorkspaceSettings(root=str(tmp_path / "workspace")))
    with client(settings) as api:
        assert (
            api.post("/auth/setup", data={"password": PASSWORD, "confirm": PASSWORD}).status_code
            == 403
        )
        page = api.get("/auth/setup")
        nonce = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
        payload = {"password": PASSWORD, "confirm": PASSWORD, "csrf": nonce}
        assert (
            api.post(
                "/auth/setup", data=payload, headers={"Origin": "https://evil.invalid"}
            ).status_code
            == 403
        )
        assert api.post("/auth/setup", data={**payload, "confirm": "different"}).status_code == 422
        response = api.post("/auth/setup", data=payload)
        assert response.status_code == 200 and PASSWORD not in response.text
        assert api.get("/api/access").json()["configured"]
        assert not api.app.state.daedalus.dispatcher.busy_runs()
        assert api.post("/auth/setup", data={**payload, "password": "a" * 5000}).status_code == 403


def test_unsafe_credential_files_fail_closed(configured, tmp_path):
    path = configured.workspace.root_path / ".service/access.json"
    path.chmod(0o644)
    with pytest.raises(ConfigError):
        create_app(configured)
    path.unlink()
    other = tmp_path / "outside.json"
    other.write_text(json.dumps({}))
    path.symlink_to(other)
    with pytest.raises(ConfigError):
        create_app(configured)
