"""Failed replacement must retain the running configuration and never stop its owner."""

import json
import plistlib
import re
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from daedalus.config import ConfigError, load_settings
from daedalus.errors import DaedalusError
from daedalus.service import autostart, control
from daedalus.service.access import AccessControl
from daedalus.service.access_config import access_change, configure_access
from daedalus.service.app import create_app


@pytest.fixture
def saved(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        "[workspace]\nroot = "
        + json.dumps(str(tmp_path / "workspace"))
        + '\n[service] # keep comment\nhost = "127.0.0.1"\nport = 13499\n'
        "\n[execution]\npark_on_escalation = true\n"
    )
    return load_settings(config)


def test_credentials_required_before_config_write_and_failed_handoff_rolls_back(saved):
    path = __import__("pathlib").Path(saved.source_path)
    original = path.read_bytes()
    with pytest.raises(ConfigError):
        configure_access(saved, lan=True)
    assert path.read_bytes() == original
    AccessControl(saved).save_password("synthetic-password-only")
    with pytest.raises(RuntimeError), access_change(saved, lan=True):
        assert load_settings(path).service.host == "0.0.0.0"
        raise RuntimeError("replacement failed")
    assert path.read_bytes() == original
    configure_access(saved, lan=True)
    updated = load_settings(path)
    assert updated.service.auth_required and updated.service.host == "0.0.0.0"
    assert updated.execution.park_on_escalation and updated.service.port == 13499
    assert "# keep comment" in path.read_text()
    assert "synthetic-password" not in path.read_text()


def test_permission_denial_does_not_claim_existing_supervisor_is_dead(monkeypatch):
    def denied(*_):
        raise PermissionError

    monkeypatch.setattr(control.os, "kill", denied)
    assert control._alive(12345)
    assert not control._alive(None)


def test_launchagent_preserves_normal_stop_and_contains_no_model_secret(
    saved, tmp_path, monkeypatch
):
    monkeypatch.setattr(autostart.sys, "platform", "darwin")
    path = tmp_path / "LaunchAgents/service.plist"
    monkeypatch.setattr(autostart, "plist_for", lambda _: path)
    monkeypatch.setattr(autostart, "status", lambda _: {"loaded": False})
    command = Mock(return_value="")
    monkeypatch.setattr(autostart, "command", command)
    autostart.install(saved.source_path, saved.workspace.root_path)
    spec = plistlib.loads(path.read_bytes())
    assert spec["KeepAlive"] == {"SuccessfulExit": False}
    assert spec["RunAtLoad"] and spec["ExitTimeOut"] == 600
    assert spec["ProgramArguments"][-2:] == ["--wait-lock", "120"]
    assert set(spec["EnvironmentVariables"]) == {"PYTHONPATH", "DAEDALUS_LAUNCHD"}
    assert path.stat().st_mode & 0o777 == 0o600
    command.assert_called_once()


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_launchagent_install_refuses_unsupported_platform_without_side_effects(
    saved, tmp_path, monkeypatch, platform
):
    monkeypatch.setattr(autostart.sys, "platform", platform)
    path = tmp_path / "LaunchAgents/service.plist"
    monkeypatch.setattr(autostart, "plist_for", lambda _: path)
    command = Mock()
    monkeypatch.setattr(autostart, "command", command)
    with pytest.raises(DaedalusError):
        autostart.install(saved.source_path, saved.workspace.root_path)
    assert not path.parent.exists()
    assert not (saved.workspace.root_path / ".service").exists()
    command.assert_not_called()


def test_bootstrap_failure_does_not_stop_current_backend(saved, monkeypatch):
    monkeypatch.setattr(control, "managed_control", lambda _: {"managed": True})
    stopped = Mock()
    monkeypatch.setattr(control, "request_control", stopped)
    monkeypatch.setattr(autostart, "install", Mock(side_effect=DaedalusError("launchd denied")))
    with pytest.raises(DaedalusError):
        autostart.handoff(saved, autostart=True)
    stopped.assert_not_called()


def test_repeated_enable_on_launchd_never_stops_current_backend(saved, monkeypatch):
    monkeypatch.setattr(control, "managed_control", lambda _: {"managed": True})
    stopped = Mock()
    monkeypatch.setattr(control, "request_control", stopped)
    monkeypatch.setattr(autostart, "install", lambda *_: {"running": True})
    monkeypatch.setenv("DAEDALUS_LAUNCHD", "1")
    app = create_app(saved)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 1234)) as api:
        page = api.get("/auth/setup").text
        nonce = re.search(r'name="csrf" value="([^"]+)"', page)[1]
        result = api.post("/auth/autostart", data={"csrf": nonce})
        assert result.status_code == 200
        assert "后台托管已启用" in result.text
        assert app.state.daedalus.dispatcher.describe()["accepting"]
    stopped.assert_not_called()
