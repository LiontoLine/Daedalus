"""A destructive fixture check must refuse any process outside its isolated workspace."""

import io
import json
from contextlib import nullcontext
from pathlib import Path

import pytest

from daedalus.config import Settings, WorkspaceSettings
from daedalus.service import autostart, autostart_probe, control


@pytest.mark.parametrize("foreign", [True, False])
def test_crash_check_only_signals_verified_disposable_backend(tmp_path, monkeypatch, foreign):
    settings = Settings(workspace=WorkspaceSettings(root=str(tmp_path / "production")))
    workspace = None
    crashed = False
    signals = []

    class Socket:
        def bind(self, _):
            pass

        def getsockname(self):
            return ("127.0.0.1", 13555)

    monkeypatch.setattr(autostart_probe.socket, "socket", lambda: nullcontext(Socket()))

    def install(config, root):
        nonlocal workspace
        workspace = root
        (root / ".service").mkdir(parents=True)
        (root / ".service/controller.json").write_text(json.dumps({"backend_pid": 987654}))

    def response(*_, **__):
        data = {
            "workspace": str(workspace),
            "process_id": 987654 if not foreign else 987655,
            "service_session_id": "after" if crashed else "before",
            "dispatcher": {"active": [], "dispatched": []},
        }
        (workspace / ".service/controller.json").write_text(
            json.dumps(
                {
                    "backend_pid": 987654,
                    "status": "running",
                    "session_id": data["service_session_id"],
                }
            )
        )
        return io.BytesIO(json.dumps(data).encode())

    def kill(pid, sig):
        nonlocal crashed
        assert pid == 987654
        signals.append((pid, sig))
        crashed = True

    commands = []
    monkeypatch.setattr(autostart, "install", install)
    monkeypatch.setattr(autostart, "status", lambda _: {"running": False})
    monkeypatch.setattr(autostart, "command", lambda *args: commands.append(args))
    monkeypatch.setattr(autostart, "plist_for", lambda _: tmp_path / "disposable.plist")
    monkeypatch.setattr(autostart_probe.urllib.request, "urlopen", response)
    monkeypatch.setattr(autostart_probe.os, "kill", kill)
    monkeypatch.setattr(autostart_probe.time, "sleep", lambda _: None)
    monkeypatch.setattr(control, "command", lambda *_a, **_k: {})
    result = autostart_probe.run_probe(settings)
    assert result["cleaned_up"] and result["automatic_resume"] is False
    assert result["status"] == ("FAIL" if foreign else "PASS")
    assert len(signals) == (0 if foreign else 1)
    assert commands[-1][0] == "bootout"
    assert Path(result["workspace"]) != settings.workspace.root_path
