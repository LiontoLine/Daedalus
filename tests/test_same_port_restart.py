"""Explicit older-instance shutdown, followed by startup on the original port."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from daedalus.config import load_settings
from daedalus.errors import DaedalusError
from daedalus.service import control, legacy, terminal
from tests.test_terminal_entry import console_fixture


def environment(tmp_path):
    config = tmp_path / "console.toml"
    config.write_text(
        "[workspace]\nroot = "
        + json.dumps(str(tmp_path / "workspace"))
        + "\n[service]\nport = 13499\n"
    )
    return config, load_settings(config)


def legacy_fixture(tmp_path, monkeypatch):
    config, settings = environment(tmp_path)
    calls = []
    monkeypatch.setattr(legacy, "listening_pid", lambda port: 765432)
    monkeypatch.setattr(legacy, "process_identity", lambda pid: "same-user-same-birth-time")
    monkeypatch.setattr(legacy, "running", lambda pid: False)
    monkeypatch.setattr(legacy.os, "kill", lambda pid, sig: calls.append((pid, sig)))

    def http(settings, path, post=False):
        if path == "/api/health":
            return {"status": "ok", "dispatcher": {}, "workspace": "/old/workspace"}
        if path == "/openapi.json":
            return {"info": {"title": "Daedalus"}}
        if path == "/api/runs":
            return {"runs": [{"run_id": "task-one"}]}
        if path.startswith("/api/backup"):
            raise DaedalusError("old database path is missing")
        return {"evidence": "saved task view"}

    monkeypatch.setattr(legacy, "http_json", http)
    return config, settings, calls


def test_verified_legacy_is_gracefully_stopped_after_saving_evidence(tmp_path, monkeypatch):
    _, settings, calls = legacy_fixture(tmp_path, monkeypatch)
    result = legacy.stop_legacy(settings)
    assert calls == [(765432, signal.SIGTERM)]
    snapshot = json.loads(Path(result["snapshot"]).read_text())
    assert not snapshot["is_database_backup"] and not snapshot["automatic_resume"]
    assert snapshot["records"]["details"]["task-one"]["specs"]["evidence"] == "saved task view"
    note = json.loads((settings.workspace.root_path / ".service/session.json").read_text())
    assert "无法生成完整备份" in note["note"] and not note["checkpoint_saved"]


def test_unknown_service_is_never_stopped(tmp_path, monkeypatch):
    _, settings, calls = legacy_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        legacy,
        "http_json",
        lambda *a, **k: {
            "status": "ok",
            "dispatcher": {},
            "info": {"title": "another application"},
        },
    )
    with pytest.raises(DaedalusError, match="其他程序"):
        legacy.stop_legacy(settings)
    assert calls == []


def test_pid_change_before_signal_refuses_shutdown(tmp_path, monkeypatch):
    _, settings, calls = legacy_fixture(tmp_path, monkeypatch)
    pids = iter([765432, 765433])
    monkeypatch.setattr(legacy, "listening_pid", lambda port: next(pids))
    with pytest.raises(DaedalusError, match="发生变化"):
        legacy.stop_legacy(settings)
    assert calls == []


def test_denied_restart_cannot_shut_down_a_service_it_cannot_replace(tmp_path, monkeypatch):
    config, _ = environment(tmp_path)

    class Socket:
        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def bind(self, *args):
            raise PermissionError("denied")

    monkeypatch.setattr(legacy.socket, "socket", Socket)
    monkeypatch.setattr(
        legacy,
        "stop_legacy",
        lambda *a, **k: pytest.fail("must not stop before listen permission check"),
    )
    with pytest.raises(DaedalusError, match="现有服务未被停止"):
        control.command("restart", config)


def test_restart_shuts_down_legacy_before_binding_the_same_port(tmp_path, monkeypatch):
    config, _ = environment(tmp_path)
    events = []
    monkeypatch.setattr(legacy, "assert_restart_permission", lambda settings: None)
    monkeypatch.setattr(
        legacy, "stop_legacy", lambda *a, **k: events.append("legacy-shutdown") or {"old_pid": 1}
    )

    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def setsockopt(self, *args):
            pass

        def bind(self, address):
            assert address == ("127.0.0.1", 13499)
            events.append("bind-original-port")

    monkeypatch.setattr(control.socket, "socket", Socket)
    reads = iter([{}, {"supervisor_pid": 456789, "status": "running"}])
    monkeypatch.setattr(control, "_read", lambda path: next(reads))

    class Process:
        pid = 456789

        def poll(self):
            return None

    monkeypatch.setattr(
        control.subprocess, "Popen", lambda *a, **k: events.append("start-new-backend") or Process()
    )
    result = control.command("restart", config)
    assert events == ["legacy-shutdown", "bind-original-port", "start-new-backend"]
    assert result["status"] == "running" and "原端口" in result["message"]


def test_restart_flag_enters_console_after_restart(tmp_path, monkeypatch):
    from daedalus.cli import main

    calls = []
    monkeypatch.setattr(terminal, "run_console", lambda **options: calls.append(options) or 0)
    assert main(["--restart"]) == 0
    assert calls[-1]["restart"] is True
    # Exercise the actual console path with a controlled service transport.
    monkeypatch.undo()
    config, commands, _, read, output = console_fixture(tmp_path, monkeypatch, ["/detach"])
    assert (
        terminal.run_console(config_path=str(config), restart=True, read=read, output=output) == 0
    )
    assert commands == ["restart"]


def test_explicit_legacy_shutdown_really_terminates_a_disposable_child(tmp_path, monkeypatch):
    _, settings, _ = legacy_fixture(tmp_path, monkeypatch)
    monkeypatch.undo()
    ready = tmp_path / "ready"
    code = "import signal,sys,time;from pathlib import Path;signal.signal(signal.SIGTERM,lambda *a:sys.exit(0));Path(sys.argv[1]).touch();time.sleep(30)"
    process = subprocess.Popen([sys.executable, "-c", code, str(ready)])
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists()
        monkeypatch.setattr(legacy, "listening_pid", lambda port: process.pid)
        monkeypatch.setattr(legacy, "process_identity", lambda pid: "test-child")
        monkeypatch.setattr(legacy, "running", lambda pid: process.poll() is None)

        def http(settings, path, post=False):
            if path == "/api/health":
                return {
                    "status": "ok",
                    "dispatcher": {},
                    "workspace": str(settings.workspace.root_path),
                    "process_id": process.pid,
                }
            if path == "/openapi.json":
                return {"info": {"title": "Daedalus"}}
            if path == "/api/runs":
                return {"runs": []}
            return {"verified": True, "path": "test-only-backup"}

        monkeypatch.setattr(legacy, "http_json", http)
        result = legacy.stop_legacy(settings, wait_timeout=5)
        assert result["old_pid"] == process.pid and process.wait(timeout=3) == 0
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=3)


def test_retry_waits_for_a_closing_legacy_process_without_sending_another_signal(
    tmp_path, monkeypatch
):
    _, settings, calls = legacy_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(legacy, "running", lambda pid: True)
    with pytest.raises(DaedalusError, match="正在正常关闭"):
        legacy.stop_legacy(settings, wait_timeout=0)
    assert calls == [(765432, signal.SIGTERM)]
    monkeypatch.setattr(legacy, "running", lambda pid: False)
    monkeypatch.setattr(
        legacy,
        "listening_pid",
        lambda port: pytest.fail("closing process is remembered even after its port closes"),
    )
    result = legacy.stop_legacy(settings)
    assert result["old_pid"] == 765432 and len(calls) == 1
    assert not (settings.workspace.root_path / ".service/legacy-pending.json").exists()
