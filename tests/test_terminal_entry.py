"""The bare terminal command, explicit human continuation, and reversible local install."""

import io
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from daedalus.errors import DaedalusError
from daedalus.service import terminal
from scripts.install_cli import install


def console_fixture(tmp_path, monkeypatch, lines):
    config = tmp_path / "console.toml"
    config.write_text("[workspace]\nroot = " + json.dumps(str(tmp_path / "workspace")) + "\n")
    commands, requests = [], []

    def control(action, path, **options):
        commands.append(action)
        return {"status": "stopped" if action == "stop" else "running", "message": action}

    def api(settings, path, body=None):
        requests.append((path, body))
        if path == "/api/service":
            return {
                "control": {"managed": True},
                "previous_session": {"note": "inspect saved checkpoint"},
                "reminders": [],
            }
        if path == "/api/health":
            return {"workspace": str(tmp_path / "workspace")}
        if path.endswith("/recovery"):
            return {
                "last_verified_node": "first",
                "integration_head": "verified-commit",
                "frontier": [{"node_id": "second", "objective": "continue here"}],
                "blockers": [],
                "busy": False,
                "checkpoint_digest": "exact-checkpoint",
            }
        if path == "/api/owners":
            return {"enforced": False}
        return {"accepted": True}

    monkeypatch.setattr(terminal, "command", control)
    monkeypatch.setattr(terminal, "_api", api)
    iterator = iter(lines)

    def read(prompt):
        item = next(iterator)
        if isinstance(item, BaseException):
            raise item
        return item

    return config, commands, requests, read, io.StringIO()


def test_terminal_has_service_controls_and_detaches_without_stopping(tmp_path, monkeypatch):
    config, commands, requests, read, output = console_fixture(
        tmp_path, monkeypatch, ["/status", "/stop", "/start", "/detach"]
    )
    assert terminal.run_console(config_path=str(config), read=read, output=output) == 0
    assert commands == ["start", "status", "stop", "start"]
    assert all(body is None for _, body in requests)
    assert "inspect saved checkpoint" in output.getvalue()


def test_ctrl_c_saves_and_stops_the_managed_backend(tmp_path, monkeypatch):
    config, commands, _, read, output = console_fixture(
        tmp_path, monkeypatch, [KeyboardInterrupt()]
    )
    assert terminal.run_console(config_path=str(config), read=read, output=output) == 0
    assert commands == ["start", "stop"]
    assert "保存断点" in output.getvalue()


@pytest.mark.parametrize("resume", [False, True])
def test_review_only_saves_and_continuation_requires_a_separate_command(
    tmp_path, monkeypatch, resume
):
    lines = (
        ["/review task-1", "operator", "verified first node", "y"]
        + (["/resume task-1"] if resume else [])
        + ["/detach"]
    )
    config, commands, requests, read, output = console_fixture(tmp_path, monkeypatch, lines)
    assert terminal.run_console(config_path=str(config), read=read, output=output) == 0
    posts = [(path, body) for path, body in requests if body is not None]
    assert posts[0][0] == "/api/runs/task-1/recovery-review"
    assert posts[0][1]["checkpoint_digest"] == "exact-checkpoint"
    assert any(path.endswith("/resume") for path, _ in posts) == resume
    assert commands == ["start"]


def test_declining_review_leaves_task_unchanged(tmp_path, monkeypatch):
    config, _, requests, read, output = console_fixture(
        tmp_path, monkeypatch, ["/review task-1", "operator", "pending", "n", "/detach"]
    )
    terminal.run_console(config_path=str(config), read=read, output=output)
    assert all(body is None for _, body in requests)
    assert "任务保持暂停" in output.getvalue()


def test_startup_refusal_preserves_the_console_without_stopping_an_old_service(
    tmp_path, monkeypatch
):
    config, _commands, requests, read, output = console_fixture(tmp_path, monkeypatch, ["/detach"])

    def refuse(*args, **kwargs):
        raise DaedalusError("original service preserved")

    monkeypatch.setattr(terminal, "command", refuse)
    assert terminal.run_console(config_path=str(config), read=read, output=output) == 0
    assert "original service preserved" in output.getvalue()
    assert requests == []


def test_installer_preserves_shell_config_and_passes_arguments_without_shell_evaluation(tmp_path):
    project = tmp_path / "project with spaces"
    home = tmp_path / "home"
    python = project / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    home.mkdir()
    (home / ".zshrc").write_text("# existing user settings\n")
    code = "import json,sys;print(json.dumps(sys.argv[1:]))"
    python.write_text(
        "#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -c " + shlex.quote(code) + ' "$@"\n'
    )
    python.chmod(0o755)
    wrapper = install(project, home)
    install(project, home)
    assert (home / ".zshrc").read_text().startswith("# existing user settings\n")
    assert (home / ".zshrc").read_text().count("# Daedalus terminal entry") == 1
    result = subprocess.run(
        [str(wrapper), "status", "a b", "$(never-execute)"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == ["-m", "daedalus", "status", "a b", "$(never-execute)"]


def test_installer_refuses_to_replace_an_unrelated_command(tmp_path):
    project = tmp_path / "project"
    home = tmp_path / "home"
    python = project / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text("placeholder")
    destination = home / ".local/bin/daedalus"
    destination.parent.mkdir(parents=True)
    destination.write_text("unrelated command")
    with pytest.raises(RuntimeError, match="unrelated"):
        install(project, home)
    assert destination.read_text() == "unrelated command"


@pytest.mark.parametrize("mode", ["legacy", "other_workspace"])
def test_terminal_never_sends_resume_to_a_legacy_backend_or_other_workspace(
    tmp_path, monkeypatch, mode
):
    config, _, requests, read, output = console_fixture(
        tmp_path, monkeypatch, ["/resume task-1", "/detach"]
    )

    def unsafe_backend(settings, path, body=None):
        requests.append((path, body))
        if path == "/api/service":
            return {"control": {"managed": mode != "legacy"}, "reminders": []}
        if path == "/api/health":
            return {"workspace": str(tmp_path / "other-workspace")}
        pytest.fail("an unsafe backend must not receive recovery commands")

    monkeypatch.setattr(terminal, "_api", unsafe_backend)
    terminal.run_console(config_path=str(config), read=read, output=output)
    assert all(body is None for _, body in requests)
    assert ("需要新版托管后端" if mode == "legacy" else "工作区不同") in output.getvalue()
