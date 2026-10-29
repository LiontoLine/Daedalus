# ruff: noqa: RUF001
"""User LaunchAgent registration and graceful supervisor handoff on macOS."""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import subprocess
import sys
import time
from pathlib import Path

from daedalus.errors import DaedalusError


def label_for(config):
    digest = hashlib.sha256(str(Path(config).resolve()).encode()).hexdigest()[:12]
    return "com.daedalus.service." + digest


def plist_for(config):
    return Path.home() / "Library/LaunchAgents" / (label_for(config) + ".plist")


def command(*args):
    result = subprocess.run(["/bin/launchctl", *args], capture_output=True, text=True, timeout=15)
    if result.returncode:
        # Keep diagnostic text bounded; never return an entire launchctl environment dump.
        from daedalus.infrastructure.redact import redact_text

        raise DaedalusError(
            "launchctl 操作失败: " + redact_text(result.stderr)[:700], exit_code=result.returncode
        )
    return result.stdout


def specification(config, workspace):
    workspace = Path(workspace).resolve()
    return {
        "Label": label_for(config),
        "ProgramArguments": [
            sys.executable,
            "-m",
            "daedalus",
            "service",
            "supervise",
            "--config",
            str(Path(config).resolve()),
            "--wait-lock",
            "120",
        ],
        # Workspace roots historically resolve against the launch directory. Preserve it.
        "WorkingDirectory": str(Path.cwd()),
        "EnvironmentVariables": {
            "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
            "DAEDALUS_LAUNCHD": "1",
        },
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 30,
        "ExitTimeOut": 600,
        "StandardOutPath": str(workspace / ".service/launchd.log"),
        "StandardErrorPath": str(workspace / ".service/launchd.log"),
    }


def status(config):
    path = plist_for(config)
    loaded = False
    running = False
    pid = None
    if sys.platform == "darwin":
        try:
            report = command("print", f"gui/{os.getuid()}/{label_for(config)}")
            loaded = True
            running = bool(re.search(r"(?m)^\s*state = running\s*$", report))
            match = re.search(r"(?m)^\s*pid = (\d+)\s*$", report)
            pid = int(match[1]) if match and running else None
        except (DaedalusError, OSError, subprocess.TimeoutExpired):
            pass
    return {
        "supported": sys.platform == "darwin",
        "installed": path.is_file(),
        "loaded": loaded,
        "running": running,
        "pid": pid,
        "managed_by_launchd": os.environ.get("DAEDALUS_LAUNCHD") == "1",
        "label": label_for(config),
        "automatic_resume": False,
    }


def install(config, workspace):
    if sys.platform != "darwin":
        raise DaedalusError("当前入口使用 macOS 用户 LaunchAgent")
    path = plist_for(config)
    if path.is_symlink():
        raise DaedalusError("启动项路径不能是符号链接")
    if path.exists():
        with path.open("rb") as source:
            previous = plistlib.load(source)
        if previous.get("Label") != label_for(config):
            raise DaedalusError("同名启动项不属于此工作区，未覆盖")
    path.parent.mkdir(parents=True, exist_ok=True)
    (workspace / ".service").mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".plist.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            plistlib.dump(specification(config, workspace), output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    if not status(config)["loaded"]:
        command("bootstrap", f"gui/{os.getuid()}", str(path))
    return status(config)


def handoff(settings, *, autostart=False):
    """Start a replacement waiting on the same lock before stopping the old owner."""
    from daedalus.service.control import managed_control, request_control

    if not settings.source_path:
        raise DaedalusError("需要持久配置文件才能托管启动")
    if not managed_control(settings)["managed"]:
        raise DaedalusError("当前后端未托管；请先通过 daedalus 启动")
    if autostart:
        report = install(settings.source_path, settings.workspace.root_path)
        if os.environ.get("DAEDALUS_LAUNCHD") == "1":
            return {**report, "already_active": True}
        if not report["running"]:
            command("kickstart", f"gui/{os.getuid()}/{label_for(settings.source_path)}")
    else:
        child = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "daedalus",
                "service",
                "supervise",
                "--config",
                settings.source_path,
                "--wait-lock",
                "120",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        report = {"installed": False, "automatic_resume": False}
    # A scheduled launchd job is not proof that Python can import the application.
    # Wait for a fresh replacement to validate imports/config and reach the workspace lock.
    deadline = time.monotonic() + 12
    ready = False
    from daedalus.service.control import _alive, _read

    while time.monotonic() < deadline:
        pid = status(settings.source_path).get("pid") if autostart else child.pid
        if pid and _alive(pid):
            record = _read(settings.workspace.root_path / f".service/standby-{pid}.json")
            if (
                record.get("pid") == pid
                and record.get("config") == str(Path(settings.source_path).resolve())
                and record.get("controller_version") == 2
            ):
                ready = True
                break
        time.sleep(0.2)
    if not ready:
        if not autostart and child.poll() is None:
            child.terminate()
        raise DaedalusError("替代监督进程未通过启动预检，现有服务保持运行")
    request_control(settings, "stop", "切换后台托管；仅重启服务，旧任务保持人工审查")
    return report
