# ruff: noqa: RUF001
"""Local, persistent service supervisor. Only signals a child it started itself."""

from __future__ import annotations

import errno
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from daedalus.application.service_lifecycle import atomic_json
from daedalus.config import load_settings
from daedalus.errors import DaedalusError


def default_config() -> Path:
    root = Path.home() / ".local" / "share" / "daedalus"
    existing = root / "ui-example" / "console.toml"
    if existing.is_file():
        return existing
    path = root / "console.toml"
    if not path.exists():
        root.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "[workspace]\nroot = "
            + json.dumps(str(root / "workspace"))
            + '\n[service]\nhost = "127.0.0.1"\nport = 13499\n'
        )
        path.chmod(0o600)
    return path


def _read(path: Path) -> dict:
    try:
        result = json.loads(path.read_text())
        return result if isinstance(result, dict) else {}
    except (OSError, ValueError):
        return {}


def _paths(settings):
    directory = settings.workspace.root_path / ".service"
    return directory, directory / "controller.json", directory / "request.json"


def _alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return int(pid) > 0
    except PermissionError:
        # EPERM proves existence, not death; avoid creating a competing instance.
        return int(pid) > 0
    except (OSError, TypeError, ValueError):
        return False


def managed_control(settings) -> dict:
    _, path, _ = _paths(settings)
    state = _read(path)
    managed = bool(
        state.get("token")
        and state.get("token") == os.environ.get("DAEDALUS_SERVICE_TOKEN")
        and state.get("backend_pid") == os.getpid()
        and _alive(state.get("supervisor_pid"))
    )
    return {
        "managed": managed,
        "status": state.get("status", "unmanaged"),
        "can_restart": managed,
        "can_stop": managed,
        "hint": "终端输入 daedalus 开启控制台；使用 /start、/stop、/restart 管理服务。",
    }


def request_control(settings, action: str, note: str = "") -> dict:
    if action not in {"stop", "restart"}:
        raise DaedalusError("只支持停止或重启服务")
    if not managed_control(settings)["managed"]:
        raise DaedalusError(
            "此进程由旧启动方式运行，尚未接入终端管理；请通过 daedalus 启动新版托管服务"
        )
    _, state_path, request_path = _paths(settings)
    state = _read(state_path)
    atomic_json(
        request_path,
        {
            "token": state["token"],
            "action": action,
            "note": note[:2000],
            "backend_pid": os.getpid(),
        },
    )
    return {
        "accepted": True,
        "action": action,
        "status": "stopping",
        "message": "正在保存当前批次的断点。新会话只提醒，任务不会自动继续。",
    }


def pending_note(settings) -> str:
    _, state_path, request_path = _paths(settings)
    state, request = _read(state_path), _read(request_path)
    if (
        managed_control(settings)["managed"]
        and request.get("token") == state.get("token")
        and request.get("backend_pid") == os.getpid()
    ):
        return str(request.get("note", ""))[:2000]
    return ""


def _health(settings, child_pid: int) -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    host = settings.service.host
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    from daedalus.service.access import owner_headers
    request = urllib.request.Request(f"http://{host}:{settings.service.port}/api/health",
                                     headers=owner_headers(settings))
    with opener.open(request, timeout=2) as response:
        payload = json.load(response)
    if payload.get("process_id") != child_pid or not payload.get("service_session_id"):
        raise DaedalusError("该端口尚未由本次启动的新版后端接管")
    return payload


def _spawn_backend(config: Path, token: str, output):
    return subprocess.Popen(
        [sys.executable, "-m", "daedalus", "serve", "--config", str(config)],
        env={**os.environ, "DAEDALUS_SERVICE_TOKEN": token},
        stdin=subprocess.DEVNULL,
        stdout=output,
        stderr=subprocess.STDOUT,
    )


def supervise(config: Path, *, ready_timeout: float = 30, lock_timeout: float = 0) -> int:
    """Hold the workspace lock until a deliberate stop or an unexpected child exit."""
    import fcntl

    settings = load_settings(config)
    directory, state_path, request_path = _paths(settings)
    directory.mkdir(parents=True, exist_ok=True)
    if lock_timeout:
        # Import/validate the replacement before its owner is asked to release the lock.
        from daedalus.service.access import AccessControl
        from daedalus.service.app import create_app  # noqa: F401 - dependency preflight only
        AccessControl(settings).validate_bind()
        standby = directory / f"standby-{os.getpid()}.json"
        atomic_json(standby, {"pid": os.getpid(), "config": str(config.resolve()),
                             "controller_version": 2, "automatic_resume": False})
    else:
        standby = None
    stop = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stop.set())
    with (
        (directory / "controller.lock").open("a") as lock,
        (directory / "service.log").open("ab", buffering=0) as output,
    ):
        deadline = time.monotonic() + lock_timeout
        while True:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if stop.is_set() or time.monotonic() >= deadline:
                    if standby:
                        standby.unlink(missing_ok=True)
                    return 1
                stop.wait(0.2)
        if standby:
            standby.unlink(missing_ok=True)
        token = secrets.token_hex(24)
        generation = 0
        while not stop.is_set():
            fresh = load_settings(config)
            if fresh.workspace.root_path != settings.workspace.root_path:
                return 1
            settings = fresh
            request_path.unlink(missing_ok=True)
            child = _spawn_backend(config, token, output)
            state = {
                "status": "starting",
                "supervisor_pid": os.getpid(),
                "backend_pid": child.pid,
                "config": str(config),
                "token": token,
                "generation": generation,
                "automatic_resume": False,
                "controller_version": 2,
            }
            atomic_json(state_path, state)
            deadline = time.monotonic() + ready_timeout
            ready = False
            while child.poll() is None and not stop.is_set() and time.monotonic() < deadline:
                try:
                    health = _health(settings, child.pid)
                    ready = True
                    state.update(status="running", session_id=health["service_session_id"])
                    atomic_json(state_path, state)
                    break
                except (OSError, ValueError, DaedalusError):
                    stop.wait(0.2)
            action = "stop"
            if ready:
                while child.poll() is None and not stop.is_set():
                    request = _read(request_path)
                    if (
                        request.get("token") == token
                        and request.get("backend_pid") == child.pid
                        and request.get("action") in {"stop", "restart"}
                    ):
                        action = request["action"]
                        break
                    stop.wait(0.2)
            state["status"] = "stopping"
            atomic_json(state_path, state)
            if child.poll() is None:
                child.terminate()
            # No forced kill: a running atomic step is allowed to settle and save its receipts.
            code = child.wait()
            session = _read(directory / "session.json")
            saved = (
                session.get("session_id") == state.get("session_id")
                and session.get("checkpoint_saved") is True
            )
            raw_code = code
            # Uvicorn can restore SIGTERM after completing its graceful shutdown.
            # Accept that signal exit only with this session's checkpoint acknowledgement.
            if code == -signal.SIGTERM and saved:
                code = 0
            state.update(
                status="stopped", exit_code=code, raw_exit_code=raw_code,
                checkpoint_saved=saved,
            )
            atomic_json(state_path, state)
            if not ready or action != "restart" or stop.is_set() or code != 0 or not saved:
                return 0 if ready and code == 0 and saved else 1
            generation += 1
    return 0


def command(action: str, config: Path, *, open_browser=False, wait_timeout=35) -> dict:
    settings = load_settings(config)
    directory, state_path, request_path = _paths(settings)
    state = _read(state_path)
    running = _alive(state.get("supervisor_pid")) and state.get("status") in {
        "starting",
        "running",
        "stopping",
    }
    if action == "status":
        return {
            "status": state.get("status", "stopped") if running else "stopped",
            "workspace": str(settings.workspace.root_path),
            "automatic_resume": False,
            "message": "托管后端：" + (state.get("status", "running") if running else "未运行"),
        }
    if action == "toggle":
        action = "stop" if running else "start"
    legacy_stopped = None
    if not running and action in {"stop", "restart"}:
        from daedalus.service.legacy import assert_restart_permission, stop_legacy

        if action == "restart":
            assert_restart_permission(settings)
        legacy_stopped = stop_legacy(settings, wait_timeout=wait_timeout)
        if legacy_stopped and action == "stop":
            return {
                "status": "stopped",
                "message": "旧服务已正常关闭，重启前的任务审计视图已留存。",
            }
    if running and action in {"stop", "restart"}:
        if state.get("status") != "running":
            raise DaedalusError("服务正在启动或保存断点，请稍候再操作")
        atomic_json(
            request_path,
            {
                "token": state["token"],
                "backend_pid": state["backend_pid"],
                "action": action,
                "note": "终端" + ("重启" if action == "restart" else "关闭"),
            },
        )
        old_pid = state["backend_pid"]
        deadline = time.monotonic() + wait_timeout
        while time.monotonic() < deadline:
            current = _read(state_path)
            if current.get("status") == "stopped" and (
                current.get("checkpoint_saved") is False or current.get("exit_code", 0) != 0
            ):
                raise DaedalusError(
                    "服务已退出，但断点保存未获确认；不会自动重开。"
                    "请检查工作区 .service/service.log"
                )
            if current.get("status") == "stopped" and action == "stop":
                return {
                    "status": "stopped",
                    "message": "已关闭。中断任务已保留，重开后仅提醒，需人工审查。",
                }
            if (
                action == "restart"
                and current.get("status") == "running"
                and current.get("backend_pid") != old_pid
            ):
                return {"status": "running", "message": "已重启，任务等待人工审查。"}
            time.sleep(0.2)
        return {
            "status": "stopping",
            "message": "正在等待当前步骤批次安全结束，请勿强制关闭；断点会自动保存。",
        }
    if running:
        result = {"status": state["status"], "message": "服务已经运行"}
    else:
        if action not in {"start", "restart"}:
            return {"status": "stopped", "message": "当前没有由此入口管理的后端实例。"}
        # Probe BEFORE touching any old process, so a restricted execution environment is safe.
        try:
            with socket.socket() as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind((settings.service.host, settings.service.port))
        except OSError as error:
            if error.errno == errno.EADDRINUSE:
                raise DaedalusError(
                    "原端口已被占用；输入 /restart 正常关闭旧后端后在同一端口重开"
                ) from error
            raise DaedalusError(
                "无法启动：监听端口被占用或当前终端无监听权限。现有服务未被停止。"
            ) from error
        directory.mkdir(parents=True, exist_ok=True)
        supervisor = subprocess.Popen(
            [sys.executable, "-m", "daedalus", "service", "supervise", "--config", str(config)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + wait_timeout
        while time.monotonic() < deadline:
            current = _read(state_path)
            if (
                current.get("supervisor_pid") == supervisor.pid
                and current.get("status") == "running"
            ):
                result = {"status": "running", "message": "已开启，启动提醒不会自动恢复任务"}
                if legacy_stopped:
                    result["message"] = (
                        "旧服务已正常关闭，新后端已在原端口开启；中断任务等待人工审查。"
                    )
                break
            if supervisor.poll() is not None:
                raise DaedalusError(
                    "后端启动失败，详情见工作区 .service/service.log；原有任务未自动运行"
                )
            time.sleep(0.2)
        else:
            raise DaedalusError("后端仍在启动，请查看工作区 .service/service.log")
    if open_browser and result["status"] == "running":
        import webbrowser

        webbrowser.open(f"http://{settings.service.host}:{settings.service.port}/")
    return result
