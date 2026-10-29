# ruff: noqa: RUF001
"""Explicit same-port shutdown of a verified older Daedalus instance."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from daedalus.application.service_lifecycle import atomic_json
from daedalus.domain.ids import new_id, utc_now
from daedalus.errors import DaedalusError


def _process_read(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        raise DaedalusError("无法读取本机进程状态，不能确认服务关闭或重启完成") from None


def listening_pid(port: int) -> int | None:
    result = _process_read(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fp"])
    pids = {
        int(line[1:])
        for line in result.stdout.splitlines()
        if line.startswith("p") and line[1:].isdigit()
    }
    if len(pids) > 1:
        raise DaedalusError("此端口有多个监听进程，无法确认旧后端，未停止任何进程")
    return next(iter(pids)) if pids else None


def process_identity(pid: int) -> str:
    result = _process_read(["ps", "-p", str(pid), "-o", "uid=,lstart=,comm="])
    parts = result.stdout.strip().split(maxsplit=1)
    if result.returncode or len(parts) != 2 or parts[0] != str(os.getuid()):
        raise DaedalusError("无法确认旧后端的进程身份，未停止任何进程")
    return result.stdout.strip()


def running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    status = _process_read(["ps", "-p", str(pid), "-o", "stat="])
    return bool(status.stdout.strip()) and not status.stdout.strip().startswith("Z")


def http_json(settings, path: str, *, post=False):
    host = settings.service.host
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    if ":" in host:
        host = "[" + host + "]"
    request = urllib.request.Request(
        f"http://{host}:{settings.service.port}{path}", method="POST" if post else "GET"
    )
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            request, timeout=10
        ) as response:
            raw = response.read(32 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        raise DaedalusError(f"读取旧服务接口失败：HTTP {error.code}，未完成服务重启") from None
    except OSError:
        raise DaedalusError("无法读取旧服务接口，未完成服务重启") from None
    if len(raw) > 32 * 1024 * 1024:
        raise DaedalusError("旧服务的审计视图超过大小限制，未执行停止")
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("not an object")
        return payload
    except ValueError:
        raise DaedalusError("旧服务返回了无法识别的数据，未完成重启") from None


def assert_restart_permission(settings):
    """Never stop an old server from a context that cannot start its replacement."""
    family = socket.AF_INET6 if ":" in settings.service.host else socket.AF_INET
    try:
        with socket.socket(family) as probe:
            probe.bind((settings.service.host, 0))
    except OSError:
        raise DaedalusError(
            "当前执行环境没有本地监听权限，不能执行关闭后重开；现有服务未被停止"
        ) from None


def stop_legacy(settings, *, wait_timeout=35) -> dict | None:
    directory = settings.workspace.root_path / ".service"
    pending_path = directory / "legacy-pending.json"
    try:
        pending = json.loads(pending_path.read_text())
    except (OSError, ValueError):
        pending = None
    if isinstance(pending, dict) and pending.get("port") == settings.service.port:
        return _finish_stop(settings, pending, wait_timeout=wait_timeout)
    pid = listening_pid(settings.service.port)
    if pid is None:
        return None
    if pid in {os.getpid(), os.getppid()} or pid <= 1:
        raise DaedalusError("端口进程身份异常，未停止任何进程")
    identity = process_identity(pid)
    try:
        health = http_json(settings, "/api/health")
        schema = http_json(settings, "/openapi.json")
    except (OSError, ValueError, DaedalusError):
        raise DaedalusError("无法识别端口上的旧服务，未停止任何进程") from None
    if (
        health.get("status") != "ok"
        or not isinstance(health.get("dispatcher"), dict)
        or not isinstance(health.get("workspace"), str)
        or not health["workspace"]
        or schema.get("info", {}).get("title") != "Daedalus"
        or (health.get("process_id") and health["process_id"] != pid)
    ):
        raise DaedalusError("端口由其他程序占用，不能当作 Daedalus 关闭")
    # Preserve what the old API can still read before its process releases open DB handles.
    # This view is NOT called a database backup and never authorises an automatic resume.
    records = {"health": health, "runs": http_json(settings, "/api/runs"), "details": {}}
    for row in records["runs"].get("runs", []):
        run_id = str(row["run_id"])
        prefix = "/api/runs/" + urllib.parse.quote(run_id, safe="")
        records["details"][run_id] = {
            name: http_json(settings, prefix + suffix)
            for name, suffix in (("run", ""), ("specs", "/specs"), ("audit", "/audit"))
        }
    backup = None
    try:
        result = http_json(settings, "/api/backup?label=before-terminal-restart", post=True)
        if result.get("verified") is True:
            backup = result
    except (OSError, ValueError, DaedalusError):
        pass  # A missing /tmp database is represented explicitly in the saved view.
    snapshot_id = new_id("legacy")
    snapshot = directory / "legacy" / (snapshot_id + ".json")
    atomic_json(
        snapshot,
        {
            "recorded_at": utc_now(),
            "old_pid": pid,
            "port": settings.service.port,
            "database_backup": backup,
            "is_database_backup": False,
            "automatic_resume": False,
            "records": records,
        },
    )
    if listening_pid(settings.service.port) != pid or process_identity(pid) != identity:
        raise DaedalusError("旧服务进程已发生变化，请重新执行重启；未向其他进程发送信号")
    pending = {
        "pid": pid,
        "identity": identity,
        "health": health,
        "backup": backup,
        "snapshot_id": snapshot_id,
        "snapshot": str(snapshot),
        "port": settings.service.port,
    }
    atomic_json(pending_path, pending)
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pending_path.unlink(missing_ok=True)
        raise DaedalusError("当前终端无权关闭旧进程，旧服务未被停止") from None
    return _finish_stop(settings, pending, wait_timeout=wait_timeout)


def _finish_stop(settings, pending: dict, *, wait_timeout):
    pid, identity = pending["pid"], pending["identity"]
    directory = settings.workspace.root_path / ".service"
    deadline = time.monotonic() + wait_timeout
    while running(pid):
        if process_identity(pid) != identity:
            break  # The original process is gone; a reused PID must never be signalled.
        if time.monotonic() >= deadline:
            raise DaedalusError(
                "旧服务正在正常关闭并保存任务，请稍候再执行 /restart；不会强制结束或更换端口"
            )
        time.sleep(0.2)
    note = "旧服务已正常关闭；启动只提醒，中断任务需人工审查。"
    if pending["backup"] is None:
        note += (
            "旧数据库无法生成完整备份，已留存可读任务和审计视图供核对，"
            "不能将其当作可自动恢复的数据库。"
        )
    if Path(pending["health"]["workspace"]).resolve() != settings.workspace.root_path.resolve():
        note += "旧实例与当前持久工作区不同，历史数据库未自动迁移。"
    atomic_json(
        directory / "session.json",
        {
            "session_id": pending["snapshot_id"],
            "status": "stopped",
            "stopped_at": utc_now(),
            "note": note,
            "legacy_snapshot": pending["snapshot"],
            "checkpoint_saved": pending["backup"] is not None,
            "automatic_resume": False,
        },
    )
    (directory / "legacy-pending.json").unlink(missing_ok=True)
    return {
        "old_pid": pid,
        "snapshot": pending["snapshot"],
        "database_backup_verified": pending["backup"] is not None,
    }
