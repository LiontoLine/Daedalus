# ruff: noqa: RUF001
"""The single `daedalus` terminal entry; startup reminders never resume work."""

from __future__ import annotations

import json
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from daedalus.config import load_settings
from daedalus.errors import DaedalusError
from daedalus.service.control import command, default_config

HELP = """/start       开启后端       /stop        保存断点并关闭后端
/restart     保存断点并重启 /status      查看服务状态
/reminders   查看启动提醒   /tasks       查看任务
/review ID   人工审查断点   /resume ID   明确继续已审查的任务
/open        打开网页       /detach      保留后端，退出终端
/quit 或 Ctrl+C             保存断点，关闭后端并退出"""


def _api(settings, path: str, body=None):
    from daedalus.service.access import owner_headers
    host = settings.service.host
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    if ":" in host:
        host = "[" + host + "]"
    request = urllib.request.Request(
        f"http://{host}:{settings.service.port}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **owner_headers(settings)},
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            request, timeout=10
        ) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read(20000))
            detail = payload.get("detail", payload.get("error", {}))
            message = detail if isinstance(detail, str) else detail.get("message", "请求被拒绝")
        except (ValueError, AttributeError):
            message = "请求被拒绝"
        raise DaedalusError(f"HTTP {error.code}：{message}") from None
    except (OSError, ValueError):
        raise DaedalusError("无法连接后端；使用 /start 开启，或 /status 查看状态") from None


def _reminders(settings, output):
    report = _api(settings, "/api/service")
    previous = report.get("previous_session", {})
    if previous.get("note"):
        print("上次备注：" + str(previous["note"]), file=output)
    reminders = report.get("reminders", [])
    for item in reminders:
        print(
            f"  {item['run_id']} · 待人工审查 · 已验证 {len(item['verified_nodes'])} 个节点，"
            f"待续 {len(item['frontier'])} 个节点",
            file=output,
        )
    print("中断任务未自动执行。" if reminders else "没有待恢复的中断任务。", file=output)


def _require_managed_backend(settings):
    report = _api(settings, "/api/service")
    if not report.get("control", {}).get("managed"):
        raise DaedalusError("恢复操作需要新版托管后端；当前旧服务只可查看，不会发送继续任务请求")
    health = _api(settings, "/api/health")
    if Path(health.get("workspace", "")).resolve() != settings.workspace.root_path.resolve():
        raise DaedalusError("后端与终端的工作区不同，拒绝恢复任务")


def _review(settings, run_id, read, output):
    from daedalus.application.identity import OwnerRegistry
    from daedalus.infrastructure.store import EventStore

    _require_managed_backend(settings)
    encoded = urllib.parse.quote(run_id, safe="")
    view = _api(settings, f"/api/runs/{encoded}/recovery")
    print("最近已验证节点：" + (view["last_verified_node"] or "无"), file=output)
    print("保留的集成提交：" + (view["integration_head"] or "不可用"), file=output)
    for node in view["frontier"]:
        print(f"  待续 {node['node_id']}：{node['objective']}", file=output)
    if view.get("busy") or view["blockers"]:
        raise DaedalusError("；".join(view["blockers"]) or "任务仍在执行或排队，请等待停止")
    reviewer = read("审查者：").strip()
    note = read("审查备注：").strip()
    if read("已核对上述节点？输入 y 仅保存审查，任务不启动：[y/N] ").strip().lower() != "y":
        print("未保存审查，任务保持暂停。", file=output)
        return
    signature = ""
    owners = _api(settings, "/api/owners")
    if owners.get("enforced"):
        # The human explicitly reviewed this checkpoint. Use an enrolled local identity;
        # send only its bound signature, never its credential, to the server.
        health = _api(settings, "/api/health")
        if Path(health["workspace"]).resolve() != settings.workspace.root_path.resolve():
            raise DaedalusError("后端与终端的工作区不同，拒绝签署恢复审查")
        with EventStore(settings.workspace.database_path) as store:
            signature = OwnerRegistry.for_store(store).sign(
                reviewer, view["review_statement_digest"]
            )
    _api(
        settings,
        f"/api/runs/{encoded}/recovery-review",
        {
            "reviewed_by": reviewer,
            "checkpoint_digest": view["checkpoint_digest"],
            "note": note,
            "signature": signature,
        },
    )
    print(f"审查已保存，任务没有执行。明确继续请运行 /resume {run_id}", file=output)


def run_console(*, config_path="", open_browser=False, restart=False, read=None, output=None) -> int:
    output = output or sys.stdout
    read = read or input
    config = Path(config_path).expanduser().resolve() if config_path else default_config()
    settings = load_settings(config)
    print("Daedalus · 工程交付控制台", file=output)
    print("工作区：" + str(settings.workspace.root_path), file=output)
    print("启动只显示提醒；中断任务需人工审查后明确继续。", file=output)
    try:
        result = command("restart" if restart else "start", config, open_browser=open_browser)
        print(result["message"], file=output)
        _reminders(settings, output)
    except DaedalusError as error:
        print("提示：" + error.message, file=output)
    print(HELP, file=output)
    while True:
        try:
            line = read("daedalus> ")
            words = shlex.split(line.strip().removeprefix("/"))
            if not words:
                continue
            action, *arguments = words
            if action in {"quit", "exit"}:
                result = command("stop", config)
                print(result["message"], file=output)
                return 0
            if action == "detach":
                print("已退出控制台，后端保持原状态。", file=output)
                return 0
            if action in {"start", "stop", "restart", "status", "open"}:
                result = command(
                    "start" if action == "open" else action, config, open_browser=action == "open"
                )
                print(result.get("message", result["status"]), file=output)
                if action in {"start", "restart"} and result["status"] == "running":
                    _reminders(settings, output)
            elif action in {"help", "?"}:
                print(HELP, file=output)
            elif action == "reminders":
                _reminders(settings, output)
            elif action == "tasks":
                for run in _api(settings, "/api/runs").get("runs", []):
                    print(f"  {run['run_id']} · {run['status']}", file=output)
            elif action in {"review", "resume"}:
                if len(arguments) != 1:
                    raise DaedalusError(f"用法：/{action} 任务ID")
                if action == "review":
                    _review(settings, arguments[0], read, output)
                else:
                    _require_managed_backend(settings)
                    run_id = urllib.parse.quote(arguments[0], safe="")
                    _api(settings, f"/api/runs/{run_id}/resume", {})
                    print("已明确请求继续；原有审查、门禁与预算仍生效。", file=output)
            else:
                print("输入 /help 查看可用操作。", file=output)
        except (EOFError, KeyboardInterrupt):
            print("\n正在保存断点并关闭后端…", file=output)
            try:
                print(command("stop", config)["message"], file=output)
                return 0
            except DaedalusError as error:
                print(error.message, file=output)
                return 1
        except (DaedalusError, ValueError) as error:
            print("提示：" + str(error), file=output)
