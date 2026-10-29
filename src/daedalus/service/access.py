# ruff: noqa: RUF001, E501
"""Single-operator LAN authentication. Owner approvals remain separate.

Passwords are salted PBKDF2 hashes. Only the session signing key is stored as a
secret in the owner's 0600 file, like the existing service-control token. No model
credential is read here. Unconfigured non-loopback listeners fail before startup.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import stat
import threading
import time
from urllib.parse import parse_qs

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from daedalus.config import ConfigError
from daedalus.infrastructure.knowledge import atomic_json

COOKIE = "daedalus_session"
ROUNDS = 600_000
TTL = 8 * 3600
LAN = tuple(
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)


def loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _allowed_peer(host):
    try:
        address = ipaddress.ip_address(host)
        return any(address in network for network in LAN)
    except ValueError:
        return False


def _record(settings):
    path = settings.workspace.root_path / ".service" / "access.json"
    if path.parent.is_symlink():
        raise ConfigError("访问凭据目录不能是符号链接")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ConfigError("访问凭据不可安全读取") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ConfigError("访问凭据必须为当前用户所有的 0600 普通文件")
        with os.fdopen(fd, "r") as source:
            fd = -1
            row = json.loads(source.read(65537))
        if (
            row.get("version") != 1
            or row.get("workspace_digest")
            != hashlib.sha256(str(settings.workspace.root_path).encode()).hexdigest()
            or row.get("rounds") != ROUNDS
            or any(
                not isinstance(row.get(k), str) or not re.fullmatch(r"[0-9a-f]{64}", row[k])
                for k in ("salt", "password_hash", "session_key")
            )
        ):
            raise ValueError("invalid credential record")
        return row
    except (ValueError, TypeError, AttributeError) as error:
        raise ConfigError("访问凭据格式无效；未降级为免登录") from error
    finally:
        if fd >= 0:
            os.close(fd)


def _sign(record, scope, lifetime):
    now = int(time.time())
    body = f"1.{now}.{now + lifetime}.{scope}.{secrets.token_hex(16)}"
    signature = hmac.new(
        bytes.fromhex(record["session_key"]), body.encode(), hashlib.sha256
    ).hexdigest()
    return body + "." + signature


def owner_headers(settings):
    """Short-lived CLI authentication; never print or persist this bearer token."""
    if not settings.service.auth_required:
        return {}
    record = _record(settings)
    if record is None:
        raise ConfigError("请先在本机访问设置中配置口令")
    return {"Authorization": "Bearer " + _sign(record, "cli", 60)}


class AccessControl:
    def __init__(self, settings):
        self.settings = settings
        self._bootstrap = secrets.token_hex(32)
        self._attempts = {}
        self._lock = threading.Lock()

    def validate_bind(self):
        configured = _record(self.settings) is not None
        if not loopback(self.settings.service.host) and not self.settings.service.auth_required:
            raise ConfigError("非本机监听必须启用 service.auth_required 并先配置访问口令")
        if self.settings.service.auth_required and not configured:
            raise ConfigError("启用登录前请先以本机监听启动，在 /auth/setup 设置访问口令")

    def configured(self):
        return _record(self.settings) is not None

    def token(self, scope="web"):
        record = _record(self.settings)
        if record is None:
            raise ConfigError("访问口令尚未配置")
        return _sign(record, scope, TTL if scope == "web" else 60)

    def valid(self, token):
        record = _record(self.settings)
        if not record or not isinstance(token, str) or len(token) > 512:
            return False
        try:
            version, issued, expires, scope, nonce, signature = token.split(".")
            issued, expires = int(issued), int(expires)
            limit = {"web": TTL, "cli": 60}[scope]
            now = int(time.time())
            if (
                version != "1"
                or not issued <= now + 5
                or not now < expires
                or not 0 < expires - issued <= limit
            ):
                return False
            if not re.fullmatch(r"[0-9a-f]{32}", nonce):
                return False
            body = token.rsplit(".", 1)[0]
            expected = hmac.new(
                bytes.fromhex(record["session_key"]), body.encode(), hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(signature, expected)
        except (ValueError, KeyError):
            return False

    def authenticated(self, request):
        header = request.headers.get("authorization", "")
        token = header[7:] if header.startswith("Bearer ") else request.cookies.get(COOKIE)
        return self.valid(token)

    @staticmethod
    def local(request):
        return bool(
            request.client
            and loopback(request.client.host)
            and loopback(request.url.hostname or "")
        )

    @staticmethod
    def same_origin(request):
        origin = request.headers.get("origin")
        return origin is None or origin == str(request.base_url).rstrip("/")

    def save_password(self, password):
        if not isinstance(password, str) or not 12 <= len(password) <= 256 or password.isspace():
            raise ValueError("访问口令需要 12–256 个字符")
        salt = secrets.token_hex(32)
        row = {
            "version": 1,
            "workspace_digest": hashlib.sha256(
                str(self.settings.workspace.root_path).encode()
            ).hexdigest(),
            "rounds": ROUNDS,
            "salt": salt,
            "password_hash": hashlib.pbkdf2_hmac(
                "sha256", password.encode(), bytes.fromhex(salt), ROUNDS
            ).hex(),
            "session_key": secrets.token_hex(32),
        }
        path = self.settings.workspace.root_path / ".service" / "access.json"
        if path.parent.is_symlink() or path.is_symlink():
            raise ConfigError("访问凭据路径不能是符号链接")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_json(path, row)

    def check_password(self, password, peer):
        now = time.monotonic()
        with self._lock:
            entries = [t for t in self._attempts.get(peer, []) if now - t < 300]
            if len(entries) >= 5:
                return "limited"
            if len(self._attempts) >= 1024 and peer not in self._attempts:
                self._attempts = {
                    k: v for k, v in self._attempts.items() if v and now - v[-1] < 300
                }
                if len(self._attempts) >= 1024:
                    return "limited"
            entries.append(now)
            self._attempts[peer] = entries
        record = _record(self.settings)
        valid = False
        if record and isinstance(password, str) and len(password) <= 256:
            derived = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), bytes.fromhex(record["salt"]), ROUNDS
            ).hex()
            valid = hmac.compare_digest(derived, record["password_hash"])
        if valid:
            with self._lock:
                self._attempts.pop(peer, None)
        return "ok" if valid else "invalid"


def _page(title, body, status=200):
    return HTMLResponse(
        '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        f"<title>Daedalus · {html.escape(title)}</title><style>"
        "body{font:16px/1.7 system-ui;max-width:620px;margin:8vh auto;padding:24px;color:#dfe8f1;background:#10141d}"
        "input,button{box-sizing:border-box;display:block;width:100%;padding:12px;margin:12px 0;border-radius:8px}"
        "a{color:#9bdad6}code{overflow-wrap:anywhere}</style>"
        f"<h1>{html.escape(title)}</h1>{body}</html>",
        status_code=status,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'",
        },
    )


def install_access(app, settings):
    guard = AccessControl(settings)
    guard.validate_bind()
    app.state.access = guard

    @app.middleware("http")
    async def authenticate(request, call_next):
        if settings.service.auth_required:
            if not request.client or not _allowed_peer(request.client.host):
                return JSONResponse({"detail": "当前仅允许本机和私有局域网访问"}, status_code=403)
            public = request.url.path in {
                "/healthz",
                "/auth/login",
                "/auth/setup",
            } or request.url.path.startswith("/static/")
            if not public and not guard.authenticated(request):
                if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
                    return RedirectResponse("/auth/login", status_code=303)
                return JSONResponse({"detail": "authentication_required"}, status_code=401)
            if request.method not in {"GET", "HEAD", "OPTIONS"} and not guard.same_origin(request):
                return JSONResponse({"detail": "拒绝跨站操作"}, status_code=403)
        response = await call_next(request)
        if settings.service.auth_required and not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/api/access")
    def access_status():
        return {
            "enabled": settings.service.auth_required,
            "configured": guard.configured(),
            "host": settings.service.host,
            "scope": "single-operator LAN",
            "automatic_resume": False,
        }

    def csrf():
        body = str(int(time.time()) // 600)
        return (
            body
            + "."
            + hmac.new(guard._bootstrap.encode(), body.encode(), hashlib.sha256).hexdigest()
        )

    async def form(request):
        try:
            length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return None
        if length < 0 or length > 4096:
            return None
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 4096:
                return None
        try:
            data = parse_qs(body.decode(), strict_parsing=True)
        except (ValueError, UnicodeError):
            return None
        return {k: v[0] for k, v in data.items() if len(v) == 1}

    @app.get("/auth/setup")
    def setup(request: Request):
        if not guard.local(request):
            return _page("仅限本机配置", "请在运行 Daedalus 的电脑上打开此页面。", 403)
        if guard.configured() and not guard.authenticated(request):
            return RedirectResponse("/auth/login", status_code=303)
        from daedalus.service.autostart import status

        startup = (
            status(settings.source_path)
            if settings.source_path
            else {"installed": False, "loaded": False}
        )
        access_note = "已启用登录" if settings.service.auth_required else "当前仅本机免登录"
        operations = (
            f"<hr><h2>运行方式</h2><p>{access_note} · 监听 {html.escape(settings.service.host)} · "
            f"登录自启：{'已安装' if startup['installed'] else '未安装'}</p>"
            f'<form method="post" action="/auth/autostart"><input type="hidden" name="csrf" value="{csrf()}">'
            "<button>启用登录自启与故障拉起</button></form>"
            f'<form method="post" action="/auth/check-autostart"><input type="hidden" name="csrf" value="{csrf()}">'
            "<p>使用空白临时工作区验证故障拉起与正常关闭，不调用模型。</p>"
            "<button>验证后台故障恢复</button></form>"
        )
        if guard.configured():
            operations += (
                f'<form method="post" action="/auth/enable"><input type="hidden" name="csrf" value="{csrf()}">'
                '<label>访问范围<select name="scope"><option value="local">本机登录保护</option><option value="lan">私有局域网访问</option></select></label>'
                "<button>应用访问设置并安全重启</button></form>"
            )
        return _page(
            "访问设置",
            "<p>设置独立的网页访问口令；模型密钥继续使用系统钥匙串。配置不会启动或恢复任务。</p>"
            f'<form method="post"><input type="hidden" name="csrf" value="{csrf()}">'
            '<label>新口令（至少 12 字符）<input name="password" type="password" minlength="12" maxlength="256" autocomplete="new-password" required></label>'
            '<label>再次输入<input name="confirm" type="password" minlength="12" maxlength="256" autocomplete="new-password" required></label>'
            "<button>安全保存访问口令</button></form>" + operations + '<a href="/">返回工作台</a>',
        )

    @app.post("/auth/setup")
    async def save(request: Request):
        if not guard.local(request) or not guard.same_origin(request):
            return _page("配置被拒绝", "需要来自本机工作台的操作。", 403)
        if guard.configured() and not guard.authenticated(request):
            return _page("需要登录", '<a href="/auth/login">先登录再修改口令</a>', 401)
        data = await form(request)
        if not data or not hmac.compare_digest(data.get("csrf", ""), csrf()):
            return _page("页面已过期", '<a href="/auth/setup">重新打开访问设置</a>', 403)
        if data.get("password") != data.get("confirm"):
            return _page("未保存", '<p>两次输入不一致。</p><a href="/auth/setup">重新填写</a>', 422)
        try:
            await run_in_threadpool(guard.save_password, data.get("password"))
        except ValueError:
            return _page(
                "未保存", '<p>口令长度需为 12–256 字符。</p><a href="/auth/setup">重新填写</a>', 422
            )
        response = _page(
            "口令已安全保存",
            '<p>已保存加盐口令摘要。模型连接与任务保持原状态。</p><a href="/auth/setup">继续设置访问范围和登录自启</a>',
        )
        response.set_cookie(
            COOKIE,
            guard.token(),
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            max_age=TTL,
        )
        return response

    @app.get("/auth/login")
    def login():
        return _page(
            "登录 Daedalus",
            '<p>使用网页访问口令登录。登录不会继续中断任务。</p><form method="post">'
            '<label>访问口令<input type="password" name="password" autocomplete="current-password" maxlength="256" required></label>'
            "<button>登录</button></form>",
        )

    @app.post("/auth/login")
    async def check_login(request: Request):
        if not guard.same_origin(request):
            return _page("登录被拒绝", "请求来源不匹配。", 403)
        data = await form(request)
        result = await run_in_threadpool(
            guard.check_password,
            (data or {}).get("password"),
            request.client.host if request.client else "unknown",
        )
        if result != "ok":
            return _page(
                "暂时无法登录",
                '<p>口令不正确或尝试过于频繁，请稍后再试。</p><a href="/auth/login">返回登录</a>',
                429 if result == "limited" else 401,
            )
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            COOKIE,
            guard.token(),
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            max_age=TTL,
        )
        return response

    @app.post("/auth/logout")
    def logout(request: Request):
        if not guard.same_origin(request):
            return JSONResponse({"detail": "拒绝跨站操作"}, status_code=403)
        response = RedirectResponse("/auth/login", status_code=303)
        response.delete_cookie(COOKIE, httponly=True, samesite="strict")
        return response

    async def authorised_operation(request):
        if not guard.local(request) or not guard.same_origin(request):
            return None
        if guard.configured() and not guard.authenticated(request):
            return None
        data = await form(request)
        if not data or not hmac.compare_digest(data.get("csrf", ""), csrf()):
            return None
        return data

    def wait_page():
        session = app.state.daedalus.lifecycle.session_id
        return _page(
            "正在安全切换服务",
            '<p id="handoff-status">等待新服务就绪；旧任务仅保留提醒。</p>'
            f'<div id="handoff" data-session="{html.escape(session)}"></div>'
            '<a href="/auth/setup">返回访问设置</a><script src="/static/access-handoff.js"></script>',
        )

    @app.post("/auth/autostart")
    async def enable_autostart(request: Request):
        data = await authorised_operation(request)
        if data is None:
            return _page("操作被拒绝", "需要本机页面的有效操作。", 403)
        state = app.state.daedalus
        if state.dispatcher.busy_runs():
            return _page("正在执行任务", "请等待当前运行结束后再切换托管方式。", 409)
        from daedalus.service.autostart import handoff

        report = await run_in_threadpool(handoff, settings, autostart=True)
        if report.get("already_active"):
            return _page(
                "后台托管已启用",
                '<p>当前服务已由登录启动项托管。</p><a href="/auth/setup">返回访问设置</a>',
            )
        state.lifecycle.stopping("启用登录自启与故障拉起；旧任务不自动继续")
        state.dispatcher.request_stop()
        return wait_page()

    @app.post("/auth/check-autostart")
    async def check_autostart(request: Request):
        if await authorised_operation(request) is None:
            return _page("操作被拒绝", "需要本机页面的有效操作。", 403)
        state = app.state.daedalus
        if state.dispatcher.busy_runs():
            return _page("正在执行任务", "请等待当前运行结束后再验证后台托管。", 409)
        from daedalus.service.autostart_probe import run_probe

        report = await run_in_threadpool(run_probe, settings)
        return _page(
            "后台故障恢复验证",
            "<pre>"
            + html.escape(json.dumps(report, ensure_ascii=False, indent=2))
            + '</pre><a href="/auth/setup">返回访问设置</a>',
        )

    @app.post("/auth/enable")
    async def enable_login(request: Request):
        data = await authorised_operation(request)
        if data is None or not guard.configured() or not guard.authenticated(request):
            return _page("操作被拒绝", "请先在本机配置并验证访问口令。", 403)
        if data.get("scope") not in {"local", "lan"}:
            return _page("范围无效", "请选择本机或私有局域网。", 422)
        state = app.state.daedalus
        if state.dispatcher.busy_runs():
            return _page("正在执行任务", "请等待当前运行结束后再改变访问设置。", 409)
        from daedalus.service.access_config import access_change
        from daedalus.service.autostart import handoff
        from daedalus.service.control import _paths, _read, managed_control, request_control

        if not managed_control(settings)["managed"]:
            return _page("需要托管服务", "请先通过 daedalus 入口启动。", 409)

        def switch():
            with access_change(settings, lan=data["scope"] == "lan"):
                _, controller, _ = _paths(settings)
                if _read(controller).get("controller_version", 0) >= 2:
                    request_control(settings, "restart", "启用网页访问保护；旧任务保持人工审查")
                else:
                    handoff(settings)

        await run_in_threadpool(switch)
        state.lifecycle.stopping("更新访问设置；旧任务保持人工审查")
        state.dispatcher.request_stop()
        return wait_page()

    return guard
