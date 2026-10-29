#!/usr/bin/env python3
"""Smoke-test the installed console over ASGI, without sockets or test dependencies."""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import daedalus
from daedalus.config import load_settings
from daedalus.service.app import create_app

PATHS = (
    "/api/health",
    "/",
    "/runs",
    "/planning",
    "/execution",
    "/audit",
    "/static/console.css",
    "/static/console.js",
    "/static/model-providers.json",
    "/api/model",
    "/api/model/catalog",
    "/api/model/template",
    "/api/model/export",
    "/api/service",
    "/static/vendor/diff2html.min.js",
    "/static/vendor/diff2html.min.css",
    "/static/vendor/inter-latin.woff2",
)


async def verify(expected_root: Path | None = None) -> dict:
    package = Path(daedalus.__file__).resolve()
    if expected_root and not package.is_relative_to(expected_root.resolve()):
        raise AssertionError(
            f"imported {package} instead of the installed artifact under {expected_root}"
        )
    results = {}
    from daedalus.cli import main

    with patch("daedalus.service.terminal.run_console", return_value=0) as terminal_entry:
        if main([]) != 0 or terminal_entry.call_count != 1:
            raise AssertionError("installed daedalus command does not enter the terminal console")
    with tempfile.TemporaryDirectory(prefix="daedalus-installed-smoke-") as directory:
        app = create_app(load_settings(None, workspace_root=directory))
        async with app.router.lifespan_context(app):
            for path in PATHS:
                messages = []

                async def receive():
                    return {"type": "http.request", "body": b"", "more_body": False}

                async def send(message, messages=messages):
                    messages.append(message)

                await app(
                    {
                        "type": "http",
                        "asgi": {"version": "3.0", "spec_version": "2.4"},
                        "http_version": "1.1",
                        "method": "GET",
                        "scheme": "http",
                        "path": path,
                        "raw_path": path.encode(),
                        "query_string": b"",
                        "root_path": "",
                        "headers": [],
                        "server": ("localhost", 80),
                        "client": ("127.0.0.1", 1),
                    },
                    receive,
                    send,
                )
                status = next(m["status"] for m in messages if m["type"] == "http.response.start")
                body = b"".join(
                    m.get("body", b"") for m in messages if m["type"] == "http.response.body"
                )
                if status != 200 or not body:
                    raise AssertionError(
                        f"installed route {path}: status={status}, bytes={len(body)}"
                    )
                results[path] = {"status": status, "bytes": len(body)}
    return {
        "package": str(package),
        "transport": "in-process ASGI; no listening socket",
        "terminal_entry": "bare daedalus command dispatch verified without launching a listener",
        "routes": results,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-root", type=Path)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(verify(args.expected_root)), ensure_ascii=False, indent=2))
