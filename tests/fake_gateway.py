"""A local OpenAI-compatible gateway, for proving the model plane without a credential.

The model plane is the system's central claim — "uncertain capability confined by a
deterministic control plane" — and until this existed it had never been executed by a test.
This is a real HTTP server speaking the real wire protocol, so the production client's
request shaping, error handling, token accounting and redaction are all exercised for real.
Only the intelligence behind it is scripted.

It is deliberately a *real* server on a loopback port rather than a mocked client method:
mocking `client.complete` would test the mock, not the transport.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

Responder = Callable[[dict[str, Any]], "Reply"]


@dataclass
class Reply:
    """One canned answer, plus the HTTP status to serve it with."""

    content: str = ""
    status: int = 200
    error_body: dict[str, Any] | None = None
    prompt_tokens: int = 11
    completion_tokens: int = 7
    model: str = "fake-gpt"

    def body(self) -> dict[str, Any]:
        if self.error_body is not None:
            return self.error_body
        return {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "model": self.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": self.content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.prompt_tokens + self.completion_tokens,
            },
        }


@dataclass
class FakeGateway:
    """A loopback `/chat/completions` endpoint with a scripted reply queue."""

    replies: list[Reply] = field(default_factory=list)
    responder: Responder | None = None
    default_reply: Reply = field(default_factory=lambda: Reply(content="{}"))
    require_auth: str = ""
    #: Port to bind. 0 means "let the OS pick", which is right for tests; a fixed port is
    #: needed when the gateway address has to be written into a config file first.
    port: int = 0
    _server: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    requests: list[dict[str, Any]] = field(default_factory=list, init=False)
    headers: list[dict[str, str]] = field(default_factory=list, init=False)

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> "FakeGateway":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def start(self) -> "FakeGateway":
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:  # noqa: ANN002 - silence the default
                return

            def do_POST(self) -> None:  # noqa: N802 - the name is fixed by the base class
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(length).decode("utf-8") if length else "{}"
                try:
                    payload = json.loads(raw)
                except ValueError:
                    payload = {"__unparsable": raw}

                gateway.requests.append(payload)
                gateway.headers.append({k: v for k, v in self.headers.items()})

                if gateway.require_auth:
                    authorization = self.headers.get("Authorization", "")
                    if authorization != f"Bearer {gateway.require_auth}":
                        self._send(
                            401,
                            {
                                "error": {
                                    "message": "missing or invalid api key",
                                    "type": "invalid_request_error",
                                }
                            },
                        )
                        return

                if self.path.rstrip("/") != "/v1/chat/completions":
                    self._send(404, {"error": {"message": f"unknown path {self.path}"}})
                    return

                reply = gateway._next_reply(payload)
                self._send(reply.status, reply.body())

            def _send(self, status: int, body: dict[str, Any]) -> None:
                encoded = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # ------------------------------------------------------------------- access
    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("the fake gateway is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/v1"

    @property
    def request_count(self) -> int:
        return len(self.requests)

    def last_prompt(self) -> str:
        """The concatenated user+system content of the most recent request."""
        if not self.requests:
            return ""
        messages = self.requests[-1].get("messages") or []
        return "\n".join(str(m.get("content", "")) for m in messages)

    def _next_reply(self, payload: dict[str, Any]) -> Reply:
        if self.responder is not None:
            return self.responder(payload)
        if self.replies:
            return self.replies.pop(0)
        return self.default_reply


def planner_reply(*, node_ids: list[str], tree: str, goal_id: str = "GOAL-FAKE") -> Reply:
    """A well-formed Tri-Spec candidate, as a competent planner would return it."""
    return Reply(
        content=json.dumps(
            {
                "spec_01_goal": {
                    "goal_id": goal_id,
                    "objective": "fix the word counter",
                    "invariants": ["no change outside the declared paths"],
                    "acceptance_criteria": [
                        {
                            "criterion_id": "AC-1",
                            "kind": "exit_code",
                            "statement": "the tests pass",
                            "command": "python3 -m pytest tests -q",
                        }
                    ],
                    "risk_level": "normal",
                },
                "spec_02_plan": {
                    "plan_id": f"PLAN-{goal_id}",
                    "goal_id": goal_id,
                    "nodes": [
                        {
                            "node_id": node_ids[0],
                            "objective": "fix the counter",
                            "deps": [],
                            "expected_artifacts": [tree],
                            "allowed_tools": ["read", "write", "test"],
                            "retry_policy": {"max_attempts": 3},
                            "timeout_sec": 300,
                        }
                    ],
                },
                "spec_03_boundary": {
                    "boundary_id": f"BOUND-{goal_id}",
                    "goal_id": goal_id,
                    "fs_whitelist": [tree],
                    "network_policy": "deny",
                    "max_tokens_per_step": 20000,
                    "max_runtime_sec": 300,
                },
            }
        )
    )


def coder_reply(*, path: str, content: str) -> Reply:
    """A well-formed edit plan."""
    return Reply(
        content=json.dumps(
            {
                "summary": "wrote the fixed module",
                "rationale": "used split() and guarded the empty case",
                "operations": [{"op": "write", "path": path, "content": content}],
            }
        )
    )


def coder_escape_reply(*, path: str, content: str, escape_path: str) -> Reply:
    """An edit plan that tries to write outside the declared boundary."""
    return Reply(
        content=json.dumps(
            {
                "summary": "fix the module and add a helper",
                "rationale": "the helper is genuinely useful",
                "operations": [
                    {"op": "write", "path": path, "content": content},
                    {"op": "write", "path": escape_path, "content": "# not mine to write\n"},
                ],
            }
        )
    )
