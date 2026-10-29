"""Deterministic offline model clients.

The whole Phase-1 acceptance test runs against these, which is the point: the FSM,
the boundary, the gate and the event log can all be proven correct without a network,
a credential or a nondeterministic vendor. A model that is flaky must never be the
reason a control-plane test fails.

`MockModelClient`   — routes a prompt to whatever produces the answer (used by the
                      planner/coder/reviewer implementations directly).
`ScriptedModelClient` — replays a canned sequence of responses, so a test can force a
                      syntax error, a boundary escape or a REVISE decision exactly once.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from daedalus.model.base import Completion, Message, ModelError


@dataclass
class MockModelClient:
    """Answers from a callable. Token counts are estimated so budgets still bind."""

    name: str = "mock"
    model: str = "mock-deterministic"
    responder: object | None = None  # Callable[[str], str]
    tokens_per_char: float = 0.25
    calls: list[str] = field(default_factory=list)

    def complete(
        self,
        messages: list[Message],
        *,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format_json: bool = False,
    ) -> Completion:
        prompt = "\n".join(message.content for message in messages)
        self.calls.append(prompt)
        if self.responder is None:
            raise ModelError("MockModelClient has no responder configured")
        text = str(self.responder(prompt))  # type: ignore[operator]
        prompt_tokens = int(len(prompt) * self.tokens_per_char)
        completion_tokens = int(len(text) * self.tokens_per_char)
        return Completion(
            text=text,
            model=self.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=0,
            stopped_reason="stop",
        )


@dataclass
class ScriptedModelClient:
    """Replays responses in order; raises when the script is exhausted."""

    responses: list[str] = field(default_factory=list)
    name: str = "scripted"
    model: str = "scripted-deterministic"
    index: int = 0
    repeat_last: bool = False
    calls: list[str] = field(default_factory=list)

    def complete(
        self,
        messages: list[Message],
        *,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format_json: bool = False,
    ) -> Completion:
        prompt = "\n".join(message.content for message in messages)
        self.calls.append(prompt)
        if self.index >= len(self.responses):
            if not self.repeat_last or not self.responses:
                raise ModelError(
                    f"ScriptedModelClient exhausted after {self.index} response(s)"
                )
            text = self.responses[-1]
        else:
            text = self.responses[self.index]
            self.index += 1
        return Completion(
            text=text,
            model=self.model,
            prompt_tokens=int(len(prompt) * 0.25),
            completion_tokens=int(len(text) * 0.25),
            latency_ms=0,
            stopped_reason="stop",
        )
