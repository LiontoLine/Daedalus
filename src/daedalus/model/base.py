"""The model transport contract plus a token accountant.

`TokenBudget` is enforced *before* a call is dispatched and *after* it returns, so a
runaway loop surfaces as a `QuotaExceeded` in the FSM rather than as an unexplained
bill.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from daedalus.errors import (
    ModelBudgetExceeded,
    ModelError,
    ModelResponseIncomplete,
)
from daedalus.errors import (
    ModelTimeout as ModelTimeout,
)
from daedalus.errors import (
    ModelUnavailable as ModelUnavailable,
)


def token_usage_details(usage: Any) -> dict[str, Any]:
    """Retain numeric usage only; provider payloads never enter telemetry wholesale."""
    if not isinstance(usage, dict):
        return {}
    keys = {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "prompt_cache_hit_tokens",
        "prompt_cache_miss_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
        "promptTokenCount",
        "candidatesTokenCount",
        "thoughtsTokenCount",
    }
    result = {
        key: value
        for key, value in usage.items()
        if key in keys and type(value) is int and value >= 0
    }
    for key in (
        "prompt_tokens_details",
        "completion_tokens_details",
        "input_tokens_details",
        "output_tokens_details",
    ):
        details = usage.get(key)
        if isinstance(details, dict):
            selected = {
                name: value
                for name, value in details.items()
                if name in {"cached_tokens", "reasoning_tokens"}
                and type(value) is int
                and value >= 0
            }
            if selected:
                result[key] = selected
    return result


def _new_lock() -> threading.RLock:
    return threading.RLock()


@dataclass(frozen=True, slots=True)
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str

    def to_payload(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True, slots=True)
class Completion:
    text: str
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0
    raw: dict[str, Any] = field(default_factory=dict)
    stopped_reason: str = ""

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class ModelClient(Protocol):
    name: str
    model: str

    def complete(
        self,
        messages: list[Message],
        *,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format_json: bool = False,
    ) -> Completion: ...


class TokenBudget:
    """Attempt-local usage and one shared, atomically reserved run allowance.

    A scope survives worker-thread exit so its later gate/rebase sees the same spend.
    New attempts have fresh step allowances; their spend still accumulates in the run.
    Reservations are estimates, never reported as supplier usage or persisted as spend.
    """

    def __init__(
        self,
        max_tokens_per_step: int = 20_000,
        max_tokens_per_run: int = 200_000,
        step_used: int = 0,
        run_used: int = 0,
        calls: int = 0,
        per_model: dict[str, int] | None = None,
        on_record: Any = None,
        usage_history: list[Completion] | None = None,
        _lock: Any = None,
    ) -> None:
        self.max_tokens_per_step = max_tokens_per_step
        self.max_tokens_per_run = max_tokens_per_run
        self.run_used, self.calls = run_used, calls
        self.per_model = dict(per_model or {})
        self.on_record = on_record
        self.usage_history = list(usage_history or [])
        self._lock = _lock or _new_lock()
        self._scope = ContextVar(f"token-budget-{id(self)}", default=("", 0))
        self._step_usage: dict[tuple[str, int], int] = {("", 0): step_used}
        self._reserved: dict[tuple[str, int], int] = {}

    @property
    def step_used(self) -> int:
        with self._lock:
            return self._step_usage.get(self._scope.get(), 0)

    @step_used.setter
    def step_used(self, value: int) -> None:
        with self._lock:
            self._step_usage[self._scope.get()] = value

    @contextmanager
    def step_scope(self, step_id: str, attempt: int):
        """Bind this thread/task to an existing attempt without resetting its usage."""
        if not isinstance(step_id, str) or type(attempt) is not int or attempt < 0:
            raise ValueError("invalid token budget attempt identity")
        token = self._scope.set((step_id, attempt))
        try:
            yield self
        finally:
            self._scope.reset(token)

    def check(self, estimated: int = 0) -> None:
        if type(estimated) is not int or estimated < 0:
            raise ValueError("token estimate must be a nonnegative integer")
        with self._lock:
            self._check_locked(estimated)

    def _check_locked(self, estimated: int) -> None:
        scope = self._scope.get()
        step_used = self._step_usage.get(scope, 0)
        step_reserved = self._reserved.get(scope, 0)
        run_reserved = sum(self._reserved.values())
        if step_used + step_reserved + estimated > self.max_tokens_per_step:
            raise ModelBudgetExceeded(
                f"per-step token budget would be exceeded: "
                f"{step_used}+{step_reserved}+{estimated} > "
                f"{self.max_tokens_per_step}",
                used=step_used,
                reserved=step_reserved,
                limit=self.max_tokens_per_step,
                scope="step",
            )
        if self.run_used + run_reserved + estimated > self.max_tokens_per_run:
            raise ModelBudgetExceeded(
                f"per-run token budget would be exceeded: "
                f"{self.run_used}+{run_reserved}+{estimated} > "
                f"{self.max_tokens_per_run}",
                used=self.run_used,
                reserved=run_reserved,
                limit=self.max_tokens_per_run,
                scope="run",
            )

    @contextmanager
    def reservation(self, estimated: int, *, headroom: int = 0):
        """Reserve under the same lock as admission; every exit releases unused tokens."""
        if any(type(n) is not int or n < 0 for n in (estimated, headroom)):
            raise ValueError("token reservations must be nonnegative integers")
        ticket = _TokenReservation(self._scope.get(), estimated + headroom)
        with self._lock:
            self._check_locked(ticket.amount)
            self._reserved[ticket.scope] = self._reserved.get(ticket.scope, 0) + ticket.amount
        try:
            yield ticket
        finally:
            with self._lock:
                self._release_locked(ticket)

    def _release_locked(self, ticket: _TokenReservation) -> None:
        if ticket.active:
            self._reserved[ticket.scope] -= ticket.amount
            if not self._reserved[ticket.scope]:
                del self._reserved[ticket.scope]
            ticket.active = False

    def record(
        self, completion: Completion, *, reservation: _TokenReservation | None = None
    ) -> None:
        if any(
            type(n) is not int or n < 0
            for n in (
                completion.prompt_tokens,
                completion.completion_tokens,
            )
        ):
            raise ModelError("model token usage must contain nonnegative integers")
        tokens = completion.total_tokens
        scope = reservation.scope if reservation else self._scope.get()
        completion = replace(
            completion,
            raw={**completion.raw, "budget_step_id": scope[0], "budget_attempt": scope[1]},
        )
        with self._lock:
            if reservation is not None:
                self._release_locked(reservation)
            self._step_usage[scope] = self._step_usage.get(scope, 0) + tokens
            self.run_used += tokens
            self.calls += 1
            key = completion.model or "unknown"
            self.per_model[key] = self.per_model.get(key, 0) + tokens
            self.usage_history.append(
                Completion(
                    text="",
                    model=completion.model,
                    prompt_tokens=completion.prompt_tokens,
                    completion_tokens=completion.completion_tokens,
                    latency_ms=completion.latency_ms,
                    raw={"failed_response": bool(completion.raw.get("failed_response"))},
                )
            )
        if self.on_record is not None:
            with suppress(Exception):  # observability must never break a run
                self.on_record(completion)

    def record_error(
        self, error: Exception, *, reservation: _TokenReservation | None = None
    ) -> None:
        """Charge reported usage from a failed response; never invent missing usage."""
        usage = getattr(error, "context", {}).get("usage")
        if isinstance(usage, dict):
            usage = token_usage_details(usage)
            self.record(
                Completion(
                    text="",
                    model=str(getattr(error, "context", {}).get("model", "")),
                    prompt_tokens=int(usage.get("prompt_tokens", 0)),
                    completion_tokens=int(usage.get("completion_tokens", 0)),
                    raw={"failed_response": True},
                ),
                reservation=reservation,
            )

    def reset_step(self) -> None:
        with self._lock:
            if self._reserved.get(self._scope.get(), 0):
                raise RuntimeError("cannot reset an attempt with in-flight model calls")
            self.step_used = 0

    def describe(self) -> dict[str, int]:
        with self._lock:
            return {
                "step_used": self.step_used,
                "run_used": self.run_used,
                "max_tokens_per_step": self.max_tokens_per_step,
                "max_tokens_per_run": self.max_tokens_per_run,
                "calls": self.calls,
                "step_reserved": self._reserved.get(self._scope.get(), 0),
                "run_reserved": sum(self._reserved.values()),
            }


@dataclass
class _TokenReservation:
    scope: tuple[str, int]
    amount: int
    active: bool = True


def budgeted_completion(
    client: ModelClient,
    messages: list[Message],
    *,
    budget: TokenBudget | None = None,
    estimated: int | None = None,
    headroom: int = 0,
    **options,
) -> Completion:
    """One dispatch, one usage settlement, including a failed/incomplete response.

    Unknown usage stays unknown and releases its in-flight reservation on exit. Actual
    reported usage can exceed an estimate; subsequent admission and gates then refuse it.
    """

    def dispatch():
        completion = client.complete(messages, **options)
        if not completion.text.strip() or completion.stopped_reason in {
            "length",
            "max_tokens",
            "MAX_TOKENS",
        }:
            raise ModelResponseIncomplete(
                "model response was truncated or had no visible answer",
                model=completion.model,
                finish_reason=completion.stopped_reason or "empty_text",
                usage={
                    "prompt_tokens": completion.prompt_tokens,
                    "completion_tokens": completion.completion_tokens,
                },
            )
        return completion

    if budget is None:
        return dispatch()
    estimate = (
        estimated
        if estimated is not None
        else (
            sum(len(message.content) for message in messages) + options.get("max_tokens", 4096) + 64
        )
    )
    with budget.reservation(estimate, headroom=headroom) as ticket:
        try:
            completion = dispatch()
        except Exception as error:
            budget.record_error(error, reservation=ticket)
            raise
        budget.record(completion, reservation=ticket)
        return completion


@dataclass
class ModelRegistry:
    """Named model roles: planner, coder, reviewer.

    Roles are resolved by name so that a plan can pick a cheap coder and an expensive
    reviewer without the orchestration code knowing which vendor that is.
    """

    clients: dict[str, ModelClient] = field(default_factory=dict)

    def register(self, role: str, client: ModelClient) -> None:
        self.clients[role] = client

    def get(self, role: str) -> ModelClient:
        try:
            return self.clients[role]
        except KeyError:
            raise ModelError(
                f"no model client registered for role {role!r}; known roles: {sorted(self.clients)}"
            ) from None

    def has(self, role: str) -> bool:
        return role in self.clients

    def describe(self) -> dict[str, str]:
        return {
            role: f"{getattr(client, 'name', '?')}:{getattr(client, 'model', '?')}"
            for role, client in self.clients.items()
        }
