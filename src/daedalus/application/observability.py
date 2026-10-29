"""Structured logging and correlation (Spec §15).

Every log line carries the identifiers needed to answer "which run, which step, which
event". Without that, a log is a wall of text; with it, a log is queryable evidence.

Secrets are scrubbed on the way out through the same redactor the event store uses, so a
log file and an event payload can never disagree about what was allowed to be written.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator

from daedalus.infrastructure.redact import redact, redact_text

LOGGER_NAME = "daedalus"

_context: ContextVar[dict[str, str]] = ContextVar("daedalus_log_context", default={})


@dataclass(frozen=True, slots=True)
class LogContext:
    run_id: str = ""
    step_id: str = ""
    event_id: str = ""
    worker_id: str = ""
    component: str = ""

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.__dict__.items() if v}


@contextmanager
def log_context(**fields: str) -> Iterator[None]:
    """Bind correlation fields for the duration of a block."""
    merged = {**_context.get(), **{k: v for k, v in fields.items() if v}}
    token = _context.set(merged)
    try:
        yield
    finally:
        _context.reset(token)


def current_context() -> dict[str, str]:
    return dict(_context.get())


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with correlation fields and secrets redacted."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        payload.update(current_context())
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = value
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(redact(payload), sort_keys=True, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    """Human-readable, still redacted, still correlated."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = time.strftime("%H:%M:%S", time.localtime(record.created))
        context = current_context()
        suffix = " ".join(f"{key}={value}" for key, value in sorted(context.items()))
        message = redact_text(record.getMessage())
        line = f"{stamp} {record.levelname:<7} {record.name:<22} {message}"
        if suffix:
            line = f"{line}  [{suffix}]"
        if record.exc_info:
            line = f"{line}\n{redact_text(self.formatException(record.exc_info))}"
        return line


class _Adapter(logging.LoggerAdapter):
    """A LoggerAdapter that merges bound fields into `extra_fields` on every record."""

    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        extra = dict(kwargs.get("extra") or {})
        bound = dict(getattr(self, "extra_fields", {}) or {})
        merged = {**bound, **(extra.get("extra_fields") or {})}
        if merged:
            extra["extra_fields"] = merged
        kwargs["extra"] = extra
        return msg, kwargs


_configured = False


def configure_logging(
    *,
    level: str = "INFO",
    json_output: bool | None = None,
    stream: Any = None,
) -> None:
    """Install the Daedalus handler on the `daedalus` logger namespace."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(stream or sys.stderr)
    if json_output is None:
        json_output = not (stream or sys.stderr).isatty()
    handler.setFormatter(JsonFormatter() if json_output else TextFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    _configured = True


def get_logger(name: str = "", **fields: Any) -> logging.LoggerAdapter:
    """A logger under the `daedalus` namespace, optionally with bound fields.

    `LoggerAdapter.__init__` only accepts `(logger, extra)`, so bound fields are attached
    after construction; the adapter merges them into the record alongside any per-call
    fields.
    """
    if not _configured:
        configure_logging()
    full = f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME
    adapter = _Adapter(logging.getLogger(full), {})
    adapter.extra_fields = dict(fields)
    return adapter
