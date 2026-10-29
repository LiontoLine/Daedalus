"""Atomic changes to fixed access settings; credentials never enter the TOML."""

import os
import re
import tempfile
import tomllib
from contextlib import contextmanager
from pathlib import Path

from daedalus.config import ConfigError, _from_mapping
from daedalus.service.access import AccessControl


def configure_access(settings, *, lan):
    if not settings.source_path:
        raise ConfigError("请通过带持久配置的 daedalus 入口启动")
    path = Path(settings.source_path).resolve()
    lines = path.read_text().splitlines(keepends=True)
    start = next(
        (i for i, line in enumerate(lines) if re.fullmatch(r"\s*\[service\]\s*(?:#.*)?\n?", line)),
        None,
    )
    if start is None:
        lines.append("\n[service]\n")
        start = len(lines) - 1
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines)
    )
    section = lines[start:end]
    for key, value in {
        "host": '"0.0.0.0"' if lan else '"127.0.0.1"',
        "auth_required": "true",
    }.items():
        indices = [i for i, line in enumerate(section) if re.match(r"\s*" + key + r"\s*=", line)]
        if indices:
            section[indices[0]] = f"{key} = {value}\n"
        else:
            if not section[-1].endswith("\n"):
                section[-1] += "\n"
            section.append(f"{key} = {value}\n")
    updated = "".join([*lines[:start], *section, *lines[end:]])
    proposed = _from_mapping(tomllib.loads(updated), source_path=str(path))
    proposed.validate()
    AccessControl(proposed).validate_bind()
    fd, temporary = tempfile.mkstemp(prefix=".access-config-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(updated)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return proposed


@contextmanager
def access_change(settings, *, lan):
    """Roll back this exact edit if arranging the replacement fails."""
    path = Path(settings.source_path).resolve()
    original = path.read_bytes()
    mode = path.stat().st_mode & 0o777
    proposed = configure_access(settings, lan=lan)
    written = path.read_bytes()
    try:
        yield proposed
    except Exception:
        if path.read_bytes() == written:
            fd, temporary = tempfile.mkstemp(prefix=".access-rollback-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as output:
                    os.fchmod(output.fileno(), mode)
                    output.write(original)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, path)
            finally:
                Path(temporary).unlink(missing_ok=True)
        raise
