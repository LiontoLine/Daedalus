"""Bounded command execution with an owned POSIX process group.

This controls ordinary descendants, including children inheriting output pipes.
It is lifecycle cleanup, not a namespace: a hostile child can leave the session.
"""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
from typing import Any, Sequence


def command_output_excerpt(text: str, limit: int) -> str:
    """Keep command identity and the final exception within a fixed prompt allowance."""
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    marker = "\n...[output omitted]...\n"
    if limit <= len(marker):
        return text[-limit:]
    head = (limit-len(marker))//2
    tail = limit-len(marker)-head
    return text[:head]+marker+text[-tail:]


def command_failure_code(exit_code: int, stderr: str) -> str:
    """Normalize shell spawn failures at the infrastructure boundary, never as code feedback."""
    if exit_code != 0 and re.search(
        r"(?im)^(?:[^\n]*[/ ])?(?:bash|sh|zsh|dash)(?::[^\n]*)?: "
        r"(?:fork: |fork: retry: )?(?:Resource temporarily unavailable|Cannot allocate memory|Too many open files)",
        stderr,
    ):
        return "execution_environment_unavailable"
    return ""


def resource_preexec(*, timeout_sec: int, boundary: Any = None):
    import resource

    runtime = min(timeout_sec, boundary.max_runtime_sec) if boundary else timeout_sec
    cpu = max(1, math.ceil(runtime * (boundary.cpu_limit if boundary else 1)))
    file_bytes = (
        min(boundary.disk_mb * 1024 * 1024, 256 * 1024 * 1024) if boundary else 256 * 1024 * 1024
    )

    def apply() -> None:
        # Never raise a limit inherited from the service. An unenforceable limit
        # fails process creation instead of silently continuing without it.
        def limit(kind: int, value: int) -> None:
            _, hard = resource.getrlimit(kind)
            value = value if hard == resource.RLIM_INFINITY else min(hard, value)
            resource.setrlimit(kind, (value, value))

        limit(resource.RLIMIT_CPU, cpu)
        limit(resource.RLIMIT_NOFILE, 1024)
        # NPROC is shared by the whole uid, including the user's desktop processes.
        # Lowering it to a task's process_limit can prevent even a shell pipeline from
        # forking. Keep inherited user limits; task PID limits require a container.
        limit(resource.RLIMIT_FSIZE, file_bytes)
        # macOS memory controls are not asserted by this driver. Linux AS is a
        # per-process address-space ceiling, not a task-wide cgroup budget.
        if boundary is not None and sys.platform.startswith("linux"):
            limit(resource.RLIMIT_AS, boundary.memory_mb * 1024 * 1024)

    return apply


def resource_enforcement() -> dict[str, bool | str]:
    return {
        "cpu_time": os.name == "posix",
        "single_file_size": os.name == "posix",
        "process_count_scope": "inherited per-user limit; task PID limit not enforced",
        "task_process_count": False,
        "memory_scope": "per-process address space"
        if sys.platform.startswith("linux")
        else "not enforced",
        "total_disk": False,
        "task_memory": False,
        "cpu_rate": False,
    }


def _terminate(process: subprocess.Popen[str]) -> None:
    if os.name == "posix":
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                break
            if sig == signal.SIGTERM:
                try:
                    process.wait(timeout=0.3)
                except subprocess.TimeoutExpired:
                    pass
    elif process.poll() is None:
        process.kill()
    process.wait(timeout=2)


def run_command(
    command: Sequence[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    preexec_fn: Any = None,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        # Importing a candidate during verification must not add Python bytecode
        # to the tree subsequently sent for review or checked before commit.
        env={**(os.environ if env is None else env), "PYTHONDONTWRITEBYTECODE": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=os.name == "posix",
        preexec_fn=preexec_fn,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        _terminate(process)
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            # A descendant outside our group can retain pipes. Do not wait forever.
            stdout, stderr = expired.stdout, expired.stderr
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr) from None
    except BaseException:
        _terminate(process)
        raise
    else:
        _terminate(process)  # reap background descendants even after a successful parent
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
