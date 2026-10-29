"""Opt-in kernel checks in disposable containers; no model gateway or real secrets."""

import os
from dataclasses import replace

import pytest

from daedalus.domain.spec import BoundarySpec
from daedalus.infrastructure.sandbox import ContainerDriver

pytestmark = pytest.mark.skipif(
    os.environ.get("DAEDALUS_RUNTIME_TESTS") != "1",
    reason="explicit disposable runtime check required",
)


@pytest.fixture
def runtime(tmp_path):
    driver = ContainerDriver(image=os.environ.get("DAEDALUS_RUNTIME_IMAGE", "python:3.12-slim"))
    assert driver.probe().available
    box = tmp_path / "workspace"
    box.mkdir()
    box.chmod(0o777)
    boundary = BoundarySpec(
        "runtime",
        "runtime",
        isolation="container",
        memory_mb=128,
        cpu_limit=1,
        process_limit=16,
        max_runtime_sec=20,
    )
    return driver, box, boundary


def command(runtime, code, *, timeout=15, boundary=None):
    driver, box, default = runtime
    return driver.run(
        worktree=box,
        command=["python3", "-c", code],
        timeout_sec=timeout,
        boundary=boundary or default,
    )


def test_confinement_can_write_mount_but_cannot_read_host_canary(runtime):
    driver, box, boundary = runtime
    canary = box.parent / "outside-canary.txt"
    canary.write_text("synthetic isolation marker")
    result = command(
        runtime,
        "from pathlib import Path; Path('inside.txt').write_text('ok'); "
        f"assert not Path({str(canary)!r}).exists(); print('confined')",
    )
    assert result.ok and "confined" in result.stdout
    assert (box / "inside.txt").read_text() == "ok"
    assert canary.read_text() == "synthetic isolation marker"


def test_confinement_readonly_root_and_unprivileged_identity(runtime):
    result = command(
        runtime,
        "import os,errno; assert os.getuid()==65534; "
        "assert 'CapEff:\t0000000000000000' in open('/proc/self/status').read(); "
        "\ntry: open('/var/tmp/daedalus-root-write','w')\n"
        "except OSError as e: assert e.errno==errno.EROFS\n"
        "else: raise AssertionError('writable root')\nprint('restricted')",
    )
    assert result.ok and "restricted" in result.stdout


def test_confinement_network_is_unreachable_in_namespace(runtime):
    result = command(
        runtime,
        "import socket,errno\n"
        "try: socket.create_connection(('1.1.1.1',53),timeout=2)\n"
        "except OSError as e: assert e.errno in (errno.ENETUNREACH,errno.EACCES,errno.EPERM)\n"
        "else: raise AssertionError('network open')\nprint('network denied')",
    )
    assert result.ok and "network denied" in result.stdout


def test_confinement_memory_limit_is_enforced(runtime):
    boundary = replace(runtime[2], memory_mb=64)
    result = command(
        runtime, "block=bytearray(256*1024*1024); print('unexpected allocation')", boundary=boundary
    )
    assert not result.ok and "unexpected allocation" not in result.stdout
    assert result.exit_code == 137


def test_confinement_pid_limit_refuses_additional_children(runtime):
    boundary = replace(runtime[2], process_limit=4)
    result = command(
        runtime,
        "import os,time\nchildren=[]\nrefused=False\n"
        "for i in range(8):\n"
        "    try: pid=os.fork()\n"
        "    except BlockingIOError: refused=True; break\n"
        "    if pid==0: time.sleep(.4); os._exit(0)\n"
        "    children.append(pid)\n"
        "for pid in children: os.waitpid(pid,0)\n"
        "assert refused\nprint('pid limit enforced')",
        boundary=boundary,
    )
    assert result.ok and "pid limit enforced" in result.stdout


def test_confinement_timeout_removes_only_its_container(runtime):
    import subprocess

    driver, box, boundary = runtime
    result = command(runtime, "import time; time.sleep(30)", timeout=1)
    assert result.timed_out and result.exit_code == 124
    name = result.isolation["container_name"]
    inspect = subprocess.run(
        [driver.resolve_runtime().binary, "inspect", name], capture_output=True, text=True
    )
    assert inspect.returncode != 0 and "no such object" in inspect.stderr.lower()
