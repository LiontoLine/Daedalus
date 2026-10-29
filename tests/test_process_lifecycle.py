"""Real subprocess cleanup and runtime-independent container lifecycle regressions."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from daedalus.domain.spec import BoundarySpec
from daedalus.infrastructure.process import resource_preexec, run_command
from daedalus.infrastructure.sandbox.container import (
    ContainerDriver,
    ContainerRuntime,
    ContainerUnavailable,
)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process group contract")
@pytest.mark.parametrize("parent_exits", [False, True])
def test_descendants_cannot_keep_running_after_the_command_finishes(tmp_path, parent_exits):
    marker = tmp_path / "survived"
    child = (
        "import signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(1);Path("
        + repr(str(marker))
        + ").touch()"
    )
    parent = (
        "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',"
        + repr(child)
        + "],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);print('started',flush=True);"
        + ("time.sleep(0.1)" if parent_exits else "time.sleep(10)")
    )
    if parent_exits:
        result = run_command([sys.executable, "-c", parent], timeout=2)
        assert result.returncode == 0 and "started" in result.stdout
    else:
        with pytest.raises(subprocess.TimeoutExpired) as error:
            run_command([sys.executable, "-c", parent], timeout=0.3)
        assert "started" in error.value.stdout
    time.sleep(1.1)
    assert not marker.exists(), (
        "a descendant survived cleanup and executed after the caller finished"
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX rlimits")
def test_resource_limits_use_the_frozen_boundary(tmp_path):
    import resource
    inherited_process_limit = resource.getrlimit(resource.RLIMIT_NPROC)[0]
    boundary = BoundarySpec(
        boundary_id="B", goal_id="G", max_runtime_sec=10, cpu_limit=1, process_limit=64, disk_mb=2
    )
    code = "import resource,json;print(json.dumps({k:resource.getrlimit(getattr(resource,k))[0] for k in ['RLIMIT_CPU','RLIMIT_FSIZE','RLIMIT_NPROC']}))"
    result = run_command(
        [sys.executable, "-c", code],
        timeout=2,
        preexec_fn=resource_preexec(timeout_sec=2, boundary=boundary),
    )
    values = json.loads(result.stdout)
    assert values["RLIMIT_CPU"] <= 2
    assert values["RLIMIT_FSIZE"] <= 2 * 1024 * 1024
    assert values["RLIMIT_NPROC"] == inherited_process_limit


@pytest.mark.skipif(os.name != "posix", reason="POSIX rlimits")
def test_task_process_number_does_not_starve_the_shared_desktop_uid(tmp_path):
    boundary = BoundarySpec(boundary_id="B", goal_id="G", process_limit=1)
    result = run_command(
        ["bash", "-c", "printf ok | cat"], timeout=5, cwd=tmp_path,
        preexec_fn=resource_preexec(timeout_sec=5, boundary=boundary),
    )
    assert result.returncode == 0 and result.stdout == "ok", result.stderr


@pytest.mark.parametrize("cleanup_ok", [True, False])
def test_container_timeout_removes_only_its_owned_container(tmp_path, monkeypatch, cleanup_ok):
    runtime = ContainerRuntime(binary="docker", kind="docker")
    monkeypatch.setattr(ContainerDriver, "resolve_runtime", lambda self: runtime)
    calls = []

    def invoke(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, 1, output=b"partial output")
        return subprocess.CompletedProcess(
            argv,
            0 if cleanup_ok else 1,
            stdout="",
            stderr="" if cleanup_ok else "daemon unavailable",
        )

    monkeypatch.setattr(subprocess, "run", invoke)
    outcome = ContainerDriver().run(
        worktree=tmp_path,
        command=["sleep", "100"],
        timeout_sec=1,
        boundary=BoundarySpec(boundary_id="B", goal_id="G"),
    )
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["docker", "rm", "--force", name]
    assert name.startswith("daedalus-") and outcome.timed_out
    assert outcome.exit_code == (124 if cleanup_ok else 125)
    if not cleanup_ok:
        assert "cleanup unconfirmed" in outcome.stderr


def test_sensitive_worktree_cannot_be_mounted_even_as_the_only_bind():
    with pytest.raises(ContainerUnavailable, match="sensitive host mount"):
        ContainerDriver().build_argv(
            runtime=ContainerRuntime(binary="docker", kind="docker"),
            worktree=Path.home(),
            command=["true"],
            boundary=BoundarySpec(boundary_id="B", goal_id="G"),
        )


@pytest.mark.parametrize("environment", [None, {}, {"PYTHONDONTWRITEBYTECODE": "0"}])
def test_verification_imports_leave_no_untracked_bytecode(tmp_path, environment):
    import sys

    from daedalus.infrastructure.process import run_command

    module = tmp_path / "candidate.py"
    module.write_text("VALUE = 41\n")
    outcome = run_command(
        [sys.executable, "-c", "import candidate; assert candidate.VALUE + 1 == 42"],
        cwd=tmp_path, timeout=10, env=environment,
    )
    assert outcome.returncode == 0, outcome.stderr
    assert not (tmp_path / "__pycache__").exists()
    assert module.read_text() == "VALUE = 41\n"
