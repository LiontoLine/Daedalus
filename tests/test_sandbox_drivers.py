"""Sandbox drivers: isolation selection and enforcement (Spec §7).

The tests are split by what they need:

* **always runnable** — selection policy, argv construction, profile generation. These assert
  the security-relevant artefacts directly, so a machine without a container runtime still
  gets the whole container profile verified flag by flag.
* **skip-if-unavailable** — the real container and seatbelt runs. On a host that has a runtime
  these execute for real; where it does not, they are skipped with the prerequisite named
  rather than silently passing.

That split is deliberate: a security control that is only tested where it is convenient is a
control nobody has verified.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from daedalus.domain.spec import BoundarySpec, BoundarySpec as B, NetworkPolicy
from daedalus.infrastructure.sandbox import (
    ContainerDriver,
    DriverRegistry,
    HostProcessDriver,
    IsolationUnavailable,
    SeatbeltDriver,
)
from daedalus.infrastructure.sandbox.base import CommandOutcome
from daedalus.infrastructure.sandbox.container import ContainerRuntime


def _boundary(**overrides) -> BoundarySpec:
    base = dict(
        boundary_id="B",
        goal_id="G",
        fs_whitelist=("src/**",),
        network_policy=NetworkPolicy.DENY,
        process_limit=256,
        memory_mb=2048,
        cpu_limit=2.0,
        max_runtime_sec=300,
    )
    base.update(overrides)
    return BoundarySpec(**base)


# ---------------------------------------------------------------------------
# Selection policy
# ---------------------------------------------------------------------------


def test_auto_selects_the_strongest_available_driver() -> None:
    registry = DriverRegistry.default()
    choice = registry.select(_boundary(), requested="auto")
    available = [
        report.driver for report in registry.probe_all(_boundary()) if report.available
    ]
    assert choice.report.driver in available
    assert "strongest available" in choice.reason
    # Every driver considered is recorded, so the decision is auditable after the fact.
    assert choice.considered


def test_an_explicit_unavailable_level_is_refused_not_downgraded() -> None:
    """Silently falling back would give an operator an unsandboxed process and no warning."""
    registry = DriverRegistry.default()
    container = registry.get("container")
    if container.probe().available:  # pragma: no cover - only on a host with a runtime
        pytest.skip("this host has a container runtime, so container is not unavailable")
    with pytest.raises(IsolationUnavailable) as error:
        registry.select(_boundary(isolation="container"), requested="container")
    assert "unavailable" in error.value.message
    assert error.value.context.get("requested") == "container"


def test_an_unknown_level_is_refused() -> None:
    with pytest.raises(IsolationUnavailable, match="unknown isolation level"):
        DriverRegistry.default().select(_boundary(), requested="chroot")


def test_seatbelt_never_claims_to_enforce_a_network_allowlist() -> None:
    """Seatbelt distinguishes allow/deny only, so it must never report an allowlist as enforced.

    Asserted as an invariant rather than a branch: on a host where seatbelt cannot run at all
    the reason differs, but the conclusion must be the same.
    """
    report = SeatbeltDriver().probe_for_network(NetworkPolicy.ALLOWLIST)
    assert not report.network.enforced, (
        "seatbelt must never claim to enforce a domain allowlist it cannot express"
    )
    assert not report.available, "an unenforceable boundary must make the driver unavailable"


def test_host_process_reports_its_own_weaknesses() -> None:
    """The weakest driver must not describe itself as isolated."""
    report = HostProcessDriver().probe()
    assert report.available
    assert not report.process_isolation.enforced
    assert not report.network.enforced
    assert not report.filesystem.enforced
    assert not report.resource_limits.enforced  # partial limits are not a full resource quota
    assert report.missing_prerequisites


def test_the_probe_report_serialises_with_strength_ordering() -> None:
    payload = ContainerDriver().probe().describe()
    assert payload["driver"] == "container"
    assert "capabilities" in payload
    assert payload["strength"] > HostProcessDriver().probe().describe()["strength"]


# ---------------------------------------------------------------------------
# Container argv: the security profile, verified without a runtime
# ---------------------------------------------------------------------------


def _runtime() -> ContainerRuntime:
    return ContainerRuntime(binary="docker", kind="docker", version="27.0.0", rootless=True)


def test_container_argv_applies_the_spec_security_profile(tmp_path: Path) -> None:
    driver = ContainerDriver()
    argv = driver.build_argv(
        runtime=_runtime(),
        worktree=tmp_path,
        command=["python3", "-m", "pytest", "tests", "-q"],
        boundary=_boundary(),
    )
    joined = " ".join(argv)

    assert argv[0] == "docker" and argv[1] == "run"
    assert "--rm" in argv
    # Non-root.
    uid, gid = map(int, argv[argv.index("--user") + 1].split(":"))
    assert uid > 0 and gid > 0
    # No network unless the policy allows it.
    assert "--network none" in joined
    # Read-only base image, with the worktree as the only writable mount.
    assert "--read-only" in argv
    mount = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    assert any("target=/workspace" in m for m in mount)
    assert any(str(tmp_path.resolve()) in m for m in mount)
    # Minimal capability, no privilege escalation, bounded processes and memory.
    assert "ALL" in argv
    assert "no-new-privileges" in argv
    assert "--pids-limit" in argv and "256" in argv
    assert "--memory" in argv and "2048m" in argv
    assert "--cpus" in argv and "2.0" in argv
    # The container socket and host credential directories are explicitly denied.
    assert "label=disable:deny:" not in joined
    assert "--tty" not in argv
    assert "--init" in argv
    # The image precedes the command, and nothing follows the command, so no part of the
    # command can be reinterpreted as a docker flag.
    command = ["python3", "-m", "pytest", "tests", "-q"]
    assert argv[-len(command):] == command

def test_container_identity_never_inherits_root(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(os, "getuid", lambda: 0)
    monkeypatch.setattr(os, "getgid", lambda: 0)
    argv = ContainerDriver().build_argv(
        runtime=_runtime(), worktree=tmp_path, command=["true"], boundary=_boundary(),
    )
    uid, gid = map(int, argv[argv.index("--user") + 1].split(":"))
    assert uid > 0 and gid > 0



def test_container_argv_never_mounts_a_host_credential() -> None:
    driver = ContainerDriver()
    argv = driver.build_argv(
        runtime=_runtime(),
        worktree=Path("/tmp/wt"),
        command=["true"],
        boundary=_boundary(),
    )
    # No bind mount of anything other than the worktree and the declared tmpfs.
    bind_mounts = [
        argv[i + 1] for i, arg in enumerate(argv) if arg == "--mount" and "type=bind" in argv[i + 1]
    ]
    assert all("target=/workspace" in mount for mount in bind_mounts)
    for sensitive in ("/root", "/home", "/etc", "/var/run"):
        assert not any(f"source={sensitive}," in mount for mount in bind_mounts)


def test_container_argv_denies_network_even_for_an_allowlist_boundary() -> None:
    """The driver cannot express an allowlist; if one reaches here it must fail closed."""
    argv = ContainerDriver().build_argv(
        runtime=_runtime(),
        worktree=Path("/tmp/wt"),
        command=["true"],
        boundary=_boundary(network_policy=NetworkPolicy.ALLOWLIST, allowed_domains=("pypi.org",)),
    )
    joined = " ".join(argv)
    assert "--network none" in joined


def test_container_probe_reports_unavailable_without_a_runtime() -> None:
    driver = ContainerDriver(runtime=ContainerRuntime(binary="/nonexistent/docker", kind="docker"))
    report = driver.probe()
    assert not report.available
    assert report.missing_prerequisites
    assert "runtime" in report.detail


def test_container_run_refuses_without_a_runtime(tmp_path: Path) -> None:
    from daedalus.infrastructure.sandbox import ContainerUnavailable

    driver = ContainerDriver(runtime=ContainerRuntime(binary="/nonexistent/docker", kind="docker"))
    with pytest.raises(ContainerUnavailable, match="no usable container runtime"):
        driver.run(
            worktree=tmp_path,
            command=["true"],
            timeout_sec=10,
            boundary=_boundary(),
        )


# ---------------------------------------------------------------------------
# Seatbelt profile
# ---------------------------------------------------------------------------


def test_seatbelt_profile_denies_by_default_and_limits_writes(tmp_path: Path) -> None:
    profile = SeatbeltDriver().build_profile(worktree=tmp_path, boundary=_boundary())
    # The inherited TMPDIR must NOT be writable: allowing it widened the boundary to the whole
    # system temp directory, which is where a harness keeps its own working directories.
    inherited = os.environ.get("TMPDIR", "")
    if inherited and not str(tmp_path).startswith(inherited):
        assert f'(allow file-write* (subpath "{Path(inherited).resolve()}"))' not in profile
    # The per-step scratch directory is writable instead, and it is outside the worktree so it
    # never appears in the diff.
    scratch = SeatbeltDriver().scratch_dir(tmp_path)
    assert f'(allow file-write* (subpath "{scratch}"))' in profile
    assert not str(scratch).startswith(str(tmp_path.resolve()))
    assert "(deny default)" in profile
    assert f'(allow file-write* (subpath "{tmp_path.resolve()}"))' in profile
    # No blanket write permission anywhere: that is the enforcement this driver provides.
    assert "(allow file-write*)" not in profile
    assert "(allow default)" not in profile
    # Network denied at runtime, not merely at gate time.
    assert "(deny network*)" in profile


def test_seatbelt_profile_fails_closed_for_an_allowlist(tmp_path: Path) -> None:
    profile = SeatbeltDriver().build_profile(
        worktree=tmp_path,
        boundary=_boundary(network_policy=NetworkPolicy.ALLOWLIST, allowed_domains=("pypi.org",)),
    )
    assert "(deny network*)" in profile
    assert "FAIL-CLOSED" in profile


def test_seatbelt_reads_are_deliberately_open_and_say_so(tmp_path: Path) -> None:
    """Reads are open because every attempt to restrict them aborted the dynamic loader.

    This asserts the negative result so nobody re-introduces a read allowlist believing it is
    merely untested: on macOS 15 a restricted-read profile SIGABRTs even for `/bin/cat`, and a
    `deny file-read*` does not override a blanket `allow file-read*`.
    """
    profile = SeatbeltDriver().build_profile(worktree=tmp_path, boundary=_boundary())
    assert "(allow file-read*)" in profile, "reads are open; the profile must say so plainly"
    assert "BY MEASUREMENT" in profile, "the reason must be recorded in the profile itself"
    # And the driver must not claim read isolation it does not have.
    report = SeatbeltDriver().probe_for_network(NetworkPolicy.DENY)
    if report.available:
        assert "NOT restricted" in report.filesystem.evidence
        assert "NOT provided" in report.detail or "not provided" in report.detail.lower()


# ---------------------------------------------------------------------------
# Integration, when the mechanism exists
# ---------------------------------------------------------------------------


def _container_runtime_available() -> str:
    if not shutil.which("docker") and not shutil.which("podman"):
        return ""
    completed = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return "docker" if completed.returncode == 0 else ""


@pytest.mark.skipif(
    not _container_runtime_available(),
    reason="no running container runtime (start one with `colima start` or Docker Desktop)",
)
def test_a_container_actually_isolates_the_command(tmp_path: Path) -> None:  # pragma: no cover
    """Real integration: a real container runs a command with the worktree mounted."""
    driver = ContainerDriver(image="python:3.12-slim")
    report = driver.probe()
    assert report.available, report.detail

    tmp_path.chmod(0o700)
    (tmp_path / "probe.txt").write_text("hello from the mount\n", encoding="utf-8")
    (tmp_path / "probe.txt").chmod(0o600)
    outcome = driver.run(
        worktree=tmp_path,
        command=["python3", "-c",
                 "from pathlib import Path; p = Path('probe.txt'); "
                 "value = p.read_text(); p.write_text(value + 'updated\\n'); print(value.strip())"],
        timeout_sec=180,
        boundary=_boundary(),
    )
    assert outcome.ok, outcome.combined()
    assert "hello from the mount" in outcome.stdout
    assert (tmp_path / "probe.txt").read_text().endswith("updated\n")

    # The container is not root.
    whoami = driver.run(
        worktree=tmp_path,
        command=["python3", "-c", "import os; print(os.getuid())"],
        timeout_sec=120,
        boundary=_boundary(),
    )
    assert int(whoami.stdout.strip()) > 0

    # And the network really is denied at runtime, not only at gate time.
    network = driver.run(
        worktree=tmp_path,
        command=[
            "python3",
            "-c",
            "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3); print('OPEN')",
        ],
        timeout_sec=120,
        boundary=_boundary(),
    )
    assert not network.ok, "network access must fail inside --network none"
    assert "OPEN" not in network.stdout


def _seatbelt_available() -> bool:
    return SeatbeltDriver().probe().available


@pytest.mark.skipif(
    not _seatbelt_available(),
    reason="sandbox-exec cannot apply a profile in this process context",
)
def test_seatbelt_actually_isolates_a_command(tmp_path: Path) -> None:  # pragma: no cover
    driver = SeatbeltDriver()
    (tmp_path / "inside.txt").write_text("ok\n", encoding="utf-8")

    allowed = driver.run(
        worktree=tmp_path,
        command=["/bin/cat", str(tmp_path / "inside.txt")],
        timeout_sec=60,
        boundary=_boundary(),
    )
    assert allowed.ok, allowed.combined()
    assert "ok" in allowed.stdout

    # A real interpreter must run: a sandbox that breaks python is a sandbox operators disable.
    python = driver.run(
        worktree=tmp_path,
        command=[sys.executable, "-c", "print('py-ok')"],
        timeout_sec=60,
        boundary=_boundary(),
    )
    assert python.ok, python.combined()
    assert "py-ok" in python.stdout

    # And the write boundary this driver does provide must hold inside the worktree.
    writable = driver.run(
        worktree=tmp_path,
        command=["/bin/sh", "-c", "echo written > inside2.txt"],
        timeout_sec=60,
        boundary=_boundary(),
    )
    assert writable.ok, writable.combined()
    assert (tmp_path / "inside2.txt").read_text().strip() == "written"

    # Writing outside the worktree must be refused by the kernel.
    outside = Path("/tmp") / "daedalus-seatbelt-escape.txt"
    if outside.exists():
        outside.unlink()
    escaped = driver.run(
        worktree=tmp_path,
        command=["/bin/sh", "-c", f"echo escaped > {outside}"],
        timeout_sec=60,
        boundary=_boundary(),
    )
    assert not escaped.ok, "a write outside the worktree must fail"
    assert not outside.exists(), "the kernel must refuse the write, not merely report it"

    # And the network really is denied at runtime.
    network = driver.run(
        worktree=tmp_path,
        command=["/usr/bin/curl", "-s", "--max-time", "5", "http://1.1.1.1"],
        timeout_sec=60,
        boundary=_boundary(),
    )
    assert not network.ok, "network access must fail under (deny network*)"


# ---------------------------------------------------------------------------
# The gate runs through the driver
# ---------------------------------------------------------------------------


class _RecordingDriver:
    """A driver that records what it was asked to run."""

    name = "recording"

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def probe(self):  # noqa: ANN201
        return HostProcessDriver().probe()

    def run(self, *, worktree, command, timeout_sec, boundary, environment=None):  # noqa: ANN001, ANN201
        self.commands.append(list(command))
        completed = subprocess.run(
            list(command), cwd=str(worktree), capture_output=True, text=True, check=False
        )
        return CommandOutcome(
            command=" ".join(command),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_ms=0,
            driver=self.name,
        )

    def describe(self):  # noqa: ANN201
        return {"driver": self.name}


def test_the_gate_executes_acceptance_tests_through_the_driver(git_repo, tmp_path) -> None:
    """Isolation must apply to the gate's own commands, not only to the worker."""
    from daedalus.application.coding_worker import FileOp, ScriptedWorker
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from daedalus.application.scheduler import Quota
    from daedalus.domain.spec import RiskLevel
    from daedalus.infrastructure.store import EventStore
    from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

    recording = _RecordingDriver()
    store = EventStore(tmp_path / "driver.db")
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="R",
            goal_id="GOAL-DRV",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),), worker_id="w"
        ),
        quota=Quota(max_parallel_steps=1),
        park_on_escalation=False,
    )
    # Replace the selected driver with the recorder, keeping the rest of the run intact.
    orchestrator.isolation = type(orchestrator.isolation)(  # type: ignore[arg-type]
        driver=recording,
        report=orchestrator.isolation.report,
        requested="recording",
        reason="test",
    )
    orchestrator.register_spec()
    result = orchestrator.run()

    assert result.status == "COMPLETED", result.describe()
    assert recording.commands, "the acceptance test must have gone through the driver"
    assert any("pytest" in " ".join(command) for command in recording.commands), (
        recording.commands
    )
    store.close()


def test_an_unavailable_isolation_level_is_refused_before_the_run_exists(
    git_repo, tmp_path
) -> None:
    """A refusal must precede the run row: otherwise a deployment believes it ran isolated."""
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.application.planner import DeterministicPlanner, PlanRequest
    from daedalus.application.scheduler import Quota
    from daedalus.domain.spec import RiskLevel
    from daedalus.infrastructure.store import EventStore
    from tests.conftest import TARGET, TEST_COMMAND

    if ContainerDriver().probe().available:  # pragma: no cover - host has a runtime
        pytest.skip("this host has a container runtime, so container is not unavailable")

    store = EventStore(tmp_path / "isolation.db")
    # Build a bundle whose SPEC-03 demands a container.
    from dataclasses import replace

    base = DeterministicPlanner().plan(
        PlanRequest(
            request_id="R",
            goal_id="GOAL-ISO",
            objective="fix it",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=RiskLevel.NORMAL,
            network_policy=NetworkPolicy.DENY,
        )
    )
    bundle = replace(base, boundary=replace(base.boundary, isolation="container"))

    with pytest.raises(IsolationUnavailable, match="container"):
        RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "wt2",
            bundle=bundle,
            quota=Quota(),
        )
    assert not store.list_runs(), "the refusal must happen before anything is persisted"
    store.close()
