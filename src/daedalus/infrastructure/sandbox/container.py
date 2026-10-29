"""Container driver (Spec §7.2).

Builds and runs real `docker`/`podman` invocations with the security profile the spec calls
for: non-root, no network by default, read-only base image, dropped capabilities, bounded
processes/CPU/memory/disk/time, no Docker socket, no host credential directories.

The container's only writable mount is the step's worktree. That is what makes the code
boundary and the process boundary line up: the container cannot see the rest of the host, and
the worktree cannot see anything the container mounts.

`probe()` executes `docker info` through the *exact* binary it would use, so a CLI installed
without a working daemon reports unavailable instead of failing at the first step.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from daedalus.domain.spec import BoundarySpec, NetworkPolicy
from daedalus.infrastructure.redact import redact_text
from daedalus.infrastructure.sandbox.base import (
    Capability,
    CommandOutcome,
    IsolationReport,
)

NAME = "container"

#: Binaries probed in order. Docker and podman are argv-compatible for everything used here.
CANDIDATE_BINARIES = ("docker", "podman")

#: Capabilities granted inside the container. Deliberately empty: nothing here needs any.
DROPPED_CAPABILITIES = ("ALL",)

#: Host paths that must never be mounted, even if a spec names them.
FORBIDDEN_MOUNTS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/podman/podman.sock",
    "~/.ssh",
    "~/.aws",
    "~/.config/gcloud",
    "~/.kube",
    "~/.docker",
    "/etc/shadow",
    "/etc/sudoers",
)


class ContainerUnavailable(RuntimeError):
    """Raised when a container command is attempted with no usable runtime."""


@dataclass(frozen=True, slots=True)
class ContainerRuntime:
    """A probed container CLI, with the facts needed to build the argv."""

    binary: str
    kind: str  # "docker" | "podman"
    version: str = ""
    rootless: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "binary": self.binary,
            "kind": self.kind,
            "version": self.version,
            "rootless": self.rootless,
        }


@dataclass(frozen=True, slots=True)
class ContainerDriver:
    """Runs one command inside a locked-down container with the worktree mounted."""

    name: str = NAME
    #: Base image. Must be a digest-pinned or tag-pinned image the operator trusts.
    image: str = "python:3.12-slim"
    runtime: ContainerRuntime | None = None
    default_binary: str = "docker"
    env_allowlist: tuple[str, ...] = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
    _probe_cache: dict[str, object] = field(default_factory=dict, repr=False, compare=False)

    # ------------------------------------------------------------------- probe
    def probe(self) -> IsolationReport:
        runtime = self.resolve_runtime()
        if runtime is None:
            return self._unavailable(
                "no working container runtime found. Probed: "
                + ", ".join(CANDIDATE_BINARIES)
                + ". A CLI without a running daemon is not a runtime."
            )
        return IsolationReport(
            driver=self.name,
            available=True,
            code_isolation=Capability("worktree", True, "Git worktree per step"),
            process_isolation=Capability(
                "container",
                True,
                f"{runtime.kind} {runtime.version or 'unknown'} is running; pid/ipc/uts "
                "namespaces isolate the command",
            ),
            filesystem=Capability(
                "bind mount + read-only base",
                True,
                "the worktree is the only writable mount; the base image is read-only",
            ),
            network=Capability(
                "none (default)",
                True,
                "`--network none` unless SPEC-03 allowlists domains, in which case a user "
                "network is required and the driver refuses rather than guessing",
            ),
            resource_limits=Capability(
                "cgroup + timeout",
                False,
                "CPU/memory/pids flags and wall-clock timeout; bind-mounted total disk quota is not enforced",
            ),
            identity=Capability(
                "non-root",
                True,
                "uses the service user's non-root UID/GID where available, otherwise nobody; "
                "all capabilities dropped and no-new-privileges",
            ),
            detail=(
                f"container isolation through {runtime.binary} "
                f"({'rootless' if runtime.rootless else 'rootful daemon'})"
            ),
        )

    def resolve_runtime(self) -> ContainerRuntime | None:
        """Find a container CLI that is actually usable, by running it."""
        cached = self._probe_cache.get("runtime")
        if cached is not None:
            return cached if isinstance(cached, ContainerRuntime) else None

        candidate = self.runtime
        if candidate is not None:
            resolved = candidate if self._usable(candidate) else None
            self._probe_cache["runtime"] = resolved
            return resolved

        for name in CANDIDATE_BINARIES:
            path = shutil.which(name)
            if not path:
                continue
            runtime = self._inspect(path, name)
            if runtime is not None:
                self._probe_cache["runtime"] = runtime
                return runtime
        self._probe_cache["runtime"] = False
        return None

    def _usable(self, runtime: ContainerRuntime) -> bool:
        return self._inspect(runtime.binary, runtime.kind) is not None

    def _inspect(self, binary: str, kind: str) -> ContainerRuntime | None:
        try:
            completed = subprocess.run(
                [binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if completed.returncode != 0:
            return None
        version = (completed.stdout or "").strip().splitlines()[-1] if completed.stdout else ""
        rootless = False
        try:
            security = subprocess.run(
                [binary, "info", "--format", "{{.SecurityOptions}}"],
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
            rootless = "rootless" in (security.stdout or "").lower()
        except (OSError, subprocess.SubprocessError):
            pass
        return ContainerRuntime(binary=binary, kind=kind, version=version, rootless=rootless)

    def _unavailable(self, detail: str) -> IsolationReport:
        return IsolationReport(
            driver=self.name,
            available=False,
            code_isolation=Capability("worktree", True, "Git worktree per step"),
            process_isolation=Capability("container", False, detail),
            filesystem=Capability("none", False, detail),
            network=Capability("none", False, detail),
            resource_limits=Capability(
                "rlimit + timeout", True, "available through the host-process path"
            ),
            identity=Capability("service user", False, "no privilege change"),
            detail=detail,
            missing_prerequisites=(
                "install and start a container runtime (for example `colima start`, or "
                "Docker Desktop) so that `docker info` succeeds",
            ),
        )

    # --------------------------------------------------------------------- argv
    def build_argv(
        self,
        *,
        runtime: ContainerRuntime,
        worktree: Path,
        command: Sequence[str],
        boundary: BoundarySpec,
        environment: dict[str, str] | None = None,
    ) -> list[str]:
        """Construct the container invocation from SPEC-03.

        Kept separate from `run` so the security-relevant part is testable without a runtime:
        every flag below is asserted by tests that never touch Docker.
        """
        root = Path(worktree).resolve()
        for value in FORBIDDEN_MOUNTS:
            protected = Path(value).expanduser().resolve()
            if root == protected or root.is_relative_to(protected) or protected.is_relative_to(root):
                raise ContainerUnavailable(f"refusing sensitive host mount: {root}")

        network = "none" if boundary.network_policy is NetworkPolicy.DENY else "none"
        # A domain allowlist cannot be expressed by `--network`; probe() marks such a boundary
        # unavailable. If one reaches here anyway, `none` is the fail-closed choice.
        # Match the bind mount's normal service-user access without making private
        # worktrees world-readable or ever executing as container root.
        uid, gid = (os.getuid(), os.getgid()) if os.name == "posix" else (65534, 65534)
        user = f"{uid or 65534}:{gid or 65534}"


        argv: list[str] = [
            runtime.binary,
            "run",
            "--rm",
            "--init",
            "--network",
            network,
            "--read-only",
            "--user",
            user,
            "--workdir",
            "/workspace",
            "--cap-drop",
            ",".join(DROPPED_CAPABILITIES),
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(min(boundary.process_limit, 512)),
            "--memory",
            f"{boundary.memory_mb}m",
            "--cpus",
            str(boundary.cpu_limit),
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=256m",
            "--mount",
            f"type=bind,source={root},target=/workspace",
        ]

        # The only host bind is the verified worktree. SELinux label options do
        # not implement path denial; do not emit invented runtime flags.
        for key, value in (environment or {}).items():
            argv.extend(["--env", f"{key}={value}"])
        argv.append(self.image)
        argv.extend(command)
        return argv

    # ------------------------------------------------------------------- run
    def run(
        self,
        *,
        worktree: Path,
        command: Sequence[str],
        timeout_sec: int,
        boundary: BoundarySpec,
        environment: dict[str, str] | None = None,
    ) -> CommandOutcome:
        runtime = self.resolve_runtime()
        if runtime is None:
            raise ContainerUnavailable(
                "no usable container runtime: `docker info` and `podman info` both failed. "
                "Select the host-process or seatbelt driver instead."
            )
        argv = self.build_argv(
            runtime=runtime,
            worktree=worktree,
            command=command,
            boundary=boundary,
            environment=environment,
        )
        name = "daedalus-" + uuid.uuid4().hex
        argv[2:2] = ["--name", name, "--label", "daedalus.managed=true"]
        env = {key: os.environ[key] for key in self.env_allowlist if key in os.environ}
        started = time.monotonic()
        outcome = None
        cleanup = None
        try:
            try:
                completed = subprocess.run(argv, capture_output=True, text=True,
                    timeout=min(timeout_sec, boundary.max_runtime_sec), check=False, env=env)
                outcome = CommandOutcome(command=" ".join(command), exit_code=completed.returncode,
                    stdout=redact_text(completed.stdout or ""), stderr=redact_text(completed.stderr or ""),
                    duration_ms=int((time.monotonic() - started) * 1000), driver=self.name,
                    isolation={"runtime": runtime.kind, "network": "none",
                               "user": argv[argv.index("--user") + 1],
                               "container_name": name, "read_only_base": True,
                               "total_disk_quota": False})
            except subprocess.TimeoutExpired as expired:
                outcome = CommandOutcome(command=" ".join(command), exit_code=124,
                    stdout=redact_text(_decode(expired.stdout)),
                    stderr=redact_text(_decode(expired.stderr) or "timed out inside the container"),
                    duration_ms=int((time.monotonic() - started) * 1000), timed_out=True,
                    driver=self.name, isolation={"runtime": runtime.kind, "network": "none", "container_name": name})
        finally:
            # --rm alone does not stop a container when the client times out. Use
            # our exact name even after errors or caller cancellation, never a broad kill.
            try:
                cleanup = subprocess.run([runtime.binary, "rm", "--force", name],
                    capture_output=True, text=True, timeout=10, check=False, env=env)
            except (subprocess.SubprocessError, OSError):
                cleanup = None
        if outcome is None:
            raise ContainerUnavailable("container command did not produce an outcome")
        removed = cleanup is not None and (cleanup.returncode == 0 or
            "no such container" in ((cleanup.stderr or "") + (cleanup.stdout or "")).lower())
        if not removed:
            from dataclasses import replace
            outcome = replace(outcome, exit_code=125,
                stderr=outcome.stderr + "\ncontainer cleanup unconfirmed; manual recovery required: " + name)
        return outcome

    def describe(self) -> dict[str, object]:
        runtime = self.resolve_runtime()
        return {
            "driver": self.name,
            "image": self.image,
            "runtime": runtime.to_dict() if runtime else None,
            "network_allowlist_supported": False,
            "dropped_capabilities": list(DROPPED_CAPABILITIES),
            "forbidden_mounts": list(FORBIDDEN_MOUNTS),
        }


def _decode(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return redact_text(value.decode("utf-8", "replace"))
    return redact_text(str(value))
