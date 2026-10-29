"""macOS Seatbelt driver (`sandbox-exec`).

A zero-install, kernel-enforced sandbox: it restricts **writes** to the step's worktree and
**denies network access at runtime**, which is the gap the host-process driver leaves open.

It does **not** restrict reads. That is a measured limitation rather than a design choice — see
`build_profile` for the three profile shapes that were tried and what each one did. The honest
summary is: write boundary and network denial, no read confidentiality.

Two honest caveats are built into the code rather than left to documentation:

* Seatbelt distinguishes only allow/deny for the network. It cannot express a domain allowlist,
  so a `network_policy = allowlist` boundary is **not enforceable** by this driver and
  `probe()` says so instead of quietly denying everything and blaming the task.
* `sandbox-exec` is deprecated by Apple. It still works on current releases, but a driver that
  assumed it would work forever is how a security control silently disappears. `probe()`
  therefore *applies a trivial profile* and reports the real answer, and a deployment that has
  lost the ability to sandbox sees `available: false` with the exact error.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from daedalus.domain.spec import BoundarySpec, NetworkPolicy
from daedalus.infrastructure.redact import redact_text
from daedalus.infrastructure.process import run_command, resource_preexec, resource_enforcement
from daedalus.infrastructure.sandbox.base import (
    Capability,
    CommandOutcome,
    IsolationReport,
)

NAME = "seatbelt"
SANDBOX_EXEC = "/usr/bin/sandbox-exec"

#: Read-only system locations a Python process legitimately needs. Deliberately broad: a
#: sandbox that breaks the interpreter is a sandbox operators switch off.
READ_ONLY_ROOTS = (
    "/usr",
    "/System",
    "/Library",
    "/bin",
    "/sbin",
    "/opt/homebrew",
    "/private/var/db/dyld",
    "/dev/null",
    "/dev/urandom",
    "/dev/random",
)


@dataclass(frozen=True, slots=True)
class SeatbeltDriver:
    """Wraps a command in a per-invocation Seatbelt profile derived from SPEC-03."""

    name: str = NAME
    executable: str = SANDBOX_EXEC
    read_only_roots: tuple[str, ...] = READ_ONLY_ROOTS
    env_allowlist: tuple[str, ...] = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
    _probe_cache: dict[str, object] = field(default_factory=dict, repr=False, compare=False)

    # ------------------------------------------------------------------- probe
    def probe(self) -> IsolationReport:
        return self.probe_for_network(NetworkPolicy.DENY)

    def probe_for_network(self, policy: NetworkPolicy) -> IsolationReport:
        """Probe, reporting whether this driver can honour the requested network policy."""
        binary = shutil.which(self.executable) or ""
        if not binary:
            return self._unavailable(
                f"{self.executable} is not present on this host",
                "no sandbox-exec binary",
            )
        if os.name != "posix":
            return self._unavailable("Seatbelt is macOS-only", "a macOS host")

        ok, detail = self._apply_trivial_profile(binary)
        if not ok:
            return self._unavailable(
                "sandbox-exec is present but cannot apply a profile here "
                f"({detail}). The process is probably already inside a sandbox that denies "
                "sandbox_apply.",
                "an unsandboxed process context",
            )
        if policy is NetworkPolicy.ALLOWLIST:
            return IsolationReport(
                driver=self.name,
                available=False,
                code_isolation=Capability("worktree", True, "Git worktree per step"),
                process_isolation=Capability(
                    "seatbelt", True, "sandbox-exec applied a profile successfully"
                ),
                filesystem=Capability(
                    "write-only", True, "writes limited to the worktree; reads unrestricted"
                ),
                network=Capability(
                    "allow/deny only",
                    False,
                    "Seatbelt cannot express a domain allowlist; network_policy=allowlist is "
                    "not enforceable by this driver",
                ),
                resource_limits=Capability(
                    "rlimit + timeout", False, "partial rlimits; no task-wide memory or total disk quota"
                ),
                identity=Capability(
                    "service user", False, "Seatbelt does not change the uid"
                ),
                detail=(
                    "seatbelt works, but the requested allowlist network policy cannot be "
                    "expressed. Refusing rather than silently denying all network."
                ),
                missing_prerequisites=(
                    "a container runtime, for a network allowlist",
                ),
            )
        return IsolationReport(
            driver=self.name,
            available=True,
            code_isolation=Capability("worktree", True, "Git worktree per step"),
            process_isolation=Capability(
                "seatbelt", True, "sandbox-exec applied a profile successfully"
            ),
            filesystem=Capability(
                "write-only",
                True,
                "kernel-enforced: writes are limited to the worktree. Reads are deliberately "
                "NOT restricted — see build_profile for the measured reason.",
            ),
            network=Capability(
                "deny",
                True,
                "`(deny network*)` blocks sockets at runtime, not merely at gate time",
            ),
            resource_limits=Capability(
                "rlimit + timeout", False, "partial rlimits plus timeout; no task-wide memory or total disk quota"
            ),
            identity=Capability(
                "service user",
                False,
                "Seatbelt does not change the uid; the command runs as the service user",
            ),
            detail=(
                "kernel-enforced write boundary and runtime network deny, no container "
                "required. Read confidentiality is NOT provided: use the container driver "
                "for that."
            ),
        )

    def _apply_trivial_profile(self, binary: str) -> tuple[bool, str]:
        cached = self._probe_cache.get("trivial")
        if isinstance(cached, tuple):
            return cached
        try:
            completed = subprocess.run(
                [binary, "-p", "(version 1)(allow default)", "/usr/bin/true"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            result = (False, f"{type(error).__name__}: {error}")
        else:
            if completed.returncode == 0:
                result = (True, "ok")
            else:
                result = (
                    False,
                    (completed.stderr or completed.stdout or "unknown").strip()[:200],
                )
        self._probe_cache["trivial"] = result
        return result

    def _unavailable(self, detail: str, missing: str) -> IsolationReport:
        return IsolationReport(
            driver=self.name,
            available=False,
            code_isolation=Capability("worktree", True, "Git worktree per step"),
            process_isolation=Capability("seatbelt", False, detail),
            filesystem=Capability("none", False, detail),
            network=Capability("none", False, detail),
            resource_limits=Capability(
                "rlimit + timeout", False, "partial rlimits available through the host-process path"
            ),
            identity=Capability("service user", False, "no privilege change"),
            detail=detail,
            missing_prerequisites=(missing,),
        )

    # -------------------------------------------------------------- profile
    def scratch_dir(self, worktree: Path) -> Path:
        """A per-step temp directory that is NOT inside the worktree.

        It is a sibling of the worktree, so it never appears in the diff, and it is the only
        writable location outside the worktree. Setting `TMPDIR` to it is what lets a command
        have a usable temp dir without widening the write boundary.
        """
        root = Path(worktree).resolve()
        return root.parent / ".daedalus-scratch" / root.name

    def build_profile(
        self, *, worktree: Path, boundary: BoundarySpec, scratch: Path | None = None
    ) -> str:
        """Generate the Seatbelt profile for one worktree and one boundary.

        The shape below is the result of measurement, not preference. Three candidate shapes
        were applied on macOS 15 and observed:

        * **restricted reads** (an allowlist of system roots plus the worktree): the dynamic
          loader aborts with SIGABRT even for `/bin/cat`. The set of paths dyld needs differs
          per OS version and includes cryptex paths that are impractical to enumerate.
        * **`(import "system.sb")`** with write/network restrictions layered on top:
          `execvp` fails for `/bin/cat` and `/usr/bin/env`, so nothing runs at all.
        * **open reads with a credential denylist** (`(deny file-read* ...)` after a blanket
          `(allow file-read*)`): the deny does **not** override the blanket allow; a file in
          the denied directory was read successfully. Selective read restriction is therefore
          not expressible this way.

        What remains, and what this profile delivers, is a **kernel-enforced write boundary**
        (writes only inside the worktree) and a **kernel-enforced network deny**. Both were
        verified: a write outside the worktree fails with `Operation not permitted`, and curl
        cannot connect.

        Read confidentiality is explicitly *not* a property of this driver. The trade-off is
        deliberate: a profile that breaks the interpreter is a profile operators switch off,
        and a disabled sandbox protects nothing. Exfiltration is still constrained — the write
        boundary stops it being parked on disk, `(deny network*)` stops it being sent, and the
        gate plus the redactor catch credential shapes inside the artifact. For a real read
        boundary, use the container driver: its view is the container filesystem plus the one
        mount.
        """
        root = Path(worktree).resolve()
        lines = [
            "(version 1)",
            ";; Generated from SPEC-03. Deny by default: anything not listed is refused.",
            "(deny default)",
            ";; A command must be able to execute; the *set* of tools is constrained by",
            ";; SPEC-03 allowed_tools and enforced by the gate, not by this profile.",
            "(allow process*)",
            "(allow sysctl-read)",
            "(allow mach-lookup)",
            ";; Reads are open BY MEASUREMENT, not by preference: a read allowlist aborts the",
            ";; dynamic loader (see the docstring). Read confidentiality needs a container.",
            "(allow file-read*)",
            ";; The write boundary is the enforcement this driver actually provides:",
            ";; kernel-enforced, limited to the step's own worktree.",
            f'(allow file-write* (subpath "{root}"))',
            '(allow file-write* (literal "/dev/null"))',
        ]
        # The scratch directory, and NOT `$TMPDIR` itself. Allowing the inherited `$TMPDIR`
        # silently widened the boundary to the whole system temp directory — on macOS that is
        # `/var/folders/...`, which is also where a test harness puts its own working
        # directories, so a write "outside the worktree" could succeed. Measured, not assumed.
        scratch_path = Path(scratch).resolve() if scratch is not None else self.scratch_dir(root)
        lines.append(f'(allow file-write* (subpath "{scratch_path}"))')

        if boundary.network_policy is NetworkPolicy.DENY:
            lines.append(";; SPEC-03 network_policy = deny, enforced at runtime.")
        else:
            # `probe_for_network` refuses an allowlist boundary, so reaching here means the
            # caller overrode the driver choice. Deny rather than hand out open network.
            lines.append(
                ";; FAIL-CLOSED: an allowlist was requested but Seatbelt cannot express it."
            )
        lines.append("(deny network*)")
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------ run
    def run(
        self,
        *,
        worktree: Path,
        command: Sequence[str],
        timeout_sec: int,
        boundary: BoundarySpec,
        environment: dict[str, str] | None = None,
    ) -> CommandOutcome:
        scratch = self.scratch_dir(worktree)
        scratch.mkdir(parents=True, exist_ok=True)
        profile = self.build_profile(worktree=worktree, boundary=boundary, scratch=scratch)
        env = {key: os.environ[key] for key in self.env_allowlist if key in os.environ}
        # The child's temp dir is the scratch directory, so the profile can keep the write
        # boundary narrow while the command still has somewhere to write.
        env["TMPDIR"] = str(scratch)
        if boundary.network_policy is NetworkPolicy.DENY:
            env["DAEDALUS_NETWORK"] = "deny"
        env.update(environment or {})

        handle = tempfile.NamedTemporaryFile("w", suffix=".sb", delete=False)
        try:
            handle.write(profile)
            handle.close()
            argv = [self.executable, "-f", handle.name, *command]
            started = time.monotonic()
            try:
                completed = run_command(
                    argv,
                    cwd=str(worktree),
                    env=env,
                    timeout=min(timeout_sec, boundary.max_runtime_sec),
                    preexec_fn=resource_preexec(timeout_sec=timeout_sec, boundary=boundary) if os.name == "posix" else None,
                )
                duration = int((time.monotonic() - started) * 1000)
                return CommandOutcome(
                    command=" ".join(command),
                    exit_code=completed.returncode,
                    stdout=redact_text(completed.stdout or ""),
                    stderr=redact_text(completed.stderr or ""),
                    duration_ms=duration,
                    driver=self.name,
                    isolation={
                        "network": boundary.network_policy.value,
                        "filesystem": "seatbelt allowlist",
                        "resources": resource_enforcement(),
                        "process_cleanup": "owned process group",
                    },
                )
            except subprocess.TimeoutExpired as expired:
                duration = int((time.monotonic() - started) * 1000)
                return CommandOutcome(
                    command=" ".join(command),
                    exit_code=124,
                    stdout=_decode(expired.stdout),
                    stderr=redact_text(_decode(expired.stderr) or "timed out"),
                    duration_ms=duration,
                    timed_out=True,
                    driver=self.name,
                    isolation={"network": boundary.network_policy.value},
                )
        finally:
            try:
                os.unlink(handle.name)
            except OSError:
                pass

    def describe(self) -> dict[str, object]:
        return {
            "driver": self.name,
            "executable": self.executable,
            "read_only_roots": list(self.read_only_roots),
            "network_allowlist_supported": False,
        }


def _decode(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return redact_text(value.decode("utf-8", "replace"))
    return redact_text(str(value))
