"""Security policy enforcement (Spec §2.3, §2.4, §7, §8).

This is the module the model is *never* allowed to influence for the current task:
SPEC-03 declares the boundary, and this file is the only thing that interprets it.
`tests/gatekeeper/test_meta_spec.py` asserts the protected-path set is non-empty and
that the Gatekeeper refuses to be modified by the task it is currently judging.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from daedalus.domain.pathglob import matches_any, normalize_path
from daedalus.domain.spec import BoundarySpec, MetaSpec

#: Commands that are refused regardless of SPEC-03, because they either escape the
#: sandbox, reach the network, or destroy evidence.
FORBIDDEN_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sudo", re.compile(r"(^|\s)sudo(\s|$)")),
    ("su", re.compile(r"(^|\s)su(\s+-|$)")),
    ("docker_socket", re.compile(r"/var/run/docker\.sock")),
    ("docker", re.compile(r"(^|\s)docker(\s|$)")),
    ("podman", re.compile(r"(^|\s)podman(\s|$)")),
    ("chmod_777_root", re.compile(r"chmod\s+-R\s+777\s+/(\s|$)")),
    ("rm_rf_root", re.compile(r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+/(\s|$)")),
    ("git_push", re.compile(r"(^|\s)git\s+push")),
    ("git_push_force", re.compile(r"git\s+push\s+.*--force")),
    ("git_reset_hard_origin", re.compile(r"git\s+reset\s+--hard\s+origin/")),
    ("pip_install", re.compile(r"(^|\s)(pip|pip3)\s+install")),
    ("npm_install", re.compile(r"(^|\s)(npm|yarn|pnpm)\s+(i|install|add)(\s|$)")),
    ("apt_get", re.compile(r"(^|\s)(apt|apt-get|brew|yum|dnf|apk)\s+(install|add)(\s|$)")),
    ("curl_pipe_shell", re.compile(r"(curl|wget)\s+[^|]*\|\s*(ba|z|k)?sh")),
    ("eval_remote", re.compile(r"eval\s+\$\(curl")),
    ("ssh", re.compile(r"(^|\s)ssh(\s|$)")),
    ("scp", re.compile(r"(^|\s)scp(\s|$)")),
    ("mount", re.compile(r"(^|\s)mount(\s|$)")),
    ("host_credential_read", re.compile(r"(\$HOME|~)/\.(ssh|aws|config/gcloud|kube)")),
    ("proc_environ_dump", re.compile(r"/proc/[0-9]+/environ")),
    ("history_scrape", re.compile(r"\.(bash_history|zsh_history|netrc|git-credentials)")),
)

#: Paths that are never writable even if SPEC-03 accidentally whitelists them.
ALWAYS_DENIED_PATHS: tuple[str, ...] = (
    ".git/config",
    ".git/hooks/**",
    ".git/objects/**",
    "**/.ssh/**",
    "**/.aws/**",
    "**/.env",
    "**/*.pem",
    "**/*.key",
    "/etc/**",
    "/var/**",
    "/usr/**",
    "**/id_rsa*",
)

#: Network-shaped imports, used as an advisory check when network_policy=deny.
NETWORK_MODULE_HINTS: tuple[str, ...] = (
    "import socket",
    "import requests",
    "import httpx",
    "import urllib",
    "from urllib",
    "import aiohttp",
    "import http.client",
    "import ftplib",
    "import smtplib",
    "import telnetlib",
    "import paramiko",
)

NETWORK_COMMAND_HINTS: tuple[str, ...] = ("curl ", "wget ", "nc ", "ncat ", "telnet ")


@dataclass(frozen=True, slots=True)
class BoundaryDecision:
    allowed: bool
    violations: tuple[str, ...] = ()
    advisories: tuple[str, ...] = ()
    kind: str = ""

    @property
    def is_clean(self) -> bool:
        return self.allowed and not self.violations


@dataclass
class BoundaryGuard:
    """Interprets SPEC-03 + Meta-Spec into allow/deny decisions."""

    boundary: BoundarySpec
    meta: MetaSpec
    _verified: list[str] = field(default_factory=list)

    # -------------------------------------------------------------- filesystem
    def check_paths(self, paths: Iterable[str]) -> BoundaryDecision:
        violations: list[str] = []
        for raw in paths:
            path = normalize_path(raw)
            if not path:
                continue
            if matches_any(ALWAYS_DENIED_PATHS, path):
                violations.append(f"path always denied by the platform policy: {path}")
                continue
            if self.meta.is_protected(path):
                violations.append(
                    f"path is protected by Meta-Spec and may not be modified by a task: {path}"
                )
                continue
            if not self.meta.is_agent_writable(path):
                violations.append(f"path is outside the Meta-Spec agent-writable set: {path}")
                continue
            if not self.boundary.allows_path(path):
                violations.append(
                    f"path is outside the SPEC-03 fs_whitelist: {path}"
                )
        return BoundaryDecision(
            allowed=not violations,
            violations=tuple(violations),
            kind="filesystem",
        )

    def check_diff(self, changed_files: Iterable[str], *, patch: str = "") -> BoundaryDecision:
        decision = self.check_paths(changed_files)
        advisories: list[str] = []

        if self.boundary.network_policy.value == "deny" and patch:
            for hint in NETWORK_MODULE_HINTS:
                if hint in patch:
                    advisories.append(
                        f"added network-capable import under network_policy=deny: {hint!r}"
                    )
            for hint in NETWORK_COMMAND_HINTS:
                if hint in patch:
                    advisories.append(
                        f"added network-capable command under network_policy=deny: {hint.strip()!r}"
                    )

        return BoundaryDecision(
            allowed=decision.allowed,
            violations=decision.violations,
            advisories=tuple(advisories),
            kind="diff",
        )

    def check_dependency_change(self, changed_files: Iterable[str]) -> BoundaryDecision:
        """Spec §7.4: dependencies arrive via a manifest + lock file, never ad hoc."""
        names = {normalize_path(path) for path in changed_files}
        manifest = normalize_path(self.boundary.dependency_manifest) if self.boundary.dependency_manifest else ""
        lock = normalize_path(self.boundary.lock_file) if self.boundary.lock_file else ""
        if not manifest:
            return BoundaryDecision(allowed=True, kind="dependency")
        if manifest in names and lock and lock not in names:
            return BoundaryDecision(
                allowed=False,
                violations=(
                    f"{manifest} changed without the corresponding lock file {lock}; "
                    "dependency changes must be paired with a lock update",
                ),
                kind="dependency",
            )
        return BoundaryDecision(allowed=True, kind="dependency")

    # --------------------------------------------------------------- commands
    def check_command(self, command: str) -> BoundaryDecision:
        if not command.strip():
            return BoundaryDecision(allowed=False, violations=("empty command",), kind="command")
        violations: list[str] = []
        for name, pattern in FORBIDDEN_COMMAND_PATTERNS:
            if pattern.search(command):
                violations.append(f"command matches forbidden pattern {name!r}: {command.strip()}")
        if self.boundary.network_policy.value == "deny":
            for hint in NETWORK_COMMAND_HINTS:
                if hint in command and not any("pattern" in item for item in violations):
                    violations.append(
                        f"command performs network access while network_policy=deny: {command.strip()}"
                    )
                    break
        return BoundaryDecision(
            allowed=not violations,
            violations=tuple(violations),
            kind="command",
        )

    def check_tool(self, tool: str) -> BoundaryDecision:
        if not self.boundary.allows_tool(tool):
            return BoundaryDecision(
                allowed=False,
                violations=(f"tool {tool!r} is not in the SPEC-03 allowed_tools set",),
                kind="tool",
            )
        return BoundaryDecision(allowed=True, kind="tool")

    # ------------------------------------------------------------------ quota
    def check_token_budget(self, tokens_used: int) -> BoundaryDecision:
        if tokens_used > self.boundary.max_tokens_per_step:
            return BoundaryDecision(
                allowed=False,
                violations=(
                    f"token budget exhausted: {tokens_used} > "
                    f"{self.boundary.max_tokens_per_step}",
                ),
                kind="quota",
            )
        return BoundaryDecision(allowed=True, kind="quota")

    def check_runtime(self, elapsed_sec: float) -> BoundaryDecision:
        if elapsed_sec > self.boundary.max_runtime_sec:
            return BoundaryDecision(
                allowed=False,
                violations=(
                    f"runtime budget exhausted: {elapsed_sec:.1f}s > "
                    f"{self.boundary.max_runtime_sec}s",
                ),
                kind="quota",
            )
        return BoundaryDecision(allowed=True, kind="quota")

    def describe(self) -> dict[str, object]:
        return {
            "network_policy": self.boundary.network_policy.value,
            "fs_whitelist": list(self.boundary.fs_whitelist),
            "fs_denylist": list(self.boundary.fs_denylist),
            "max_runtime_sec": self.boundary.max_runtime_sec,
            "max_tokens_per_step": self.boundary.max_tokens_per_step,
            "protected_paths": list(self.meta.protected_paths),
            "human_approval_required": list(self.meta.human_approval_required),
        }
