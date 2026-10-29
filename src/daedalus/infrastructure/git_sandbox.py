"""Git worktree isolation (Spec §7.1, §11).

A worktree is the *code* boundary; it is not the *process* boundary. Phase 1 keeps
process isolation to rlimits, a scrubbed environment, a timeout and a network-deny
policy at the gate. Container isolation is a Phase 3 concern and is tracked as such —
this module does not pretend to be a container.

Two invariants make commit safety work:

1. A step's worktree is created from an exact base commit and never re-based behind
   the caller's back.
2. A diff is only ever integrated after it has been checked against the SPEC-03
   filesystem whitelist *and* the Meta-Spec protected paths.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from daedalus.domain.pathglob import normalize_path
from daedalus.errors import CommitConflict, DaedalusError
from daedalus.infrastructure.redact import redact_text
from daedalus.infrastructure.process import command_output_excerpt, run_command, resource_preexec

DEFAULT_GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "/bin/echo",
    "GIT_AUTHOR_NAME": "daedalus",
    "GIT_AUTHOR_EMAIL": "daedalus@localhost",
    "GIT_COMMITTER_NAME": "daedalus",
    "GIT_COMMITTER_EMAIL": "daedalus@localhost",
}


class GitError(DaedalusError):
    code = "git_error"


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    error_code: str = ""

    @property
    def failure_code(self) -> str:
        from daedalus.infrastructure.process import command_failure_code
        return self.error_code or command_failure_code(self.exit_code, self.stderr)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def combined(self, limit: int = 20_000) -> str:
        text = (self.stdout + ("\n" if self.stdout and self.stderr else "") + self.stderr).strip()
        return command_output_excerpt(text, limit)


@dataclass
class DiffSummary:
    files: tuple[str, ...] = ()
    patch: str = ""
    stat: str = ""
    untracked: tuple[str, ...] = ()
    insertions: int = 0
    deletions: int = 0

    @property
    def is_empty(self) -> bool:
        return not self.files and not self.untracked


@dataclass
class GitSandbox:
    """One isolated worktree, plus the git operations the control plane needs."""

    repo_path: Path
    worktree_path: Path
    branch: str
    base_commit: str
    run_root: Path
    _created: bool = True

    # ------------------------------------------------------------------ factory
    @staticmethod
    def main_commit(repo_path: str | Path, ref: str = "HEAD") -> str:
        result = _git(Path(repo_path), ["rev-parse", ref], check=True)
        return result.stdout.strip()

    @staticmethod
    def create(
        *,
        repo_path: str | Path,
        run_root: str | Path,
        name: str,
        base_ref: str = "HEAD",
    ) -> "GitSandbox":
        repo = Path(repo_path).resolve()
        return GitSandbox.create_from(
            repo_path=repo, run_root=run_root, name=name, base_commit=GitSandbox.main_commit(repo, base_ref)
        )

    @staticmethod
    def create_from(
        *,
        repo_path: str | Path,
        run_root: str | Path,
        name: str,
        base_commit: str,
    ) -> "GitSandbox":
        """Create a worktree pinned to an exact commit.

        Pinning to a commit rather than a ref is what makes a parallel DAG run possible:
        two independent steps must both start from the *same* integration point instead
        of racing on whatever HEAD happens to be.
        """
        repo = Path(repo_path).resolve()
        root = Path(run_root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        worktree = root / name
        branch = f"daedalus/{name}"

        if worktree.exists():
            shutil.rmtree(worktree, ignore_errors=True)
        _git(repo, ["worktree", "prune"], check=False)
        _git(repo, ["branch", "-D", branch], check=False)
        added = _git(
            repo, ["worktree", "add", "--detach", str(worktree), base_commit], check=False
        )
        if not added.ok:
            raise GitError(
                f"cannot create a worktree at {base_commit[:12]}: {added.stderr.strip()[:300]}"
            )
        # A detached worktree keeps the run branch out of the way; the step's own branch
        # is created lazily on first commit, so a step that never commits leaves no ref.
        return GitSandbox(
            repo_path=repo,
            worktree_path=worktree,
            branch=branch,
            base_commit=base_commit,
            run_root=root,
            _created=True,
        )

    # ------------------------------------------------------------------ branches
    def branch_exists(self, branch: str) -> bool:
        return _git(
            self.repo_path, ["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], check=False
        ).ok

    def ensure_branch(self, branch: str, commit: str) -> str:
        """Create `branch` at `commit` if absent; return its current head."""
        if not self.branch_exists(branch):
            _git(self.repo_path, ["branch", branch, commit], check=True)
        return self.main_head(branch)

    def contains(self, branch: str, commit: str) -> bool:
        """True when `commit` is already an ancestor of `branch`."""
        existing = self.main_head(branch) if self.branch_exists(branch) else ""
        if not existing:
            return False
        return _is_ancestor_of(self.repo_path, commit, existing)

    def delete_branch(self, branch: str) -> None:
        _git(self.repo_path, ["branch", "-D", branch], check=False)

    @staticmethod
    def reopen(
        *,
        repo_path: str | Path,
        worktree_path: str | Path,
        base_commit: str,
        branch: str = "",
    ) -> "GitSandbox":
        """Re-attach to an existing worktree WITHOUT touching its contents.

        `create_from` deliberately deletes and recreates; that is right for a fresh step and
        catastrophic for a resumed one, where the whole point is that the pending change is
        still sitting in the working tree waiting for a decision.
        """
        repo = Path(repo_path).resolve()
        worktree = Path(worktree_path).resolve()
        if not worktree.is_dir():
            raise GitError(
                f"cannot resume: worktree {worktree} no longer exists. Re-run the step "
                "instead of resuming it."
            )
        if not (worktree / ".git").exists():
            raise GitError(f"cannot resume: {worktree} is not a Git worktree")
        head = _git(worktree, ["rev-parse", "HEAD"], check=False)
        if not head.ok:
            raise GitError(f"cannot resume: {worktree} has no usable HEAD")
        return GitSandbox(
            repo_path=repo,
            worktree_path=worktree,
            branch=branch,
            base_commit=base_commit,
            run_root=worktree.parent,
            _created=False,
        )

    # -------------------------------------------------------------------- reads
    def head(self) -> str:
        return _git(self.worktree_path, ["rev-parse", "HEAD"], check=True).stdout.strip()

    def current_branch(self) -> str:
        return _git(self.worktree_path, ["rev-parse", "--abbrev-ref", "HEAD"], check=True).stdout.strip()

    def main_head(self, ref: str = "HEAD") -> str:
        return _git(self.repo_path, ["rev-parse", ref], check=True).stdout.strip()

    def status_porcelain(self) -> list[str]:
        out = _git(self.worktree_path, ["status", "--porcelain"], check=True).stdout
        return [line for line in out.splitlines() if line.strip()]

    def changed_files(self) -> tuple[str, ...]:
        """Every path this worktree has touched, tracked or not, relative to base."""
        tracked = _git(
            self.worktree_path,
            ["diff", "--name-only", self.base_commit],
            check=True,
        ).stdout
        staged = _git(self.worktree_path, ["diff", "--name-only", "--cached"], check=True).stdout
        untracked = _git(
            self.worktree_path,
            ["ls-files", "--others", "--exclude-standard"],
            check=True,
        ).stdout
        names = set()
        for blob in (tracked, staged, untracked):
            for line in blob.splitlines():
                if line.strip():
                    names.add(normalize_path(line.strip()))
        return tuple(sorted(names))

    def diff(self) -> DiffSummary:
        """Full diff of the worktree against its base commit, including new files."""
        self.stage_all()
        patch = _git(
            self.worktree_path,
            ["diff", "--cached", "--no-color", "--no-ext-diff", "--unified=3", self.base_commit],
            check=True,
        ).stdout
        stat = _git(
            self.worktree_path,
            ["diff", "--cached", "--shortstat", self.base_commit],
            check=True,
        ).stdout.strip()
        numstat = _git(
            self.worktree_path,
            ["diff", "--cached", "--numstat", self.base_commit],
            check=True,
        ).stdout
        files: list[str] = []
        insertions = deletions = 0
        for line in numstat.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            added, removed, path = parts
            files.append(normalize_path(path))
            insertions += int(added) if added.isdigit() else 0
            deletions += int(removed) if removed.isdigit() else 0
        return DiffSummary(
            files=tuple(sorted(set(files))),
            patch=patch,
            stat=stat,
            untracked=tuple(
                normalize_path(p)
                for p in _git(
                    self.worktree_path, ["ls-files", "--others", "--exclude-standard"], check=True
                ).stdout.splitlines()
                if p.strip()
            ),
            insertions=insertions,
            deletions=deletions,
        )

    @staticmethod
    def read_file_at(repo_path: str | Path, commit: str, relative_path: str) -> str:
        """Read a blob at a commit without checking anything out.

        Needed to compute a dependency digest for a step that may turn out to be a cache
        hit: paying for a full checkout just to decide *not* to run would defeat the point.
        """
        result = _git(
            Path(repo_path),
            ["show", f"{commit}:{normalize_path(relative_path)}"],
            check=False,
        )
        return result.stdout if result.ok else ""

    def read_file(self, relative_path: str) -> str:
        path = self.worktree_path / normalize_path(relative_path)
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    def exists(self, relative_path: str) -> bool:
        return (self.worktree_path / normalize_path(relative_path)).exists()

    def list_files(self) -> tuple[str, ...]:
        out = _git(
            self.worktree_path,
            ["ls-files", "--cached", "--others", "--exclude-standard"],
            check=True,
        ).stdout
        return tuple(sorted(normalize_path(line) for line in out.splitlines() if line.strip()))

    # ------------------------------------------------------------------- writes
    def resolve_inside(self, relative_path: str) -> Path:
        """Resolve a repo-relative path, refusing traversal and absolute paths.

        `normalize_path` silently collapses `../`, which is the right behaviour for
        interpreting a boundary pattern but the wrong behaviour for executing a write:
        `../../etc/passwd` would quietly become `<worktree>/etc/passwd`. Here we detect
        the attempt and refuse it, and then still verify containment as a second layer.
        """
        raw = relative_path.replace("\\", "/").strip()
        if raw.startswith("/") or (len(raw) > 1 and raw[1] == ":"):
            raise GitError(f"refusing an absolute path inside the worktree: {relative_path}")
        if ".." in raw.split("/"):
            raise GitError(f"refusing a path containing '..': {relative_path}")

        root = self.worktree_path.resolve()
        candidate = (root / raw).resolve()
        if candidate != root and root not in candidate.parents:
            raise GitError(f"refusing to touch a path outside the worktree: {relative_path}")
        return candidate

    def write_file(self, relative_path: str, content: str) -> Path:
        """Write inside the worktree only, refusing to escape it."""
        resolved = self.resolve_inside(relative_path)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        return resolved

    def delete_file(self, relative_path: str) -> None:
        path = self.resolve_inside(relative_path)
        if path.is_file():
            path.unlink()

    def stage_all(self) -> None:
        _git(self.worktree_path, ["add", "-A"], check=True)

    def reset_hard(self) -> None:
        """Discard everything. Used when a step is REVISE'd inside the same attempt."""
        _git(self.worktree_path, ["reset", "--hard", self.base_commit], check=True)
        _git(self.worktree_path, ["clean", "-fdx"], check=True)

    def tree_digest(self) -> str:
        """Digest of the staged index — the identity of the *content* being committed.

        Captured at gate time so a crashed run can recognise work it had already
        validated, without the control plane fabricating commit timestamps to force a
        reproducible SHA (real commit dates are audit evidence and are preserved).
        """
        self.stage_all()
        return _git(self.worktree_path, ["write-tree"], check=True).stdout.strip()

    def commit(self, message: str) -> str:
        self.stage_all()
        if not self.diff().patch.strip():
            raise GitError("refusing to create an empty commit")
        _git(self.worktree_path, ["commit", "-m", message, "--no-verify"], check=True)
        return self.head()

    def commit_once(self, message: str, *, expected_tree: str = "") -> str:
        """Commit, or return the existing commit when this exact content is already in.

        Recovery contract: if HEAD is not the base and its tree matches the tree that was
        gated, the commit already exists and must be reused rather than recreated. This
        closes the window between `git commit` and the control-plane transaction.
        """
        head = self.head()
        if head != self.base_commit and expected_tree:
            head_tree = _git(
                self.worktree_path, ["rev-parse", f"{head}^{{tree}}"], check=True
            ).stdout.strip()
            if head_tree == expected_tree:
                return head
        return self.commit(message)

    def rebase_onto(self, upstream: str) -> tuple[bool, str]:
        """Rebase this worktree's commit onto `upstream`.

        Returns `(ok, detail)`. A conflict is aborted rather than left half-applied, so
        the worktree stays usable for the REVISE that must follow.
        """
        result = _git(
            self.worktree_path,
            ["-c", "rebase.autostash=false", "rebase", upstream],
            check=False,
        )
        if result.ok:
            return True, self.head()
        conflicts = _git(
            self.worktree_path, ["diff", "--name-only", "--diff-filter=U"], check=False
        ).stdout
        _git(self.worktree_path, ["rebase", "--abort"], check=False)
        detail = conflicts.strip() or result.stderr.strip()[:400]
        return False, detail

    # ------------------------------------------------------------- integration
    def assert_base_matches_main(self, ref: str = "HEAD") -> None:
        """Spec §11.2: never force-push over authoritative history."""
        current = self.main_head(ref)
        if current != self.base_commit:
            raise CommitConflict(
                f"main {ref} moved from {self.base_commit[:12]} to {current[:12]}; "
                "the run must rebase and re-gate instead of overwriting history",
                base_commit=self.base_commit,
                main_commit=current,
            )

    def integrate_into(self, target_branch: str) -> str:
        """Fast-forward `target_branch` onto this worktree's HEAD.

        Used for per-step integration into the *run* branch. Compare-and-swap on the
        branch's current value, so a concurrent advance fails loudly instead of being
        silently overwritten.
        """
        commit = self.head()
        current = self.main_head(target_branch) if self.branch_exists(target_branch) else ""
        if current == commit:
            return commit
        if not current:
            _git(self.repo_path, ["branch", target_branch, commit], check=True)
            return commit
        if not _is_ancestor_of(self.worktree_path, current, commit):
            raise CommitConflict(
                f"commit {commit[:12]} does not descend from {target_branch} "
                f"{current[:12]}; a rebase and re-gate is required",
                target=target_branch,
                branch_commit=current,
                worktree_commit=commit,
            )
        _git(
            self.repo_path,
            ["update-ref", f"refs/heads/{target_branch}", commit, current],
            check=True,
        )
        return commit

    def integrate(self, target_branch: str, message: str) -> str:
        """Fast-forward the target branch onto this worktree's HEAD.

        Refuses anything that is not a fast-forward, so history is never rewritten and
        `git push --force` is never needed (Spec §11.2).

        `expected_old` is read at the moment of the ref update, which makes concurrent
        advancement of the target branch a compare-and-swap failure rather than a
        silent overwrite.
        """
        commit = self.head()
        current = self.main_head(target_branch)
        if current == commit:
            return commit
        if not _is_ancestor_of(self.worktree_path, current, commit):
            raise CommitConflict(
                f"the worktree commit {commit[:12]} does not descend from "
                f"{target_branch} {current[:12]}; a rebase and re-gate is required "
                "instead of overwriting history",
                target=target_branch,
                main_commit=current,
                worktree_commit=commit,
            )
        _git(
            self.repo_path,
            ["update-ref", f"refs/heads/{target_branch}", commit, current],
            check=True,
        )
        return commit

    # ---------------------------------------------------------------- process
    def run(
        self,
        command: list[str],
        *,
        timeout_sec: int = 60,
        env_allowlist: tuple[str, ...] = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"),
        extra_env: dict[str, str] | None = None,
        cwd: str | None = None,
        network: bool = False,
        boundary: object | None = None,
    ) -> CommandResult:
        """Run a command with a scrubbed environment, a hard timeout and rlimits."""
        workdir = (self.worktree_path / cwd) if cwd else self.worktree_path
        env = {key: os.environ[key] for key in env_allowlist if key in os.environ}
        env.update(DEFAULT_GIT_ENV)
        if not network:
            env["DAEDALUS_NETWORK"] = "deny"
        env.update(extra_env or {})

        started = time.monotonic()
        try:
            completed = run_command(
                command,
                cwd=str(workdir),
                env=env,
                timeout=timeout_sec,
                preexec_fn=resource_preexec(timeout_sec=timeout_sec, boundary=boundary) if os.name == "posix" else None,
            )
            duration = int((time.monotonic() - started) * 1000)
            return CommandResult(
                command=" ".join(command),
                exit_code=completed.returncode,
                stdout=redact_text(completed.stdout or ""),
                stderr=redact_text(completed.stderr or ""),
                duration_ms=duration,
            )
        except subprocess.TimeoutExpired as expired:
            duration = int((time.monotonic() - started) * 1000)
            return CommandResult(
                command=" ".join(command),
                exit_code=124,
                stdout=redact_text((expired.stdout or b"").decode("utf-8", "replace") if isinstance(expired.stdout, bytes) else (expired.stdout or "")),
                stderr=redact_text((expired.stderr or b"").decode("utf-8", "replace") if isinstance(expired.stderr, bytes) else (expired.stderr or "")),
                duration_ms=duration,
                timed_out=True,
            )

    # ----------------------------------------------------------------- cleanup
    def remove(self) -> None:
        if not self._created:
            return
        _git(self.repo_path, ["worktree", "remove", "--force", str(self.worktree_path)], check=False)
        shutil.rmtree(self.worktree_path, ignore_errors=True)
        _git(self.repo_path, ["branch", "-D", self.branch], check=False)
        _git(self.repo_path, ["worktree", "prune"], check=False)
        self._created = False


def _git(cwd: Path, args: list[str], *, check: bool) -> CommandResult:
    env = dict(os.environ)
    env.update(DEFAULT_GIT_ENV)
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    result = CommandResult(
        command="git " + " ".join(args),
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        duration_ms=0,
    )
    if check and not result.ok:
        raise GitError(
            f"git {' '.join(args)} failed ({result.exit_code}): {result.stderr.strip()[:400]}"
        )
    return result


def init_repo(path: str | Path, *, branch: str = "main") -> Path:
    """Create a repository with a deterministic initial commit (used by the demo)."""
    repo = Path(path).resolve()
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, ["init", "-q", "-b", branch], check=True)
    _git(repo, ["config", "user.email", "daedalus@localhost"], check=True)
    _git(repo, ["config", "user.name", "daedalus"], check=True)
    _git(repo, ["config", "commit.gpgsign", "false"], check=True)
    return repo


def initial_commit(repo: str | Path, message: str = "chore: initial scaffold") -> str:
    root = Path(repo).resolve()
    _git(root, ["add", "-A"], check=True)
    _git(root, ["commit", "-q", "-m", message, "--no-verify", "--allow-empty"], check=True)
    return _git(root, ["rev-parse", "HEAD"], check=True).stdout.strip()


def _is_ancestor_of(cwd: Path, ancestor: str, descendant: str) -> bool:
    result = _git(cwd, ["merge-base", "--is-ancestor", ancestor, descendant], check=False)
    return result.exit_code == 0
