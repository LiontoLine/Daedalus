"""Per-step worktree pool (Spec §6.4, §7.1, §11.2).

Phase 1 gave a run exactly one worktree, which capped the DAG at one step at a time and
made `Quota.max_parallel_steps` a comment rather than a constraint. This module gives each
step its own worktree so independent nodes can genuinely run at once.

Two decisions make parallelism safe here:

**The run branch is the integration target, not `main`.** Independent steps all branch
from the same integration point, and each one that commits lands on the run branch. Only
when the whole DAG has committed is `main` fast-forwarded. That preserves the Phase-1
property that a partial failure leaves the authoritative branch untouched, while still
allowing real concurrency (Phase 1 could not have both).

**Worktrees are created on the control-plane thread.** Acquisition and release are
serialised; only the worker's own execution runs concurrently. This keeps every Git and
SQLite mutation deterministic while the slow, untrusted part is parallel.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from daedalus.domain.ids import stable_id
from daedalus.errors import DaedalusError
from daedalus.infrastructure.git_sandbox import GitSandbox, _git  # noqa: PLC2701 - same package


class PoolExhausted(DaedalusError):
    code = "pool_exhausted"


@dataclass
class WorktreePool:
    """Owns the worktrees for one run, plus the run branch they integrate into."""

    repo_path: Path
    run_root: Path
    run_id: str
    base_commit: str
    target_branch: str = "main"
    max_size: int = 4
    migrate_worktrees: bool = False

    run_branch: str = field(init=False)
    _live: dict[str, GitSandbox] = field(default_factory=dict, init=False)
    _retired: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self.repo_path = Path(self.repo_path).resolve()
        self.run_root = Path(self.run_root).resolve()
        self.run_root.mkdir(parents=True, exist_ok=True)
        slug = stable_id("runbranch", self.run_id)[len("runbranch_") :][:16]
        self.run_branch = f"daedalus/run/{slug}"
        # The run branch starts exactly at the run's base commit.
        if not self._branch_exists(self.run_branch):
            _git(self.repo_path, ["branch", self.run_branch, self.base_commit], check=True)

    # ------------------------------------------------------------------ lifecycle
    def acquire(self, step_id: str, *, base_commit: str = "", attempt: int = 1) -> GitSandbox:
        """Check out a worktree for one step from an exact commit."""
        if step_id in self._live:
            return self._live[step_id]
        if len(self._live) >= self.max_size:
            raise PoolExhausted(
                f"worktree pool is full ({len(self._live)}/{self.max_size}); admission "
                "control must be applied by the scheduler, not by the pool",
                size=len(self._live),
                max_size=self.max_size,
            )
        base = base_commit or self.integration_head()
        name = f"{self.run_id}/{_safe_slug(step_id)}"
        name += f"/attempt-{attempt}"
        sandbox = GitSandbox.create_from(
            repo_path=self.repo_path,
            run_root=self.run_root,
            name=name,
            base_commit=base,
        )
        self._live[step_id] = sandbox
        return sandbox

    def reopen_step(
        self, step_id: str, *, base_commit: str, worktree_path: str
    ) -> GitSandbox:
        """Re-attach to a worktree kept alive by a parked run."""
        sandbox = GitSandbox.reopen(
            repo_path=self.repo_path,
            worktree_path=worktree_path,
            base_commit=base_commit,
            branch=f"daedalus/{_safe_slug(step_id)}",
        )
        self._live[step_id] = sandbox
        return sandbox

    def park(self) -> None:
        """Stop tracking live worktrees *without deleting them*.

        A parked run is waiting for a human, and the pending change in each worktree is the
        thing being decided on. `destroy()` would throw away the subject of the decision.
        """
        self._retired.extend(self._live)
        self._live.clear()

    def sandbox_for(self, step_id: str) -> GitSandbox | None:
        return self._live.get(step_id)

    def release(self, step_id: str, *, keep: bool = False) -> None:
        """Remove a step's worktree.

        `keep=True` retains the directory but stops tracking it as live, which is what a
        failed step needs: its evidence stays on disk for attribution while the slot is
        returned to the pool.
        """
        sandbox = self._live.pop(step_id, None)
        if sandbox is None:
            return
        if keep:
            self._retired.append(step_id)
            return
        self._remove(sandbox)

    def reset(self, step_id: str) -> None:
        """Discard a step's work, keeping the worktree for a retry."""
        sandbox = self._live.get(step_id)
        if sandbox is not None:
            sandbox.reset_hard()

    def destroy(self, *, keep_failed: bool = True) -> None:
        """Tear the run's worktrees down.

        The run branch is deliberately **not** deleted: on a failed run it holds the
        commits that did succeed, and Spec §12.1 forbids deleting history. On a successful
        run it has already been fast-forwarded into the target branch.
        """
        kept: list[str] = []
        for step_id, sandbox in list(self._live.items()):
            if keep_failed and self._retired and step_id in self._retired:
                kept.append(step_id)
                continue
            self._remove(sandbox)
        self._live.clear()
        _git(self.repo_path, ["worktree", "prune"], check=False)

    # ---------------------------------------------------------------- integration
    def integration_head(self) -> str:
        """Where the next step should branch from."""
        result = _git(
            self.repo_path, ["rev-parse", "--verify", "--quiet", f"refs/heads/{self.run_branch}"],
            check=False,
        )
        return result.stdout.strip() if result.ok else self.base_commit

    def integrate(self, sandbox: GitSandbox) -> str:
        """Fast-forward the run branch onto a step's commit."""
        return sandbox.integrate_into(self.run_branch)

    def contains_commit(self, commit: str) -> bool:
        """True when the run branch already contains `commit`."""
        head = self.integration_head()
        return _is_ancestor(self.repo_path, commit, head)

    def promote_to_target(self, *, expected_commit: str = "") -> str:
        """Fast-forward the authoritative branch onto the run branch.

        Fast-forward only. A run branch that diverged from the target cannot be promoted
        silently, because that would rewrite the authoritative branch (Spec §11.2).
        """
        head = self.integration_head()
        if expected_commit and head != expected_commit:
            raise DaedalusError("integrated head changed after final goal approval; promotion refused")
        current = _git(
            self.repo_path, ["rev-parse", f"refs/heads/{self.target_branch}"], check=True
        ).stdout.strip()
        if current == head:
            return current
        if not _is_ancestor(self.repo_path, current, head):
            raise DaedalusError(
                f"run branch {self.run_branch} diverged from {self.target_branch}; "
                "refusing an automatic promotion",
                target=self.target_branch,
                target_commit=current,
                run_commit=head,
            )
        _git(
            self.repo_path,
            ["update-ref", f"refs/heads/{self.target_branch}", head, current],
            check=True,
        )
        return head

    def describe(self) -> dict[str, object]:
        return {
            "run_branch": self.run_branch,
            "base_commit": self.base_commit,
            "target_branch": self.target_branch,
            "integration_head": self.integration_head(),
            "live_worktrees": sorted(self._live),
            "retired_worktrees": sorted(self._retired),
            "max_size": self.max_size,
        }

    # -------------------------------------------------------------------- helpers
    def _branch_exists(self, branch: str) -> bool:
        return _git(
            self.repo_path, ["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], check=False
        ).ok

    def _remove(self, sandbox: GitSandbox) -> None:
        _git(
            self.repo_path,
            ["worktree", "remove", "--force", str(sandbox.worktree_path)],
            check=False,
        )
        shutil.rmtree(sandbox.worktree_path, ignore_errors=True)


def _safe_slug(step_id: str) -> str:
    """A filesystem- and ref-safe name for a step."""
    return "".join(char if char.isalnum() or char in "-_." else "-" for char in step_id)[-80:]


def _is_ancestor(cwd: Path, ancestor: str, descendant: str) -> bool:
    return _git(cwd, ["merge-base", "--is-ancestor", ancestor, descendant], check=False).exit_code == 0
