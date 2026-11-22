"""Accepted refs must hand off usable files without discarding operator data."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from daedalus.application.worktree_pool import WorktreePool
from daedalus.errors import CommitConflict, DaedalusError
from daedalus.infrastructure.git_sandbox import (
    GitSandbox,
    _git,
    fast_forward_branch,
    init_repo,
    initial_commit,
)


@pytest.fixture
def delivery(tmp_path: Path):
    repo = init_repo(tmp_path / "operator repo with spaces")
    (repo / "app.py").write_text("print('before')\n", encoding="utf-8")
    (repo / "notes.txt").write_text("tracked operator notes\n", encoding="utf-8")
    (repo / ".gitignore").write_text("ignored.txt\nignored-dir/\n", encoding="utf-8")
    base = initial_commit(repo)
    pool = WorktreePool(
        repo_path=repo, run_root=tmp_path / "run workspace", run_id="handoff",
        base_commit=base,
    )
    sandbox = pool.acquire("accepted-step")
    sandbox.write_file("app.py", "print('accepted')\n")
    commit = sandbox.commit("accepted implementation")
    pool.integrate(sandbox)
    return repo, pool, sandbox, base, commit


def _output(repo: Path) -> str:
    return subprocess.run(
        [sys.executable, str(repo / "app.py")], check=True,
        capture_output=True, text=True,
    ).stdout.strip()


@pytest.mark.parametrize("entrypoint", ["pool", "integrate", "integrate_into"])
def test_clean_handoff_updates_the_checkout_and_is_idempotent(delivery, entrypoint):
    repo, pool, sandbox, base, commit = delivery
    workspace = repo / "untracked workspace"
    workspace.mkdir()
    (workspace / "state.json").write_text("operator data", encoding="utf-8")
    assert pool.integration_head() == commit
    assert GitSandbox.main_commit(repo, "main") == base
    assert _output(repo) == "before"

    def deliver():
        if entrypoint == "pool":
            return pool.promote_to_target(expected_commit=commit)
        if entrypoint == "integrate":
            return sandbox.integrate("main", "approved handoff")
        return sandbox.integrate_into("main")

    assert deliver() == commit
    assert GitSandbox.main_commit(repo, "main") == commit
    assert _output(repo) == "accepted"
    assert deliver() == commit
    assert (workspace / "state.json").read_text(encoding="utf-8") == "operator data"
    assert not _git(repo, ["status", "--porcelain", "--untracked-files=no"], check=True).stdout


@pytest.mark.parametrize("change", ["unstaged", "staged", "deleted", "index-only"])
def test_handoff_refuses_pending_tracked_changes(delivery, change):
    repo, pool, _, base, commit = delivery
    notes = repo / "notes.txt"
    original = notes.read_text(encoding="utf-8")
    if change == "deleted":
        notes.unlink()
    else:
        notes.write_text("operator edits\n", encoding="utf-8")
        if change in {"staged", "index-only"}:
            _git(repo, ["add", "notes.txt"], check=True)
        if change == "index-only":
            notes.write_text(original, encoding="utf-8")
    before = _git(repo, ["status", "--porcelain"], check=True).stdout
    with pytest.raises(CommitConflict, match="pending tracked"):
        pool.promote_to_target(expected_commit=commit)
    assert GitSandbox.main_commit(repo, "main") == base
    assert _output(repo) == "before"
    assert _git(repo, ["status", "--porcelain"], check=True).stdout == before
    if change != "deleted":
        assert notes.read_text(encoding="utf-8") == (
            original if change == "index-only" else "operator edits\n"
        )


@pytest.mark.parametrize("path", ["new file.txt", "ignored.txt", "ignored-dir/data.txt"])
def test_handoff_preserves_conflicting_untracked_and_ignored_data(delivery, path):
    repo, pool, sandbox, base, _ = delivery
    sandbox.write_file(path, "accepted addition\n")
    _git(sandbox.worktree_path, ["add", "--force", "--", path], check=True)
    commit = sandbox.commit("accepted addition")
    pool.integrate(sandbox)
    operator_file = repo / path
    operator_file.parent.mkdir(parents=True, exist_ok=True)
    operator_file.write_text("private operator data\n", encoding="utf-8")
    with pytest.raises(DaedalusError):
        pool.promote_to_target(expected_commit=commit)
    assert GitSandbox.main_commit(repo, "main") == base
    assert _output(repo) == "before"
    assert operator_file.read_text(encoding="utf-8") == "private operator data\n"
    assert not _git(repo, ["diff", "--cached", "--name-only"], check=True).stdout


@pytest.mark.parametrize("same_commit", [False, True])
def test_handoff_refuses_a_target_checked_out_in_another_worktree(
    delivery, tmp_path, same_commit,
):
    repo, pool, _, base, commit = delivery
    _git(repo, ["switch", "-c", "operator"], check=True)
    elsewhere = tmp_path / "other operator worktree"
    _git(repo, ["worktree", "add", str(elsewhere), "main"], check=True)
    with pytest.raises(CommitConflict, match="another worktree"):
        fast_forward_branch(repo, "main", base if same_commit else commit)
    assert GitSandbox.main_commit(repo, "main") == base
    assert _output(elsewhere) == "before"
    assert _output(repo) == "before"
    assert pool.integration_head() == commit


def test_same_ref_does_not_hide_a_stale_or_dirty_checkout(delivery):
    repo, pool, _, base, commit = delivery
    # Reproduce an earlier ref-only delivery: the ref is accepted, the files are old.
    _git(repo, ["update-ref", "refs/heads/main", commit, base], check=True)
    with pytest.raises(CommitConflict, match="pending tracked"):
        pool.promote_to_target(expected_commit=commit)
    assert _output(repo) == "before"
    assert GitSandbox.main_commit(repo, "main") == commit


def test_exact_approved_commit_is_required_before_any_handoff(delivery):
    repo, pool, _, base, _ = delivery
    with pytest.raises(DaedalusError, match="changed after final goal approval"):
        pool.promote_to_target(expected_commit=base)
    assert GitSandbox.main_commit(repo, "main") == base
    assert _output(repo) == "before"


def test_unchecked_out_branch_uses_cas_without_touching_operator_checkout(delivery):
    repo, _, _, base, commit = delivery
    _git(repo, ["branch", "release/accepted", base], check=True)
    (repo / "notes.txt").write_text("operator work\n", encoding="utf-8")
    assert fast_forward_branch(
        repo, "refs/heads/release/accepted", commit, expected_old=base
    ) == commit
    assert fast_forward_branch(repo, "release/accepted", commit) == commit
    assert GitSandbox.main_commit(repo, "release/accepted") == commit
    assert GitSandbox.main_commit(repo, "main") == base
    assert (repo / "notes.txt").read_text(encoding="utf-8") == "operator work\n"
    assert fast_forward_branch(repo, "release/accepted", commit, expected_old=base) == commit
    with pytest.raises(CommitConflict, match="moved before handoff"):
        fast_forward_branch(repo, "release/accepted", base, expected_old=base)


def test_bare_target_keeps_exact_cas_delivery(delivery, tmp_path):
    repo, _, _, base, commit = delivery
    bare = tmp_path / "bare target.git"
    _git(repo, ["clone", "--bare", str(repo), str(bare)], check=True)
    assert fast_forward_branch(bare, "main", commit, expected_old=base) == commit
    assert GitSandbox.main_commit(bare, "main") == commit
    assert fast_forward_branch(bare, "main", commit) == commit
    assert fast_forward_branch(bare, "main", commit, expected_old=base) == commit
    with pytest.raises(CommitConflict, match="moved before handoff"):
        fast_forward_branch(bare, "main", base, expected_old=base)
    assert _output(repo) == "before"


@pytest.mark.parametrize("target", ["HEAD", "delivery-alias", "refs/heads/delivery-alias"])
def test_symbolic_branch_names_deliver_to_the_actual_checkout(delivery, target):
    repo, _, _, base, commit = delivery
    _git(repo, ["symbolic-ref", "refs/heads/delivery-alias", "refs/heads/main"], check=True)
    assert fast_forward_branch(repo, target, commit, expected_old=base) == commit
    assert GitSandbox.main_commit(repo, "main") == commit
    assert _output(repo) == "accepted"
    assert fast_forward_branch(repo, target, commit, expected_old=base) == commit


def test_controller_handoff_never_executes_repository_hooks(delivery):
    repo, pool, _, _, commit = delivery
    hook_dir = repo / "operator hooks"
    hook_dir.mkdir()
    marker = repo / "hook-executed"
    for name in ("post-merge", "post-checkout", "reference-transaction"):
        hook = hook_dir / name
        hook.write_text(
            '#!/bin/sh\nprintf "unsafe" > "' + str(marker) + '"\nexit 1\n',
            encoding="utf-8",
        )
        hook.chmod(0o755)
    _git(repo, ["config", "core.hooksPath", str(hook_dir)], check=True)
    assert pool.promote_to_target(expected_commit=commit) == commit
    assert _output(repo) == "accepted"
    assert not marker.exists()


def test_checked_out_cas_race_is_rejected_before_files_are_changed(delivery, monkeypatch):
    repo, _, sandbox, base, commit = delivery
    competitor = GitSandbox.create_from(
        repo_path=repo, run_root=sandbox.run_root, name="competitor", base_commit=base,
    )
    competitor.write_file("notes.txt", "competing commit\n")
    competing_commit = competitor.commit("concurrent target advance")
    original_popen = subprocess.Popen
    raced = False

    def advance_before_ref_lock(command, *args, **kwargs):
        nonlocal raced
        if command[-2:] == ["update-ref", "--stdin"] and not raced:
            raced = True
            _git(repo, ["update-ref", "refs/heads/main", competing_commit, base], check=True)
        return original_popen(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", advance_before_ref_lock)
    with pytest.raises(CommitConflict, match="moved or is locked"):
        fast_forward_branch(repo, "main", commit, expected_old=base)
    assert raced
    assert GitSandbox.main_commit(repo, "main") == competing_commit
    assert _output(repo) == "before"
    assert (repo / "notes.txt").read_text(encoding="utf-8") == "tracked operator notes\n"


@pytest.mark.parametrize(
    ("candidate_path", "operator_path"),
    [("ignored-dir", "ignored-dir/private.txt"), ("ignored.txt/new.txt", "ignored.txt")],
)
def test_handoff_refuses_ignored_file_directory_collisions(
    delivery, candidate_path, operator_path,
):
    repo, pool, sandbox, base, _ = delivery
    sandbox.write_file(candidate_path, "accepted addition\n")
    _git(sandbox.worktree_path, ["add", "--force", "--", candidate_path], check=True)
    commit = sandbox.commit("accepted file-directory transition")
    pool.integrate(sandbox)
    private = repo / operator_path
    private.parent.mkdir(parents=True, exist_ok=True)
    private.write_text("operator data\n", encoding="utf-8")
    with pytest.raises(CommitConflict, match="untracked or ignored"):
        pool.promote_to_target(expected_commit=commit)
    assert private.read_text(encoding="utf-8") == "operator data\n"
    assert GitSandbox.main_commit(repo, "main") == base
    assert _output(repo) == "before"


def test_unrelated_untracked_files_can_share_an_incoming_directory(delivery):
    repo, pool, sandbox, _, _ = delivery
    sandbox.write_file("shared/accepted.txt", "accepted addition\n")
    commit = sandbox.commit("accepted addition in shared directory")
    pool.integrate(sandbox)
    shared = repo / "shared"
    shared.mkdir()
    (shared / "operator.txt").write_text("operator data\n", encoding="utf-8")
    assert pool.promote_to_target(expected_commit=commit) == commit
    assert (shared / "operator.txt").read_text(encoding="utf-8") == "operator data\n"
    assert (shared / "accepted.txt").read_text(encoding="utf-8") == "accepted addition\n"
    assert _output(repo) == "accepted"


def test_integration_can_create_a_previously_unchecked_out_branch(delivery):
    repo, _, sandbox, base, commit = delivery
    assert sandbox.integrate_into("new/accepted") == commit
    assert GitSandbox.main_commit(repo, "new/accepted") == commit
    assert GitSandbox.main_commit(repo, "main") == base
    assert _output(repo) == "before"
