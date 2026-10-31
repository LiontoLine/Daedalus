"""Reject unpinned, mismatched, corrupt or undeclared dependencies before tests run."""

from dataclasses import replace
import hashlib
from pathlib import Path
import zipfile

import pytest

from daedalus.application.dependencies import (
    DependencyError,
    cache_wheel,
    parse_lock,
    verify_python,
    validate_dependencies,
)
from daedalus.application.gatekeeper.tier1 import Tier1Gate
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.coding_worker import ScriptedWorker, FileOp
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.infrastructure.store import EventStore
from daedalus.infrastructure.git_sandbox import GitSandbox, _git, initial_commit
from tests.conftest import TARGET, TEST_COMMAND, CORRECT_IMPLEMENTATION
from tests.wheel_fixture import make_wheel


def provision(tmp_path, name="demo-dep", version="1.0", **kwargs):
    wheel = make_wheel(tmp_path / "wheels", name, version, **kwargs)
    info = cache_wheel(tmp_path / "dependency-cache", wheel)
    return info, f"{name}=={version} --hash=sha256:{info['sha256']}\n"


def test_real_wheel_hash_record_and_transitive_requirements_are_verified(tmp_path):
    one, lock1 = provision(tmp_path, requires=("other>=2,<3",))
    two, lock2 = provision(tmp_path, "other", "2.1")
    result = verify_python(
        "requirements.txt", "demo-dep>=1\n", lock1 + lock2, tmp_path / "dependency-cache"
    )
    assert len(result["packages"]) == 2
    assert result["downloads"] == 0 and not result["installed"]
    assert result["publisher_signature"] == "not_verified"
    assert result["validation_digest"]


@pytest.mark.parametrize(
    "lock",
    [
        "thing>=1 --hash=sha256:" + "a" * 64,
        "thing==1",
        "thing==1.* --hash=sha256:" + "a" * 64,
        "-r injected.txt",
        "thing @ https://host/a.whl --hash=sha256:" + "a" * 64,
        "thing==1 --hash=sha256:" + "a" * 64 + " --index-url=https://host",
        "thing==1; sys_platform == 'linux' --hash=sha256:" + "a" * 64,
        "thing==1 --hash=sha256:" + "a" * 64 + "\nTHING==2 --hash=sha256:" + "b" * 64,
    ],
)
def test_ambiguous_or_untrusted_locks_are_refused(lock):
    with pytest.raises((DependencyError, ValueError)):
        parse_lock(lock)


def test_cache_corruption_is_not_repaired_or_downloaded(tmp_path):
    info, lock = provision(tmp_path)
    cached = tmp_path / "dependency-cache" / info["sha256"] / info["filename"]
    cached.chmod(0o644)
    cached.write_bytes(b"corrupted")
    with pytest.raises(DependencyError, match="SHA-256"):
        verify_python("requirements.txt", "demo-dep==1.0", lock, tmp_path / "dependency-cache")
    assert cached.read_bytes() == b"corrupted"


def test_lock_cannot_mislabel_a_cached_artifact(tmp_path):
    info, lock = provision(tmp_path)
    with pytest.raises(DependencyError, match="identity"):
        verify_python(
            "requirements.txt",
            "demo-dep==2.0",
            lock.replace("==1.0", "==2.0"),
            tmp_path / "dependency-cache",
        )


def test_transitive_dependency_must_be_present_and_satisfy_constraints(tmp_path):
    info, lock = provision(tmp_path, requires=("other>=2",))
    with pytest.raises(DependencyError, match="missing from lock"):
        verify_python("requirements.txt", "demo-dep==1.0", lock, tmp_path / "dependency-cache")
    _, other = provision(tmp_path, "other", "1.0")
    with pytest.raises(DependencyError, match="violates"):
        verify_python(
            "requirements.txt", "demo-dep==1.0", lock + other, tmp_path / "dependency-cache"
        )


def test_manifest_constraints_extras_and_markers_are_checked(tmp_path):
    _, one = provision(
        tmp_path, requires=("other>=2; extra == 'fast'", "not-here; python_version < '2'")
    )
    _, two = provision(tmp_path, "other", "2.1")
    with pytest.raises(DependencyError, match="missing"):
        verify_python("requirements.txt", "demo-dep[fast]>=1", one, tmp_path / "dependency-cache")
    result = verify_python(
        "pyproject.toml",
        '[project]\nname="app"\ndependencies=["demo-dep[fast]>=1"]\n',
        one + two,
        tmp_path / "dependency-cache",
    )
    assert len(result["packages"]) == 2
    with pytest.raises(DependencyError, match="violates"):
        verify_python("requirements.txt", "demo-dep>=2", one + two, tmp_path / "dependency-cache")


def test_cache_symlinks_and_candidate_local_cache_are_refused(tmp_path):
    info, lock = provision(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path / "dependency-cache", target_is_directory=True)
    with pytest.raises(DependencyError, match="symlink"):
        verify_python("requirements.txt", "demo-dep==1.0", lock, alias)
    from daedalus.domain.spec import BoundarySpec

    boundary = BoundarySpec(
        "B", "G", dependency_manifest="requirements.txt", lock_file="requirements.lock"
    )
    with pytest.raises(DependencyError, match="outside"):
        validate_dependencies(
            boundary=boundary,
            changed_files=(),
            read=lambda p: "",
            cache=tmp_path / "dependency-cache",
            worktree=tmp_path,
        )


@pytest.mark.parametrize(
    "bad_file", ["../escape.py", "/absolute.py", "dir/../../escape.py", "dir\\escape.py"]
)
def test_unsafe_wheel_paths_are_never_cached(tmp_path, bad_file):
    wheel = make_wheel(tmp_path / "wheels", extra_files={bad_file: b"bad"})
    with pytest.raises(DependencyError, match="unsafe"):
        cache_wheel(tmp_path / "cache", wheel)
    assert not (tmp_path / "cache").exists()


def test_record_checksums_are_checked_even_when_outer_hash_is_current(tmp_path):
    wheel = make_wheel(tmp_path / "wheels")
    with zipfile.ZipFile(wheel) as archive:
        files = {n: archive.read(n) for n in archive.namelist()}
    files["demo_dep/__init__.py"] = b"changed after RECORD was generated"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    with pytest.raises(DependencyError, match="RECORD"):
        cache_wheel(tmp_path / "cache", wheel)


def test_undeclared_manifest_change_stops_tests_and_publication(git_repo, tmp_path, monkeypatch):
    bundle = DeterministicPlanner().plan(
        PlanRequest("r", "G", "fix text", (TARGET, "requirements.txt"), TEST_COMMAND)
    )
    calls = []

    def must_not_run(*args, **kwargs):
        calls.append(True)
        raise AssertionError("acceptance cannot run after dependency rejection")

    monkeypatch.setattr(Tier1Gate, "_check_acceptance", must_not_run)
    with EventStore(tmp_path / "events.db") as store:
        owner = RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "trees",
            bundle=bundle,
            worker=ScriptedWorker(
                ops=(
                    FileOp("write", TARGET, CORRECT_IMPLEMENTATION),
                    FileOp("write", "requirements.txt", "unknown==1.0\n"),
                )
            ),
            retry_backoff_sec=0,
        )
        owner.register_spec()
        base = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
        result = owner.run()
        assert result.status != "COMPLETED"
        assert not calls
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == base
        checks = [
            g
            for g in store.gate_results_for_step(store.list_steps(owner.run_id)[0]["step_id"])
            if int(g["tier"]) == 1
        ]
        assert checks and "dependency" in checks[0]["reasons"]


def test_valid_dependencies_are_checked_in_original_and_goal_gates(git_repo, tmp_path):
    info, lock = provision(tmp_path)
    (git_repo / "requirements.txt").write_text("demo-dep>=1\n")
    (git_repo / "requirements.lock").write_text(lock)
    initial_commit(git_repo, "add locked offline dependency")
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            "r",
            "G",
            "fix text",
            (TARGET,),
            TEST_COMMAND,
            dependency_manifest="requirements.txt",
            lock_file="requirements.lock",
        )
    )
    with EventStore(tmp_path / "events.db") as store:
        owner = RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "trees",
            bundle=bundle,
            worker=ScriptedWorker(ops=(FileOp("write", TARGET, CORRECT_IMPLEMENTATION),)),
            goal_audit_enabled=True,
        )
        owner.register_spec()
        result = owner.run()
        assert result.status == "COMPLETED", result.describe()
        goals = store.events_for("goal:" + owner.run_id)
        report = next(e.payload for e in goals if e.event_type == "GoalAuditCompleted")
        assert report["dependency_validation"]["passed"]
        assert (
            report["dependency_validation"]["evidence"]["packages"][0]["sha256"] == info["sha256"]
        )


def test_cli_cache_add_and_verify(tmp_path, capsys):
    from daedalus.cli import main

    wheel = make_wheel(tmp_path / "wheels")
    assert (
        main(
            [
                "dependencies",
                "cache-add",
                "--workspace",
                str(tmp_path / "ws"),
                "--wheel",
                str(wheel),
            ]
        )
        == 0
    )
    info = __import__("json").loads(capsys.readouterr().out)
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("demo-dep>=1\n")
    lock = tmp_path / "requirements.lock"
    lock.write_text("demo-dep==1.0 --hash=sha256:" + info["sha256"] + "\n")
    assert (
        main(
            [
                "dependencies",
                "verify",
                "--workspace",
                str(tmp_path / "ws"),
                "--manifest",
                str(manifest),
                "--lock",
                str(lock),
            ]
        )
        == 0
    )
    assert __import__("json").loads(capsys.readouterr().out)["installed"] is False


def test_dist_info_identity_must_match_the_wheel_not_just_metadata(tmp_path):
    wheel = make_wheel(tmp_path / "wheels")
    with zipfile.ZipFile(wheel) as archive:
        files = {
            n.replace("demo_dep-1.0.dist-info", "other-1.0.dist-info"): archive.read(n)
            for n in archive.namelist()
        }
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    with pytest.raises(DependencyError, match="directory.*identity"):
        cache_wheel(tmp_path / "cache", wheel)


def test_goal_audit_rechecks_cache_instead_of_trusting_original_gate(
    git_repo, tmp_path, monkeypatch
):
    from daedalus.application.goal_audit import audit_delivery

    info, lock = provision(tmp_path)
    (git_repo / "requirements.txt").write_text("demo-dep==1.0\n")
    (git_repo / "requirements.lock").write_text(lock)
    initial_commit(git_repo, "locked dependency")
    bundle = DeterministicPlanner().plan(
        PlanRequest(
            "r",
            "G",
            "fix text",
            (TARGET,),
            TEST_COMMAND,
            dependency_manifest="requirements.txt",
            lock_file="requirements.lock",
        )
    )
    cached = tmp_path / "dependency-cache" / info["sha256"] / info["filename"]
    with EventStore(tmp_path / "events.db") as store:
        owner = RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "trees",
            bundle=bundle,
            worker=ScriptedWorker(ops=(FileOp("write", TARGET, CORRECT_IMPLEMENTATION),)),
            goal_audit_enabled=True,
        )
        owner.register_spec()
        original = audit_delivery

        def tamper_then_audit(*args, **kwargs):
            cached.chmod(0o644)
            cached.write_bytes(b"changed after step gate")
            return original(*args, **kwargs)

        monkeypatch.setattr("daedalus.application.branch_repair.audit_delivery", tamper_then_audit)
        base = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
        result = owner.run()
        assert result.status != "COMPLETED"
        assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == base
