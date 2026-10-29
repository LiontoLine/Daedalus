"""Kill the real controller across Git/SQLite boundaries, then reconcile twice."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys

import pytest

from daedalus.application.recovery import recover_workspace, Finding
from daedalus.application.resume import resume_run
from daedalus.infrastructure.git_sandbox import _git
from daedalus.infrastructure.repository_lock import repository_lock, RepositoryBusy
from daedalus.infrastructure.store import EventStore

ROOT = Path(__file__).resolve().parents[1]
PHASES = [
    "intent",
    "git_commit",
    "integration",
    "artifact_before",
    "artifact_after",
    "artifact_metadata",
    "receipt",
    "publish_before",
    "publish_after",
    "run_closed",
]


def crash(repo, root, phase):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src") + os.pathsep + str(ROOT)}
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests/commit_crash_driver.py"), str(repo), str(root), phase],
        env=env,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == -signal.SIGKILL, result.stderr
    assert json.loads((root / "reached.json").read_text())["phase"] == phase


@pytest.mark.skipif(os.name != "posix", reason="SIGKILL and POSIX repository locks")
@pytest.mark.parametrize("phase", PHASES)
def test_hard_kill_never_duplicates_or_fabricates_a_commit(git_repo, tmp_path, phase):
    base = _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip()
    crash(git_repo, tmp_path, phase)
    refs_before = _git(git_repo, ["show-ref"], check=True).stdout
    count_before = _git(git_repo, ["rev-list", "--all", "--count"], check=True).stdout
    with EventStore(tmp_path / "crash.db") as store:
        step = store.list_steps("run-crash")[0]
        if phase in {
            "intent",
            "git_commit",
            "integration",
            "artifact_before",
            "artifact_after",
            "artifact_metadata",
        }:
            assert step["state"] == "COMMITTING"
            assert not store.idempotent_result("exec-crash:" + step["step_id"] + ":commit")
        else:
            assert step["state"] == "COMMITTED"
            artifact = store.artifacts_for_step(step["step_id"])[-1]
            assert artifact["status"] == "COMMITTED"
            assert json.loads(artifact["document"])["commit"]
            assert artifact["gate_result_ref"]
        dry = recover_workspace(store=store, apply=False, worktrees_root=tmp_path / "worktrees")
        first = recover_workspace(store=store, apply=True, worktrees_root=tmp_path / "worktrees")
        before_events = store.event_count()
        second = recover_workspace(store=store, apply=True, worktrees_root=tmp_path / "worktrees")
        assert store.event_count() == before_events, "a second recovery appended duplicate facts"
        events = store.events_for_execution("exec-crash")
        commits = [e for e in events if e.event_type == "StepCommitted"]
        assert len(commits) <= 1
        if phase in {"integration", "artifact_before", "artifact_after", "artifact_metadata"}:
            assert len(commits) == 1 and commits[0].payload["recovered"], [
                (i.finding.value, i.detail) for i in first.items if not i.repairable
            ]
            assert any(i.finding is Finding.INCOMPLETE_COMMIT and i.action for i in first.items)
            artifact = store.get_artifact(commits[0].payload["artifact_digest"])
            assert artifact["status"] == "COMMITTED"
        if phase in {"intent", "git_commit"}:
            assert not commits
            assert Path(step["worktree_path"]).exists(), "unresolved evidence was deleted"
        if phase in {"publish_after", "run_closed"}:
            assert store.get_run("run-crash")["status"] == "COMPLETED"
            assert len([e for e in events if e.event_type == "RunCompleted"]) == 1
        else:
            assert store.get_run("run-crash")["status"] == "RUNNING"
            assert _git(git_repo, ["rev-parse", "main"], check=True).stdout.strip() == base
        assert not store.verify_sequences()
        assert not store.step_invariant_violations()
    assert _git(git_repo, ["show-ref"], check=True).stdout == refs_before
    assert _git(git_repo, ["rev-list", "--all", "--count"], check=True).stdout == count_before


def test_reconciliation_refuses_a_changed_tree(git_repo, tmp_path):
    crash(git_repo, tmp_path, "integration")
    with EventStore(tmp_path / "crash.db") as store:
        step = store.list_steps("run-crash")[0]
        path = Path(step["worktree_path"]) / "unreviewed.txt"
        path.write_text("unreviewed")
        report = recover_workspace(store=store, apply=True, worktrees_root=tmp_path / "worktrees")
        assert store.get_step(step["step_id"])["state"] == "COMMITTING"
        assert any(
            i.finding is Finding.INCOMPLETE_COMMIT and not i.repairable for i in report.items
        )
        assert path.exists()


def test_explicit_resume_uses_recovered_receipts_without_running_worker(git_repo, tmp_path):
    crash(git_repo, tmp_path, "integration")
    with EventStore(tmp_path / "crash.db") as store:
        recover_workspace(store=store, apply=True, worktrees_root=tmp_path / "worktrees")

        class MustNotRun:
            name = "must-not-run"

            def implement(self, *args):
                raise AssertionError("recovered committed work must never execute again")

        from daedalus.application.service_lifecycle import checkpoint, review_checkpoint
        view = checkpoint(store, "run-crash")
        review_checkpoint(store, "run-crash", reviewed_by="operator",
                          checkpoint_digest=view["checkpoint_digest"], note="reconciled commit receipts checked")
        result = resume_run(
            store=store, run_id="run-crash", workspace=str(tmp_path), worker=MustNotRun()
        )
        assert result.status == "COMPLETED", result.describe()
        assert result.promoted_commit and len(result.commits) == 1
        assert (
            len(
                [
                    e
                    for e in store.events_for_execution("exec-crash")
                    if e.event_type == "StepCommitted"
                ]
            )
            == 1
        )


def test_live_repository_cannot_be_recovered_from_another_process(git_repo, tmp_path):
    crash(git_repo, tmp_path, "integration")
    code = "from pathlib import Path;from daedalus.infrastructure.store import EventStore;from daedalus.application.recovery import recover_workspace;from daedalus.infrastructure.repository_lock import RepositoryBusy;import sys\nwith EventStore(sys.argv[1]) as s:\n try:recover_workspace(store=s,apply=True)\n except RepositoryBusy:sys.exit(23)\n"
    with repository_lock(git_repo):
        # Corrective stages can nest ownership on the same thread.
        with repository_lock(git_repo):
            result = subprocess.run(
                [sys.executable, "-c", code, str(tmp_path / "crash.db")],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=15,
            )
        assert result.returncode == 23, result.stderr


@pytest.mark.parametrize("tamper", ["artifact_tree", "gate_subject"])
def test_recovery_refuses_mismatched_review_evidence(git_repo, tmp_path, tamper):
    crash(git_repo, tmp_path, "integration")
    with EventStore(tmp_path / "crash.db") as store:
        step = store.list_steps("run-crash")[0]
        if tamper == "artifact_tree":
            artifact = store.artifacts_for_step(step["step_id"])[-1]
            document = json.loads(artifact["document"])
            document["extra"]["gated_tree"] = "wrong-reviewed-tree"
            store.record_artifact({**artifact, "document": json.dumps(document)})
        else:
            # Deliberate projection corruption, not a recovery technique.
            store.connection.execute(
                "UPDATE gate_results SET subject_digest='other-spec' WHERE step_id=?",
                (step["step_id"],),
            )
        report = recover_workspace(store=store, apply=True, worktrees_root=tmp_path / "worktrees")
        assert store.get_step(step["step_id"])["state"] == "COMMITTING"
        assert any(
            i.finding is Finding.INCOMPLETE_COMMIT and not i.repairable for i in report.items
        )
        assert not [
            e for e in store.events_for_execution("exec-crash") if e.event_type == "StepCommitted"
        ]


def test_unresolved_committing_evidence_survives_a_failed_run(git_repo, tmp_path):
    from daedalus.application.fsm_service import StateMachineService

    crash(git_repo, tmp_path, "intent")
    with EventStore(tmp_path / "crash.db") as store:
        step = store.list_steps("run-crash")[0]
        StateMachineService(store).transition_run(
            run_id="run-crash",
            execution_id="exec-crash",
            event_type="RunFailed",
            actor="operator",
            payload={"reason": "stop after crash"},
        )
        recover_workspace(store=store, apply=True, worktrees_root=tmp_path / "worktrees")
        assert Path(step["worktree_path"]).is_dir()
        assert store.get_step(step["step_id"])["state"] == "COMMITTING"
        assert store.get_run("run-crash")["status"] == "FAILED"


def test_newer_gate_failure_supersedes_an_old_pass(git_repo, tmp_path):
    from daedalus.application.orchestrator import RunOrchestrator
    from daedalus.domain.spec import SpecBundle
    from daedalus.errors import DaedalusError

    crash(git_repo, tmp_path, "integration")
    with EventStore(tmp_path / "crash.db") as store:
        step = store.list_steps("run-crash")[0]
        artifact = store.artifacts_for_step(step["step_id"])[-1]
        store.record_gate_result(
            gate_result_id="later-failing-gate",
            step_id=step["step_id"],
            execution_id="exec-crash",
            artifact_digest=artifact["artifact_digest"],
            tier=1,
            decision="FAIL",
            subject_digest=step["spec_digest"],
            reasons=["newer regression"],
            violations=[],
            confidence=None,
            evidence={"checks": []},
        )
        bundle = SpecBundle.from_dict(json.loads(store.get_spec(step["spec_digest"])["document"]))
        owner = RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "worktrees",
            bundle=bundle,
            run_id="run-crash",
            execution_id="exec-crash",
        )
        with pytest.raises(DaedalusError, match="no matching passing"):
            owner._reconstruct_gate_outcome(
                step["step_id"], artifact["artifact_digest"], step["node_id"]
            )
        report = recover_workspace(store=store, apply=True, worktrees_root=tmp_path / "worktrees")
        assert store.get_step(step["step_id"])["state"] == "COMMITTING"
        assert any("superseded" in item.detail for item in report.items)
