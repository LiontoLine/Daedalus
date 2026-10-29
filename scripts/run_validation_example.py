#!/usr/bin/env python3
"""Offline independent-validation drill in a NEW, isolated demo repository.

The worker and the two principals are scripted fixtures. This proves the control
protocol, not real human independence, model competence or container isolation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.identity import OwnerRegistry
from daedalus.application.independent_validation import IndependentValidationService
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.resume import resume_run
from daedalus.config import load_settings
from daedalus.domain.identity import Role
from daedalus.domain.spec import RiskLevel
from daedalus.domain.validation import ValidationError
from daedalus.infrastructure.git_sandbox import _git, init_repo, initial_commit
from daedalus.infrastructure.store import EventStore


def run_example(root: Path, *, pending=False):
    if root.exists() and any(root.iterdir()):
        raise ValueError("example destination must be empty")
    root.mkdir(parents=True, exist_ok=True)
    repo = init_repo(root / "repo")
    (repo / "app.py").write_text("def count_words(text):\n    return len(text.split(' '))\n")
    (repo / ".gitignore").write_text("__pycache__/\n")
    initial_commit(repo, "initialize independent validation example")
    settings = load_settings(None, workspace_root=str(root / "workspace"))
    settings.ensure_directories()
    with EventStore(settings.workspace.database_path) as store:
        # Public demo fixtures, never a credential for a real workspace.
        identity = OwnerRegistry(
            store,
            environ={
                "DEMO_OWNER_KEY": "demo-owner-key-not-for-production",
                "DEMO_REVIEWER_KEY": "demo-reviewer-key-not-for-production",
            },
        )
        identity.enroll("demo-owner", role=Role.OWNER, secret_env="DEMO_OWNER_KEY")
        identity.enroll("demo-reviewer", role=Role.REVIEWER, secret_env="DEMO_REVIEWER_KEY")
        bundle = DeterministicPlanner().plan(
            PlanRequest(
                request_id="validation-example",
                goal_id="V-EXAMPLE",
                objective="按任意空白计算词数，空文本为 0",
                owner_id="demo-owner",
                risk_level=RiskLevel.HIGH,
                target_paths=("app.py",),
                test_command="python3 -c \"from app import count_words; assert count_words('a  b\\tc') == 3; assert count_words('') == 0\"",
            )
        )
        owner = RunOrchestrator(
            store=store,
            repo_path=repo,
            run_root=settings.workspace.worktrees_path / "run-validation-example",
            run_id="run-validation-example",
            bundle=bundle,
            worker=ScriptedWorker(
                ops=(
                    FileOp(
                        "write", "app.py", "def count_words(text):\n    return len(text.split())\n"
                    ),
                ),
                worker_id="scripted-demo-worker",
            ),
            identity=identity,
            goal_audit_enabled=True,
            independent_validation_levels=("high", "critical"),
            retry_backoff_sec=0,
        )
        owner.register_spec()
        owner.approve_spec(
            approved_by="demo-owner", signature=identity.sign("demo-owner", bundle.digest())
        )
        base = _git(repo, ["rev-parse", "main"], check=True).stdout.strip()
        result = owner.run()
        assert result.status == "AWAITING_APPROVAL"
        assert _git(repo, ["rev-parse", "main"], check=True).stdout.strip() == base
        service = IndependentValidationService(store, identity)
        report = service.evaluate(owner.run_id)
        assert report["checks_passed"]
        notes = (
            "SCRIPTED FIXTURE: checked exact diff, repeated whitespace and empty-input acceptance."
        )
        claim = service.claim(
            owner.run_id, report["validation_id"], decision="APPROVE", review_notes=notes
        )
        same_identity_blocked = False
        try:
            service.attest(
                owner.run_id,
                report["validation_id"],
                validator_id="demo-owner",
                review_notes=notes,
                signature=identity.sign_validation("demo-owner", claim.digest()),
            )
        except ValidationError:
            same_identity_blocked = True
        assert same_identity_blocked
        if not pending:
            service.attest(
                owner.run_id,
                report["validation_id"],
                validator_id="demo-reviewer",
                review_notes=notes,
                signature=identity.sign_validation("demo-reviewer", claim.digest()),
            )
            result = resume_run(
                store=store,
                run_id=owner.run_id,
                workspace=str(settings.workspace.root_path),
                identity=identity,
            )
            assert result.status == "COMPLETED" and result.promoted_commit == report["commit"]
        summary = {
            "root": str(root),
            "workspace": str(settings.workspace.root_path),
            "repo": str(repo),
            "run_id": owner.run_id,
            "status": result.status,
            "base_commit": base,
            "candidate_commit": report["commit"],
            "target_commit": _git(repo, ["rev-parse", "main"], check=True).stdout.strip(),
            "same_identity_blocked": same_identity_blocked,
            "validation": service.view(owner.run_id),
            "event_sequence_errors": store.verify_sequences(),
            "real_model_calls": 0,
            "scope": "scripted worker and demo identities; fresh worktree on same controller; no real human or container evidence",
        }
        (root / "result.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
        return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument(
        "--pending", action="store_true", help="leave the example parked after fresh acceptance"
    )
    args = parser.parse_args()
    print(
        json.dumps(
            run_example(args.destination.expanduser().resolve(), pending=args.pending),
            ensure_ascii=False,
            indent=2,
        )
    )
