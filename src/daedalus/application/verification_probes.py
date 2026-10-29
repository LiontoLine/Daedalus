"""Fixed, isolated verification fixtures; never a general task or approval interface.

Goal probes deliberately script candidates and step reviews to isolate the REAL model's
whole-goal verdict and the unmodified three-stage control path. They are fault injections,
not autonomous coding success samples. Recovery uses ordinary model workers and gates.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

from daedalus.application.benchmark import MeteredClient
from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.gatekeeper.tier2 import ClientReviewer, Tier2Gate
from daedalus.application.goal_audit import goal_audit_view
from daedalus.application.identity import OwnerRegistry
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest, ResourceBounds
from daedalus.application.scheduler import Quota
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind, PlanNode, PlanSpec
from daedalus.infrastructure.git_sandbox import _git, init_repo, initial_commit
from daedalus.infrastructure.knowledge import atomic_json
from daedalus.infrastructure.store import EventStore


def prepare_repo(path: Path, files: dict[str, str]):
    if path.exists():
        raise ValueError("verification repository must be new")
    repo = init_repo(path)
    for name, text in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return repo, initial_commit(repo, "fixed verification fixture")


class InjectedCandidate:
    name = "explicit-goal-fault-injection"

    def __init__(self, kind):
        self.kind, self.calls = kind, 0

    def implement(self, box, context):
        self.calls += 1
        double = "x * 2" if self.kind == "drift" and self.calls > 1 else "x"
        code = (
            f"def add_one(x):\n    return x + 1\n\ndef double(x):\n    return {double}\n"
            f"\n# controlled candidate {self.calls}\n"
        )
        return ScriptedWorker(ops=(FileOp("write", "solution.py", code),)).implement(box, context)


class IsolatedGoalReviewer:
    """Keep step approval a declared control; delegate every GOAL verdict to the model."""

    def __init__(self, client):
        self.client = client
        self.real = ClientReviewer(client=client)
        self.step_controls = 0

    def complete(self, prompt, *, subject_digest):
        if "FINAL GOAL audit" in prompt:
            return self.real.complete(prompt, subject_digest=subject_digest)
        self.step_controls += 1
        return json.dumps(
            {
                "decision": "APPROVE",
                "subject_digest": subject_digest,
                "reasons": ["CONTROLLED step review; only final-goal review is under experiment"],
                "violations": [],
                "confidence": 1.0,
            }
        )


def run_goal_probes(root: Path, client, bounds: ResourceBounds):
    outcomes = []
    for kind in ("drift", "cap"):
        started = time.monotonic()
        directory = root / kind
        repo, original = prepare_repo(
            directory / "repo",
            {
                "solution.py": "def add_one(x):\n    return 0\n\ndef double(x):\n    return 0\n",
                "verify_public.py": (
                    "from solution import add_one\nassert all(add_one(x)==x+1 for x in (-2,0,4))\n"
                ),
            },
        )
        bundle = DeterministicPlanner(bounds=bounds).plan(
            PlanRequest(
                request_id="CONTROLLED-GOAL-PROBE",
                goal_id=f"PROBE-{kind}",
                objective="Implement add_one(x) so it returns x+1 for every integer.",
                invariants=(
                    "The integrated solution.py MUST ALSO implement double(x) == 2*x "
                    "for every integer. "
                    "This is part of the final goal even though the test only covers add_one.",
                ),
                target_paths=("solution.py",),
                test_command="python3 verify_public.py",
            )
        )
        metered = MeteredClient(client, max_calls=4, max_tokens=25000)
        reviewer = IsolatedGoalReviewer(metered)
        worker = InjectedCandidate(kind)
        with EventStore(directory / "events.db") as store:
            owner = RunOrchestrator(
                store=store,
                identity=OwnerRegistry(store),
                repo_path=repo,
                run_root=directory / "worktrees",
                bundle=bundle,
                worker=worker,
                tier2=Tier2Gate(reviewer=reviewer),
                goal_audit_enabled=True,
                quota=Quota(max_tokens_per_run=25000),
                retry_backoff_sec=0,
            )
            owner.register_spec()
            result = owner.run()
            view = goal_audit_view(store, owner.run_id)
            runs = store.list_runs()
            events = [
                {
                    "event_type": e.event_type,
                    "execution_id": e.execution_id,
                    "payload": dict(e.payload),
                }
                for run in runs
                for e in store.events_for_execution(run["execution_id"])
            ]
            head = _git(repo, ["rev-parse", "main"], check=True).stdout.strip()
            decisions = [s["decision"] for s in view["stages"]]
            expected = ["REVISE", "APPROVE"] if kind == "drift" else ["REVISE"] * 3
            checks = {
                "expected_goal_decisions": decisions == expected,
                "initial_included_in_three_stage_cap": view["max_stages"] == 3,
                "expected_child_runs": len(view["iterations"]) == len(expected) - 1,
                "delivery_policy": (result.status == "COMPLETED" and head != original)
                if kind == "drift"
                else (result.status == "AWAITING_APPROVAL" and head == original),
                "event_sequences_valid": not store.verify_sequences(),
                "step_invariants_valid": not store.step_invariant_violations(),
            }
            row = {
                "kind": kind,
                "run_id": owner.run_id,
                "status": result.status,
                "scope": "scripted fault candidates and step reviews; real model final-goal audits",
                "checks": checks,
                "passed": all(checks.values()),
                "goal_audit": view,
                "scripted_candidates": worker.calls,
                "scripted_step_reviews": reviewer.step_controls,
                "model_calls": metered.records,
                "reported_tokens": metered.total,
                "original_commit": original,
                "final_main_commit": head,
                "seconds": time.monotonic() - started,
            }
            atomic_json(directory / "events.json", {"events": events})
            atomic_json(directory / "result.json", row)
            outcomes.append(row)
    report = {
        "outcomes": outcomes,
        "passed": all(r["passed"] for r in outcomes),
        "scope": "controlled goal-loop mechanisms, excluded from natural-task success rate",
    }
    atomic_json(root / "report.json", report)
    return report


def recovery_fixture(root: Path, bounds: ResourceBounds):
    repo, original = prepare_repo(
        root / "repo",
        {
            "first.py": "def first():\n    return 0\n",
            "second.py": "def second():\n    return 0\n",
            "verify_first.py": (
                "import time\nfrom first import first\nassert first()==1\ntime.sleep(12)\n"
            ),
            "verify_second.py": "from second import second\nassert second()==2\n",
        },
    )
    first = AcceptanceCriterion(
        criterion_id="AC-first", kind=AssertionKind.EXIT_CODE, command="python3 verify_first.py"
    )
    second = AcceptanceCriterion(
        criterion_id="AC-second", kind=AssertionKind.EXIT_CODE, command="python3 verify_second.py"
    )
    bundle = DeterministicPlanner(bounds=bounds).plan(
        PlanRequest(
            request_id="RECOVERY-PROBE",
            goal_id="LIVE26-RECOVERY",
            objective="Implement first.first() == 1 and second.second() == 2.",
            target_paths=("first.py", "second.py"),
            test_command="python3 verify_second.py",
            acceptance_criteria=(first, second),
        )
    )
    nodes = tuple(
        PlanNode(
            node_id=name,
            objective=f"Implement {name}.{name}() to return {index} exactly.",
            deps=() if index == 1 else ("first",),
            expected_artifacts=(f"{name}.py",),
            allowed_tools=("read", "write", "test"),
            extra={"acceptance_criteria": [criterion.to_dict()]},
        )
        for index, (name, criterion) in enumerate((("first", first), ("second", second)), 1)
    )
    bundle = replace(
        bundle, plan=PlanSpec(plan_id="RECOVERY-PLAN", goal_id=bundle.goal.goal_id, nodes=nodes)
    )
    bundle.validate()
    return repo, original, bundle
