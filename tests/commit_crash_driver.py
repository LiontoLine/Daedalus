"""Independent process used by the hard-kill commit boundary tests."""

import json
import os
from pathlib import Path
import signal
import sys

from daedalus.application.coding_worker import ScriptedWorker, FileOp
from daedalus.application.fsm_service import StateMachineService
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.worktree_pool import WorktreePool
from daedalus.infrastructure.git_sandbox import GitSandbox
from daedalus.infrastructure.store import EventStore
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

repo, directory, phase = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]


def die():
    (directory / "reached.json").write_text(json.dumps({"phase": phase}))
    os.kill(os.getpid(), signal.SIGKILL)


def wrap(cls, method, when, predicate=lambda *a, **k: True):
    original = getattr(cls, method)

    def wrapped(*args, **kwargs):
        matched = predicate(*args, **kwargs)
        if when == "before" and matched:
            die()
        result = original(*args, **kwargs)
        if when == "after" and matched:
            die()
        return result

    setattr(cls, method, wrapped)


if phase == "intent":
    wrap(
        StateMachineService,
        "transition_step",
        "after",
        lambda *a, **kw: kw.get("event_type") == "StepCommitRequested",
    )
elif phase == "git_commit":
    wrap(GitSandbox, "commit_once", "after")
elif phase == "integration":
    wrap(WorktreePool, "integrate", "after")
elif phase in {"artifact_before", "artifact_after"}:
    wrap(EventStore, "update_artifact_status", "before" if phase == "artifact_before" else "after")
elif phase == "artifact_metadata":
    wrap(
        EventStore,
        "record_artifact",
        "after",
        lambda self, document: "commit" in json.loads(document.get("document", "{}")),
    )
elif phase == "receipt":
    import daedalus.application.fsm_service as module

    original = module._commit_step_transaction

    def committed(*args, **kwargs):
        result = original(*args, **kwargs)
        die()
        return result

    module._commit_step_transaction = committed
elif phase in {"publish_before", "publish_after"}:
    wrap(WorktreePool, "promote_to_target", "before" if phase == "publish_before" else "after")
elif phase == "run_closed":
    wrap(
        StateMachineService,
        "transition_run",
        "after",
        lambda *a, **kw: kw.get("event_type") == "RunCompleted",
    )
else:
    raise ValueError(phase)

bundle = DeterministicPlanner().plan(
    PlanRequest(
        request_id="CRASH",
        goal_id="G-CRASH",
        objective="correct whitespace word counting",
        target_paths=(TARGET,),
        test_command=TEST_COMMAND,
    )
)
with EventStore(directory / "crash.db") as store:
    owner = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=directory / "worktrees",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),)
        ),
        run_id="run-crash",
        execution_id="exec-crash",
        goal_audit_enabled=True,
        retry_backoff_sec=0,
    )
    owner.register_spec()
    owner.run()
raise AssertionError("the requested crash point was not reached")
