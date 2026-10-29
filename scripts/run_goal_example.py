#!/usr/bin/env python3
"""Real offline goal-audit correction example; no model or network calls.

The two initial nodes each pass their own criterion, but node two overwrites
node one's implementation. The whole-goal audit catches that regression. A
separate corrective stage restores both behaviors before main is advanced.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import shlex

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.goal_audit import goal_audit_view
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.domain.ids import utc_now
from daedalus.domain.spec import (
    AcceptanceCriterion,
    AssertionKind,
    BoundarySpec,
    GoalSpec,
    MetaSpec,
    PlanNode,
    PlanSpec,
    RetryPolicy,
    SpecBundle,
)
from daedalus.infrastructure.git_sandbox import init_repo, initial_commit
from daedalus.infrastructure.store import EventStore

WORDS = "def count_words(text):\n    return len(text.split())\n"
SLUG = 'def make_slug(text):\n    return "-".join(text.lower().split())\n'


@dataclass
class GoalExampleWorker:
    name: str = "goal-example-scripted-worker"
    worker_id: str = "goal-example-scripted-worker"

    def implement(self, sandbox, context):
        code = (
            WORDS + "\n" + SLUG
            if context.revision_feedback
            else WORDS
            if context.node.node_id == "words"
            else SLUG
        )
        return ScriptedWorker(
            ops=(FileOp(op="write", path="tools.py", content=code),),
            worker_id=self.worker_id,
            summary="确定性 worker：演示跨步骤回归及目标审计修复",
        ).implement(sandbox, context)


def run_example(data_root: Path) -> dict:
    workspace = data_root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().replace(":", "").replace("-", "").replace(".", "")
    repo = init_repo(data_root / "repositories" / stamp)
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    (repo / "README.md").write_text("# 真实离线目标审计示例\n确定性 worker，没有模型调用。\n")
    initial_commit(repo, "initialize goal audit example")

    def criterion(name, code):
        return AcceptanceCriterion(
            criterion_id=name,
            kind=AssertionKind.TEST_RESULT,
            command="python3 -c " + shlex.quote(code),
        )

    words = criterion(
        "words", "from tools import count_words; assert count_words('hello world') == 2"
    )
    slug = criterion(
        "slug", "from tools import make_slug; assert make_slug('Hello World') == 'hello-world'"
    )
    bundle = SpecBundle(
        goal=GoalSpec(
            goal_id="GOAL-AUDIT-EXAMPLE",
            objective="单词统计与短链接生成必须同时可用（真实离线目标审计示例）",
            acceptance_criteria=(words, slug),
        ),
        plan=PlanSpec(
            plan_id="PLAN-AUDIT-EXAMPLE",
            goal_id="GOAL-AUDIT-EXAMPLE",
            nodes=(
                PlanNode(
                    node_id="words",
                    objective="实现单词统计",
                    expected_artifacts=("tools.py",),
                    retry_policy=RetryPolicy(max_attempts=1),
                    extra={"acceptance_criteria": [words.to_dict()]},
                ),
                PlanNode(
                    node_id="slug",
                    objective="实现短链接生成",
                    deps=("words",),
                    expected_artifacts=("tools.py",),
                    retry_policy=RetryPolicy(max_attempts=1),
                    extra={"acceptance_criteria": [slug.to_dict()]},
                ),
            ),
        ),
        boundary=BoundarySpec(
            boundary_id="B",
            goal_id="GOAL-AUDIT-EXAMPLE",
            fs_whitelist=("tools.py",),
            max_runtime_sec=120,
        ),
        meta=MetaSpec.default(),
    )
    with EventStore(workspace / "daedalus.db") as store:
        owner = RunOrchestrator(
            store=store,
            repo_path=repo,
            run_root=workspace / "worktrees",
            bundle=bundle,
            worker=GoalExampleWorker(),
            goal_audit_enabled=True,
            retry_backoff_sec=0,
        )
        owner.register_spec()
        result = owner.run()
        view = goal_audit_view(store, owner.run_id)
        assert result.status == "COMPLETED", result.describe()
        assert [s["decision"] for s in view["stages"]] == ["REVISE", "APPROVE"], view
        assert not store.verify_sequences()
        report = {
            "run_id": owner.run_id,
            "status": result.status,
            "goal_audit": view,
            "promoted_commit": result.promoted_commit,
            "repository": str(repo),
            "database": str(workspace / "daedalus.db"),
            "worker": "scripted; no model calls",
        }
    config = data_root / "console.toml"
    config.write_text(
        "[workspace]\nroot = " + json.dumps(str(workspace)) + '\ntarget_branch = "main"\n'
    )
    report["config"] = str(config)
    (data_root / "latest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root", type=Path, default=Path.home() / ".local/share/daedalus/goal-example"
    )
    args = parser.parse_args()
    print(json.dumps(run_example(args.data_root.resolve()), ensure_ascii=False, indent=2))
