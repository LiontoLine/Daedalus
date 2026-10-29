#!/usr/bin/env python3
"""Run a small offline DAG in an isolated, durable workspace for the real console.

The worker is scripted. SQLite, Git worktrees, dependency scheduling, tests and gates
are real; this is a UI/control-plane example, never a claim about model competence.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.observability import configure_logging, log_context
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.scheduler import Quota
from daedalus.config import load_settings
from daedalus.domain.ids import utc_now
from daedalus.domain.spec import (
    AcceptanceCriterion, AssertionKind, BoundarySpec, GoalSpec, MetaSpec,
    NetworkPolicy, PlanNode, PlanSpec, RetryPolicy, SpecBundle,
)
from daedalus.infrastructure.git_sandbox import GitSandbox, init_repo, initial_commit
from daedalus.infrastructure.store.event_store import EventStore

DEFAULT_DATA = Path.home() / ".local/share/daedalus/ui-example"
OPS = {
    "step-01-scaffold": {
        "src/textkit/__init__.py": '"""Small text utilities used by the Daedalus UI example."""\nVERSION = "0.1"\n',
        "tests/test_setup.py": 'from textkit import VERSION\n\ndef test_package_version():\n    assert VERSION == "0.1"\n',
    },
    "step-02-words": {
        "src/textkit/words.py": 'def count_words(text: str) -> int:\n    return len(text.split())\n',
        "tests/test_words.py": 'from textkit.words import count_words\n\ndef test_words():\n    assert count_words("hello world") == 2\n\ndef test_empty():\n    assert count_words("") == 0\n\ndef test_whitespace():\n    assert count_words("  one\\n two\\tthree ") == 3\n',
    },
    "step-03-slug": {
        "src/textkit/slug.py": 'def make_slug(text: str) -> str:\n    return "-".join(text.lower().split())\n',
        "tests/test_slug.py": 'from textkit.slug import make_slug\n\ndef test_slug():\n    assert make_slug("Hello World") == "hello-world"\n\ndef test_empty():\n    assert make_slug("") == ""\n\ndef test_spaces():\n    assert make_slug("  One   TWO  ") == "one-two"\n',
    },
    "step-04-summary": {
        "src/textkit/summary.py": 'from textkit.slug import make_slug\nfrom textkit.words import count_words\n\ndef summarize(text: str) -> dict:\n    return {"words": count_words(text), "slug": make_slug(text)}\n',
        "tests/test_summary.py": 'from textkit.summary import summarize\n\ndef test_summary():\n    assert summarize("Hello World") == {"words": 2, "slug": "hello-world"}\n\ndef test_empty():\n    assert summarize("") == {"words": 0, "slug": ""}\n',
    },
}
TITLES = {
    "step-01-scaffold": "建立文本工具包与基础测试",
    "step-02-words": "实现单词统计（并行分支）",
    "step-03-slug": "实现短链接生成（并行分支）",
    "step-04-summary": "汇合两条分支并执行回归测试",
}


@dataclass
class ExampleWorker:
    name: str = "ui-example-scripted-worker"
    worker_id: str = "ui-example-scripted-worker"

    def implement(self, sandbox, context):
        worker = ScriptedWorker(
            ops=tuple(FileOp(op="write", path=path, content=content)
                      for path, content in OPS[context.node.node_id].items()),
            name=self.name, worker_id=self.worker_id,
            summary=TITLES[context.node.node_id] + "；由确定性 worker 生成，模型未参与。",
        )
        return worker.implement(sandbox, context)


def run_example(data_root: Path, *, reuse: bool = False) -> dict:
    data_root.mkdir(parents=True, exist_ok=True)
    latest = data_root / "latest.json"
    if reuse and latest.exists():
        recorded = json.loads(latest.read_text())
        if Path(recorded["database"]).is_file():
            with EventStore(recorded["database"]) as store:
                run = store.get_run(recorded["run_id"])
                if run and run["status"] == "COMPLETED":
                    return recorded
    config = data_root / "console.toml"
    workspace = data_root / "workspace"
    config.write_text(
        '[workspace]\nroot = ' + json.dumps(str(workspace))
        + '\ntarget_branch = "main"\n[service]\nhost = "127.0.0.1"\nport = 13499\n'
        + '[quota]\nmax_parallel_steps = 2\nmax_cpu = 2.0\nmax_memory_mb = 2048\n'
    )
    stamp = utc_now().replace(":", "").replace("-", "").replace(".", "")
    repo = init_repo(data_root / "repositories" / ("textkit-" + stamp))
    (repo / "pyproject.toml").write_text('[tool.pytest.ini_options]\npythonpath = ["src"]\ntestpaths = ["tests"]\n')
    (repo / ".gitignore").write_text('__pycache__/\n.pytest_cache/\n*.pyc\n')
    (repo / "README.md").write_text('# Textkit · Daedalus 执行示例\n\n确定性 worker；真实 DAG、测试、门禁与 Git 提交。没有调用模型。\n')
    initial_commit(repo, "chore: initialize isolated textkit example")
    goal_id = "GOAL-TEXTKIT-" + stamp
    dependencies = {
        "step-01-scaffold": (),
        "step-02-words": ("step-01-scaffold",),
        "step-03-slug": ("step-01-scaffold",),
        "step-04-summary": ("step-02-words", "step-03-slug"),
    }
    test_files = ["tests/test_setup.py", "tests/test_words.py", "tests/test_slug.py", "tests"]
    criteria = tuple(AcceptanceCriterion(
        criterion_id="AC-" + node, kind=AssertionKind.EXIT_CODE,
        statement=TITLES[node], command="python3 -m pytest " + test_path + " -q",
    ) for node, test_path in zip(OPS, test_files, strict=True))
    nodes = tuple(PlanNode(
        node_id=node, objective=TITLES[node], intent=TITLES[node],
        deps=dependencies[node], expected_artifacts=tuple(OPS[node]),
        allowed_tools=("read", "write", "test"), timeout_sec=120,
        retry_policy=RetryPolicy(max_attempts=2),
        extra={"acceptance_criteria": [criterion.to_dict()]},
    ) for node, criterion in zip(OPS, criteria, strict=True))
    bundle = SpecBundle(
        goal=GoalSpec(goal_id=goal_id, objective="文本工具包：单词统计与短链接生成（真实离线执行示例）",
                      acceptance_criteria=criteria,
                      invariants=("只修改独立示例仓库", "不访问网络", "worker 为确定性脚本，未使用模型")),
        plan=PlanSpec(plan_id="PLAN-" + goal_id, goal_id=goal_id, nodes=nodes),
        boundary=BoundarySpec(boundary_id="BOUND-" + goal_id, goal_id=goal_id,
            fs_whitelist=("src/**/*.py", "tests/**/*.py"), network_policy=NetworkPolicy.DENY,
            allowed_tools=("read", "write", "test"), cpu_limit=1, memory_mb=1024,
            max_runtime_sec=120),
        meta=MetaSpec.default(),
    )
    settings = load_settings(str(config))
    settings.ensure_directories()
    configure_logging()
    with EventStore(settings.workspace.database_path) as store:
        engine = RunOrchestrator(
            store=store, repo_path=repo, run_root=settings.workspace.worktrees_path,
            bundle=bundle, worker=ExampleWorker(), quota=Quota(max_parallel_steps=2, max_cpu=2, max_memory_mb=2048),
        )
        engine.register_spec()
        with log_context(run_id=engine.run_id, execution_id=engine.execution_id, component="ui-example"):
            result = engine.run()
        if result.status != "COMPLETED":
            raise RuntimeError(json.dumps(result.describe(), ensure_ascii=False))
        rows = store.list_steps(result.run_id)
        assert len(rows) == 4 and all(row["state"] == "COMMITTED" for row in rows)
        assert not store.verify_sequences()
        event_count = len(store.events_for_execution(result.execution_id))
    # Promotion advances the authoritative ref; the checkout's index may still be at
    # its old base. Verify the landed tree in a fresh worktree, never reset that checkout.
    verify_tree = GitSandbox.create(repo_path=repo, run_root=data_root / "verification",
                                    name="verify-" + result.run_id, base_ref="main")
    try:
        verification = verify_tree.run([sys.executable, "-m", "pytest", "tests", "-q"], timeout_sec=60)
        if not verification.ok:
            raise RuntimeError(verification.combined())
    finally:
        verify_tree.remove()
    report = {
        "run_id": result.run_id, "execution_id": result.execution_id,
        "url": "http://127.0.0.1:13499/execution/" + result.run_id,
        "config": str(config), "database": str(settings.workspace.database_path), "repository": str(repo),
        "status": result.status, "committed_steps": 4, "events": event_count,
        "worker": "scripted (no model calls)", "test_result": verification.stdout.strip(),
    }
    latest.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--reuse", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run_example(args.data_root.expanduser().resolve(), reuse=args.reuse), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
