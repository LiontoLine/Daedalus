"""Compact exact edits must preserve unrelated text and reject an entire stale batch."""

import json
from dataclasses import replace

import pytest

from daedalus.application.coding_worker import FileOp, ModelWorker, apply_file_ops
from daedalus.errors import BoundaryViolation
from daedalus.infrastructure.git_sandbox import GitSandbox
from tests.conftest import TARGET
from tests.test_agent_investigation import context_for
from tests.test_agentic_rag import Controller


@pytest.fixture
def box(git_repo, tmp_path):
    sandbox = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="compact")
    try:
        yield sandbox
    finally:
        sandbox.remove()


def test_exact_replacement_preserves_unicode_and_unrelated_tail(box):
    text = "标题\nold body\n" + "unchanged tail\n" * 2000
    box.write_file(TARGET, text)
    op = FileOp.from_dict(
        {"op": "replace", "path": TARGET, "old_text": "old body", "new_text": "新内容"}
    )
    assert FileOp.from_dict(op.to_dict()) == op
    assert apply_file_ops(box, [op]) == (TARGET,)
    assert box.read_file(TARGET) == text.replace("old body", "新内容")


@pytest.mark.parametrize("new_text", ["", "abc", "\n"])
def test_replace_allows_removal_and_insertion_in_a_unique_snippet(box, new_text):
    box.write_file(TARGET, "left UNIQUE right\n")
    apply_file_ops(box, [FileOp("replace", TARGET, old_text="UNIQUE", new_text=new_text)])
    assert box.read_file(TARGET) == "left " + new_text + " right\n"


@pytest.mark.parametrize("old", ["missing", "ambiguous"])
def test_stale_or_ambiguous_later_edit_leaves_earlier_writes_unapplied(box, old):
    original = box.read_file(TARGET)
    ops = [
        FileOp("write", TARGET, "ambiguous ambiguous"),
        FileOp("write", "new.py", "must not appear"),
        FileOp("replace", TARGET, old_text=old, new_text="changed"),
    ]
    with pytest.raises(ValueError, match="exactly once"):
        apply_file_ops(box, ops)
    assert box.read_file(TARGET) == original and not box.exists("new.py")


def test_sequential_edits_are_validated_against_the_batchs_result(box):
    apply_file_ops(
        box,
        [
            FileOp("write", "new.py", "one two"),
            FileOp("replace", "new.py", old_text="one", new_text="three"),
            FileOp("replace", "new.py", old_text="three two", new_text="four"),
        ],
    )
    assert box.read_file("new.py") == "four"
    with pytest.raises(ValueError):
        apply_file_ops(
            box,
            [
                FileOp("delete", "new.py"),
                FileOp("replace", "new.py", old_text="four", new_text="five"),
            ],
        )
    assert box.read_file("new.py") == "four"


@pytest.mark.parametrize(
    "payload",
    [
        None,
        "operation",
        {"op": "unknown", "path": TARGET},
        {"op": "replace", "path": TARGET, "old_text": "", "new_text": "x"},
        {"op": "replace", "path": TARGET, "old_text": 12, "new_text": "x"},
        {"op": "replace", "path": TARGET, "old_text": "x", "new_text": None},
    ],
)
def test_invalid_operation_shapes_are_rejected(payload):
    with pytest.raises(ValueError):
        FileOp.from_dict(payload)


@pytest.mark.parametrize("outside", [True, False])
def test_symlink_artifact_is_refused_before_prompt_reads_or_model_call(box, tmp_path, outside):
    target = tmp_path / "private.txt" if outside else box.worktree_path / "pyproject.toml"
    if outside:
        target.write_text("private text that must never reach the model")
    path = box.worktree_path / TARGET
    path.unlink()
    path.symlink_to(target)
    client = Controller([])
    result = ModelWorker(client).implement(box, context_for(box))
    assert not result.ok and result.error == "boundary_violation" and client.calls == []


def test_late_symlink_or_directory_rejects_the_whole_batch(box, tmp_path):
    original = box.read_file(TARGET)
    private = tmp_path / "private.txt"
    private.write_text("untouched")
    (box.worktree_path / "alias.py").symlink_to(private)
    with pytest.raises(BoundaryViolation):
        apply_file_ops(
            box,
            [
                FileOp("write", TARGET, "changed"),
                FileOp("replace", "alias.py", old_text="untouched", new_text="bad"),
            ],
        )
    assert box.read_file(TARGET) == original and private.read_text() == "untouched"
    with pytest.raises(BoundaryViolation):
        apply_file_ops(box, [FileOp("write", TARGET, "changed"), FileOp("write", "src", "bad")])
    assert box.read_file(TARGET) == original


def test_worker_reports_compact_operation_and_marks_incomplete_source_views(box):
    source = "UNIQUE visible snippet\n" + "preserve trailing content\n" * 700
    box.write_file(TARGET, source)
    model = Controller(
        [
            {
                "operations": [
                    {
                        "op": "replace",
                        "path": TARGET,
                        "old_text": "UNIQUE visible snippet",
                        "new_text": "updated snippet",
                    }
                ]
            }
        ]
    )
    result = ModelWorker(client=model).implement(box, context_for(box))
    assert result.ok and box.read_file(TARGET) == source.replace(
        "UNIQUE visible snippet", "updated snippet"
    )
    assert "TRUNCATED" in model.calls[0][-1].content
    assert result.extra["generation"]["edit_operations"] == {"replace": 1}
    receipt = json.loads(result.execution_log.splitlines()[0].removeprefix("GENERATION "))
    assert receipt["max_output_tokens"] == 8192 and receipt["edit_operations"] == {"replace": 1}


def test_worker_returns_actionable_stale_edit_failure_without_mutation(box):
    before = box.read_file(TARGET)
    client = Controller(
        [
            {
                "operations": [
                    {"op": "write", "path": TARGET, "content": "new"},
                    {"op": "replace", "path": TARGET, "old_text": "wrong", "new_text": "other"},
                ]
            }
        ]
    )
    result = ModelWorker(client).implement(box, context_for(box))
    assert not result.ok and result.error == "invalid_edit_plan"
    assert box.read_file(TARGET) == before


def test_stale_feedback_locates_the_frozen_task_not_a_hallucinated_symbol(box):
    text = "".join(
        f"class Distractor{i}:\n    def compute(self):\n        return 'unrelated-{i}'\n\n"
        for i in range(100)
    ) + "class Target:\n    def compute(self):\n        return 'required-behavior'\n"
    box.write_file(TARGET, text)
    context = context_for(box)
    context = replace(
        context,
        node=replace(context.node, objective="Target.compute", intent="Target.compute"),
        bundle=replace(context.bundle, goal=replace(context.bundle.goal, objective="Target.compute")),
    )
    client = Controller([{"operations": [{
        "op": "replace", "path": TARGET,
        "old_text": "class Distractor0:\n    def compute(self):\n        return 'imagined'",
        "new_text": "class Distractor0:\n    def compute(self):\n        return 'wrong'",
    }]}])
    result = ModelWorker(client).implement(box, context)
    assert result.error == "invalid_edit_plan"
    assert "return 'required-behavior'" in result.execution_log
    assert box.read_file(TARGET) == text
