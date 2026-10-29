"""Semantic review receives actual bounded dependencies, not guessed helper APIs."""

import json
from dataclasses import replace

import pytest

from daedalus.application.gatekeeper.tier2 import SemanticReviewRequest, Tier2Gate
from daedalus.application.review_context import dependency_context
from daedalus.infrastructure.git_sandbox import GitSandbox, _git
from daedalus.security.outbound import SecretInPayload
from tests.test_retrieval_tools import commit


@pytest.fixture
def box(git_repo, tmp_path):
    commit(
        git_repo,
        **{
            "contracts.py": "def sort_key(row): return row['created_at'], row['id']\n",
            "api.py": "from contracts import sort_key\n",
        },
    )
    sandbox = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="review")
    try:
        yield sandbox
    finally:
        sandbox.remove()


def test_review_uses_committed_helper_and_ignores_untracked_and_worktree_override(box):
    (box.worktree_path / "contracts.py").write_text("PRIVATE UNCOMMITTED OVERRIDE")
    (box.worktree_path / "untracked.py").write_text("PRIVATE UNTRACKED")
    (box.worktree_path / "api.py").write_text("from contracts import sort_key\nimport untracked\n")
    payload = dependency_context(box, ("api.py",))
    data = json.loads(payload)
    assert data["commit"] == box.head()
    assert [r["path"] for r in data["sources"]] == ["contracts.py"]
    assert "row['created_at'], row['id']" in payload and "PRIVATE" not in payload


def test_relative_imports_and_limits_are_explicit(git_repo, tmp_path):
    commit(
        git_repo,
        **{
            "pkg/worker.py": "from .helpers import value\nimport a,b,c,d\n",
            "pkg/helpers.py": "value = 7\n",
            **{f"{name}.py": "# safe source\n" * 400 for name in "abcd"},
        },
    )
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="review")
    try:
        context = json.loads(dependency_context(box, ("pkg/worker.py",)))
        assert len(context["sources"]) == 3 and all(
            len(r["text"]) <= 3000 for r in context["sources"]
        )
        assert all(r["truncated"] for r in context["sources"])
        assert {r["path"] for r in context["omitted"]} == {"d.py", "pkg/helpers.py"}
        (box.worktree_path / "pkg/worker.py").write_text("from .helpers import value\n")
        assert (
            json.loads(dependency_context(box, ("pkg/worker.py",)))["sources"][0]["path"]
            == "pkg/helpers.py"
        )
    finally:
        box.remove()


def test_committed_symlink_is_not_followed(git_repo, tmp_path):
    outside = tmp_path / "private.py"
    outside.write_text("PRIVATE OUTSIDE")
    (git_repo / "linked.py").symlink_to(outside)
    _git(git_repo, ["add", "linked.py"], check=True)
    _git(git_repo, ["commit", "-m", "fixture link"], check=True)
    commit(git_repo, **{"api.py": "import linked\n"})
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="review")
    try:
        payload = dependency_context(box, ("api.py",))
        data = json.loads(payload)
        assert not data["sources"] and data["omitted"][0]["reason"] == "not_regular_committed_file"
        assert "PRIVATE OUTSIDE" not in payload
    finally:
        box.remove()


def test_secret_anywhere_in_dependency_blocks_before_truncation_or_dispatch(git_repo, tmp_path):
    commit(
        git_repo,
        **{"api.py": "import helper\n", "helper.py": "# safe\n" * 1000 + repr("sk-" + "a" * 30)},
    )
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="review")
    try:
        with pytest.raises(SecretInPayload):
            dependency_context(box, ("api.py",))
    finally:
        box.remove()


def test_dependency_context_is_part_of_review_subject_identity(box):
    request = SemanticReviewRequest("step", "execution", "artifact", "goal", "intent")
    enriched = replace(request, reference_context=dependency_context(box, ("api.py",)))
    assert request.subject_digest() != enriched.subject_digest()
    assert "created_at" in enriched.render()

    # An approval echoing the old evidence-free subject cannot approve the new request.
    class StaleReviewer:
        def complete(self, prompt, **kwargs):
            return json.dumps(
                {
                    "decision": "APPROVE",
                    "subject_digest": request.subject_digest(),
                    "reasons": ["old review"],
                    "violations": [],
                    "confidence": 1,
                }
            )

    result = Tier2Gate(StaleReviewer()).review(enriched)
    assert result.fail_closed


def test_review_follows_reexported_base_definition_and_keeps_its_real_contract(git_repo, tmp_path):
    commit(
        git_repo,
        **{
            "pkg/__init__.py": "from pkg.base import Basic\n",
            "pkg/base.py": "class Basic:\n    _args = ()\n    def args(self):\n        return self._args\n"
            + "# filler\n" * 15000,
            "pkg/feature.py": "from pkg import Basic\nclass Token(Basic):\n    pass\nclass String(Token):\n    text = 'old'\n",
        },
    )
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "refs", name="base")
    try:
        box.write_file("pkg/feature.py", box.read_file("pkg/feature.py").replace("'old'", "'new'"))
        data = json.loads(
            dependency_context(box, ("pkg/feature.py",), query="String reconstruction")
        )
        assert any(
            s["path"] == "pkg/base.py" and "return self._args" in s["text"] for s in data["sources"]
        )
        assert all(len(s["text"]) <= 1500 for s in data["sources"])
    finally:
        box.remove()


def test_step_review_and_final_goal_audit_both_receive_dependency_evidence(git_repo, tmp_path):
    from daedalus.application.coding_worker import FileOp, ScriptedWorker
    from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
    from tests.test_goal_audit import GoalReviewer, make_owner

    commit(
        git_repo,
        **{"src/example_project/review_rules.py": "CONTRACT_SENTINEL = 'actual-helper-v1'\n"},
    )
    worker = ScriptedWorker(
        ops=(
            FileOp(
                "write",
                TARGET,
                CORRECT_IMPLEMENTATION + "\nfrom .review_rules import CONTRACT_SENTINEL\n",
            ),
        )
    )
    reviewer = GoalReviewer(["APPROVE"])
    seen = []
    complete = reviewer.complete

    def observe(prompt, *, subject_digest):
        assert "actual-helper-v1" in prompt and "src/example_project/review_rules.py" in prompt
        seen.append(prompt)
        return complete(prompt, subject_digest=subject_digest)

    reviewer.complete = observe
    owner = make_owner(git_repo, tmp_path, reviewer, worker)
    try:
        result = owner.run()
        assert result.status == "COMPLETED"
        assert len(seen) == 2 and reviewer.goals == reviewer.step_reviews == 1
        assert not owner.store.verify_sequences()
    finally:
        owner.store.close()


def test_reviewer_receives_candidate_function_body_with_hash_not_only_patch_lines(box):
    import hashlib

    candidate = "from contracts import sort_key\n\ndef sort_rows(rows):\n    return sorted(rows, key=sort_key)\n"
    box.write_file("api.py", candidate)
    data = json.loads(dependency_context(box, ("api.py",), query="fix sort_rows"))
    assert data["candidate_sources"][0]["text"] == candidate
    assert data["candidate_sources"][0]["source_kind"] == "candidate_worktree"
    assert data["candidate_sources"][0]["sha256"] == hashlib.sha256(candidate.encode()).hexdigest()
    assert data["sources"][0]["path"] == "contracts.py"
    box.write_file("api.py", candidate.replace("sorted", "list"))
    changed = dependency_context(box, ("api.py",), query="fix sort_rows")
    assert changed != json.dumps(data)
    assert (
        json.loads(changed)["candidate_sources"][0]["sha256"]
        != data["candidate_sources"][0]["sha256"]
    )


def test_secret_dependency_parks_with_audit_evidence_and_zero_review_calls(git_repo, tmp_path):
    from daedalus.application.coding_worker import FileOp, ScriptedWorker
    from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
    from tests.test_goal_audit import GoalReviewer, make_owner

    commit(
        git_repo,
        **{
            "src/example_project/review_rules.py": "SENTINEL = 1\n"
            + "# unrelated\n" * 1000
            + repr("sk-" + "a" * 30)
        },
    )
    worker = ScriptedWorker(
        ops=(
            FileOp(
                "write", TARGET, CORRECT_IMPLEMENTATION + "\nfrom .review_rules import SENTINEL\n"
            ),
        )
    )
    reviewer = GoalReviewer(["APPROVE"])
    owner = make_owner(git_repo, tmp_path, reviewer, worker)
    try:
        result = owner.run()
        assert result.status == "AWAITING_APPROVAL"
        assert reviewer.step_reviews == reviewer.goals == 0
        events = owner.store.events_for_execution(owner.execution_id)
        review = [e for e in events if e.event_type == "StepTier2Decided"]
        assert len(review) == 1 and review[0].payload["fail_closed"]
        assert "secret_in_payload" in review[0].payload["summary"]
        assert not owner.store.verify_sequences()
    finally:
        owner.store.close()
