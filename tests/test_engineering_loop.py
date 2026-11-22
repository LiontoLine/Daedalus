"""Real code/check transitions inside one candidate, without granting delivery authority."""

import hashlib
import json
from dataclasses import replace

import pytest

from daedalus.application.coding_worker import ModelWorker
from daedalus.application.gatekeeper.tier2 import Tier2Gate
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.worker import WorkerContext
from daedalus.application.worker_checks import CheckRequest, DeclaredCheckRunner
from daedalus.application.worker_factory import build_model_worker
from daedalus.infrastructure.git_sandbox import GitSandbox, _git
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Completion, TokenBudget
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET
from tests.test_agentic_rag import Controller
from tests.test_goal_audit import GoalReviewer
from tests.test_worker_checks import COMMAND


PARTIAL = CORRECT_IMPLEMENTATION.replace("    if not tokens:\n        return 0.0\n", "")


def bundle_for():
    return DeterministicPlanner().plan(
        PlanRequest("engineering", "engineering-goal", "fix word counting and empty input",
                    (TARGET,), COMMAND)
    )


def check(bundle):
    criteria = bundle.plan.nodes[0].acceptance_criteria or bundle.goal.acceptance_criteria
    return {"action": "check", "criterion_id": criteria[0].criterion_id,
            "gap": "does the original word-count and empty-input behavior pass?"}


def edit(source, *, terminal=False):
    payload = {"operations": [{"op": "write", "path": TARGET, "content": source}]}
    if not terminal:
        payload["action"] = "edit"
    return payload


def repair_sequence(bundle):
    return [check(bundle), edit(PARTIAL), check(bundle), edit(CORRECT_IMPLEMENTATION),
            check(bundle), {"action": "finish"}]


@pytest.fixture
def environment(git_repo, tmp_path):
    box = GitSandbox.create(repo_path=git_repo, run_root=tmp_path / "trees", name="engineering")
    bundle = bundle_for()
    context = WorkerContext("step", "execution", bundle.plan.nodes[0], bundle,
                            box.base_commit, 1)
    try:
        yield box, context
    finally:
        box.remove()


def test_native_failure_partial_repair_and_final_repair_preserve_accumulated_code(environment):
    box, context = environment
    model, budget = Controller(repair_sequence(context.bundle)), TokenBudget()
    result = build_model_worker(model, budget=budget).implement(box, context)
    assert result.ok, result.execution_log
    assert box.read_file(TARGET) == CORRECT_IMPLEMENTATION
    receipts = result.extra["check_receipts"]
    assert [(r["executed"], r["passed"]) for r in receipts] == [
        (True, False), (True, False), (True, True),
    ]
    assert len({r["tree_digest"] for r in receipts}) == 3
    assert len({r["criterion_digest"] for r in receipts}) == 1
    assert all(not r["approval"] for r in receipts)
    assert box.head() == context.base_commit
    assert result.tokens_used == budget.run_used == 600
    # The middle failure is real execution of the partial implementation, not model prose.
    assert "ZeroDivisionError" in model.calls[3][-1].content
    diagnosis = model.calls[3][-1].content.split(
        "ENGINEERING DIAGNOSIS (deterministic guidance, not approval):\n"
    )[-1]
    assert json.loads(diagnosis)["category"] == "executed_failure"
    assert receipts[-1]["tree_digest"] == box.tree_digest()


def test_unchanged_check_with_new_explanation_does_not_execute_again(environment):
    box, context = environment
    request = check(context.bundle)
    model = Controller([request, {**request, "gap": "a different explanation"}])
    result = build_model_worker(model).implement(box, context)
    assert result.error == "worker_no_progress"
    assert len(result.extra["check_receipts"]) == 1
    assert not result.extra["check_receipts"][0]["passed"]
    assert not box.changed_files()


def test_finish_cannot_hide_an_executed_failure_on_the_same_tree(environment):
    box, context = environment
    result = build_model_worker(Controller([
        edit(PARTIAL), check(context.bundle), {"action": "finish"},
    ])).implement(box, context)
    assert not result.ok and result.error == "worker_validation_failed"
    assert box.read_file(TARGET) == PARTIAL
    assert not result.extra["check_receipts"][0]["passed"]
    records = result.extra["engineering_observations"]["records"]
    failure = next(row for row in records if row["kind"] == "executed_check_failed")
    assert "ZeroDivisionError" in failure["content"]
    assert failure["tree_digest"] == box.tree_digest()
    assert failure["criterion_id"] == check(context.bundle)["criterion_id"]
    assert result.extra["engineering_diagnosis"]["category"] == "executed_failure"
    assert result.extra["engineering_diagnosis"]["approval"] is False


def test_existing_candidate_can_be_validated_without_a_forced_rewrite(environment):
    box, context = environment
    box.write_file(TARGET, CORRECT_IMPLEMENTATION)
    result = build_model_worker(Controller([
        check(context.bundle), {"action": "finish"},
    ])).implement(box, context)
    assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
    assert result.extra["engineering_loop"]["edit_rounds"] == 0
    assert result.extra["check_receipts"][0]["passed"]
    assert box.head() == context.base_commit


def test_one_shot_refuses_continuation_before_applying_edits(environment):
    box, context = environment
    before = box.read_file(TARGET)
    worker = build_model_worker(Controller([edit(CORRECT_IMPLEMENTATION)]))
    worker.enable_continuations = False
    result = worker.implement(box, context)
    assert result.error == "invalid_edit_plan" and box.read_file(TARGET) == before
    assert not result.extra["check_receipts"]


def test_check_cannot_smuggle_a_command_or_edit_into_the_tool(environment):
    box, context = environment
    before = box.read_file(TARGET)
    payload = {**check(context.bundle), "command": "touch unauthorized"}
    result = build_model_worker(Controller([payload])).implement(box, context)
    assert result.error == "invalid_edit_plan"
    assert not result.extra["check_receipts"] and box.read_file(TARGET) == before
    assert not box.exists("unauthorized")


def test_edit_oscillation_stops_before_repeating_checks_or_more_model_calls(environment):
    box, context = environment
    model = Controller([edit(PARTIAL), edit(CORRECT_IMPLEMENTATION), edit(PARTIAL)])
    result = build_model_worker(model).implement(box, context)
    assert result.error == "worker_no_progress"
    assert box.read_file(TARGET) == PARTIAL and not result.extra["check_receipts"]


def test_native_observation_does_not_reset_shared_model_budget(environment):
    box, context = environment
    budget, model = TokenBudget(), Controller([check(context.bundle)])
    runner = DeclaredCheckRunner()

    def observe(*args):
        observation = runner(*args)
        budget.record(Completion("", prompt_tokens=19000))
        return observation

    result = ModelWorker(model, budget=budget, check_context=observe).implement(box, context)
    assert result.error == "model_budget_exceeded" and not result.ok
    assert budget.run_used == 19100 and len(model.calls) == 1
    assert result.tokens_used == 100 and result.extra["check_receipts"][0]["executed"]


def test_expired_node_deadline_prevents_coding_dispatch(environment):
    box, context = environment
    model = Controller([])


    # Supply an already expired operational deadline; frozen acceptance is unchanged.
    expired = replace(context, deadline_monotonic=1.0)
    result = build_model_worker(model).implement(box, expired)
    assert result.error == "worker_deadline_exceeded" and not model.calls
    assert not box.changed_files()


def test_real_orchestrator_delivers_only_after_final_original_acceptance(git_repo, tmp_path):
    bundle = bundle_for()
    worker = build_model_worker(Controller(repair_sequence(bundle)))
    with EventStore(tmp_path / "engineering.db") as store:
        reviewer = GoalReviewer(["APPROVE"])
        reviewer.criteria = [c.criterion_id for c in bundle.goal.acceptance_criteria]
        owner = RunOrchestrator(store=store, repo_path=git_repo, run_root=tmp_path / "runs",
                                bundle=bundle, worker=worker, goal_audit_enabled=True,
                                tier2=Tier2Gate(reviewer=reviewer),
                                park_on_escalation=False, retry_backoff_sec=0)
        owner.register_spec()
        result = owner.run()
        assert result.promoted_commit and result.status == "COMPLETED", result.describe()
        observed = [e for e in store.events_for(f"run:{owner.run_id}")
                    if e.event_type == "WorkerEngineeringObserved"]
        assert [r["passed"] for r in observed[0].payload["check_receipts"]] == [False, False, True]
        assert _git(git_repo, ["show", f"{result.promoted_commit}:{TARGET}"],
                    check=True).stdout == CORRECT_IMPLEMENTATION


def test_a_passed_inner_check_cannot_approve_a_later_broken_tree(git_repo, tmp_path):
    bundle = bundle_for()
    responses = [edit(CORRECT_IMPLEMENTATION), check(bundle), edit(PARTIAL, terminal=True)]
    responses.extend(edit(PARTIAL, terminal=True) for _ in range(3))
    worker = build_model_worker(Controller(responses))
    before = _git(git_repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
    with EventStore(tmp_path / "stale-check.db") as store:
        owner = RunOrchestrator(store=store, repo_path=git_repo, run_root=tmp_path / "runs",
                                bundle=bundle, worker=worker, goal_audit_enabled=True,
                                park_on_escalation=False, retry_backoff_sec=0)
        owner.register_spec()
        result = owner.run()
        assert not result.promoted_commit
        assert _git(git_repo, ["rev-parse", "HEAD"], check=True).stdout.strip() == before
        events = store.events_for(f"run:{owner.run_id}")
        observed = [e for e in events if e.event_type == "WorkerEngineeringObserved"]
        assert observed[0].payload["check_receipts"][0]["passed"]
        failures = [e for e in events if e.event_type == "TrunkNodeFailed"]
        assert any(any(row.get("ok") is False for row in e.payload.get("criteria", []))
                   for e in failures)
        memory = owner._repair_memory(store.list_steps(owner.run_id)[0]["step_id"])
        assert any(row.get("historical_requested_checks") for row in memory)


def test_stale_batch_can_be_repaired_without_losing_prior_work(environment):
    box, context = environment
    stale = {
        "action": "edit",
        "operations": [
            {"op": "write", "path": TARGET, "content": CORRECT_IMPLEMENTATION},
            {"op": "replace", "path": TARGET, "old_text": "missing old source",
             "new_text": "must not be applied"},
        ],
    }

    class ObserveAtomicFailure(Controller):
        def complete(self, messages, **kwargs):
            if len(self.calls) == 2:
                assert box.read_file(TARGET) == PARTIAL
            return super().complete(messages, **kwargs)

    model = ObserveAtomicFailure([
        edit(PARTIAL), stale, edit(CORRECT_IMPLEMENTATION),
        check(context.bundle), {"action": "finish"},
    ])
    result = build_model_worker(model).implement(box, context)
    assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
    assert result.extra["check_receipts"][0]["passed"]
    stale = next(row for row in result.extra["engineering_observations"]["records"]
                 if row["kind"] == "stale_edit")
    assert "average_word_length" in stale["content"]
    assert stale["tree_digest"] != box.tree_digest()
    diagnosis = json.loads(model.calls[2][-1].content.split(
        "ENGINEERING DIAGNOSIS (deterministic guidance, not approval):\n"
    )[-1])
    assert diagnosis["category"] == "stale_edit"


def test_repeated_stale_edit_does_not_spend_the_entire_action_allowance(environment):
    box, context = environment
    stale = {"action": "edit", "operations": [
        {"op": "replace", "path": TARGET, "old_text": "missing old source",
         "new_text": "never written"},
    ]}
    model = Controller([stale, stale])
    before = box.read_file(TARGET)
    result = build_model_worker(model).implement(box, context)
    assert result.error == "worker_no_progress"
    assert box.read_file(TARGET) == before


def test_observations_keep_historical_tree_after_a_terminal_candidate_changes_it(environment):
    box, context = environment
    original_tree = box.tree_digest()
    model = Controller([check(context.bundle), edit(CORRECT_IMPLEMENTATION, terminal=True)])
    observations = []
    runner = DeclaredCheckRunner()

    def observe(*args):
        observation = runner(*args)
        observations.append(observation)
        return observation

    result = ModelWorker(model, check_context=observe).implement(box, context)
    assert result.ok and box.tree_digest() != original_tree
    record = result.extra["engineering_observations"]["records"][0]
    assert record["kind"] == "executed_check_failed"
    assert record["tree_digest"] == original_tree
    assert record["content_digest"] == hashlib.sha256(
        observations[0].content.encode("utf-8")
    ).hexdigest()
    diagnosis = result.extra["engineering_diagnosis"]
    assert diagnosis["category"] == "historical_evidence"
    assert diagnosis["current_tree_digest"] == box.tree_digest()
    assert not diagnosis["approval"]


def test_review_hypothesis_invites_falsification_in_the_actual_model_prompt(environment):
    box, context = environment
    context = replace(
        context, revision_feedback="Reviewer hypothesis: empty input might lose all words.",
        repair_memory=({"evidence_kind": "review_hypothesis",
                        "observation": "Empty input might lose all words."},),
    )

    class EvidenceFirst(Controller):
        def complete(self, messages, **kwargs):
            prompt = messages[-1].content
            diagnosis = json.loads(prompt.split(
                "ENGINEERING DIAGNOSIS (deterministic guidance, not approval):\n"
            )[-1])
            if not self.calls:
                assert diagnosis["category"] == "review_hypothesis"
                assert "falsify" in diagnosis["next_action"]
                assert "do not mutate code merely" in diagnosis["next_action"]
            else:
                assert diagnosis["category"] == "executed_failure"
                assert "AssertionError" in prompt
            return super().complete(messages, **kwargs)

    model = EvidenceFirst([check(context.bundle), edit(CORRECT_IMPLEMENTATION, terminal=True)])
    result = build_model_worker(model).implement(box, context)
    assert result.ok and len(model.calls) == 2


def test_simple_terminal_edit_keeps_the_one_call_path(environment):
    box, context = environment
    model = Controller([edit(CORRECT_IMPLEMENTATION, terminal=True)])
    result = build_model_worker(model).implement(box, context)
    assert result.ok and len(model.calls) == 1
    assert result.extra["engineering_observations"] == {"records": [], "omitted_records": 0}
    assert not result.extra["check_receipts"]


def test_oversized_inspection_batch_keeps_candidate_and_reports_remaining_allowance(environment):
    box, context = environment
    def read(line):
        return {"tool": "read", "path": TARGET, "line": line,
                "gap": "inspect the current implementation"}
    model = Controller([
        edit(PARTIAL),
        {"action": "inspect", "requests": [read(1), read(2)]},
        {"action": "inspect", "requests": [read(3), read(4)]},
        {"action": "inspect", "requests": [read(3)]},
        edit(CORRECT_IMPLEMENTATION), check(context.bundle), {"action": "finish"},
    ])
    result = build_model_worker(model).implement(box, context)
    assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
    assert [row["arguments"]["line"] for row in result.extra["inspection_receipts"]] == [1, 2, 3]
    assert result.extra["check_receipts"][-1]["passed"]
    assert sum(not row["ok"] for row in result.extra["engineering_loop"]["actions"]) == 1


def test_terminal_noop_after_edit_can_repair_inside_same_candidate(environment):
    box, context = environment
    model = Controller([
        edit(PARTIAL), edit(PARTIAL, terminal=True), edit(CORRECT_IMPLEMENTATION),
        check(context.bundle), {"action": "finish"},
    ])
    result = build_model_worker(model).implement(box, context)
    assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
    assert result.extra["engineering_loop"]["edit_rounds"] == 2
    assert result.extra["check_receipts"][-1]["passed"]


def test_scoped_failure_history_defers_initial_retrieval_but_allows_new_investigation(environment):
    box, context = environment
    context = replace(context, attempt=2, repair_memory=({
        "evidence_kind": "executed_check_failure",
        "failed_criteria": [check(context.bundle)["criterion_id"]],
        "source_run_id": "same-scoped-history",
    },))
    model = Controller([
        {"action": "investigate", "query": "empty-input contract",
         "gap": "need a new source fact, not a repeated initial retrieval"},
        edit(CORRECT_IMPLEMENTATION), check(context.bundle), {"action": "finish"},
    ])
    worker = build_model_worker(model)
    def initial(context):
        raise AssertionError("redundant initial retrieval must not dispatch")
    worker.reference_context = initial
    worker.investigate_context = lambda context, query, gap: "The empty-input consumer requires zero."
    result = worker.implement(box, context)
    assert result.ok and result.extra["check_receipts"][-1]["passed"]
    assert "The empty-input consumer requires zero." in model.calls[1][-1].content


def test_terminal_repair_is_checked_and_continues_on_same_failed_candidate(environment):
    box, context = environment
    context = replace(context, attempt=2, repair_memory=({
        "evidence_kind": "executed_check_failure",
        "failed_criteria": [check(context.bundle)["criterion_id"]],
        "source_run_id": "same-scoped-history",
    },))

    class Accumulated(Controller):
        def complete(self, messages, **options):
            if self.calls:
                assert "ZeroDivisionError" in messages[-1].content
                current = messages[-1].content.split("CURRENT CONTENT:", 1)[-1]
                assert PARTIAL.strip() in current
            return super().complete(messages, **options)

    model = Accumulated([edit(PARTIAL, terminal=True),
                         edit(CORRECT_IMPLEMENTATION, terminal=True)])
    result = build_model_worker(model).implement(box, context)
    assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
    assert [row["passed"] for row in result.extra["check_receipts"]] == [False, True]
    assert len({row["tree_digest"] for row in result.extra["check_receipts"]}) == 2
    assert result.extra["engineering_loop"]["edit_rounds"] == 2
    assert len(model.calls) == 2


@pytest.mark.parametrize("one_shot", [False, True])
def test_review_hypothesis_or_one_shot_cannot_trigger_automatic_native_repair_checks(
    environment, one_shot,
):
    box, context = environment
    context = replace(context, attempt=2, repair_memory=({
        "evidence_kind": "executed_check_failure" if one_shot else "review_hypothesis",
        "failed_criteria": [check(context.bundle)["criterion_id"]],
        "source_run_id": "scoped-history",
    },))
    model = Controller([edit(CORRECT_IMPLEMENTATION, terminal=True)])
    worker = build_model_worker(model)
    worker.enable_continuations = not one_shot
    result = worker.implement(box, context)
    assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
    assert result.extra["check_receipts"] == [] and len(model.calls) == 1


def test_automatic_repair_checks_do_not_extend_the_native_check_allowance(environment):
    box, context = environment
    context = replace(context, attempt=2, repair_memory=({
        "evidence_kind": "executed_check_failure",
        "failed_criteria": [check(context.bundle)["criterion_id"]],
    },))
    budget = TokenBudget()
    model = Controller(
        [edit(PARTIAL + f"\n# candidate {i}\n", terminal=True) for i in range(3)]
        + [edit(CORRECT_IMPLEMENTATION, terminal=True)]
    )
    result = build_model_worker(model, budget=budget).implement(box, context)
    assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
    assert [r["passed"] for r in result.extra["check_receipts"]] == [False] * 3
    assert result.tokens_used == budget.run_used == 400
    assert all(not row["approval"] for row in result.extra["check_receipts"])
    # Exhausting inner observations cannot replace the independent outer acceptance.
    final = DeclaredCheckRunner()(
        box, context, CheckRequest(check(context.bundle)["criterion_id"], "outer frozen acceptance"),
    )
    assert final.receipt["passed"] and final.receipt["tree_digest"] == box.tree_digest()


def test_incremental_paired_edit_observes_the_failed_tree_before_next_edit(environment):
    from daedalus.domain.spec import AcceptanceCriterion, AssertionKind
    from tests.test_worker_checks import python_command

    box, context = environment
    fix = context.bundle.goal.acceptance_criteria[0]
    preserve = AcceptanceCriterion(
        "preserve-words", AssertionKind.EXIT_CODE,
        command=python_command(
            "import sys; sys.path.insert(0,'src'); "
            "from example_project.textstats import summarize; "
            "assert summarize('one two')['words'] == 2"
        ),
    )
    bundle = replace(context.bundle, goal=replace(
        context.bundle.goal, acceptance_criteria=(fix, preserve),
    ))
    context = replace(context, bundle=bundle, repair_memory=({
        "evidence_kind": "executed_check_failure",
        "candidate_tree": box.tree_digest(),
        "failed_criteria": [fix.criterion_id],
        "historical_passed_criteria": [preserve.criterion_id],
    },))

    class ObserveThenRepair(Controller):
        def complete(self, messages, **options):
            if self.calls:
                assert "ZeroDivisionError" in messages[-1].content
            return super().complete(messages, **options)

    model = ObserveThenRepair([edit(PARTIAL), edit(CORRECT_IMPLEMENTATION, terminal=True)])
    result = build_model_worker(model).implement(box, context)
    assert result.ok and box.read_file(TARGET) == CORRECT_IMPLEMENTATION
    receipts = result.extra["check_receipts"]
    assert [(r["criterion_id"], r["passed"]) for r in receipts] == [
        (fix.criterion_id, False), (fix.criterion_id, True), (preserve.criterion_id, True),
    ]
    assert receipts[0]["tree_digest"] != box.tree_digest()
    assert all(r["tree_digest"] == box.tree_digest() for r in receipts[1:])
