"""Task intake: a task, the model's questions, a human's clicks, a frozen spec (Spec §2, §15).

The intake is the console's front door, which makes it the one place where "the model proposes
and the control plane disposes" has to hold before a run exists at all. These tests hold the
four properties that make that claim true:

* a question is only usable if it names a field the spec actually has, offers distinct typed
  values, and does not repeat a field — and an illegal one is *reported*, not dropped;
* the human's click binds the field it answers, so answering is not theatre;
* the model is required and its absence is a loud refusal, never a rule-based plan wearing the
  model's name;
* the boundary is asked about whether or not the model asked, because SPEC-03's whitelist is
  the one field Daedalus refuses to inherit from a default.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from daedalus.application.intake import (
    IntakeService,
    ModelQuestioner,
    boundary_question,
)
from daedalus.application.planner import ModelPlanner
from daedalus.domain.intake import (
    SPEC_FIELDS,
    IntakeAnswerRejected,
    IntakeModelUnavailable,
    IntakeQuestionsRejected,
    validate_questions,
)
from daedalus.infrastructure.repo_scan import scan
from daedalus.infrastructure.store import EventStore
from daedalus.model.base import Completion, Message, ModelError
from daedalus.model.mock import MockModelClient
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

# --------------------------------------------------------------------------- fixtures


class ScriptedIntakeModel:
    """A model that answers the intake prompt with questions and the planner prompt with a spec.

    The discriminator is the intake system prompt by name, not a substring likely to appear in
    a generated identifier: matching on "intake" alone silently fed the questions payload to the
    planner once, because the intake's `request_id` contains `intake`.
    """

    def __init__(self, questions: object, plan: object | None = None, *, fail: bool = False):
        self.name = "scripted-intake"
        self.model = "scripted"
        self.base_url = "http://127.0.0.1:1/v1"
        self._questions = questions
        self._plan = plan
        self._fail = fail
        self.calls: list[str] = []

    def complete(self, messages, *, temperature=0.0, max_tokens=4096,
                 response_format_json=False) -> Completion:
        prompt = "\n".join(m.content for m in messages)
        self.calls.append(prompt)
        if self._fail:
            raise ModelError("endpoint down")
        payload = self._questions if "intake 环节" in prompt else self._plan
        text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
        return Completion(text=text, model=self.model, prompt_tokens=10, completion_tokens=10,
                          stopped_reason="stop")


def _questions_payload() -> dict:
    return {
        "questions": [
            {
                "id": "q1",
                "field": "test_command",
                "question": "用什么命令判定改动正确？",
                "why": "Tier-1 检查 11 会真的执行它",
                "options": [
                    {"id": "o1", "label": "只跑 tests", "effect": "最快",
                     "value": "python3 -m pytest tests -q"},
                    {"id": "o2", "label": "跑整个仓库", "effect": "覆盖更广",
                     "value": "python3 -m pytest -q"},
                ],
            },
            {
                "id": "q2",
                "field": "risk_level",
                "question": "风险等级？",
                "why": "high/critical 强制人工审批",
                "options": [
                    {"id": "o1", "label": "normal", "effect": "常规流程", "value": "normal"},
                    {"id": "o2", "label": "high", "effect": "强制审批并验签", "value": "high"},
                ],
            },
        ]
    }


def _plan_payload() -> dict:
    from tests.fake_gateway import planner_reply

    return json.loads(planner_reply(node_ids=["N1"], tree=TARGET).content)


def _service(tmp_path: Path, root: Path, model) -> IntakeService:
    store = EventStore(tmp_path / "ws" / "daedalus.db")
    return IntakeService(
        store=store,
        questioner_factory=lambda: ModelQuestioner(client=model),
        planner_factory=lambda: ModelPlanner(client=model, require_model=True),
        base_request={
            "target_paths": [TARGET],
            "test_command": TEST_COMMAND,
            "risk_level": "normal",
            "network_policy": "deny",
        },
    )


def intake_env(root: Path, tmp_path: Path, *, questions=None, plan=None, fail=False):
    """A service wired to a scripted model. Returns `(service, model, repo)`."""
    model = ScriptedIntakeModel(
        questions if questions is not None else _questions_payload(),
        plan if plan is not None else _plan_payload(),
        fail=fail,
    )
    return _service(tmp_path, root, model), model, root


# ------------------------------------------------------------------ question validation


def test_shape_variants_are_accepted_but_illegal_values_are_not() -> None:
    """A wrong bracket is a shape problem; a wrong value is a spec problem.

    A small local model writes `["python3 -m pytest -q"]` where the field is a string. Refusing
    that made the flow unusable for a model that had proposed perfectly good options. Unwrapping
    one unambiguous value is safe; what must not loosen is whether the value is *legal*.
    """
    accepted, rejected = validate_questions([
        {
            "field": "test_command", "question": "q", "why": "w",
            "options": [{"id": "a", "label": "a", "effect": "e", "value": ["pytest -q"]},
                        {"id": "b", "label": "b", "effect": "e", "value": ["npm test"]}],
        },
        {
            "field": "target_paths", "question": "q", "why": "w",
            "options": [{"id": "a", "label": "a", "effect": "e", "value": "src/a.py"},
                        {"id": "b", "label": "b", "effect": "e", "value": ["src/b.py"]}],
        },
    ])
    assert [tuple(option.value for option in item.options) for item in accepted] == [
        ("pytest -q", "npm test"),
        (["src/a.py"], ["src/b.py"]),
    ]
    assert rejected == []


@pytest.mark.parametrize(
    "item, expected",
    [
        ({"field": "delete_everything", "question": "q", "why": "w",
          "options": [{"id": "a", "label": "a", "effect": "e", "value": 1},
                      {"id": "b", "label": "b", "effect": "e", "value": 2}]},
         "不在可回答字段表内"),
        ({"field": "risk_level", "question": "q", "why": "w",
          "options": [{"id": "a", "label": "a", "effect": "e", "value": "catastrophic"},
                      {"id": "b", "label": "b", "effect": "e", "value": "low"}]},
         "合法取值"),
        ({"field": "test_command", "question": "q", "why": "w",
          "options": [{"id": "a", "label": "a", "effect": "e", "value": "pytest"}]},
         "就不是选择题"),
        ({"field": "test_command", "question": "q", "why": "w",
          "options": [{"id": "a", "label": "a", "effect": "e", "value": "pytest"},
                      {"id": "b", "label": "b", "effect": "e", "value": "pytest"}]},
         "取值相同"),
        ({"field": "max_attempts", "question": "q", "why": "w",
          "options": [{"id": "a", "label": "a", "effect": "e", "value": 99},
                      {"id": "b", "label": "b", "effect": "e", "value": 2}]},
         "合法取值"),
    ],
)
def test_a_question_the_control_plane_cannot_use_is_reported(item, expected) -> None:
    """Every illegal question is named in a rejection, never silently dropped.

    A dropped question is a field the model wanted to decide and did not get to; an operator
    who is not told about it cannot know that field went unanswered.
    """
    accepted, rejected = validate_questions([item])
    assert accepted == []
    assert rejected and expected in rejected[0], rejected


def test_a_field_cannot_be_asked_twice() -> None:
    """Two questions about one field means one answer silently overwrites the other."""
    item = {
        "field": "risk_level", "question": "q", "why": "w",
        "options": [{"id": "a", "label": "a", "effect": "e", "value": "low"},
                    {"id": "b", "label": "b", "effect": "e", "value": "high"}],
    }
    accepted, rejected = validate_questions([item, {**item, "id": "second"}])
    assert len(accepted) == 1
    assert any("被问了两次" in line for line in rejected)


def test_every_answerable_field_says_which_spec_it_lands_in() -> None:
    """The question screen prints this, and a wrong attribution misdescribes the answer."""
    for key, spec_field in SPEC_FIELDS.items():
        assert spec_field.spec.startswith("SPEC-") or spec_field.spec == "Meta-Spec", key
        assert spec_field.label and spec_field.explains, key


# ------------------------------------------------------------------ the boundary floor


def test_the_boundary_is_asked_even_when_the_model_skips_it(git_repo, tmp_path) -> None:
    """SPEC-03's whitelist is the one field that may not be inherited from a default.

    The first live run against a real local model asked only about the test command, which
    would have frozen a boundary no human ever agreed to. The control plane adds the question
    itself and the console labels it as added.
    """
    service, _model, root = intake_env(git_repo, tmp_path)
    service.questioner_factory = lambda: ModelQuestioner(
        client=ScriptedIntakeModel({"questions": []})
    )
    outcome = service.start(str(root), "改一下字数统计")
    fields = [question.field for question in outcome.session.questions]
    assert fields[0] == "target_paths", fields
    assert any("控制面补充" in line for line in outcome.session.rejections)


def test_the_boundary_question_options_are_real_paths(git_repo, tmp_path) -> None:
    """Its options come from the scan, so a model cannot get a hallucinated path into the spec."""
    facts = scan(git_repo)
    question = boundary_question(facts)
    assert question is not None
    known = set(facts.source_files) | set(facts.test_files)
    for option in question.options:
        values = option.value if isinstance(option.value, list) else [option.value]
        for value in values:
            assert value in known or value.endswith("/"), (option.label, value)


# ------------------------------------------------------------------ model required


def test_an_unreachable_model_refuses_instead_of_substituting_rules(git_repo, tmp_path) -> None:
    """The operator was told the model would ask. A silent rule-based plan would be a lie."""
    service, _model, root = intake_env(git_repo, tmp_path, fail=True)
    with pytest.raises(IntakeModelUnavailable) as caught:
        service.start(str(root), "改一下字数统计")
    message = str(caught.value)
    assert "没有应答" in message
    assert "不是降级为规则计划的理由" in message


def test_an_illegal_question_set_refuses_with_its_reasons(git_repo, tmp_path) -> None:
    service, _model, root = intake_env(
        git_repo, tmp_path,
        questions={"questions": [
            {"field": "nonsense", "question": "q", "why": "w",
             "options": [{"id": "a", "label": "a", "effect": "e", "value": 1},
                         {"id": "b", "label": "b", "effect": "e", "value": 2}]},
        ]},
    )
    with pytest.raises(IntakeQuestionsRejected) as caught:
        service.start(str(root), "改一下字数统计")
    assert caught.value.rejections
    assert any("不在可回答字段表内" in line for line in caught.value.rejections)


def test_a_truncated_reply_is_reported_as_truncation(git_repo, tmp_path) -> None:
    """Truncation and refusal send the operator in different directions."""
    model = ScriptedIntakeModel("{not json", plan=_plan_payload())
    original = model.complete

    def truncated(messages, **kwargs):
        completion = original(messages, **kwargs)
        return Completion(text=completion.text, model=completion.model,
                          stopped_reason="length")

    model.complete = truncated  # type: ignore[method-assign]
    service = _service(tmp_path, git_repo, model)
    with pytest.raises(IntakeQuestionsRejected) as caught:
        service.start(str(git_repo), "改一下字数统计")
    assert "截断" in str(caught.value)


def test_a_non_git_directory_is_refused_before_any_question(git_repo, tmp_path) -> None:
    """Finding out after five questions that Daedalus cannot isolate the repo is worse."""
    plain = tmp_path / "plain"
    plain.mkdir()
    service, _model, _root = intake_env(git_repo, tmp_path)
    with pytest.raises(Exception) as caught:
        service.start(str(plain), "改一下")
    assert "不是 Git 仓库" in str(caught.value)


# ------------------------------------------------------------------ the lifecycle


def test_answering_binds_the_field_it_answers(git_repo, tmp_path) -> None:
    """A click is authoritative: the answer reaches the plan request, not just the record."""
    service, _model, root = intake_env(git_repo, tmp_path)
    session = service.start(str(root), "改一下字数统计").session

    session = service.answer(session.intake_id, "q1", option_id="o2")
    session = service.answer(session.intake_id, "q2", option_id="o2")
    boundary = next(item for item in session.questions if item.field == "target_paths")
    session = service.answer(session.intake_id, boundary.id, option_id=boundary.options[0].id)

    request = service.request_for(session)
    assert request.test_command == "python3 -m pytest -q"
    assert request.risk_level.value == "high"
    # The boundary answer, not the `base_request` default, is what the plan request carries.
    assert request.target_paths == tuple(boundary.options[0].value)
    assert request.target_paths != ("src/example_project/textstats.py",) or \
        boundary.options[0].value == ["src/example_project/textstats.py"]


def test_an_answer_to_a_question_that_was_never_asked_is_refused(git_repo, tmp_path) -> None:
    service, _model, root = intake_env(git_repo, tmp_path)
    session = service.start(str(root), "改一下字数统计").session
    with pytest.raises(IntakeAnswerRejected) as caught:
        service.answer(session.intake_id, "never-asked", option_id="o1")
    assert "没有问过" in str(caught.value)


def test_an_option_that_does_not_exist_is_refused(git_repo, tmp_path) -> None:
    service, _model, root = intake_env(git_repo, tmp_path)
    session = service.start(str(root), "改一下字数统计").session
    with pytest.raises(IntakeAnswerRejected) as caught:
        service.answer(session.intake_id, "q1", option_id="o9")
    assert "没有" in str(caught.value)


def test_a_written_answer_is_validated_like_a_clicked_one(git_repo, tmp_path) -> None:
    """Typing `catastrophic` for the risk level must fail exactly as a click would."""
    service, _model, root = intake_env(git_repo, tmp_path)
    session = service.start(str(root), "改一下字数统计").session
    with pytest.raises(IntakeAnswerRejected):
        service.answer(session.intake_id, "q2", free_text="catastrophic")
    session = service.answer(session.intake_id, "q2", free_text="low")
    assert session.answer_for("risk_level").value == "low"


def test_skipping_a_question_leaves_the_default_in_place(git_repo, tmp_path) -> None:
    service, _model, root = intake_env(git_repo, tmp_path)
    session = service.start(str(root), "改一下字数统计").session
    session = service.answer(session.intake_id, "q1", option_id="o2")
    session = service.answer(session.intake_id, "q2", skip=True)
    assert session.answer_for("risk_level") is None
    request = service.request_for(session)
    assert request.risk_level.value == "normal", "the unanswered field keeps the default"
    assert request.test_command == "python3 -m pytest -q", "the answered field still binds"


def test_the_derived_spec_binds_the_answers(git_repo, tmp_path) -> None:
    service, _model, root = intake_env(git_repo, tmp_path)
    session = service.start(str(root), "改一下字数统计").session
    for question in session.questions:
        session = service.answer(session.intake_id, question.id, option_id=question.options[0].id)

    session, bundle, _adjustments = service.derive(session.intake_id)
    assert session.spec_digest == bundle.digest()
    assert session.status == "DERIVED"
    # The click binds the request exactly; hardening may then *narrow* the whitelist, and that is
    # the only direction it may move — a spec that widened the boundary past what the human
    # agreed to would be the failure mode this whole flow exists to prevent.
    clicked = set(session.answer_for("target_paths").value)
    assert set(service.request_for(session).target_paths) == clicked
    assert set(bundle.boundary.fs_whitelist) <= clicked, bundle.boundary.fs_whitelist
    assert bundle.goal.acceptance_criteria, "a spec without an acceptance criterion cannot fail"


def test_a_spec_the_control_plane_refuses_is_not_frozen(git_repo, tmp_path) -> None:
    """A model's spec that fails validation is a refusal, not something to repair silently."""
    broken = _plan_payload()
    broken["spec_02_plan"]["nodes"] = []
    service, _model, root = intake_env(git_repo, tmp_path, plan=broken)
    session = service.start(str(root), "改一下字数统计").session
    for question in session.questions:
        session = service.answer(session.intake_id, question.id, option_id=question.options[0].id)
    with pytest.raises(Exception):
        service.derive(session.intake_id)


def test_the_intake_is_recorded_so_why_is_answerable(git_repo, tmp_path) -> None:
    """The record holds the questions as asked and the answers as clicked, plus the events."""
    service, _model, root = intake_env(git_repo, tmp_path)
    session = service.start(str(root), "改一下字数统计").session
    session = service.answer(session.intake_id, "q1", option_id="o2")
    session, bundle, _ = service.derive(session.intake_id)
    service.mark_frozen(session.intake_id, run_id="run_x", spec_digest=bundle.digest())

    stored = service.load(session.intake_id)
    assert stored.status == "FROZEN"
    assert stored.run_id == "run_x"
    assert [answer.label for answer in stored.answers] == ["跑整个仓库"]
    assert stored.questions[0].options[0].effect, "the options are stored as the operator saw them"

    types = [
        event.event_type
        for event in service.store.all_events()
        if event.aggregate_id == f"intake:{session.intake_id}"
    ]
    assert types == [
        "IntakeQuestionsAsked",
        "IntakeAnswered",
        "IntakeSpecDerived",
        "IntakeFrozen",
    ], types


def test_the_review_payload_names_what_the_model_decided_alone(git_repo, tmp_path) -> None:
    """`unasked_policy_fields` is what lets the review screen stop implying every field was chosen."""
    service, _model, root = intake_env(git_repo, tmp_path)
    session = service.start(str(root), "改一下字数统计").session
    session = service.answer(session.intake_id, "q1", option_id="o1")
    payload = session.to_payload()
    assert "risk_level" in payload["unasked_policy_fields"]
    assert "network_policy" in payload["unasked_policy_fields"]
    assert "test_command" not in payload["unasked_policy_fields"]
    assert payload["model"] == "scripted"


# ------------------------------------------------------------------ the HTTP surface


def _http_app(tmp_path: Path, questions=None, plan=None, *, fail=False):
    """A real app whose planner role answers from the script instead of the network."""
    from fastapi.testclient import TestClient

    from daedalus.config import load_settings
    from daedalus.service.app import create_app

    model = ScriptedIntakeModel(
        questions if questions is not None else _questions_payload(),
        plan if plan is not None else _plan_payload(),
        fail=fail,
    )
    settings = load_settings(None, workspace_root=str(tmp_path / "http-ws"))
    app = create_app(settings)
    state = app.state.daedalus
    state.build_model_client = lambda role="": model  # type: ignore[assignment]
    state.intake.questioner_factory = lambda: ModelQuestioner(client=model)
    state.intake.planner_factory = lambda: ModelPlanner(client=model, require_model=True)
    state.intake.base_request = {
        "target_paths": [TARGET],
        "test_command": TEST_COMMAND,
        "risk_level": "normal",
        "network_policy": "deny",
    }
    return TestClient(app), model


def test_the_intake_runs_over_http_from_task_to_frozen_run(git_repo, tmp_path) -> None:
    """The whole front door through real HTTP: task, questions, answers, spec, freeze.

    This is the flow the console drives, so it is asserted end to end rather than per endpoint:
    the buttons on the page are only as good as this path.
    """
    client, _model = _http_app(tmp_path)
    with client:
        started = client.post(
            "/api/intakes",
            json={"repo_path": str(git_repo), "objective": "改一下字数统计"},
        )
        assert started.status_code == 201, started.text
        intake = started.json()["intake"]
        intake_id = intake["intake_id"]
        assert intake["model"] == "scripted"
        assert {question["field"] for question in intake["questions"]} >= {
            "test_command", "risk_level", "target_paths",
        }
        for question in intake["questions"]:
            assert question["field_spec"].startswith("SPEC-")
            assert len(question["options"]) >= 2

        for question in intake["questions"]:
            answered = client.post(
                f"/api/intakes/{intake_id}/answers",
                json={"question_id": question["id"], "option_id": question["options"][0]["id"]},
            )
            assert answered.status_code == 200, answered.text
        assert answered.json()["intake"]["status"] == "DERIVED"

        derived = client.post(f"/api/intakes/{intake_id}/spec")
        assert derived.status_code == 200, derived.text
        body = derived.json()
        assert body["spec_digest"]
        assert len(body["specs"]) == 4, "the review screen shows the same four cards as 规划"

        calls_before_freeze = len(_model.calls)
        _model._plan = "the model changed its mind; freeze must not ask it again"
        frozen = client.post(f"/api/intakes/{intake_id}/freeze", json={"spec_digest": body["spec_digest"]})
        assert frozen.status_code == 202, frozen.text
        assert frozen.json()["run_id"]
        assert frozen.json()["spec_digest"] == body["spec_digest"]
        assert len(_model.calls) == calls_before_freeze

        record = client.get(f"/api/intakes/{intake_id}").json()["intake"]
        assert record["status"] == "FROZEN"
        assert record["run_id"] == frozen.json()["run_id"]


def test_an_unreachable_model_is_a_503_over_http(git_repo, tmp_path) -> None:
    """503 rather than 500: the operator's model config is the thing to fix, and it is retryable."""
    client, _model = _http_app(tmp_path, fail=True)
    with client:
        response = client.post(
            "/api/intakes",
            json={"repo_path": str(git_repo), "objective": "改一下"},
        )
        assert response.status_code == 503, response.text
        assert "没有应答" in response.json()["detail"]


def test_an_illegal_question_set_is_a_422_carrying_its_reasons(git_repo, tmp_path) -> None:
    client, _model = _http_app(
        tmp_path,
        questions={"questions": [
            {"field": "nonsense", "question": "q", "why": "w",
             "options": [{"id": "a", "label": "a", "effect": "e", "value": 1},
                         {"id": "b", "label": "b", "effect": "e", "value": 2}]},
        ]},
    )
    with client:
        response = client.post(
            "/api/intakes",
            json={"repo_path": str(git_repo), "objective": "改一下"},
        )
        assert response.status_code == 422, response.text
        detail = response.json()["detail"]
        assert detail["rejections"], detail


def test_freezing_before_a_spec_exists_is_refused(git_repo, tmp_path) -> None:
    client, _model = _http_app(tmp_path)
    with client:
        intake_id = client.post(
            "/api/intakes",
            json={"repo_path": str(git_repo), "objective": "改一下"},
        ).json()["intake"]["intake_id"]
        response = client.post(f"/api/intakes/{intake_id}/freeze", json={})
        assert response.status_code == 409, response.text
        assert "还没有得出 spec" in response.json()["detail"]


def test_an_unknown_intake_is_a_404(tmp_path) -> None:
    client, _model = _http_app(tmp_path)
    with client:
        assert client.get("/api/intakes/intake_nope").status_code == 404
        assert client.post(
            "/api/intakes/intake_nope/answers",
            json={"question_id": "q", "option_id": "o"},
        ).status_code == 404


def test_the_repo_list_offers_repositories_this_workspace_has_seen(git_repo, tmp_path) -> None:
    """Typing an absolute path is a poor front door; what the workspace has seen fills the list.

    Both sources are exercised, because they are stored in different places and an earlier
    version read only the intake one: a run's repository is not a column on `runs` (it lives in
    the `RunStarted` payload), so "past run" silently contributed nothing while the intake
    source made the feature look like it worked.
    """
    from daedalus.domain.ids import new_id

    client, _model = _http_app(tmp_path)
    with client:
        service = client.app.state.daedalus.intake  # type: ignore[attr-defined]
        assert client.get("/api/repos").json()["repos"] == []

        client.post("/api/intakes", json={"repo_path": str(git_repo), "objective": "改一下"})
        repos = client.get("/api/repos").json()["repos"]
        assert [row["path"] for row in repos] == [str(git_repo.resolve())]
        # `startswith`: pytest's tmp_path lives under the system temporary directory, so the
        # scratch marker is appended. The provenance is what is under test, not the marker.
        assert repos[0]["source"].startswith("之前提过任务"), repos[0]

        # Now the run source: a run recorded this repository in its RunStarted event, which is
        # the only place it is recorded at all.
        store = service.store
        run_id = new_id("run")
        from daedalus.domain.ids import utc_now

        now = utc_now()
        store.project_run({
            "run_id": run_id,
            "goal_id": "G",
            "execution_id": "exec_x",
            "spec_digest": "d",
            "status": "COMPLETED",
            "created_at": now,
            "updated_at": now,
        })
        store.append_many([
            {
                "aggregate_id": run_id,
                "execution_id": "exec_x",
                "event_type": "RunStarted",
                "actor": "test",
                "payload": {"repo_path": str(git_repo)},
            }
        ])
        # The run source wins the label: both point at the same repository and the list is
        # de-duplicated by path, so exactly one entry remains.
        repos = client.get("/api/repos").json()["repos"]
        assert len(repos) == 1, repos
        assert repos[0]["source"].startswith("之前跑过"), repos


def test_known_repos_skips_a_repository_that_no_longer_exists(tmp_path) -> None:
    """Offering a deleted path is worse than offering nothing: the click fails one step later."""
    from daedalus.infrastructure.repo_scan import known_repos

    gone = tmp_path / "gone"
    gone.mkdir()
    (gone / ".git").mkdir()
    assert known_repos([(str(gone), "之前跑过")]) != []
    import shutil as _shutil

    _shutil.rmtree(gone)
    assert known_repos([(str(gone), "之前跑过")]) == []


def test_the_console_page_and_its_hooks_are_served(git_repo, tmp_path) -> None:
    """The intake is the landing page, and it renders the panels the script fills."""
    client, _model = _http_app(tmp_path)
    with client:
        page = client.get("/")
        assert page.status_code == 200
        for marker in (
            'id="intake-objective"', 'id="intake-repos"', 'id="intake-start"',
            'id="intake-step-questions"', 'id="intake-options"', 'id="intake-document"',
            'id="intake-freeze"',
        ):
            assert marker in page.text, marker
        # The run list moved to /runs, and the old URL still resolves.
        assert client.get("/runs").status_code == 200


# ------------------------------------------------------------------ the format repair


class _OneBadReplyThenGood:
    """Replies with a malformed option once, then correctly once told what was wrong.

    A tiny local model drops a `label` from one option often enough that the intake died on a
    formatting mistake. The refusal was correct but useless; the control plane already knows
    exactly what was malformed, so it says so and asks once more.
    """

    name = "flaky-intake"
    model = "flaky"
    base_url = "http://127.0.0.1:1/v1"

    def __init__(self, good: dict) -> None:
        self._good = good
        self.calls: list[str] = []

    def complete(self, messages, *, temperature=0.0, max_tokens=4096,
                 response_format_json=False):
        from daedalus.model.base import Completion

        prompt = "\n".join(getattr(m, "content", "") for m in messages)
        self.calls.append(prompt)
        if "被拒绝了" in prompt:
            payload = self._good
        else:
            payload = {"questions": [
                {"id": "q1", "field": "test_command", "question": "q", "why": "w",
                 "options": [
                     {"id": "o1", "label": "a", "effect": "e", "value": "pytest -q"},
                     # No `effect`: malformed, and the reason the first reply is unusable.
                     {"id": "o2", "label": "b", "value": "pytest"},
                 ]},
            ]}
        return Completion(text=json.dumps(payload, ensure_ascii=False), model=self.model,
                          prompt_tokens=5, completion_tokens=5, stopped_reason="stop")


def test_a_malformed_reply_is_repaired_once_with_the_reasons_quoted(git_repo, tmp_path) -> None:
    """The repair corrects shape, never content, and says that it happened."""
    model = _OneBadReplyThenGood(_questions_payload())
    service = _service(tmp_path, git_repo, model)
    outcome = service.start(str(git_repo), "改一下字数统计")
    assert outcome.session.questions, "the second reply must be used"
    # The control-plane boundary question is prepended, so the model's own question is found by
    # field rather than by position.
    assert "test_command" in [q.field for q in outcome.session.questions]
    assert any("重问了一次" in line for line in outcome.session.rejections), \
        outcome.session.rejections
    assert any("缺少 label 或 effect" in line for line in outcome.session.rejections)
    # The repair prompt quotes the reason, which is the whole mechanism.
    assert any("被拒绝了" in call and "effect" in call for call in model.calls)


def test_a_still_malformed_reply_refuses_rather_than_inventing_questions(git_repo, tmp_path) -> None:
    """Two failures refuse. The repair is one chance, not a loop that eventually fabricates."""
    bad = {"questions": [
        {"id": "q1", "field": "test_command", "question": "q", "why": "w",
         "options": [{"id": "o1", "label": "a", "value": "pytest -q"},
                     {"id": "o2", "label": "b", "value": "pytest"}]},
    ]}
    service = _service(tmp_path, git_repo, ScriptedIntakeModel(bad, _plan_payload()))
    with pytest.raises(IntakeQuestionsRejected) as caught:
        service.start(str(git_repo), "改一下字数统计")
    assert any("缺少 label 或 effect" in line for line in caught.value.rejections)


def test_no_model_configured_points_at_the_panel(git_repo, tmp_path) -> None:
    """The zero-provider path, which every other test stepped around.

    `test_the_console_can_be_used_with_no_model_configured_over_http` sets an override first, so
    it never reached `IntakeService.start` with nothing configured — and a missing import on that
    branch raised `NameError`, which the HTTP layer turned into a 500. The error an operator sees
    when they have no model must name the panel that fixes it.
    """
    from daedalus.config import ConfigError
    from daedalus.infrastructure.store import EventStore

    class _Unconfigured:
        """A questioner factory that refuses the way an unconfigured workspace does."""

        def __call__(self):
            raise ConfigError("no model provider configured for role 'planner' (known: [])")

    service = IntakeService(
        store=EventStore(tmp_path / "empty" / "daedalus.db"),
        questioner_factory=_Unconfigured(),
        planner_factory=lambda: None,  # never reached
    )
    with pytest.raises(IntakeModelUnavailable) as caught:
        service.start(str(git_repo), "改一下")
    message = str(caught.value)
    assert "没有可用的模型" in message
    assert "「模型」面板" in message, "the error must name the place that fixes it"
    assert "先测一下" in message
