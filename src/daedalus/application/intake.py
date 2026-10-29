"""Task intake as a use case: ask, answer, derive, freeze (Spec §2, §3, §15).

The console's front door. A person types one sentence; a model reads the task and the
repository and proposes a few questions with clickable answers; the answers become the
boundaries of the frozen contract.

Three decisions in here are load-bearing, and each is the opposite of what would have been
convenient:

**The model is required, not optional.** `ModelPlanner` falls back to the deterministic
planner on any failure, which is right for a run — an infrastructure problem should not stop
work that has already been authorised. It is wrong here. The operator is told the model will
ask the questions; if it cannot, the honest outcome is "模型不可达", not a rule-based plan
presented behind a model's name. `IntakeModelUnavailable` exists for that.

**The model's question set is validated against a closed vocabulary before it is shown.** A
question it proposes is only usable if it names a field the spec actually has, offers two to
four distinct typed values, and does not repeat a field. Rejections are surfaced rather than
dropped, because a dropped question is a field the model wanted to decide and did not get to.

**A human's answer beats the model.** The answers are folded into `PlanRequest` *before* the
planner runs, so clicking "只改 textstats.py" produces a `fs_whitelist` with exactly that in
it. An answer that did not bind anything would make the whole screen theatre.

What this module deliberately does not do: it does not create a run. `freeze()` registers the
spec and hands back a receipt; starting work stays in the orchestrator, so the intake cannot
become a second write path into the FSM.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from daedalus.application.planner import ModelPlanner, PlanRequest
from daedalus.domain.ids import new_id, utc_now
from daedalus.domain.intake import (
    MAX_OPTIONS,
    SPEC_FIELDS,
    IntakeAnswer,
    IntakeAnswerRejected,
    IntakeModelUnavailable,
    IntakeOption,
    IntakeQuestion,
    IntakeQuestionsRejected,
    IntakeSession,
    coerce_answer,
    validate_questions,
)
from daedalus.domain.spec import NetworkPolicy, RiskLevel, SpecBundle
from daedalus.errors import DaedalusError, ModelError
from daedalus.infrastructure.redact import redact_text
from daedalus.infrastructure.repo_scan import RepoFacts, rank_candidates, scan
from daedalus.model.base import Completion, Message, ModelClient, TokenBudget
from daedalus.security.outbound import SecretInPayload, assert_outbound_clean

QUESTION_TIMEOUT_SEC = 90
#: A five-question payload with effects is a few hundred tokens, but a small local model pads
#: every option with a restated `options` key. Too small a ceiling truncates the JSON mid-object,
#: which then reads as "the model returned nothing usable" - a confusing diagnosis for what is
#: really "give it more room".
QUESTION_MAX_TOKENS = 3000

_QUESTIONER_SYSTEM = """\
你是 Daedalus 控制面的 intake 环节。Daedalus 是一个确定性控制平面：模型只提议，控制面决定。

人类用一句话描述任务，你已经读过他的 Git 仓库（只读，没有执行任何东西）。
你的工作：问**最少**的几个问题，把任务的契约补齐，每题给出可点击的选项。

铁律：
1. 最多 5 题，通常 2-3 题就够。如果任务和仓库已经决定了契约，就一题都不问。
2. 每题必须指定 field，只能从下面这张表里选，别的一律不接受：
   target_paths   - 允许 Agent 写哪些文件（值：仓库相对路径的数组）
   test_command   - 判定改动是否正确的命令（值：字符串）
   risk_level     - "low" / "normal" / "high" / "critical" 之一
   network_policy - "deny" / "allowlist" 之一
   invariants     - 必须永远成立的断言（值：字符串数组）
   max_attempts   - 1..5 的整数
3. 选项必须是彼此**互相排斥的真实方案**，不是"是/否"，也不要让人类去确认一个你已经在
   仓库信息里看到的事实。反例（禁止）："检测到的命令里有 pytest 吗？"
4. 每个选项要有 value（该 field 的合法完整取值）、label（短标签）、effect（一句话说明
   选它对这次运行意味着什么）。不要再嵌套 options 字段。
5. 用仓库信息。WRITABLE_CANDIDATES 里列出的文件才可以出现在选项里，不要编造路径。
6. 最安全、最可能的答案放第一个。
7. why 用中文说清这一题在决定什么。输出语言跟随任务描述的语言。

只输出 JSON，别的什么都不要，不要代码围栏：
{"questions":[{"id":"q1","field":"target_paths",
"question":"这次允许 Agent 改哪些文件？",
"why":"边界决定越界检查在写入前拦什么",
"options":[{"id":"o1","label":"只改 textstats.py",
"effect":"边界最小，越界会在写入前被拒绝",
"value":["src/example_project/textstats.py"]}]}]}"""


def boundary_question(
    facts: RepoFacts, objective: str = ""
) -> IntakeQuestion | None:
    """The one question the control plane asks whether or not the model did.

    SPEC-03's writable-path list is the field Daedalus refuses to guess: every boundary check and
    the boundary guard itself are built from it, so a boundary inherited from a default is a
    boundary no human ever agreed to. When the model does not ask about it, this question is
    added - and the console labels it as added by the control plane rather than the model,
    because presenting it as the model's question would misdescribe who decided to ask.

    The options are *scopes*, not a guess at "the file this task is about". A scan cannot know
    that: an earlier version ranked candidates by the identifiers in the task and offered the
    best-scoring file as "the narrowest", which put `__init__.py` first for a task about
    `summarize()` because a re-export shim also mentions it. Claiming to have identified the
    file was a false statement in the one panel whose value is that its statements can be
    checked. So the options are real sets - all source files, source plus tests, a directory, or
    an explicit path the operator wrote - and the ranked candidates are shown as *evidence*,
    with the free-text field for anyone who wants to name the exact file.
    """
    paths = [candidate.path for candidate in facts.target_candidates]
    if not paths:
        return None
    test_paths = [path for path in paths if path in facts.test_files]
    source_paths = [path for path in paths if path not in facts.test_files]

    options: list[IntakeOption] = []
    # An explicit path in the task is the one case with no ambiguity, so it becomes the narrowest
    # option. Anything else would be a guess dressed as a recommendation.
    named = _named_path(objective, paths)
    if named:
        options.append(
            IntakeOption(
                id="boundary-named",
                label=f"只改任务里点名的 {named}",
                effect="边界最小：任务描述里明确写了这个路径，只有它可写",
                value=[named],
            )
        )
    if source_paths:
        options.append(
            IntakeOption(
                id="boundary-source",
                label=f"改全部 {len(source_paths)} 个源文件（不含测试）",
                effect="边界是扫描到的源文件集合；越界会在写入之前被拒绝",
                value=sorted(source_paths),
            )
        )
    if test_paths:
        options.append(
            IntakeOption(
                id="boundary-with-tests",
                label="源文件 + 测试文件",
                effect="允许同时改测试；改测试等于改验收标准，需要额外理由",
                value=sorted(paths),
            )
        )
    directories = sorted({path.split("/")[0] + "/" for path in paths if "/" in path})
    if directories:
        options.append(
            IntakeOption(
                id="boundary-directory",
                # The label names every directory in the value. A label that said "整个 src/ 目录"
                # while the value also contained `tests/` promised a narrower boundary than it
                # granted, which is the one direction a boundary label may never be wrong in.
                label="整个 " + "、".join(directories) + " 目录",
                effect="边界放宽到这些目录；越界检查仍然会拦下目录之外的一切",
                value=directories,
            )
        )
    if len(options) < 2:
        return None

    # Evidence, not a recommendation: the operator can see what the scan found and disagree.
    ranked = rank_candidates(facts, objective)
    hot = [candidate for candidate in ranked if candidate.why != "源文件"][:4]
    evidence = "；".join(f"{candidate.path}（{candidate.why}）" for candidate in hot)
    why = "边界决定越界检查在写入之前拦掉什么；它必须由人决定，不能由默认值继承。"
    if evidence:
        why += f" 扫描到的线索：{evidence}。要精确到某个文件，用下面的输入框写路径。"
    else:
        why += f" 扫描到的候选：{'、'.join(paths[:6])}。要精确到某个文件，用下面的输入框写路径。"

    return IntakeQuestion(
        id="boundary",
        field="target_paths",
        question="这次允许 Agent 写哪些文件？",
        why=why,
        options=tuple(options[:MAX_OPTIONS]),
    )


def _named_path(objective: str, paths: list[str]) -> str:
    """A candidate path the task text names outright, if any."""
    lowered = objective.replace("\\", "/")
    for path in paths:
        if path in lowered:
            return path
        stem = path.rsplit("/", 1)[-1]
        if len(stem) > 6 and stem in lowered:
            return path
    return ""


@dataclass
class IntakeOutcome:
    """What `start()` returns: the session plus how the model behaved."""

    session: IntakeSession
    facts: RepoFacts
    model_error: str = ""


@dataclass
class ModelQuestioner:
    """Asks a model for the clarifying questions. Never fabricates them on failure."""

    client: ModelClient
    budget: TokenBudget | None = None
    #: Recorded on the session so the review screen can name what proposed the spec.
    name: str = "intake-questioner"
    last_raw: str = ""
    #: True when the first reply was unusable and a second, format-corrected reply was used.
    #: Surfaced in the session's notes: a repaired intake is still worth telling the operator
    #: about, because "the model needed two tries" is a fact about the model they chose.
    repaired: bool = False

    def propose(self, objective: str, facts: RepoFacts) -> tuple[list[IntakeQuestion], list[str]]:
        prompt = self._render(objective, facts)
        try:
            assert_outbound_clean(prompt, where="the intake prompt")
        except SecretInPayload as error:
            # A credential shape in the task text is a refusal, not a redaction: the operator
            # pasted something that must not leave the process, and silently rewriting their
            # task would hide that it happened.
            raise IntakeQuestionsRejected(
                f"任务描述里出现了凭证形状的内容，已拒绝发送：{error.message}"
            ) from error

        try:
            from daedalus.model.base import budgeted_completion
            completion = budgeted_completion(
                self.client,
                [
                    Message(role="system", content=_QUESTIONER_SYSTEM),
                    Message(role="user", content=prompt),
                ],
                budget=self.budget,
                # Zero, not a little: this is a schema-constrained reply, and the only thing
                # variety buys here is a malformed option that costs the operator the whole
                # intake. Questions do not need to be surprising; they need to be valid.
                temperature=0.0,
                max_tokens=QUESTION_MAX_TOKENS,
                response_format_json=True,
            )
        except ModelError as error:
            if error.code == "model_output_incomplete":
                raise IntakeQuestionsRejected(
                    "模型回复被截断或没有完整可见内容，暂未生成可用问题。"
                    "请增加输出预算或调整模型后重试。"
                ) from error
            raise _unavailable(self.client, error) from error

        self.last_raw = completion.text

        payload = _parse_json_object(completion.text)
        questions, rejections = self._validate(payload, completion)
        if not questions and rejections:
            # One repair round. A small model drops a `label` or an `effect` and the whole
            # intake dies on a *formatting* mistake; the control plane already knows exactly
            # what was wrong, so it says so and asks again. Nothing about the decision is
            # invented here — the same fields, the same options, corrected shape only — and if
            # the second reply is still unusable the intake refuses as before.
            repaired = self._repair(objective, facts, rejections)
            if repaired is not None:
                questions, second = self._validate(repaired[0], repaired[1])
                if questions:
                    self.repaired = True
                    rejections = [
                        "模型第一次回复的格式不合法，控制面把具体原因回传后重问了一次，"
                        f"第二次通过。第一次的问题：{'；'.join(repaired[2][:3])}"
                    ]
        if (payload.get("questions") if payload else None) and not questions:
            raise IntakeQuestionsRejected(
                "模型提出的问题没有一条可用（字段名、选项数或取值类型不合法），"
                "重问一次之后仍然不可用，所以这次提任务无法继续。",
                rejections=tuple(rejections),
            )
        return questions, rejections

    def _validate(
        self, payload: dict[str, Any] | None, completion: Completion
    ) -> tuple[list[IntakeQuestion], list[str]]:
        """Parse-and-validate one reply, or explain why it is unusable."""
        if payload is None:
            if completion.stopped_reason == "length":
                raise IntakeQuestionsRejected(
                    f"模型在 {QUESTION_MAX_TOKENS} token 内没写完 JSON，回复被截断，"
                    "所以问题无法解析。换一个更会按格式回答的模型，或者把问题要求再收紧。"
                )
            raise IntakeQuestionsRejected(
                "模型没有返回可解析的 JSON 对象，所以无法确定要问什么。"
                f"它返回的开头是：{redact_text(completion.text)[:200]!r}"
            )
        return validate_questions(payload.get("questions"))

    def _repair(
        self, objective: str, facts: RepoFacts, rejections: list[str]
    ) -> tuple[dict[str, Any] | None, Completion, list[str]] | None:
        """Re-ask once, quoting the exact reasons the first reply was unusable."""
        try:
            from daedalus.model.base import budgeted_completion
            completion = budgeted_completion(
                self.client,
                [
                    Message(role="system", content=_QUESTIONER_SYSTEM),
                    Message(role="user", content=self._render(objective, facts)),
                    Message(
                        role="user",
                        content=(
                            "你上一次的回复被拒绝了，原因如下：\n"
                            + "\n".join(f"- {line}" for line in rejections)
                            + "\n请重新输出完整的 JSON，每个 option 都必须有 id、label、effect、"
                            "value 四个字段，并且 value 是该 field 的合法取值。"
                        ),
                    ),
                ],
                budget=self.budget,
                temperature=0.0,
                max_tokens=QUESTION_MAX_TOKENS,
                response_format_json=True,
            )
        except ModelError:
            return None
        self.last_raw = completion.text
        return _parse_json_object(completion.text), completion, list(rejections)

    def _render(self, objective: str, facts: RepoFacts) -> str:
        return (
            f"TASK (as the human wrote it):\n{objective}\n\n"
            f"REPOSITORY FACTS (read from disk, read-only, nothing executed):\n"
            f"{facts.to_prompt()}\n"
            "Ask the questions now. JSON only."
        )


def _unavailable(client: ModelClient, error: Exception) -> DaedalusError:
    endpoint = getattr(client, "base_url", "?")
    model = getattr(client, "model", "?")
    return IntakeModelUnavailable(
        f"模型 {model}（{endpoint}）没有应答，所以这次提任务无法继续：{error}。"
        "这不是降级为规则计划的理由——那样界面会声称是模型问的问题。"
        "请检查服务配置里的模型端点，或在配置里换一个可用的模型。"
    )


def _parse_json_object(text: str) -> dict[str, Any] | None:
    """Parse the model's JSON, tolerating a fenced or chatty reply.

    A 3B local model routinely wraps JSON in prose or a code fence. Retrying costs another
    call and asking again does not make the answer well-formed, so the object is located
    instead. If there is genuinely no object, the caller refuses.
    """
    stripped = text.strip()
    for candidate in (stripped, _strip_fence(stripped), _first_object(stripped)):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _strip_fence(text: str) -> str:
    if "```" not in text:
        return ""
    parts = text.split("```")
    if len(parts) < 2:
        return ""
    body = parts[1]
    if body.startswith("json"):
        body = body[4:]
    return body.strip()


def _first_object(text: str) -> str:
    start = text.find("{")
    if start < 0:
        return ""
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return ""


# --------------------------------------------------------------------------- the service


@dataclass
class IntakeService:
    """The intake lifecycle, over a store and a model client."""

    store: Any
    questioner_factory: Callable[[], ModelQuestioner]
    planner_factory: Callable[[], ModelPlanner]
    #: Where to look for repositories beyond the ones past runs recorded.
    repo_roots: tuple[str, ...] = ()
    #: Defaults an unanswered field keeps. The review screen names each one it used.
    base_request: dict[str, Any] = field(default_factory=dict)
    reference_context_factory: Callable[[str, PlanRequest, Any], str] | None = None

    # ------------------------------------------------------------------ start

    def start(self, repo_path: str, objective: str, *, goal_id: str = "") -> IntakeOutcome:
        objective = objective.strip()
        if not objective:
            raise DaedalusError("提任务需要一个目标描述")
        try:
            facts = scan(repo_path)
        except NotADirectoryError as error:
            raise DaedalusError(f"{error} 不是一个目录，无法读取") from error
        if not facts.is_git:
            # Refused here rather than at freeze time: Daedalus needs Git for worktree
            # isolation, and finding that out after answering five questions is worse.
            raise DaedalusError(
                f"{facts.path} 不是 Git 仓库（没有 .git）。Daedalus 依赖 Git 做 worktree "
                "隔离与提交，请选择或先初始化一个仓库。"
            )

        try:
            questioner = self.questioner_factory()
        except DaedalusError as error:
            # The most likely cause by far is that no model is configured at all, and the raw
            # message ("no model provider configured for role 'planner'") does not tell an
            # operator that the console has a panel for exactly this.
            raise IntakeModelUnavailable(
                f"没有可用的模型：{error}。打开提任务页下方的「模型」面板填一个接口"
                "（填完先点「先测一下」），或者写进 daedalus.toml 的 [model.*] 段。"
                "提任务必须由模型出题，没有模型时无法进行。"
            ) from error
        questions, rejections = questioner.propose(objective, facts)
        # The boundary is the one field the control plane will not inherit from a default. If
        # the model did not ask about it, a question built from the scan is added and flagged,
        # so the console can say who asked it.
        if not any(question.field == "target_paths" for question in questions):
            # The objective is passed so a path the task names outright becomes the narrowest
            # option; without it that option could never appear.
            added = boundary_question(facts, objective)
            if added is not None:
                questions = [added, *questions]
                rejections = [
                    *rejections,
                    "模型没有问可写范围；这一题由控制面补充，因为边界不能由默认值继承。",
                ]

        session = IntakeSession(
            intake_id=new_id("intake"),
            repo_path=facts.path,
            objective=objective,
            model=f"{getattr(questioner.client, 'model', '?')}",
            questions=questions,
            rejections=rejections,
            status="QUESTIONING" if questions else "DERIVED",
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        self._persist(session)
        self._event(
            session,
            "IntakeQuestionsAsked",
            {
                "questions": [question.id for question in questions],
                "fields": [question.field for question in questions],
                "model": session.model,
                "rejections": list(rejections),
            },
        )
        return IntakeOutcome(session=session, facts=facts)

    # ------------------------------------------------------------------ answer

    def answer(
        self,
        intake_id: str,
        question_id: str,
        *,
        option_id: str = "",
        free_text: str = "",
        skip: bool = False,
    ) -> IntakeSession:
        session = self.load(intake_id)
        if session.status in {"FROZEN", "ABANDONED"}:
            raise IntakeAnswerRejected("已冻结或放弃的需求不能修改，请新建任务")
        question = next(
            (item for item in session.questions if item.id == question_id), None
        )
        if question is None:
            raise IntakeAnswerRejected(
                f"{intake_id} 没有问过 {question_id!r}；已问的是 "
                f"{[item.id for item in session.questions]}"
            )
        if skip:
            session.spec_digest = ""
            session.answers = [
                item for item in session.answers if item.question_id != question_id
            ]
            self._persist(session)
            return session

        if option_id:
            option = next(
                (item for item in question.options if item.id == option_id), None
            )
            if option is None:
                raise IntakeAnswerRejected(
                    f"{question.id} 没有 {option_id!r} 这个选项；有的是 "
                    f"{[item.id for item in question.options]}"
                )
            answer = IntakeAnswer(
                question_id=question.id,
                field=question.field,
                value=option.value,
                label=option.label,
            )
        else:
            text = free_text.strip()
            if not text:
                raise IntakeAnswerRejected("要么点一个选项，要么写下你自己的答案")
            raw: Any = [part.strip() for part in text.split(",") if part.strip()]
            if question.field in {"test_command", "risk_level", "network_policy"}:
                raw = text
            if question.field == "max_attempts":
                raw = int(text) if text.isdigit() else text
            value = coerce_answer(question, raw)
            answer = IntakeAnswer(
                question_id=question.id,
                field=question.field,
                value=value,
                label="（自己填写）",
                free_text=text,
            )

        session.answers = [
            item for item in session.answers if item.question_id != question_id
        ]
        session.answers.append(answer)
        session.spec_digest = ""
        if len(session.answers) >= len(session.questions) and session.status == "QUESTIONING":
            session.status = "DERIVED"
        self._persist(session)
        self._event(
            session,
            "IntakeAnswered",
            {
                "question_id": answer.question_id,
                "field": answer.field,
                "label": answer.label,
                "value": answer.value,
                "free_text": answer.free_text,
            },
        )
        return session

    # ------------------------------------------------------------------ derive

    def request_for(self, session: IntakeSession) -> PlanRequest:
        """Fold the answers into a plan request. The human's clicks are authoritative."""
        base = dict(self.base_request)
        values = {answer.field: answer.value for answer in session.answers}

        target_paths = values.get("target_paths") or base.get("target_paths") or []
        test_command = values.get("test_command") or base.get("test_command") or ""
        risk = values.get("risk_level") or base.get("risk_level") or RiskLevel.NORMAL.value
        network = (
            values.get("network_policy")
            or base.get("network_policy")
            or NetworkPolicy.DENY.value
        )
        invariants = values.get("invariants") or base.get("invariants") or []
        max_attempts = values.get("max_attempts") or base.get("max_attempts")

        extra = [
            "The following were decided by a human clicking through intake questions and are "
            "NOT yours to change:",
            f"  target_paths = {json.dumps(target_paths, ensure_ascii=False)}",
            f"  test_command = {test_command}",
            f"  risk_level = {risk}",
            f"  network_policy = {network}",
        ]
        if invariants:
            extra.append(f"  invariants = {json.dumps(invariants, ensure_ascii=False)}")
        answered = session.answered_fields()
        unanswered_policy = sorted(
            key
            for key, spec_field in SPEC_FIELDS.items()
            if spec_field.policy and key not in answered
        )
        if unanswered_policy:
            extra.append(
                "No human answer covered these policy fields, so keep them at the values "
                f"above and say so in the plan: {unanswered_policy}"
            )

        request = PlanRequest(
            request_id=f"REQ-{session.intake_id}",
            goal_id=base.get("goal_id", "GOAL-001"),
            objective=session.objective,
            target_paths=tuple(target_paths),
            test_command=test_command,
            invariants=tuple(invariants),
            risk_level=RiskLevel(risk),
            network_policy=NetworkPolicy(network),
            extra_context="\n".join(extra),
        )
        if max_attempts:
            request = _with_attempts(request, int(max_attempts))
        return request

    def derive(self, intake_id: str) -> tuple[IntakeSession, SpecBundle, tuple[str, ...]]:
        """Produce the spec from the answers. The model is required; failures are reported."""
        session = self.load(intake_id)
        if session.status in {"FROZEN", "ABANDONED"}:
            raise DaedalusError("已冻结或放弃的需求不能重新规划")
        request = self.request_for(session)
        planner = self.planner_factory()
        if self.reference_context_factory is not None:
            from dataclasses import replace
            reference = self.reference_context_factory(session.repo_path, request, planner.budget)
            request = replace(request, extra_context=request.extra_context + reference)
        bundle = planner.plan(request)
        adjustments = tuple(getattr(planner, "last_adjustments", ()) or ())
        # A content-addressed snapshot is the reviewed contract; freeze must never re-plan.
        from daedalus.application.service_lifecycle import atomic_json
        directory = Path(self.store.path).parent / "intake-specs"
        directory.mkdir(parents=True, exist_ok=True)
        assert_outbound_clean(json.dumps(bundle.to_dict()), where="the reviewed planning snapshot")
        atomic_json(directory / (bundle.digest() + ".json"), bundle.to_dict())
        session.spec_digest = bundle.digest()
        session.status = "DERIVED"
        self._persist(session)
        self._event(
            session,
            "IntakeSpecDerived",
            {
                "spec_digest": bundle.digest(),
                "model": session.model,
                "answers": [
                    {"field": answer.field, "value": answer.value} for answer in session.answers
                ],
                "adjustments": list(adjustments),
            },
        )
        return session, bundle, adjustments

    def reviewed_bundle(self, intake_id: str, expected_digest: str) -> SpecBundle:
        session = self.load(intake_id)
        if (session.status != "DERIVED" or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
                or expected_digest != session.spec_digest):
            raise DaedalusError("规划已变化或未提交确认摘要，请重新查看并确认规划")
        path = Path(self.store.path).parent / "intake-specs" / (session.spec_digest + ".json")
        try:
            bundle = SpecBundle.from_dict(json.loads(path.read_text()))
            bundle.validate()
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise DaedalusError("已确认的规划快照不可读取，请重新生成并查看规划") from error
        if bundle.digest() != expected_digest:
            raise DaedalusError("规划快照摘要不匹配，拒绝执行")
        return bundle

    # ------------------------------------------------------------------ freeze

    def mark_frozen(self, intake_id: str, *, run_id: str, spec_digest: str) -> IntakeSession:
        session = self.load(intake_id)
        session.run_id = run_id
        session.spec_digest = spec_digest
        session.status = "FROZEN"
        self._persist(session)
        self._event(
            session,
            "IntakeFrozen",
            {"run_id": run_id, "spec_digest": spec_digest},
        )
        return session

    def abandon(self, intake_id: str) -> IntakeSession:
        session = self.load(intake_id)
        session.status = "ABANDONED"
        self._persist(session)
        self._event(session, "IntakeAbandoned", {})
        return session

    # ------------------------------------------------------------------ reads

    def load(self, intake_id: str) -> IntakeSession:
        row = self.store.get_intake(intake_id)
        if row is None:
            raise DaedalusError(f"没有 {intake_id} 这个提任务记录")
        return _session_from_row(row)

    def recent(self, limit: int = 20) -> list[IntakeSession]:
        return [_session_from_row(row) for row in self.store.list_intakes(limit)]

    def known_repos(self) -> list[dict[str, str]]:
        """Repositories the intake can offer without asking anyone to type a path.

        Both sources are things this workspace has actually seen: repositories past runs used,
        and repositories past intakes named. A fresh workspace legitimately has none, and the
        console then says so and offers a path field — scanning the filesystem for Git
        directories is not something a control plane should do uninvited.
        """
        from daedalus.infrastructure.repo_scan import known_repos

        # The repository a run used is not a column on `runs` — it lives in the `RunStarted`
        # event payload, and `run_repo_path` is the one function that knows that. Reading a
        # `repo_path` key off the projection silently produced an empty list, which is the
        # failure mode of a feature that looks like it works.
        from daedalus.application.replay import run_repo_path

        seen: list[tuple[str, str]] = []
        for row in self.store.list_runs()[:60]:
            try:
                path = run_repo_path(self.store, str(row["run_id"]))
            except DaedalusError:
                continue
            if path:
                seen.append((path, "之前跑过"))
        seen += [
            (str(row["repo_path"]), "之前提过任务")
            for row in self.store.list_intakes(50)
            if row.get("repo_path")
        ]
        return known_repos(seen, list(self.repo_roots))

    # ------------------------------------------------------------------ internals

    def _persist(self, session: IntakeSession) -> None:
        self.store.save_intake(
            {
                "intake_id": session.intake_id,
                "repo_path": session.repo_path,
                "objective": session.objective,
                "model": session.model,
                "status": session.status,
                "questions": [question.to_payload() for question in session.questions],
                "answers": [answer.to_payload() for answer in session.answers],
                "rejections": list(session.rejections),
                "spec_digest": session.spec_digest,
                "run_id": session.run_id,
                "created_at": session.created_at or utc_now(),
            }
        )

    def _event(self, session: IntakeSession, event_type: str, payload: dict[str, Any]) -> None:
        """Record the intake's decisive transitions on the log, alongside the projection.

        The `intakes` row is the state; these events are the trail. An intake with no events
        would make "was this spec frozen by a person, or did it just appear?" unanswerable.
        """
        self.store.append_many(
            [
                {
                    "aggregate_id": f"intake:{session.intake_id}",
                    "execution_id": "",
                    "event_type": event_type,
                    "actor": "intake",
                    "payload": payload,
                    "correlation_id": session.intake_id,
                }
            ]
        )


def _with_attempts(request: PlanRequest, attempts: int) -> PlanRequest:
    """`PlanRequest` has no retry field; the planner's nodes do.

    Applied after planning rather than before, because the attempt budget belongs to the plan.
    Kept as an explicit step so the review screen can show it as a human decision.
    """
    from dataclasses import replace

    return replace(request, extra_context=request.extra_context + (
        f"\nEvery node's retry_policy.max_attempts must be exactly {attempts}."
    ))


def _session_from_row(row: dict[str, Any]) -> IntakeSession:
    questions: list[IntakeQuestion] = []
    for item in row.get("questions") or []:
        if not isinstance(item, dict):
            continue
        options: list[IntakeOption] = []
        for option in item.get("options") or []:
            if not isinstance(option, dict):
                continue
            options.append(
                IntakeOption(
                    id=str(option.get("id", "")),
                    label=str(option.get("label", "")),
                    effect=str(option.get("effect", "")),
                    value=option.get("value"),
                )
            )
        field_key = str(item.get("field", ""))
        if field_key not in SPEC_FIELDS:
            continue
        questions.append(
            IntakeQuestion(
                id=str(item.get("id", "")),
                field=field_key,
                question=str(item.get("question", "")),
                why=str(item.get("why", "")),
                options=tuple(options),
            )
        )
    answers: list[IntakeAnswer] = []
    for item in row.get("answers") or []:
        if not isinstance(item, dict):
            continue
        answers.append(
            IntakeAnswer(
                question_id=str(item.get("question_id", "")),
                field=str(item.get("field", "")),
                value=item.get("value"),
                label=str(item.get("label", "")),
                free_text=str(item.get("free_text", "")),
            )
        )
    return IntakeSession(
        intake_id=str(row["intake_id"]),
        repo_path=str(row["repo_path"]),
        objective=str(row["objective"]),
        model=str(row.get("model", "")),
        questions=questions,
        answers=answers,
        rejections=[str(item) for item in (row.get("rejections") or [])],
        spec_digest=str(row.get("spec_digest", "")),
        run_id=str(row.get("run_id", "")),
        status=str(row.get("status", "QUESTIONING")),
        created_at=str(row.get("created_at", "")),
        updated_at=str(row.get("updated_at", "")),
    )
