"""Task intake: a human's clicks, turned into a spec (Spec §2, §3, §15).

The console's front door is not a form. A person types one sentence — what they want done —
and the model asks a short series of questions with clickable answers. Those clicks have to
*mean* something, and that is what this module decides.

The rule it exists to enforce: **the model may propose questions and options, but only a
closed vocabulary of spec fields can be answered.** Every question names a `field`, every
option carries a `value`, and `validate_questions()` refuses anything outside that
vocabulary, of the wrong type, or with too few options to be a choice at all. A model that
returns `{"field": "delete_protected_paths"}` gets its question dropped and the reason
reported — it does not get to invent a knob.

Two consequences worth stating plainly, because both are deliberate:

* The human's answer is **authoritative** for the field it covers. If they click "只改
  src/example_project/textstats.py", the boundary contract says exactly that, whatever the
  model later proposes. Answering questions that did not bind anything would be theatre.
* The questions are *not* required to cover everything. Whatever they leave unanswered keeps
  the caller's default, and the review screen shows what the model chose on the human's
  behalf. An intake that silently decided the risk level would be worse than one that asked.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from daedalus.domain.spec import NetworkPolicy, RiskLevel
from daedalus.errors import DaedalusError

#: How many questions an intake may ask. Three to five is a conversation; twelve is a form,
#: and the point of this flow is that it is not a form.
MIN_QUESTIONS = 0
MAX_QUESTIONS = 5

#: Fewer than two options is not a choice — it is a statement with a button.
MIN_OPTIONS = 2
MAX_OPTIONS = 4


class IntakeError(DaedalusError):
    """The intake cannot proceed, and the reason is the operator's to act on."""


class IntakeModelUnavailable(IntakeError):
    """No model answered.

    Deliberately *not* a silent fallback to the deterministic planner. The operator was told
    the model would ask the questions; quietly substituting a rule-based plan would make the
    review screen describe a decision process that did not happen.
    """


class IntakeQuestionsRejected(IntakeError):
    """The model answered, but nothing it proposed was usable as a question."""

    def __init__(self, message: str, *, rejections: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.rejections = rejections


class IntakeAnswerRejected(IntakeError):
    """An answer does not correspond to a question this intake asked."""


# --------------------------------------------------------------------------- vocabulary


def _as_str_list(value: Any) -> list[str] | None:
    """A list of non-empty strings, tolerating the single-value shape.

    A model that writes `"src/a.py"` where the field is a list has not proposed a different
    boundary — it used the wrong brackets. Unwrapping one unambiguous value is safe; unwrapping
    anything ambiguous is not, so a bare string becomes a one-element list and nothing else is
    reshaped. What must not be relaxed is whether the value is *legal*, and it still is not.
    """
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if not isinstance(value, list) or not value:
        return None
    if not all(isinstance(item, str) and item.strip() for item in value):
        return None
    return [item.strip() for item in value]


def _as_nonempty_str(value: Any) -> str | None:
    """A non-empty string, tolerating a one-element list for the same reason as above."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list) and len(value) == 1:
        return _as_nonempty_str(value[0])
    return None


def _as_count(value: Any) -> int | None:
    """An integer 1..5. A numeric string is the same number, so it is accepted as one."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 5 else None
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        return number if 1 <= number <= 5 else None
    if isinstance(value, list) and len(value) == 1:
        return _as_count(value[0])
    return None


def _as_risk(value: Any) -> str | None:
    return _as_enum(value, RiskLevel)


def _as_network(value: Any) -> str | None:
    return _as_enum(value, NetworkPolicy)


def _as_enum(value: Any, enum: type) -> str | None:
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if isinstance(value, str):
        try:
            return enum(value.strip().lower()).value
        except ValueError:
            return None
    return None


@dataclass(frozen=True, slots=True)
class SpecField:
    """One answerable field of the frozen contract."""

    key: str
    #: What the field is called on the review screen.
    label: str
    #: Which frozen document this field lands in. Shown on the question screen: a field labelled
    #: as belonging to the wrong spec tells the operator their answer controls something it does
    #: not.
    spec: str
    #: One line, in the operator's terms, about what this field decides.
    explains: str
    coerce: Callable[[Any], Any]
    #: True when the model choosing this on the human's behalf would be a silent policy
    #: decision. The review screen calls these out.
    policy: bool = False


SPEC_FIELDS: dict[str, SpecField] = {
    field_.key: field_
    for field_ in (
        SpecField(
            key="target_paths",
            spec="SPEC-03 边界契约",
            label="可写路径",
            explains="Agent 只能改这里列出的文件；越界会在写入之前被拒绝。",
            coerce=_as_str_list,
            policy=True,
        ),
        SpecField(
            key="test_command",
            spec="SPEC-01 目标契约",
            label="验收命令",
            explains="Tier-1 检查 11 会真的跑这条命令；它失败就不会提交。",
            coerce=_as_nonempty_str,
        ),
        SpecField(
            key="risk_level",
            spec="SPEC-01 目标契约",
            label="风险等级",
            explains="high/critical 会强制人工审批，并且签批必须是一个能验通的签名。",
            coerce=_as_risk,
            policy=True,
        ),
        SpecField(
            key="network_policy",
            spec="SPEC-03 边界契约",
            label="网络策略",
            explains="deny 时会在门禁期拒绝联网；容器/seatbelt 下由内核强制。",
            coerce=_as_network,
            policy=True,
        ),
        SpecField(
            key="invariants",
            spec="SPEC-01 目标契约",
            label="额外不变量",
            explains="必须始终成立的断言，写进 SPEC-01，逐条随 spec 一起冻结。",
            coerce=_as_str_list,
        ),
        SpecField(
            key="max_attempts",
            spec="SPEC-02 执行计划",
            label="重试上限",
            explains="一个 step 最多重新执行几次；用满之后转人工。",
            coerce=_as_count,
        ),
    )
}


@dataclass(frozen=True, slots=True)
class IntakeOption:
    id: str
    label: str
    #: One line on what choosing this means for the run. Required, because an option whose
    #: consequence is not stated is a guess.
    effect: str
    value: Any

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "effect": self.effect, "value": self.value}


@dataclass(frozen=True, slots=True)
class IntakeQuestion:
    id: str
    field: str
    question: str
    #: Why this is being asked. Shown under the question; an unexplained question reads as
    #: bureaucracy.
    why: str
    options: tuple[IntakeOption, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "field": self.field,
            "field_label": SPEC_FIELDS[self.field].label,
            "field_spec": SPEC_FIELDS[self.field].spec,
            "question": self.question,
            "why": self.why,
            "options": [option.to_payload() for option in self.options],
        }


@dataclass(frozen=True, slots=True)
class IntakeAnswer:
    question_id: str
    field: str
    value: Any
    #: The label the operator clicked, kept so the audit reads as what they chose rather than
    #: as a JSON value they never saw.
    label: str
    #: Set when the operator wrote their own answer instead of picking one.
    free_text: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "question_id": self.question_id,
            "field": self.field,
            "label": self.label,
            "value": self.value,
            "free_text": self.free_text,
        }


@dataclass
class IntakeSession:
    """One intake: a task, the questions asked, the answers given, and the spec they produced."""

    intake_id: str
    repo_path: str
    objective: str
    model: str = ""
    questions: list[IntakeQuestion] = field(default_factory=list)
    answers: list[IntakeAnswer] = field(default_factory=list)
    rejections: list[str] = field(default_factory=list)
    spec_digest: str = ""
    run_id: str = ""
    status: str = "QUESTIONING"
    created_at: str = ""
    updated_at: str = ""

    def answer_for(self, field_key: str) -> IntakeAnswer | None:
        for answer in self.answers:
            if answer.field == field_key:
                return answer
        return None

    def answered_fields(self) -> set[str]:
        return {answer.field for answer in self.answers}

    def to_payload(self, *, with_document: dict[str, Any] | None = None) -> dict[str, Any]:
        answered = self.answered_fields()
        return {
            "intake_id": self.intake_id,
            "repo_path": self.repo_path,
            "objective": self.objective,
            "model": self.model,
            "status": self.status,
            "questions": [question.to_payload() for question in self.questions],
            "answers": [answer.to_payload() for answer in self.answers],
            "rejections": list(self.rejections),
            "spec_digest": self.spec_digest,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            # Which fields the model answered on the operator's behalf, so the review screen
            # can say so instead of presenting every field as an explicit choice.
            "unasked_policy_fields": sorted(
                key
                for key, spec_field in SPEC_FIELDS.items()
                if spec_field.policy and key not in answered
            ),
            "document": with_document or {},
        }


# --------------------------------------------------------------------------- validation


def validate_questions(raw: Any) -> tuple[list[IntakeQuestion], list[str]]:
    """Turn a model's proposal into questions, or explain why it could not be used.

    Returns both the accepted questions and the rejections. Rejections are returned rather than
    raised on their own because a model that produces three good questions and one illegal one
    should still produce a usable intake — but the operator is told about the fourth, because a
    dropped question is a field the model wanted to decide and did not get to.
    """
    rejections: list[str] = []
    if not isinstance(raw, list):
        return [], ["模型返回的 questions 不是数组"]

    accepted: list[IntakeQuestion] = []
    seen_ids: set[str] = set()
    seen_fields: set[str] = set()

    for index, item in enumerate(raw):
        where = f"第 {index + 1} 题"
        if not isinstance(item, dict):
            rejections.append(f"{where}：不是对象")
            continue
        field_key = str(item.get("field", "")).strip()
        spec_field = SPEC_FIELDS.get(field_key)
        if spec_field is None:
            rejections.append(f"{where}：field {field_key!r} 不在可回答字段表内")
            continue
        if field_key in seen_fields:
            # Two questions about one field means one answer silently overwrites the other.
            rejections.append(f"{where}：字段 {field_key} 被问了两次")
            continue
        question_id = str(item.get("id", "")).strip() or f"q{index + 1}"
        if question_id in seen_ids:
            rejections.append(f"{where}：id {question_id!r} 重复")
            continue
        question_text = str(item.get("question", "")).strip()
        if not question_text:
            rejections.append(f"{where}：没有问题文本")
            continue

        raw_options = item.get("options")
        if not isinstance(raw_options, list) or len(raw_options) < MIN_OPTIONS:
            rejections.append(
                f"{where}：只有 {len(raw_options) if isinstance(raw_options, list) else 0} 个选项，"
                f"少于 {MIN_OPTIONS} 个就不是选择题"
            )
            continue

        options: list[IntakeOption] = []
        option_ids: set[str] = set()
        option_values: list[Any] = []
        for position, option in enumerate(raw_options[:MAX_OPTIONS]):
            if not isinstance(option, dict):
                rejections.append(f"{where} 选项 {position + 1}：不是对象")
                continue
            label = str(option.get("label", "")).strip()
            effect = str(option.get("effect", "")).strip()
            if not label or not effect:
                rejections.append(f"{where} 选项 {position + 1}：缺少 label 或 effect")
                continue
            # The type check is the point: `coerce` is the only thing that decides whether a
            # value may become part of a spec, and it is not the model's function.
            value = spec_field.coerce(option.get("value"))
            if value is None:
                rejections.append(
                    f"{where} 选项 {position + 1}：value 不是 {field_key} 的合法取值"
                )
                continue
            option_id = str(option.get("id", "")).strip() or f"o{position + 1}"
            if option_id in option_ids:
                rejections.append(f"{where} 选项 {position + 1}：id {option_id!r} 重复")
                continue
            if value in option_values:
                # Two options with the same value is one choice drawn twice.
                rejections.append(f"{where} 选项 {position + 1}：与前面的选项取值相同")
                continue
            option_ids.add(option_id)
            option_values.append(value)
            options.append(
                IntakeOption(id=option_id, label=label, effect=effect, value=value)
            )

        if len(options) < MIN_OPTIONS:
            rejections.append(f"{where}：去掉不合法的选项之后不足 {MIN_OPTIONS} 个")
            continue
        if len(raw_options) > MAX_OPTIONS:
            rejections.append(
                f"{where}：给了 {len(raw_options)} 个选项，只保留前 {MAX_OPTIONS} 个"
            )

        seen_ids.add(question_id)
        seen_fields.add(field_key)
        accepted.append(
            IntakeQuestion(
                id=question_id,
                field=field_key,
                question=question_text,
                why=str(item.get("why", "")).strip(),
                options=tuple(options),
            )
        )
        if len(accepted) >= MAX_QUESTIONS:
            if len(raw) > MAX_QUESTIONS:
                rejections.append(f"题数超过 {MAX_QUESTIONS}，只保留前 {MAX_QUESTIONS} 题")
            break

    return accepted, rejections


def coerce_answer(question: IntakeQuestion, value: Any) -> Any:
    """A free-form answer still has to be a legal value for the field it answers."""
    coerced = SPEC_FIELDS[question.field].coerce(value)
    if coerced is None:
        raise IntakeAnswerRejected(
            f"{value!r} 不是 {SPEC_FIELDS[question.field].label} 的合法取值"
        )
    return coerced
