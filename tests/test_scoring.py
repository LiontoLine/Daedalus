"""The audit score (Spec §15, §27).

The score exists to answer "how much evidence is there that this was done properly?" in one
glance, and its whole design is the difference between that question and "is this change
correct?". These tests hold the properties that make the number safe to show:

* it is computed from persisted evidence only, so a run with no evidence cannot score well;
* every component reports the facts that produced it, so the number can always be unpacked;
* a disqualifying fact (a boundary violation, an unverified high-risk sign-off) is not averaged
  away by good numbers elsewhere — it drives its own component to zero;
* the payload says what the score is not. A summary that reads as a verdict is the failure mode
  this project exists to argue against.

The last one is the reason `scale_note` is asserted rather than ignored: the console renders it,
and a console that showed only a ring and a band would be making a claim the system cannot
support.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from daedalus.application.coding_worker import FileOp, ScriptedWorker
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.application.scoring import _band, score_run
from daedalus.demo import BROKEN_IMPLEMENTATION
from daedalus.domain.fsm import RunState
from daedalus.domain.spec import NetworkPolicy, RiskLevel
from daedalus.infrastructure.store import EventStore
from tests.conftest import CORRECT_IMPLEMENTATION, TARGET, TEST_COMMAND

EXPECTED_KEYS = (
    "gate_coverage",
    "test_evidence",
    "boundary_compliance",
    "approval_integrity",
    "digest_completeness",
    "attempt_economy",
    "evidence_completeness",
)


def _run(
    tmp_path: Path,
    repo: Path,
    *,
    risk: RiskLevel = RiskLevel.NORMAL,
    worker=None,
    park_on_escalation: bool = True,
):
    """Drive one real run and hand back its store, so the score is computed from real evidence."""
    from daedalus.application.orchestrator import RunOrchestrator

    bundle = DeterministicPlanner().plan(
        PlanRequest(
            request_id="REQ-SCORE",
            goal_id="GOAL-SCORE",
            objective="fix the counter",
            target_paths=(TARGET,),
            test_command=TEST_COMMAND,
            risk_level=risk,
            network_policy=NetworkPolicy.DENY,
        )
    )
    store = EventStore(tmp_path / "ws" / "daedalus.db")
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=worker
        or ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-score",
        ),
        park_on_escalation=park_on_escalation,
    )
    orchestrator.register_spec()
    orchestrator.create_run()
    return store, orchestrator


def _completed(tmp_path: Path, repo: Path, **kwargs):
    store, orchestrator = _run(tmp_path, repo, **kwargs)
    result = orchestrator.run()
    assert result.status == RunState.COMPLETED.value, result.describe()
    return store, orchestrator


def _component(payload: dict, key: str) -> dict:
    return next(component for component in payload["components"] if component["key"] == key)


class _PerAttemptWorker:
    """Applies a different script on each attempt, so a retry is a genuinely different candidate.

    `ScriptedWorker` applies the same operations on every call, which cannot express "attempt 1
    was wrong and attempt 2 fixed it" — the whole point of an efficiency component.
    """

    name = "per-attempt-worker"

    def __init__(self, scripts, worker_id: str = "worker-score-attempts") -> None:
        self._scripts = list(scripts)
        self.worker_id = worker_id
        self.calls = 0

    def implement(self, sandbox, context):
        script = self._scripts[min(self.calls, len(self._scripts) - 1)]
        self.calls += 1
        return ScriptedWorker(ops=script, worker_id=self.worker_id).implement(sandbox, context)


# ------------------------------------------------------------------ the aggregate


def test_a_clean_run_scores_high_and_can_be_unpacked(git_repo, tmp_path) -> None:
    """A run that left a complete trail scores well — and says why, component by component."""
    store, orchestrator = _completed(tmp_path, git_repo)
    payload = score_run(store, orchestrator.run_id).to_payload()

    assert [component["key"] for component in payload["components"]] == list(EXPECTED_KEYS)
    assert payload["score"] >= 90, payload
    assert payload["band"] == "A"
    for component in payload["components"]:
        assert component["detail"], f"{component['key']} must state what decided it"
        assert component["evidence"], f"{component['key']} must name the facts behind it"
        assert 0.0 <= component["value"] <= 1.0, component


def test_the_score_is_the_weighted_mean_of_its_components(git_repo, tmp_path) -> None:
    """The number must be reproducible from what the panel shows beside it.

    A ring labelled 96.7 next to seven bars a reader can add up to something else is a number
    nobody can check, which defeats the point of showing the bars at all.
    """
    store, orchestrator = _completed(tmp_path, git_repo)
    payload = score_run(store, orchestrator.run_id).to_payload()

    total_weight = sum(component["weight"] for component in payload["components"])
    earned = sum(component["score"] for component in payload["components"])
    assert payload["score"] == pytest.approx(earned / total_weight * 100, abs=0.05)


def test_the_payload_states_that_the_score_is_not_a_verdict(git_repo, tmp_path) -> None:
    store, orchestrator = _completed(tmp_path, git_repo)
    payload = score_run(store, orchestrator.run_id).to_payload()

    assert "不代表" in payload["scale_note"]
    assert "事实" in payload["scale_note"]
    # The notes must say the model's own judgement is not an input. Otherwise a reader has no way
    # to know whether "the model said it was fine" is part of the number.
    assert any("模型" in note for note in payload["notes"])
    assert payload["run_id"] == orchestrator.run_id


def test_the_bands_are_ordered_and_cover_the_range() -> None:
    assert _band(100) == "A"
    assert _band(90) == "A"
    assert _band(89.9) == "B"
    assert _band(75) == "B"
    assert _band(60) == "C"
    assert _band(40) == "D"
    assert _band(0) == "E"
    # Monotone the right way round: A is the *best* band, so the index must never climb as the
    # score rises. An inverted comparison here would pass on any band function that is ordered.
    order = "ABCDE"
    previous = len(order)
    for score in range(0, 101):
        index = order.index(_band(float(score)))
        assert index <= previous, f"a higher score got a worse band at {score}"
        previous = index


def test_an_unknown_run_is_refused_rather_than_scored(tmp_path) -> None:
    """A missing run must raise, not return a zero: "no evidence" and "no such run" differ."""
    store = EventStore(tmp_path / "ws" / "daedalus.db")
    with pytest.raises(KeyError):
        score_run(store, "run_does_not_exist")


# ------------------------------------------------------------------- components


def test_the_committed_run_has_full_gate_and_acceptance_coverage(git_repo, tmp_path) -> None:
    store, orchestrator = _completed(tmp_path, git_repo)
    payload = score_run(store, orchestrator.run_id).to_payload()

    assert _component(payload, "gate_coverage")["value"] == 1.0
    assert _component(payload, "gate_coverage")["severity"] == "ok"
    # The acceptance command really ran, so the evidence is a record rather than an assumption.
    assert _component(payload, "test_evidence")["value"] == 1.0
    assert _component(payload, "test_evidence")["severity"] == "ok"
    assert _component(payload, "digest_completeness")["value"] == 1.0
    assert _component(payload, "evidence_completeness")["value"] == 1.0


def test_a_run_with_no_committed_step_scores_on_missing_evidence(tmp_path, git_repo) -> None:
    """A run that never committed cannot score well, however clean its log looks."""
    store, orchestrator = _run(
        tmp_path,
        git_repo,
        # No ops: the worker produces an empty diff, so the run fails rather than commits.
        worker=ScriptedWorker(ops=(), worker_id="worker-empty"),
        park_on_escalation=False,
    )
    result = orchestrator.run()
    assert result.status != RunState.COMPLETED.value

    payload = score_run(store, orchestrator.run_id).to_payload()
    assert _component(payload, "gate_coverage")["value"] == 0.0
    assert _component(payload, "gate_coverage")["severity"] == "warn"
    assert any("没有任何已提交的步骤" in note for note in payload["notes"])
    assert payload["score"] < 70, payload


def test_a_boundary_violation_is_not_averaged_away(git_repo, tmp_path) -> None:
    """One recorded attempt to leave the declared area zeroes its own component.

    This is the property that makes the score more than a sum: a boundary violation is
    disqualifying, so a run with a violation and otherwise perfect evidence must not read as
    "nearly perfect".
    """
    store, orchestrator = _completed(tmp_path, git_repo)
    baseline = score_run(store, orchestrator.run_id).to_payload()
    assert _component(baseline, "boundary_compliance")["value"] == 1.0

    # Record a Tier-1 whitelist failure the way the gate does, then re-score. Going through the
    # real append keeps the test honest about the shape the component reads.
    run = store.get_run(orchestrator.run_id)
    store.append_many(
        [
            {
                "aggregate_id": f"{orchestrator.run_id}:{TARGET}",
                "execution_id": str(run["execution_id"]),
                "event_type": "StepTier1Decided",
                "actor": "gatekeeper",
                "payload": {"summary": "01_path_whitelist=fail 02_...", "decision": "REVISE"},
                "correlation_id": "score-test",
            }
        ]
    )
    after = score_run(store, orchestrator.run_id).to_payload()
    boundary = _component(after, "boundary_compliance")
    assert boundary["value"] == 0.0
    assert boundary["severity"] == "bad"
    assert any("01_path_whitelist" in line for line in boundary["evidence"])
    assert after["score"] < baseline["score"]


def test_an_unverified_high_risk_signoff_zeroes_approval_integrity(git_repo, tmp_path) -> None:
    """For a high-risk spec, a typed name is not a signature, and the score must say so.

    The component is `info` when no signature is required at all — "not applicable" and "required
    but missing" are different facts and must not render the same.
    """
    store, orchestrator = _completed(tmp_path, git_repo, risk=RiskLevel.NORMAL)
    payload = score_run(store, orchestrator.run_id).to_payload()
    normal = _component(payload, "approval_integrity")
    assert normal["value"] == 1.0
    assert normal["severity"] == "info"
    assert "不要求" in normal["detail"]

    # Flip the stored spec to high risk *without* a verified approval, which is exactly the state
    # a typed name leaves behind.
    store.connection.execute(
        "UPDATE specs SET risk_level = 'high', approval_verified = 0, approved_by = 'someone' "
        "WHERE spec_digest = ?",
        (str(store.get_run(orchestrator.run_id)["spec_digest"]),),
    )
    store.connection.commit()
    after = score_run(store, orchestrator.run_id).to_payload()
    approval = _component(after, "approval_integrity")
    assert approval["value"] == 0.0
    assert approval["severity"] == "bad"
    assert any("someone" in line for line in approval["evidence"])


def test_a_clean_run_is_not_penalised_on_attempt_economy(git_repo, tmp_path) -> None:
    """Efficiency is the lowest-weighted factor on purpose: it must not dominate safety."""
    store, orchestrator = _completed(tmp_path, git_repo)
    payload = score_run(store, orchestrator.run_id).to_payload()

    economy = _component(payload, "attempt_economy")
    assert economy["value"] == 1.0
    assert economy["weight"] == 1.0, "efficiency must carry the smallest weight"
    assert economy["weight"] < min(
        _component(payload, key)["weight"]
        for key in ("gate_coverage", "boundary_compliance")
    )


def test_a_retried_run_reports_the_attempts_it_spent(git_repo, tmp_path) -> None:
    """The evidence for the efficiency component is the attempt counts, not a feeling."""
    store, orchestrator = _run(
        tmp_path,
        git_repo,
        worker=_PerAttemptWorker(
            scripts=(
                (FileOp(op="write", path=TARGET, content=BROKEN_IMPLEMENTATION),),
                (FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            )
        ),
    )
    result = orchestrator.run()
    assert result.status == RunState.COMPLETED.value, result.describe()
    attempts = [row["attempt"] for row in store.list_steps(orchestrator.run_id)]
    assert max(attempts) >= 2, f"the fixture must really retry, got attempts={attempts}"

    payload = score_run(store, orchestrator.run_id).to_payload()
    economy = _component(payload, "attempt_economy")
    assert economy["value"] < 1.0, "a retry must cost something, or the component measures nothing"
    assert "重试" in economy["detail"]
    assert any("次尝试" in line for line in economy["evidence"])
    # And the retry shows up in the aggregate rather than being lost in the mean.
    assert payload["score"] < 100

def test_a_step_that_parked_is_not_reported_as_retried(git_repo, tmp_path) -> None:
    """`attempt` is the attempt a step is on; retries are `attempt - 1`, not "uncommitted".

    Deriving retries by subtracting the committed count from the attempt total said "1 次是重试"
    for a run whose single attempt parked for a human owner. A component in this module exists to
    state facts, and that was a false one - in the factor an operator reads as "did this waste
    work?", which is exactly where a wrong answer is most tempting to act on.
    """
    from daedalus.application.gatekeeper.tier2 import Tier2Gate
    from daedalus.application.orchestrator import RunOrchestrator
    from tests.test_approval_and_resume import AlwaysEscalate, _request

    store = EventStore(tmp_path / "parked.db")
    bundle = DeterministicPlanner().plan(_request(RiskLevel.NORMAL))
    orchestrator = RunOrchestrator(
        store=store,
        repo_path=git_repo,
        run_root=tmp_path / "wt",
        bundle=bundle,
        worker=ScriptedWorker(
            ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
            worker_id="worker-parked",
        ),
        tier2=Tier2Gate(reviewer=AlwaysEscalate()),
        park_on_escalation=True,
    )
    orchestrator.register_spec()
    result = orchestrator.run()
    assert result.status == RunState.AWAITING_APPROVAL.value, result.describe()

    step = store.list_steps(orchestrator.run_id)[0]
    assert step["state"] == "ESCALATED" and int(step["attempt"]) == 1, step
    economy = _component(score_run(store, orchestrator.run_id).to_payload(), "attempt_economy")
    assert economy["detail"] == "共 1 次尝试，0 次是重试", economy
    assert economy["evidence"] == ["0/1 个步骤最终提交，共 1 次尝试"], economy
    # One attempt that parked is not a retry, and the value says no attempt produced a commit.
    assert economy["value"] == 0.0
