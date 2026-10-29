"""Tri-Spec and Meta-Spec contracts (Spec §2, §3, §13).

These tests encode the "model proposes, the contract disposes" rule: a plausible but
illegal spec must be rejected by validation, not argued with.
"""

from __future__ import annotations

import pytest

from daedalus.application.planner import (
    DeterministicPlanner,
    PlanRequest,
    SpecHardening,
)
from daedalus.domain.spec import (
    AcceptanceCriterion,
    AssertionKind,
    BoundarySpec,
    GoalSpec,
    MetaSpec,
    NetworkPolicy,
    PlanNode,
    PlanSpec,
    RiskLevel,
    SpecBundle,
)
from daedalus.errors import PlanGraphError, SpecError


def _goal(**overrides) -> GoalSpec:
    base = dict(
        goal_id="GOAL-1",
        objective="fix the counter",
        acceptance_criteria=(
            AcceptanceCriterion(
                criterion_id="AC-1", kind=AssertionKind.EXIT_CODE, command="true"
            ),
        ),
        risk_level=RiskLevel.NORMAL,
    )
    base.update(overrides)
    return GoalSpec(**base)


def _boundary(**overrides) -> BoundarySpec:
    base = dict(
        boundary_id="B-1",
        goal_id="GOAL-1",
        fs_whitelist=("src/**/*.py",),
        network_policy=NetworkPolicy.DENY,
    )
    base.update(overrides)
    return BoundarySpec(**base)


def _plan(nodes: tuple[PlanNode, ...], **overrides) -> PlanSpec:
    base = dict(plan_id="P-1", goal_id="GOAL-1", nodes=nodes)
    base.update(overrides)
    return PlanSpec(**base)


def test_goal_requires_an_executable_assertion() -> None:
    with pytest.raises(SpecError, match="executable"):
        _goal(
            acceptance_criteria=(
                AcceptanceCriterion(
                    criterion_id="AC-1",
                    kind=AssertionKind.NATURAL_LANGUAGE,
                    statement="it looks good to me",
                ),
            )
        ).validate()


def test_goal_requires_acceptance_criteria() -> None:
    with pytest.raises(SpecError):
        _goal(acceptance_criteria=()).validate()


def test_plan_rejects_a_cycle() -> None:
    nodes = (
        PlanNode(node_id="a", deps=("b",), expected_artifacts=("src/a.py",)),
        PlanNode(node_id="b", deps=("a",), expected_artifacts=("src/b.py",)),
    )
    with pytest.raises(PlanGraphError):
        _plan(nodes).validate()


def test_plan_rejects_unknown_deps_and_duplicates() -> None:
    with pytest.raises(PlanGraphError, match="unknown node"):
        _plan((PlanNode(node_id="a", deps=("ghost",), expected_artifacts=("src/a.py",)),)).validate()
    with pytest.raises(SpecError, match="unique"):
        _plan(
            (
                PlanNode(node_id="a", expected_artifacts=("src/a.py",)),
                PlanNode(node_id="a", expected_artifacts=("src/b.py",)),
            )
        ).validate()


def test_plan_requires_finite_timeout_and_artifacts() -> None:
    with pytest.raises(SpecError, match="timeout_sec"):
        _plan(
            (PlanNode(node_id="a", expected_artifacts=("src/a.py",), timeout_sec=0),)
        ).validate()
    with pytest.raises(SpecError, match="expected_artifacts"):
        _plan((PlanNode(node_id="a"),)).validate()


def test_retry_policy_cannot_be_infinite() -> None:
    from daedalus.domain.spec import RetryPolicy

    with pytest.raises(SpecError, match="max_attempts"):
        RetryPolicy.from_dict({"max_attempts": 10_000})


def test_boundary_requires_a_whitelist_and_consistent_network_policy() -> None:
    with pytest.raises(SpecError, match="fs_whitelist"):
        _boundary(fs_whitelist=()).validate()
    with pytest.raises(SpecError, match="allowed_domains"):
        _boundary(network_policy=NetworkPolicy.DENY, allowed_domains=("example.com",)).validate()
    with pytest.raises(SpecError, match="allowed_domains"):
        _boundary(network_policy=NetworkPolicy.ALLOWLIST, allowed_domains=()).validate()


def test_boundary_path_matching_semantics() -> None:
    boundary = _boundary(
        fs_whitelist=("src/**/*.py", "docs/*.md"),
        fs_denylist=("src/vendor/**",),
    )
    assert boundary.allows_path("src/example_project/textstats.py")
    assert boundary.allows_path("docs/readme.md")
    assert not boundary.allows_path("src/vendor/lib.py")
    assert not boundary.allows_path("src/example_project/secrets.py".replace("src/", "etc/"))
    assert not boundary.allows_path("README.md")
    assert not boundary.allows_path("")


def test_digest_ignores_timestamps_but_tracks_content() -> None:
    first = SpecBundle(
        goal=_goal(),
        plan=_plan((PlanNode(node_id="a", expected_artifacts=("src/a.py",)),)),
        boundary=_boundary(),
        meta=MetaSpec.default(),
    )
    second = SpecBundle(
        goal=_goal(created_at="2099-01-01T00:00:00Z"),
        plan=_plan((PlanNode(node_id="a", expected_artifacts=("src/a.py",)),)),
        boundary=_boundary(),
        meta=MetaSpec.default(),
    )
    assert first.digest() == second.digest()

    changed = SpecBundle(
        goal=_goal(objective="something else"),
        plan=_plan((PlanNode(node_id="a", expected_artifacts=("src/a.py",)),)),
        boundary=_boundary(),
        meta=MetaSpec.default(),
    )
    assert changed.digest() != first.digest()


def test_bundle_rejects_cross_spec_goal_mismatch() -> None:
    bundle = SpecBundle(
        goal=_goal(),
        plan=_plan((PlanNode(node_id="a", expected_artifacts=("src/a.py",)),), goal_id="OTHER"),
        boundary=_boundary(),
        meta=MetaSpec.default(),
    )
    with pytest.raises(SpecError, match="SPEC-02"):
        bundle.validate()


def test_meta_spec_refuses_self_relaxation() -> None:
    with pytest.raises(SpecError, match="Gatekeeper"):
        MetaSpec(
            protected_paths=("src/daedalus/domain/fsm.py",),
            allow_gatekeeper_self_modification=True,
        ).validate()
    with pytest.raises(SpecError, match="human approval"):
        MetaSpec(
            protected_paths=("src/daedalus/domain/fsm.py",),
            human_approval_required=("gatekeeper",),
        ).validate()


def test_hardening_strips_protected_paths_and_keeps_the_task_alive() -> None:
    request = PlanRequest(
        request_id="REQ-1",
        goal_id="GOAL-1",
        objective="fix the counter",
        target_paths=(
            "src/example_project/textstats.py",
            "src/daedalus/domain/fsm.py",  # protected
            ".env",  # always denied
        ),
        test_command="true",
    )
    bundle = DeterministicPlanner().plan(request)
    assert "src/example_project/textstats.py" in bundle.boundary.fs_whitelist
    assert "src/daedalus/domain/fsm.py" not in bundle.boundary.fs_whitelist
    assert ".env" not in bundle.boundary.fs_whitelist
    assert bundle.boundary.offending_paths(list(bundle.boundary.fs_whitelist)) == ()


def test_hardening_refuses_a_task_with_no_legal_target() -> None:
    request = PlanRequest(
        request_id="REQ-2",
        goal_id="GOAL-2",
        objective="rewrite the state machine",
        target_paths=("src/daedalus/domain/fsm.py",),
        test_command="true",
    )
    with pytest.raises(SpecError, match="Meta-Spec"):
        DeterministicPlanner().plan(request)


def test_meta_spec_marks_control_plane_paths_protected() -> None:
    meta = MetaSpec.default()
    assert meta.is_protected("src/daedalus/domain/fsm.py")
    assert meta.is_protected("src/daedalus/application/gatekeeper/tier1.py")
    assert not meta.is_protected("src/example_project/textstats.py")


def test_stale_downstream_closure() -> None:
    nodes = (
        PlanNode(node_id="a", expected_artifacts=("src/a.py",)),
        PlanNode(node_id="b", deps=("a",), expected_artifacts=("src/b.py",)),
        PlanNode(node_id="c", deps=("b",), expected_artifacts=("src/c.py",)),
        PlanNode(node_id="d", expected_artifacts=("src/d.py",)),
    )
    plan = _plan(nodes)
    plan.validate()
    assert plan.downstream_closure(("a",)) == ("a", "b", "c")
    assert plan.downstream_closure(("d",)) == ("d",)
