"""Evidence coverage is not correctness, approval, or a global repair permission."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from daedalus.application.repair_evidence import (
    affected_nodes,
    build_snapshot,
    criterion_status,
    diagnose_criteria,
    freeze_contract,
    select_candidates,
    validation_criteria,
)
from daedalus.domain.canonical import digest_of
from daedalus.domain.spec import (
    AcceptanceCriterion,
    AssertionKind,
    BoundarySpec,
    GoalSpec,
    MetaSpec,
    PlanNode,
    PlanSpec,
    SpecBundle,
)


def assertion(name, *, path=None):
    return AcceptanceCriterion(
        criterion_id=name,
        kind=AssertionKind.EXPECTED_FILE,
        path=path or f"src/{name}.py",
        statement=f"original {name} behavior",
    )


def node(name, *criteria, deps=(), artifacts=None):
    return PlanNode(
        node_id=name,
        objective=f"original {name} objective",
        deps=deps,
        expected_artifacts=(f"src/{name}.py",) if artifacts is None else artifacts,
        extra={"acceptance_criteria": [criterion.to_dict() for criterion in criteria]}
        if criteria else {},
    )


def bundle_for(nodes, criteria):
    return SpecBundle(
        goal=GoalSpec(
            goal_id="goal",
            objective="unchanged original intent",
            invariants=("preserve the invariant",),
            acceptance_criteria=tuple(criteria),
        ),
        plan=PlanSpec(plan_id="plan", goal_id="goal", nodes=tuple(nodes)),
        boundary=BoundarySpec(boundary_id="boundary", goal_id="goal", fs_whitelist=("src/**",)),
        meta=MetaSpec(),
    )


def check(criterion, ok=True, **extra):
    return {"criterion_id": criterion.criterion_id, "ok": ok, "exit_code": 0 if ok else 1,
            "error_code": "", **extra}


def review(criterion, status, evidence="specific original-goal evidence"):
    return {"criterion_id": criterion.criterion_id, "status": status, "evidence": evidence}


def records(snapshot):
    return {row["node_id"]: row for row in snapshot["nodes"]}


def test_freeze_records_exact_original_contract_and_inherited_goal_criteria():
    criterion = assertion("a")
    bundle = bundle_for([node("a")], [criterion])
    frozen = freeze_contract(bundle)
    assert frozen == {
        "spec_digest": bundle.digest(),
        "goal_intent": bundle.goal.objective,
        "invariants": list(bundle.goal.invariants),
        "nodes": [{"node_id": "a", "deps": [], "objective": "original a objective",
                   "expected_artifacts": ["src/a.py"], "expectations": [criterion.to_dict()]}],
    }
    assert validation_criteria(bundle, {"node_id": "a"}, build_snapshot(bundle, "head")) == (criterion,)


def test_freeze_and_snapshot_do_not_leak_mutable_input_references():
    criterion = replace(assertion("a"), expect={"nested": [1]})
    bundle = bundle_for([node("a", criterion)], [criterion])
    frozen = freeze_contract(bundle)
    frozen["nodes"][0]["expectations"][0]["expect"]["nested"].append(2)
    assert criterion.expect == {"nested": [1]}
    row = check(criterion, behavior_evidence={"receipt": ["original"]})
    snapshot = build_snapshot(bundle, "head", criteria=[row])
    row["behavior_evidence"]["receipt"].append("later")
    assert records(snapshot)["a"]["expectations"][0]["evidence"]["rows"][0]["behavior_evidence"] == {
        "receipt": ["original"]}


def test_snapshot_is_digest_bound_to_commit_spec_and_evidence():
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion)], [criterion])
    initial = build_snapshot(bundle, "one", criteria=[check(criterion)])
    same = build_snapshot(bundle, "one", criteria=[check(criterion)])
    different_commit = build_snapshot(bundle, "two", criteria=[check(criterion)])
    different_evidence = build_snapshot(bundle, "one", criteria=[check(criterion, False)])
    assert initial == same
    assert initial["digest"] == digest_of({k: v for k, v in initial.items() if k != "digest"})
    assert len({initial["digest"], different_commit["digest"], different_evidence["digest"]}) == 3
    initial["nodes"][0]["score"] = 999
    with pytest.raises(ValueError, match="digest mismatch"):
        select_candidates(bundle, initial)
    with pytest.raises(ValueError, match="frozen spec"):
        validation_criteria(replace(bundle, goal=replace(bundle.goal, objective="changed")),
                            {"node_id": "a"}, same)


def test_latest_final_evidence_overrides_old_node_validation_even_when_invalidated():
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion)], [criterion])
    snapshot = build_snapshot(
        bundle, "head", criteria=[check(criterion, False)],
        node_evidence={"a": [check(criterion)]}, node_states={"a": "STALE"},
    )
    record = records(snapshot)["a"]
    assert record["status"] == "UNMET"
    assert record["score"] == 0
    assert record["expectations"][0]["evidence"]["source"] == "final"
    assert snapshot["failed_criteria"] == ["a"]


def test_unknown_blocked_and_stale_are_distinct_and_not_repairable():
    a, b, c = (assertion(name) for name in ("a", "b", "c"))
    bundle = bundle_for([node("a", a), node("b", b, deps=("a",)), node("c", c)], [a, b, c])
    snapshot = build_snapshot(bundle, "head", node_evidence={"c": [check(c)]},
                              node_states={"c": "STALE"})
    assert {key: row["status"] for key, row in records(snapshot).items()} == {
        "a": "UNKNOWN", "b": "BLOCKED", "c": "STALE"}
    assert select_candidates(bundle, snapshot) == []
    assert snapshot["failed_criteria"] == []


@pytest.mark.parametrize("state", ["MET", "UNMET", "COMMITTED", "FAILED"])
def test_execution_or_node_state_does_not_manufacture_criterion_evidence(state):
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion)], [criterion])
    snapshot = build_snapshot(bundle, "head", node_states={"a": state})
    assert records(snapshot)["a"]["status"] == "UNKNOWN"
    assert select_candidates(bundle, snapshot) == []


def test_natural_language_requires_real_semantic_evidence_not_gate_success():
    criterion = AcceptanceCriterion("intent", AssertionKind.NATURAL_LANGUAGE, statement="correct priority")
    bundle = bundle_for([node("a", criterion)], [criterion])
    skipped = {"criterion_id": "intent", "kind": "natural_language", "executed": False}
    assert records(build_snapshot(bundle, "head", criteria=[skipped]))["a"]["status"] == "UNKNOWN"
    assert criterion_status(criterion, [check(criterion)]) == "UNKNOWN"
    assert criterion_status(criterion, [review(criterion, "MET", " ")]) == "UNKNOWN"
    snapshot = build_snapshot(bundle, "head", criteria=[skipped],
                              semantic_criteria=[review(criterion, "UNMET", "wrong priority order")])
    assert records(snapshot)["a"]["status"] == "UNMET"
    assert select_candidates(bundle, snapshot)[0]["node_id"] == "a"
    passed = build_snapshot(bundle, "head", criteria=[skipped], semantic_criteria=[review(criterion, "MET")])
    assert records(passed)["a"]["status"] == "MET"


def test_tier1_failure_is_not_rescued_by_semantic_met_and_semantic_unmet_vetoes_pass():
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion)], [criterion])
    for ok, semantic in [(False, "MET"), (True, "UNMET")]:
        snapshot = build_snapshot(bundle, "head", criteria=[check(criterion, ok)],
                                  semantic_criteria=[review(criterion, semantic)])
        assert records(snapshot)["a"]["status"] == "UNMET"
        assert select_candidates(bundle, snapshot)[0]["criterion_ids"] == ["a"]


@pytest.mark.parametrize("extra", [
    {"error_code": "execution_environment_unavailable"},
    {"error_code": "command_timeout"},
    {"blocked_by": "dependency_integrity"},
])
def test_infrastructure_failures_are_blocked_not_concrete_repair_targets(extra):
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion)], [criterion])
    snapshot = build_snapshot(bundle, "head", criteria=[check(criterion, False, **extra)],
                              semantic_criteria=[review(criterion, "UNMET")])
    assert records(snapshot)["a"]["status"] == "BLOCKED"
    assert select_candidates(bundle, snapshot) == []


def test_wrong_priority_selects_upstream_concrete_failure_not_blocked_descendant():
    a, b = assertion("a"), assertion("b")
    bundle = bundle_for([node("a", a), node("b", b, deps=("a",))], [a, b])
    snapshot = build_snapshot(bundle, "head", criteria=[check(a, False)])
    assert records(snapshot)["b"]["status"] == "BLOCKED"
    assert select_candidates(bundle, snapshot) == [{
        "node_id": "a", "affected_node_ids": ["a", "b"], "criterion_ids": ["a"],
        "reason": "concrete unmet original expectations: a",
    }]
    both_failed = build_snapshot(bundle, "head", criteria=[check(a, False), check(b, False)])
    assert [row["node_id"] for row in select_candidates(bundle, both_failed)] == ["a"]
    assert select_candidates(bundle, both_failed, excluded=("a",)) == []


def test_candidates_rank_smallest_scope_then_reverse_topological_order():
    a, b, c, d = (assertion(name) for name in ("a", "b", "c", "d"))
    bundle = bundle_for([node("a", a), node("b", b), node("c", c),
                         node("d", d, deps=("a",))], [a, b, c, d])
    snapshot = build_snapshot(bundle, "head", criteria=[check(a, False), check(b, False), check(c, False)])
    assert [row["node_id"] for row in select_candidates(bundle, snapshot)] == ["c", "b", "a"]
    assert [row["node_id"] for row in select_candidates(bundle, snapshot, excluded=("c",))] == ["b", "a"]


def test_shared_artifact_and_downstream_invalidation_reaches_fixed_point_not_unrelated_nodes():
    criteria = [assertion(name) for name in ("a", "b", "c", "d", "e", "unrelated")]
    a, b, c, d, e, unrelated = criteria
    bundle = bundle_for([
        node("a", a, artifacts=("src/shared.py",)),
        node("b", b, artifacts=("./src/shared.py",)),
        node("c", c, deps=("b",), artifacts=("src/next.py",)),
        node("d", d, artifacts=("src/next.py",)),
        node("e", e, deps=("d",)),
        node("unrelated", unrelated),
    ], criteria)
    assert affected_nodes(bundle, "a") == ("a", "b", "c", "d", "e")
    snapshot = build_snapshot(bundle, "head", node_evidence={
        n.node_id: [check(c)] for n, c in zip(bundle.plan.nodes, criteria, strict=True)
    }, node_states={key: "STALE" for key in affected_nodes(bundle, "a") if key != "a"})
    assert records(snapshot)["e"]["status"] == "STALE"
    assert records(snapshot)["unrelated"]["status"] == "MET"


def test_actual_changed_files_attribute_additional_owners_and_their_descendants():
    a, b, c, untouched = (assertion(name) for name in ("a", "b", "c", "untouched"))
    bundle = bundle_for([node("a", a), node("b", b), node("c", c, deps=("b",)),
                         node("untouched", untouched)], [a, b, c, untouched])
    assert affected_nodes(bundle, "a", changed_files=("src/b.py",)) == ("a", "b", "c")
    assert affected_nodes(bundle, "a", changed_files=("src/no-owner.py",)) == ("a",)


def test_shared_globs_are_conservative_but_preserve_disjoint_artifacts():
    a, b, c = assertion("a"), assertion("b"), assertion("c")
    bundle = bundle_for([node("a", a, artifacts=("src/pkg/*.py",)),
                         node("b", b, artifacts=("src/pkg/a*",)),
                         node("c", c, artifacts=("src/elsewhere/c.py",))], [a, b, c])
    assert affected_nodes(bundle, "a") == ("a", "b")


def test_inherited_goal_expectations_use_original_path_owners_not_global_writable_guess():
    a, b = assertion("a"), assertion("b")
    bundle = bundle_for([node("a"), node("b")], [a, b])
    snapshot = build_snapshot(bundle, "head", criteria=[check(a, False), check(b)])
    assert [row["node_id"] for row in select_candidates(bundle, snapshot)] == ["a"]
    command = AcceptanceCriterion("global", AssertionKind.TEST_RESULT, command="python3 -m pytest")
    ambiguous = bundle_for([node("a"), node("b")], [command])
    assert select_candidates(ambiguous, build_snapshot(ambiguous, "head", criteria=[check(command, False)])) == []


def test_missing_original_artifacts_never_produce_a_repair_candidate():
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion, artifacts=())], [criterion])
    assert select_candidates(bundle, build_snapshot(bundle, "head", criteria=[check(criterion, False)])) == []


def test_validation_retains_affected_and_already_met_goal_checks_without_unrelated_unmet():
    a, b, c, d = (assertion(name) for name in ("a", "b", "c", "d"))
    bundle = bundle_for([node("a", a), node("b", b, deps=("a",)), node("c", c), node("d", d)],
                        [a, b, c, d])
    snapshot = build_snapshot(bundle, "head", criteria=[check(a, False), check(b), check(c), check(d, False)])
    candidate = next(row for row in select_candidates(bundle, snapshot) if row["node_id"] == "a")
    assert validation_criteria(bundle, candidate, snapshot) == (a, b, c)
    # Actual affected owners supplied after a real edit expand validation, never narrow it.
    assert validation_criteria(bundle, {**candidate, "affected_node_ids": ["d"]}, snapshot) == (a, b, d, c)


def test_identical_duplicate_ids_deduplicate_and_conflicting_frozen_ids_fail_closed():
    a, b = assertion("a"), assertion("b")
    bundle = bundle_for([node("a", a), node("b", a, b, deps=("a",))], [a, b])
    snapshot = build_snapshot(bundle, "head", criteria=[check(a), check(b)])
    assert validation_criteria(bundle, {"node_id": "a"}, snapshot) == (a, b)
    conflicting = replace(bundle, plan=replace(bundle.plan, nodes=(
        node("a", replace(a, path="src/different.py")), node("b", b),
    )))
    for operation in (
        lambda: freeze_contract(conflicting),
        lambda: build_snapshot(conflicting, "head"),
        lambda: validation_criteria(conflicting, {"node_id": "a"}, snapshot),
    ):
        with pytest.raises(ValueError, match="conflicting frozen criterion: a"):
            operation()


def test_semantic_unknown_does_not_become_repair_permission_or_deterministic_approval():
    a, b = assertion("a"), assertion("b")
    bundle = bundle_for([node("a", a, b)], [a, b])
    snapshot = build_snapshot(bundle, "head", criteria=[check(a), check(b)],
                              semantic_criteria=[review(b, "UNKNOWN", "intent not established")])
    record = records(snapshot)["a"]
    assert record["score"] == 0.5
    assert record["status"] == "UNKNOWN"
    assert select_candidates(bundle, snapshot) == []


def test_malformed_status_is_unknown_not_a_concrete_repair():
    criterion = assertion("a")
    assert criterion_status(criterion, [{"criterion_id": "a", "status": ["MET"]}]) == "UNKNOWN"


def test_diagnosis_reports_ambiguous_global_owners_without_selecting_them():
    criterion = AcceptanceCriterion("global", AssertionKind.TEST_RESULT, command="python3 -m pytest")
    bundle = bundle_for([node("a"), node("b")], [criterion])
    snapshot = build_snapshot(bundle, "head", criteria=[check(criterion, False, executed=True)])
    diagnostic = diagnose_criteria(bundle, snapshot)
    row = diagnostic["criteria"][0]
    assert row["criterion_id"] == "global" and row["status"] == "UNMET"
    assert [owner["node_id"] for owner in row["owner_candidates"]] == ["a", "b"]
    assert all(owner["ownership_basis"] == "ambiguous_inherited_global"
               and not owner["selected"] for owner in row["owner_candidates"])
    assert row["ambiguity_reason"] and row["non_repairable_reason"] == "ambiguous_global_ownership"
    assert select_candidates(bundle, snapshot) == []


def test_executed_failure_diagnosis_explains_frozen_path_and_affected_range():
    a, b, c = assertion("a"), assertion("b"), assertion("c")
    bundle = bundle_for([node("a"), node("b", b, deps=("a",)), node("c", c)], [a, b, c])
    snapshot = build_snapshot(bundle, "tree", criteria=[
        check(a, False, executed=True, output="expected original behavior"),
    ])
    row = next(item for item in diagnose_criteria(bundle, snapshot)["criteria"]
               if item["criterion_id"] == "a")
    owner = row["owner_candidates"][0]
    assert owner["node_id"] == "a"
    assert owner["ownership_basis"] == "inherited_path_overlap"
    assert owner["matched_frozen_paths"] == ["src/a.py"]
    assert owner["affected_node_ids"] == ["a", "b"] and owner["selected"]
    receipt = row["evidence_provenance"][0]
    assert receipt["source"] == "final" and receipt["executed"] is True
    assert receipt["row_status"] == "UNMET" and receipt["evidence"] == "expected original behavior"


def test_uncertain_diagnoses_and_semantic_unmet_keep_existing_authority():
    a, b, c = assertion("a"), assertion("b"), assertion("c")
    semantic = AcceptanceCriterion("intent", AssertionKind.NATURAL_LANGUAGE, statement="correct order")
    bundle = bundle_for([node("a", a), node("b", b, deps=("a",)), node("c", c),
                         node("semantic", semantic)], [a, b, c, semantic])
    snapshot = build_snapshot(
        bundle, "head", node_evidence={"c": [check(c)]}, node_states={"c": "STALE"},
        semantic_criteria=[review(semantic, "UNMET", "wrong order")],
    )
    rows = {row["criterion_id"]: row for row in diagnose_criteria(bundle, snapshot)["criteria"]}
    assert {key: rows[key]["status"] for key in "abc"} == {
        "a": "UNKNOWN", "b": "BLOCKED", "c": "STALE",
    }
    assert all(rows[key]["non_repairable_reason"] for key in "abc")
    assert rows["intent"]["owner_candidates"][0]["selected"]
    assert [candidate["node_id"] for candidate in select_candidates(bundle, snapshot)] == ["semantic"]


def test_diagnosis_redacts_full_evidence_before_excerpt_and_bounds_serialized_context():
    criteria = [assertion(f"criterion-{index}") for index in range(40)]
    bundle = bundle_for([node(f"node-{index}", criterion)
                         for index, criterion in enumerate(criteria)], criteria)
    credential = "sk-" + "A" * 32
    snapshot = build_snapshot(bundle, "head", criteria=[
        check(criterion, False, output="failure " * 3000 + credential)
        for criterion in criteria
    ])
    diagnostic = diagnose_criteria(bundle, snapshot)
    serialized = json.dumps(diagnostic, ensure_ascii=False)
    assert credential not in serialized
    assert len(serialized) < 13000
    assert diagnostic["truncated"] and diagnostic["criteria_omitted"] > 0
    assert all(row["status"] == "UNMET" for row in diagnostic["criteria"])
    assert len(select_candidates(bundle, snapshot)) == 40


@pytest.mark.parametrize("kind", [AssertionKind.EXPECTED_FILE, AssertionKind.NATURAL_LANGUAGE])
def test_semantic_extras_cannot_become_execution_or_change_repair_classification(kind):
    criterion = replace(assertion("a"), kind=kind)
    bundle = bundle_for([node("a", criterion)], [criterion])
    untrusted = {
        **review(criterion, "UNMET", "the original behavior is absent"),
        "ok": True, "executed": True, "error_code": "command_timeout",
        "blocked_by": "invented dependency", "output": "invented execution output",
        "behavior_evidence": {"receipt": {"complete": True, "passed": True}},
        "evidence_type": "deterministic",
    }
    snapshot = build_snapshot(bundle, "head", semantic_criteria=[untrusted])
    expectation = records(snapshot)["a"]["expectations"][0]
    assert expectation["status"] == "UNMET"
    assert expectation["evidence"]["rows"] == [{
        **review(criterion, "UNMET", "the original behavior is absent"),
        "evidence_type": "semantic",
    }]
    assert select_candidates(bundle, snapshot)[0]["criterion_ids"] == ["a"]
    provenance = diagnose_criteria(bundle, snapshot)["criteria"][0]["evidence_provenance"][0]
    assert provenance["evidence_type"] == "semantic"
    assert provenance["executed"] is None
    assert provenance["error_code"] == provenance["blocked_by"] == ""
    assert provenance["row_status"] == "UNMET"


def test_semantic_execution_claim_cannot_rescue_a_native_failure():
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion)], [criterion])
    snapshot = build_snapshot(
        bundle, "head", criteria=[check(criterion, False, executed=True)],
        semantic_criteria=[{**review(criterion, "MET"), "ok": True, "executed": True}],
    )
    assert records(snapshot)["a"]["status"] == "UNMET"
    assert select_candidates(bundle, snapshot)[0]["criterion_ids"] == ["a"]
    provenance = diagnose_criteria(bundle, snapshot)["criteria"][0]["evidence_provenance"]
    assert [(row["evidence_type"], row["executed"], row["row_status"]) for row in provenance] == [
        ("deterministic", True, "UNMET"), ("semantic", None, "MET"),
    ]


@pytest.mark.parametrize("consumer", [select_candidates, diagnose_criteria])
@pytest.mark.parametrize("mutation", [
    "missing_node", "duplicate_node", "foreign_node", "missing_criterion",
    "duplicate_criterion", "foreign_criterion", "foreign_row_id", "missing_evidence",
    "foreign_dependency", "missing_dependency", "node_status", "criterion_status",
    "forged_satisfaction", "forged_failure", "forged_score", "forged_failed_criteria",
    "foreign_source", "empty_final_rows", "untyped_row", "wrong_native_kind",
    "wrong_native_command", "wrong_criterion_digest",
])
def test_recomputed_digest_does_not_make_malformed_frozen_snapshots_usable(consumer, mutation):
    a, b = assertion("a"), assertion("b")
    bundle = bundle_for([node("a", a), node("b", b, deps=("a",))], [a, b])
    snapshot = build_snapshot(bundle, "head", criteria=[check(a, False), check(b)])
    first, second = snapshot["nodes"]
    expectation = first["expectations"][0]
    row = expectation["evidence"]["rows"][0]
    if mutation == "missing_node":
        snapshot["nodes"].pop()
    elif mutation == "duplicate_node":
        snapshot["nodes"][1] = deepcopy(first)
    elif mutation == "foreign_node":
        first["node_id"] = "not-frozen"
    elif mutation == "missing_criterion":
        first["expectations"].clear()
    elif mutation == "duplicate_criterion":
        first["expectations"].append(deepcopy(expectation))
    elif mutation == "foreign_criterion":
        expectation["criterion_id"] = "not-frozen"
    elif mutation == "foreign_row_id":
        row["criterion_id"] = "b"
    elif mutation == "missing_evidence":
        expectation.pop("evidence")
    elif mutation == "foreign_dependency":
        second["deps"] = ["not-frozen"]
    elif mutation == "missing_dependency":
        second["deps"] = []
    elif mutation == "node_status":
        first["status"] = "APPROVED"
    elif mutation == "criterion_status":
        expectation["status"] = ["UNMET"]
    elif mutation == "forged_satisfaction":
        expectation["status"] = first["status"] = "MET"
        first["score"] = 1.0
        snapshot["failed_criteria"] = []
    elif mutation == "forged_failure":
        second["expectations"][0]["status"] = second["status"] = "UNMET"
        second["score"] = 0.0
        snapshot["failed_criteria"] = ["a", "b"]
    elif mutation == "forged_score":
        first["score"] = 1.0
    elif mutation == "forged_failed_criteria":
        snapshot["failed_criteria"] = []
    elif mutation == "foreign_source":
        expectation["evidence"]["source"] = "approved"
    elif mutation == "empty_final_rows":
        expectation["evidence"]["rows"] = []
    elif mutation == "untyped_row":
        row.pop("evidence_type")
    elif mutation == "wrong_native_kind":
        row["kind"] = AssertionKind.NATURAL_LANGUAGE.value
    elif mutation == "wrong_native_command":
        row["command"] = "another check"
    elif mutation == "wrong_criterion_digest":
        row["criterion_digest"] = "another criterion"
    snapshot["digest"] = digest_of({key: value for key, value in snapshot.items() if key != "digest"})
    with pytest.raises(ValueError, match="malformed frozen snapshot"):
        consumer(bundle, snapshot)


@pytest.mark.parametrize("extra", [{"ok": True}, {"executed": True}, {"behavior_evidence": {}}])
def test_semantic_snapshot_cannot_reintroduce_stripped_native_fields(extra):
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion)], [criterion])
    snapshot = build_snapshot(bundle, "head", semantic_criteria=[review(criterion, "UNMET")])
    snapshot["nodes"][0]["expectations"][0]["evidence"]["rows"][0].update(extra)
    snapshot["digest"] = digest_of({key: value for key, value in snapshot.items() if key != "digest"})
    for consumer in (select_candidates, diagnose_criteria):
        with pytest.raises(ValueError, match="malformed frozen snapshot"):
            consumer(bundle, snapshot)


def test_shared_final_criterion_cannot_have_conflicting_node_receipts():
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion), node("b", criterion)], [criterion])
    snapshot = build_snapshot(bundle, "head", criteria=[check(criterion, False)])
    forged = snapshot["nodes"][1]
    forged["expectations"][0]["evidence"]["rows"][0]["ok"] = True
    forged["expectations"][0]["status"] = forged["status"] = "MET"
    forged["score"] = 1.0
    snapshot["digest"] = digest_of({key: value for key, value in snapshot.items() if key != "digest"})
    with pytest.raises(ValueError, match="malformed frozen snapshot"):
        diagnose_criteria(bundle, snapshot)


def test_stale_cached_rows_and_current_final_evidence_replay_without_false_repairs():
    a, b, c = (assertion(name) for name in ("a", "b", "c"))
    bundle = bundle_for([node("a", a, b), node("c", c, deps=("a",))], [a, b, c])
    snapshot = build_snapshot(
        bundle, "new-head", criteria=[check(a)],
        node_evidence={"a": [check(a, False), check(b, False)]},
        node_states={"a": "STALE"},
    )
    assert [row["status"] for row in records(snapshot)["a"]["expectations"]] == ["MET", "STALE"]
    assert records(snapshot)["c"]["status"] == "BLOCKED"
    assert select_candidates(bundle, snapshot) == []
    diagnostic = {row["criterion_id"]: row for row in diagnose_criteria(bundle, snapshot)["criteria"]}
    assert diagnostic["b"]["status"] == "STALE"
    assert diagnostic["b"]["non_repairable_reason"] == "stale_evidence"
    assert diagnostic["c"]["status"] == "BLOCKED"


def test_semantic_unknown_with_native_extras_stays_uncertain():
    criterion = assertion("a")
    bundle = bundle_for([node("a", criterion)], [criterion])
    snapshot = build_snapshot(
        bundle, "head", criteria=[check(criterion)],
        semantic_criteria=[{**review(criterion, "UNKNOWN", "intent is unestablished"),
                            "ok": True, "executed": True, "exit_code": 0}],
    )
    assert records(snapshot)["a"]["status"] == "UNKNOWN"
    assert select_candidates(bundle, snapshot) == []
    diagnostic = diagnose_criteria(bundle, snapshot)["criteria"][0]
    assert diagnostic["non_repairable_reason"] == "missing_or_unknown_evidence"
    semantic = next(row for row in diagnostic["evidence_provenance"]
                    if row["evidence_type"] == "semantic")
    assert semantic["executed"] is None and semantic["row_status"] == "UNKNOWN"
