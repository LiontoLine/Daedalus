"""Event-only trunk reads distinguish accepted evidence from rejected candidates."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from daedalus.application.trunk_view import trunk_view


class RecordedStore:
    """Minimal read surface; any attempted side effect fails with AttributeError."""

    def __init__(self):
        self.events = []

    def get_run(self, run_id):
        return {"run_id": "root", "execution_id": "execution"} if run_id == "root" else None

    def events_for_execution(self, execution_id):
        assert execution_id == "execution"
        return self.events

    def record(self, kind, payload, aggregate="run:root"):
        self.events.append(SimpleNamespace(
            aggregate_id=aggregate, event_id=f"event-{len(self.events)}", event_type=kind,
            timestamp="2026-10-30T00:00:00Z", payload=deepcopy(payload),
        ))


def frozen(store):
    contract = {
        "spec_digest": "original-spec", "goal_intent": "original goal", "invariants": ["original invariant"],
        "nodes": [
            {"node_id": node_id, "deps": deps, "objective": f"objective {node_id}",
             "expected_artifacts": [f"{node_id}.py"], "expectations": [
                 {"criterion_id": node_id, "kind": "script", "statement": f"criterion {node_id}",
                  "command": f"check-{node_id}"},
             ]}
            for node_id, deps in [("a", []), ("b", ["a"])]
        ],
    }
    store.record("TrunkExpectationsFrozen", contract)
    return contract


def snapshot(commit, a="MET", b="MET"):
    return {"spec_digest": "original-spec", "commit": commit, "digest": f"snapshot-{commit}",
            "nodes": [{"node_id": node_id, "status": state, "score": float(state == "MET"), "deps": deps,
                       "expectations": [{"criterion_id": node_id, "statement": "not the frozen statement",
                                         "status": state, "evidence": {"source": "final", "rows": []}}]}
                      for node_id, state, deps in [("a", a, []), ("b", b, ["a"])]],
            "failed_criteria": [node_id for node_id, state in [("a", a), ("b", b)] if state == "UNMET"]}


def test_legacy_runs_do_not_infer_expectation_evidence_or_mutate_history():
    store = RecordedStore()
    store.record("StepCommitted", {"node_id": "a", "commit": "legacy"})
    store.record("GoalAuditCompleted", {"decision": "APPROVE", "commit": "legacy"}, "goal:root")
    before = deepcopy([event.payload for event in store.events])
    view = trunk_view(store, "root")
    assert view["enabled"] is False
    assert view["nodes"] == []
    assert view["commit"] == ""
    assert [event.payload for event in store.events] == before
    assert trunk_view(store, "missing")["enabled"] is False


def test_frozen_initial_evidence_does_not_confuse_execution_with_satisfaction():
    store = RecordedStore()
    contract = frozen(store)
    store.record("StepCommitted", {"node_id": "a", "commit": "not-evidence"})
    view = trunk_view(store, "root")
    assert view["contract"] == contract
    assert [node["status"] for node in view["nodes"]] == ["UNKNOWN", "BLOCKED"]
    assert all(node["score"] == 0 for node in view["nodes"])
    assert "not correctness probability" in view["coverage_disclaimer"]


def test_local_deltas_reuse_tier1_rows_and_invalidate_before_applying_new_evidence():
    store = RecordedStore()
    frozen(store)
    store.record("TrunkNodeValidated", {"node_id": "a", "commit": "first", "criteria": [
        {"criterion_id": "a", "ok": True, "executed": True},
    ]})
    view = trunk_view(store, "root")
    assert [node["status"] for node in view["nodes"]] == ["MET", "UNKNOWN"]
    store.record("TrunkNodeValidated", {"node_id": "b", "commit": "second", "invalidated_nodes": ["a", "b"],
                                       "criteria": [{"criterion_id": "b", "ok": True, "executed": True}]})
    view = trunk_view(store, "root")
    assert [node["status"] for node in view["nodes"]] == ["STALE", "MET"]
    assert [node["commit"] for node in view["nodes"]] == ["first", "second"]
    assert view["commit"] == "second"
    assert view["nodes"][0]["score"] == 0


def test_failure_detail_does_not_erase_previously_recorded_failed_criteria():
    store = RecordedStore()
    frozen(store)
    row = {"criterion_id": "a", "ok": False, "executed": True, "detail": "assertion failed"}
    store.record("TrunkNodeFailed", {"node_id": "a", "commit": "retained", "criteria": [row]})
    store.record("TrunkNodeFailed", {"node_id": "a", "commit": "retained", "criteria": [],
                                     "reason": "retained patch before reset"})
    view = trunk_view(store, "root")
    assert view["nodes"][0]["status"] == "UNMET"
    assert view["nodes"][0]["expectations"][0]["evidence"]["rows"] == [row]
    assert view["failed_criteria"] == ["a"]


def test_goal_snapshot_supersedes_cached_rows_without_rewriting_immutable_snapshots():
    store = RecordedStore()
    frozen(store)
    old = snapshot("old")
    store.record("GoalTrunkSnapshot", old, "goal:root")
    store.record("TrunkNodeValidated", {"node_id": "b", "commit": "new", "invalidated_nodes": ["a"],
                                       "criteria": [{"criterion_id": "b", "ok": True}]})
    current = snapshot("new", "UNMET", "UNKNOWN")
    store.record("GoalTrunkSnapshot", current, "goal:root")
    view = trunk_view(store, "root")
    assert [node["status"] for node in view["nodes"]] == ["UNMET", "UNKNOWN"]
    assert view["nodes"][0]["expectations"][0]["statement"] == "criterion a"
    assert view["snapshots"] == [old, current]
    assert view["digest"] == "snapshot-new"
    view["snapshots"][0]["nodes"][0]["status"] = "UNMET"
    view["contract"]["goal_intent"] = "tampered"
    reread = trunk_view(store, "root")
    assert reread["snapshots"][0] == old
    assert reread["contract"]["goal_intent"] == "original goal"


def test_rejected_branch_and_child_events_never_become_current_trunk():
    store = RecordedStore()
    frozen(store)
    store.record("GoalTrunkSnapshot", snapshot("accepted"), "goal:root")
    store.record("RepairBranchStarted", {"branch_id": "branch", "node_id": "a", "base_commit": "accepted",
                                         "affected_node_ids": ["a", "b"]}, "goal:root")
    store.record("TrunkNodeValidated", {"node_id": "a", "commit": "private-child", "criteria": []}, "run:child")
    store.record("RepairBranchRejected", {"branch_id": "branch", "commit": "failed-candidate",
                                          "reasons": ["invariant failed"],
                                          "validation": {"snapshot": snapshot("failed-candidate", "UNMET")}}, "goal:root")
    view = trunk_view(store, "root")
    assert view["commit"] == "accepted"
    assert [node["status"] for node in view["nodes"]] == ["MET", "MET"]
    assert view["branches"][0]["status"] == "REJECTED"
    assert len(view["branches"][0]["events"]) == 2
    assert view["candidates"][0]["snapshot"]["commit"] == "failed-candidate"
    assert len(view["snapshots"]) == 1


def test_promotion_is_explicit_and_goal_snapshot_reestablishes_current_evidence():
    store = RecordedStore()
    frozen(store)
    store.record("GoalTrunkSnapshot", snapshot("old"), "goal:root")
    store.record("RepairBranchPromoted", {"branch_id": "good", "node_id": "a", "base_commit": "old",
                                          "commit": "accepted-new", "affected_node_ids": ["a", "b"],
                                          "validation": {"snapshot": snapshot("accepted-new")}}, "goal:root")
    interim = trunk_view(store, "root")
    assert interim["commit"] == "accepted-new"
    assert all(node["status"] == "STALE" for node in interim["nodes"])
    assert interim["digest"] == ""
    store.record("GoalTrunkSnapshot", snapshot("accepted-new"), "goal:root")
    view = trunk_view(store, "root")
    assert all(node["status"] == "MET" for node in view["nodes"])
    assert view["branches"][0]["status"] == "PROMOTED"
    assert view["digest"] == "snapshot-accepted-new"


