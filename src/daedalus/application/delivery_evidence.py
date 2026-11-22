"""Read-only projection of Git publication receipts, not acceptance or current ref state."""
from __future__ import annotations

import re


def delivery_events(store, run):
    """Bind the latest publication attempt and its matching completion to this execution."""
    request, completed = None, None
    conflict = False
    for event in store.events_for(f"delivery:{run['run_id']}"):
        if event.execution_id != run["execution_id"]:
            continue
        if event.event_type == "DeliveryRequested":
            request, completed = event, None
            subject = event.payload
            commit, branch = subject.get("commit"), subject.get("target_branch")
            conflict = not (
                subject.get("run_id") == run["run_id"]
                and subject.get("execution_id") == run["execution_id"]
                and subject.get("spec_digest") == run["spec_digest"]
                and isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit)
                and isinstance(branch, str) and branch
            )
        elif event.event_type == "DeliveryCompleted":
            if request is None or event.payload != request.payload:
                conflict = True
            elif not conflict:
                completed = event
    return request, None if conflict else completed, conflict


def delivery_view(store, run) -> dict:
    request, completed, conflict = delivery_events(store, run)
    subject = request.payload if request and not conflict else {}
    if conflict:
        status = "EVIDENCE_CONFLICT"
    elif completed:
        status = "PUBLISHED"
    elif request:
        status = "PENDING_CONFIRMATION"
    elif run["status"] in {"FAILED", "PARTIAL_FAILURE", "CANCELLED", "ROLLED_BACK"}:
        status = "NOT_PUBLISHED"
    else:
        status = "NOT_RECORDED"
    return {
        "status": status,
        "commit": subject["commit"] if completed else "",
        "candidate_commit": subject.get("commit", ""),
        "target_branch": subject.get("target_branch", ""),
        "confirmed_at": completed.timestamp if completed else "",
    }
