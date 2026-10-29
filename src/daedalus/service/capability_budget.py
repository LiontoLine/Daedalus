"""Explicit, immutable budget amendment; unknown supplier usage remains unknown."""

import hashlib
import json


def json_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def amended_parent_cost(old, parent, protocol):
    """Admit one sealed transport loss at the entire model context maximum.

    The 2.25 CNY allowance exceeds 1,100,000 input tokens at 2 CNY/M plus
    2,048 output tokens at 8 CNY/M. 1,100,000 exceeds either interpretation
    of the published 1M context. This is reserved budget, never reported usage.
    Any new unknown request still stops the experiment without another amendment.
    """
    if old.get("status") not in {"COMPLETE", "INCOMPLETE"}:
        raise ValueError("parent is not sealed")
    ledger = old.get("series-usage")
    if (not isinstance(ledger, dict) or json_digest(ledger) != parent["usage_sha256"]
            or json_digest(protocol) != parent["protocol_sha256"]
            or protocol.get("model") != "deepseek-flash"
            or protocol.get("inference_profile") != "deepseek_bounded_json"):
        raise ValueError("parent ledger or model no longer matches the amendment")
    allowances = parent.get("unknown_reservations", [])
    expected = {r["index"]: r for r in allowances}
    if len(expected) != len(allowances):
        raise ValueError("duplicate unknown reservation")
    used, seen = 0.0, set()
    for row in ledger["call_records"]:
        if not row.get("request_dispatched", True):
            continue
        if row.get("usage_available"):
            used += (row.get("prompt_tokens", 0)*2 + row.get("completion_tokens", 0)*8)/1e6
            continue
        allowance = expected.get(row["index"], {})
        if (allowance.get("input_digest") != row.get("input_digest")
                or row.get("max_output_tokens") != 2048
                or allowance.get("reserved_cost_cny") != 2.25
                or row.get("error_type") != "IncompleteRead"):
            raise ValueError("unreserved provider usage is unknown")
        used += 2.25
        seen.add(row["index"])
    if seen != set(expected):
        raise ValueError("unknown reservation no longer matches the sealed ledger")
    return used
