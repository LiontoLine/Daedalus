"""Small, versioned read-only observations available to the coding worker."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from daedalus.domain.canonical import digest_of
from daedalus.infrastructure.retrieval_tools import RepositorySearch
from daedalus.security.outbound import assert_outbound_clean

MAX_INSPECTIONS = 3


@dataclass(frozen=True)
class InspectionRequest:
    tool: str
    arguments: dict
    gap: str

    @classmethod
    def parse(cls, payload: dict) -> InspectionRequest:
        if not isinstance(payload, dict):
            raise ValueError("inspection request must be an object")
        tool, gap = payload.get("tool"), payload.get("gap")
        fields = {"read": {"path", "line"}, "grep": {"query", "path"}, "symbol": {"name", "path"}}
        if not isinstance(tool, str) or tool not in fields:
            raise ValueError("inspection supports read, grep and symbol only")
        if not isinstance(gap, str) or not 0 < len(gap.strip()) <= 240:
            raise ValueError("inspection requires an evidence gap up to 240 characters")
        if payload.get("operations", []) != []:
            raise ValueError("inspection cannot include file edits")
        args = {key: payload[key] for key in fields[tool] if key in payload}
        required = {"read": "path", "grep": "query", "symbol": "name"}[tool]
        value = args.get(required)
        if not isinstance(value, str) or not 0 < len(value.strip()) <= 240:
            raise ValueError("inspection requires a bounded nonempty argument")
        if "path" in args and tool != "read":
            from daedalus.domain.pathglob import normalize_path
            path = args["path"]
            if (not isinstance(path, str) or not path or len(path) > 240
                    or path.startswith("/") or ".." in path.split("/")
                    or normalize_path(path) != path
                    or any(c in path for c in "*?[\\")):
                raise ValueError("inspection requires an exact repository-relative path")
        if tool == "read":
            args.setdefault("line", 1)
            if type(args["line"]) is not int or not 1 <= args["line"] <= 100000:
                raise ValueError("inspection requires a positive integer line")
        assert_outbound_clean(json.dumps(args) + gap, where="coding inspection request")
        return cls(tool, args, gap.strip())

    @property
    def identity(self) -> str:
        return digest_of({"tool": self.tool, "arguments": self.arguments})


@dataclass(frozen=True)
class InspectionObservation:
    content: str
    receipt: dict


class RepositoryInspector:
    def __call__(self, sandbox, context, request: InspectionRequest) -> InspectionObservation:
        tools = RepositorySearch(str(sandbox.worktree_path))
        if request.tool == "read":
            row = tools.read(request.arguments["path"], request.arguments["line"])
            rows = [row] if row else []
        elif request.tool == "grep":
            paths = (request.arguments["path"],) if "path" in request.arguments else ()
            rows = tools.grep(request.arguments["query"], paths=paths, limit=3, scoped=bool(paths))
        else:
            paths = (request.arguments["path"],) if "path" in request.arguments else ()
            rows = tools.symbol(request.arguments["name"], paths=paths, limit=3)
        # Keep the observation bounded even if a repository has unusually long lines.
        rows = [{**row, "text": row["text"][:2400]} for row in rows[:3]]
        content = json.dumps(
            {
                "tool": request.tool,
                "arguments": dict(request.arguments),
                "commit": tools.head,
                "status": "found" if rows else "not_found",
                "sources": rows,
            },
            ensure_ascii=False,
        )
        assert_outbound_clean(content, where="coding inspection observation")
        return InspectionObservation(
            content,
            {
                "tool": request.tool,
                "arguments": dict(request.arguments),
                "request_digest": request.identity,
                "commit": tools.head,
                "evidence_digest": digest_of(rows),
                "sources": sorted({row["path"] for row in rows}),
                "status": "found" if rows else "not_found",
            },
        )


def safe_receipts(extra: dict) -> list[dict]:
    """Persist only bounded observation metadata, never arbitrary worker extra fields."""
    if not isinstance(extra, dict):
        return []
    values = extra.get("inspection_receipts", [])
    if not isinstance(values, list):
        return []
    result = []
    for row in values[:MAX_INSPECTIONS]:
        if not isinstance(row, dict) or not isinstance(row.get("tool"), str):
            continue
        if row["tool"] not in {"read", "grep", "symbol"}:
            continue
        if not isinstance(row.get("status"), str) or row["status"] not in {"found", "not_found"}:
            continue
        if any(
            not isinstance(row.get(k), str) or not re.fullmatch(r"[0-9a-f]{64}", row[k])
            for k in ("request_digest", "evidence_digest")
        ):
            continue
        if not isinstance(row.get("commit"), str) or not re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})", row["commit"]
        ):
            continue
        if not isinstance(row.get("arguments"), dict):
            continue
        try:
            request = InspectionRequest.parse(
                {**row["arguments"], "tool": row["tool"], "gap": "recorded observation"}
            )
        except (ValueError, TypeError):
            continue
        if request.identity != row["request_digest"]:
            continue
        paths = row.get("sources")
        if (
            not isinstance(paths, list)
            or len(paths) > 3
            or any(not isinstance(p, str) or len(p) > 500 for p in paths)
        ):
            continue
        value = {
            key: row[key]
            for key in (
                "tool",
                "arguments",
                "status",
                "commit",
                "request_digest",
                "evidence_digest",
                "sources",
            )
        }
        value["arguments"] = dict(request.arguments)
        assert_outbound_clean(json.dumps(value), where="inspection metadata")
        result.append(value)
    return result
