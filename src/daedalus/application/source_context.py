"""Deterministic source windows; no model, gold patch or filesystem access."""

from __future__ import annotations

import ast
import re


def source_view(text: str, query: str, *, limit: int = 8000) -> str:
    """Keep exact source slices and their lines, prioritizing named Python symbols.

    Full-source secret checking belongs to the caller, before this lossy operation.
    Omitted code is explicitly marked; this view never grants additional read access.
    """
    if len(text) <= limit:
        return text
    lines = text.splitlines(keepends=True)
    words = set(re.findall(r"[A-Za-z_][A-Za-z_0-9]*", query))
    common = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "return",
        "self",
        "None",
        "True",
        "False",
        "value",
        "values",
        "existing",
        "public",
        "code",
        "issue",
        "this",
        "that",
        "def",
        "class",
    }
    meaningful = words - common
    ranked = []
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError):
        tree = None
    if tree is not None:
        classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or (
                isinstance(node, ast.ClassDef) and node.name in words
            ):
                identifiers = set(
                    re.findall(
                        r"[A-Za-z_][A-Za-z_0-9]*", "".join(lines[node.lineno - 1 : node.end_lineno])
                    )
                )
                priority = 1000 if isinstance(node, ast.ClassDef) else 2000
                score = (priority if node.name in words else 0) + min(
                    30, len(identifiers & meaningful)
                )
                if score:
                    ranked.append((-score, node.lineno, node))
        # A named subclass needs the constructor that interprets its class attributes.
        for name in words & classes.keys():
            pending = [classes[name]]
            for _ in range(2):
                parents = [
                    classes[b.id]
                    for child in pending
                    for b in child.bases
                    if isinstance(b, ast.Name) and b.id in classes
                ]
                for parent in parents:
                    for method in parent.body:
                        if isinstance(method, ast.FunctionDef) and method.name in {
                            "__new__",
                            "__init__",
                        }:
                            ranked.append((-900, method.lineno, method))
                pending = parents
    if not ranked:
        return "[TRUNCATED: source prefix only]\n" + text[: limit - 50]
    selected, remaining = set(), max(0, limit - 250)
    ordered = [node for _, _, node in sorted(ranked, key=lambda row: row[:2])[:6]]
    ordered += [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))][:8]
    for node in ordered:
        indices = list(range(max(0, node.lineno - 3), node.end_lineno))
        if isinstance(node, ast.ClassDef) and sum(len(lines[i]) for i in indices) > limit // 2:
            # Never fill the window with the beginning of a large enclosing class.
            indices = list(range(max(0, node.lineno - 3), node.lineno))
            for child in node.body:
                if isinstance(child, (ast.Assign, ast.AnnAssign)):
                    indices += list(range(child.lineno - 1, child.end_lineno))
                if len(indices) > 20:
                    break
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            doc = node.body[0]
            if (
                isinstance(doc, ast.Expr)
                and isinstance(doc.value, ast.Constant)
                and isinstance(doc.value.value, str)
                and len(doc.value.value) > 400
            ):
                indices = [i for i in indices if not doc.lineno + 2 <= i < doc.end_lineno - 2]
        fresh = [i for i in indices if i not in selected]
        if not fresh:
            continue
        size = sum(len(lines[i]) for i in fresh)
        if size + 70 > remaining:
            # Keep both control-flow entry and the result/exception tail explicitly.
            front, back = [], []
            allowance = max(0, remaining - 100)
            used = 0
            for i in fresh:
                if used + len(lines[i]) > allowance * 0.7:
                    break
                front.append(i)
                used += len(lines[i])
            for i in reversed(fresh):
                if i in front or used + len(lines[i]) > allowance:
                    break
                back.append(i)
                used += len(lines[i])
            fresh = front + back
            size = used
        selected.update(fresh)
        remaining -= size + 70
        if remaining < 100:
            break
    groups = []
    for i in sorted(selected):
        if groups and groups[-1][1] == i:
            groups[-1] = (groups[-1][0], i + 1)
        else:
            groups.append((i, i + 1))
    return (
        "[TRUNCATED: selected source windows; omitted code exists]\n"
        + "\n".join(
            f"LINES {start + 1}-{end}:\n" + "".join(lines[start:end]) for start, end in groups
        )
    )[:limit]


def failure_excerpt(text: str, *, limit: int = 1800) -> str:
    """Preserve the assertion/traceback tail instead of spending feedback on banners."""
    if len(text) <= limit:
        return text
    return text[:200] + "\n...[output omitted]...\n" + text[-(limit - 230) :]
