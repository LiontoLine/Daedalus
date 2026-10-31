"""Deterministic source windows; no model, gold patch or filesystem access."""

from __future__ import annotations

import ast
import re


def _caller_queries(tree: ast.Module, words: set[str]) -> list[str]:
    """Find one syntactic local caller and argument producer, not an exhaustive proof."""
    named_owners = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)} & words
    for owner in ast.walk(tree):
        if not isinstance(owner, ast.ClassDef):
            continue
        methods = {n.name: n for n in owner.body
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        targets = methods.keys() & words
        if named_owners and owner.name not in named_owners:
            continue
        for caller in methods.values():
            for call in ast.walk(caller):
                if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and isinstance(call.func.value, ast.Name)
                        and call.func.value.id == "self" and call.func.attr in targets):
                    continue
                arguments = {n.id for arg in (*call.args, *(k.value for k in call.keywords))
                             for n in ast.walk(arg) if isinstance(n, ast.Name)}
                bindings = {}
                for statement in caller.body:
                    if statement.lineno >= call.lineno:
                        break
                    written = {n.id for n in ast.walk(statement)
                               if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
                    for name in written & arguments:
                        # Conditional or nontrivial reassignment defeats this small resolver.
                        bindings.pop(name, None)
                        if isinstance(statement, ast.Assign):
                            bindings[name] = statement.value
                for producer in bindings.values():
                    # A producer also named in the query still needs its own source window.
                    if (isinstance(producer, ast.Call)
                            and isinstance(producer.func, ast.Attribute)
                            and isinstance(producer.func.value, ast.Name)
                            and producer.func.value.id == "self"
                            and producer.func.attr in methods
                            and producer.func.attr != call.func.attr):
                        return [f"{owner.name}.{producer.func.attr}",
                                f"{owner.name}.{caller.name}"]
    return []


def source_view(
    text: str, query: str, *, limit: int = 8000, fallback_query: str = "",
    include_callers: bool = False,
) -> str:
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
        if include_callers and limit >= 1200:
            flow = _caller_queries(tree, words)
            if flow:
                primary = source_view(text, query, limit=limit // 4 - 50)
                producer = source_view(text, flow[0], limit=limit // 2 - 50)
                caller = source_view(text, flow[1], limit=limit // 4 - 50)
                return (
                    "FOCAL CURRENT SOURCE:\n" + primary
                    + "\nARGUMENT PRODUCER " + flow[0] + ":\n" + producer
                    + "\nLOCAL CALLER " + flow[1] + ":\n" + caller
                )[:limit]
        classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
        named_methods = {
            method
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name in words
            for method in node.body
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
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
                if node in named_methods:
                    # Class-qualified queries must outrank unrelated same-name methods.
                    priority = 3000
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
        if fallback_query:
            return source_view(text, fallback_query, limit=limit)
        return "[TRUNCATED: source prefix only]\n" + text[: limit - 50]
    selected, remaining = set(), max(0, limit - 250)
    ordered = [node for _, _, node in sorted(ranked, key=lambda row: row[:2])[:6]]
    registrations = [
        n for n in tree.body
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
        and isinstance(n.value.func, ast.Attribute)
        and isinstance(n.value.func.value, ast.Name)
        and n.value.func.value.id in words
    ]
    ordered = registrations[:4] + ordered
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
                and len(doc.value.value) > 120
            ):
                # Keep the closing delimiter and following comments contiguous
                # with the first statement, so edits can preserve the docstring.
                indices = [i for i in indices if not doc.lineno - 1 <= i < doc.end_lineno - 1]
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
