"""Bounded committed local dependency evidence for a semantic reviewer.

This is code lookup, not a vector search or a correctness proof. It grants no tools
to the reviewer. Source text is untrusted and passes the usual outbound secret gate.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import PurePosixPath

from daedalus.application.source_context import source_view
from daedalus.infrastructure.git_sandbox import GitSandbox, _git
from daedalus.infrastructure.retrieval_tools import RepositorySearch
from daedalus.security.outbound import assert_outbound_clean

MAX_FILES = 3
MAX_FILE_CHARS = 3000


def dependency_context(
    sandbox: GitSandbox, changed_files: tuple[str, ...], *, query: str = ""
) -> str:
    commit = sandbox.head()
    candidates: set[str] = set()
    changed = set(changed_files)
    changed_lines = {}
    if query:
        path, line = "", 0
        for value in sandbox.diff().patch.splitlines():
            if value.startswith("+++ b/"):
                path = value[6:]
                changed_lines.setdefault(path, set())
            elif value.startswith("@@ "):
                match = re.search(r"\+(\d+)", value)
                line = int(match[1]) if match else 0
            elif path and value.startswith("+"):
                changed_lines[path].add(line)
                line += 1
            elif path and value.startswith("-"):
                changed_lines[path].add(line)
            elif value.startswith(" "):
                line += 1
    priority = {}
    search = None
    resolved_symbols = set()
    candidate_sources = []
    for name in sorted(changed):
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or path.suffix != ".py":
            continue
        resolved = sandbox.resolve_inside(name)
        if (
            not resolved.is_file()
            or resolved.relative_to(sandbox.worktree_path.resolve()).as_posix() != name
        ):
            continue
        try:
            candidate = sandbox.read_file(name)
            tree = ast.parse(candidate)
            local_query = query
            classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
            focus = set(re.findall(r"[A-Za-z_]\w*", query))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    node.lineno <= line <= node.end_lineno for line in changed_lines.get(name, ())
                ):
                    focus.add(node.name)
            local_query += "\nChanged symbols: " + " ".join(sorted(focus))
            parents = focus & classes.keys()
            inherited = set()
            for _ in range(3):
                bases = {
                    base.id
                    for cls in parents
                    for base in classes[cls].bases
                    if isinstance(base, ast.Name)
                }
                inherited |= bases
                parents = bases & classes.keys()
            if query and len(candidate_sources) < 2:
                assert_outbound_clean(candidate, where="candidate review source before selection")
                candidate_sources.append(
                    {
                        "path": name,
                        "base_commit": commit,
                        "source_kind": "candidate_worktree",
                        "sha256": hashlib.sha256(candidate.encode()).hexdigest(),
                        "truncated": len(candidate) > 3200,
                        "text": source_view(candidate, local_query, limit=3200),
                    }
                )
        except (SyntaxError, UnicodeError):
            continue
        for node in ast.walk(tree):
            if query and isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if (alias.asname or alias.name) not in inherited | focus:
                        continue
                    if alias.name in resolved_symbols or len(resolved_symbols) >= 4:
                        continue
                    resolved_symbols.add(alias.name)
                    # Resolve re-exports through versioned definitions, never installed packages.
                    if search is None:
                        search = RepositorySearch(str(sandbox.worktree_path))
                    for found in search.symbol(alias.name, limit=3):
                        definition = found["path"]
                        if (
                            definition not in changed
                            and "tests" not in PurePosixPath(definition).parts
                        ):
                            candidates.add(definition)
                            priority.setdefault(definition, set()).add(alias.name)
            names = (
                [item.name for item in node.names]
                if isinstance(node, ast.Import)
                else (
                    ([node.module] if node.module else [item.name for item in node.names])
                    if isinstance(node, ast.ImportFrom)
                    else []
                )
            )
            for module in names:
                parent = PurePosixPath(".")
                if isinstance(node, ast.ImportFrom) and node.level:
                    parent = path.parent
                    for _ in range(node.level - 1):
                        parent = parent.parent
                stem = parent / module.replace(".", "/")
                candidates.update((str(stem) + ".py", str(stem / "__init__.py")))
                if not isinstance(node, ast.ImportFrom) or not node.level:
                    candidates.update(
                        ("src/" + str(stem) + ".py", "src/" + str(stem / "__init__.py"))
                    )
    sources = []
    omitted = []
    selected = sorted(candidates - changed, key=lambda path: (path not in priority, path))
    for name in selected[:24]:
        # Read Git objects, never symlinks, untracked files or the host's installed modules.
        entry = _git(sandbox.worktree_path, ["ls-tree", commit, "--", name], check=True)
        if not entry.stdout.strip():
            continue
        mode, kind, rest = entry.stdout.strip().split(maxsplit=2)
        blob = rest.split("\t", 1)[0]
        if kind != "blob" or mode not in {"100644", "100755"}:
            omitted.append({"path": name, "reason": "not_regular_committed_file"})
            continue
        size = int(_git(sandbox.worktree_path, ["cat-file", "-s", blob], check=True).stdout)
        if size > (500000 if query else 100000) or len(sources) >= (2 if query else MAX_FILES):
            omitted.append({"path": name, "reason": "context_limit"})
            continue
        content = _git(sandbox.worktree_path, ["show", f"{commit}:{name}"], check=True).stdout
        assert_outbound_clean(content, where="a committed review dependency")
        limit = 1500 if query else MAX_FILE_CHARS
        sources.append(
            {
                "path": name,
                "blob": blob,
                "sha256": hashlib.sha256(content.encode()).hexdigest(),
                "truncated": len(content) > limit,
                "text": source_view(
                    content, query + " " + " ".join(sorted(priority.get(name, ()))), limit=limit
                )
                if query
                else content[:limit],
            }
        )
    if not sources and not omitted and not candidate_sources:
        return ""
    return json.dumps(
        {
            "commit": commit,
            "sources": sources,
            "candidate_sources": candidate_sources,
            "omitted": omitted,
            "candidates_truncated": len(selected) > 24,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
