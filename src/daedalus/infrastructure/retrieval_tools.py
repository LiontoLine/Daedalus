"""Read-only, versioned repository search tools and structure-aware text chunks."""

from __future__ import annotations

import ast
import posixpath
import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from daedalus.infrastructure.git_sandbox import _git
from daedalus.security.outbound import SecretInPayload, assert_outbound_clean

TEXT_SUFFIXES = {".md", ".txt", ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java"}


def sections(text: str, *, limit: int = 1200) -> list[dict]:
    """Keep Markdown headings/paragraphs together; split long blocks at line boundaries.

    Line ranges always refer to the source. Fenced code is not mistaken for a heading.
    This is structural splitting, not a trained semantic segmenter.
    """
    lines = text.splitlines(keepends=True)
    result, start, heading, fence = [], 0, "", False

    def emit(stop):
        nonlocal start
        while start < stop:
            end, size = start, 0
            while end < stop and (size + len(lines[end]) <= limit or end == start):
                size += len(lines[end])
                end += 1
            body = "".join(lines[start:end])
            # An unusually long single line still has a bounded representation.
            for offset in range(0, len(body), limit):
                value = body[offset : offset + limit]
                if value.strip():
                    result.append(
                        {
                            "text": value,
                            "line_start": start + 1,
                            "line_end": end,
                            "section": heading,
                        }
                    )
            start = end

    for index, line in enumerate(lines):
        if line.lstrip().startswith(("```", "~~~")):
            fence = not fence
        if not fence and re.match(r"^#{1,6}\s+", line):
            emit(index)
            heading = line.strip().lstrip("#").strip()
        elif (
            not fence and not line.strip() and sum(map(len, lines[start : index + 1])) >= limit // 2
        ):
            emit(index + 1)
    emit(len(lines))
    return result


def patterns(query: str) -> list[str]:
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_./-]*|[\u4e00-\u9fff]{2,}", query)
    ignored = {
        "implement",
        "existing",
        "public",
        "according",
        "preserve",
        "modify",
        "only",
        "standard",
        "library",
        "never",
        "change",
        "tests",
        "test",
        "with",
        "from",
        "that",
        "this",
        "the",
        "and",
        "contract",
        "python3",
        "keep",
        "plan",
        "def",
        "class",
    }
    candidates = list(dict.fromkeys(w for w in words if len(w) >= 3 and w.lower() not in ignored))
    return sorted(candidates, key=lambda w: (not any(c in w for c in "_/."), -len(w)))[:6]


def _qualified_definitions(tree: ast.AST) -> dict[int, str]:
    names = {}
    pending = [(tree, ())]
    while pending:
        node, owners = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            owners = (*owners, node.name)
            names[id(node)] = ".".join(owners)
        pending.extend((child, owners) for child in ast.iter_child_nodes(node))
    return names


class RepositorySearch:
    """Read immutable Git objects, never working-tree files or symlink targets.

    By default observations name HEAD. A trusted caller may pin an existing commit
    or tree object by its full SHA and further restrict the eligible file paths.
    ``head`` always records the actual commit, independently of ``revision``.
    """

    def __init__(self, repo: str, *, revision: str | None = None,
                 allowed_paths: set[str] | None = None):
        if revision is not None and (
            not isinstance(revision, str)
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision)
        ):
            raise ValueError("repository search revision must be a full object SHA")
        self.repo = repo
        self.head = _git(repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
        if revision is not None:
            kind = _git(repo, ["cat-file", "-t", revision], check=False)
            if kind.exit_code or kind.stdout.strip() not in {"tree", "commit"}:
                raise ValueError("repository search revision must name a commit or tree")
        self.revision = revision if revision is not None else self.head
        self.files = {}
        self._texts = {}
        self._source_status = {}
        for row in _git(repo, ["ls-tree", "-r", self.revision], check=True).stdout.splitlines():
            meta, _, path = row.partition("\t")
            item = PurePosixPath(path)
            if (
                meta.startswith(("100644 blob ", "100755 blob "))
                and item.suffix.lower() in TEXT_SUFFIXES
                and (allowed_paths is None or path in allowed_paths)
                and not any(
                    p.startswith(".") or p in {"archive", "vendor", "node_modules"}
                    for p in item.parts
                )
            ):
                self.files[path] = meta.split()[2]

    def source(self, path: str) -> str | None:
        if path not in self.files:
            return None
        if path in self._texts:
            return self._texts[path]
        blob = self.files[path]
        if int(_git(self.repo, ["cat-file", "-s", blob], check=True).stdout) > 256000:
            self._texts[path] = None
            self._source_status[path] = "too_large"
            return None
        text = _git(self.repo, ["show", blob], check=True).stdout
        try:
            assert_outbound_clean(path + "\n" + text, where="repository search source")
        except SecretInPayload:
            self._source_status[path] = "blocked_sensitive"
            self._texts[path] = None
            return None
        self._texts[path] = text
        self._source_status[path] = "readable"
        return text

    def source_status(self, path: str) -> str:
        """Explain unavailable source without exposing its contents or secret findings."""
        self.source(path)
        return self._source_status.get(path, "not_found")

    def read(self, path: str, start: int = 1, *, lines: int = 30) -> dict | None:
        if not isinstance(start, int) or start < 1:
            return None
        text = self.source(path)
        if text is None:
            return None
        source_lines = text.splitlines(keepends=True)
        stop = min(len(source_lines), start - 1 + min(max(lines, 1), 60))
        snippet = "".join(source_lines[start - 1 : stop])[:2400]
        if not snippet.strip():
            return None
        return {
            "kind": "code" if PurePosixPath(path).suffix not in {".md", ".txt"} else "document",
            "source": f"git:{self.revision}:{path}",
            "title": f"{path}:{start}-{stop}",
            "text": snippet,
            "path": path,
            "line_start": start,
            "line_end": stop,
        }

    def grep(self, query: str, *, paths: tuple[str, ...] = (), limit: int = 6,
             scoped: bool = False) -> list[dict]:
        needles = patterns(query)
        if not needles:
            return []
        args = ["grep", "-l", "-z", "-I", "-F", "-i"]
        for needle in needles:
            args.extend(["-e", needle])
        args.extend([self.revision, "--"])
        if scoped:
            # Literal paths only: a tool request cannot inject Git pathspec magic.
            safe_paths = [p for p in paths if p in self.files]
            if not safe_paths:
                return []
            args.extend(":(literal)" + p for p in safe_paths)
        else:
            args.extend(f"*{suffix}" for suffix in sorted(TEXT_SUFFIXES))
        matched = _git(self.repo, args, check=False)
        if matched.exit_code not in {0, 1}:
            return []
        candidates = [
            path
            for value in matched.stdout.split("\0") if value
            if (path := value.removeprefix(self.revision + ":")) in self.files
        ]
        candidates.sort(key=lambda p: (p not in paths, p))
        result = []
        for path in candidates[:20]:
            text = self.source(path)
            if text is None:
                continue
            # The entire matched file was scanned before returning any snippet.
            covered_until = 0
            for line, value in enumerate(text.splitlines(), 1):
                if line <= covered_until or not any(
                    needle.casefold() in value.casefold() for needle in needles
                ):
                    continue
                chunk = self.read(path, max(1, line - 3), lines=22)
                if chunk:
                    result.append(chunk)
                    covered_until = chunk["line_end"]
                if len(result) >= limit:
                    return result
                if not scoped:
                    break
        return result

    def code_chunks(self, *, limit: int = 400) -> list[dict]:
        if limit <= 0:
            return []
        result = []
        paths = [p for p in sorted(self.files) if PurePosixPath(p).suffix not in {".md", ".txt"}]
        for path in paths[:80]:
            text = self.source(path)
            if text is None:
                continue
            spans = []
            if path.endswith(".py"):
                try:
                    tree = ast.parse(text)
                    spans = [
                        (node.lineno, node.end_lineno, node.name)
                        for node in ast.walk(tree)
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    ]
                except SyntaxError:
                    pass
            lines = text.splitlines(keepends=True)
            if not spans:
                spans = [(1, len(lines), "module")]
            for start, end, symbol in sorted(spans):
                segment = "".join(lines[start - 1 : end])
                for part in sections(segment):
                    result.append(
                        {
                            "kind": "code",
                            "source": f"git:{self.revision}:{path}",
                            "title": f"{path}::{symbol}",
                            "path": path,
                            "symbol": symbol,
                            **part,
                            "line_start": start + part["line_start"] - 1,
                            "line_end": start + part["line_end"] - 1,
                        }
                    )
                    if len(result) >= limit:
                        return result
        return result

    def enclosing_symbol(self, path: str, line: int) -> str | None:
        """Find the narrowest admitted Python definition containing a failure line."""
        if not path.endswith(".py") or type(line) is not int or line < 1:
            return None
        text = self.source(path)
        if text is None:
            return None
        try:
            tree = ast.parse(text)
        except (SyntaxError, RecursionError):
            return None
        definitions = [node for node in ast.walk(tree)
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and node.lineno <= line <= node.end_lineno]
        if not definitions:
            return None
        node = min(definitions, key=lambda value: value.end_lineno - value.lineno)
        return _qualified_definitions(tree)[id(node)]

    def related(self, path: str, line: int, *, limit: int = 1) -> list[dict]:
        """Bounded same-file Python relations; syntactic navigation, not a call graph."""
        if not path.endswith(".py") or type(line) is not int or line < 1 or limit <= 0:
            return []
        text = self.source(path)
        if text is None:
            return []
        try:
            tree = ast.parse(text)
        except (SyntaxError, RecursionError):
            return []
        classes = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
        functions = (ast.FunctionDef, ast.AsyncFunctionDef)
        owners = [(owner, node) for owner in classes.values() for node in owner.body
                  if isinstance(node, functions) and node.lineno - 3 <= line <= node.end_lineno]
        if not owners:
            return []
        containing = [pair for pair in owners if pair[1].lineno <= line]
        owner, focal = min(
            containing or owners, key=lambda pair: pair[1].end_lineno - pair[1].lineno,
        )
        # Symbol windows commonly start two lines before a definition. Prefer that
        # nearby header over the preceding method's final line, within the same class.
        following = [pair for pair in owners if pair[0] is owner and line < pair[1].lineno <= line + 3]
        if following and focal.lineno < line:
            owner, focal = min(following, key=lambda pair: pair[1].lineno)
        methods = {node.name: node for node in owner.body if isinstance(node, functions)}
        candidates = {}

        def add(priority, related_owner, method, relation):
            if method is not focal:
                previous = candidates.get(method.lineno)
                if previous is None or priority < previous[0]:
                    candidates[method.lineno] = (priority, related_owner, method, relation)

        def factory_scenario(method):
            for statement in method.body:
                if not (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                        and isinstance(statement.targets[0], ast.Name)
                        and isinstance(statement.value, ast.Call)):
                    continue
                factory = statement.targets[0].id
                if sum(isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
                       and node.id == factory for node in ast.walk(method)) != 1:
                    continue
                invocations = [
                    (tuple(ast.dump(arg) for arg in call.args),
                     tuple((kw.arg, ast.dump(kw.value)) for kw in call.keywords))
                    for call in ast.walk(method) if isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name) and call.func.id == factory
                ]
                if invocations:
                    return ast.dump(statement.value), tuple(invocations)
            return None

        if focal.name.startswith("test"):
            scenario = factory_scenario(focal)
            if scenario is not None:
                for method in methods.values():
                    other = factory_scenario(method) if method.name.startswith("test") else None
                    if other is not None and other[0] == scenario[0] and other[1] != scenario[1]:
                        add(-1, owner, method, "setup_variant")

        # A similarly named method in an unrelated class is not an override.
        descendants = {owner.name}
        for _ in range(min(len(classes), 8)):
            updated = descendants | {
                name for name, cls in classes.items()
                if any(isinstance(base, ast.Name) and base.id in descendants for base in cls.bases)
            }
            if updated == descendants:
                break
            descendants = updated
        for name in descendants - {owner.name}:
            for method in classes[name].body:
                if isinstance(method, functions) and method.name == focal.name:
                    add(0, classes[name], method, "overriding_definition")

        def self_call(node):
            return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "self")

        def fields(method, context):
            return {node.attr for node in ast.walk(method) if isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name) and node.value.id == "self"
                    and isinstance(node.ctx, context)}

        reads, writes = fields(focal, ast.Load), fields(focal, ast.Store)
        for method in methods.values():
            if method.name != "__init__" and reads & fields(method, ast.Store):
                add(2, owner, method, "state_writer")
            if writes & fields(method, ast.Load):
                add(4, owner, method, "state_consumer")
            bindings = {}
            for statement in method.body:
                stored = {node.id for node in ast.walk(statement)
                          if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
                if not isinstance(statement, ast.Assign):
                    for name in stored:
                        bindings.pop(name, None)
                for call in ast.walk(statement):
                    if not self_call(call) or call.func.attr != focal.name:
                        continue
                    args = {name.id for arg in (*call.args, *(kw.value for kw in call.keywords))
                            for name in ast.walk(arg) if isinstance(name, ast.Name)}
                    for name in args:
                        producer = bindings.get(name)
                        if producer in methods:
                            add(1, owner, methods[producer], "argument_producer")
                    add(3, owner, method, "local_caller")
                # Resolve only simple unconditional assignment after its RHS calls.
                if isinstance(statement, ast.Assign):
                    for name in stored:
                        bindings.pop(name, None)
                    if self_call(statement.value):
                        for target in statement.targets:
                            if isinstance(target, ast.Name):
                                bindings[target.id] = statement.value.func.attr
        for call in ast.walk(focal):
            if self_call(call) and call.func.attr in methods:
                add(5, owner, methods[call.func.attr], "direct_callee")
        result = []
        for _, related_owner, method, relation in sorted(
            candidates.values(), key=lambda row: (
                row[0], abs(row[2].lineno - focal.lineno), row[2].lineno,
            ),
        )[:min(limit, 2)]:
            start = max(1, method.lineno - 2)
            row = self.read(path, start, lines=min(60, method.end_lineno - start + 1))
            if row:
                result.append({
                    **row, "relation": relation, "symbol": related_owner.name + "." + method.name,
                    "related_to": owner.name + "." + focal.name, "syntactic_only": True,
                    "source_truncated": method.end_lineno > row["line_end"] or len(row["text"]) >= 2400,
                })
        return result

    def symbol(self, name: str, *, limit: int = 8, paths: tuple[str, ...] = ()) -> list[dict]:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}(?:[.][A-Za-z_][A-Za-z0-9_]{0,127}){0,7}", name):
            return []
        leaf = name.rsplit(".", 1)[-1]
        qualified = "." in name
        # Git narrows candidates by identifier first. The old first-80-files scan could
        # never reach implementations in a large repository's later directories.
        matched = _git(self.repo, ["grep", "-l", "-z", "-I", "-F", "-e", leaf,
                                   self.revision, "--", "*.py"], check=False)
        candidates = [p.removeprefix(self.revision + ":") for p in matched.stdout.split("\0") if p]
        candidates = sorted(p for p in candidates if p in self.files and (not paths or p in paths))
        definitions, callers = [], []
        for path in candidates[:80]:
            text = self.source(path)
            if text is None:
                continue
            try:
                tree = ast.parse(text)
            except (SyntaxError, RecursionError):
                continue
            owner_names = _qualified_definitions(tree) if qualified else {}
            module = path.removesuffix(".py").replace("/", ".")
            module = module.removesuffix(".__init__")
            for node in ast.walk(tree):
                relation = ""
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    and (node.name == leaf if not qualified else
                         name in {owner_names[id(node)], module + "." + owner_names[id(node)]})
                ):
                    relation = "definition"
                elif not qualified and isinstance(node, ast.Call) and (
                    (isinstance(node.func, ast.Name) and node.func.id == name)
                    or (isinstance(node.func, ast.Attribute) and node.func.attr == name)
                ):
                    relation = "caller"
                if relation:
                    start = max(1, node.lineno - 2)
                    is_function = relation == "definition" and isinstance(
                        node, (ast.FunctionDef, ast.AsyncFunctionDef),
                    )
                    lines = min(60, node.end_lineno - start + 1) if is_function else 24
                    row = self.read(path, start, lines=lines)
                    if row:
                        if is_function:
                            row["source_truncated"] = (
                                node.end_lineno > row["line_end"] or len(row["text"]) >= 2400
                            )
                        (definitions if relation == "definition" else callers).append(
                            {**row, "relation": relation, "symbol": name})
                    if len(definitions) >= limit:
                        return definitions[:limit]
        return (definitions + callers)[:limit]

    def follow_link(self, origin: dict, link_index: int = 0) -> dict | None:
        source = origin.get("source", "")
        if not source.startswith("git:" + self.revision + ":") or not isinstance(link_index, int):
            return None
        links = re.findall(r"\[[^\]]*\]\(([^\s)]+)(?:\s[^)]*)?\)", origin["text"])
        if not 0 <= link_index < len(links):
            return None
        link = urlsplit(links[link_index])
        if link.scheme or link.netloc or link.query:
            return None
        current = source.split(":", 2)[2]
        path = (
            posixpath.normpath(posixpath.join(posixpath.dirname(current), unquote(link.path)))
            if link.path
            else current
        )
        if path.startswith(("/", "../")) or path == "..":
            return None
        text = self.source(path)
        if text is None:
            return None
        start = 1
        if link.fragment:
            anchor = unquote(link.fragment).casefold()
            for line, value in enumerate(text.splitlines(), 1):
                if value.startswith("#"):
                    slug = re.sub(r"[^\w\s-]", "", value.lstrip("#").strip().casefold())
                    if re.sub(r"\s+", "-", slug) == anchor:
                        start = line
                        break
            else:
                return None
        return self.read(path, start)
