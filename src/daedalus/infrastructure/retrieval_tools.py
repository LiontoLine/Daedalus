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


class RepositorySearch:
    """All reads name a Git commit; no shell, network, working-tree or symlink reads."""

    def __init__(self, repo: str):
        self.repo = repo
        self.head = _git(repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
        self.files = {}
        self._texts = {}
        for row in _git(repo, ["ls-tree", "-r", self.head], check=True).stdout.splitlines():
            meta, _, path = row.partition("\t")
            item = PurePosixPath(path)
            if (
                meta.startswith(("100644 blob ", "100755 blob "))
                and item.suffix.lower() in TEXT_SUFFIXES
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
            return None
        text = _git(self.repo, ["show", blob], check=True).stdout
        try:
            assert_outbound_clean(path + "\n" + text, where="repository search source")
        except SecretInPayload:
            self._texts[path] = None
            return None
        self._texts[path] = text
        return text

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
            "source": f"git:{self.head}:{path}",
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
        args.extend([self.head, "--"])
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
        candidates = [p.removeprefix(self.head + ":") for p in matched.stdout.split("\0") if p]
        candidates.sort(key=lambda p: (p not in paths, p))
        result = []
        for path in candidates[:20]:
            text = self.source(path)
            if text is None:
                continue
            # The entire matched file was scanned before returning any snippet.
            line = next(
                (
                    i
                    for i, value in enumerate(text.splitlines(), 1)
                    if any(n.casefold() in value.casefold() for n in needles)
                ),
                1,
            )
            chunk = self.read(path, max(1, line - 3), lines=22)
            if chunk:
                result.append(chunk)
            if len(result) >= limit:
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
                            "source": f"git:{self.head}:{path}",
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

    def symbol(self, name: str, *, limit: int = 8, paths: tuple[str, ...] = ()) -> list[dict]:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
            return []
        # Git narrows candidates by identifier first. The old first-80-files scan could
        # never reach implementations in a large repository's later directories.
        matched = _git(self.repo, ["grep", "-l", "-z", "-I", "-F", "-e", name,
                                   self.head, "--", "*.py"], check=False)
        candidates = [p.removeprefix(self.head + ":") for p in matched.stdout.split("\0") if p]
        candidates = sorted(p for p in candidates if p in self.files and (not paths or p in paths))
        definitions, callers = [], []
        for path in candidates[:80]:
            text = self.source(path)
            if text is None:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                relation = ""
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    and node.name == name
                ):
                    relation = "definition"
                elif isinstance(node, ast.Call) and (
                    (isinstance(node.func, ast.Name) and node.func.id == name)
                    or (isinstance(node.func, ast.Attribute) and node.func.attr == name)
                ):
                    relation = "caller"
                if relation:
                    row = self.read(path, max(1, node.lineno - 2), lines=24)
                    if row:
                        (definitions if relation == "definition" else callers).append(
                            {**row, "relation": relation, "symbol": name})
                    if len(definitions) >= limit:
                        return definitions[:limit]
        return (definitions + callers)[:limit]

    def follow_link(self, origin: dict, link_index: int = 0) -> dict | None:
        source = origin.get("source", "")
        if not source.startswith("git:" + self.head + ":") or not isinstance(link_index, int):
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
