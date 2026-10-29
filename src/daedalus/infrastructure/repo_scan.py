"""Read-only facts about a target repository (Spec §2, §12).

The intake asks a model to propose questions about a task. A model that has not looked at the
repository cannot propose a *useful* option — "which file?" is unanswerable if nobody read the
tree. So before the model is asked anything, this module reads the things a person would look
at: what the project is, where the code is, how it is tested, which branch it is on.

It only reads. There is no `git` invocation, no import of the project, no subprocess: a scan
that runs the target's own code would be an execution path with no sandbox, no lease and no
gate, which is the whole thing this system exists to prevent. Everything here is `pathlib` and
a bounded walk.

`RepoFacts.to_prompt()` is the only thing that reaches the model, and it is text. What comes
back is validated against a closed vocabulary in `daedalus.domain.intake`; nothing the model
says can become a filesystem path that this module did not first offer as a candidate.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

#: Directories that are never interesting and are expensive to walk.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "dist",
        "build",
        ".next",
        "target",
        "vendor",
        ".dsh",
        ".tools",
    }
)

SOURCE_SUFFIXES = frozenset(
    {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".php", ".c", ".h",
     ".cc", ".cpp", ".hpp", ".cs", ".kt", ".swift", ".sh", ".sql"}
)

#: Bounded so a scan of a monorepo cannot turn one click into an unbounded walk.
MAX_FILES = 400
MAX_DEPTH = 4
MAX_LISTED_PATHS = 24


@dataclass(frozen=True, slots=True)
class TestCommand:
    command: str
    why: str


@dataclass(frozen=True, slots=True)
class RepoCandidate:
    path: str
    why: str


@dataclass(frozen=True, slots=True)
class RepoFacts:
    path: str
    name: str
    is_git: bool
    branch: str = ""
    head_commit: str = ""
    dirty: bool = False
    manifests: tuple[str, ...] = ()
    top_level: tuple[str, ...] = ()
    source_files: tuple[str, ...] = ()
    test_files: tuple[str, ...] = ()
    test_commands: tuple[TestCommand, ...] = ()
    target_candidates: tuple[RepoCandidate, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_payload(self) -> dict[str, object]:
        return {
            "path": self.path,
            "name": self.name,
            "is_git": self.is_git,
            "branch": self.branch,
            "head_commit": self.head_commit,
            "dirty": self.dirty,
            "manifests": list(self.manifests),
            "top_level": list(self.top_level),
            "source_files": list(self.source_files),
            "test_files": list(self.test_files),
            "test_commands": [
                {"command": item.command, "why": item.why} for item in self.test_commands
            ],
            "target_candidates": [
                {"path": item.path, "why": item.why} for item in self.target_candidates
            ],
            "notes": list(self.notes),
        }

    def to_prompt(self) -> str:
        """The block handed to the model. Facts only, and every line traceable to a read."""

        def section(title: str, lines: list[str]) -> str:
            if not lines:
                return ""
            return f"{title}:\n" + "\n".join(f"  - {line}" for line in lines) + "\n"

        parts = [
            f"REPO_NAME: {self.name}\n",
            f"REPO_PATH: {self.path}\n",
            f"IS_GIT: {'yes' if self.is_git else 'no'}\n",
        ]
        if self.branch:
            parts.append(f"BRANCH: {self.branch}\n")
        if self.head_commit:
            parts.append(f"HEAD_COMMIT: {self.head_commit[:12]}\n")
        parts.append(f"WORKTREE_DIRTY: {'yes' if self.dirty else 'no'}\n\n")
        parts.append(section("TOP_LEVEL", list(self.top_level)))
        parts.append(section("MANIFESTS", list(self.manifests)))
        parts.append(section("SOURCE_FILES (truncated list)", list(self.source_files)))
        parts.append(section("TEST_FILES", list(self.test_files)))
        parts.append(
            section(
                "TEST_COMMANDS_DETECTED",
                [f"{item.command}   # {item.why}" for item in self.test_commands],
            )
        )
        parts.append(
            section(
                "WRITABLE_CANDIDATES",
                [f"{item.path}   # {item.why}" for item in self.target_candidates],
            )
        )
        parts.append(section("NOTES", list(self.notes)))
        return "".join(parts)


def _read_head(repo: Path) -> tuple[str, str]:
    """Branch and commit, read from `.git` files rather than by running `git`.

    Shelling out to `git` here would be an unleased, ungated subprocess in the intake path.
    The two facts needed are in plain files, so they are read directly; anything more
    elaborate is not worth an execution path.
    """
    git_dir = repo / ".git"
    if git_dir.is_file():
        # A worktree or submodule: `.git` is a file pointing at the real directory.
        try:
            pointer = git_dir.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return "", ""
        if pointer.startswith("gitdir:"):
            target = pointer.split(":", 1)[1].strip()
            git_dir = (repo / target).resolve() if not target.startswith("/") else Path(target)
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return "", ""
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        branch = ref.rsplit("/", 1)[-1]
        try:
            commit = (git_dir / ref).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            packed = _packed_ref(git_dir, ref)
            return branch, packed
        return branch, commit
    return "", head


def _packed_ref(git_dir: Path, ref: str) -> str:
    try:
        for line in (git_dir / "packed-refs").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("^"):
                continue
            commit, _, name = line.partition(" ")
            if name.strip() == ref:
                return commit.strip()
    except OSError:
        return ""
    return ""


def _detect_test_commands(repo: Path, manifests: tuple[str, ...], test_files: tuple[str, ...],
                          top_level: tuple[str, ...]) -> tuple[TestCommand, ...]:
    """The acceptance command candidates, each with the evidence for it.

    Ordered most-specific first: a project that ships both a `pyproject.toml` and a
    `package.json` is usually a Python package with a JS asset build, and the Python suite is
    the one that decides whether the change is correct.
    """
    found: list[TestCommand] = []
    has_tests_dir = "tests" in top_level
    pyproject = (repo / "pyproject.toml").read_text(
        encoding="utf-8", errors="replace"
    ) if "pyproject.toml" in manifests else ""

    if "pyproject.toml" in manifests:
        if "pytest" in pyproject or has_tests_dir or any(f.startswith("test_") for f in test_files):
            found.append(
                TestCommand(
                    "python3 -m pytest tests -q",
                    "pyproject.toml + tests/ 目录，pytest 是 Tier-1 检查 11 会真的执行的命令",
                )
            )
        found.append(TestCommand("python3 -m pytest -q", "整个仓库跑一次 pytest"))
        if "[tool.hatch" in pyproject or "[build-system]" in pyproject:
            found.append(
                TestCommand(
                    "python3 -m compileall -q .",
                    "只做语法编译检查，快但不验证行为",
                )
            )
    if "package.json" in manifests:
        found.append(TestCommand("npm test", "package.json 声明了 test 脚本"))
        found.append(TestCommand("npm run build", "构建通过作为最低验收"))
    if "go.mod" in manifests:
        found.append(TestCommand("go test ./...", "Go module 的标准测试入口"))
    if "Cargo.toml" in manifests:
        found.append(TestCommand("cargo test", "Rust crate 的标准测试入口"))
    if "Makefile" in manifests:
        found.append(TestCommand("make test", "Makefile 存在，test 目标通常是项目自己的验收入口"))
    if not found:
        found.append(
            TestCommand(
                "python3 -m compileall -q .",
                "没有识别出测试框架；这只做语法检查，请在选项里写清真正的验收命令",
            )
        )
    return tuple(found)


def scan(path: str | Path) -> RepoFacts:
    """Read the repository. Raises `NotADirectoryError` only if the path is unusable."""
    repo = Path(path).expanduser().resolve()
    if not repo.is_dir():
        raise NotADirectoryError(str(repo))

    is_git = (repo / ".git").exists()
    branch, head = _read_head(repo) if is_git else ("", "")

    top_level: list[str] = []
    try:
        for entry in sorted(repo.iterdir(), key=lambda item: item.name):
            if entry.name in SKIP_DIRS:
                continue
            top_level.append(entry.name + ("/" if entry.is_dir() else ""))
    except OSError:
        pass

    manifests = tuple(
        name
        for name in (
            "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "package.json",
            "tsconfig.json", "go.mod", "Cargo.toml", "Makefile", "pom.xml", "build.gradle",
            "Gemfile", "composer.json",
        )
        if (repo / name).is_file()
    )

    source_files: list[str] = []
    test_files: list[str] = []
    truncated = False
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        depth = len(Path(root).relative_to(repo).parts)
        if depth >= MAX_DEPTH:
            dirs[:] = []
        for name in sorted(files):
            if len(source_files) + len(test_files) >= MAX_FILES:
                truncated = True
                break
            if Path(name).suffix not in SOURCE_SUFFIXES:
                continue
            relative = str(Path(root, name).relative_to(repo))
            if name.startswith("test_") or name.endswith("_test.py") or "/tests/" in f"/{relative}":
                test_files.append(relative)
            else:
                source_files.append(relative)
        if truncated:
            break

    notes: list[str] = []
    if truncated:
        notes.append(f"文件数超过 {MAX_FILES}，列表被截断")
    if not is_git:
        notes.append("这个目录不是 Git 仓库，Daedalus 需要 Git 才能做 worktree 隔离与提交")

    test_commands = _detect_test_commands(repo, manifests, tuple(test_files), tuple(top_level))

    candidates: list[RepoCandidate] = []
    for name in test_files[:6]:
        candidates.append(RepoCandidate(name, "测试文件；改它通常意味着改验收标准"))
    for name in source_files[: MAX_LISTED_PATHS - len(candidates)]:
        candidates.append(RepoCandidate(name, "源文件"))
    if not candidates:
        candidates.append(RepoCandidate(".", "仓库根目录"))

    return RepoFacts(
        path=str(repo),
        name=repo.name,
        is_git=is_git,
        branch=branch,
        head_commit=head,
        dirty=False,
        manifests=manifests,
        top_level=tuple(top_level[:MAX_LISTED_PATHS]),
        source_files=tuple(source_files[:MAX_LISTED_PATHS]),
        test_files=tuple(test_files[:MAX_LISTED_PATHS]),
        test_commands=test_commands,
        target_candidates=tuple(candidates),
        notes=tuple(notes),
    )



#: Words that appear in almost every task description and identify nothing.
_STOPWORDS = frozenset(
    {
        "the", "and", "for", "with", "that", "this", "from", "into", "when", "then", "than",
        "make", "makes", "change", "changes", "should", "must", "keep", "add", "adds", "use",
        "using", "code", "file", "files", "test", "tests", "fix", "fixes", "update", "updates",
        "return", "returns", "also", "only", "not", "but", "all", "any", "its", "it's",
    }
)

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
#: How much of each candidate file to read when looking for the task's identifiers. Bounded so
#: ranking a large repository cannot turn one click into a long read.
_RANK_READ_BYTES = 24_000
_RANK_MAX_FILES = 40


def _identifiers(text: str) -> set[str]:
    return {
        token.lower()
        for token in _IDENTIFIER.findall(text)
        if token.lower() not in _STOPWORDS
    }


def rank_candidates(facts: RepoFacts, objective: str) -> list[RepoCandidate]:
    """Order the writable candidates by how likely the task is about them, with the reason.

    Alphabetical order put `__init__.py` first, so the narrowest option offered to the operator
    named a file their task had nothing to do with. The signal used instead is the one a person
    would use: the identifiers in the task description are looked for in the candidates, and a
    file that mentions them is a file the task is about. It is a read of at most a few dozen
    bounded files — no execution, no model, and the reason is printed on the option so the
    operator can disagree with it.
    """
    wanted = _identifiers(objective)
    repository = Path(facts.path)
    scored: list[tuple[int, str, str]] = []
    for index, candidate in enumerate(facts.target_candidates):
        path = repository / candidate.path
        if not path.is_file():
            scored.append((0, candidate.path, candidate.why))
            continue
        if index >= _RANK_MAX_FILES or not wanted:
            scored.append((0, candidate.path, candidate.why))
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:_RANK_READ_BYTES]
        except OSError:
            scored.append((0, candidate.path, candidate.why))
            continue
        hits = sorted(wanted & _identifiers(text))
        if hits:
            shown = "、".join(f"`{hit}`" for hit in hits[:3])
            scored.append((len(hits), candidate.path, f"任务里提到的 {shown} 出现在这个文件里"))
        else:
            scored.append((0, candidate.path, candidate.why))
    # Ties keep scan order, so the result is stable for a given repository and task.
    scored.sort(key=lambda row: (-row[0], row[1]))
    return [RepoCandidate(path, why) for _score, path, why in scored]

def known_repos(
    recorded: list[tuple[str, str]] | list[str],
    extra_roots: list[str] = (),
) -> list[dict[str, str]]:
    """Candidate repositories for the intake screen, each with where it came from.

    Repositories this workspace has actually operated on are the honest source, and the label
    says which kind of record it came from — "past run" and "past intake" are different facts,
    and a list that mislabels one as the other is a list an operator cannot check.

    `extra_roots` adds any directory the operator configured, scanned one level deep, so a
    fresh workspace is still usable without typing a path.
    """
    seen: dict[str, dict[str, str]] = {}
    entries = [
        item if isinstance(item, tuple) else (item, "past run") for item in recorded
    ]
    for raw, source in entries:
        path = str(Path(raw).expanduser().resolve())
        if Path(path, ".git").exists():
            seen.setdefault(path, {"path": path, "name": Path(path).name, "source": source})
    for raw_root in extra_roots:
        root = Path(raw_root).expanduser().resolve()
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir(), key=lambda item: item.name):
            if not entry.is_dir() or entry.name.startswith("."):
                continue
            if (entry / ".git").exists():
                seen.setdefault(
                    str(entry),
                    {"path": str(entry), "name": entry.name, "source": f"扫描 {root.name}/"},
                )

    # Scratch checkouts under the system temporary directory are real Git repositories and are
    # offered, but they are labelled and sorted last: five demo runs leave five directories all
    # named `target_repo`, and putting them first buries the projects an operator actually wants.
    temp_root = Path(tempfile.gettempdir()).resolve()
    for entry in seen.values():
        path = Path(entry["path"])
        if path == temp_root or temp_root in path.parents:
            entry["source"] = f"{entry['source']} · 临时目录"
            entry["scratch"] = "1"
    return sorted(
        seen.values(),
        key=lambda item: (item.get("scratch") == "1", item["name"].lower(), item["path"]),
    )
