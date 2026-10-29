"""Offline Python dependency validation; no downloads, installation or code execution.

The controller's cache lives beside its database, outside candidate worktrees.
Hashes establish correspondence to operator-provisioned bytes, not publisher
identity or absence of vulnerabilities. The actual installed environment is a
separate acceptance requirement.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import re
import stat
import sys
import tomllib
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.tags import parse_tag, sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

from daedalus.domain.canonical import digest_of
from daedalus.domain.spec import BoundarySpec
from daedalus.errors import DaedalusError

MAX_WHEEL_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024
HASH = re.compile(r"--hash(?:=|\s+)sha256:([a-fA-F0-9]{64})(?=\s|$)")
MANIFEST_NAMES = {
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}


class DependencyError(DaedalusError):
    code = "dependency_validation_error"


def require(condition, message):
    if not condition:
        raise DependencyError(message)


def dependency_path(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in MANIFEST_NAMES or (
        name.startswith("requirements") and name.endswith((".txt", ".in", ".lock"))
    )


def _requirement(text: str) -> Requirement:
    try:
        item = Requirement(text)
    except InvalidRequirement as error:
        raise DependencyError("dependency requirement is malformed or unsupported") from error
    require(item.url is None, "direct URL, local and VCS dependencies are refused")
    return item


def _lines(text: str) -> list[str]:
    require(len(text.encode()) <= MAX_INPUT_BYTES, "dependency input exceeds size limit")
    joined = text.replace("\\\r\n", " ").replace("\\\n", " ")
    return [
        line.split(" #", 1)[0].strip()
        for line in joined.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


@dataclass(frozen=True)
class Locked:
    requirement: Requirement
    version: Version
    hashes: tuple[str, ...]


def parse_lock(text: str) -> dict[str, Locked]:
    locked = {}
    for line in _lines(text):
        hashes = tuple(sorted(set(match.lower() for match in HASH.findall(line))))
        require(hashes, "every locked dependency requires a SHA-256 hash")
        remaining = HASH.sub("", line).strip()
        require(
            "--" not in remaining,
            "unsupported lock option; indexes, includes and install directives are refused",
        )
        item = _requirement(remaining)
        pins = list(item.specifier)
        require(
            len(pins) == 1 and pins[0].operator == "==" and "*" not in pins[0].version,
            "every locked dependency requires one exact version",
        )
        require(
            item.marker is None,
            "lock must be resolved for one environment; conditional lock entries are refused",
        )
        name = str(canonicalize_name(item.name))
        require(name not in locked, "duplicate normalized dependency name in lock")
        locked[name] = Locked(item, Version(pins[0].version), hashes)
    return locked


def manifest_requirements(path: str, text: str) -> list[Requirement]:
    if PurePosixPath(path).name == "pyproject.toml":
        require(len(text.encode()) <= MAX_INPUT_BYTES, "manifest exceeds size limit")
        raw = tomllib.loads(text)
        project = raw.get("project", {})
        require(
            not ({"dependencies", "optional-dependencies"} & set(project.get("dynamic", []))),
            "dynamic project dependencies cannot be verified offline",
        )
        require(
            "tool" not in raw or "poetry" not in raw["tool"],
            "Poetry manifests require a supported lock validator",
        )
        values = list(project.get("dependencies", [])) + list(
            raw.get("build-system", {}).get("requires", [])
        )
        for group in project.get("optional-dependencies", {}).values():
            values.extend(group)
        for group in raw.get("dependency-groups", {}).values():
            require(
                isinstance(group, list) and all(isinstance(item, str) for item in group),
                "dependency group includes are not supported",
            )
            values.extend(group)
        require(
            all(isinstance(item, str) for item in values), "manifest dependencies must be strings"
        )
        return [_requirement(item) for item in values]
    name = PurePosixPath(path).name
    require(
        name.startswith("requirements") and name.endswith((".txt", ".in")),
        "this validator supports Python requirements and PEP 621 pyproject manifests only",
    )
    result = []
    for line in _lines(text):
        require(not line.startswith("-"), "manifest directives and recursive includes are refused")
        result.append(_requirement(line))
    return result


def _read_regular(path: Path, limit=MAX_WHEEL_BYTES) -> bytes:
    require(not path.is_symlink(), "dependency cache symlinks are refused")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_size <= limit,
            "cache entry must be a bounded regular file",
        )
        data = stream.read(limit + 1)
    require(len(data) <= limit, "cache entry exceeds size limit")
    return data


def inspect_wheel(data: bytes, filename: str) -> dict:
    require(len(data) <= MAX_WHEEL_BYTES, "wheel exceeds size limit")
    name, version, _build, tags = parse_wheel_filename(filename)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        require(
            len(entries) <= 10000 and sum(e.file_size for e in entries) <= MAX_EXPANDED_BYTES,
            "wheel expansion exceeds limits",
        )
        names = [e.filename for e in entries]
        require(len(names) == len(set(names)), "wheel contains duplicate paths")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            require(
                not path.is_absolute()
                and ".." not in path.parts
                and "\\" not in entry.filename
                and not stat.S_ISLNK(entry.external_attr >> 16),
                "wheel contains unsafe paths or symlinks",
            )
        metadata = [n for n in names if n.endswith(".dist-info/METADATA") and n.count("/") == 1]
        require(len(metadata) == 1, "wheel must have one top-level METADATA")
        meta_path = metadata[0]
        prefix = meta_path.rsplit("/", 1)[0]
        distribution, separator, dist_version = prefix.removesuffix(".dist-info").rpartition("-")
        require(
            separator
            and canonicalize_name(distribution) == name
            and Version(dist_version) == version,
            "wheel dist-info directory and filename identity disagree",
        )
        require(
            len({n.split("/", 1)[0] for n in names if ".dist-info/" in n}) == 1,
            "wheel contains multiple dist-info directories",
        )
        require(
            prefix.endswith(".dist-info")
            and archive.getinfo(meta_path).file_size <= MAX_INPUT_BYTES,
            "wheel metadata exceeds limits",
        )
        meta = BytesParser(policy=policy.default).parsebytes(archive.read(meta_path))
        require(
            len(meta.get_all("Name", [])) == 1 and len(meta.get_all("Version", [])) == 1,
            "wheel metadata identity is missing or ambiguous",
        )
        require(
            canonicalize_name(meta["Name"]) == name and Version(meta["Version"]) == version,
            "wheel filename and metadata identity disagree",
        )
        require(
            archive.getinfo(prefix + "/WHEEL").file_size <= MAX_INPUT_BYTES,
            "wheel WHEEL metadata exceeds limits",
        )
        wheel_text = archive.read(prefix + "/WHEEL").decode()
        wheel_meta = BytesParser(policy=policy.default).parsebytes(wheel_text.encode())
        require(
            wheel_meta.get_all("Wheel-Version", []) == ["1.0"]
            and len(wheel_meta.get_all("Root-Is-Purelib", [])) == 1,
            "unsupported or ambiguous wheel format metadata",
        )
        wheel_tags = set().union(*(parse_tag(value) for value in wheel_meta.get_all("Tag", [])))
        require(wheel_tags == set(tags), "wheel filename and declared tags disagree")
        require(
            wheel_meta.get("Root-Is-Purelib", "").lower() == "true"
            and all(t.abi == "none" and t.platform == "any" for t in tags),
            "initial offline validator supports pure Python universal wheels only",
        )
        require(
            bool(set(tags) & set(sys_tags())),
            "wheel is incompatible with the validation interpreter",
        )
        python = meta.get("Requires-Python", "")
        require(
            not python or Version(".".join(map(str, sys.version_info[:3]))) in SpecifierSet(python),
            "wheel Requires-Python does not match the validation interpreter",
        )
        record_path = prefix + "/RECORD"
        require(
            archive.getinfo(record_path).file_size <= MAX_INPUT_BYTES, "wheel RECORD exceeds limits"
        )
        rows = list(csv.reader(io.StringIO(archive.read(record_path).decode())))
        require(
            all(len(row) == 3 for row in rows) and len({row[0] for row in rows}) == len(rows),
            "wheel RECORD is malformed or duplicated",
        )
        files = {e.filename for e in entries if not e.is_dir()}
        require({row[0] for row in rows} == files, "wheel RECORD does not cover exactly all files")
        for file, checksum, length in rows:
            if file == record_path:
                require(not checksum and not length, "RECORD must not hash itself")
                continue
            require(checksum.startswith("sha256="), "wheel RECORD requires SHA-256 for every file")
            contents = archive.read(file)
            expected = (
                base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).rstrip(b"=").decode()
            )
            require(
                checksum == "sha256=" + expected and length == str(len(contents)),
                "wheel RECORD checksum or size mismatch",
            )
        requirements = [str(_requirement(value)) for value in meta.get_all("Requires-Dist", [])]
        return {
            "name": str(name),
            "version": str(version),
            "filename": filename,
            "sha256": hashlib.sha256(data).hexdigest(),
            "requires": requirements,
            "validation_environment": default_environment(),
        }


def cache_wheel(cache: Path, wheel: Path) -> dict:
    """Explicit operator import; never called by worker or HTTP endpoints."""
    info = inspect_wheel(_read_regular(wheel), wheel.name)
    require(not cache.is_symlink(), "cache root must not be a symlink")
    target = cache / info["sha256"]
    target.mkdir(parents=True, exist_ok=True)
    require(not target.is_symlink(), "cache content directory must not be a symlink")
    output = target / wheel.name
    data = _read_regular(wheel)
    require(hashlib.sha256(data).hexdigest() == info["sha256"], "wheel changed during cache import")
    if output.exists() or output.is_symlink():
        require(
            hashlib.sha256(_read_regular(output)).hexdigest() == info["sha256"],
            "existing cache entry is corrupt; operator repair required",
        )
    else:
        descriptor = os.open(
            output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o444
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
    return info


def verify_python(manifest_path: str, manifest: str, lock: str, cache: Path) -> dict:
    locked = parse_lock(lock)
    roots = manifest_requirements(manifest_path, manifest)
    environment = default_environment()
    require(not cache.is_symlink(), "cache root must not be a symlink")
    wheels = {}
    for name, pin in locked.items():
        chosen = None
        for sha in pin.hashes:
            directory = cache / sha
            require(not directory.is_symlink(), "cache content directory must not be a symlink")
            for file in sorted(directory.glob("*.whl")):
                data = _read_regular(file)
                require(hashlib.sha256(data).hexdigest() == sha, "cached wheel SHA-256 mismatch")
                info = inspect_wheel(data, file.name)
                require(
                    info["name"] == name and Version(info["version"]) == pin.version,
                    "locked package and cached wheel identity disagree",
                )
                chosen = info
                break
            if chosen:
                break
        require(chosen is not None, "a locked wheel is absent from the operator-provisioned cache")
        wheels[name] = chosen
    extras = {name: set(pin.requirement.extras) for name, pin in locked.items()}
    pending = [(requirement, {""}) for requirement in roots]
    pending.extend((pin.requirement, {""}) for pin in locked.values())
    expanded = set()
    while pending:
        requirement, parent_extras = pending.pop()
        if requirement.marker and not any(
            requirement.marker.evaluate({**environment, "extra": extra})
            for extra in parent_extras | {""}
        ):
            continue
        name = str(canonicalize_name(requirement.name))
        require(name in locked, "manifest or transitive dependency is missing from lock")
        require(
            locked[name].version in requirement.specifier,
            "locked version violates a manifest or transitive constraint",
        )
        extras[name].update(requirement.extras)
        identity = (name, tuple(sorted(extras[name])))
        if identity not in expanded:
            expanded.add(identity)
            pending.extend(
                (_requirement(value), extras[name].copy()) for value in wheels[name]["requires"]
            )
    result = {
        "format": "python-hash-lock-v1",
        "packages": [wheels[name] for name in sorted(wheels)],
        "environment": environment,
        "scope": "static_metadata_and_operator_cache; installed_environment_not_attested",
        "downloads": 0,
        "installed": False,
        "vulnerability_scan": "not_performed",
        "publisher_signature": "not_verified",
    }
    return {**result, "validation_digest": digest_of(result)}


def validate_dependencies(
    *,
    boundary: BoundarySpec,
    changed_files,
    read: Callable[[str], str],
    cache: Path | None,
    worktree: Path | None = None,
) -> dict:
    touched = [path for path in changed_files if dependency_path(path)]
    manifest, lock = boundary.dependency_manifest, boundary.lock_file
    require(
        not touched or (manifest and lock),
        "dependency file changes require an explicit manifest and lock in frozen SPEC-03",
    )
    require(not touched or set(touched) <= {manifest, lock}, "undeclared dependency files changed")
    if not manifest and not lock:
        return {
            "scope": "not_applicable_no_declared_dependency_change",
            "packages": [],
            "installed": False,
        }
    require(
        manifest and lock and manifest != lock,
        "dependency declaration requires distinct manifest and lock paths",
    )
    require(cache is not None, "operator-provisioned dependency cache is not configured")
    if worktree:
        require(
            not cache.resolve().is_relative_to(worktree.resolve()),
            "trusted dependency cache must be outside the candidate worktree",
        )
    return verify_python(manifest, read(manifest), read(lock), cache)
