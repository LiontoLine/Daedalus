"""Operator-frozen worker control for a fresh paired development experiment."""

import hashlib
import sys
import types
from pathlib import Path


def baseline_path(data: Path, revision: str = "poststudy") -> Path:
    if revision == "efficiency-v1":
        return data / (
            "diagnostics/worker-efficiency-20261028/source/"
            "src/daedalus/application/coding_worker.py"
        )
    if revision != "poststudy":
        raise ValueError("unknown worker control revision")
    return data / (
        "diagnostics/capability-cycle-20261027/poststudy-source/"
        "src/daedalus/application/coding_worker.py"
    )


def baseline_worker(data: Path, expected_digest: str, *, evidence_path: Path | None = None,
                    revision: str = "poststudy"):
    path = baseline_path(data,revision)
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != expected_digest:
        raise ValueError("frozen worker baseline digest does not match")
    if evidence_path is not None:
        evidence_path.write_bytes(source)
    name = "_daedalus_worker_control_" + expected_digest
    if name not in sys.modules:
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        try:
            # Compile the verified bytes: do not reopen the path after checking it.
            exec(compile(source,str(path),"exec"),module.__dict__)
        except BaseException:
            sys.modules.pop(name,None)
            raise
    return sys.modules[name].ModelWorker
