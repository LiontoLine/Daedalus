"""One writer per Git repository across threads and service/CLI processes."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import threading

from daedalus.errors import DaedalusError
from daedalus.infrastructure.git_sandbox import _git


class RepositoryBusy(DaedalusError):
    code = "repository_busy"


_GUARD = threading.Lock()
_LOCKS: dict[str, threading.RLock] = {}
_LOCAL = threading.local()


@contextmanager
def repository_lock(repo: Path):
    if os.name != "posix":
        raise DaedalusError("repository writer locking requires POSIX flock")
    import fcntl

    common = Path(
        _git(
            Path(repo), ["rev-parse", "--path-format=absolute", "--git-common-dir"], check=True
        ).stdout.strip()
    ).resolve()
    key = str(common)
    with _GUARD:
        mutex = _LOCKS.setdefault(key, threading.RLock())
    if not mutex.acquire(blocking=False):
        raise RepositoryBusy("another thread owns this repository", repository=str(repo))
    try:
        held = getattr(_LOCAL, "held", None)
        if held is None:
            held = _LOCAL.held = {}
        if key in held:
            yield
            return
        descriptor = os.open(
            common / "daedalus-operation.lock",
            os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RepositoryBusy(
                    "another process owns this repository", repository=str(repo)
                ) from error
            held[key] = descriptor
            try:
                yield
            finally:
                del held[key]
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
    finally:
        mutex.release()
