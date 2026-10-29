"""Service state and the bounded run dispatcher.

Two design commitments, both inherited from the control plane's own philosophy:

**Creation is durable; execution is not implicit.** `POST /api/runs` writes the spec and the
run, then returns a receipt. Execution happens on a bounded worker pool. If the process dies
mid-run, the next startup *reports* the interrupted run and does not silently continue it —
implicit resumption would carry on from a context nobody reviewed (Spec §1.4).

**One run per repository at a time.** A repository is a shared resource: two runs writing
worktrees and refs into it would be a race the event log cannot describe. A per-repository
lock is the honest constraint, and it is enforced here rather than hoped for.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from daedalus.application.observability import get_logger, log_context
from daedalus.application.orchestrator import RunOrchestrator, RunResult
from daedalus.application.scheduler import Quota
from daedalus.config import Settings
from daedalus.errors import DaedalusError
from daedalus.infrastructure.store.event_store import EventStore

logger = get_logger("service")


class ServiceError(DaedalusError):
    code = "service_error"


class ServiceBusy(ServiceError):
    code = "service_busy"


@dataclass
class DispatchReceipt:
    """What the caller gets back immediately, before any work has happened."""

    run_id: str
    execution_id: str
    accepted: bool
    message: str = ""
    queue_position: int = 0

    def describe(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "execution_id": self.execution_id,
            "accepted": self.accepted,
            "message": self.message,
            "queue_position": self.queue_position,
        }


@dataclass
class _Job:
    run_id: str
    repo_path: str
    invoke: Callable[[], RunResult]
    #: Bound into the log context so every line a run emits can be tied to its execution
    #: (Spec §27 requires execution_id in the logs). Last, because a dataclass cannot put a
    #: defaulted field before a required one.
    execution_id: str = ""
    future: Future[Any] | None = None
    error: str = ""


@dataclass
class RunDispatcher:
    """A bounded pool that executes runs, one at a time per repository."""

    settings: Settings
    store: EventStore
    max_concurrent_runs: int = 2
    _pool: ThreadPoolExecutor | None = field(default=None, init=False, repr=False)
    _repo_locks: dict[str, threading.Lock] = field(default_factory=dict, init=False, repr=False)
    _active: dict[str, _Job] = field(default_factory=dict, init=False, repr=False)
    _jobs: dict[str, _Job] = field(default_factory=dict, init=False, repr=False)
    _guard: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _accepting: bool = field(default=True, init=False)
    #: Set by `shutdown`. A closed dispatcher must stay closed: `submit` used to call
    #: `start()` when the pool was gone, which silently resurrected it and defeated the
    #: shutdown that had just been requested.
    _closed: bool = field(default=False, init=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        with self._guard:
            if self._closed:
                raise ServiceBusy("the dispatcher has been shut down and cannot be restarted")
            if self._pool is None:
                self._pool = ThreadPoolExecutor(
                    max_workers=max(1, self.max_concurrent_runs),
                    thread_name_prefix="daedalus-run",
                )
                self._accepting = True
                logger.info(
                    "dispatcher started with %d worker(s)", max(1, self.max_concurrent_runs)
                )

    def shutdown(self, wait: bool = False) -> None:
        """Stop accepting work and let queued work be cancelled.

        A *running* job is not aborted mid-step: interrupting a step would leave a lease and
        a worktree in a state only `daedalus recover` could explain. `wait=True` is what the
        service uses at shutdown so a run finishes its current step before the store closes.
        """
        self.request_stop()
        with self._guard:
            self._accepting = False
            self._closed = True
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=wait, cancel_futures=True)
            logger.info("dispatcher stopped")

    def request_stop(self) -> None:
        """Stop admissions now; active controllers park at their next atomic boundary."""
        self._stop.set()
        with self._guard:
            self._accepting = False
            self._closed = True

    def __enter__(self) -> "RunDispatcher":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.shutdown(wait=True)

    # ------------------------------------------------------------------- dispatch
    def _execution_id_for(self, run_id: str) -> str:
        """The execution a run is currently on, for log correlation only.

        Best-effort: a missing row means an empty field in the logs, never a refused run.
        Log correlation must not become a precondition for doing work.
        """
        try:
            row = self.store.get_run(run_id)
        except Exception:  # noqa: BLE001 - correlation must not break dispatch
            return ""
        return str(row["execution_id"]) if row else ""

    def submit(self, job_run_id: str, repo_path: str, invoke: Callable[[], RunResult]) -> DispatchReceipt:
        with self._guard:
            if self._closed:
                raise ServiceBusy("the dispatcher is shutting down and is not accepting runs")
            if self._pool is None:
                self.start()
            if not self._accepting:
                raise ServiceBusy("the dispatcher is shutting down and is not accepting runs")
            previous = self._jobs.get(job_run_id)
            if previous is not None and (previous.future is None or not previous.future.done() or job_run_id in self._active):
                raise ServiceBusy(f"run {job_run_id} is already dispatched")

            job = _Job(
                run_id=job_run_id,
                execution_id=self._execution_id_for(job_run_id),
                repo_path=repo_path,
                invoke=invoke,
            )
            self._jobs[job_run_id] = job
            queue_position = self._queue_position(repo_path)
            job.future = self._pool.submit(self._execute, job)  # type: ignore[union-attr]

        return DispatchReceipt(
            run_id=job_run_id,
            execution_id="",
            accepted=True,
            message="accepted; execution is bounded and runs in the background",
            queue_position=queue_position,
        )

    def _execute(self, job: _Job) -> RunResult | None:
        lock = self._lock_for(job.repo_path)
        # Blocking behind the repository lock is intentional: a repository is a shared
        # resource and serialising per repository is a real constraint, not a bug.
        with lock:
            with self._guard:
                if self._stop.is_set():
                    return None
                self._active[job.run_id] = job
            try:
                with log_context(
                        run_id=job.run_id,
                        # §27 requires the logs to carry execution_id. It was bound only on
                        # the resume path, so an ordinary run's logs could not be tied to the
                        # execution they belonged to.
                        execution_id=job.execution_id,
                        component="dispatcher",
                    ):
                    logger.info("run started")
                    from daedalus.application.service_lifecycle import cooperative_stop
                    with cooperative_stop(self._stop):
                        result = job.invoke()
                    logger.info("run finished with status %s", result.status)
                return result
            except DaedalusError as error:
                job.error = error.message
                logger.error("run failed: %s", error.message)
                return None
            except Exception as error:  # noqa: BLE001 - a crashed run must not kill the pool
                job.error = f"{type(error).__name__}: {error}"
                logger.exception("run crashed")
                return None
            finally:
                with self._guard:
                    self._active.pop(job.run_id, None)

    def _lock_for(self, repo_path: str) -> threading.Lock:
        key = str(Path(repo_path).resolve())
        with self._guard:
            lock = self._repo_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._repo_locks[key] = lock
            return lock

    def _queue_position(self, repo_path: str) -> int:
        key = str(Path(repo_path).resolve())
        return sum(1 for job in self._active.values() if job.repo_path == key)

    # -------------------------------------------------------------------- status
    def is_active(self, run_id: str) -> bool:
        with self._guard:
            return run_id in self._active

    def busy_runs(self) -> list[str]:
        with self._guard:
            return sorted(run_id for run_id, job in self._jobs.items()
                          if job.future is None or not job.future.done())

    def active_runs(self) -> list[str]:
        with self._guard:
            return sorted(self._active)

    def describe(self) -> dict[str, Any]:
        with self._guard:
            return {
                "max_concurrent_runs": self.max_concurrent_runs,
                "active": sorted(self._active),
                "dispatched": sorted(self._jobs),
                "accepting": self._accepting,
            }


def build_orchestrator(
    *,
    settings: Settings,
    store: EventStore,
    bundle,
    repo_path: str,
    worker,
    tier2=None,
    run_root: Path | None = None,
    identity=None,
) -> RunOrchestrator:
    """Construct an orchestrator with every limit taken from configuration."""
    quota_settings = settings.quota
    if (bundle.boundary.memory_mb > quota_settings.max_memory_mb
            or bundle.boundary.cpu_limit > quota_settings.max_cpu):
        raise ServiceError("规划资源超过当前服务配额，请按当前配额重新规划后再执行")
    return RunOrchestrator(
        store=store,
        repo_path=Path(repo_path),
        run_root=run_root or settings.workspace.worktrees_path,
        bundle=bundle,
        worker=worker,
        tier2=tier2,
        goal_audit_enabled=True,
        independent_validation_levels=tuple(settings.policy.independent_validation_levels),
        quota=Quota(
            max_parallel_steps=quota_settings.max_parallel_steps,
            max_cpu=quota_settings.max_cpu,
            max_memory_mb=quota_settings.max_memory_mb,
            max_llm_requests=quota_settings.max_llm_requests,
            max_tokens_per_run=quota_settings.max_tokens_per_run,
        ),
        target_branch=settings.workspace.target_branch,
        park_on_escalation=settings.execution.park_on_escalation,
        manual_review_levels=tuple(settings.policy.manual_review_levels),
        execution_ttl_sec=settings.execution.execution_ttl_sec,
        retry_backoff_sec=settings.execution.retry_backoff_sec,
        retry_backoff_factor=settings.execution.retry_backoff_factor,
        retry_backoff_cap_sec=settings.execution.retry_backoff_cap_sec,
        identity=identity,
    )
