"""A worker that refuses to work, for replays that are expected to hit the cache.

`daedalus replay` without a model must be honest: if every step's five digests match a
verified artifact, nothing needs to execute and the replay is a pure bookkeeping operation.
If a step misses the cache, there is no coder available, and the replay must fail loudly
with that fact rather than producing a half-run that looks successful.
"""

from __future__ import annotations

from daedalus.application.worker import WorkerContext, WorkerResult
from daedalus.infrastructure.git_sandbox import GitSandbox


class CacheMissWorker:
    name = "cache-miss-guard"
    worker_id = "worker-cache-miss-guard"

    def implement(self, sandbox: GitSandbox, context: WorkerContext) -> WorkerResult:
        return WorkerResult(
            ok=False,
            summary=(
                "no artifact could be reused for this step and no coding worker is "
                "configured; pass --model to execute cache misses"
            ),
            execution_log=(
                "the reuse key did not match any committed artifact. This is reported "
                "rather than silently skipped: a replay that cannot reuse work and cannot "
                "perform it has not replayed anything."
            ),
            worker_id=self.worker_id,
            error="no_worker_configured",
        )
