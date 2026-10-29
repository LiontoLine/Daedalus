"""Worker lease contract (Spec §6.3).

A lease is the only thing that makes a step safe to run concurrently: a worker that
cannot renew a lease must stop, because another worker may already own the step.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from daedalus.domain.ids import new_id


@dataclass(frozen=True, slots=True)
class Lease:
    lease_id: str
    step_id: str
    execution_id: str
    worker_id: str
    acquired_at: str
    expire_at: str
    attempt: int = 1

    @staticmethod
    def issue(
        *,
        step_id: str,
        execution_id: str,
        worker_id: str,
        ttl_sec: int,
        attempt: int = 1,
        now: datetime | None = None,
    ) -> "Lease":
        current = now or datetime.now(UTC)
        return Lease(
            lease_id=new_id("lease"),
            step_id=step_id,
            execution_id=execution_id,
            worker_id=worker_id,
            acquired_at=current.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            expire_at=(current + timedelta(seconds=ttl_sec))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            attempt=attempt,
        )

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return datetime.fromisoformat(self.expire_at.replace("Z", "+00:00")) <= current

    def to_payload(self) -> dict[str, object]:
        return {
            "lease_id": self.lease_id,
            "step_id": self.step_id,
            "execution_id": self.execution_id,
            "worker_id": self.worker_id,
            "acquired_at": self.acquired_at,
            "expire_at": self.expire_at,
            "attempt": self.attempt,
        }
