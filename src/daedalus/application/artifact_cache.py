"""Artifact reuse (Spec §13.2).

An artifact may be reused only when **all five** digests match:

    Spec Digest MATCH
    Code Base Commit MATCH
    Dependency Digest MATCH
    Toolchain Digest MATCH
    Input Artifact Digest MATCH

Otherwise `INVALIDATE`. The point of this module is to make that a single, testable
predicate rather than a set of conditions scattered across the orchestrator, because a
cache that is one condition too permissive silently turns a verified system into an
unverified one.

Two extra requirements are enforced here beyond the digest list, because the spec's list
alone would still admit a bad reuse:

* the candidate must have reached `COMMITTED` — a `REVISE`d or `ESCALATED` artifact is
  evidence of *failure*, never a result to replay;
* the candidate must name the gate result that approved it, so a reuse event can point at
  the original verdict instead of asserting one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from daedalus.domain.canonical import digest_of, sha256_hex
from daedalus.infrastructure.store.event_store import EventStore


@dataclass(frozen=True, slots=True)
class ReuseKey:
    """The five-way identity of a piece of work (Spec §13.2 / §14).

    `spec_digest` here is the **node-level** subject digest, not the whole-bundle digest. The
    bundle digest would make every artifact depend on every other node's definition, which
    contradicts Spec §13.1's selective replay.
    """

    spec_digest: str
    code_base_digest: str
    dependency_digest: str
    toolchain_digest: str
    input_artifact_digest: str

    def digest(self) -> str:
        return digest_of(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return {
            "spec_digest": self.spec_digest,
            "code_base_digest": self.code_base_digest,
            "dependency_digest": self.dependency_digest,
            "toolchain_digest": self.toolchain_digest,
            "input_artifact_digest": self.input_artifact_digest,
        }

    def mismatch(self, other: "ReuseKey") -> tuple[str, ...]:
        """Which of the five did not match. Empty tuple means reusable."""
        mine = self.to_dict()
        theirs = other.to_dict()
        return tuple(sorted(key for key in mine if mine[key] != theirs[key]))

    def is_complete(self) -> bool:
        return all(self.to_dict().values())


@dataclass(frozen=True, slots=True)
class ReuseDecision:
    reusable: bool
    artifact_digest: str = ""
    commit: str = ""
    gate_result_ref: str = ""
    mismatches: tuple[str, ...] = ()
    reason: str = ""

    def describe(self) -> dict[str, object]:
        return {
            "reusable": self.reusable,
            "artifact_digest": self.artifact_digest,
            "commit": self.commit,
            "gate_result_ref": self.gate_result_ref,
            "mismatches": list(self.mismatches),
            "reason": self.reason,
        }


@dataclass
class ArtifactCache:
    """Looks up reusable artifacts. Read-only: it never writes to the store."""

    store: EventStore
    enabled: bool = True
    #: Only consider artifacts produced by these executions (empty means any).
    allowed_executions: frozenset[str] = field(default_factory=frozenset)

    def lookup(self, key: ReuseKey, *, exclude_execution_id: str = "") -> ReuseDecision:
        if not self.enabled:
            return ReuseDecision(reusable=False, reason="artifact reuse is disabled")
        if not key.is_complete():
            # A partially-computed key cannot prove anything, so it must not authorise a
            # reuse. This is the fail-closed default.
            return ReuseDecision(
                reusable=False,
                reason=f"incomplete reuse key: {sorted(k for k, v in key.to_dict().items() if not v)}",
            )

        rows = self.store.connection.execute(
            """
            SELECT * FROM artifacts
            WHERE node_spec_digest = ?
              AND code_base_digest = ?
              AND dependency_digest = ?
              AND toolchain_digest = ?
              AND input_artifact_digest = ?
              AND status = 'COMMITTED'
            ORDER BY created_at DESC
            """,
            (
                key.spec_digest,
                key.code_base_digest,
                key.dependency_digest,
                key.toolchain_digest,
                key.input_artifact_digest,
            ),
        ).fetchall()

        if not rows:
            return ReuseDecision(
                reusable=False,
                reason="no committed artifact matches all five digests (INVALIDATE)",
            )

        for row in rows:
            execution_id = str(row["execution_id"])
            if exclude_execution_id and execution_id == exclude_execution_id:
                # Reusing this execution's own artifact would mean the step never really
                # ran in this execution; that is a cache loop, not a cache hit.
                continue
            if self.allowed_executions and execution_id not in self.allowed_executions:
                continue
            gate_ref = str(row["gate_result_ref"])
            if not gate_ref:
                return ReuseDecision(
                    reusable=False,
                    mismatches=(),
                    reason=(
                        f"artifact {str(row['artifact_digest'])[:12]} is COMMITTED but names "
                        "no gate result; refusing to reuse an unattributable verdict"
                    ),
                )
            document = _loads(str(row["document"]))
            commit = str(document.get("commit", ""))
            return ReuseDecision(
                reusable=True,
                artifact_digest=str(row["artifact_digest"]),
                commit=commit,
                gate_result_ref=gate_ref,
                reason="all five digests match and the artifact names its gate result",
            )

        return ReuseDecision(
            reusable=False,
            reason="every matching artifact belongs to the execution being replayed",
        )

    def record_commit_on_artifact(
        self, artifact_digest: str, *, commit: str, gate_result_ref: str
    ) -> None:
        """Attach the landed commit to an artifact document so a later replay can reuse it.

        Without the commit, a cache hit could not tell the scheduler where the reused work
        sits in history.
        """
        row = self.store.get_artifact(artifact_digest)
        if row is None:
            return
        document = _loads(str(row["document"]))
        document["commit"] = commit
        self.store.record_artifact(
            {
                **dict(row),
                "document": _dumps(document),
                "gate_result_ref": gate_result_ref,
                "status": "COMMITTED",
            }
        )


def reuse_key_for(
    *,
    spec_digest: str,
    base_commit: str,
    dependency_digest: str,
    toolchain_digest: str,
    input_artifacts: tuple[tuple[str, str], ...] = (),
) -> ReuseKey:
    """Build a `ReuseKey` for a step about to run.

    `spec_digest` is the **node-level** subject digest (see `domain.spec.node_subject_digest`),
    so an edit to a different node does not invalidate this one.

    `input_artifacts` is the sorted set of `(upstream step id, artifact digest)` pairs, so a
    change anywhere *upstream* still invalidates this node even though a change elsewhere in the
    plan does not. `code_base_digest` is the digest of the commit the step would start from.
    """
    return ReuseKey(
        spec_digest=spec_digest,
        code_base_digest=sha256_hex(base_commit),
        dependency_digest=dependency_digest,
        toolchain_digest=toolchain_digest,
        input_artifact_digest=digest_of(sorted(input_artifacts)),
    )


def _loads(raw: str) -> dict[str, object]:
    import json

    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _dumps(value: dict[str, object]) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
