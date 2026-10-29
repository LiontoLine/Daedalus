"""Step artifact record (Spec §14).

Every step that reaches the gate must produce one of these, and it must be
traceable back through execution -> worker -> sandbox -> diff -> gate -> commit.
`*_digest` fields are the reuse key: an artifact is only cacheable when every one
of them matches (Spec §13.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from daedalus.domain.canonical import digest_of


@dataclass(frozen=True, slots=True)
class Artifact:
    step_id: str
    execution_id: str
    parent_commit: str
    changed_files: tuple[str, ...] = ()
    patch_digest: str = ""
    artifact_digest: str = ""
    spec_digest: str = ""
    #: Digest of what THIS node's work depends on. The reuse key uses this rather than the
    #: bundle digest, so a change elsewhere in the plan does not invalidate unrelated work.
    node_spec_digest: str = ""
    dependency_digest: str = ""
    toolchain_digest: str = ""
    code_base_digest: str = ""
    input_artifact_digest: str = ""
    execution_log_ref: str = ""
    gate_result_ref: str = ""
    status: str = "AWAITING_GATEKEEPER"
    worker_id: str = ""
    sandbox_image: str = "host-process"
    model: str = ""
    created_at: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def reuse_key(self) -> dict[str, str]:
        """The five-way match required before any cached result may be reused."""
        return {
            "spec_digest": self.node_spec_digest or self.spec_digest,
            "code_base_digest": self.code_base_digest,
            "dependency_digest": self.dependency_digest,
            "toolchain_digest": self.toolchain_digest,
            "input_artifact_digest": self.input_artifact_digest,
        }

    def is_reusable_for(self, other: "Artifact") -> bool:
        """Spec §13.2: ALL digests must match, otherwise INVALIDATE."""
        return self.reuse_key() == other.reuse_key()

    def digest(self) -> str:
        return digest_of(
            {
                "step_id": self.step_id,
                "execution_id": self.execution_id,
                "parent_commit": self.parent_commit,
                "changed_files": list(self.changed_files),
                "patch_digest": self.patch_digest,
                "artifact_digest": self.artifact_digest,
                "spec_digest": self.spec_digest,
                "gate_result_ref": self.gate_result_ref,
                "status": self.status,
            }
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "execution_id": self.execution_id,
            "parent_commit": self.parent_commit,
            "changed_files": list(self.changed_files),
            "patch_digest": self.patch_digest,
            "artifact_digest": self.artifact_digest,
            "spec_digest": self.spec_digest,
            "node_spec_digest": self.node_spec_digest,
            "dependency_digest": self.dependency_digest,
            "toolchain_digest": self.toolchain_digest,
            "code_base_digest": self.code_base_digest,
            "input_artifact_digest": self.input_artifact_digest,
            "execution_log_ref": self.execution_log_ref,
            "gate_result_ref": self.gate_result_ref,
            "status": self.status,
            "worker_id": self.worker_id,
            "sandbox_image": self.sandbox_image,
            "model": self.model,
        }
