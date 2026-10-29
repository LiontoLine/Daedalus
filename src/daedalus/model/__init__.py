"""Model plane: untrusted intelligence behind a narrow, auditable contract.

Nothing in this package may mutate authoritative state. A model call returns a
*candidate*, and only the control plane decides what happens to it (Spec §1.2).

The transport is deliberately tiny — one method, `complete` — so that the offline
deterministic stub and the real OpenAI-compatible client are genuinely interchangeable
and every test can run without a network or a credential.
"""

from daedalus.model.base import (
    Completion,
    Message,
    ModelClient,
    ModelError,
    ModelRegistry,
    TokenBudget,
)
from daedalus.model.mock import MockModelClient, ScriptedModelClient
from daedalus.model.openai_compatible import OpenAICompatibleClient

__all__ = [
    "Completion",
    "Message",
    "MockModelClient",
    "ModelClient",
    "ModelError",
    "ModelRegistry",
    "OpenAICompatibleClient",
    "ScriptedModelClient",
    "TokenBudget",
]
