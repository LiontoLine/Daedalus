"""Secret broker (Spec §8).

Principle: least privilege, shortest lifetime, no credentials by default.

The agent never receives a long-lived credential. It receives a *capability grant*
with an explicit scope and an expiry, and the grant is resolved by the control plane
at the moment of use. Everything the broker returns is registered so the redactor can
scrub it out of logs, events and artifacts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from daedalus.domain.ids import new_id
from daedalus.errors import DaedalusError
from daedalus.infrastructure.redact import REDACTED, is_secret_key


class CapabilityDenied(DaedalusError):
    code = "capability_denied"


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    grant_id: str
    capability: str
    scope: str
    issued_at: str
    expires_at: str
    redeemed: bool = False

    @property
    def expired(self) -> bool:
        return datetime.fromisoformat(self.expires_at.replace("Z", "+00:00")) <= datetime.now(UTC)

    def to_payload(self) -> dict[str, object]:
        return {
            "grant_id": self.grant_id,
            "capability": self.capability,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


#: Environment variables consulted when a grant's scope does not name one.
DEFAULT_CREDENTIAL_ENV_NAMES = ("DAEDALUS_MODEL_API_KEY", "OPENAI_API_KEY")


@dataclass
class SecretBroker:
    """Issues short-lived grants over named capabilities held by the host.

    A grant's `scope` names the environment variable to read. The configuration declares
    `model.<role>.api_key_env`, so the scope is where that declaration is honoured — reading a
    hard-coded list instead would make the configured variable silently ineffective, which is
    exactly the kind of "the setting exists but does nothing" failure that is worst in a
    credential path.
    """

    ttl_sec: int = 300
    allowed_capabilities: frozenset[str] = frozenset({"model.api_key"})
    fallback_env_names: tuple[str, ...] = DEFAULT_CREDENTIAL_ENV_NAMES
    environ: dict[str, str] | None = None
    _grants: dict[str, CapabilityGrant] = field(default_factory=dict)
    _known_secret_values: set[str] = field(default_factory=set, repr=False)

    def request(self, capability: str, *, scope: str = "read") -> CapabilityGrant:
        if capability not in self.allowed_capabilities:
            raise CapabilityDenied(
                f"capability {capability!r} is not grantable; the agent must not hold it",
                capability=capability,
            )
        now = datetime.now(UTC)
        grant = CapabilityGrant(
            grant_id=new_id("grant"),
            capability=capability,
            scope=scope,
            issued_at=now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            expires_at=(now + timedelta(seconds=self.ttl_sec))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        )
        self._grants[grant.grant_id] = grant
        return grant

    def redeem(self, grant: CapabilityGrant) -> str:
        """Resolve a grant into the actual secret value, at the point of use only."""
        stored = self._grants.get(grant.grant_id)
        if stored is None:
            raise CapabilityDenied(f"unknown grant {grant.grant_id}")
        if stored.expired:
            raise CapabilityDenied(f"grant {grant.grant_id} expired at {stored.expires_at}")
        if grant.capability != "model.api_key":
            raise CapabilityDenied(f"cannot resolve capability {grant.capability!r}")

        source = dict(os.environ if self.environ is None else self.environ)
        candidates = self._candidate_names(stored)
        for name in candidates:
            value = source.get(name, "")
            if value:
                self._known_secret_values.add(value)
                return value
        raise CapabilityDenied(
            "no model credential is present in the environment. Set "
            + " or ".join(candidates)
            + " before starting the process."
        )

    def available(self, scope: str = "read") -> bool:
        """Whether a credential is present for `scope`, without reading the value out.

        Reporting "the variable is set" is not reporting the key. The console needs the former:
        an operator looking at "which model is answering?" has to be able to see that the
        configured environment variable is missing, because that is the most common reason a
        call fails and the least obvious from the outside.
        """
        grant = CapabilityGrant(
            grant_id="probe",
            capability="model.api_key",
            scope=scope,
            issued_at="",
            expires_at="",
        )
        source = dict(os.environ if self.environ is None else self.environ)
        return any(source.get(name, "") for name in self._candidate_names(grant))

    def _candidate_names(self, grant: CapabilityGrant) -> tuple[str, ...]:
        """The configured variable first, then the conventional fallbacks."""
        configured = grant.scope if grant.scope and grant.scope != "read" else ""
        names = [configured] if configured else []
        names.extend(name for name in self.fallback_env_names if name not in names)
        return tuple(names)

    def known_secret_values(self) -> frozenset[str]:
        """Values the redactor must always mask, even if they look harmless."""
        return frozenset(self._known_secret_values)

    def describe_capabilities(self) -> dict[str, object]:
        return {
            "grantable": sorted(self.allowed_capabilities),
            "ttl_sec": self.ttl_sec,
            "fallback_env_names": list(self.fallback_env_names),
            "active_grants": len([g for g in self._grants.values() if not g.expired]),
        }


def scrub_environment(environ: dict[str, str] | None = None) -> dict[str, str]:
    """A child-process environment with every secret-shaped variable removed.

    Returns the *names* replaced, so the caller can record that redaction happened
    without ever recording the value.
    """
    source = dict(os.environ if environ is None else environ)
    safe: dict[str, str] = {}
    for key, value in source.items():
        if is_secret_key(key):
            safe[key] = REDACTED
        else:
            safe[key] = value
    return safe


def redacted_names(environ: dict[str, str] | None = None) -> tuple[str, ...]:
    source = dict(os.environ if environ is None else environ)
    return tuple(sorted(key for key in source if is_secret_key(key)))
