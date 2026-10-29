"""Release gate: the Spec §25 pre-production checklist, executed (Spec §22, §25, §28).

§25 lists the checks that must pass before the system is considered production-ready. A checklist
in a document is a thing people tick without running. This runs them:

* **behavioural** checks execute the existing test suite, because those tests *are* the
  permission, boundary, secret-leak, duplicate-event and git-conflict checks;
* **runtime** checks probe the host's isolation, verify the event log's integrity and confirm a
  verified snapshot exists;
* **configuration** checks refuse a posture that would make the guarantees meaningless — an
  unapproved high-risk policy, an empty protected-path set, a config file with a credential in it.

The output is a go/no-go with per-check evidence, and a non-zero exit when anything fails, so it
can be a CI gate rather than a report someone reads.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from daedalus.application.alerting import evaluate_alerts
from daedalus.application.backup import list_backups
from daedalus.application.preflight import run_preflight
from daedalus.application.identity import OwnerRegistry
from daedalus.config import Settings
from daedalus.domain.spec import MetaSpec
from daedalus.infrastructure.redact import is_secret_key
from daedalus.infrastructure.store.event_store import EventStore


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    #: The check ran and passed, but with a caveat the operator must know about.
    WARN = "warn"


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    category: str
    status: CheckStatus
    detail: str = ""
    evidence: dict[str, object] = field(default_factory=dict)
    remediation: str = ""

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "category": self.category,
            "status": self.status.value,
            "detail": self.detail,
            "evidence": dict(self.evidence),
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class ReleaseGateReport:
    checks: tuple[CheckResult, ...]
    version: str = ""
    mode: str = "production"

    def __post_init__(self) -> None:
        if self.mode not in {"production", "development"}:
            raise ValueError("unknown release gate mode")

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(c for c in self.checks if c.status is CheckStatus.FAIL)

    @property
    def warnings(self) -> tuple[CheckResult, ...]:
        return tuple(c for c in self.checks if c.status is CheckStatus.WARN)

    @property
    def skipped(self) -> tuple[CheckResult, ...]:
        return tuple(c for c in self.checks if c.status is CheckStatus.SKIP)

    @property
    def go(self) -> bool:
        if self.mode == "development":
            return bool(self.checks) and not self.failures
        names = {c.name for c in self.checks}
        return REQUIRED_PRODUCTION_CHECKS <= names and all(
            c.status is CheckStatus.PASS for c in self.checks
        )

    def describe(self) -> dict[str, object]:
        return {
            "go": self.go,
            "mode": self.mode,
            "production_ready": self.mode == "production" and self.go,
            "blocking_checks": [c.name for c in self.checks if c.status is not CheckStatus.PASS]
                if self.mode == "production" else [c.name for c in self.failures],
            "missing_checks": sorted(REQUIRED_PRODUCTION_CHECKS - {c.name for c in self.checks})
                if self.mode == "production" else [],
            "version": self.version,
            "checks": [check.describe() for check in self.checks],
            "failures": len(self.failures),
            "warnings": len(self.warnings),
            "skipped": len(self.skipped),
        }


#: §25's list, mapped to the check that implements it.
CHECKLIST_COVERAGE: dict[str, str] = {
    "权限测试": "test_boundary_and_e2e / test_fsm",
    "越权测试": "test_boundary_and_e2e::test_worker_cannot_write_outside_the_boundary",
    "网络隔离测试": "test_sandbox_drivers / preflight",
    "Secret 泄漏测试": "test_boundary_and_e2e::test_secret_never_lands_in_the_event_log",
    "Container Escape 防护验证": "UNVERIFIED: argv assertions are not runtime containment evidence",
    "状态恢复测试": "test_event_store::test_replay_rebuilds_state_from_the_log_alone",
    "重复事件测试": "test_event_store (idempotency)",
    "数据库恢复测试": "test_operations (backup/restore)",
    "Git 冲突测试": "test_parallel_and_rebase::test_rebase_conflict_returns_revise_then_recovers",
}


REQUIRED_PRODUCTION_CHECKS = frozenset({
    "self_modification_boundary", "no_credential_in_config", "high_risk_requires_approval",
    "approval_signature_verified", "network_default_deny", "process_isolation_available",
    "event_log_integrity", "verified_snapshot_exists", "no_active_alerts",
    "behavioural_test_suite", "runtime_security_evidence", "dependency_runtime_evidence",
    "independent_validation_policy", "independent_validation_principals",
})


def run_release_gate(
    *,
    settings: Settings,
    store: EventStore,
    repo_root: Path | None = None,
    run_tests: bool = True,
    test_timeout_sec: int = 1800,
    mode: str = "production",
) -> ReleaseGateReport:
    """Run every pre-production check and report go/no-go."""
    if mode not in {"production", "development"}:
        raise ValueError("unknown release gate mode")
    checks: list[CheckResult] = []
    root = repo_root or _find_repo_root()

    checks.append(_check_protected_paths())
    checks.append(_check_config_has_no_credential(settings))
    checks.append(_check_high_risk_requires_approval(settings))
    checks.append(_check_identity_enrolled(settings, store))
    checks.extend(_check_independent_validation(settings, store))
    checks.append(_check_network_posture(settings))
    checks.append(_check_isolation(settings))
    checks.append(_check_event_integrity(store))
    checks.append(_check_backup_exists(settings))
    checks.append(_check_alerts(store, settings))
    if run_tests:
        checks.append(_check_test_suite(root, timeout_sec=test_timeout_sec))
    else:
        checks.append(
            CheckResult(
                name="behavioural_test_suite",
                category="behaviour",
                status=CheckStatus.SKIP,
                detail="--no-tests was requested; the behavioural checks did not run",
                remediation=(
                    "run without --no-tests before a release. The permission, boundary, "
                    "secret-leak, duplicate-event and git-conflict checks all live in the suite."
                ),
            )
        )

    # A runtime probe proves availability, not containment, quotas or orphan cleanup.
    # Until those deployment-bound checks exist, production must remain no-go.
    checks.append(CheckResult(
        name="runtime_security_evidence", category="runtime", status=CheckStatus.SKIP,
        detail="deployment-bound containment, resource and crash-cleanup verification is not implemented",
        remediation="implement and execute runtime security acceptance; argv checks cannot substitute",
    ))
    checks.append(CheckResult(
        name="dependency_runtime_evidence", category="runtime", status=CheckStatus.SKIP,
        detail="offline lock/cache integrity is implemented; installed environment, publisher provenance and vulnerability evidence are not attested",
        remediation="bind sandbox-installed dependencies to verified artifacts and supply deployment-bound provenance/vulnerability evidence",
    ))
    from daedalus import __version__

    return ReleaseGateReport(checks=tuple(checks), version=__version__, mode=mode)


def _find_repo_root() -> Path:
    """Locate the repository this package was installed from, if it is still present."""
    here = Path(__file__).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "tests").is_dir():
            return candidate
    return here.parent


# ---------------------------------------------------------------------------
# Configuration checks
# ---------------------------------------------------------------------------


def _check_protected_paths() -> CheckResult:
    meta = MetaSpec.default()
    protected = meta.protected_paths
    required_capabilities = {"gatekeeper", "security_policy", "meta_spec", "event_store"}
    missing = sorted(required_capabilities - set(meta.human_approval_required))
    if not protected or missing:
        return CheckResult(
            name="self_modification_boundary",
            category="configuration",
            status=CheckStatus.FAIL,
            detail=(
                f"the Meta-Spec protects {len(protected)} path(s) and requires approval for "
                f"{sorted(meta.human_approval_required)}; missing {missing}"
            ),
            remediation=(
                "restore the shipped Meta-Spec. An empty protection set means the system could "
                "modify its own regulator (Spec §21)."
            ),
        )
    if meta.allow_gatekeeper_self_modification or meta.allow_control_plane_self_modification:
        return CheckResult(
            name="self_modification_boundary",
            category="configuration",
            status=CheckStatus.FAIL,
            detail="the Meta-Spec permits self-modification of the Gatekeeper or control plane",
            remediation="set both `allow_*_self_modification` flags to false.",
        )
    return CheckResult(
        name="self_modification_boundary",
        category="configuration",
        status=CheckStatus.PASS,
        detail=f"{len(protected)} protected path(s); approval required for {sorted(required_capabilities)}",
        evidence={"protected_paths": list(protected)},
    )


def _check_config_has_no_credential(settings: Settings) -> CheckResult:
    """A credential in the config file is a leak waiting to be committed."""
    path = Path(settings.source_path) if settings.source_path else None
    if path is None or not path.is_file():
        return CheckResult(
            name="no_credential_in_config",
            category="configuration",
            status=CheckStatus.PASS,
            detail="no config file in use; settings came from defaults and the environment",
        )
    text = path.read_text(encoding="utf-8")
    suspects: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip().strip('"').strip("'")
        value = value.strip().strip('"').strip("'")
        if not value:
            continue
        reason = _credential_shape(key, value)
        if reason:
            suspects.append(f"{key} = <{len(value)} chars> ({reason})")
    if suspects:
        return CheckResult(
            name="no_credential_in_config",
            category="configuration",
            status=CheckStatus.FAIL,
            detail=f"{len(suspects)} suspicious value(s) in {path}",
            evidence={"suspects": suspects[:10]},
            remediation=(
                "credentials belong in the environment variable named by "
                "`model.<role>.api_key_env`, never in the config file."
            ),
        )
    return CheckResult(
        name="no_credential_in_config",
        category="configuration",
        status=CheckStatus.PASS,
        detail=f"{path} contains no credential-shaped values",
    )


#: A bare token: long, and with no path or sentence separators. A filesystem path has "/" and
#: "."; a URL has "://"; an ordinary setting has spaces or is short. This catches a credential
#: pasted into the wrong field, which the loader cannot detect because the field is not
#: credential-shaped.
_BARE_TOKEN = __import__("re").compile(r"^[A-Za-z0-9_\-]{32,}$")


def _credential_shape(key: str, value: str) -> str:
    """Why this value looks like a credential, or an empty string."""
    from daedalus.infrastructure.redact import redact_text

    if is_secret_key(key):
        return "the key name is credential-shaped"
    if redact_text(value) != value:
        return "the value matches a known credential format"
    if _BARE_TOKEN.match(value):
        return "a long unbroken token with no separators"
    return ""


def _check_high_risk_requires_approval(settings: Settings) -> CheckResult:
    levels = set(settings.policy.manual_review_levels)
    if "critical" not in levels:
        return CheckResult(
            name="high_risk_requires_approval",
            category="configuration",
            status=CheckStatus.FAIL,
            detail=(
                "critical is not in policy.manual_review_levels, so a critical change could "
                "merge on a semantic review alone"
            ),
            remediation="add \"critical\" to `policy.manual_review_levels` (Spec §10).",
        )
    return CheckResult(
        name="high_risk_requires_approval",
        category="configuration",
        status=CheckStatus.PASS,
        detail=f"manual review required for {sorted(levels)}",
    )


def _check_identity_enrolled(settings: Settings, store: EventStore) -> CheckResult:
    """Spec §3.2 at the release gate.

    FAIL rather than WARN when `[identity] required` is set: a deployment that has declared it
    verifies approvals and has nobody able to give one cannot approve anything, so it must not
    ship. WARN when it is not required, because single-user use is legitimate — but the
    warning names the gap, so a go/no-go decision is never made in ignorance of it.
    """
    registry = OwnerRegistry(store=store, required=settings.identity.required)
    signers = [owner for owner in registry.list() if owner.can_sign]
    detail = (
        f"{registry.enrolled} owner(s) enrolled, {len(signers)} able to sign; "
        f"approval verification {'is' if registry.enforced else 'is NOT'} in force"
    )
    if settings.identity.required and not signers:
        return CheckResult(
            name="approval_signature_verified",
            category="security",
            status=CheckStatus.FAIL,
            detail=(
                f"[identity] required = true but no enrolled owner can sign ({detail}). "
                "High-risk specs cannot be approved, so no high-risk work can run."
            ),
            remediation=(
                "enrol a signer: `daedalus owners add --owner-id <you> --role owner "
                "--secret-env <VAR>` and put the secret in that variable."
            ),
        )
    return CheckResult(
        name="approval_signature_verified",
        category="security",
        status=CheckStatus.PASS if registry.enforced else CheckStatus.WARN,
        detail=detail,
        remediation=(
            ""
            if registry.enforced
            else (
                "an approval is currently a name, not a verified signature (Spec §3.2). "
                "Enrol owners and set `[identity] required = true` for a deployment where "
                "more than one person can reach the API."
            )
        ),
    )


def _check_independent_validation(settings: Settings, store: EventStore) -> list[CheckResult]:
    policy_ok = {"high", "critical"} <= set(settings.policy.independent_validation_levels)
    principals = OwnerRegistry(store).list()
    candidates = [p for p in principals if not p.revoked and p.key_fingerprint and p.secret_env]
    pairs = [
        (a.owner_id, b.owner_id)
        for a in candidates
        for b in candidates
        if a.role.value == "owner"
        and b.role.value in {"reviewer", "owner"}
        and a.owner_id != b.owner_id
        and a.key_fingerprint != b.key_fingerprint
    ]
    return [
        CheckResult(
            name="independent_validation_policy",
            category="configuration",
            status=CheckStatus.PASS if policy_ok else CheckStatus.FAIL,
            detail="high/critical must require fresh acceptance and independent attestation",
            remediation="set policy.independent_validation_levels = ['high', 'critical']"
            if not policy_ok
            else "",
        ),
        CheckResult(
            name="independent_validation_principals",
            category="security",
            status=CheckStatus.PASS if pairs else CheckStatus.FAIL,
            detail="separate approval/validation identities and keys enrolled"
            if pairs
            else "no distinct owner and independent reviewer keys enrolled",
            evidence={
                "eligible_pairs": [list(pair) for pair in pairs],
                "scope": "enrolment readiness; keys verified at attestation",
            },
            remediation="enrol an owner and a separate reviewer using different keys"
            if not pairs
            else "",
        ),
    ]

def _check_network_posture(settings: Settings) -> CheckResult:
    if settings.policy.network_policy != "deny":
        return CheckResult(
            name="network_default_deny",
            category="configuration",
            status=CheckStatus.WARN,
            detail=(
                f"policy.network_policy is {settings.policy.network_policy!r}; the default is "
                "'deny'"
            ),
            remediation=(
                "SPEC-03 can only narrow this, so a permissive default lets any task reach the "
                "network unless it says otherwise."
            ),
        )
    return CheckResult(
        name="network_default_deny",
        category="configuration",
        status=CheckStatus.PASS,
        detail="the configured default network policy is deny",
    )


def _check_isolation(settings: Settings) -> CheckResult:
    report = run_preflight(settings)
    process_gap = next((gap for gap in report.gaps if "no process isolation" in gap), "")
    if process_gap:
        return CheckResult(
            name="process_isolation_available",
            category="runtime",
            status=CheckStatus.WARN,
            detail=f"selected {report.selected}: {process_gap}",
            evidence={"gaps": list(report.gaps), "drivers": [r.driver for r in report.drivers]},
            remediation=(
                "acceptable for trusted tasks, but a production deployment handling untrusted "
                "changes should install a container runtime (`colima start`) and re-run this."
            ),
        )
    return CheckResult(
        name="process_isolation_available",
        category="runtime",
        status=CheckStatus.PASS,
        detail=f"selected {report.selected} with process isolation enforced",
        evidence={"gaps": list(report.gaps)},
    )


# ---------------------------------------------------------------------------
# Runtime checks
# ---------------------------------------------------------------------------


def _check_event_integrity(store: EventStore) -> CheckResult:
    broken = store.verify_sequences()
    if broken:
        return CheckResult(
            name="event_log_integrity",
            category="runtime",
            status=CheckStatus.FAIL,
            detail=f"{len(broken)} aggregate(s) have a sequence gap",
            evidence={"aggregates": broken[:10]},
            remediation="restore from a verified snapshot; do not patch the gap.",
        )
    count = store.event_count()
    return CheckResult(
        name="event_log_integrity",
        category="runtime",
        status=CheckStatus.PASS,
        detail=f"{count} event(s), every aggregate sequence is gapless",
    )


def _check_backup_exists(settings: Settings) -> CheckResult:
    backups = list_backups(settings.workspace)
    verified = [b for b in backups if b.get("verified")]
    if not verified:
        return CheckResult(
            name="verified_snapshot_exists",
            category="runtime",
            status=CheckStatus.FAIL,
            detail="no verified snapshot exists in this workspace",
            evidence={"backups_path": str(settings.workspace.backups_path), "found": len(backups)},
            remediation="run `daedalus backup` and rehearse a restore before releasing.",
        )
    return CheckResult(
        name="verified_snapshot_exists",
        category="runtime",
        status=CheckStatus.PASS,
        detail=f"{len(verified)} verified snapshot(s); newest {verified[0].get('path')}",
    )


def _check_alerts(store: EventStore, settings: Settings) -> CheckResult:
    report = evaluate_alerts(store=store, settings=settings, include_recovery=True)
    if not report.healthy:
        critical = [a for a in report.active if a.severity.value == "critical"]
        return CheckResult(
            name="no_active_alerts",
            category="runtime",
            status=CheckStatus.FAIL if critical else CheckStatus.WARN,
            detail=(
                f"{len(report.active)} active alert(s), {len(critical)} critical: "
                + "; ".join(a.rule for a in report.active[:5])
            ),
            evidence=report.describe(),
            remediation="resolve the alerts (`daedalus alerts`) before releasing.",
        )
    return CheckResult(
        name="no_active_alerts",
        category="runtime",
        status=CheckStatus.PASS,
        detail=f"{len(report.evaluated)} rules evaluated, none active",
    )


# ---------------------------------------------------------------------------
# Behavioural checks
# ---------------------------------------------------------------------------


def _check_test_suite(root: Path, *, timeout_sec: int) -> CheckResult:
    """Run the suite. These tests *are* most of the §25 checklist."""
    if not (root / "tests").is_dir():
        return CheckResult(
            name="behavioural_test_suite",
            category="behaviour",
            status=CheckStatus.SKIP,
            detail=f"no tests directory under {root}; the installed package has no suite",
            remediation=(
                "run the release gate from the source checkout, where the permission, boundary "
                "and secret-leak checks live."
            ),
        )
    with tempfile.TemporaryDirectory(prefix="daedalus-release-") as directory:
        junit = Path(directory) / "results.xml"
        command = [sys.executable, "-m", "pytest", "-q", "--no-header", "tests", f"--junitxml={junit}"]
        try:
            completed = subprocess.run(command, cwd=str(root), capture_output=True, text=True,
                                       timeout=timeout_sec, check=False)
        except (subprocess.TimeoutExpired, OSError) as error:
            return CheckResult(name="behavioural_test_suite", category="behaviour",
                               status=CheckStatus.FAIL, detail=f"suite could not complete: {error}")
        try:
            report = ET.parse(junit).getroot()
            cases = list(report.iter("testcase"))
            skipped = sum(case.find("skipped") is not None for case in cases)
            failed = sum(case.find("failure") is not None or case.find("error") is not None for case in cases)
        except (OSError, ET.ParseError):
            cases, skipped, failed = [], 0, 0
        passed = completed.returncode == 0 and bool(cases) and not failed
        status = CheckStatus.FAIL if not passed else CheckStatus.WARN if skipped else CheckStatus.PASS
        return CheckResult(
            name="behavioural_test_suite", category="behaviour", status=status,
            detail=f"{len(cases)} tests recorded; {skipped} skipped; exit {completed.returncode}",
            evidence={"command": " ".join(command), "exit_code": completed.returncode,
                      "tests": len(cases), "skipped": skipped, "failed": failed},
            remediation="" if status is CheckStatus.PASS else "all required tests must execute and pass before production release",
        )


def checklist_coverage() -> dict[str, object]:
    """The §25 checklist and where each item is actually verified."""
    return {
        "checklist": CHECKLIST_COVERAGE,
        "note": (
            "Mappings describe available evidence; UNVERIFIED items block production release."
        ),
    }
