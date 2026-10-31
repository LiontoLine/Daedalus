"""Outbound secret guard (Spec §8: "Secret 不得写入 LLM Prompt").

The gap this closes: file content was rendered into model prompts without any check, so a
credential committed in a target file was sent to the model verbatim. Inbound responses were
redacted; outbound requests were not.

Why this **refuses** rather than redacts. Redacting the prompt is the obvious move and it is
wrong here: the model would faithfully write `***REDACTED***` back into the file, replacing a
real credential with a placeholder and corrupting the repository — and the gate would not
necessarily catch it, because the placeholder is not a secret shape. A silent corruption is
worse than a loud refusal.

So the rule is fail-closed and specific:

* the prompt is scanned before it leaves the process;
* if a credential shape is found, the step does not run and says which path was implicated;
* the operator removes the credential or narrows SPEC-03, and the step retries.

The same scanner runs on the diff, so a worker that *introduces* a credential is caught at the
gate rather than at the model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from daedalus.errors import DaedalusError
from daedalus.infrastructure.redact import (
    _PATTERNS,
    is_symbolic_secret_reference,
    json_objects,
)


class SecretInPayload(DaedalusError):
    """A credential shape was found in content about to leave the process.

    Never auto-retried: re-running does not remove a credential from a file, and retrying would
    send it again.
    """

    code = "secret_in_payload"


@dataclass(frozen=True, slots=True)
class SecretFinding:
    kind: str
    count: int
    sample_line: int = 0

    def describe(self) -> dict[str, object]:
        return {"kind": self.kind, "count": self.count, "line": self.sample_line}


#: Added lines in a unified diff. `+++` is the file header, not content.
_ADDED_LINE = re.compile(r"^\+(?!\+\+)")


def scan_text(text: str) -> tuple[SecretFinding, ...]:
    """Find credential shapes in arbitrary text. Reports kinds, never values."""
    objects = list(json_objects(text))
    findings: dict[str, SecretFinding] = {}
    for name, pattern in _PATTERNS:
        matches = [match for match in pattern.finditer(text)
                   if not any(start <= match.start() < end for start, end, _ in objects)
                   and (name != "key_value" or not is_symbolic_secret_reference(text, match))]
        if matches:
            line = text.count("\n", 0, matches[0].start()) + 1
            findings[name] = SecretFinding(kind=name, count=len(matches), sample_line=line)
    for start, _, value in objects:
        line = text.count("\n", 0, start) + 1
        pending = [value]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                pending.extend(item.keys())
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
            elif isinstance(item, str):
                for finding in scan_text(item):
                    previous = findings.get(finding.kind)
                    findings[finding.kind] = SecretFinding(
                        kind=finding.kind, count=finding.count + (previous.count if previous else 0),
                        sample_line=min(line, previous.sample_line) if previous else line,
                    )
    return tuple(findings[name] for name, _ in _PATTERNS if name in findings)


def scan_added_lines(patch: str) -> tuple[SecretFinding, ...]:
    """Find credential shapes in the lines a patch *adds*.

    Deliberately only the added lines: a credential that already existed in the file should not
    block every attempt to edit that file, but introducing one must be caught.
    """
    added = "\n".join(
        line[1:] for line in patch.splitlines() if _ADDED_LINE.match(line)
    )
    return scan_text(added)


def assert_outbound_clean(text: str, *, where: str) -> None:
    """Raise `SecretInPayload` if `text` contains a credential shape."""
    findings = scan_text(text)
    if not findings:
        return
    kinds = ", ".join(f"{finding.kind}×{finding.count}" for finding in findings)
    raise SecretInPayload(
        f"refusing to send {where} to a model: it contains what looks like a credential "
        f"({kinds}). Remove the credential from the file, or narrow SPEC-03 so the step cannot "
        "read it. The prompt is not redacted on the way out because the model would write the "
        "placeholder back into the file.",
        where=where,
        findings=[finding.describe() for finding in findings],
    )


def describe_findings(findings: tuple[SecretFinding, ...]) -> str:
    return ", ".join(f"{finding.kind}×{finding.count}" for finding in findings) or "none"
