# Repository Guide for Coding Agents

## Project identity

This repository contains **Daedalus**, a deterministic control plane that confines
uncertain model capability inside a verifiable, recoverable and auditable engineering
system. The Python package is `daedalus` and the implementation follows
`Daedalus_System_Implementation_Spec_v2.1`.

Read `docs/architecture.md` before changing anything in `domain/`, `application/gatekeeper/`,
`application/scheduler.py` or `infrastructure/store/`. Those modules are the trust
boundary, and their contracts are load-bearing.

## Sources of truth

1. Executable code, tests, and the persisted event/state contracts.
2. `docs/architecture.md` for layering, the state machine and the gate pipeline.
3. `docs/roadmap.md` for what is actually implemented versus planned.
4. `docs/agentpanelx-reuse.md` for provenance of inherited design decisions.

Do not treat `daedalus demo` output as evidence that a *real model* works. The demo uses
a scripted worker on purpose: it proves the control plane, not a model's competence.

## Repository map

- `src/daedalus/domain/` — pure contracts. No I/O, no SQLite, no subprocess, no imports
  from higher layers. `fsm.py` is the only place allowed to declare a legal transition.
- `src/daedalus/application/` — use cases: FSM service, scheduler, orchestrator, planner,
  workers, gatekeeper.
- `src/daedalus/infrastructure/` — side effects: SQLite event store, Git worktree sandbox,
  redaction.
- `src/daedalus/security/` — boundary enforcement and the secret broker. Meta-Spec protected.
- `src/daedalus/model/` — the untrusted intelligence plane behind one narrow protocol.
- `src/daedalus/cli.py`, `src/daedalus/demo.py` — interfaces.
- `tests/` — behaviour, adversarial gate tests, recovery tests.

## Development principles

- **The FSM decides transitions.** Never write a step status directly. Every mutation goes
  `validate precondition -> append event -> persist state -> emit side effect`, inside one
  transaction.
- **The event log is authoritative.** Projections (`runs`, `steps`, `leases`, `artifacts`,
  `gate_results`) are rebuildable caches. If they disagree with the log, the log wins.
- **Tier-1 always runs; Tier-2 may only make the outcome more conservative.** A
  deterministic failure must never be rescued by a model, and must never spend model budget.
- **Fail closed.** Any ambiguity in reviewer output, transport failure or unexpected
  exception resolves to ESCALATE, never APPROVE.
- **Boundary checks happen before the write**, not after. A rejected batch writes nothing.
- **Errors declare their retryability.** Add new terminal conditions to
  `NON_RETRYABLE_ERRORS` rather than encoding the decision in an exception message.
- **Report the selected isolation driver, not an assumed one.** Worktrees are code
  boundaries, not process isolation. Use `preflight` and `docs/roadmap.md` for limits.

## Never do

- Do not add a third-party SDK to the trusted path. The model client uses `urllib` on
  purpose.
- Do not loosen `MetaSpec` (protected paths, approval requirements, the two
  `allow_*_self_modification = False` invariants).
- Do not write secrets into events, logs, prompts or artifacts. Route through
  `infrastructure/redact.py` and keep `assert_clean` failing loudly.
- Do not use `git push --force`, or integrate anything that is not a fast-forward.
- Do not edit a SQLite row or a managed Git ref to "fix" state; go through the service.

## Verification

```bash
python3 -m pytest                      # full suite, no network, no credentials
python3 scripts/run_demo.py            # offline closed-loop scenarios
python3 -m pytest tests/test_fsm.py -q # fast inner loop while working on the FSM
```

Default verification must never call a model gateway. A credentialed check is opt-in and
must be reported separately from the offline suite.

Before handing off a change to the FSM, the gate, the scheduler or the event store, run
the full suite: those modules have adversarial tests that exist specifically to catch a
relaxed invariant.

### Task-result regression is separate from control-plane regression

- A completed experiment is not a resolved task. Keep stopped, rejected and unsafe
  deliveries open until the original issue checks, existing regression, required
  gates and actual delivery all pass on an identified candidate.
- Continue named failures on the same task before treating fresh tasks as evidence
  that those failures were fixed. Preserve original scores; link development repair
  iterations separately. Reused tasks are not an independent capability score.
- For this local optimization, read
  `external_data/realwork_20261027/diagnostics/task-closure-20261030/case-closure.json`
  when present. Update it from real task receipts, never from unit-test counts.
  This private research ledger is not a dependency of ordinary installation or use.
- Preserve evidence types in memory: executed failures and historical passed checks
  differ from a reviewer's unverified hypothesis. Neither is current approval.
  Persisted logs are not automatically model context; verify what the worker received.
