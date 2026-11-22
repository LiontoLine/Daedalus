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

### Blind experiments

- For **every experimental batch**, start a **new test-author subagent** before
  execution. Give it only public behavior, interfaces and resource limits, not
  implementation source, diffs, solver traces, past answers or credentials. It
  authors and freezes the workload, independent oracle and measurement code in a
  separate directory; it does not implement the product or run the experiment.
- Keep hidden checks outside the implementation and target worktrees. Do not send
  test source, fixtures with expected answers, or raw hidden failures to the
  implementation agent or model under test. Pre-existing repository regression
  commands remain ordinary development checks, not independent experiments.
- Use a non-agent runner, or a separate restricted runner with only a frozen
  command and result channel. Do not let an agent running the experiment browse
  implementation source or hidden check code. Use a packaged candidate in a
  disposable workspace; hand the implementer only sanitized results. If isolation
  is unavailable, do not claim a blind result.
- Record the test-author identity, hashes of the candidate and experiment, the
  measurement protocol and all outcomes. Never retune a hidden oracle after
  seeing results; a changed experiment needs a new author and a new record.
- Before a paid batch, qualify the exact harness against its documented CLI/API
  and make sure its native commands respect the selected sandbox. Missing fields
  or setup failures invalidate the measurement; keep the result and fix the
  harness through a fresh author, never change product isolation to pass it.
- Operator-provided public requirements can guide the solver. Their private test
  source, method names, inputs and raw failures cannot. The gate runs the checks
  and exports only public requirement outcomes and receipt identifiers to models.
  This still does not make an operator-owned in-process test an opaque oracle for
  malicious code; keep the sealed benchmark outside that path.

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
- Explicit replay may recall one failed parent only when the recorded repository,
  frozen spec, original replay base and actual node base match. Do not broaden
  scope, treat old observations as current approval, or fetch unrelated task history.
- Autonomous original-task regressions are recorded separately under the private
  ledger's `autonomous_regressions`: an accepted, assisted historical patch is not
  cold-start model delivery. Preserve configured-profile diagnostic failures as
  well as profile-matched runs; compare only matching workload/context/profile
  protocols, and never combine unit-test counts with task results.
- Qualify the original native interpreter and complete test counters before paid
  replay. A corrected probe environment is a new development protocol, not a model
  accuracy gain. Keep its earlier failed runs rather than rewriting their scores.
- Terminal-repair rechecking and assertion-first consumer navigation have actual
  native receipts, but mechanism proof is not successful autonomous task delivery.
  Read the latest phase, stop codes and delivered artifacts before planning changes;
  do not repeat a paid run without a concrete code or protocol change.
- A source request or receipt path does not prove source content was delivered.
  Inspect `status`, nonempty `sources`, and the actual model message. A blocked
  whole-file scan must not be bypassed through snippets or fixture exceptions.
- A changed read receipt does not make a rejected same-spec, same-base, same-patch
  review subject new. Keep observations in events, but use an actual delta in code
  or qualified executable behavior before spending another paid review or replay.
- Keep newly autonomous accepted artifacts under same-task native regression after
  later code changes. Separate retained artifact closure from a new cold-start trial;
  a later failed solve does not erase a previously verified delivery or its provenance.
- `autonomous_case_closure` tracks retained, verified task artifacts. Per-phase trial
  rows and `last_cold_start_failures` track fresh solve outcomes; do not replace one
  metric with the other when reporting progress or deciding what remains open.
- A failed-line window is not the whole input contract. Inspect the actual prompt
  for contrasting invocation inputs and assertions before claiming a source gap
  is closed; same-setup variants are syntactic hints, not execution or new approval.
- Keep canonical bounded evidence separate from model-visible projection. Scan
  complete observations before selecting fields. Preserve useful historical
  bodies, tree identity, content digests and explicit truncation markers; removing
  responsibility clues is not a token-efficiency improvement. Context compaction
  does not authorize a smaller estimate, reset budget or reduced review reserve.
- Stale-edit refresh must expose the changed expression, not merely any method
  mentioned by broad task prose. Preserve explicit frozen `Class.method` targets
  over a model-invented owner; verify both precedence directions with real behavior.
- Match experimental scoring to frozen check contracts: a plain exit-code script
  need not emit a native counter receipt. Keep the designated original-issue
  supervisor's complete receipt requirement; version policy changes and preserve
  historical reports rather than rescoring failed candidates.
