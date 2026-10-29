"""Frozen, native-host upstream issue evaluation using the actual Daedalus pipeline.

Oracle localization is supplied equally to all arms; upstream gold/test patches
are never present in solver worktrees. This is not an official SWE-bench score.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
from itertools import permutations
import json
from pathlib import Path
import shutil
import subprocess
import time

from daedalus.application.benchmark import (
    CountedWorker, MeteredClient, _daedalus, _single_loop, write_report,
)
from daedalus.application.coding_worker import ModelWorker
from daedalus.application.inspection import RepositoryInspector
from daedalus.application.planner import DeterministicPlanner, PlanRequest
from daedalus.domain.spec import AcceptanceCriterion, AssertionKind
from daedalus.errors import ModelError
from daedalus.infrastructure.git_sandbox import GitSandbox, _git, initial_commit, init_repo
from daedalus.infrastructure.knowledge import atomic_json
from daedalus.infrastructure.redact import redact, redact_text
from daedalus.model.base import TokenBudget

PROJECT = Path(__file__).resolve().parents[3]
DATA = PROJECT / "external_data/realwork_20261027"
EVIDENCE = PROJECT / "docs/realwork_validation_2026-10-27"
ARMS = ("model", "single", "daedalus")


def catalog():
    path = EVIDENCE / "qualified-cases.json"
    return json.loads(path.read_text()) if path.exists() else []


def test_command(row, *, hidden=False):
    python = str(DATA / "env/bin/python")
    contract = row.get("test_contract")
    if contract:
        from daedalus.application.upstream_contract import validate_contract
        validate_contract(contract)
        if contract["repo"] != row["repo"] or contract["hidden_labels"] != row["labels"]:
            raise ValueError("native test contract does not bind this workload")
        if not hidden:
            if row["repo"] == "sympy/sympy":
                return [python, "verify_regression.py"]
            return [python, "tests/runtests.py", *contract["public_labels"],
                    "--noinput", "--parallel", "1", "--verbosity", "1"]
    if row.get("repo", "django/django") == "sympy/sympy":
        return [python, "bin/test", *row["labels"]]
    return [python, "tests/runtests.py", *row["labels"], "--noinput", "--parallel", "1", "--verbosity", "1"]


def _setup(row, root, max_tokens):
    task = json.loads((DATA / "tasks" / row["case"] / "task.json").read_text())
    repo = root / "repo"
    shutil.copytree(PROJECT / row["upstream_root"], repo,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
    init_repo(repo)
    command = test_command(row)
    if row.get("test_contract", {}).get("public_runner"):
        (repo / "verify_regression.py").write_text(row["test_contract"]["public_runner"])
    # The interpreter and upstream test modules are operator-frozen. No model shell.
    wrapper = (
        "import os, pathlib, subprocess, sys\n"
        "root=pathlib.Path(__file__).resolve().parent\n"
        "env=dict(os.environ)\n"
        "env['PYTHONPATH']=str(root)\n"
        "env['PYTHONDONTWRITEBYTECODE']='1'\n"
        f"sys.exit(subprocess.run({command!r},cwd=root,env=env).returncode)\n"
    )
    (repo / "verify_public.py").write_text(wrapper)
    if row.get("test_contract"):
        from daedalus.application.native_verifier import render_native_verifier
        count = (len(row["test_contract"]["public_labels"])
                 if row["repo"] == "django/django" else None)
        immutable = sorted({str(p.relative_to(repo)) for p in repo.rglob("*")
            if p.is_file() and ".git" not in p.relative_to(repo).parts
            and str(p.relative_to(repo)) not in row["targets"]}
            | {"verify_public.py","verify_hidden.py"}
            | ({"verify_issue.py"} if row.get("public_reproduction") else set()))
        wrapper = render_native_verifier(command, row["repo"], expected_tests=count,
                                         immutable_files=immutable)
        (repo / "verify_public.py").write_text(wrapper)
        hidden_command = test_command(row, hidden=True)
        (repo / "verify_hidden.py").write_text(render_native_verifier(
            hidden_command,row["repo"],immutable_files=immutable))
        task = {**task, "_hidden_verifier":"verify_hidden.py"}
    if row.get("public_reproduction"):
        reproduction = row["public_reproduction"]
        (repo / "verify_issue.py").write_text(reproduction["code"])
        wrapper = (render_native_verifier(
            command,row["repo"],expected_tests=count,
            followup=[str(DATA / 'env/bin/python'), 'verify_issue.py'],immutable_files=immutable
        ) if row.get("test_contract") else wrapper.replace(
            f"sys.exit(subprocess.run({command!r},cwd=root,env=env).returncode)",
            f"regression=subprocess.run({command!r},cwd=root,env=env).returncode\n"
            "if regression: sys.exit(regression)\n"
            f"sys.exit(subprocess.run({[str(DATA / 'env/bin/python'), 'verify_issue.py']!r},cwd=root,env=env).returncode)"
        ))
        (repo / "verify_public.py").write_text(wrapper)
    with (repo / ".gitignore").open("a") as stream:
        stream.write("\n__pycache__/\n*.pyc\n")
    initial_commit(repo, "freeze upstream issue base, public tests and local runner")
    tree = _git(repo, ["rev-parse", "HEAD^{tree}"], check=True).stdout.strip()
    goal = (task["problem_statement"] + "\n\nResolve this upstream issue without adding dependencies. "
            "Keep all existing public APIs and behavior unrelated to this issue. "
            "The supplied writable files are oracle-localized, not a discovery task. "
            "Upstream regression tests are immutable; newly added issue tests remain hidden.")
    if row.get("public_reproduction"):
        goal += "\nFrozen public reproduction: " + row["public_reproduction"]["statement"]
    criteria = (AcceptanceCriterion("upstream-regression", AssertionKind.EXIT_CODE,
                                   statement=task["problem_statement"], command="python3 verify_public.py"),)
    bundle = DeterministicPlanner().plan(PlanRequest(
        "realwork", row["case"], goal, tuple(row["targets"]), "python3 verify_public.py",
        acceptance_criteria=criteria, max_tokens_per_step=max_tokens, max_runtime_sec=300,
    ))
    bundle = replace(bundle, plan=replace(bundle.plan, nodes=tuple(
        replace(node, expected_artifacts=tuple(row["targets"])) for node in bundle.plan.nodes
    )))
    if row.get("isolation") == "seatbelt":
        bundle = replace(bundle,boundary=replace(bundle.boundary,isolation="seatbelt"))
    return repo, bundle, tree, task


def _evaluate(repo, bundle, task, root, commit):
    box = GitSandbox.create_from(repo_path=repo, run_root=root / "evaluation",
                                 name="heldout", base_commit=commit)
    try:
        def native_check(filename):
            if bundle.boundary.isolation == "seatbelt":
                from daedalus.infrastructure.sandbox import SeatbeltDriver
                return SeatbeltDriver().run(worktree=box.worktree_path,
                    command=["python3",filename],timeout_sec=120,boundary=bundle.boundary)
            return box.run(["python3",filename],timeout_sec=120)
        public = native_check("verify_public.py")
        applied = subprocess.run(["git", "apply", "--check", "-"], input=task["test_patch"],
                                 text=True, cwd=box.worktree_path, capture_output=True)
        if applied.returncode == 0:
            applied = subprocess.run(["git", "apply", "-"], input=task["test_patch"],
                                     text=True, cwd=box.worktree_path, capture_output=True)
        verifier = ("verify_hidden.py" if task.get("_hidden_verifier") == "verify_hidden.py"
                    else "verify_public.py")
        hidden = native_check(verifier) if applied.returncode == 0 else None
        initial = _git(repo, ["rev-list", "--max-parents=0", "HEAD"], check=True).stdout.strip()
        changed = _git(repo, ["diff", "--name-only", initial, commit], check=True).stdout.splitlines()
        policy = set(changed) <= set(bundle.boundary.fs_whitelist)
        return {"public_passed": public.ok, "heldout_passed": bool(hidden and hidden.ok),
                "policy_passed": policy, "policy_error": "" if policy else "out_of_scope_paths",
                "changed_files": changed, "hidden_patch_applied": applied.returncode == 0,
                "evaluation_output": hidden.combined(8000) if hidden else "hidden_test_patch_not_applicable"}
    finally:
        box.remove()


def run_realwork(destination, client, *, stop_requested, max_tokens=300000, max_calls=144, continuation=None,
                 optimization=False, contract_smoke=None, cycle=None):
    destination.mkdir(parents=True)
    selected = (cycle["cases"] if cycle else
                json.loads((DATA / "diagnostics/fresh-smoke-cases.json").read_text()) if contract_smoke else
                json.loads((PROJECT / "docs/failure_optimization_2026-10-27/cases.json").read_text())
                if optimization else catalog())
    if contract_smoke or cycle:
        from daedalus.application.upstream_contract import admit_contract
        if not 1 <= len(selected) <= (6 if cycle else 2):
            raise ValueError("fixed check contains too many fresh tasks")
        for row in selected:
            admit_contract(row)
    arms = ("daedalus",) if contract_smoke else ("single", "daedalus") if optimization else ARMS
    efficiency = bool(cycle and cycle.get("study") in {"worker-efficiency-v1","worker-efficiency-v2"})
    worker_control = ModelWorker
    if efficiency:
        from daedalus.application.realwork_workers import baseline_worker
        worker_control = baseline_worker(DATA,cycle["baseline_worker_sha256"],
            evidence_path=destination/"worker-control.py",
            revision="efficiency-v1" if cycle["study"]=="worker-efficiency-v2" else "poststudy")
        arms = ("baseline","optimized")
    money_context = (cycle["monetary_admission"] if cycle else contract_smoke if contract_smoke else
                     {"max_total_cost_cny":0.65, "prior_cost_upper_cny":0}
                     if optimization else continuation)
    if not selected:
        raise ValueError("qualified upstream cases have not been frozen")
    token_ceiling=540000 if cycle else 1000000 if continuation else 300000
    call_ceiling=240 if continuation else 144
    if not (1 <= max_tokens <= token_ceiling and 1 <= max_calls <= call_ceiling):
        raise ValueError("series cap exceeds the fixed release budget")
    remaining_keys={tuple(key) for key in continuation["remaining_keys"]} if continuation else None
    protocol = {
        "version": 1, "scope": "oracle-localized upstream issues, native host; not official SWE-bench",
        "cases": [{k:r[k] for k in ["case", "base_commit", "targets", "labels", "archive_sha256", "source_chars"]} for r in selected],
        "task_sha256": {r["case"]:hashlib.sha256((DATA/"tasks"/r["case"]/"task.json").read_bytes()).hexdigest() for r in selected},
        "model": client.model, "inference_profile": getattr(client, "inference_profile", "configured"),
        "arms": arms, "arm_order": "cyclic permutations, in frozen task order",
        "max_tokens": max_tokens, "max_calls": max_calls, "max_tokens_per_arm": 30000,
        "budget_continuation":continuation,
        "study": cycle.get("study", "capability-cycle-v1") if cycle else "contract-smoke-v1" if contract_smoke else "optimization-v1" if optimization else "upstream-v1",
        "cycle": {k:v for k,v in cycle.items() if k not in {"cases","monetary_admission"}} if cycle else None,
        "monetary_admission": money_context,
        "worker_settings": {"initial_output_tokens":2048 if (contract_smoke or cycle) else 4096 if optimization else 8192,
                            "review_headroom_tokens":8192 if (optimization or contract_smoke or cycle) else 2048},
        "public_reproductions": {r["case"]:r["public_reproduction"] for r in selected
                                 if r.get("public_reproduction")},
        "test_contracts": {r["case"]:r["test_contract"] for r in selected if r.get("test_contract")},
        "max_calls_per_arm": 6, "repeats": 1,
        "price": {"currency": "CNY", "peak_input_per_million": 2, "peak_output_per_million": 8,
                  "source": "https://api-docs.deepseek.com/zh-cn/quick_start/pricing/",
                  "checked": cycle.get("price_checked","2026-10-27") if cycle else "2026-10-27"},
        "no_automatic_resume": True, "stop_on_unknown_usage": True,
        "selection_rule_sha256": cycle["plan_sha256"] if cycle else hashlib.sha256((
            DATA/"diagnostics/fresh-smoke-cases.json" if contract_smoke else
            PROJECT/"docs/failure_optimization_2026-10-27/cases.json" if optimization
            else EVIDENCE/"selection-rule.json").read_bytes()).hexdigest(),
        "implementation_sha256": {str(p.relative_to(PROJECT)):hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in (PROJECT/"src/daedalus").rglob("*.py")},
        "limitations": ["Two-project convenience subset; no population estimate", "oracle file localization supplied equally",
                        "native-host adaptation and qualification filtering differ from official SWE-bench Docker harness",
                        "all failures and stops retained; no outcome-based exclusions or paid reruns"],
    }
    if efficiency:
        protocol["scope"] = "fresh paired worker development check; oracle-localized native Django tasks"
        protocol["limitations"] = [
            "Small development sample, one run per task; no general capability or cost superiority claim",
            "same current gatekeeper and model for both workers; baseline worker source exported separately",
            "all failures retained; no sealed tasks resumed or rerun",
            "native Seatbelt denies network and external writes, not host reads",
        ]
    protocol["sha256"] = hashlib.sha256(json.dumps(protocol,sort_keys=True).encode()).hexdigest()
    atomic_json(destination/"protocol.json", protocol)
    series = MeteredClient(client, max_calls, max_tokens)
    money_blocked=False
    admission_count=0

    def cost_upper():
        return sum((r.get("prompt_tokens",0)*2+r.get("completion_tokens",0)*8)/1000000 for r in series.records if r.get("usage_available",False))

    class Guarded:
        model = client.model
        name = client.name
        inference_profile = getattr(client, "inference_profile", "configured")

        def complete(self, messages, **options):
            nonlocal money_blocked, admission_count
            if stop_requested() or any(r.get("request_dispatched", True) and not r.get("usage_available", False) for r in series.records):
                raise ModelError("series stopped or previous provider usage unknown", request_not_dispatched=True)
            if money_context:
                remaining=money_context["max_total_cost_cny"]-money_context["prior_cost_upper_cny"]-cost_upper()
                prompt_bound=sum(len(m.content.encode("utf-8")) for m in messages)+2048
                output_affordable=int((remaining-prompt_bound*2/1000000)*1000000/8)
                if output_affordable < 256:
                    money_blocked=True
                    raise ModelError("whole-study monetary admission reserve exhausted",request_not_dispatched=True)
                options["max_tokens"]=min(options.get("max_tokens",4096),output_affordable)
            # Persist an admission before crossing the paid boundary. A process death
            # cannot erase the fact that a request may have reached the supplier.
            admission_path = None
            record_count = len(series.records)
            if cycle and cycle.get("study") in {"capability-cycle-transport-v1","worker-efficiency-v1",
                                                "worker-efficiency-v2"}:
                admission_count += 1
                admission_path = destination/"monetary-admissions"/f"request-{admission_count:03}.json"
                admission = {
                    "index":admission_count,"expected_call_index":record_count+1,"state":"PREPARED",
                    "input_digest":hashlib.sha256(json.dumps(
                        [m.to_payload() for m in messages],sort_keys=True).encode()).hexdigest(),
                    "input_byte_bound":prompt_bound,"max_output_tokens":options.get("max_tokens",4096),
                    "reserved_cost_upper_cny":(prompt_bound*2+options.get("max_tokens",4096)*8)/1e6,
                    "known_prior_cost_cny":cost_upper(),
                    "prior_budget_occupied_cny":money_context["prior_cost_upper_cny"],
                }
                atomic_json(admission_path,admission)
            try:
                completion = series.complete(messages, **options)
            finally:
                if admission_path is not None:
                    latest = (series.records[-1] if len(series.records) > record_count else
                              {"request_dispatched":False,"usage_available":False})
                    admission.update(state="RETURNED",call_record=latest)
                    atomic_json(admission_path,admission)
                    atomic_json(destination/"series-usage.json",redact({
                        "reported_tokens":series.total,"logical_calls":len(series.records),
                        "call_records":series.records}))
            atomic_json(destination/"model-calls"/f"call-{len(series.records):03}.json", {
                "input_digest":series.records[-1]["input_digest"],
                "model":completion.model, "response":redact_text(completion.text),
                "prompt_tokens":completion.prompt_tokens,"completion_tokens":completion.completion_tokens,
                "http_framing_recovered":bool(completion.raw.get("http_framing_recovered")),
            })
            return completion

    rows = []
    reason = ""
    for index, case in enumerate(selected):
        order = tuple(permutations(arms))[index % len(tuple(permutations(arms)))]
        for arm in order:
            if remaining_keys is not None and (case["case"],arm) not in remaining_keys:
                continue
            if money_blocked:
                reason="whole_study_monetary_reserve"
                break
            if stop_requested():
                reason = "explicit_stop"
                break
            if any(r.get("request_dispatched", True) and not r.get("usage_available", False) for r in series.records):
                reason = "provider_usage_unknown"
                break
            if len(series.records) >= max_calls or max_tokens-series.total < 10000:
                reason = "series_budget_reserve"
                break
            root = destination / f"trial-01-{case['case']}-{arm}"
            root.mkdir()
            started = time.monotonic()
            metered = MeteredClient(Guarded(), 6, 30000)
            factory = worker_control if arm == "baseline" else ModelWorker
            worker = CountedWorker(factory(metered, budget=TokenBudget(
                max_tokens_per_run=30000, max_tokens_per_step=30000),
                initial_output_tokens=2048 if (contract_smoke or cycle) else 4096 if optimization else 8192,
                review_headroom_tokens=8192 if (optimization or contract_smoke or cycle) else 2048,
                inspection_context=RepositoryInspector() if arm != "model" else None))
            outcome = {"status":"ERROR", "delivered":False, "manual_interventions":0}
            evaluated = {}
            error = None
            tree = None
            try:
                repo, bundle, tree, task = _setup(case, root, 30000)
                outcome = (_single_loop(repo,bundle,worker,root,30000,attempts=1 if arm=="model" else 3)
                           if arm != "daedalus" and not efficiency else
                           _daedalus(repo,bundle,worker,metered,root,30000))
                evaluated = _evaluate(repo,bundle,task,root,outcome["candidate_commit"])
            except Exception as failure:
                error = type(failure).__name__
                atomic_json(root/"error.json",{"type":error,"detail":redact_text(str(failure))[:1000]})
            calls = metered.records
            dispatched = [r for r in calls if r.get("request_dispatched", True)]
            usage_known = bool(dispatched) and all(r.get("usage_available",False) for r in dispatched)
            row = {"case":case["case"], "repeat":1, "arm":arm, "order":order.index(arm), "fault":"",
                   "initial_tree":tree, **outcome, **evaluated, "error":error,
                   "wall_seconds":time.monotonic()-started, "worker_calls":worker.calls,
                   "inspections":worker.observations, "model_calls":len(calls),
                   "dispatched_model_calls":len(dispatched), "model_completions":sum(r["ok"] for r in calls),
                   "tokens":sum(r.get("prompt_tokens",0)+r.get("completion_tokens",0) for r in calls) if usage_known else None,
                   "model_evidence_valid":any(r["ok"] for r in calls), "call_records":calls,
                   "artifact_root":root.name}
            row["safe_delivery"] = bool(row["delivered"] and all(row.get(k) for k in ["public_passed","heldout_passed","policy_passed"]))
            row["unsafe_delivery"] = bool(row["delivered"] and not row["safe_delivery"])
            rows.append(row)
            atomic_json(root/"result.json",redact(row))
            atomic_json(destination/"progress.json",redact(rows))
            atomic_json(destination/"series-usage.json",redact({"reported_tokens":series.total,"logical_calls":len(series.records),"call_records":series.records}))
        if reason:
            break
    if money_blocked:
        reason=reason or "whole_study_monetary_reserve"
    if any(r.get("request_dispatched",True) and not r.get("usage_available",False) for r in series.records):
        reason=reason or "provider_usage_unknown"
    report = {"mode":"model", "arms":arms, "planned_trials_per_arm":len(selected),
              "status":"INCOMPLETE" if reason or len(rows)!=(len(remaining_keys) if remaining_keys is not None else len(arms)*len(selected)) else "COMPLETE",
              "stop_reason":reason, "protocol_sha256":protocol["sha256"], "trials":rows,
              "real_model_completions":sum(r["model_completions"] for r in rows),
              "scope":protocol["scope"], "limitations":protocol["limitations"],
              "series_reported_tokens":series.total, "series_logical_calls":len(series.records)}
    write_report(destination, report)
    return report
