# ruff: noqa: E501
"""Frozen fresh review subjects for a context ablation, not a coding benchmark.

Ten contracts each have a correct and faulty fixed candidate. Hidden executable
checks establish labels before any model call. The model never sees those labels
or checks. Both conditions review exactly the same candidate commit.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from daedalus.application.benchmark import MeteredClient
from daedalus.application.gatekeeper.tier2 import ClientReviewer, Tier2Gate
from daedalus.application.goal_audit import GoalReviewRequest
from daedalus.application.review_context import dependency_context
from daedalus.domain.canonical import digest_of
from daedalus.infrastructure.git_sandbox import GitSandbox, _git, init_repo, initial_commit
from daedalus.infrastructure.knowledge import atomic_json


@dataclass(frozen=True)
class ReviewCase:
    family: str
    contract: str
    helper: str
    correct: str
    faulty: str
    oracle: str


CASES = (
    ReviewCase(
        "stable_order",
        "Input is a list of rows with timestamp strings and unique integer ids. ordered(rows) returns ascending (timestamp,id) order without mutating input. Use the read-only helpers.sort_key if useful.",
        "def sort_key(row): return (row['timestamp'], row['id'])\n",
        "from helpers import sort_key\ndef ordered(rows): return sorted(rows,key=sort_key)\n",
        "from helpers import sort_key\ndef ordered(rows): return sorted(rows,key=lambda r:sort_key(r)[0])\n",
        "from impl import ordered\nimport copy\nr=[{'timestamp':'a','id':2},{'timestamp':'a','id':1},{'timestamp':'b','id':3}];b=copy.deepcopy(r)\nassert [x['id']for x in ordered(r)]==[1,2,3] and r==b\n",
    ),
    ReviewCase(
        "normalization",
        "label(value) accepts strings and returns NFC Unicode, collapsed internal whitespace and the limit from helpers.POLICY. Do not mutate any shared policy. helpers.normalize is a read-only helper; inspect its actual signature rather than assuming mutation or argument conventions.",
        "import unicodedata\nPOLICY={'limit':64}\ndef normalize(value,*,policy): return unicodedata.normalize('NFC',' '.join(value.split()))[:policy['limit']]\n",
        "from helpers import normalize,POLICY\ndef label(value): return normalize(value,policy=POLICY)\n",
        "from helpers import normalize,POLICY\ndef label(value): return value.strip()\n",
        "from impl import label\nfrom helpers import POLICY\nassert label('  Cafe'+chr(769)+'   task  ')=='Café task'\nassert label('x'*80)=='x'*64 and POLICY=={'limit':64}\n",
    ),
    ReviewCase(
        "expiry_boundary",
        "expired(now,started,ttl) uses nonnegative integer timestamps and positive integer ttl. A lease is expired at and after started+ttl, and active strictly before that instant. Helpers are read-only.",
        "def deadline(started,*,seconds): return started+seconds\n",
        "from helpers import deadline\ndef expired(now,started,ttl): return now>=deadline(started,seconds=ttl)\n",
        "from helpers import deadline\ndef expired(now,started,ttl): return now>deadline(started,seconds=ttl)\n",
        "from impl import expired\nassert expired(15,10,5) is True and expired(14,10,5) is False and expired(16,10,5) is True\n",
    ),
    ReviewCase(
        "unknown_usage",
        "totals(records) returns {'known_tokens': int, 'unknown_requests': int}. Each record has prompt/completion values that are nonnegative ints or None. Missing or None token fields mean unknown; known zero is a known request. Do not mutate records. helpers.classify may be used.",
        "def classify(r):\n p,o=r.get('prompt_tokens'),r.get('completion_tokens')\n return None if p is None or o is None else p+o\n",
        "from helpers import classify\ndef totals(records):\n known=unknown=0\n for r in records:\n  n=classify(r)\n  if n is None: unknown+=1\n  else: known+=n\n return {'known_tokens':known,'unknown_requests':unknown}\n",
        "from helpers import classify\ndef totals(records):\n known=unknown=0\n for r in records:\n  n=classify(r)\n  if not n: unknown+=1\n  else: known+=n\n return {'known_tokens':known,'unknown_requests':unknown}\n",
        "from impl import totals\nimport copy\nr=[{'prompt_tokens':0,'completion_tokens':0},{'prompt_tokens':None,'completion_tokens':5},{'prompt_tokens':2,'completion_tokens':3}];b=copy.deepcopy(r)\nassert totals(r)=={'known_tokens':5,'unknown_requests':1} and r==b\n",
    ),
    ReviewCase(
        "cursor_exclusive",
        "after(rows,cursor) takes rows already sorted by (ts,id), unique integer ids, string ts, and a valid JSON [ts,id] cursor. Return only rows strictly after that cursor, preserving order and input. Malformed inputs are outside this frozen contract.",
        "import json\ndef decode(value): return tuple(json.loads(value))\n",
        "from helpers import decode\ndef after(rows,cursor):\n key=decode(cursor)\n return [r for r in rows if (r['ts'],r['id'])>key]\n",
        "from helpers import decode\ndef after(rows,cursor):\n key=decode(cursor)\n return [r for r in rows if (r['ts'],r['id'])>=key]\n",
        "from impl import after\nr=[{'ts':'a','id':1},{'ts':'a','id':2},{'ts':'b','id':3}]\nassert [x['id']for x in after(r,'[\"a\",2]')]==[3] and len(r)==3\n",
    ),
    ReviewCase(
        "url_path",
        "resolved(value) receives a percent-encoded relative URL path, possibly with a single leading slash. Inputs contain no traversal or absolute filesystem paths. Return 'workspace/' followed by the URL-decoded path with that leading slash removed. helpers.decode_path is read-only.",
        "from urllib.parse import unquote\ndef decode_path(value): return unquote(value).removeprefix('/')\n",
        "from helpers import decode_path\ndef resolved(value): return 'workspace/'+decode_path(value)\n",
        "from helpers import decode_path\ndef resolved(value): return 'workspace/'+value.removeprefix('/')\n",
        "from impl import resolved\nassert resolved('/docs%2Fhello%20world.md')=='workspace/docs/hello world.md'\n",
    ),
    ReviewCase(
        "redacted_log",
        "log_entry(item) returns sorted-key JSON containing all fields from an input mapping of string keys and string/int values, except the value of 'secret' must be '[redacted]'. Input must remain unchanged; helpers.clean may be used. No real credentials are present in this fixture.",
        "def clean(item): return {k:('[redacted]' if k=='secret' else v)for k,v in item.items()}\n",
        "import json\nfrom helpers import clean\ndef log_entry(item): return json.dumps(clean(item),sort_keys=True)\n",
        "import json\nfrom helpers import clean\ndef log_entry(item): return json.dumps(item,sort_keys=True)\n",
        "from impl import log_entry\nimport json\nx={'id':2,'secret':'synthetic-fixture'}\nassert json.loads(log_entry(x))=={'id':2,'secret':'[redacted]'} and x['secret']=='synthetic-fixture'\n",
    ),
    ReviewCase(
        "immutable_transition",
        "finish(record) returns a NEW mapping preserving every field except state='done'. Input mapping must remain unchanged. helpers.transition is a read-only API; determine from its source whether it mutates or returns a value.",
        "def transition(record): return {**record,'state':'done'}\n",
        "from helpers import transition\ndef finish(record): return transition(record)\n",
        "from helpers import transition\ndef finish(record):\n transition(record)\n return record\n",
        "from impl import finish\nx={'id':1,'state':'pending'};y=finish(x)\nassert y=={'id':1,'state':'done'} and x=={'id':1,'state':'pending'} and y is not x\n",
    ),
    ReviewCase(
        "micro_units",
        "charge(value) accepts finite nonnegative decimal strings with at most six fractional digits, and returns an integer number of micro-units (one unit equals 1000000 micro-units). helpers.units may be used; its actual return unit is part of the available source context.",
        "from decimal import Decimal\ndef units(value): return int(Decimal(value)*1000000)\n",
        "from helpers import units\ndef charge(value): return units(value)\n",
        "from helpers import units\ndef charge(value): return units(value)*1000000\n",
        "from impl import charge\nassert charge('1.000001')==1000001 and charge('0')==0\n",
    ),
    ReviewCase(
        "config_projection",
        "public_config(source) returns a NEW mapping with only endpoint and model fields if present. All unknown fields, including secret, are omitted. Input must not change. Inputs are string-keyed mappings; no endpoint or model normalization is requested. helpers.project is read-only.",
        "def project(source): return {k:source[k]for k in ('endpoint','model')if k in source}\n",
        "from helpers import project\ndef public_config(source): return project(source)\n",
        "from helpers import project\ndef public_config(source):\n out=project(source)\n out.update(source)\n return out\n",
        "from impl import public_config\nx={'endpoint':'https://example.invalid','model':'demo','secret':'synthetic-fixture','extra':3}\ny=public_config(x)\nassert y=={'endpoint':x['endpoint'],'model':'demo'} and y is not x and x['extra']==3\n",
    ),
)


def prepare(root: Path):
    """Create and test all fixed subjects before writing the model-call protocol."""
    subjects = []
    for case in CASES:
        for correct, source in ((True, case.correct), (False, case.faulty)):
            index = len(subjects) + 1
            directory = root / "subjects" / f"subject-{index:02}"
            directory.mkdir(parents=True)
            repo = init_repo(directory / "repo")
            (repo / "helpers.py").write_text(case.helper)
            (repo / "impl.py").write_text("# candidate implementation\n")
            (repo / ".gitignore").write_text("__pycache__/\n")
            initial_commit(repo, "initialize frozen review subject")
            base = _git(repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
            (repo / "impl.py").write_text(source)
            _git(repo, ["add", "impl.py"], check=True)
            _git(repo, ["commit", "-m", "fixed review candidate"], check=True)
            commit = _git(repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
            smoke = subprocess.run(
                [sys.executable, "-c", "import impl; import helpers"],
                cwd=repo,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if smoke.returncode:
                raise ValueError("candidate import smoke check failed: " + case.family)
            changed = _git(
                repo, ["diff", "--name-only", base, commit], check=True
            ).stdout.splitlines()
            if changed != ["impl.py"]:
                raise ValueError("candidate changed an undeclared path")
            check = subprocess.run(
                [sys.executable, "-c", case.oracle],
                cwd=repo,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if (check.returncode == 0) != correct:
                raise ValueError("review oracle self-check failed: " + case.family)
            box = GitSandbox.create_from(
                repo_path=repo, run_root=directory / "trees", name="evidence", base_commit=commit
            )
            try:
                context = dependency_context(box, ("impl.py",))
            finally:
                box.remove()
            patch = _git(repo, ["diff", base, commit, "--", "impl.py"], check=True).stdout
            request = GoalReviewRequest(
                step_id=f"review:{index:02}",
                execution_id="context-ablation",
                artifact_digest=digest_of({"commit": commit}),
                goal_intent=case.contract,
                node_intent="Review this entire fixed delivery against its original contract",
                acceptance_criteria=("contract: " + case.contract,),
                changed_files=("impl.py",),
                patch=patch,
                tier1_summary="Syntax and path boundary passed. Public smoke checks passed; they do not establish all contract clauses.",
                reference_context=context,
            )
            subjects.append(
                {
                    "id": f"subject-{index:02}",
                    "family": case.family,
                    "expected_approve": correct,
                    "candidate_commit": commit,
                    "oracle_exit_code": check.returncode,
                    "import_smoke_exit_code": smoke.returncode,
                    "oracle_output": (check.stdout + check.stderr)[-2000:],
                    "contract": case.contract,
                    "helper": case.helper,
                    "candidate": source,
                    "oracle": case.oracle,
                    "request": asdict(request),
                    "rendered_request_sha256": {
                        "with_context": hashlib.sha256(request.render().encode()).hexdigest(),
                        "without_context": hashlib.sha256(
                            replace(request, reference_context="").render().encode()
                        ).hexdigest(),
                    },
                }
            )
    return subjects


def run_review_comparison(root, client: MeteredClient, *, stop_requested=lambda: False):
    batch_started = time.monotonic()
    subjects = prepare(root)
    protocol = {
        "scope": "20 fixed subjects from 10 contracts; paired production goal-review calls, not agent coding ability",
        "model": client.model,
        "inference_profile": client.inference_profile,
        "max_reported_tokens": client.max_tokens,
        "max_calls": client.max_calls,
        "subjects": subjects,
        "planned_reviews": 40,
        "conditions": ["without_context", "with_context"],
        "implementation_sha256": {
            name: hashlib.sha256((Path(__file__).parents[1] / name).read_bytes()).hexdigest()
            for name in (
                "application/review_probes.py",
                "application/review_context.py",
                "application/goal_audit.py",
                "application/gatekeeper/tier2.py",
                "model/multi_provider.py",
            )
        },
    }
    atomic_json(root / "protocol.json", protocol)
    atomic_json(
        root / "protocol-sha256.json",
        {
            "sha256": hashlib.sha256((root / "protocol.json").read_bytes()).hexdigest(),
            "frozen_before_dispatch": True,
        },
    )
    rows = []
    reviewer = ClientReviewer(client)
    interrupted = False
    for index, subject in enumerate(subjects):
        conditions = (
            ("without_context", "with_context")
            if index % 2 == 0
            else ("with_context", "without_context")
        )
        for condition in conditions:
            if (
                stop_requested()
                or client.total >= client.max_tokens
                or len(client.records) >= client.max_calls
                or any(
                    c.get("request_dispatched", True) and not c.get("usage_available", False)
                    for c in client.records
                )
            ):
                interrupted = True
                break
            request = GoalReviewRequest(**subject["request"])
            if condition == "without_context":
                request = replace(request, reference_context="")
            start = time.monotonic()
            before = len(client.records)
            reviewed = Tier2Gate(reviewer).review(request)
            calls = client.records[before:]
            criteria = reviewed.raw.get("criterion_results")
            coherent = (
                isinstance(criteria, list)
                and len(criteria) == 1
                and isinstance(criteria[0], dict)
                and criteria[0].get("criterion_id") == "contract"
                and isinstance(criteria[0].get("evidence"), str)
                and bool(criteria[0]["evidence"].strip())
                and criteria[0].get("status") in {"MET", "UNMET", "UNKNOWN"}
            )
            approved = (
                reviewed.decision.value == "APPROVE"
                and not reviewed.fail_closed
                and coherent
                and criteria[0]["status"] == "MET"
            )
            row = {
                "subject": subject["id"],
                "family": subject["family"],
                "expected_approve": subject["expected_approve"],
                "condition": condition,
                "decision": reviewed.decision.value,
                "approved": approved,
                "fail_closed": reviewed.fail_closed,
                "criterion_report_valid": coherent,
                "criterion_status": criteria[0]["status"] if coherent else "INVALID",
                "reasons": list(reviewed.reasons),
                "violations": list(reviewed.violations),
                "review_payload": reviewed.raw,
                "failure_reason": reviewed.failure_reason,
                "subject_digest": request.subject_digest(),
                "candidate_commit": subject["candidate_commit"],
                "call_records": calls,
                "wall_seconds": time.monotonic() - start,
                "reported_tokens": sum(
                    c.get("prompt_tokens", 0) + c.get("completion_tokens", 0) for c in calls
                ),
                "model_response_valid": any(c["ok"] for c in calls)
                and not reviewed.fail_closed
                and coherent,
            }
            rows.append(row)
            atomic_json(root / "progress.json", {"reviews": rows})
        if interrupted:
            break
    summary = {}
    for condition in protocol["conditions"]:
        selected = [r for r in rows if r["condition"] == condition]
        summary[condition] = {
            "reviewed": len(selected),
            "planned": 20,
            "correct_candidates_approved": sum(
                r["approved"] and r["expected_approve"] for r in selected
            ),
            "correct_candidates_planned": 10,
            "faulty_candidates_approved": sum(
                r["approved"] and not r["expected_approve"] for r in selected
            ),
            "faulty_candidates_revised": sum(
                r["decision"] == "REVISE"
                and r["model_response_valid"]
                and r["criterion_status"] == "UNMET"
                and not r["expected_approve"]
                for r in selected
            ),
            "invalid_model_responses": sum(not r["model_response_valid"] for r in selected),
            "reported_tokens": sum(r["reported_tokens"] for r in selected),
            "wall_seconds": sum(r["wall_seconds"] for r in selected),
        }
    report = {
        "status": "INTERRUPTED" if interrupted else "COMPLETE",
        "summary": summary,
        "reviews": rows,
        "reported_tokens": client.total,
        "logical_calls": len(client.records),
        "elapsed_seconds": time.monotonic() - batch_started,
        "scope": protocol["scope"],
        "agent_superiority_claim": False,
    }
    atomic_json(root / "report.json", report)
    return report
