#!/usr/bin/env python3
"""End-to-end live check: a real uvicorn service, a real run, real browser payloads.

Every other test in this repository drives the application through in-process clients. That
proves the API layer but not the *served* system: the Jinja templates, the static console
bundle, the HTML routes and the subprocess boot path are all exercised here and only here.

The check is deliberately end-to-end and adversarial about its own claims:

  1. Boot `daedalus serve` as a genuinely separate process, exactly as an operator would.
  2. Drive a real run to a terminal state through the public HTTP API, with the model plane
     answered by a real loopback gateway (the transport is exercised, not mocked).
  3. Fetch every console page and assert HTTP 200 *and* that the DOM hooks the console
     JavaScript binds to are actually present. A 200 with a missing `#dag` element means the
     visualisation silently does nothing, which is worse than a 404.
  4. Fetch every read endpoint added for the console and assert it returns real data.

Exit code 0 means the whole path is live. Any assertion failure prints the exact failure.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from fake_gateway import FakeGateway, Reply, coder_reply, planner_reply  # noqa: E402


def intake_questions_reply() -> Reply:
    """A well-formed question set, shaped the way a competent model would answer."""
    return Reply(
        content=json.dumps(
            {
                "questions": [
                    {
                        "id": "q1",
                        "field": "target_paths",
                        "question": "这次允许 Agent 改哪些文件？",
                        "why": "边界决定越界检查在写入之前拦掉什么。",
                        "options": [
                            {"id": "o1", "label": f"只改 {TARGET}",
                             "effect": "边界最小，越界会在写入之前被拒绝",
                             "value": [TARGET]},
                            {"id": "o2", "label": "src 目录",
                             "effect": "边界放宽到一个目录",
                             "value": ["src/"]},
                        ],
                    },
                    {
                        "id": "q2",
                        "field": "test_command",
                        "question": "用什么命令判定这次改动是正确的？",
                        "why": "Tier-1 检查 11 会真的执行这条命令。",
                        "options": [
                            {"id": "o1", "label": TEST_COMMAND,
                             "effect": "跑 tests 目录", "value": TEST_COMMAND},
                            {"id": "o2", "label": "python3 -m pytest -q",
                             "effect": "跑整个仓库", "value": "python3 -m pytest -q"},
                        ],
                    },
                ]
            },
            ensure_ascii=False,
        )
    )


from daedalus.demo import (  # noqa: E402
    CORRECT_IMPLEMENTATION,
    KeywordReviewer,
    TARGET,
    TEST_COMMAND,
    _prepare_repo,
)

FAKE_KEY = "live-check-key"
CONSOLE_JS = REPO_ROOT / "src" / "daedalus" / "service" / "static" / "console.js"

CONFIG_TEMPLATE = """\
[workspace]
root = "{workspace}"
target_branch = "main"

[quota]
max_parallel_steps = 2

[service]
host = "127.0.0.1"
port = {port}
max_concurrent_runs = 2

[policy]
manual_review_levels = ["critical"]

[model]
default_role = "coder"

[model.planner]
base_url = "http://127.0.0.1:{gateway_port}/v1"
model = "fake-gpt"
api_key_env = "DAEDALUS_LIVE_KEY"

[model.coder]
base_url = "http://127.0.0.1:{gateway_port}/v1"
model = "fake-gpt"
api_key_env = "DAEDALUS_LIVE_KEY"

[model.reviewer]
base_url = "http://127.0.0.1:{gateway_port}/v1"
model = "fake-gpt"
api_key_env = "DAEDALUS_LIVE_KEY"
"""


class CheckFailure(AssertionError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)
    print(f"  ok  {message}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(url: str, *, method: str = "GET", payload: dict | None = None) -> tuple[int, str]:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def wait_for_health(base: str, process: subprocess.Popen, timeout: float = 45.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise CheckFailure(f"service exited early with code {process.returncode}")
        try:
            status, _ = request(f"{base}/api/health")
            if status == 200:
                return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.25)
    raise CheckFailure("service did not become healthy in time")


def responder(payload: dict) -> Reply:
    """Answer intake, planner, coder and reviewer requests from one local gateway.

    The planner prompt asks for the Tri-Spec shape by name, so that string is the honest
    discriminator; the coder prompt asks for an operation list.
    """
    prompt = "\n".join(str(m.get("content", "")) for m in payload.get("messages", []))
    if "You are a semantic risk reviewer inside a deterministic control plane." in prompt:
        subject_digest = next(
            line.removeprefix("SUBJECT_DIGEST: ")
            for line in prompt.splitlines()
            if line.startswith("SUBJECT_DIGEST: ")
        )
        review = json.loads(KeywordReviewer(vetoes=()).complete(
            prompt, subject_digest=subject_digest,
        ))
        if "FINAL GOAL audit" in prompt:
            summary = json.loads(
                prompt.split("## Deterministic gate summary\n", 1)[1]
                .split("\n\n## Changed files", 1)[0]
            )
            review["criterion_results"] = [
                {
                    "criterion_id": row["criterion_id"],
                    "status": "MET" if row["ok"] else "UNMET",
                    "evidence": f"{row['command']} exited with {row['exit_code']} "
                    "on the integrated commit.",
                }
                for row in summary["evidence"]["criteria"]
            ]
        return Reply(content=json.dumps(review))
    if "intake 环节" in prompt:
        # The discriminator is the intake prompt by name. Matching on "intake" alone also matched
        # the planner prompt, whose request id contains it, and fed the questions to the planner.
        return intake_questions_reply()
    if "spec_01_goal" in prompt:
        return planner_reply(node_ids=["N1"], tree=TARGET)
    return coder_reply(path=TARGET, content=CORRECT_IMPLEMENTATION)


def render_payloads(**payloads: dict) -> dict:
    """Run the console's render functions over real payloads, in Node, with a DOM stub."""
    node = shutil.which("node")
    if node is None:
        return {"failures": [], "steps": 0, "step_boxes": 0, "checks": 0, "skipped": "no node"}
    captured = Path(tempfile.gettempdir()) / "daedalus-render-payload.json"
    captured.write_text(json.dumps(payloads, indent=2))
    result = subprocess.run(
        [node, str(REPO_ROOT / "scripts" / "console_render_check.js"), str(CONSOLE_JS)],
        input=json.dumps(payloads),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode not in (0, 1):
        raise CheckFailure(
            f"the render check crashed:\n{result.stderr.strip()[:1500]}"
            f"\npayload kept at {captured}"
        )
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise CheckFailure(
            f"unreadable render report: {result.stdout[:300]} / {result.stderr[:800]}"
        ) from None


def main() -> int:
    port = free_port()
    gateway_port = free_port()
    root = Path(tempfile.mkdtemp(prefix="daedalus-live-"))
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    service: subprocess.Popen | None = None
    config_path = root / "daedalus.toml"
    log_path = root / "service.log"

    try:
        config_path.write_text(
            CONFIG_TEMPLATE.format(
                workspace=workspace, port=port, gateway_port=gateway_port
            )
        )
        gateway = FakeGateway(port=gateway_port, responder=responder)
        environment = {**os.environ, "DAEDALUS_LIVE_KEY": FAKE_KEY}

        with gateway:
            print(f"gateway on 127.0.0.1:{gateway_port}, service on 127.0.0.1:{port}")
            print(f"workspace {workspace}")
            log = log_path.open("w")
            service = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "daedalus",
                    "serve",
                    "--config",
                    str(config_path),
                ],
                cwd=str(REPO_ROOT),
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            base = f"http://127.0.0.1:{port}"
            wait_for_health(base, service)
            print("\n[1] service boot")
            check(True, "daedalus serve is healthy over HTTP")

            print("\n[2] console pages")
            pages = {
                # `/` is the intake: the front door, not a dashboard.
                "/": ('id="intake-start"',),
                "/runs": ('id="runs"',),
                "/operations": ('id="metrics-bars"',),
                "/escalations": (),
            }
            for path, markers in pages.items():
                status, body = request(f"{base}{path}")
                check(status == 200, f"GET {path} -> HTTP {status}")
                for marker in markers:
                    check(marker in body, f"{path} payload references {marker!r}")

            print("\n[3] static bundle")
            # Asset contents are exercised by the render check below; source names and
            # CSS classes are not a public contract.
            for asset in ("/static/console.js", "/static/console.css"):
                status, body = request(f"{base}{asset}")
                check(status == 200, f"GET {asset} -> HTTP {status}")
            # The console must not reach the network at runtime: a vendored renderer that is
            # actually served is what makes the audit diff work on an offline machine.
            for vendored in (
                "/static/vendor/diff2html.min.js",
                "/static/vendor/diff2html.min.css",
                "/static/vendor/inter-latin.woff2",
            ):
                status, _ = request(f"{base}{vendored}")
                check(status == 200, f"GET {vendored} -> HTTP {status}")

            print("\n[4] drive a real run to a terminal state")
            repo = _prepare_repo(root)
            status, body = request(
                f"{base}/api/runs",
                method="POST",
                payload={
                    "repo_path": str(repo),
                    "objective": "fix the word counter",
                    "target_paths": [TARGET],
                    "test_command": TEST_COMMAND,
                    "use_model": True,
                    "approve_spec_by": "live-check",
                },
            )
            check(status == 202, f"POST /api/runs -> HTTP {status}: {body[:200]}")
            receipt = json.loads(body)
            run_id = receipt["run_id"]
            print(f"      run {run_id} accepted")

            terminal = {
                "COMPLETED",
                "PARTIAL_FAILURE",
                "FAILED",
                "CANCELLED",
            }
            status_text = ""
            deadline = time.time() + 180
            while time.time() < deadline:
                code, body = request(f"{base}/api/runs/{run_id}")
                if code != 200:
                    raise CheckFailure(f"GET /api/runs/{run_id} -> HTTP {code}: {body[:200]}")
                view = json.loads(body)
                status_text = view["run"]["status"]
                if status_text in terminal or status_text == "AWAITING_APPROVAL":
                    break
                time.sleep(0.5)
            check(status_text == "COMPLETED", f"run reached a terminal state ({status_text})")
            check(
                len(gateway.requests) >= 2,
                f"the model plane was really exercised ({len(gateway.requests)} calls)",
            )

            print("\n[5] console read endpoints return real data")
            _, body = request(f"{base}/api/runs/{run_id}/plan")
            plan = json.loads(body)
            check(len(plan.get("nodes", [])) >= 1, "GET /plan returns the DAG nodes")
            check(
                all("state" in node for node in plan["nodes"]),
                "every plan node carries a visualisable state",
            )

            view = json.loads(request(f"{base}/api/runs/{run_id}")[1])
            check(len(view.get("steps", [])) >= 1, "the run view lists steps")
            step = view["steps"][0]
            checks = [
                check_row
                for listed in view["steps"]
                for gate in listed["gates"]
                for check_row in gate["checks"]
            ]
            check(
                len(checks) >= 10,
                f"the run view carries the Tier-1 gate checks ({len(checks)} found)",
            )
            names = {str(row["name"]) for row in checks}
            check(
                "01_path_whitelist" in names and "12_secret_content" in names,
                "the Tier-1 checks include the boundary and secret scans",
            )

            digest = view["run"]["spec_digest"]
            status, body = request(f"{base}/api/specs/{digest}")
            check(status == 200, f"GET /api/specs/<digest> -> HTTP {status}")
            check("spec_01_goal" in body, "the spec view returns the Tri-Spec document")

            step_id = step["step_id"]
            status, body = request(f"{base}/api/runs/{run_id}/steps/{step_id}/patch")
            check(status == 200, f"GET .../patch -> HTTP {status}")
            patch = json.loads(body)
            check(bool(patch.get("patch")), "the patch endpoint returns a non-empty diff")
            check(
                bool(patch.get("changed_files")),
                f"the patch endpoint names the changed files ({patch.get('changed_files')})",
            )

            status, body = request(f"{base}/api/runs/{run_id}/steps/{step_id}/log")
            check(status == 200, f"GET .../log -> HTTP {status}")
            log = json.loads(body)
            check(
                log["reference"].startswith("audit://") and bool(log["entries"]),
                f"the artifact's execution_log_ref resolves ({len(log.get('entries', []))} rows)",
            )

            status, body = request(f"{base}/api/runs/{run_id}/export?fmt=jsonl")
            check(status == 200, f"GET .../export?fmt=jsonl -> HTTP {status}")
            check(len(body.strip().splitlines()) >= 5, "the audit export has event rows")

            status, body = request(f"{base}/api/runs/{run_id}/export?fmt=csv")
            check(status == 200, f"GET .../export?fmt=csv -> HTTP {status}")
            check(body.splitlines()[0].startswith("event_id") or "," in body.splitlines()[0],
                  "the CSV export carries a header row")

            status, body = request(f"{base}/api/runs/{run_id}/timeline")
            check(status == 200, f"GET .../timeline -> HTTP {status}")

            for path, key in (
                ("/api/owners", "owners"),
                ("/api/executions", "executions"),
                ("/api/workers", "workers"),
            ):
                status, body = request(f"{base}{path}")
                check(status == 200, f"GET {path} -> HTTP {status}")
                payload = json.loads(body)
                check(key in payload, f"{path} returns a {key!r} collection")
            ownership = json.loads(request(f"{base}/api/owners")[1])
            check(
                "enforced" in ownership and "note" in ownership,
                "the owners endpoint states whether approvals are verified",
            )
            executions = json.loads(request(f"{base}/api/executions")[1])["executions"]
            check(
                any(row["run_id"] == run_id for row in executions),
                "the run under test has an executions row (§19)",
            )
            workers = json.loads(request(f"{base}/api/workers")[1])["workers"]
            check(bool(workers), "the worker registry records who executed the work")

            status, body = request(f"{base}/api/isolation")
            check(status == 200, f"GET /api/isolation -> HTTP {status}")
            isolation = json.loads(body)
            check(bool(isolation.get("selected")), "the isolation report names the selected driver")
            check(
                len(isolation.get("drivers", [])) >= 2,
                "the isolation report carries a probe result per driver",
            )
            check(
                all("available" in driver for driver in isolation["drivers"]),
                "every driver reports whether it was actually available",
            )
            check(bool(isolation.get("gaps")), "the isolation report names its own gaps")

            status, body = request(f"{base}/api/metrics")
            check(status == 200, f"GET /api/metrics -> HTTP {status}")
            metrics = json.loads(body)
            check(len(metrics) >= 4, f"the metrics projection carries {len(metrics)} keys")

            print("[6] the three modules render their own hooks")
            for path, markers in (
                (
                    f"/execution/{run_id}",
                    ("id=\"run-stats\"", "id=\"lane\"", "id=\"lane-track\"",
                     "id=\"step-panel\"", "id=\"step-actions\"", "id=\"step-body\"",
                     "id=\"escalation-body\""),
                ),
                (
                    f"/planning/{run_id}",
                    ("id=\"spec-cards\"", "id=\"spec-approval\"", "id=\"spec-registry\""),
                ),
                (
                    f"/audit/{run_id}",
                    ("id=\"audit-main\"", "id=\"diff\"", "id=\"diff-step\"",
                     "id=\"diff-mode\"", "id=\"events\"", "id=\"export-jsonl\""),
                ),
            ):
                status, body = request(f"{base}{path}")
                check(status == 200, f"GET {path} -> HTTP {status}")
                for marker in markers:
                    check(marker in body, f"{path} contains {marker}")
            redirected, _ = request(f"{base}/runs/{run_id}")
            check(redirected in {200, 307}, f"the old run URL still resolves (HTTP {redirected})")

            print("\n[6a] the model endpoint panel")
            code, body = request(f"{base}/api/model")
            check(code == 200, f"GET /api/model -> HTTP {code}")
            report = json.loads(body)
            check(bool(report["roles"]), "the model panel reports the configured roles")
            check(all(row["source"] for row in report["roles"]),
                  "and where each endpoint's value came from")
            check(report["persisted"] is False,
                  "and states that a console-set endpoint is not persisted")
            # A dead endpoint must be reported, not raised, and must not install anything.
            code, body = request(
                f"{base}/api/model/test",
                method="POST",
                payload={"base_url": "http://127.0.0.1:9/v1", "model": "nope",
                         "timeout_sec": 5},
            )
            check(code == 200, f"POST /api/model/test (dead) -> HTTP {code}")
            probe = json.loads(body)
            check(probe["ok"] is False and bool(probe["error"]),
                  "an unreachable endpoint reports why instead of raising")
            check(json.loads(request(f"{base}/api/model")[1])["override"] is None,
                  "a failed probe installs nothing")
            # A remote endpoint is refused until acknowledged, because it sends the repository
            # off the machine on every call.
            code, body = request(
                f"{base}/api/model",
                method="POST",
                payload={"base_url": "https://api.example.com/v1", "model": "m",
                         "api_key": "k"},
            )
            check(code == 422, f"an unacknowledged remote endpoint -> HTTP {code}")
            check(json.loads(request(f"{base}/api/model")[1])["override"] is None,
                  "an unacknowledged remote endpoint leaves the model unchanged")
            # The gateway the live check runs on is itself a reachable OpenAI-compatible
            # endpoint, so the panel can be exercised for real without another dependency.
            code, body = request(
                f"{base}/api/model",
                method="POST",
                payload={"base_url": f"http://127.0.0.1:{gateway_port}/v1",
                         "model": "fake-gpt", "api_key": FAKE_KEY, "timeout_sec": 60},
            )
            check(code == 200, f"POST /api/model (loopback) -> HTTP {code}: {body[:200]}")
            applied = json.loads(body)
            check(applied["override"] is not None, "the override is in force")
            check(FAKE_KEY not in body, "the key must never come back from the endpoint")
            code, body = request(f"{base}/api/model/test",
                                 method="POST",
                                 payload={"base_url": f"http://127.0.0.1:{gateway_port}/v1",
                                          "model": "fake-gpt", "api_key": FAKE_KEY,
                                          "timeout_sec": 60})
            check(code == 200 and json.loads(body)["ok"] is True,
                  f"a real call to the override succeeds: {body[:200]}")
            code, body = request(f"{base}/api/model", method="DELETE")
            check(code == 200 and json.loads(body)["override"] is None,
                  "and clearing it returns to the configured endpoint")

            print("\n[6b] the intake: task -> model questions -> answers -> spec")
            started = request(
                f"{base}/api/intakes",
                method="POST",
                payload={
                    "repo_path": str(repo),
                    "objective": "把 summarize() 的字数统计改成按空白切分",
                },
            )
            check(started[0] == 201, f"POST /api/intakes -> HTTP {started[0]}: {started[1][:200]}")
            intake = json.loads(started[1])["intake"]
            check(bool(intake["questions"]),
                  f"the model asked {len(intake['questions'])} question(s)")
            for question in intake["questions"]:
                check(len(question["options"]) >= 2,
                      f"question {question['id']} is a choice, not a statement")
                check(question["field_spec"].startswith("SPEC-"),
                      f"question {question['id']} names the spec it decides")
            for question in intake["questions"]:
                code, body = request(
                    f"{base}/api/intakes/{intake['intake_id']}/answers",
                    method="POST",
                    payload={"question_id": question["id"],
                             "option_id": question["options"][0]["id"]},
                )
                check(code == 200, f"answering {question['id']} -> HTTP {code}: {body[:160]}")
            check(json.loads(body)["intake"]["status"] == "DERIVED",
                  "answering every question moves the intake to DERIVED")
            code, body = request(f"{base}/api/intakes/{intake['intake_id']}/spec", method="POST")
            check(code == 200, f"POST .../spec -> HTTP {code}: {body[:200]}")
            derived = json.loads(body)
            check(bool(derived["spec_digest"]), "the derived spec has a digest")
            check(len(derived["specs"]) == 4, "the review screen has all four spec cards")
            frozen = request(
                f"{base}/api/intakes/{intake['intake_id']}/freeze",
                method="POST",
                payload={"spec_digest": derived["spec_digest"]},
            )
            check(frozen[0] == 202, f"POST .../freeze -> HTTP {frozen[0]}: {frozen[1][:200]}")
            check(bool(json.loads(frozen[1])["run_id"]), "freezing produced a run")

            print("\n[7] execute the console render functions on real payloads")
            specs_payload = json.loads(request(f"{base}/api/runs/{run_id}/specs")[1])
            check(
                len(specs_payload.get("specs", [])) == 4,
                "GET /api/runs/<id>/specs returns one card per spec",
            )
            score_payload = json.loads(request(f"{base}/api/runs/{run_id}/score")[1])
            check(
                bool(score_payload.get("components")),
                "GET /api/runs/<id>/score explains the score with its components",
            )
            check(
                bool(step.get("result_commit")),
                "the run view names the commit a step produced, so 重现 has a commit to name",
            )
            render_report = render_payloads(
                # The *answered* session: the review state has nothing to show otherwise, and
                # passing the pre-answer copy asserted against a session no operator ever sees.
                intake=derived["intake"],
                intake_specs=derived["specs"],
                intake_repos=json.loads(request(f"{base}/api/repos")[1])["repos"],
                model=json.loads(request(f"{base}/api/model")[1]),
                detail=view,
                route=json.loads(request(f"{base}/api/runs/{run_id}/route")[1]),
                patch=json.loads(
                    request(f"{base}/api/runs/{run_id}/steps/{step_id}/patch")[1]
                ),
                gate=next(
                    gate
                    for listed in view["steps"]
                    for gate in listed["gates"]
                    if gate["checks"]
                ),
                specs=specs_payload,
                registry=json.loads(request(f"{base}/api/specs")[1]),
                score=score_payload,
                metrics=json.loads(request(f"{base}/api/metrics")[1]),
                owners=json.loads(request(f"{base}/api/owners")[1]),
                executions=json.loads(request(f"{base}/api/executions")[1]),
                workers=json.loads(request(f"{base}/api/workers")[1]),
                audit=json.loads(request(f"{base}/api/runs/{run_id}/audit")[1]),
                audit_trail=[
                    json.loads(line)
                    for line in request(f"{base}/api/runs/{run_id}/export?fmt=jsonl")[1]
                    .strip().splitlines()
                    if line
                ],
            )
            if render_report.get("skipped"):
                # Say so rather than reporting a pass the check did not earn: the render functions
                # are the point of this section, and a machine without Node has not run them.
                print(f"      SKIPPED: {render_report['skipped']}")
            else:
                check(
                    render_report["failures"] == [],
                    "the console renders the live payload without a failed assertion"
                    + (f": {render_report['failures']}" if render_report["failures"] else ""),
                )
                check(
                    render_report.get("diff2html") is True,
                    "the audit diff is rendered by the vendored diff2html bundle",
                )
                check(
                    render_report["step_boxes"] == render_report["steps"] >= 1,
                    f"执行 drew {render_report['step_boxes']} box(es) for "
                    f"{render_report['steps']} step(s)",
                )
                check(
                    render_report["spec_cards"] == 4,
                    "规划 rendered all four spec cards",
                )
                check(
                    render_report["score_components"] >= 5,
                    f"审计 rendered the score's {render_report['score_components']} components",
                )
                check(
                    render_report["checks"] == len(checks),
                    f"审计 rendered {render_report['checks']} Tier-1 gate check(s)",
                )
                check(render_report["model_roles"] >= 1,
                      "模型 rendered the endpoint panel")
                check(
                    render_report["intake_questions"] >= 1
                    and render_report["intake_options"] >= 2,
                    f"提任务 rendered {render_report['intake_questions']} question(s) with "
                    f"{render_report['intake_options']} option(s) each",
                )


        print("\nall live checks passed")
        return 0
    except CheckFailure as failure:
        print(f"\nLIVE CHECK FAILED: {failure}")
        if log_path.exists():
            print("--- service log tail ---")
            print("\n".join(log_path.read_text().splitlines()[-30:]))
        return 1
    except Exception as error:  # noqa: BLE001 - the check reports, it does not crash
        print(f"\nLIVE CHECK CRASHED: {type(error).__name__}: {error}")
        if log_path.exists():
            print("--- service log tail ---")
            print("\n".join(log_path.read_text().splitlines()[-30:]))
        return 1
    finally:
        if service is not None and service.poll() is None:
            service.terminate()
            try:
                service.wait(timeout=10)
            except subprocess.TimeoutExpired:
                service.kill()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

