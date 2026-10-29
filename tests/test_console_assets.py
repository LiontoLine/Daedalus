"""The console's static wiring (Spec §10, §15).

The console has no build step, which is the right deployment trade-off but also means
nothing verifies it. A renamed element id, a typo in an `api()` path or a template that
forgets a panel produces no Python error at all: the page still returns HTTP 200 and the
visualisation silently does nothing. That failure mode is worse than a crash, so it is
tested here.

The checks are deliberately static and hermetic — no browser, no Node dependency at test
time. They verify the three things that actually break:

* every DOM id the script queries is rendered by a template or created by the script;
* every API path the script calls corresponds to a route the application registers;
* every page that hosts a panel loads the assets that panel needs.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

SERVICE = Path(__file__).resolve().parent.parent / "src" / "daedalus" / "service"
CONSOLE_JS = SERVICE / "static" / "console.js"
CONSOLE_CSS = SERVICE / "static" / "console.css"
TEMPLATES = SERVICE / "templates"
APP = SERVICE / "app.py"

_SELECTOR = re.compile(r'\$\("#([A-Za-z0-9_-]+)"')
_HTML_ID = re.compile(r'id="([A-Za-z0-9_-]+)"')
_ROUTE = re.compile(r'@app\.(?:get|post)\("([^"]+)"')
#: `api(`/api/runs/${x}/plan`)` -> `/api/runs/{}/plan`
_JS_CALL = re.compile(r"api\(\s*`([^`]+)`")
_TEMPLATE_INTERPOLATION = re.compile(r"\$\{[^}]*\}")
#: The helpers that turn a server value into markup *and* escape it. Each is asserted below to
#: actually escape, because this list is what lets an interpolation past the scan: adding a name
#: here without the assertion would be a way to smuggle an unescaped field through the one test
#: that guards against it.
_SANITIZERS = re.compile(r"(?:escapeHtml|pill|shortDigest|hashCell)\s*\(")


def _js() -> str:
    return CONSOLE_JS.read_text()


def _templates() -> dict[str, str]:
    raw = {path.name: path.read_text() for path in sorted(TEMPLATES.glob("*.html"))}
    def expand(name):
        text = raw[name]
        if text.strip() == '{% extends "workflow.html" %}':
            return expand("workflow.html")
        return re.sub(r'{% include "([^"]+)" %}', lambda match: expand(match.group(1)), text)
    return {name: expand(name) for name in raw}


def _all_template_ids() -> set[str]:
    found: set[str] = set()
    for text in _templates().values():
        found.update(_HTML_ID.findall(text))
    return found


def _normalise(path: str) -> str:
    """`/api/runs/${x}/plan` and `/api/runs/{run_id}/plan` are the same route."""
    path = path.split("?", 1)[0]
    path = _TEMPLATE_INTERPOLATION.sub("{}", path)
    path = re.sub(r"\{[^}]*\}", "{}", path)
    return path.rstrip("/") or "/"


def test_every_queried_element_is_rendered_somewhere() -> None:
    """A selector with no matching element is a silent no-op in the browser."""
    script = _js()
    selectors = set(_SELECTOR.findall(script))
    assert selectors, "the console script should query at least one element"
    # Ids the script builds itself (template literals for injected rows) count as rendered.
    available = _all_template_ids() | set(_HTML_ID.findall(script))
    missing = sorted(selectors - available)
    assert not missing, f"console.js queries element ids no template renders: {missing}"


def test_every_api_call_matches_a_registered_route(tmp_path) -> None:
    """A fetch to a path the app does not serve is a 404 the user sees as a broken panel."""
    from fastapi.testclient import TestClient
    from daedalus.config import Settings, WorkspaceSettings
    from daedalus.service.app import create_app

    with TestClient(create_app(Settings(
        workspace=WorkspaceSettings(root=str(tmp_path / "route-check"))
    ))) as client:
        routes = {_normalise(path) for path in client.get("/openapi.json").json()["paths"]}
    calls = {
        _normalise(path)
        for path in _JS_CALL.findall(_js())
        if path.startswith("/api")
    }
    assert calls, "the console script should call at least one API route"
    unmatched = sorted(call for call in calls if call not in routes)
    assert not unmatched, f"console.js calls routes the service does not register: {unmatched}"


def test_the_console_workspace_and_evidence_views_have_their_panels() -> None:
    """Each module answers one question and hosts exactly the panels it fills.

    Splitting them is the point: the old single run page mixed the frozen contract, the live
    graph and the audit trail, so an operator reading it could not tell which of the three
    they were looking at. The intake is now the landing page, because starting work should not
    require finding a dashboard first.

    The panels below are the ones the script actually fills. This test is the only thing that
    notices when a panel id is renamed in a template but not in the script — the page still
    returns 200 and goes silently blank.
    """
    templates = _templates()
    assert {"intake.html", "planning.html", "execution.html", "audit.html"} <= set(templates)

    # 提任务: one task field, clickable repositories, and three states of the same page.
    intake = templates["intake.html"] + templates["base.html"]
    for panel in ("intake-objective", "intake-repos", "intake-repo-path", "intake-start",
                  "intake-step-task", "intake-step-questions", "intake-step-review",
                  "intake-progress", "intake-question", "intake-options", "intake-rejections",
                  "intake-document", "intake-answers", "intake-freeze", "intake-recent",
                  # 模型接口: the disclosure that lets the endpoint be changed without a restart
                  "model-panel", "model-summary", "model-current", "model-form", "model-base-url",
                  "model-name", "model-key", "model-timeout", "model-role", "model-ack-wrap",
                  "model-ack", "model-test", "model-save", "model-reset", "model-out",
                  "model-caveat"):
        assert f'id="{panel}"' in intake, f"intake must render #{panel}"

    # 规划: a summary per spec, expandable to the whole document, plus the registry and the
    # approval record that froze it.
    planning = templates["planning.html"]
    for panel in ("spec-cards", "spec-approval", "spec-registry"):
        assert f'id="{panel}"' in planning, f"planning must render #{panel}"

    # 执行: the left-to-right route, one box per step, plus the detail panel that opens from a
    # box and the decisions a parked step needs.
    execution = templates["execution.html"]
    for panel in ("run-picker", "run-stats", "lane", "lane-track", "route-notes",
                  "step-panel", "step-title", "step-actions", "step-body",
                  "escalation-panel", "escalation-body",
                  "graph-fit", "graph-zoom-in", "graph-zoom-out", "focus-step",
                  "inspector-tabs", "inspector-scroll", "workspace-activity"):
        assert f'id="{panel}"' in execution, f"execution must render #{panel}"

    # 审计: the patch, the score that summarises the evidence, the §27 answer and the log.
    audit = templates["audit.html"]
    for panel in ("run-picker", "audit-main", "diff", "diff-summary", "diff-step",
                  "diff-mode", "audit", "events", "identity-out", "export-jsonl",
                  "export-csv"):
        assert f'id="{panel}"' in audit, f"audit must render #{panel}"


def test_navigation_keeps_the_current_task_context() -> None:
    templates = _templates()
    workflow = templates["workflow.html"]
    for stage in ("task", "plan", "execute", "audit"):
        assert f'href="#flow-{stage}"' in workflow
        assert f'id="flow-{stage}"' in workflow
    assert 'href="/runs"' in templates["base.html"]
    assert "openWorkflowRun" in _js()
    assert "if (isWorkflow()) await openWorkflowRun(payload.run_id" in _js()
    for name in ("intake", "planning", "execution", "audit"):
        assert templates[name + ".html"] == workflow


def test_the_run_list_presents_the_modules() -> None:
    board = _templates()["board.html"]
    for module in ("planning", "execution", "audit"):
        assert f'href="/{module}/${{id}}"' in _js(), f"task cards must link to their own {module}"
    for panel in ("task-cards", "board-search", "board-filter", "task-summary"):
        assert f'id="{panel}"' in board
    assert 'id="runs"' in board
    assert 'id="metrics-bars"' in board


def test_every_page_loads_the_console_assets() -> None:
    for name, text in _templates().items():
        if name == "base.html" or name.startswith("_"):
            continue
        assert "/static/console.js" in text or "{% extends" in text, f"{name} loads no script"


def test_every_local_asset_reference_resolves_to_a_file() -> None:
    """A renamed stylesheet must fail the build, not produce an unstyled page."""
    referenced: set[str] = set()
    for text in _templates().values():
        referenced.update(re.findall(r'(?:src|href)="(/static/[^"]+)"', text))
    assert referenced, "the templates should reference at least one static asset"
    for reference in sorted(referenced):
        target = SERVICE / reference.split("?", 1)[0].lstrip("/")
        assert target.is_file(), f"{reference} is referenced but {target} does not exist"


def test_the_gate_check_styles_the_console_relies_on_exist() -> None:
    """The panels are only legible if the classes they use are actually defined.

    Each of these carries meaning rather than decoration: a missing `.lane-node` leaves the route
    unclickable, a missing `.check-fail` hides a failing Tier-1 check, and a missing `.diff-add`
    makes an added line indistinguishable from a removed one. `diff2html`'s own classes are themed
    under `.diff-host`, so a missing `.diff-host` rule is what makes vendored diffs unreadable.
    """
    css = CONSOLE_CSS.read_text()
    for selector in (
        ".check", ".check-fail", ".check-pass",
        ".lane-svg", ".lane-node", ".lane-edge", ".lane-track", ".lane-state",
        ".stat", ".stats", ".seg", ".action", ".pill", ".chip",
        ".diff-host", ".diff-add", ".diff-del",
        ".score-ring", ".score-part", ".part-bar", ".score-note",
        ".spec-card", ".spec-cards", ".spec-head", ".spec-body", ".doc-kv",
        ".metric-row", ".escalation", ".callout",
        ".repo-card", ".option-card", ".option-key", ".intake-note", ".intake-progress",
        ".answer-row", ".intake-answers", ".model-row", ".model-fact", ".model-locality",
        ".model-grid", ".model-ack",
    ):
        assert selector in css, f"console.css must define {selector}"


def test_every_page_a_template_renders_has_an_initialiser() -> None:
    """The one check that would have caught the intake page running no JavaScript at all.

    The boot block dispatched planning/execution/audit and fell through to `initBoard()` for
    everything else, so the intake's buttons, repository cards and model panel were dead in a
    browser. Every other test passed: the ids existed, the routes matched, the render functions
    executed when called directly — none of them asked whether the page's own initialiser had
    been *reached*. This does, statically, by comparing the pages the templates declare against
    the pages the boot table names.
    """
    script = _js()
    table = script.split("const PAGE_INITIALISERS = {", 1)
    assert len(table) == 2, "the console must dispatch pages through one table"
    registered = set(re.findall(r"^\s{2}([a-z]+):", table[1].split("};", 1)[0], re.M))
    assert registered, "the dispatch table must name at least one page"

    # The page name is chosen by the route, not written in the template, so `app.py` is the
    # authoritative list of pages that can reach a browser.
    declared = set(re.findall(r'page="([a-z]+)"', APP.read_text()))
    declared |= {
        match
        for text in _templates().values()
        for match in re.findall(r'page="([a-z]+)"', text)
    }
    assert declared, "the routes should declare at least one page"
    missing = sorted(declared - registered)
    assert not missing, (
        f"these pages are rendered by a template but have no initialiser in the boot table, "
        f"so their scripts never run: {missing}"
    )


@pytest.mark.skipif(shutil.which("node") is None, reason="no JavaScript engine available")
def test_the_console_script_parses() -> None:
    """A syntax error in the console bundle breaks every page at once."""
    result = subprocess.run(
        ["node", "--check", str(CONSOLE_JS)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"console.js failed to parse:\n{result.stderr}"


RENDER_CHECK = Path(__file__).resolve().parent.parent / "scripts" / "console_render_check.js"


class _ScriptedIntakeModel:
    """A model that answers the intake prompt with questions and the planner prompt with a spec.

    The discriminator is the intake system prompt by name, not a substring: matching on "intake"
    alone fed the questions payload to the planner once, because the intake's request id contains
    `intake`. The same mistake produced a confusing failure in the demo, so it is spelled out.
    """

    name = "scripted-intake"
    model = "scripted"
    base_url = "http://127.0.0.1:1/v1"

    def complete(self, messages, *, temperature=0.0, max_tokens=4096,
                 response_format_json=False):
        from daedalus.model.base import Completion
        from tests.conftest import TARGET, TEST_COMMAND

        prompt = "\n".join(getattr(m, "content", "") for m in messages)
        if "intake 环节" in prompt:
            payload = {
                "questions": [
                    {
                        "id": "q1",
                        "field": "target_paths",
                        "question": "这次允许 Agent 改哪些文件？",
                        "why": "边界决定越界检查在写入之前拦掉什么",
                        "options": [
                            {"id": "o1", "label": "只改 textstats.py",
                             "effect": "边界最小", "value": [TARGET]},
                            {"id": "o2", "label": "src 目录",
                             "effect": "边界放宽到一个目录", "value": ["src/"]},
                        ],
                    },
                    {
                        "id": "q2",
                        "field": "test_command",
                        "question": "用什么命令判定改动正确？",
                        "why": "Tier-1 检查 11 会真的执行它",
                        "options": [
                            {"id": "o1", "label": TEST_COMMAND,
                             "effect": "跑测试目录", "value": TEST_COMMAND},
                            {"id": "o2", "label": "python3 -m pytest -q",
                             "effect": "跑整个仓库", "value": "python3 -m pytest -q"},
                        ],
                    },
                ]
            }
        else:
            from tests.fake_gateway import planner_reply

            payload = json.loads(planner_reply(node_ids=["N1"], tree=TARGET).content)
        return Completion(
            text=json.dumps(payload, ensure_ascii=False),
            model=self.model,
            prompt_tokens=10,
            completion_tokens=10,
            stopped_reason="stop",
        )


def _live_payloads(workspace: Path) -> dict:
    """Run one real run through the service and collect what the console would fetch.

    The payload keys mirror the three modules: 执行 fetches the run detail and its route, 规划
    fetches the four spec cards, 审计 fetches the score, the patch and the log. Collecting them
    from one real run means the render check runs against shapes the service actually produces
    rather than against a hand-written fixture that can drift from it.
    """
    from fastapi.testclient import TestClient

    from daedalus.application.coding_worker import FileOp, ScriptedWorker
    from daedalus.application.intake import ModelQuestioner
    from daedalus.application.planner import ModelPlanner
    from daedalus.config import load_settings
    from daedalus.infrastructure.git_sandbox import init_repo, initial_commit
    from daedalus.service.app import create_app
    from tests.conftest import CORRECT_IMPLEMENTATION, DEMO_PROJECT, TARGET, TEST_COMMAND

    repo = init_repo(workspace / "repo")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".DS_Store")
    shutil.copytree(DEMO_PROJECT / "src", repo / "src", ignore=ignore)
    shutil.copytree(DEMO_PROJECT / "tests", repo / "tests", ignore=ignore)
    shutil.copy2(DEMO_PROJECT / "pyproject.toml", repo / "pyproject.toml")
    shutil.copy2(DEMO_PROJECT / ".gitignore", repo / ".gitignore")
    initial_commit(repo, "chore: import the demo project")

    # A configured model, because that is what a deployment has and because the model panel has
    # nothing to report without one. The credential env var is deliberately left unset so the
    # "variable is missing" path is exercised too — it is the most common reason a call fails.
    config = workspace / "daedalus.toml"
    config.write_text(
        f'[workspace]\nroot = "{workspace / "ws"}"\n'
        "[model]\ndefault_role = \"planner\"\n"
        "[model.planner]\n"
        'base_url = "http://127.0.0.1:11434/v1"\n'
        'model = "console-check-model"\n'
        'api_key_env = "DAEDALUS_CONSOLE_CHECK_KEY"\n'
    )
    settings = load_settings(str(config), workspace_root=str(workspace / "ws"))
    app = create_app(settings)
    with TestClient(app) as client:
        app.state.daedalus.build_worker = lambda **_: (  # type: ignore[assignment]
            ScriptedWorker(
                ops=(FileOp(op="write", path=TARGET, content=CORRECT_IMPLEMENTATION),),
                worker_id="console-check",
            ),
            None,
        )
        created = client.post(
            "/api/runs",
            json={
                "repo_path": str(repo),
                "objective": "fix the word counter",
                "target_paths": [TARGET],
                "test_command": TEST_COMMAND,
            },
        )
        assert created.status_code == 202, created.text
        run_id = created.json()["run_id"]
        deadline = time.time() + 60
        view = client.get(f"/api/runs/{run_id}").json()
        while view["run"]["status"] not in {
            "COMPLETED", "FAILED", "CANCELLED", "PARTIAL_FAILURE"
        } and time.time() < deadline:
            time.sleep(0.1)
            view = client.get(f"/api/runs/{run_id}").json()
        assert view["run"]["status"] == "COMPLETED", view["run"]["status"]
        step_id = view["steps"][0]["step_id"]
        gate = next(
            gate for listed in view["steps"] for gate in listed["gates"] if gate["checks"]
        )
        # The render check must not be vacuous: a fixture without a commit or a score would let
        # the replay and score assertions pass without exercising anything.
        assert view["steps"][0]["result_commit"], "the demo run must record a result commit"
        score = client.get(f"/api/runs/{run_id}/score").json()
        assert score["components"], "the audit score must explain itself"

        # The intake: drive one through the same service, scripted questions and all, so the
        # front door is exercised by the render check and not only by its own unit tests.
        scripting = _ScriptedIntakeModel()
        app.state.daedalus.build_model_client = lambda role="": scripting  # type: ignore[assignment]
        app.state.daedalus.intake.questioner_factory = lambda: ModelQuestioner(client=scripting)
        app.state.daedalus.intake.planner_factory = lambda: ModelPlanner(
            client=scripting, require_model=True
        )
        started = client.post(
            "/api/intakes",
            json={"repo_path": str(repo), "objective": "把 summarize() 改成按空白切分"},
        )
        assert started.status_code == 201, started.text
        intake = started.json()["intake"]
        for question in intake["questions"]:
            answered = client.post(
                f"/api/intakes/{intake['intake_id']}/answers",
                json={"question_id": question["id"], "option_id": question["options"][0]["id"]},
            )
            assert answered.status_code == 200, answered.text
        intake = answered.json()["intake"]
        derived = client.post(f"/api/intakes/{intake['intake_id']}/spec")
        assert derived.status_code == 200, derived.text

        from tests.test_independent_validation import make_validation_run
        state = app.state.daedalus
        state.identity.environ = {"TEST_OWNER": "test-only-owner-secret-for-validation",
                                  "TEST_REVIEWER": "test-only-reviewer-secret-for-validation"}
        validation_repo = init_repo(workspace / "validation-repo")
        shutil.copytree(DEMO_PROJECT / "src", validation_repo / "src", ignore=ignore)
        shutil.copytree(DEMO_PROJECT / "tests", validation_repo / "tests", ignore=ignore)
        shutil.copy2(DEMO_PROJECT / "pyproject.toml", validation_repo / "pyproject.toml")
        shutil.copy2(DEMO_PROJECT / ".gitignore", validation_repo / ".gitignore")
        initial_commit(validation_repo, "initialize independent review render fixture")
        high_owner, validation_service, _ = make_validation_run(validation_repo, workspace,
            natural=True, store=state.store, identity=state.identity)
        report = validation_service.evaluate(high_owner.run_id)
        validation_view = client.get(f"/api/runs/{high_owner.run_id}/validations").json()

        return {
            "validation_scenario": {
                "run": dict(state.store.get_run(high_owner.run_id)), "view": validation_view,
                "detail": client.get(f"/api/runs/{high_owner.run_id}").json(),
                "plan": client.get(f"/api/runs/{high_owner.run_id}/plan").json(),
                "route": client.get(f"/api/runs/{high_owner.run_id}/route").json(),
                "specs": client.get(f"/api/runs/{high_owner.run_id}/specs").json(),
                "audit": client.get(f"/api/runs/{high_owner.run_id}/audit").json(),
            },
            "intake": intake,
            "intake_specs": derived.json()["specs"],
            "intake_repos": client.get("/api/repos").json()["repos"],
            "model": client.get("/api/model").json(),
            "detail": view,
            "route": client.get(f"/api/runs/{run_id}/route").json(),
            "plan": client.get(f"/api/runs/{run_id}/plan").json(),
            "patch": client.get(f"/api/runs/{run_id}/steps/{step_id}/patch").json(),
            "gate": gate,
            "specs": client.get(f"/api/runs/{run_id}/specs").json(),
            "registry": client.get("/api/specs").json(),
            "score": score,
            "metrics": client.get("/api/metrics").json(),
            "owners": client.get("/api/owners").json(),
            "executions": client.get("/api/executions").json(),
            "workers": client.get("/api/workers").json(),
            "audit": client.get(f"/api/runs/{run_id}/audit").json(),
            "audit_trail": [
                json.loads(line)
                for line in client.get(f"/api/runs/{run_id}/export?fmt=jsonl")
                .text.strip().splitlines()
                if line
            ],
        }


@pytest.mark.skipif(shutil.which("node") is None, reason="no JavaScript engine available")
def test_the_console_renders_a_real_run_without_throwing(tmp_path: Path) -> None:
    """Execute the render functions over payloads the service actually produced.

    Parsing is not enough. `renderLane` referenced an element no template rendered for a while:
    the file parsed, the endpoint returned 200, the page rendered and the route never appeared,
    because the function threw the moment it ran. Only executing it catches that.

    The harness loads the vendored `diff2html` into the same context, so the audit diff is
    exercised through the bundle the browser actually runs — a corrupt vendored file fails here
    rather than producing a blank panel in front of an operator.
    """
    payloads = _live_payloads(tmp_path)
    result = subprocess.run(
        [shutil.which("node"), str(RENDER_CHECK), str(CONSOLE_JS)],
        input=json.dumps(payloads),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.stdout, f"the render check produced no report:\n{result.stderr}"
    report = json.loads(result.stdout)
    assert report["failures"] == [], report["failures"]
    assert result.returncode == 0, result.stderr
    assert report["diff2html"], "the vendored diff renderer must load"
    assert report["workflow_verified"], "the unified intake/planning/execution/audit flow must be exercised"
    assert report["steps"] >= 1, "the render check must exercise at least one step"
    assert report["step_boxes"] == report["steps"], "执行 draws exactly one box per step"
    assert report["checks"] >= 1, "the render check must exercise the Tier-1 checks"
    assert report["spec_cards"] == 4, "规划 must render all four specs"
    assert report["score_components"] >= 5, "审计 must render the score's components"
    assert report["diff_lines"] >= 1, "the render check must exercise the diff viewer"
    assert report["events"] >= 1, "the render check must exercise the event log"
    assert report["intake_questions"] >= 1, "the render check must exercise 提任务"
    assert report["intake_options"] >= 2, "and draw the options the operator clicks"
    assert report["intake_specs"] == 4, "and the four spec cards the review screen shows"
    assert report["model_roles"] >= 1, "the render check must exercise the model panel"
    assert report["executions"] >= 1, "the render check must exercise the §19 executions view"
    assert report["workers"] >= 1, "the render check must exercise the §19 workers view"


def test_the_console_never_trusts_server_text_as_markup() -> None:
    """Every server-derived text field is escaped at the point it becomes markup.

    The console renders model-authored summaries, gate reasons, changed-file paths and failure
    text. Those are untrusted strings, so an unescaped interpolation is a stored-XSS path from
    the model plane into the operator's browser.

    The check parses each `${...}` interpolation (tracking brace depth, so a nested template
    literal does not end it early) and requires that any expression mentioning an untrusted
    field is wrapped in a sanitizer. An earlier version matched only `escapeHtml(field)` exactly
    and so missed `escapeHtml(a || field || b)` — a false negative in the one test that guards
    this, which is worse than having no test.

    The rule it enforces is deliberately strict: **escape at the innermost interpolation, or do
    not interpolate.** A value escaped by an enclosing call is invisible to a reader of the
    inner expression, and the console's own history shows how easily that reasoning slips — so
    the code builds such strings by concatenation instead, which needs no escaping and leaves
    the check able to tell markup from text.
    """
    script = _js()
    # Every free-text field the console renders from a server payload. This list is the guard,
    # so it has to be complete: the first version omitted `changed_files`, and a deliberate
    # un-escaping of exactly that field passed the test.
    untrusted = (
        # run / spec
        "run.status", "run.run_id", "run.execution_id", "run.goal_id", "run.spec_digest",
        "run.base_commit", "run.branch", "run.correlation_id", "run.created_at",
        "spec.risk_level", "spec.approved_by", "spec.approved_at", "spec.approval_statement",
        "spec.approval_scheme", "spec.approval_role",
        # steps, gates, artifacts, approvals
        "step.node_id", "step.step_id", "step.state", "step.last_failure", "step.objective",
        "gate.decision", "gate.tier", "gate.confidence", "gate.reasons",
        "artifact.model", "artifact.status", "artifact.sandbox_image", "artifact.worker_id",
        "artifact.changed_files", "changed_files", "artifact.artifact_digest",
        "approval.approved_by", "approval.note", "approval.decision",
        # route nodes
        "node.objective", "node.label", "node.failure", "node.worker_id", "node.plan_node_id",
        "node.state", "node.detail", "node.cache_source", "node.actor", "node.started_at",
        "node.ended_at", "node.gate_tier1", "node.gate_tier2", "node.artifact_digest",
        "node.deps", "node.expected_artifacts", "node.node_id",
        # the plan / boundary / meta panels
        "goal.goal_id", "goal.objective", "goal.invariants", "goal.risk_level",
        "criterion.criterion_id", "criterion.kind", "criterion.command",
        "boundary.network_policy", "boundary.isolation", "boundary.fs_whitelist",
        "meta.protected_paths", "meta.human_approval_required",
        # the registry and the event trail
        "row.goal_id", "row.spec_digest", "row.approved_by", "row.risk_level",
        "row.event_type", "row.actor", "row.detail", "row.timestamp", "row.reference",
        # errors last. Bare generic names (`state`, `label`, `reason`) are deliberately absent:
        # they match derived locals and fixed lookup tables — `${ROUTE_FILL[state]}` renders a
        # hex colour, not the state name — and a check that cries wolf gets deleted. The
        # explicit `node.`/`step.`/`row.` paths above are what identify server text.
        "error.message",
    )
    # Only markup contexts matter. An interpolation that builds a URL, or that is assigned to
    # `textContent`, cannot inject HTML however the value is shaped — and the field list above
    # deliberately names fields that appear in both contexts, so the check has to tell them
    # apart rather than be relaxed until it passes.
    offenders = []
    for expression, offset in _interpolations(script):
        if not _mentions_untrusted(expression, untrusted):
            continue
        if _SANITIZERS.search(expression):
            continue
        # `textContent = ...` may span several lines, so the enclosing statement is the window
        # from a few lines back rather than only the line the interpolation sits on.
        line_start = script.rfind("\n", 0, offset) + 1
        window_start = script.rfind("\n", 0, line_start - 1)
        window_start = script.rfind("\n", 0, window_start) + 1 if window_start > 0 else 0
        line_end = script.find("\n", offset)
        statement = script[window_start : line_end if line_end > 0 else len(script)]
        if "textContent" in statement or "encodeURIComponent" in statement or "api(`" in statement:
            continue
        offenders.append(f"{expression.strip()[:60]}  ← {statement.strip()[:60]}")
    assert not offenders, (
        "these interpolations mention server text without escaping it:\n  "
        + "\n  ".join(offenders[:8])
    )

    # The sanitizers must exist and must actually escape.
    for helper in ("function escapeHtml(", "function pill(", "function hashCell("):
        assert helper in script, f"the console must define {helper}"
    pill_body = script.split("function pill(", 1)[1].split("\n}", 1)[0]
    assert "escapeHtml(" in pill_body, "pill() must escape the value it wraps"
    hash_body = script.split("function hashCell(", 1)[1].split("\n}", 1)[0]
    assert "escapeHtml(" in hash_body, "hashCell() must escape the digest it prints"

    # `kvHtml([["label", value], ...])` renders `value` as markup, so a row that passes raw
    # server text is a hole — and it is invisible to the interpolation scan above, because the
    # value is a plain expression rather than a `${}`. That is exactly how an unescaped
    # `changed_files` slipped through the first version of this test.
    row_offenders = [
        value.strip()[:70]
        for value in _kv_row_values(script)
        if _mentions_untrusted(value, untrusted) and not _SANITIZERS.search(value)
    ]
    assert not row_offenders, (
        "these kvHtml rows interpolate server text without escaping it: " + str(row_offenders)
    )


def _mentions_untrusted(source: str, untrusted: tuple[str, ...]) -> bool:
    """Whether `source` renders a server text field, ignoring comparisons.

    A comparison is not a render: `${steps.filter((s) => s.state === "COMMITTED").length}`
    interpolates a number, and the field name appears only as an operand. Both callers go
    through here so they cannot disagree about what counts.
    """
    comparable = re.sub(r"[^=!<>]*[=!]==?[^=!<>]*", "", source)
    comparable = re.sub(r"[^=!<>]*[=!]=\s*[^,)]*", "", comparable)
    return any(
        re.search(rf"(?<![\w.]){re.escape(field)}(?![\w])", comparable) for field in untrusted
    )


def _kv_row_values(script: str) -> list[str]:
    """The second element of every `["label", value]` pair, with nesting handled.

    Deliberately structural rather than a regex: a row value routinely contains commas, nested
    calls and its own array literals, so splitting on punctuation gets it wrong.
    """
    values: list[str] = []
    for match in re.finditer(r'\[\s*\n?\s*"', script):
        start = match.start()
        depth = 0
        cursor = start
        while cursor < len(script):
            character = script[cursor]
            if character in "[({":
                depth += 1
            elif character in "])}":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        pair = script[start : cursor + 1]
        if not pair.startswith("[") or "," not in pair:
            continue
        # Everything after the first top-level comma is the value expression.
        inner = pair
        index = 1
        depth = 0
        comma = -1
        while index < len(inner):
            character = inner[index]
            if character in "[({":
                depth += 1
            elif character in "])}":
                depth -= 1
            elif character == "," and depth == 0:
                comma = index
                break
            index += 1
        if comma < 0:
            continue
        label = inner[:comma]
        if not re.fullmatch(r'\[\s*"[^"]*"\s*', label):
            continue
        values.append(inner[comma + 1 : -1])
    return values


def _interpolations(script: str) -> list[tuple[str, int]]:
    """Every `${...}` expression in the script, with nested braces handled.

    Returns each expression with its offset, so the caller can look at the statement it belongs
    to and decide whether that statement produces markup at all.
    """
    found: list[tuple[str, int]] = []
    index = 0
    while True:
        index = script.find("${", index)
        if index < 0:
            return found
        depth = 1
        cursor = index + 2
        while cursor < len(script) and depth:
            character = script[cursor]
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
            cursor += 1
        found.append((script[index + 2 : cursor - 1], index))
        index = cursor


def test_vendored_assets_match_their_recorded_digests() -> None:
    """Vendored JavaScript is code that runs in the operator's browser.

    The console loads nothing from the network at runtime — that keeps `pip install` the only
    install step and lets the console work in an air-gapped deployment. The cost of vendoring is
    that a swapped file is invisible, so every asset's SHA-256 is recorded in the manifest and
    recomputed here. Replacing one is expected to be a deliberate act: update the digest and the
    version in the same commit.
    """
    import hashlib
    import json

    vendor = SERVICE / "static" / "vendor"
    manifest_path = vendor / "MANIFEST.json"
    assert manifest_path.is_file(), "the vendor manifest is missing"
    manifest = json.loads(manifest_path.read_text())

    assets = manifest["assets"]
    assert assets, "the manifest lists no assets"
    for asset in assets:
        path = vendor / asset["file"]
        assert path.is_file(), f"{asset['file']} is listed but missing"
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == asset["sha256"], (
            f"{asset['file']} does not match its recorded digest.\n"
            f"  recorded {asset['sha256']}\n  actual   {actual}\n"
            "If the upgrade is intended, update the version and the digest in MANIFEST.json."
        )
        for field in ("name", "version", "licence", "url", "purpose"):
            assert asset.get(field), f"{asset['file']} does not record its {field}"


def test_the_console_loads_its_assets_from_this_server() -> None:
    """No CDN at runtime: a console that needs the internet to render is not a console for a
    machine that is deliberately offline."""
    base = _templates()["base.html"]
    for reference in re.findall(r'(?:src|href)="(https?://[^"]+)"', base):
        raise AssertionError(f"base.html loads a remote asset: {reference}")
    audit = _templates()["audit.html"]
    for reference in re.findall(r'(?:src|href)="(https?://[^"]+)"', audit):
        raise AssertionError(f"audit.html loads a remote asset: {reference}")
    # The vendored diff renderer and the typeface must actually be wired in.
    assert "/static/vendor/diff2html.min.js" in base or "/static/vendor/diff2html.min.js" in audit
    assert "/static/vendor/diff2html.min.css" in base or "/static/vendor/diff2html.min.css" in audit
    assert "inter-latin.woff2" in CONSOLE_CSS.read_text()
