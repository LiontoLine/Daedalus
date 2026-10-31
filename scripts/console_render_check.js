#!/usr/bin/env node
/* Execute the console's render functions against real server payloads.
 *
 * The console has no build step and no test runner, so "the frontend works" is normally
 * established by opening a browser and looking at it — which is not a regression test. This
 * harness loads the real `console.js` and the real vendored `diff2html` into a `vm` context with
 * a minimal DOM stub (enough for the pure render functions: element creation, namespaced
 * creation, attributes, innerHTML, appendChild, textContent) and feeds it payloads captured from
 * the live service.
 *
 * What it proves that a static check cannot:
 *   - 执行 draws one box per step, left to right, and the box carries the state it was given;
 *   - the step detail panel shows the two commits, the snapshot and every Tier-1 check;
 *   - 恢复 / 重现 are offered exactly when the run makes them possible, and a disabled action
 *     says why;
 *   - 规划 renders a summary per spec plus the whole document, with digests as digests;
 *   - 审计 renders the score, the components that produced it, and a diff through the vendored
 *     renderer;
 *   - hostile text from the model plane arrives escaped, not as live markup.
 *
 * Usage: node scripts/console_render_check.js src/daedalus/service/static/console.js < payload.json
 * Exit 0 on success; prints a JSON report and exits 1 on the first failure.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const scriptPath = process.argv[2];
if (!scriptPath) {
  console.error("usage: console_render_check.js <console.js> < payload.json");
  process.exit(2);
}
const source = fs.readFileSync(scriptPath, "utf8");
// The vendored bundle sits beside the console script, so the check loads exactly the file the
// template links rather than resolving a copy from somewhere else.
const vendorPath = path.join(
  path.dirname(scriptPath), "vendor", "diff2html.min.js",
);
const payload = JSON.parse(fs.readFileSync(0, "utf8"));


const failures = [];
function check(condition, message) {
  if (!condition) failures.push(message);
  return condition;
}

/* --------------------------------------------------------------- DOM stub */

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

function escapeAttribute(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ESCAPES[ch]);
}

class Element {
  constructor(tag, namespace = "") {
    this.tagName = tag;
    this.namespace = namespace;
    this.attributes = {};
    this.children = [];
    this.html = "";
    this.dataset = {};
    this.hidden = false;
    this.listeners = {};
    this.style = {};
    this.scrollTop = 0;
    this.scrollLeft = 0;
    this.classList = {
      toggle: (name, on) => {
        const classes = new Set((this.attributes.class || "").split(" ").filter(Boolean));
        if (on === undefined ? !classes.has(name) : on) classes.add(name); else classes.delete(name);
        this.attributes.class = Array.from(classes).join(" ");
      },
      contains: (name) => (this.attributes.class || "").split(" ").includes(name),
      add: (name) => this.classList.toggle(name, true),
      remove: (name) => this.classList.toggle(name, false),
    };
    // A real <select> always has `.options`; the stub has to as well, or a faithful render
    // throws here and only here.
    this.options = tag === "select" ? [] : undefined;
  }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
    if (name.startsWith("data-")) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = String(value);
  }
  removeAttribute(name) { delete this.attributes[name]; }
  contains(element) { return this === element || this.children.some((child) => child.contains(element)); }
  getAttribute(name) { return this.attributes[name]; }
  appendChild(child) {
    if (this.options) this.options.push(child);
    this.children.push(child);
    return child;
  }
  addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
  set innerHTML(value) { this.html = String(value); this.children = []; }
  get innerHTML() { return this.html; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  scrollIntoView() {}
  focus() {}
  // `textContent` is text, not markup. Serialising it raw made the stub report an injection for
  // content a browser renders as a text node — a false positive that would train whoever
  // maintains this to ignore the check.
  get textContent() { return this.text; }
  set textContent(value) { this.text = String(value); }
  get outerHTML() { return this.serialise(); }
  serialise() {
    // Attribute values are escaped the way a browser escapes them, so a value set through
    // `setAttribute` cannot inject markup — which is true in a browser and must be true here,
    // or the check reports injections that cannot happen and stops being believed.
    const attrs = Object.entries(this.attributes)
      .map(([key, value]) => ` ${key}="${escapeAttribute(value)}"`).join("");
    const text = (this.text || "").replace(/[&<>"']/g, (ch) => ESCAPES[ch]);
    const inner = this.html + text + this.children.map((child) => child.serialise()).join("");
    return `<${this.tagName}${attrs}>${inner}</${this.tagName}>`;
  }
}

const domListeners = {};
const elements = new Map();
// Ids the templates render as something other than a div. Modelling them keeps the
// stub honest: a <select> without `.options` throws in a faithful render.
const SELECT_IDS = new Set(["#model-role", "#diff-step", "#run-picker"]);
const elementFor = (selector) => {
  if (!elements.has(selector)) {
    elements.set(selector, new Element(SELECT_IDS.has(selector) ? "select" : "div"));
  }
  return elements.get(selector);
};

const sandbox = {
  document: {
    // Recorded rather than ignored: the boot block is where a page's whole initialiser is
    // dispatched, and a page missing from that table runs no JavaScript at all while every other
    // check still passes. Only firing the handler catches it.
    addEventListener(type, handler) { (domListeners[type] ||= []).push(handler); },
    createElement: (tag) => new Element(tag),
    createElementNS: (namespace, tag) => new Element(tag, namespace),
    querySelector: (selector) => (String(selector).startsWith("#") ? elementFor(selector) : null),
    querySelectorAll: () => [],
    getElementById: (id) => elementFor("#" + id),
    activeElement: null,
    body: { dataset: { page: "execution", runId: "template-run" } },
  },
  window: { DAEDALUS_RUN_ID: "" },
  CSS: { escape: (value) => String(value) },
  setInterval: () => 0,
  clearInterval: () => {},
  setTimeout: () => 0,
  clearTimeout: () => {},
  Date,
  Math,
  JSON,
  console: { log() {}, warn() {}, error() {} },
  fetch: async () => { throw new Error("the render check must not touch the network"); },
};
sandbox.globalThis = sandbox;
sandbox.self = sandbox;
vm.createContext(sandbox);

// The vendored renderer is loaded first and into the same context, so the audit diff is exercised
// through the code the browser actually runs. If the bundle is corrupt or its UMD wrapper does not
// attach itself, that is a failure here rather than a blank panel in front of an operator.
let diff2htmlLoaded = false;
if (fs.existsSync(vendorPath)) {
  try {
    vm.runInContext(fs.readFileSync(vendorPath, "utf8"), sandbox, { filename: vendorPath });
    diff2htmlLoaded = typeof sandbox.Diff2Html !== "undefined";
  } catch (error) {
    failures.push(`the vendored diff2html failed to load: ${error.message}`);
  }
} else {
  failures.push(`the vendored diff2html is missing at ${vendorPath}`);
}

vm.runInContext(source, sandbox, { filename: scriptPath });

/* ---------------------------------------------------------------- helpers */

// `const`/`let` declarations live in the context's global lexical environment, not on the sandbox
// object, so they are read back through the context rather than as properties.
const read = (expression) => vm.runInContext(expression, sandbox);
const escapeHtmlForCheck = sandbox.escapeHtml;

function renderMarkup(selector) {
  return elementFor(selector).outerHTML;
}

async function runChecks() {
check(read("MODULE_RUN.id") === "template-run", "the workspace opens the run identified by the rendered URL, not the latest run");
read('MODULE_RUN.id = "";');

/* ======================================================================
 * 执行 · one box per step
 * ====================================================================== */

const detail = payload.detail;
const route = payload.route;
const steps = detail.steps || [];
const attemptNodes = (route.nodes || []).filter((node) => node.kind === "attempt");
const retryEdges = (route.edges || []).filter((edge) => edge.kind === "retry");
check(attemptNodes.length >= steps.length,
  "the route records at least one attempt per step, or the fixture is not exercising retries");

const models = sandbox.buildStepModels(detail, route, payload.plan);
read(`stepModels = buildStepModels(${JSON.stringify(detail)}, ${JSON.stringify(route)}, ${JSON.stringify(payload.plan || null)});`);
check(models.length === steps.length,
  `buildStepModels produces one model per step (${steps.length} expected, got ${models.length})`);

sandbox.renderLane(models, route);
const lane = renderMarkup("#lane-track");

check(lane.includes('class="lane-svg"'), "the lane is an svg with class lane-svg");
check(lane.includes("viewBox="), "the lane svg carries a viewBox so it scales");
check(
  (lane.match(/class="lane-node/g) || []).length === models.length,
  `the lane draws one box per step (${models.length} expected)`,
);
const expectedEdges = models.reduce((sum, model) => sum + (model.plan.deps || []).length, 0);
check((lane.match(/class="lane-edge"/g) || []).length === expectedEdges,
  `the graph draws the declared dependencies (${expectedEdges} expected)`);


for (const model of models) {
  const step = model.step;
  const skin = read(`JSON.stringify(stepSkin(${JSON.stringify(step.state)}))`);
  const colours = JSON.parse(skin);
  check(lane.includes(`fill="${colours.fill}"`),
    `step ${step.node_id} uses the fill for state ${step.state}`);
  check(lane.includes(`stroke="${colours.edge}"`),
    `step ${step.node_id} uses the edge for state ${step.state}`);
  check(lane.includes(escapeHtmlForCheck(step.step_id)) || lane.includes(step.step_id),
    `step ${step.node_id} is addressable by step_id`);
  check(lane.includes(escapeHtmlForCheck((step.node_id || "").slice(0, 20))),
    `step ${step.node_id} is labelled on the box`);
  check(lane.includes(escapeHtmlForCheck(read(
    `stateText(${JSON.stringify(step.state)})`))),
  `step ${step.node_id} shows its state as text, not only as a colour`);
  if (model.attempts.length > 1) {
    check(lane.includes(`重试 ${model.attempts.length - 1}`),
      `step ${step.node_id} shows that it was retried`);
    check(lane.includes("lane-node " + `state-${step.state} retried`),
      `step ${step.node_id} is marked as retried on the box itself`);
  }
}
// Nodes show execution phases; hashes remain available in the inspector.
check(lane.includes('height="3"'), "nodes carry a compact execution phase indicator");

sandbox.renderRunStats(route, models);
const stats = renderMarkup("#run-stats");
check((stats.match(/class="stat /g) || []).length === 6,
  "the execution header draws six tiles");
check(stats.includes(escapeHtmlForCheck(route.status)),
  "the header names the run status");
const committed = models.filter((model) => model.step.state === "COMMITTED").length;
check(stats.includes(`${committed}/${models.length}`),
  "the header reports how many steps committed out of how many");

/* ---- the detail panel that opens from a box ---- */

const sample = models.find((model) => model.attempts.length > 1) || models[0];
check(Boolean(sample), "the fixture must contain at least one step");
const detailMarkup = ["overview", "changes", "gates", "history"].map((tab) => sandbox.renderStepDetail(sample, tab)).join("");
for (const section of ["执行信息", "前置依赖", "预期产出", "技术溯源", "尝试历史", "门禁逐条结论"]) {
  check(detailMarkup.includes(section), `the step panel has a ${section} section`);
}
check(detailMarkup.includes("基线提交"), "the step panel names the base commit");
check(detailMarkup.includes("产物提交"), "the step panel names the commit the step produced");
for (const row of ["artifact sha", "补丁 sha", "代码基线 sha", "gated tree sha",
                   "输入 artifact sha", "工具链 sha", "依赖 sha", "日志引用"]) {
  check(detailMarkup.includes(row), `the step panel shows the ${row} row`);
}
check(detailMarkup.includes("改动文件"), "the snapshot section names the changed files");
check(detailMarkup.includes("执行摘要"), "the snapshot section carries the worker summary");
check(
  (detailMarkup.match(/class="attempt-row /g) || []).length === sample.attempts.length,
  `the attempt history has one row per attempt (${sample.attempts.length} expected)`,
);
check(detailMarkup.includes('id="step-diff"'),
  "the step panel hosts the diff, so the async loader has somewhere to write");
const gated = sample.step.gates || [];
for (const gate of gated) {
  for (const row of gate.checks || []) {
    check(detailMarkup.includes(escapeHtmlForCheck(row.name)),
      `the step panel lists Tier-1 check ${row.name}`);
  }
}
check(detailMarkup.includes(escapeHtmlForCheck(sample.step.node_id)),
  "the step panel names the step it describes");

/* ---- 恢复 / 重现, and why a disabled one is disabled ---- */

/* 恢复 / 重现, and why a disabled one is disabled. The run status is passed in rather than set
   as module state: the panel's behaviour must be a function of its arguments, or a caller that
   renders it without going through `loadExecution` gets a parked run whose 恢复 is disabled. */
function actionsFor(model, runStatus) {
  sandbox.renderStepActions(model, runStatus);
  return renderMarkup("#step-actions");
}

const parked = actionsFor({ ...sample, step: { ...sample.step, state: "ESCALATED", execution_authorization_required: true } }, "AWAITING_APPROVAL");
check(parked.includes("恢复"), "the step panel offers 恢复");
check(parked.includes("重现"), "the step panel offers 重现");
check(parked.includes("回滚到此处"), "the step panel offers 回滚到此处");
check(!parked.includes('class="action disabled"'),
  "every action is enabled on a parked run whose step has a commit");

const completed = actionsFor(sample, "COMPLETED");
check(completed.includes('class="action disabled"'),
  "恢复 is disabled once the run is no longer waiting for a human");
check(!completed.includes('data-act="resume"'),
  "a disabled 恢复 is not wired to a click handler");
check(/class="action disabled"[^>]*>[^<]*恢复<span class="why">[^<]+<\/span>/.test(completed),
  "the disabled 恢复 says why it cannot be used");

// The replay hint must name the commit it will use: the server refuses any commit the run did not
// record, so the UI has to be specific about which one it picked.
const replayCommit = sample.step.result_commit || sample.step.base_commit;
if (replayCommit) {
  check(parked.includes(replayCommit.slice(0, 12)),
    "重现 names the commit it will replay from");
}
const noCommit = actionsFor(
  { ...sample, step: { ...sample.step, base_commit: "", result_commit: "" } },
  "COMPLETED",
);
check(noCommit.includes("没有记录任何可重现的提交"),
  "重现 refuses in words when the run recorded no commit to replay from");

/* ---- A branching graph, node interaction, and a silent polling round trip ---- */
const branchingPlan = {
  goal_id: "branching", objective: "并行分支验证", risk_level: "normal",
  nodes: [
    { node_id: "A", objective: "准备", deps: [] },
    { node_id: "B", objective: "分支一", deps: ["A"] },
    { node_id: "C", objective: "分支二", deps: ["A"] },
    { node_id: "D", objective: "汇合", deps: ["B", "C"] },
  ],
};
const branchingDetail = {
  run: { run_id: "branching-run", status: "RUNNING", goal_id: "branching" },
  steps: branchingPlan.nodes.map((node) => ({ ...sample.step,
    node_id: node.node_id, step_id: "branching-run:" + node.node_id, state: "RUNNING" })),
};
const branchingRoute = { status: "RUNNING", nodes: [], lanes: [] };
const branchingModels = sandbox.buildStepModels(branchingDetail, branchingRoute, branchingPlan);
const layout = sandbox.buildDagLayout(branchingModels);
check(layout.edges.length === 4, "a diamond has exactly its four declared dependencies");
check(layout.points.get("B").x === layout.points.get("C").x,
  "independent branches occupy the same dependency column");
check(layout.points.get("B").y !== layout.points.get("C").y,
  "parallel branches are visibly separated");
check(layout.points.get("D").x > layout.points.get("B").x,
  "the join follows both branches");
check(!layout.edges.some((edge) => edge.from === "B" && edge.to === "C"),
  "the graph never invents a dependency between parallel branches");
const undeclared = sandbox.buildStepModels({ steps: [branchingDetail.steps[0]] }, branchingRoute, branchingPlan);
check(undeclared.length === 4 && undeclared[1].declared === false,
  "future planned steps remain visible before the scheduler declares them");
check(sandbox.phaseEvidenceMissing({ ...branchingModels[0], step: { ...branchingModels[0].step, state: "COMMITTED", gates: [] } }, 2),
  "a skipped or unrecorded semantic review is never painted as a completed review");
const incomplete = sandbox.buildDagLayout([{ ...branchingModels[0], plan: { deps: ["missing"] } }]);
check(incomplete.missing.length === 1 && incomplete.edges.length === 0,
  "missing dependencies are reported rather than replaced by fake arrows");
const cycle = sandbox.buildDagLayout([
  { ...branchingModels[0], plan: { deps: ["B"] } },
  { ...branchingModels[1], plan: { deps: ["A"] } },
]);
check(cycle.cyclic, "corrupt cyclic graph data is detected without recursion or a hang");

read(`stepModels = buildStepModels(${JSON.stringify(branchingDetail)}, ${JSON.stringify(branchingRoute)}, ${JSON.stringify(branchingPlan)});
  currentRunDetail = ${JSON.stringify(branchingDetail)}; currentRoute = ${JSON.stringify(branchingRoute)};
  MODULE_RUN.id = "branching-run"; WORKSPACE.runId = "branching-run"; WORKSPACE.plan = ${JSON.stringify(branchingPlan)};`);
sandbox.renderLane(branchingModels, branchingRoute);
const graphElement = elementFor("#lane-track").children[0];
const branchNode = graphElement.children.find((element) => element.dataset.step === "branching-run:C");
check(Boolean(branchNode), "the branch is an addressable interactive node");
if (branchNode) await branchNode.listeners.click[0]();
check(read("WORKSPACE.selectedId") === "branching-run:C", "clicking a node selects that exact step");
check(elementFor("#step-title").textContent === "分支二", "the inspector opens the selected step overview");
read('WORKSPACE.tab = "history"; WORKSPACE.zoom = .75;');
const originalFetch = sandbox.fetch;
sandbox.fetch = async (url) => {
  const body = url === "/api/runs" ? { runs: [{ ...branchingDetail.run, steps: {} }] }
    : url.endsWith("/route") ? branchingRoute : url.endsWith("/plan") ? branchingPlan : branchingDetail;
  return { ok: true, text: async () => JSON.stringify(body) };
};
elementFor("#lane").scrollLeft = 137;
elementFor("#lane").scrollTop = 43;
await sandbox.loadExecution();
check(!elementFor("#execution-error").textContent, "the complete workspace refresh executes without a runtime error");
check(read("WORKSPACE.selectedId") === "branching-run:C", "polling preserves the selected branch");
check(read("WORKSPACE.tab") === "history", "polling preserves the open inspector tab");
check(read("WORKSPACE.zoom") === .75, "polling preserves the graph zoom");
check(elementFor("#lane").scrollLeft === 137 && elementFor("#lane").scrollTop === 43,
  "polling preserves the graph's panned position");
check(renderMarkup("#step-body").includes("尝试历史"), "the history tab remains rendered after polling");
sandbox.fetch = async () => { throw new Error("offline"); };
await sandbox.loadExecution();
check(elementFor("#execution-error").textContent === "offline", "failed polling is visible");
check(read("WORKSPACE.selectedId") === "branching-run:C", "failed polling does not discard the current task context");
sandbox.fetch = originalFetch;
read(`stepModels = buildStepModels(${JSON.stringify(detail)}, ${JSON.stringify(route)}, ${JSON.stringify(payload.plan || null)});
  currentRunDetail = null; currentRoute = null; MODULE_RUN.id = ""; WORKSPACE.runId = "";
  WORKSPACE.selectedId = ""; WORKSPACE.tab = "overview"; WORKSPACE.inspectorKey = ""; WORKSPACE.zoom = 1;`);
sandbox.renderLane(models, route);

/* ======================================================================
 * 规划 · a summary per spec, the whole document on expand
 * ====================================================================== */

const planning = payload.specs;
const cards = planning.specs || [];
check(cards.length === 4, `a registered run carries four spec cards (got ${cards.length})`);
const cardsMarkup = sandbox.renderSpecCards(planning);
check((cardsMarkup.match(/class="spec-card"/g) || []).length === cards.length,
  "the planning panel draws one card per spec");
for (const card of cards) {
  check(cardsMarkup.includes(`data-spec="${escapeHtmlForCheck(card.key)}"`),
    `card ${card.key} is addressable`);
  check(cardsMarkup.includes(escapeHtmlForCheck(card.title)), `card ${card.key} is titled`);
  check(cardsMarkup.includes(escapeHtmlForCheck(card.subtitle || "")),
    `card ${card.key} carries its subtitle`);
  for (const [key, value] of (card.summary || []).slice(0, 4)) {
    check(cardsMarkup.includes(escapeHtmlForCheck(key)),
      `card ${card.key} shows the summary row ${key}`);
    check(cardsMarkup.includes(escapeHtmlForCheck(
      sandbox.ellipsis(String(value), 46))),
    `card ${card.key} shows the value of ${key}`);
  }
}
check((cardsMarkup.match(/class="spec-body" hidden/g) || []).length === cards.length,
  "every card starts collapsed, so the panel opens as a summary");
check(cardsMarkup.includes('aria-expanded="false"'),
  "every card header reports that it is collapsed");
check((cardsMarkup.match(/class="chevron"/g) || []).length === cards.length,
  "every card shows that it can be expanded");
// The expanded body must be the whole document, and it must be reachable for each spec.
for (const card of cards) {
  const body = sandbox.renderDocument(card.document);
  check(body.length > 0, `spec ${card.key} has a document to expand`);
  const keys = Object.keys(card.document || {});
  for (const key of keys.slice(0, 6)) {
    check(body.includes(escapeHtmlForCheck(key)),
      `the expanded ${card.key} renders the ${key} field`);
  }
}

const goalCard = cards.find((card) => card.key === "spec_01");
if (goalCard && goalCard.document.objective) {
  check(cardsMarkup.includes(escapeHtmlForCheck(goalCard.document.objective)),
    "the expanded SPEC-01 renders its objective");
}
const boundaryCard = cards.find((card) => card.key === "spec_03");
if (boundaryCard && (boundaryCard.document.fs_whitelist || []).length) {
  const whitelist = boundaryCard.document.fs_whitelist[0];
  check(cardsMarkup.includes(escapeHtmlForCheck(String(whitelist))),
    "the expanded SPEC-03 renders the writable path whitelist");
}
// Digests are read by a human checking a claim, so they must be monospace, not body text.
check(sandbox.renderDocument("a".repeat(64)).includes('class="digest"'),
  "a 64-character digest is rendered as a digest");
check(sandbox.renderDocument(planning.spec_digest).includes('class="digest"')
  || !planning.spec_digest,
  "the spec digest is rendered as a digest");
// Booleans and nesting: a Meta-Spec with `allow_self_modification = false` must read as false
// rather than as body text a reader might skim past.
const hasBoolean = (value) => {
  if (typeof value === "boolean") return true;
  if (Array.isArray(value)) return value.some(hasBoolean);
  if (value && typeof value === "object") return Object.values(value).some(hasBoolean);
  return false;
};
const metaCard = cards.find((card) => card.key === "meta_spec");
if (metaCard && hasBoolean(metaCard.document)) {
  const nested = sandbox.renderDocument(metaCard.document);
  check(nested.includes("bool-true") || nested.includes("bool-false"),
    "boolean Meta-Spec fields are rendered as booleans, not as body text");
}
check(sandbox.renderDocument({ a: [{ b: 1 }] }).includes("doc-item"),
  "nested objects render as structure rather than as JSON");

const approvalMarkup = sandbox.renderApprovalPanel({
  ...(planning.approval || {}), risk_level: planning.risk_level,
  owner_id: planning.owner_id, spec_version: planning.spec_version,
});
check(approvalMarkup.includes(planning.approval && planning.approval.verified
  ? "check-pass" : "check-fail")
  || approvalMarkup.includes("未验证"),
"the approval panel distinguishes a verified signature from a recorded name");
check(sandbox.renderRegistry(payload.registry).includes("digest"),
  "the registry panel has a digest column");

/* ======================================================================
 * 审计 · the score, then the diff
 * ====================================================================== */

const score = payload.score;
check(Boolean(score), "the fixture must carry an audit score");
const scoreMarkup = sandbox.renderScore(score);
check(scoreMarkup.includes('class="score-ring"'), "the audit panel draws the score as a ring");
check(scoreMarkup.includes(escapeHtmlForCheck(score.score.toFixed(1))),
  "the ring is labelled with the score");
check(scoreMarkup.includes(escapeHtmlForCheck(score.band)),
  "the ring is labelled with the band");
check(
  (scoreMarkup.match(/class="score-part /g) || []).length === (score.components || []).length,
  `the score explains itself with one row per component (${(score.components || []).length})`,
);
for (const component of score.components || []) {
  const label = sandbox.ellipsis(component.label, 200);
  check(label && scoreMarkup.includes(escapeHtmlForCheck(label)),
    `the score names the ${component.label} component`);
  check(scoreMarkup.includes(escapeHtmlForCheck(component.detail)),
    `the score explains how ${component.label} was scored`);
  check(scoreMarkup.includes(`width:${Math.round(component.value * 100)}%`),
    `the ${component.label} bar reflects its value`);
  check(scoreMarkup.includes(escapeHtmlForCheck(String(component.score))),
    `the ${component.label} row shows the points it earned`);
}
// The score is not a verdict. Whatever else changes, this sentence has to reach the operator.
check(scoreMarkup.includes("不代表"), "the score states what it is not");
check(scoreMarkup.includes(escapeHtmlForCheck(score.scale_note || "")) && score.scale_note,
  "the score renders the server's own scale note rather than a hand-written one");
check(sandbox.renderScore(null) === "", "no score renders nothing rather than a zero");

/* ---- the diff, through the vendored renderer ---- */

const patch = payload.patch.patch || "";
check(diff2htmlLoaded, "the vendored diff renderer must be loaded for this check to mean anything");
sandbox.renderDiffFor(patch);
const diffMarkup = renderMarkup("#diff");
check(diffMarkup.includes("d2h-"), "the diff is rendered by diff2html, not by hand");
check(!diffMarkup.includes("<pre class=\"diff\">"),
  "the hand-rolled colourer is only the fallback, so it must not be what drew this");
if ((payload.patch.changed_files || []).length) {
  check(diffMarkup.includes(escapeHtmlForCheck(payload.patch.changed_files[0]))
    || diffMarkup.includes(payload.patch.changed_files[0]),
  "the diff names the file it changed");
}
check(diffMarkup.includes("d2h-ins") && diffMarkup.includes("d2h-del"),
  "the diff distinguishes added from removed lines");
sandbox.renderDiffFor("");
check(renderMarkup("#diff").includes("没有被记录的补丁"),
  "a step with no patch says so instead of drawing an empty diff");

// The fallback colourer is still what a browser without the vendored bundle would use, so it is
// checked on its own terms.
const coloured = sandbox.colourDiff(patch);
check(coloured.includes("diff-ctx"), "context lines are classified as diff-ctx");
if (patch.split("\n").some((line) => line.startsWith("+") && !line.startsWith("+++"))) {
  check(coloured.includes("diff-add"), "added lines are classified as diff-add");
}
if (patch.split("\n").some((line) => line.startsWith("-") && !line.startsWith("---"))) {
  check(coloured.includes("diff-del"), "removed lines are classified as diff-del");
}
if (patch.split("\n").some((line) => line.startsWith("@@"))) {
  check(coloured.includes("diff-hunk"), "hunk headers are classified as diff-hunk");
}

/* ---- the §27 answer and the event log ---- */

const auditMarkup = sandbox.renderAuditAnswer(payload.audit, route);
for (const question of ["谁", "什么时候", "哪个 Image", "谁批准", "最终 Commit"]) {
  check(auditMarkup.includes(question), `the audit view answers ${question}`);
}
const auditImages = (payload.audit.steps || [])
  .map((step) => (step.artifacts || []).map((artifact) => artifact.sandbox_image))
  .flat().filter(Boolean);
check(auditImages.length > 0, "the fixture must carry a sandbox image, or the check is vacuous");
for (const image of [...new Set(auditImages)]) {
  check(auditMarkup.includes(escapeHtmlForCheck(image)), `the audit view names image ${image}`);
}
check(!auditMarkup.includes("— · —"),
  "the audit view must not print an empty placeholder where a verdict exists");

const trail = payload.audit_trail || [];
const trailMarkup = sandbox.renderEventTable(trail);
if (trail.length) {
  check(trailMarkup.includes("<tr>"), "the event table draws rows");
  check(
    trailMarkup.includes(escapeHtmlForCheck(String(trail[trail.length - 1].event_type || ""))),
    "the newest event is first, so the trail reads backwards from now",
  );
  check((trailMarkup.match(/<tr>/g) || []).length === Math.min(300, trail.length),
    "the event table draws one row per event, capped at 300");
} else {
  check(trailMarkup.includes("没有事件"), "an empty trail says so");
}

/* ======================================================================
 * 运维 · metrics, identity, executions, workers
 * ====================================================================== */

sandbox.renderMetricBars(payload.metrics, "#metrics-bars");
const bars = renderMarkup("#metrics-bars");
check((bars.match(/class="metric-row"/g) || []).length === 5,
  "the metric panel draws one row per rate metric");
check(bars.includes("task success"), "the metric panel labels its rows");

sandbox.renderIdentity(payload.owners);
const identityMarkup = renderMarkup("#identity-out");
check(identityMarkup.includes("审批是否验签"),
  "the identity panel is labelled with whether approvals are verified");
check(identityMarkup.includes(payload.owners.enforced ? "✓ 已强制" : "未强制"),
  `the identity panel states the enforcement it reports (${payload.owners.enforced})`);
for (const owner of payload.owners.owners || []) {
  check(identityMarkup.includes(owner.owner_id), `the identity panel lists owner ${owner.owner_id}`);
}

sandbox.renderExecutions(payload.executions);
const executionsMarkup = renderMarkup("#executions tbody");
check((executionsMarkup.match(/<tr>/g) || []).length
  === (payload.executions.executions || []).length,
"the executions table draws one row per execution");

sandbox.renderWorkers(payload.workers);
const workersMarkup = renderMarkup("#workers tbody");
check((workersMarkup.match(/<tr>/g) || []).length === (payload.workers.workers || []).length,
  "the workers table draws one row per worker");

/* ======================================================================
 * 提任务 · the front door's three states
 * ====================================================================== */

const intake = payload.intake;
check(Boolean(intake), "the fixture must carry an intake session");
const intakeQuestions = intake.questions || [];
check(intakeQuestions.length >= 1, "the intake fixture must carry at least one question");
check(
  (intake.answers || []).length === intakeQuestions.length,
  "the intake fixture must be fully answered, so the review state has something to show",
);

// State 1: the repository cards, and the provenance label on each.
read(`INTAKE.repos = ${JSON.stringify(payload.intake_repos || [])}`);
read(`INTAKE.repo = ${JSON.stringify((payload.intake_repos || [{}])[0].path || "")}`);
sandbox.renderIntakeRepos();
const repoMarkup = renderMarkup("#intake-repos");
if ((payload.intake_repos || []).length) {
  for (const repo of payload.intake_repos) {
    check(repoMarkup.includes(escapeHtmlForCheck(repo.name)),
      `the intake offers repository ${repo.name}`);
    check(repoMarkup.includes(escapeHtmlForCheck(repo.source)),
      `the intake says where ${repo.name} came from`);
  }
  check((repoMarkup.match(/class="repo-card/g) || []).length === payload.intake_repos.length,
    "the intake draws one card per repository");
} else {
  check(repoMarkup.includes("还没有跑过任何仓库"),
    "an empty workspace says so rather than offering nothing");
}

// State 2: one question at a time, and every option carries its consequence.
read(`INTAKE.session = ${JSON.stringify(intake)}; INTAKE.index = 0;`);
sandbox.renderIntakeQuestion();
// The sub-line matters as much as the question: it is where the field's own spec is named.
const questionMarkup = renderMarkup("#intake-question-title")
  + renderMarkup("#intake-question-sub") + renderMarkup("#intake-question")
  + renderMarkup("#intake-options") + renderMarkup("#intake-progress");
const first = intakeQuestions[0];
check(questionMarkup.includes(escapeHtmlForCheck(first.question)),
  "the question screen shows the question the model asked");
check(questionMarkup.includes(`决定 ${escapeHtmlForCheck(first.field_spec)} 的「${
  escapeHtmlForCheck(first.field_label)}」`),
"the question screen names the spec the field belongs to, not a hardcoded one");
check(questionMarkup.includes(escapeHtmlForCheck(first.why)),
  "the question screen says why the question is being asked");
for (const option of first.options) {
  check(questionMarkup.includes(escapeHtmlForCheck(option.label)),
    `option ${option.id} is offered`);
  check(questionMarkup.includes(escapeHtmlForCheck(option.effect)),
    `option ${option.id} states what choosing it means`);
}
check((questionMarkup.match(/class="option-card/g) || []).length === first.options.length,
  `the question screen draws one card per option (${first.options.length} expected)`);
check((questionMarkup.match(/class="dot/g) || []).length === intakeQuestions.length,
  "the progress dots count the questions");
// A rejection the control plane made must reach the screen, or the operator cannot know a
// field went unasked.
const rejected = { ...intake, rejections: ["第 2 题：field 'nope' 不在可回答字段表内"] };
read(`INTAKE.session = ${JSON.stringify(rejected)}; INTAKE.index = 0;`);
sandbox.renderIntakeQuestion();
const rejectionMarkup = renderMarkup("#intake-rejections");
check(rejectionMarkup.includes("不在可回答字段表内"),
  "a rejected question is shown to the operator, not dropped");

// State 3: the review, which must say what the human decided and what the model decided alone.
read(`INTAKE.session = ${JSON.stringify(intake)};`);
const reviewSpecs = payload.intake_specs || [];
const reviewMarkup = sandbox.renderSpecCards({ specs: reviewSpecs });
check((reviewMarkup.match(/class="spec-card"/g) || []).length === reviewSpecs.length,
  "the review screen shows the same four spec cards as 规划");
for (const card of reviewSpecs) {
  check(reviewMarkup.includes(escapeHtmlForCheck(card.title)), `review shows ${card.title}`);
}
// The review screen's honesty depends on this list: it is what lets the page say which policy
// fields the model decided alone. Without it the screen implies every field was chosen.
check(Array.isArray(intake.unasked_policy_fields),
  "the intake payload names the policy fields no human answered");
check(intake.answers.every((row) => row.label),
  "an answer keeps the label the operator clicked, not only the raw value");
check(intake.answers.every((row) => row.value !== undefined && row.value !== null),
  "an answer carries the value that will bind the spec");

/* ======================================================================
 * 模型接口 · which endpoint is answering, and is the code leaving the machine
 * ====================================================================== */

const model = payload.model;
check(Boolean(model), "the fixture must carry the model report");
check(Array.isArray(model.roles), "the model report must carry a roles list");
sandbox.renderModelPanel(model);
const modelMarkup = renderMarkup("#model-current");
if (!model.roles.length) {
  // A workspace with no model configured is a real state, and the intake cannot run in it; the
  // panel must say that rather than drawing an empty area a reader would take for "loading".
  check(modelMarkup.includes("还没有配置任何模型角色"),
    "an unconfigured workspace says so instead of drawing nothing");
}
check((modelMarkup.match(/class="model-row"/g) || []).length === model.roles.length,
  `the model panel draws one row per role (${model.roles.length} expected)`);
for (const role of model.roles) {
  check(modelMarkup.includes(escapeHtmlForCheck(role.role)), `the panel lists role ${role.role}`);
  check(modelMarkup.includes(escapeHtmlForCheck(role.model)),
    `the panel names the model answering for ${role.role}`);
  check(modelMarkup.includes(escapeHtmlForCheck(role.base_url)),
    `the panel names the endpoint for ${role.role}`);
  check(modelMarkup.includes(escapeHtmlForCheck(role.source)),
    `the panel says where ${role.role}'s value came from`);
  check(modelMarkup.includes(escapeHtmlForCheck(role.key)),
    `the panel says where ${role.role}'s credential comes from`);
  // Each fact carries its own label, because the row collapses to fewer columns on a narrow
  // window and an unlabelled value does not say what it is describing.
  check(modelMarkup.includes("<b>来源</b>") && modelMarkup.includes("<b>密钥</b>"),
    "each model fact is labelled, not left to a column header");
  check(modelMarkup.includes(role.loopback ? "本机" : "非本机"),
    `the panel states whether ${role.role} is local`);
}
// A key must never be renderable from this payload, in any form.
const keyish = JSON.stringify(model);
check(!/sk-[A-Za-z0-9-]{8,}/.test(keyish),
  "the model report must not carry a key, only a fingerprint");
if (model.override) {
  check(modelMarkup.includes(escapeHtmlForCheck(model.override.key_fingerprint)),
    "the panel shows the key fingerprint so two keys can be told apart");
}
if (model.remote_warning) {
  check(read("$('#model-caveat') ? true : true"),
    "the remote warning is rendered into the caveat line");
}

/* Independent delivery review: render a real parked high-risk API response. */
const scenario = payload.validation_scenario;
if (scenario) {
  sandbox.updateValidationPanel(scenario.view, scenario.run.run_id, scenario.run);
  const validationMarkup = renderMarkup("#independent-validation");
  check(validationMarkup.includes("重新验收") && validationMarkup.includes("独立签署") && validationMarkup.includes("交付"),
    "validation shows its three ordered actions");
  check(validationMarkup.includes('id="validation-form"') && validationMarkup.includes('id="validation-review-file"'),
    "a passed fresh evaluation opens the signed review form and downloadable claim");
  check(validationMarkup.includes("尚未确认"), "non-executable goals start as UNKNOWN");
  check(!validationMarkup.includes('id="validation-deliver"'), "unattested evidence has no delivery button");
  check(validationMarkup.includes(escapeHtmlForCheck(scenario.view.request.commit.slice(0, 12))),
    "the review names the exact candidate commit");
  const changed = JSON.parse(JSON.stringify(scenario.view));
  changed.reason = '<img src=x onerror="bad()">';
  sandbox.updateValidationPanel(changed, scenario.run.run_id, scenario.run);
  check(!renderMarkup("#independent-validation").includes('<img src=x'), "validation refusal details are escaped");
  sandbox.updateValidationWorkspace(scenario.view, scenario.run.run_id);
  check(renderMarkup("#independent-validation-workspace").includes('/audit/' + scenario.run.run_id),
    "execution links directly to the same run's independent review");
  sandbox.updateValidationPanel(null, scenario.run.run_id, scenario.run);
  check(elementFor("#independent-validation-panel").hidden,
    "legacy backends without validation data keep the remaining audit usable");
}

/* ======================================================================
 * The boot path: does this page's own initialiser actually run?
 * ====================================================================== */

// Every other check in this file calls a render function directly, which cannot notice that the
// page's initialiser was never reached. The intake page shipped with a boot block that routed
// planning/execution/audit and fell through to the board initialiser for everything else, so its
// buttons, its repository cards and its model panel were dead in a browser while this file — and
// every other test — passed.
const booted = [];
const bootHandlers = {};
const bootSandbox = { ...sandbox };
bootSandbox.document = {
  addEventListener(type, handler) { bootHandlers[type] = handler; },
  createElement: (tag) => new Element(tag),
  createElementNS: (_ns, tag) => new Element(tag),
  querySelector: (selector) => (String(selector).startsWith("#") ? elementFor(selector) : null),
  querySelectorAll: () => [],
  body: Object.assign(new Element("body"), { dataset: { page: "intake" } }),
};
bootSandbox.fetch = async (path) => {
  booted.push(String(path));
  const value = String(path);
  const body = value.startsWith("/api/model")
    ? (payload.model || { roles: [], override: null, persisted: false })
    : value.startsWith("/api/repos")
      ? { repos: payload.intake_repos || [], roots: [] }
      : value.startsWith("/api/intakes")
        ? { intakes: [] }
        : {};
  return { ok: true, status: 200, text: async () => JSON.stringify(body) };
};
bootSandbox.globalThis = bootSandbox;
vm.createContext(bootSandbox);
try {
  vm.runInContext(fs.readFileSync(vendorPath, "utf8"), bootSandbox, { filename: vendorPath });
} catch (error) {
  failures.push(`the vendored diff2html failed to load in the boot context: ${error.message}`);
}
vm.runInContext(source, bootSandbox, { filename: scriptPath });

const bootHandler = bootHandlers.DOMContentLoaded;
check(typeof bootHandler === "function",
  "the console must initialise itself on DOMContentLoaded");
if (typeof bootHandler === "function") {
  const bootErrors = [];
  const originalError = bootSandbox.console.error;
  bootSandbox.console = {
    log() {}, warn() {}, error: (error) => bootErrors.push(String((error && error.message) || error)),
  };
  try {
    bootHandler();
  } catch (error) {
    bootErrors.push(String(error.message || error));
  }
  // Two turns: the initialiser is async and each awaited fetch resolves in a microtask.
  for (let turn = 0; turn < 4; turn += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  bootSandbox.console = { log() {}, warn() {}, error: originalError };
  check(bootErrors.length === 0,
    `the intake page must boot without an error: ${bootErrors.slice(0, 2).join(" | ")}`);
  check(booted.includes("/api/repos"),
    "booting the intake page must load the repository list, which only happens if the page's own "
    + `initialiser ran (requested: ${booted.slice(0, 6).join(", ") || "nothing"})`);
  check(booted.includes("/api/model"),
    "and must load the model panel, so the endpoint slot is usable");
  check(booted.some((path) => path.startsWith("/api/intakes")),
    "and must render the recent-intake list");
}

/* ======================================================================
 * Hostile text stays text
 * ====================================================================== */

const hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
const noMarkup = (markup, where) => {
  check(!markup.includes("<img"), `hostile text cannot inject markup into ${where}`);
  check(!markup.includes("<script"), `hostile text cannot inject a script into ${where}`);
};

// A step's node id, failure text and changed-file paths are model- and gate-authored, so all
// three pass through the lane, the detail panel and the diff.
const hostileStep = {
  step_id: "run-hostile:N1", node_id: hostile, state: "FAILED", attempt: 1, max_attempts: 2,
  spec_digest: hostile, base_commit: hostile, result_commit: hostile, last_failure: hostile,
  run_id: hostile, execution_id: hostile, timeout_sec: 60, worktree_path: hostile,
  created_at: hostile, updated_at: hostile, granted_attempts: 0,
  gates: [{ tier: 1, decision: hostile, confidence: null, reasons: [hostile],
            violations: [hostile], checks: [{ name: hostile, passed: false, detail: hostile }] }],
  artifacts: [{ artifact_digest: hostile, status: hostile, changed_files: [hostile],
                model: hostile, worker_id: hostile, parent_commit: hostile,
                patch_digest: hostile, code_base_digest: hostile, toolchain_digest: hostile,
                dependency_digest: hostile, input_artifact_digest: hostile,
                execution_log_ref: hostile, sandbox_image: hostile, created_at: hostile,
                snapshot: { gated_tree: hostile, diff_stat: hostile, patch_bytes: 1,
                            patch_truncated: false, worker_summary: hostile,
                            node_id: hostile, attempt: 1, commit: hostile } }],
  approvals: [],
};
const hostileModels = sandbox.buildStepModels(
  { run: { run_id: "run-hostile", status: "FAILED" }, steps: [hostileStep] },
  { status: "FAILED", lanes: [{ index: 0, node_id: "N1", label: hostile }],
    nodes: [{ key: "N1#1", kind: "attempt", plan_node_id: hostile, attempt: 1,
              state: "FAILED", failure: hostile, gate_tier1: hostile, gate_tier2: "" }],
    edges: [], notes: [hostile] },
);
sandbox.renderLane(hostileModels, { status: "FAILED", notes: [hostile] });
const hostileLane = renderMarkup("#lane-track");
noMarkup(hostileLane, "the lane");
check(hostileLane.includes("&lt;img"), "the hostile step name is present, escaped");

const hostileDetail = ["overview", "changes", "gates", "history"].map((tab) => sandbox.renderStepDetail(hostileModels[0], tab)).join("");
noMarkup(hostileDetail, "the step detail panel");
check(hostileDetail.includes("&lt;img"), "the hostile changed-file path is escaped, not dropped");

const hostileActions = actionsFor(hostileModels[0], "AWAITING_APPROVAL");
noMarkup(hostileActions, "the step actions");

noMarkup(sandbox.renderSpecCards({
  specs: [{ key: hostile, title: hostile, subtitle: hostile,
            summary: [[hostile, hostile]], document: { [hostile]: hostile } }],
}), "the planning cards");
noMarkup(sandbox.renderDocument({ [hostile]: [hostile] }), "an expanded document");

noMarkup(sandbox.renderScore({
  score: 50, band: hostile, scale_note: hostile,
  components: [{ key: hostile, label: hostile, value: 0.5, weight: 1, score: 0.5,
                 severity: "warn", detail: hostile, evidence: [hostile] }],
}), "the audit score");

sandbox.renderDiffFor(`--- a/x\n+++ b/x\n+${hostile}\n-${hostile}\n`);
noMarkup(renderMarkup("#diff"), "the diff");
check(!sandbox.colourDiff(`+${hostile}`).includes("<img"),
  "a hostile patch line cannot inject markup into the fallback colourer");

noMarkup(sandbox.renderEventTable([
  { event_type: hostile, detail: hostile, reference: hostile, actor: hostile,
    timestamp: hostile, severity: hostile },
]), "the event table");
check(!sandbox.renderEventTable([
  { event_type: hostile, detail: hostile, reference: hostile, actor: hostile,
    timestamp: hostile, severity: hostile },
]).includes("<img"), "a hostile event field is escaped");

noMarkup(sandbox.renderAuditAnswer({
  run: { created_at: hostile, spec_digest: hostile, base_commit: hostile },
  spec: { approved_by: hostile, approval_verified: false },
  steps: [{ attempt: 1, last_failure: hostile, commit: hostile,
            artifacts: [{ model: hostile, sandbox_image: hostile, changed_files: [hostile] }] }],
}, { nodes: [] }), "the §27 answer");

const hostileGate = sandbox.renderGateChecks({
  checks: [{ name: "01_path_whitelist", passed: false, detail: hostile }], reasons: [hostile],
});
noMarkup(hostileGate, "the gate checks");
noMarkup(sandbox.renderGateChecks({ checks: [], reasons: [hostile] }), "the gate reasons");

// A parked step is what the escalation panel exists for, so it is exercised with hostile text
// rather than skipped.
sandbox.renderEscalations([{ ...hostileStep, state: "ESCALATED", execution_authorization_required: true }], { run_id: "run-hostile", status: "AWAITING_APPROVAL" });
const hostileEscalation = renderMarkup("#escalation-body");
noMarkup(hostileEscalation, "the escalation panel");
check(hostileEscalation.includes("&lt;img"),
  "the hostile escalation reason is escaped, not dropped");

// Goal achievement is separate from step compliance and evidence completeness.
const goalMarkup = sandbox.renderGoalAudit({ status: "ESCALATE", max_stages: 3,
  stages: [{stage: 1, decision: "REVISE", scope: "goal_and_acceptance", commit: "abcdef",
    reasons: ["missing feature"], required_changes: ['<img src=x onerror=alert(1)>']}],
  iterations: [{stage: 2, run_id: "child", exists: true}, {stage: 3, run_id: "not-created", exists: false}],
  stop_reason: "iteration limit reached" });
check(goalMarkup.includes('/execution/child') && !goalMarkup.includes('/execution/not-created'),
  "goal stages link only to persisted child runs");
check(goalMarkup.includes("&lt;img") && !goalMarkup.includes('<img'), "goal feedback is escaped");

// Cross-page interactions: task filtering, real plan graph, audit tabs and event search.
const taskFixtures = [
  {run_id: "one", objective: "Fix login", status: "COMPLETED"},
  {run_id: "two", objective: "Write tests", status: "RUNNING"},
  {run_id: "three", objective: "Review login", status: "AWAITING_APPROVAL"},
];
check(sandbox.filterTasks(taskFixtures, "LOGIN", "done").length === 1,
  "task search combines case-insensitive text with status filtering");
check(sandbox.filterTasks(taskFixtures, "", "attention")[0].run_id === "three",
  "parked tasks appear under needs attention");
elementFor("#board-search").value = "";
elementFor("#board-filter").value = "all";
sandbox.renderRuns({runs: taskFixtures});
check(elementFor("#task-cards").innerHTML.includes('/planning/one'), "task cards preserve run context");
sandbox.renderPlanOverview(payload.plan, payload.detail);
check(elementFor("#plan-map").innerHTML.includes('data-plan-node='), "planning draws actual plan nodes");
check(elementFor("#plan-detail").innerHTML.includes("验收标准"), "plan selection shows verification requirements");
const planButtons = ["start", "finish"].map((id) => {
  const el = new Element("button"); el.dataset.planNode = id; return el;
});
const savedQueryAll = sandbox.document.querySelectorAll;
const savedMapQueryAll = elementFor("#plan-map").querySelectorAll;
elementFor("#plan-map").querySelectorAll = (selector) => selector === "[data-plan-node]" ? planButtons : [];
sandbox.renderPlanOverview({nodes: [
  {node_id: "start", objective: "Prepare", deps: []},
  {node_id: "finish", objective: "Verify result", deps: ["start"], extra: {acceptance_criteria: [{command: "pytest checks"}]}}
]}, {steps: []});
planButtons[1].listeners.click[0]();
check(elementFor("#plan-detail").innerHTML.includes("Verify result") && elementFor("#plan-detail").innerHTML.includes("pytest checks"),
  "clicking a plan node displays its own acceptance criteria");
check(planButtons[1].getAttribute("aria-pressed") === "true" && planButtons[0].getAttribute("aria-pressed") === "false",
  "plan selection highlights exactly the selected node");
elementFor("#plan-map").querySelectorAll = savedMapQueryAll;
check(sandbox.renderIntakePlan({nodes: [{node_id: "x", objective: '<img src=x onerror=alert(1)>', deps: []}]}).includes('&lt;img'), "intake plan escapes model-provided objectives");
const auditButtons = ["result", "changes", "events"].map((name) => {
  const el = new Element("button"); el.dataset.auditTab = name; return el;
});
const auditPanels = ["result", "changes", "events"].map((name) => {
  const el = new Element("section"); el.dataset.auditView = name; return el;
});
const originalQueryAll = sandbox.document.querySelectorAll;
sandbox.document.querySelectorAll = (selector) => selector === "[data-audit-tab]" ? auditButtons
  : selector === "[data-audit-view]" ? auditPanels : [];
sandbox.bindAuditViews();
auditButtons[1].listeners.click[0]();
check(auditPanels[0].hidden && !auditPanels[1].hidden && auditPanels[2].hidden,
  "audit tabs show only the selected panel");
auditButtons[1].listeners.keydown[0]({key: "ArrowRight", preventDefault() {}});
check(!auditPanels[2].hidden && auditButtons[2].tabIndex === 0,
  "audit tabs support arrow-key navigation");
sandbox.document.querySelectorAll = originalQueryAll;
vm.runInContext('AUDIT.events = [{event_type:"StepCommitted", actor:"worker"}, {event_type:"RunCreated", actor:"owner"}]', sandbox);
elementFor("#event-search").value = "worker";
sandbox.renderFilteredEvents();
check(elementFor("#events tbody").innerHTML.includes("StepCommitted") && !elementFor("#events tbody").innerHTML.includes("RunCreated"),
  "event search filters displayed evidence by actor");

/* Boot and drive the unified page with actual API response shapes. */
const wfElements = new Map(), wfHandlers = {}, wfRequests = [];
const wfElement = (selector) => {
  if (!wfElements.has(selector)) {
    const el = new Element(SELECT_IDS.has(selector) ? "select" : "div");
    el.value = ""; el.clientWidth = 920; el.clientHeight = 520;
    wfElements.set(selector, el);
  }
  return wfElements.get(selector);
};
const wfLocation = {href: "http://localhost/", pathname: "/", hash: "", origin: "http://localhost"};
let wfNavigations = 0;
const wfWindow = {history: {replaceState(_state, _title, value) {
  const url = new URL(value, wfLocation.href);
  Object.assign(wfLocation, {href: url.href, pathname: url.pathname, hash: url.hash});
}}};
wfWindow.location = {...wfLocation};
Object.defineProperty(wfWindow.location, "href", {get: () => wfLocation.href, set() { wfNavigations += 1; }});
Object.defineProperty(wfWindow.location, "pathname", {get: () => wfLocation.pathname});
Object.defineProperty(wfWindow.location, "hash", {get: () => wfLocation.hash});
const primary = payload.detail.run.run_id;
const wfData = (path) => {
  if (path === "/api/runs") return {runs: [payload.detail.run, ...(scenario ? [scenario.run] : [])]};
  if (path === "/api/repos") return {repos: payload.intake_repos || []};
  if (path === "/api/model") return payload.model;
  if (path === "/api/specs") return payload.registry;
  if (path === "/api/owners") return payload.owners;
  if (path === "/api/metrics") return payload.metrics;
  if (path === "/api/escalations") return {escalations: []};
  if (path === "/api/alerts") return {alerts: []};
  if (path.startsWith("/api/intakes") && path.endsWith("/freeze")) return {run_id: primary, spec_digest: payload.detail.run.spec_digest};
  if (path.startsWith("/api/intakes")) return {intakes: []};
  const second = scenario && path.startsWith("/api/runs/" + scenario.run.run_id);
  const data = second ? scenario : payload;
  const base = "/api/runs/" + (second ? scenario.run.run_id : primary);
  if (path === base) return second ? scenario.detail : payload.detail;
  if (path === base + "/plan") return data.plan;
  if (path === base + "/route") return data.route;
  if (path === base + "/specs") return data.specs;
  if (path === base + "/audit") return data.audit;
  if (path === base + "/score") return payload.score;
  if (path === base + "/goal-audit") return data.audit.goal_audit;
  if (path === base + "/validations") return second ? scenario.view : payload.audit.independent_validation;
  if (path.includes("/patch")) return payload.patch;
  if (path.includes("/export")) return payload.audit_trail.map((row) => JSON.stringify(row)).join("\n");
  throw new Error("Unexpected workflow request " + path);
};
const wfSandbox = {...sandbox, window: wfWindow, URL, Blob};
wfSandbox.document = {
  addEventListener(type, fn) { wfHandlers[type] = fn; },
  querySelector: (selector) => String(selector).startsWith("#") ? wfElement(selector) : null,
  querySelectorAll: () => [],
  getElementById: (id) => wfElement("#" + id),
  createElement: (tag) => new Element(tag), createElementNS: (_namespace, tag) => new Element(tag),
  body: {dataset: {page: "workflow", initialStage: "task"}}, activeElement: null,
};
wfSandbox.fetch = async (path, options = {}) => {
  wfRequests.push({path: String(path), method: options.method || "GET"});
  const body = wfData(String(path));
  return {ok: true, status: 200, text: async () => typeof body === "string" ? body : JSON.stringify(body)};
};
wfSandbox.globalThis = wfSandbox;
vm.createContext(wfSandbox);
vm.runInContext(source, wfSandbox, {filename: scriptPath});
const wfRead = (expression) => vm.runInContext(expression, wfSandbox);
await wfSandbox.initWorkflow();
await new Promise((resolve) => setTimeout(resolve, 0));
check(wfRead("MODULE_RUN.id") === "", "the new-task page never silently selects a historical run");
check(!wfElement("#workflow-create").hidden && !wfElement("#workflow-plan-empty").hidden,
  "a fresh workflow shows intake and the following-stage placeholders together");
wfElement("#intake-objective").value = "draft retained while refreshing";
await wfSandbox.loadWorkflow();
check(wfElement("#intake-objective").value === "draft retained while refreshing", "polling preserves the unfinished task draft");
wfRead(`INTAKE.session = ${JSON.stringify(payload.intake)}; INTAKE.specs = ${JSON.stringify(payload.intake_specs)}; showIntakeStep("review");`);
check(!wfElement("#workflow-draft-plan").hidden && !wfElement("#intake-step-review").hidden,
  "the reviewed draft opens in the planning stage of the same page");
const requestsBefore = wfRequests.length;
await wfSandbox.freezeIntake();
check(wfNavigations === 0, "freezing the task must never reload or navigate away from the workflow");
check(wfRead("MODULE_RUN.id") === primary, "freezing binds every stage to the accepted run");
check(!wfElement("#workflow-frozen-plan").hidden && !wfElement("#workflow-execution").hidden && !wfElement("#workflow-audit").hidden,
  "planning, execution and audit are all available on the same page after submission");
check(wfLocation.pathname.endsWith(primary) && wfLocation.hash === "#flow-execute", "the accepted run has a refreshable URL focused on execution");
const firstReads = wfRequests.slice(requestsBefore);
check(firstReads.filter((r) => r.path === "/api/runs/" + primary).length === 1,
  "all stages share a single run-detail request during a refresh");
wfElement("#spec-cards").html += "<!-- kept-open evidence -->";
await wfSandbox.loadWorkflow();
check(wfElement("#spec-cards").innerHTML.includes("kept-open evidence"), "unchanged polling preserves expanded spec evidence");
const completedProgress = wfSandbox.workflowProgress(payload.detail.run, payload.audit.goal_audit, payload.audit.independent_validation);
check(completedProgress.current === "audit" && completedProgress.states.execute === "done", "completion naturally leads to audit");
const drifting = wfSandbox.workflowProgress({status: "RUNNING"}, {status: "ITERATING", active_stage: 2});
check(drifting.current === "execute" && drifting.labels.execute.includes("2"), "goal drift returns to execution with the next iteration visible");
const exhausted = wfSandbox.workflowProgress({status: "AWAITING_APPROVAL"}, {status: "ESCALATE", active_stage: 3});
check(exhausted.current === "audit" && exhausted.states.audit === "attention", "three-stage exhaustion calls for audit handling, without inventing another iteration");
if (scenario) {
  await wfSandbox.openWorkflowRun(scenario.run.run_id, "audit");
  const pendingReview = wfSandbox.workflowProgress(scenario.run, scenario.audit.goal_audit, scenario.view);
  check(pendingReview.current === "audit" && pendingReview.labels.audit.includes("独立复核"), "a parked delivery exposes independent review in the audit stage");
  const form = wfElement("#validation-form"), submit = form.onsubmit;
  await wfSandbox.loadWorkflow();
  check(form.onsubmit === submit, "polling does not recreate the review form while the operator is signing");
}
const selectedBeforeLink = wfRead("MODULE_RUN.id");
const oldRequestCount = wfRequests.length;
let prevented = false;
wfHandlers.click({button: 0, target: {closest: () => ({href: "http://localhost/planning/" + selectedBeforeLink, target: "", hasAttribute: () => false})},
  preventDefault() {prevented = true;}});
check(prevented && wfLocation.hash === "#flow-plan" && wfRead("MODULE_RUN.id") === selectedBeforeLink,
  "links between modules become in-page stage navigation and retain the selected task");
check(wfRequests.length === oldRequestCount, "moving between stages needs no extra page or task fetch");
let nativeAnchorPrevented = false;
wfHandlers.click({button: 0, target: {closest: () => ({href: wfLocation.origin + wfLocation.pathname + "#flow-audit", target: "", hasAttribute: () => false})},
  preventDefault() {nativeAnchorPrevented = true;}});
check(!nativeAnchorPrevented, "the audit stage anchor keeps native in-page scrolling instead of being redirected to execution");
check(wfNavigations === 0, "the full workflow needs zero full-page navigations");
wfSandbox.renderWorkflowLoop({status: "UNAVAILABLE", stop_reason: "historical task has no goal audit"});
if (scenario) {
  const fetchBeforeDelay = wfSandbox.fetch;
  let releaseOlderAudit, olderAuditStarted;
  const started = new Promise((resolve) => { olderAuditStarted = resolve; });
  const blocked = new Promise((resolve) => { releaseOlderAudit = resolve; });
  let delayed = false;
  wfSandbox.fetch = async (path, options) => {
    if (!delayed && path === "/api/runs/" + primary + "/audit") {
      delayed = true; olderAuditStarted(); await blocked;
    }
    return fetchBeforeDelay(path, options);
  };
  const scrolled = [];
  wfElement("#flow-audit").scrollIntoView = () => scrolled.push("audit");
  wfElement("#flow-execute").scrollIntoView = () => scrolled.push("execute");
  const older = wfSandbox.openWorkflowRun(primary, "execute");
  await started;
  await wfSandbox.openWorkflowRun(scenario.run.run_id, "audit");
  releaseOlderAudit(); await older;
  check(wfRead("WORKFLOW.run.run_id") === scenario.run.run_id && wfRead("MODULE_RUN.id") === scenario.run.run_id,
    "a slow response from a previous selection cannot replace the current task");
  check(scrolled.slice(-1)[0] === "audit", "a slow previous selection cannot scroll away from the current task's stage");
  wfSandbox.fetch = fetchBeforeDelay;
}

// The model manager must apply imported role configs, not merely render a form.
const originalModelFetch = sandbox.fetch;
const modelRequests = [];
const importSecret = "opaque-test-only-model-key";
const roleReport = {roles:[{role:"coder",model:"native-model",base_url:"https://api.example.com/v1",source:"界面填写（只在内存里）",key:"内存密钥 · 指纹 abc123",api_format:"anthropic",provider:"anthropic",loopback:false}],supported_api_formats:["openai_chat","openai_responses","anthropic","gemini"],overrides:{}};
sandbox.renderModelPanel(roleReport);
sandbox.fetch = async (path, options={}) => {
  modelRequests.push({path:String(path),body:options.body ? JSON.parse(options.body) : null});
  const body = String(path).endsWith("/preview") ? {profiles:[{role:"coder",model:"native-model",base_url:"https://api.example.com/v1",api_format:"anthropic",key_set:true}],remote_hosts:["api.example.com"]} : roleReport;
  return {ok:true,status:200,text:async () => JSON.stringify(body)};
};
await sandbox.previewModelImport(JSON.stringify({provider:"anthropic",model:"native-model",api_key:importSecret}),"json");
check(renderMarkup("#model-import-preview-box").includes("native-model"),"import preview shows the actual model before applying");
check(!renderMarkup("#model-import-preview-box").includes(importSecret),"import preview never renders an API key");
elementFor("#model-import-ack").checked=true;
elementFor("#model-import-content").value=importSecret;
await sandbox.applyModelImport();
check(modelRequests.some((request) => request.path==="/api/model/import" && request.body.acknowledge_remote===true),"applying an import sends the operator's remote acknowledgement");
check(elementFor("#model-import-content").value==="","import source is cleared after apply");
check(read("MODEL_IMPORT === null"),"imported credentials are released from pending frontend state");
sandbox.fetch=originalModelFetch;

// Recovery reminders are passive. Saving a human review must not resume a task.
const serviceRequests = [];
const recoveryView = {run_id:"interrupted",status:"AWAITING_APPROVAL",checkpoint_digest:"checkpoint-v1",integration_head:"verified-commit",last_verified_node:"first",verified_nodes:["first"],frontier:[{node_id:"second",objective:"finish later",state:"PENDING"}],blockers:[],busy:false};
sandbox.renderServicePanel({session_id:"session-old",control:{managed:false},reminders:[recoveryView]});
check(elementFor("#service-stop").disabled,"an unmanaged legacy service is never stopped through the new UI");
check(renderMarkup("#service-reminders").includes("interrupted"),"startup reminders show the interrupted task");
sandbox.fetch=async (path, options={}) => {
  serviceRequests.push({path:String(path),method:options.method || "GET",body:options.body ? JSON.parse(options.body) : null});
  return {ok:true,status:200,text:async()=>JSON.stringify(String(path).endsWith("/recovery") ? recoveryView : {accepted:true,automatic_resume:false})};
};
await sandbox.openRecoveryCheckpoint("interrupted");
check(renderMarkup("#recovery-checkpoint").includes("verified-commit"),"the reviewer sees the verified integration commit");
check(renderMarkup("#recovery-checkpoint").includes("finish later"),"the reviewer sees the real continuation frontier");
elementFor("#recovery-confirm").checked=false;
await sandbox.reviewRecovery(true);
check(!serviceRequests.some((r)=>r.method==="POST"),"a reminder and unchecked review never dispatch work");
elementFor("#recovery-reviewer").value="operator";
elementFor("#recovery-confirm").checked=true;
await sandbox.reviewRecovery(false);
check(serviceRequests.some((r)=>r.path.endsWith("/recovery-review")&&r.body.checkpoint_digest==="checkpoint-v1"),"review pins the exact checkpoint digest");
check(!serviceRequests.some((r)=>r.path.endsWith("/resume")),"saving a reminder or review alone keeps work parked");
await sandbox.reviewRecovery(true);
check(serviceRequests.slice(-2).map((r)=>r.path).join(",")==="/api/runs/interrupted/recovery-review,/api/runs/interrupted/resume","continuation follows explicit human review");
sandbox.fetch=originalModelFetch;

return {
  steps: models.length,
  step_boxes: (lane.match(/class="lane-node/g) || []).length,
  attempts: attemptNodes.length,
  retry_edges: retryEdges.length,
  spec_cards: cards.length,
  score: score.score,
  score_band: score.band,
  score_components: (score.components || []).length,
  checks: gated.reduce((total, gate) => total + (gate.checks || []).length, 0),
  diff_lines: patch.split("\n").length,
  events: trail.length,
  markup_bytes: lane.length + stats.length + detailMarkup.length + cardsMarkup.length
    + scoreMarkup.length + diffMarkup.length + auditMarkup.length + trailMarkup.length,
  workflow_verified: true,
  independent_validation_rendered: Boolean(scenario),
  owners: (payload.owners.owners || []).length,
  owners_enforced: Boolean(payload.owners.enforced),
  executions: (payload.executions.executions || []).length,
  workers: (payload.workers.workers || []).length,
  diff2html: diff2htmlLoaded,
  intake_questions: intakeQuestions.length,
  intake_options: first.options.length,
  intake_repos: (payload.intake_repos || []).length,
  intake_specs: reviewSpecs.length,
  model_roles: model.roles.length,
  booted_intake: booted.includes("/api/repos") && booted.includes("/api/model"),
  failures,
};
}

/* ---------------------------------------------------------------- report */

let report = {
  steps: 0, step_boxes: 0, attempts: 0, checks: 0, diff_lines: 0, markup_bytes: 0, failures,
};
// `runChecks` is async because the boot check has to let the page's initialiser finish its
// fetches: firing DOMContentLoaded and asserting immediately would assert against a page that
// has not started.
(async () => {
  try {
    report = await runChecks();
  } catch (error) {
    failures.push(`the render check threw: ${error.message}\n${error.stack}`);
    report.failures = failures;
  }
  console.log(JSON.stringify(report, null, 2));
  process.exit(failures.length ? 1 : 0);
})();
