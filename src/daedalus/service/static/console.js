/* Daedalus console.
 *
 * Vanilla JS with silent polling, no build step and no framework. The reason is
 * deployment: `pip install` is the only install step, so there is no Node toolchain in the
 * trusted path and nothing to rebuild when the Python side changes. Polling beats
 * websockets here because the poll interval is the operator's tolerance for staleness,
 * not a liveness requirement — and a dropped poll must not look like a dropped system.
 */
"use strict";

const POLL_MS = 2000;
let pollTimer = null;

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[ch]);
}

function shortDigest(value, length = 12) {
  const text = String(value ?? "");
  return text ? text.slice(0, length) : "—";
}

function pill(value) {
  const text = String(value ?? "—");
  return `<span class="pill ${escapeHtml(text)}">${escapeHtml(text)}</span>`;
}

function api(path, options = {}) {
  const reads = isWorkflow() ? WORKFLOW.reads : null;
  if (!reads || (options.method && options.method !== "GET")) return requestApi(path, options);
  if (!reads.has(path)) reads.set(path, requestApi(path, options));
  return reads.get(path);
}

async function requestApi(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (_) { body = { raw: text }; }
  if (!response.ok) {
    // `detail` may be an object: the intake endpoints return a machine-readable rejection
    // (a message plus the list of questions the control plane refused). Passing that straight
    // to `new Error` produced "[object Object]" in the UI, so the structured detail is kept on
    // the error and the message is the readable part of it.
    const detail = (body && body.detail) || (body && body.error && body.error.message) || text;
    const readable = typeof detail === "string"
      ? detail
      : (detail && detail.message) || `HTTP ${response.status}`;
    const error = new Error(readable || `HTTP ${response.status}`);
    error.status = response.status;
    error.detail = detail;
    error.body = body;
    throw error;
  }
  return body;
}

function showError(target, error) {
  const node = typeof target === "string" ? $(target) : target;
  if (!node) return;
  if (!error) { node.hidden = true; node.textContent = ""; return; }
  node.hidden = false;
  node.textContent = error.message || String(error);
}

function startPolling(tick) {
  const toggle = $("#auto-refresh");
  const run = async () => {
    try { await tick(); } catch (error) { showError("#board-error", error); }
    if (toggle && toggle.checked) pollTimer = setTimeout(run, POLL_MS);
  };
  if (toggle) toggle.addEventListener("change", () => {
    clearTimeout(pollTimer);
    if (toggle.checked) run();
  });
  const manual = $("#refresh");
  if (manual) manual.addEventListener("click", run);
  run();
}

/* ------------------------------------------------------------------ badge */

async function refreshBadge() {
  try {
    const [escalations, alerts] = await Promise.all([
      api("/api/escalations"), api("/api/alerts"),
    ]);
    const badge = $("#escalation-badge");
    if (badge) {
      const count = (escalations.escalations || []).length;
      badge.hidden = count === 0;
      badge.textContent = String(count);
    }
    const alertBadge = $("#alert-badge");
    if (alertBadge) {
      const active = (alerts.alerts || []).filter((a) => a.severity !== "info").length;
      alertBadge.hidden = active === 0;
      alertBadge.textContent = String(active);
      alertBadge.className = `badge ${alerts.worst === "critical" ? "badge-critical" : ""}`;
      alertBadge.title = (alerts.alerts || []).map((a) => a.summary).join("\n");
    }
  } catch (_) { /* the badges are decorative; a failure must not break the page */ }
}

/* ------------------------------------------------------------------ board */

function renderRuns(data) {
  const body = $("#runs tbody");
  const runs = data.runs || [];
  BOARD.runs = runs;
  renderTaskCards();
  if (!runs.length) {
    body.innerHTML = `<tr><td colspan="6" class="muted">这个工作区还没有 run 记录。</td></tr>`;
    return;
  }
  body.innerHTML = runs.slice().reverse().map((run) => {
    const total = Object.values(run.steps || {}).reduce((sum, n) => sum + n, 0);
    const committed = (run.steps || {}).COMMITTED || 0;
    const percent = total ? Math.round((committed / total) * 100) : 0;
    const steps = Object.entries(run.steps || {})
      .map(([state, count]) => `${escapeHtml(state)}:${count}`).join("  ") || "—";
    return `<tr>
      <td><a href="/execution/${encodeURIComponent(run.run_id)}">${escapeHtml(run.objective || run.goal_id)}</a><br><code class="muted">${escapeHtml(shortDigest(run.run_id, 20))}</code>
          ${run.active ? '<span class="pill RUNNING">进行中</span>' : ""}</td>
      <td>${escapeHtml(run.goal_id)}</td>
      <td>${pill(run.status)}</td>
      <td class="progress-cell">
        <div class="bar"><span style="width:${percent}%"></span></div>
        <span class="muted">${committed}/${total}</span>
      </td>
      <td class="mono" title="${escapeHtml(steps)}">${escapeHtml(shortDigest(run.spec_digest))}</td>
      <td class="muted">${escapeHtml(run.updated_at || "")}</td>
    </tr>`;
  }).join("");
}

function initBoard() {
  for (const id of ["#board-search", "#board-filter"]) {
    const input = $(id);
    if (input) input.addEventListener("input", renderTaskCards);
  }
  const form = $("#new-run");
  if (form) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      const payload = {
        repo_path: data.get("repo_path"),
        goal_id: data.get("goal_id") || "GOAL-001",
        objective: data.get("objective"),
        target_paths: String(data.get("target_paths") || "")
          .split(",").map((s) => s.trim()).filter(Boolean),
        test_command: data.get("test_command"),
        risk_level: data.get("risk_level") || "normal",
        use_model: data.get("use_model") === "on",
        enable_review: data.get("enable_review") === "on",
        approve_spec_by: data.get("approve_spec_by") || "",
      };
      const button = $("button[type=submit]", form);
      button.disabled = true;
      try {
        const receipt = await api("/api/runs", { method: "POST", body: JSON.stringify(payload) });
        showError("#board-error", null);
        window.location.href = `/runs/${encodeURIComponent(receipt.run_id)}`;
      } catch (error) {
        showError("#board-error", error);
      } finally {
        button.disabled = false;
      }
    });
  }
  startPolling(async () => {
    try { renderRuns(await api("/api/runs")); showError("#board-error", null); }
    catch (error) { showError("#board-error", error); }
    try { renderMetricBars(await api("/api/metrics")); } catch (_) { /* optional panel */ }
    await refreshBadge();
  });
}

/* ------------------------------------------------------------- diff viewer */

function colourDiff(patch) {
  return patch.split("\n").map((line) => {
    let cls = "diff-ctx";
    if (line.startsWith("+++") || line.startsWith("---")) cls = "diff-file";
    else if (line.startsWith("@@")) cls = "diff-hunk";
    else if (line.startsWith("+")) cls = "diff-add";
    else if (line.startsWith("-")) cls = "diff-del";
    return `<span class="${cls}">${escapeHtml(line)}</span>`;
  }).join("\n");
}

/* ------------------------------------------------- Tier-1 check breakdown */

function renderGateChecks(gate) {
  const checks = gate.checks || [];
  if (!checks.length) {
    return (gate.reasons || []).map((r) => `<div class="reason">${escapeHtml(r)}</div>`).join("");
  }
  return `<div class="checks">${checks.map((check) => `
    <div class="check ${check.passed ? "check-pass" : "check-fail"}"
         title="${escapeHtml(check.detail || "")}">
      <span class="check-mark">${check.passed ? "✓" : "✗"}</span>
      <span class="check-name">${escapeHtml(check.name)}</span>
      ${check.detail ? `<span class="check-detail">${escapeHtml(String(check.detail).slice(0, 240))}</span>` : ""}
    </div>`).join("")}</div>`;
}

/* ------------------------------------------------------- metric bar chart */

function renderMetricBars(metrics, containerId) {
  const container = $(containerId || "#metrics-bars");
  if (!container) return;
  const rows = [
    ["step success", metrics.step_success_rate],
    ["task success", metrics.task_success_rate],
    ["retry rate", metrics.retry_rate],
    ["gate reject", metrics.gate_reject_rate],
    ["rollback", metrics.rollback_rate],
  ];
  container.innerHTML = rows.map(([label, value]) => {
    const ratio = Math.min(1, Math.max(0, value || 0));
    return `<div class="metric-row">
      <span class="metric-label">${escapeHtml(label)}</span>
      <div class="bar"><span style="width:${Math.round(ratio * 100)}%"></span></div>
      <span class="metric-value">${((value || 0) * 100).toFixed(0)}%</span>
    </div>`;
  }).join("");
}

/* --------------------------------------------------------- escalation age */

function timeAgo(iso) {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "";
  const minutes = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h`;
  return `${Math.round(hours / 24)}d`;
}

function renderEscalations(steps, run) {
  const panel = $("#escalation-panel");
  const body = $("#escalation-body");
  if (!panel || !body) return;
  if (run.status !== "AWAITING_APPROVAL") {
    panel.hidden = true;
    body.innerHTML = "";
    return;
  }
  const escalated = steps.filter((step) => step.execution_authorization_required === true);
  if (!escalated.length) { panel.hidden = true; return; }
  panel.hidden = false;

  body.innerHTML = escalated.map((step) => {
    const artifact = (step.artifacts || []).slice(-1)[0] || {};
    const gate = (step.gates || []).slice(-1)[0] || {};
    const missing = !artifact.artifact_digest;
    return `<div class="escalation" data-step="${escapeHtml(step.step_id)}">
      <div class="step-head">
        <strong>${escapeHtml(step.node_id)}</strong>
        ${pill(step.state)}
        <span class="muted">第 ${escapeHtml(step.attempt)}/${escapeHtml(step.max_attempts)} 次尝试</span>
        <span class="muted">artifact <code>${escapeHtml(shortDigest(artifact.artifact_digest))}</code></span>
      </div>
      <div class="why">${escapeHtml((gate.reasons || []).join(" | ") || step.last_failure || "")}</div>
      ${missing
        ? `<p class="muted">这一步没有产出 artifact，因此没有东西可以被"接受"。
             有意义的答复只有重试或打回。</p>`
        : ""}
      <div class="actions">
        <input class="by" placeholder="姓名（会写进审计）" aria-label="谁做的决定" />
        <input class="note" placeholder="备注（可选）" aria-label="决定备注" />
        <input class="signature" placeholder="审批签名（工作区要求时填写）" aria-label="审批签名" />
        ${missing ? "" : `<button class="proceed">接受并提交</button>`}
        <button class="retry ghost">重试（+1 次尝试）</button>
        <button class="reject danger ghost">打回</button>
      </div>
      <div class="result muted"></div>
    </div>`;
  }).join("");

  $$(".escalation", body).forEach((node) => {
    const stepId = node.dataset.step;
    const decide = async (decision) => {
      const by = $(".by", node).value.trim();
      const note = $(".note", node).value.trim();
      const signatureField = $(".signature", node);
      const signature = signatureField ? signatureField.value.trim() : "";
      const out = $(".result", node);
      // An approval is evidence about who decided, so an unnamed decision is not recorded at all
      // rather than recorded as "anonymous".
      if (!by) { out.textContent = "审批必须写明是谁做的决定"; return; }
      try {
        const result = await api(`/api/runs/${encodeURIComponent(run.run_id)}/approve`, {
          method: "POST",
          body: JSON.stringify({ step: stepId, decision, approved_by: by, note, signature }),
        });
        out.textContent = `已记录 ${result.decision}；正在恢复 run`;
        await api(`/api/runs/${encodeURIComponent(run.run_id)}/resume`, { method: "POST" });
        out.textContent = `已记录 ${result.decision}，run 已恢复`;
      } catch (error) {
        out.textContent = error.message;
      }
    };
    const proceed = $(".proceed", node);
    if (proceed) proceed.addEventListener("click", () => decide("proceed"));
    $(".retry", node).addEventListener("click", () => decide("retry"));
    $(".reject", node).addEventListener("click", () => decide("reject"));
  });
}

/* ------------------------------------------------------------ escalations */

async function decideEscalation(runId, stepId, decision, by, note, out) {
  if (!by) { out.textContent = "审批必须写明是谁做的决定"; return; }
  try {
    await api(`/api/runs/${encodeURIComponent(runId)}/approve`, {
      method: "POST",
      body: JSON.stringify({ step: stepId, decision, approved_by: by, note }),
    });
    await api(`/api/runs/${encodeURIComponent(runId)}/resume`, { method: "POST" });
    out.textContent = `已记录 ${decision}，run 已恢复`;
  } catch (error) {
    out.textContent = error.message;
  }
}

function initEscalations() {
  startPolling(async () => {
    const data = await api("/api/escalations");
    const items = data.escalations || [];
    const container = $("#escalations");
    if (!items.length) {
      container.innerHTML = `<p class="muted">目前没有等待 owner 决定的 step。</p>`;
      await refreshBadge();
      return;
    }
    container.innerHTML = items.map((item) => `
      <div class="escalation" data-run="${escapeHtml(item.run_id)}" data-step="${escapeHtml(item.step_id)}">
        <div class="step-head">
          <strong>${escapeHtml(item.node_id)}</strong>
          <span class="muted">run <a href="/runs/${encodeURIComponent(item.run_id)}">${escapeHtml(shortDigest(item.run_id, 20))}</a></span>
          ${pill(item.run_status)}
          <span class="muted">risk ${escapeHtml(item.risk_level || "—")} · attempt ${item.attempt}</span>
          ${item.waiting_since ? `<span class="muted">waiting ${escapeHtml(timeAgo(item.waiting_since))}</span>` : ""}
          <span class="muted">artifact <code>${escapeHtml(shortDigest(item.artifact_digest))}</code></span>
        </div>
        <div class="why">${escapeHtml(item.last_failure || "")}</div>
        <div class="actions">
          <input class="by" placeholder="姓名（会写进审计）" />
          <input class="note" placeholder="备注（可选）" />
          ${item.artifact_digest ? `<button class="proceed">接受并提交</button>` : ""}
          <button class="retry ghost">重试（+1 次尝试）</button>
          <button class="reject danger ghost">打回</button>
        </div>
        <div class="result muted"></div>
      </div>`).join("");

    $$(".escalation", container).forEach((node) => {
      const runId = node.dataset.run;
      const stepId = node.dataset.step;
      const out = $(".result", node);
      const fire = (decision) =>
        decideEscalation(runId, stepId, decision, $(".by", node).value.trim(), $(".note", node).value.trim(), out);
      const proceed = $(".proceed", node);
      if (proceed) proceed.addEventListener("click", () => fire("proceed"));
      $(".retry", node).addEventListener("click", () => fire("retry"));
      $(".reject", node).addEventListener("click", () => fire("reject"));
    });
    await refreshBadge();
  });
}

/* ------------------------------------------------------------- operations */

function renderIsolation(payload) {
  const target = $("#isolation-out");
  if (!target) return;
  const rows = (payload.drivers || []).map((d) => {
    const caps = Object.entries(d.capabilities || {})
      .map(([name, c]) => `${name}=${c.enforced ? "yes" : "NO"}`).join("  ");
    return `<div class="gate">${d.available ? "✓" : "×"} <strong>${escapeHtml(d.driver)}</strong>
        <span class="muted">${escapeHtml(caps)}</span>
        ${d.available ? "" : `<div class="reason">${escapeHtml(d.detail || "")}</div>`}</div>`;
  }).join("");
  const gaps = (payload.gaps || []).length
    ? `<div class="reason severity-warning">${payload.gaps.map(escapeHtml).join("<br>")}</div>`
    : `<div class="muted">没有报告缺口</div>`;
  target.innerHTML = `
    <dl class="kv">
      <dt>选中的驱动</dt><dd><strong>${escapeHtml(payload.selected)}</strong>
        — ${escapeHtml(payload.selected_reason || "")}</dd>
      <dt>已探测的驱动</dt><dd>${rows}</dd>
      <dt>已知缺口</dt><dd>${gaps}</dd>
    </dl>`;
}

function renderAlerts(payload) {
  const target = $("#alerts-out");
  if (!target) return;
  const active = (payload.alerts || []).filter((a) => a.severity !== "info");
  if (!active.length) {
    target.innerHTML = `<span class="muted">健康：已评估 ${(payload.evaluated || []).length} 条规则，没有活跃告警</span>`;
    return;
  }
  target.innerHTML = active.map((a) => `
    <div class="gate severity-${a.severity === "critical" ? "error" : "warning"}">
      [${escapeHtml(a.severity)}] <strong>${escapeHtml(a.rule)}</strong>: ${escapeHtml(a.summary)}
      ${a.action ? `<div class="reason">→ ${escapeHtml(a.action)}</div>` : ""}
    </div>`).join("");
}

function renderIdentity(identity) {
  const container = $("#identity-out");
  if (!container) return;
  const enforced = Boolean(identity.enforced);
  container.innerHTML = `
    <dl class="kv">
      <dt>审批是否验签</dt>
      <dd>${enforced
        ? `<span class="check-pass">✓ 已强制</span> —— 审批必须是一个能验通的签名`
        : `<span class="check-fail">未强制</span> —— 审批只是记录下来的一个名字`}</dd>
      <dt>Owners</dt>
      <dd>${escapeHtml(identity.owners_enrolled ?? 0)} 在位，
        历史注册 ${escapeHtml(identity.owners_ever_registered ?? 0)} 人
        ${identity.required_by_config ? " · 由配置强制要求" : ""}</dd>
      <dt>签名方案</dt>
      <dd><code>${escapeHtml(identity.scheme || "—")}</code></dd>
      <dt>为什么</dt>
      <dd class="muted">${escapeHtml(identity.note || "")}</dd>
    </dl>
    ${(identity.owners || []).length ? `<table class="table">
      <thead><tr><th>Owner</th><th>角色</th><th>签名方式</th><th>密钥指纹</th><th>已撤销</th></tr></thead>
      <tbody>${identity.owners.map((o) => `<tr>
        <td>${escapeHtml(o.owner_id)}</td>
        <td>${escapeHtml(o.role)}</td>
        <td class="muted mono">${escapeHtml(o.secret_env || "—")}</td>
        <td class="mono">${escapeHtml(shortDigest(o.key_fingerprint, 16))}</td>
        <td class="muted">${escapeHtml(o.revoked_at || "") || "—"}</td>
      </tr>`).join("")}</tbody></table>` : ""}`;
}

function renderExecutions(payload) {
  const body = $("#executions tbody");
  if (!body) return;
  const rows = payload.executions || [];
  body.innerHTML = rows.map((e) => `<tr>
    <td class="mono">${escapeHtml(shortDigest(e.execution_id, 18))}</td>
    <td class="mono">${escapeHtml(shortDigest(e.run_id, 18))}</td>
    <td>${escapeHtml(e.kind)}${e.parent_execution_id
      ? ` <span class="muted">← ${escapeHtml(shortDigest(e.parent_execution_id, 12))}</span>` : ""}</td>
    <td>${pill(e.status)}</td>
    <td>${escapeHtml(e.step_committed ?? 0)}/${escapeHtml(e.step_total ?? 0)}${
      Number(e.step_failed || 0) ? ` <span class="check-fail">${escapeHtml(e.step_failed)} 失败</span>` : ""}</td>
    <td class="muted">${escapeHtml(e.started_at || "—")}</td>
  </tr>`).join("") || `<tr><td colspan="6" class="muted">没有 execution 记录</td></tr>`;
}

function renderWorkers(payload) {
  const body = $("#workers tbody");
  if (!body) return;
  const rows = payload.workers || [];
  body.innerHTML = rows.map((w) => `<tr>
    <td class="mono">${escapeHtml(w.worker_id)}</td>
    <td>${escapeHtml(w.kind)}${w.kind === "unregistered"
      ? ` <span class="check-fail" title="有 step 记录指明这个 worker，但它从未注册过">!</span>` : ""}</td>
    <td>${pill(w.status || "UNKNOWN")}</td>
    <td>${escapeHtml(w.steps_started ?? 0)}</td>
    <td>${escapeHtml(w.steps_committed ?? 0)}</td>
    <td>${Number(w.steps_failed || 0) ? `<span class="check-fail">${escapeHtml(w.steps_failed)}</span>` : "0"}</td>
    <td class="muted">${escapeHtml(timeAgo(w.last_heartbeat_at) || "—")}</td>
  </tr>`).join("") || `<tr><td colspan="7" class="muted">没有 worker 记录</td></tr>`;
}

function initOperations() {
  const load = async () => {
    const [health, config, metrics, backups, isolation, alerts, identity, executions, workers] =
      await Promise.all([
        api("/api/health"), api("/api/config"), api("/api/metrics"), api("/api/backups"),
        api("/api/isolation"), api("/api/alerts"), api("/api/owners"),
        api("/api/executions"), api("/api/workers"),
      ]);
    renderIsolation(isolation);
    renderAlerts(alerts);
    renderIdentity(identity);
    renderExecutions(executions);
    renderWorkers(workers);
    renderMetricBars(metrics, "#metrics-bars");
    $("#health-kv").innerHTML = Object.entries(health).map(([k, v]) =>
      `<dt>${escapeHtml(k)}</dt><dd><code>${escapeHtml(typeof v === "object" ? JSON.stringify(v) : v)}</code></dd>`
    ).join("");
    $("#config").textContent = JSON.stringify(config, null, 2);
    $("#metrics").textContent = JSON.stringify(metrics, null, 2);
    $("#backups tbody").innerHTML = (backups.backups || []).map((b) => `<tr>
      <td class="mono">${escapeHtml(b.path)}</td>
      <td>${escapeHtml(b.events ?? "—")}</td>
      <td>${escapeHtml(b.integrity ?? "—")}${b.verified ? " ✓" : ""}</td>
      <td class="muted">${escapeHtml(b.created_at ?? "—")}</td>
    </tr>`).join("") || `<tr><td colspan="4" class="muted">没有快照</td></tr>`;
  };

  const dry = $("#recover-dry");
  if (dry) dry.addEventListener("click", async () => {
    try {
      const report = await api("/api/recover?apply=false", { method: "POST" });
      $("#recover-out").innerHTML = report.findings
        ? `<pre class="code">${escapeHtml(JSON.stringify(report, null, 2))}</pre>`
        : "没有发现：工作区一致";
    } catch (error) { $("#recover-out").textContent = error.message; }
  });

  const repair = $("#recover-apply");
  if (repair) repair.addEventListener("click", async () => {
    try {
      const report = await api("/api/recover?apply=true", { method: "POST" });
      $("#recover-out").innerHTML =
        `<pre class="code">${escapeHtml(JSON.stringify(report, null, 2))}</pre>`;
    } catch (error) { $("#recover-out").textContent = error.message; }
  });

  const create = $("#backup-create");
  if (create) create.addEventListener("click", async () => {
    try {
      const result = await api(`/api/backup?label=${encodeURIComponent($("#backup-label").value)}`,
        { method: "POST" });
      $("#backup-out").innerHTML = result.verified
        ? `verified snapshot at <code>${escapeHtml(result.path)}</code> (${result.events} events, integrity ${escapeHtml(result.integrity)})`
        : `<span class="severity-error">snapshot failed verification</span>`;
      await load();
    } catch (error) { $("#backup-out").textContent = error.message; }
  });

  load();
  setInterval(load, 5000);
}

/* ------------------------------------------------------------------ boot */

/*: Every page a template can render, mapped to the function that initialises it.
 *
 * This is a table rather than an if-chain with an `else`, because the `else` is what broke the
 * intake page: the boot block only routed planning/execution/audit, everything else fell through
 * to `initBoard()`, and the intake therefore ran *no* JavaScript at all — its buttons, its
 * repository cards and its model panel were all dead in a browser while every test passed,
 * because no test asserted that the page's own initialiser had been reached.
 *
 * A page with no entry here now throws, so the next missing wiring is loud on first load. */
const PAGE_INITIALISERS = {
  workflow: () => initWorkflow(),
  intake: () => initIntake(),
  board: () => initBoard(),
  escalations: () => initEscalations(),
  operations: () => initOperations(),
  planning: () => initModule(),
  execution: () => initModule(),
  audit: () => initModule(),
};

document.addEventListener("DOMContentLoaded", () => {
  initModelPanel();
  initServicePanel();
  const page = document.body.dataset.page ||
    (window.DAEDALUS_RUN_ID ? "execution" : "board");
  const initialise = PAGE_INITIALISERS[page];
  // Every error container on the page, because which one exists depends on the page and a
  // failure that renders nowhere is a failure nobody sees.
  const report = (error) => {
    for (const target of ["#intake-error", "#planning-error", "#execution-error",
                          "#audit-error", "#board-error", "#esk-error", "#workflow-error"]) {
      showError(target, error);
    }
    if (typeof console !== "undefined" && console.error) console.error(error);
  };
  if (!initialise) {
    report(new Error(`这个页面 (${page}) 没有对应的初始化函数，界面不会工作`));
    return;
  }
  try {
    // `initModule` and the intake are async; a rejection is reported rather than swallowed, so a
    // broken panel is visible instead of silently empty.
    Promise.resolve(initialise()).catch(report);
  } catch (error) {
    report(error);
  }
});

let SERVICE_REPORT = null;
let RECOVERY_CHECKPOINT = null;
function serviceMessage(message, bad = false) {
  const out = $("#service-out"); if (!out) return;
  out.hidden = false; out.className = bad ? "callout bad" : "callout"; out.textContent = message;
}
function renderServicePanel(report) {
  SERVICE_REPORT = report;
  const control = report.control || {};
  if ($("#service-summary")) $("#service-summary").textContent = control.managed ? "服务已由终端控制台托管。重启只恢复服务，中断任务等待人工审查。" : "当前服务使用旧启动方式。通过终端运行 daedalus 开启后，可在这里控制服务。";
  for (const id of ["#service-stop", "#service-restart"]) if ($(id)) $(id).disabled = !control.managed || report.status === "stopping";
  if ($("#service-reminders")) {
    $("#service-reminders").innerHTML = (report.reminders || []).map((item) => `<article class="recovery-card"><div><strong>${escapeHtml(item.run_id)}</strong><small>${escapeHtml(item.status)} · 已验证 ${item.verified_nodes.length} 个节点 · 待续 ${item.frontier.length} 个节点</small></div><button type="button" class="ghost small" data-recovery-open="${escapeHtml(item.run_id)}">查看并审查</button></article>`).join("") || '<p class="muted">没有启动时遗留的中断任务。正在执行的任务会在停止时保存断点。</p>';
    $$('[data-recovery-open]', $("#service-reminders")).forEach((button) => button.addEventListener("click", () => openRecoveryCheckpoint(button.dataset.recoveryOpen)));
  }
}
async function openServicePanel() {
  const dialog = $("#service-dialog"); if (!dialog) return;
  if (dialog.showModal && !dialog.open) dialog.showModal(); else dialog.setAttribute("open", "");
  try { renderServicePanel(await requestApi("/api/service")); }
  catch (error) { serviceMessage("后端尚未加载新版服务管理。请在终端运行 daedalus 启动新版服务。" + error.message, true); }
}
async function controlService(action) {
  try {
    for (const id of ["#service-stop", "#service-restart"]) if ($(id)) $(id).disabled = true;
    const result = await requestApi("/api/service/control", {method: "POST", headers: {"Content-Type": "application/json", "X-Daedalus-Control": "1"}, body: JSON.stringify({action, note: $("#service-stop-note")?.value || ""})});
    serviceMessage(result.message + (action === "stop" ? "关闭后可在终端用 daedalus 重新开启。" : "服务重新就绪后将刷新页面，任务不会自动继续。"));
    if (action === "restart") waitForServiceRestart(SERVICE_REPORT?.session_id);
  } catch (error) { serviceMessage(error.message, true); if (SERVICE_REPORT) renderServicePanel(SERVICE_REPORT); }
}
async function waitForServiceRestart(previous) {
  for (let count = 0; count < 120; count++) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    try {
      const response = await fetch("/api/health", {cache: "no-store"});
      const health = await response.json();
      if (health.service_session_id && health.service_session_id !== previous) { window.location.reload(); return; }
    } catch (_) { /* The service is intentionally offline while restarting. */ }
  }
  serviceMessage("仍在等待当前步骤批次保存或服务启动。稍后刷新页面即可；不要强制结束任务。", true);
}
async function openRecoveryCheckpoint(runId) {
  try {
    const view = await requestApi(`/api/runs/${encodeURIComponent(runId)}/recovery`);
    RECOVERY_CHECKPOINT = view;
    if ($("#recovery-review-panel")) $("#recovery-review-panel").hidden = false;
    if ($("#recovery-confirm")) $("#recovery-confirm").checked = false;
    if ($("#recovery-checkpoint")) $("#recovery-checkpoint").innerHTML = `<p><strong>${escapeHtml(view.run_id)}</strong> · ${escapeHtml(view.status)}</p><p>最近已验证节点：<code>${escapeHtml(view.last_verified_node || "尚无提交")}</code></p><p>保留的集成提交：<code>${escapeHtml(view.integration_head || "不可用")}</code></p><ul>${view.frontier.map((node) => `<li>${escapeHtml(node.node_id)} · ${escapeHtml(node.objective)} · ${escapeHtml(node.state)}</li>`).join("") || "<li>没有待执行节点；需核对待审查 / 交付状态。</li>"}</ul>${view.blockers.map((reason) => `<p class="callout bad">${escapeHtml(reason)}</p>`).join("")}<p class="muted">恢复只使用原任务、规格、执行记录与已验证提交，不会重跑已完成节点。未完成步骤仍需经过原有门禁。</p>`;
    if ($("#recovery-claim")) $("#recovery-claim").textContent = view.review_statement_digest || view.checkpoint_digest;
    for (const id of ["#recovery-save-review", "#recovery-resume"]) if ($(id)) $(id).disabled = view.busy || Boolean(view.blockers.length);
  } catch (error) { serviceMessage(error.message, true); }
}
async function reviewRecovery(continueTask) {
  try {
    if (!RECOVERY_CHECKPOINT || !$("#recovery-confirm")?.checked) throw new Error("请先查看断点并勾选人工审查确认。");
    const runId = RECOVERY_CHECKPOINT.run_id;
    await requestApi(`/api/runs/${encodeURIComponent(runId)}/recovery-review`, {method: "POST", body: JSON.stringify({reviewed_by: $("#recovery-reviewer")?.value || "", checkpoint_digest: RECOVERY_CHECKPOINT.checkpoint_digest, note: $("#recovery-review-note")?.value || "", signature: $("#recovery-signature")?.value || ""})});
    if ($("#recovery-signature")) $("#recovery-signature").value = "";
    if (continueTask) {
      await requestApi(`/api/runs/${encodeURIComponent(runId)}/resume`, {method: "POST"});
      serviceMessage("人工审查已记录，任务已进入执行队列。原有门禁与预算继续生效。");
      if ($("#recovery-resume")) $("#recovery-resume").disabled = true;
    } else serviceMessage("审查备注已保存。任务保持暂停，没有自动执行。");
  } catch (error) { serviceMessage(error.message, true); }
}
function initServicePanel() {
  $$('[data-service-open]').forEach((button) => button.addEventListener("click", openServicePanel));
  const bind = (id, fn) => { if ($(id)) $(id).addEventListener("click", fn); };
  bind("#service-close", () => { if ($("#service-dialog")?.close) $("#service-dialog").close(); });
  bind("#service-stop", () => controlService("stop")); bind("#service-restart", () => controlService("restart"));
  bind("#recovery-save-review", () => reviewRecovery(false)); bind("#recovery-resume", () => reviewRecovery(true));
  if ($("#service-dialog")) $("#service-dialog").addEventListener("close", () => { if ($("#recovery-signature")) $("#recovery-signature").value = ""; });
}



/* ------------------------------------------------------- shared presentations */

function ellipsis(value, limit) {
  const text = String(value ?? "")
    .replace(/\s+/g, " ")
    // A test failure arrives as a wall of "=====" and the sentence that matters is buried in it.
    // Collapsing the runs keeps the first line readable inside a card.
    .replace(/([=\-_*#~])\1{3,}/g, "$1$1$1")
    .trim();
  return text.length > limit ? text.slice(0, limit - 1) + "…" : text;
}

/* `kvHtml([["label", value], ...])` renders a definition list. Values are *markup*: every
   caller escapes what it passes, or passes text that came through `ellipsis`/`hashCell`, which
   escape in turn. */
function kvHtml(rows) {
  return rows.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${value}</dd>`).join("");
}

function renderApprovalPanel(spec) {
  const verified = Boolean(spec.approval_verified);
  // Two callers hand this panel the same fact under two names: `/api/runs/{id}` renames the
  // approval view's `statement` to `approval_statement`, `/api/runs/{id}/specs` passes it
  // through. Accepting one name silently printed an empty verdict, which reads as "not
  // recorded" rather than "not verified".
  const statement = spec.approval_statement || spec.statement || "";
  return `<dl class="kv">
      <dt>结论</dt><dd>${verified
        ? `<span class="check-pass">✓ ${escapeHtml(statement || "verified")}</span>`
        : `<span class="check-fail">未验证</span> — ${escapeHtml(statement || "无签批记录")}`}</dd>
      <dt>批准人</dt><dd>${escapeHtml(spec.approved_by || "—")}</dd>
      <dt>时间</dt><dd>${escapeHtml(spec.approved_at || "—")}</dd>
      <dt>验签原语</dt><dd><code>${escapeHtml(spec.approval_scheme || "—")}</code></dd>
      <dt>角色</dt><dd>${escapeHtml(spec.approval_role || "—")}</dd>
      <dt>风险等级</dt><dd>${escapeHtml(spec.risk_level || "—")}</dd>
      <dt>版本</dt><dd>${escapeHtml(spec.spec_version ?? "—")}${
        spec.parent_spec_digest
          ? ` · 父 <code>${escapeHtml(shortDigest(spec.parent_spec_digest, 12))}</code>` : ""}</dd>
    </dl>`;
}

function renderRegistry(payload) {
  const rows = payload.specs || [];
  if (!rows.length) return '<p class="empty">注册表为空</p>';
  return `<table class="table">
      <thead><tr><th>digest</th><th>goal</th><th>版本</th><th>风险</th><th>批准人</th>
      <th>状态</th></tr></thead>
      <tbody>${rows.map((row) => `<tr>
        <td class="mono">${escapeHtml(shortDigest(row.spec_digest, 16))}</td>
        <td>${escapeHtml(row.goal_id)}</td>
        <td class="num">${escapeHtml(row.spec_version)}</td>
        <td>${escapeHtml(row.risk_level)}</td>
        <td>${escapeHtml(row.approved_by || "—")}</td>
        <td>${row.approved_at ? "已批准" : "—"}</td>
      </tr>`).join("")}</tbody></table>`;
}

function parseJsonl(text) {
  return text.trim().split("\n").filter(Boolean).map((line) => {
    try { return JSON.parse(line); } catch (error) { return { raw: line }; }
  });
}

/* The event trail, as a pure function of parsed rows: the audit panel's whole job is display, so
   the render check must be able to execute it against a real export rather than only parse it. */
function renderEventTable(rows) {
  if (!rows.length) return '<tr><td colspan="6" class="muted">没有事件</td></tr>';
  const ordered = rows.slice().reverse().slice(0, 300);
  return ordered.map((row, index) => `<tr>
      <td class="muted num">${ordered.length - index}</td>
      <td><code>${escapeHtml(row.event_type || row.kind || "")}</code></td>
      <td class="muted"><details class="event-detail"><summary>${escapeHtml(String(row.detail || row.reference || "").slice(0, 50))}</summary><pre>${escapeHtml(String(row.detail || row.reference || ""))}</pre></details></td>
      <td class="muted mono">${escapeHtml(shortDigest(row.reference || "", 12))}</td>
      <td>${escapeHtml(row.actor || "")}</td>
      <td class="muted num">${escapeHtml(String(row.timestamp || "").slice(11, 19))}</td>
    </tr>`).join("");
}

/* The §27 answer, as a pure function so the check can run it against a real audit payload. It
   answers the ten questions the spec names and nothing else: an audit view that also shows live
   metrics invites the reader to treat a projection as evidence. */
function renderAuditAnswer(audit, route) {
  const run = audit.run || {};
  const spec = audit.spec || {};
  const steps = audit.steps || [];
  const flat = (key) => steps
    .map((step) => (step.artifacts || []).map((artifact) => artifact[key]))
    .flat().filter(Boolean);
  const finalCommit = steps.map((step) => step.commit).filter(Boolean).slice(-1)[0];
  const attempts = steps.map((step) => step.attempt || 0).reduce((a, b) => a + b, 0);
  const rows = [
    ["谁", escapeHtml(spec.approved_by || "—")],
    ["什么时候", escapeHtml(run.created_at || "—")],
    ["基于哪个 Spec", `<code>${escapeHtml(shortDigest(run.spec_digest))}</code>`],
    ["用了哪个 Model", escapeHtml([...new Set(flat("model"))].join(", ") || "—")],
    ["用了哪个 Image", escapeHtml([...new Set(flat("sandbox_image"))].join(", ") || "—")],
    // Joined with a separator *and* de-duplicated: concatenating each step's list produced a
    // run-on ("a.pyb.py") that read as one nonsense path. Escaped, because a changed-file path is
    // model-authored.
    ["改了什么", escapeHtml(
      [...new Set(steps.flatMap((step) => (step.artifacts || [])
        .flatMap((artifact) => artifact.changed_files || [])))].join(", ") || "—")],
    ["跑了什么", `${steps.length} 个 step，${attempts} 次尝试`],
    // A passing step records no failure text, and "—" would read as "not recorded" rather than
    // "passed". The gate verdict is the answer that exists.
    ["测试结果", escapeHtml(
      steps.map((step) => step.last_failure
        || String((step.gates || []).slice(-1).map((gate) => gate.decision)[0] || "")
        || "—").join(" | "))],
    ["谁批准", `${escapeHtml(spec.approved_by || "—")} · ${
      spec.approval_verified ? "签名已验证" : "未验证"}`],
    ["最终 Commit", `<code>${escapeHtml(finalCommit || run.base_commit || "—")}</code>`],
  ];
  const boxes = (route.nodes || []).filter((node) => node.kind === "attempt").length;
  return `<dl class="kv">${kvHtml(rows)}</dl>
    <p class="muted">路线上一共 ${boxes} 个尝试框；同一步骤的多次尝试各自独立。</p>`;
}

/* ======================================================================
 * 规划 · the frozen contract
 *
 * Four cards, each collapsed to a summary and expandable to the whole document. The summary
 * comes from the server (`/api/runs/{id}/specs`) rather than being derived here: a summary
 * computed in two places is a summary that eventually disagrees with itself.
 * ====================================================================== */

/*: Short badges, mapped explicitly: deriving them from the key produced "META_SPEC", which is
   wider than the chip and wrapped the card's title onto three lines. */
const SPEC_BADGE = {
  spec_01: "S01",
  spec_02: "S02",
  spec_03: "S03",
  meta_spec: "META",
};

function renderSpecCards(payload) {
  const cards = payload.specs || [];
  if (!cards.length) return '<p class="empty">这个 run 没有已注册的 spec</p>';
  return cards.map((card) => `
    <article class="spec-card" data-spec="${escapeHtml(card.key)}">
      <button class="spec-head" type="button" aria-expanded="false">
        <span class="spec-index">${escapeHtml(SPEC_BADGE[card.key] || card.key)}</span>
        <span class="spec-titles">
          <strong>${escapeHtml(card.title)}</strong>
          <span class="muted">${escapeHtml(card.subtitle)}</span>
        </span>
        <dl class="spec-facts">
          ${(card.summary || []).slice(0, 4).map(([key, value]) =>
            `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(
              ellipsis(value, 46))}</dd></div>`).join("")}
        </dl>
        <span class="chevron" aria-hidden="true"></span>
      </button>
      <div class="spec-body" hidden>
        <dl class="kv spec-facts-full">
          ${(card.summary || []).map(([key, value]) =>
            `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("")}
        </dl>
        <h4 class="section-title">完整内容</h4>
        ${renderDocument(card.document)}
      </div>
    </article>`).join("");
}

/* Render a spec document as structure, not as a JSON dump: an operator reading SPEC-03 wants
   the whitelist, not a brace. Digests and identifiers get monospace; arrays of scalars become
   chips; nested objects nest. */
function renderDocument(value, depth = 0) {
  if (value === null || value === undefined) return '<span class="muted">—</span>';
  if (typeof value === "boolean") {
    return `<span class="bool bool-${value}">${value ? "true" : "false"}</span>`;
  }
  if (typeof value === "number") return `<code class="num">${escapeHtml(value)}</code>`;
  if (typeof value === "string") {
    if (!value) return '<span class="muted">（空）</span>';
    return /^[0-9a-f]{16,}$/.test(value)
      ? `<code class="digest">${escapeHtml(value)}</code>`
      : escapeHtml(value);
  }
  if (Array.isArray(value)) {
    if (!value.length) return '<span class="muted">（空）</span>';
    if (value.every((item) => typeof item !== "object" || item === null)) {
      return `<span class="chips">${value.map((item) =>
        `<span class="chip">${escapeHtml(String(item))}</span>`).join("")}</span>`;
    }
    return `<div class="doc-list">${value.map((item) =>
      `<div class="doc-item">${renderDocument(item, depth + 1)}</div>`).join("")}</div>`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (!entries.length) return '<span class="muted">（空）</span>';
    return `<dl class="kv doc-kv">${entries.map(([key, item]) =>
      `<dt>${escapeHtml(key)}</dt><dd>${renderDocument(item, depth + 1)}</dd>`).join("")}</dl>`;
  }
  return escapeHtml(String(value));
}

function wireSpecCards() {
  $$(".spec-card .spec-head").forEach((head) => {
    head.addEventListener("click", () => {
      const card = head.closest(".spec-card");
      const body = card.querySelector(".spec-body");
      const open = head.getAttribute("aria-expanded") === "true";
      head.setAttribute("aria-expanded", String(!open));
      card.classList.toggle("open", !open);
      body.hidden = open;
      if (!open) body.animate(
        [{ opacity: 0, transform: "translateY(-4px)" }, { opacity: 1, transform: "none" }],
        { duration: 180, easing: "ease-out" },
      );
    });
  });
}

async function loadPlanning() {
  const runId = MODULE_RUN.id;
  if (!runId) return;
  const [payload, registry, plan, detail] = await Promise.all([
    api(`/api/runs/${encodeURIComponent(runId)}/specs`),
    api("/api/specs").catch(() => ({ specs: [] })),
    api(`/api/runs/${encodeURIComponent(runId)}/plan`),
    api(`/api/runs/${encodeURIComponent(runId)}`),
  ]);
  if (MODULE_RUN.id !== runId) return;
  renderPlanOverview(plan, detail);
  const cards = $("#spec-cards");
  if (cards) {
    if (stableHtml(cards, renderSpecCards(payload))) wireSpecCards();
  }
  const approval = $("#spec-approval");
  if (approval) stableHtml(approval, renderApprovalPanel({
    ...payload.approval,
    risk_level: payload.risk_level,
    owner_id: payload.owner_id,
    spec_version: payload.spec_version,
    parent_spec_digest: payload.parent_spec_digest,
  }));
  const target = $("#spec-registry");
  if (target) stableHtml(target, renderRegistry(registry));
  if (isWorkflow()) {
    WORKFLOW.plan = plan; WORKFLOW.specs = payload;
    WORKFLOW.available.plan = true;
    renderWorkflowSubmitted(); updateWorkflowSections();
  }
}

/* ---------------------------------------------------------------------- 审计评分 */

function renderScore(score) {
  if (!score) return "";
  const ring = Math.max(0, Math.min(100, score.score));
  const circumference = 2 * Math.PI * 34;
  return `
    <div class="score">
      <div class="score-ring">
        <svg viewBox="0 0 80 80" role="img"
             aria-label="审计评分 ${escapeHtml(ring.toFixed(1))} 分，等级 ${escapeHtml(score.band)}">
          <circle cx="40" cy="40" r="34" class="ring-track"></circle>
          <circle cx="40" cy="40" r="34" class="ring-value"
                  stroke-dasharray="${circumference.toFixed(1)}"
                  stroke-dashoffset="${(circumference * (1 - ring / 100)).toFixed(1)}"></circle>
        </svg>
        <div class="ring-label">
          <strong>${escapeHtml(ring.toFixed(1))}</strong>
          <span class="muted">${escapeHtml(score.band)}</span>
        </div>
      </div>
      <div class="score-parts">
        ${(score.components || []).map((component) => `
          <details class="score-part sev-${escapeHtml(component.severity)}">
            <summary>
              <span class="part-label">${escapeHtml(component.label)}</span>
              <span class="part-bar"><span style="width:${
                Math.round(component.value * 100)}%"></span></span>
              <span class="part-value">${escapeHtml(component.score)}<span class="muted">/${
                escapeHtml(component.weight)}</span></span>
            </summary>
            <p class="part-detail">${escapeHtml(component.detail)}</p>
            <ul class="part-evidence">${(component.evidence || []).map((line) =>
              `<li>${escapeHtml(line)}</li>`).join("")}</ul>
          </details>`).join("")}
      </div>
    </div>
    <p class="score-note muted">${escapeHtml(score.scale_note || "")}</p>`;
}

/* ---------------------------------------------------------------------- 审计 diff */

let diffMode = "line-by-line";

function renderDiffFor(patch) {
  if (isWorkflow()) {
    const mode = typeof diffMode === "undefined" ? "" : diffMode;
    const key = JSON.stringify([MODULE_RUN.id, patch, mode]);
    if (WORKFLOW.diffKey === key) return;
    WORKFLOW.diffKey = key;
  }
  const host = $("#diff");
  if (!host) return;
  if (!patch) {
    host.innerHTML = '<p class="empty">这一步没有被记录的补丁</p>';
    return;
  }
  if (typeof Diff2Html === "undefined") {
    host.innerHTML = `<pre class="diff">${colourDiff(patch)}</pre>`;
    return;
  }
  host.innerHTML = Diff2Html.html(patch, {
    drawFileList: false,
    matching: "lines",
    outputFormat: diffMode,
    colorScheme: "dark",
    rawTemplates: {},
  });
}

function wireDiffMode() {
  $$("#diff-mode button").forEach((button) => {
    button.addEventListener("click", () => {
      diffMode = button.dataset.mode;
      $$("#diff-mode button").forEach((other) => other.classList.toggle("on", other === button));
      const stepId = $("#diff-step") ? $("#diff-step").value : "";
      if (stepId) void loadDiff(stepId);
    });
  });
}

/* ======================================================================
 * 执行 · the run route
 *
 * One node per planned step; edges come exclusively from SPEC-02 dependencies.
 * Parallel nodes share a rank. The inspector progressively reveals overview, changes,
 * gates and history. Silent polling preserves selection, zoom, tabs and decision input.
 * ====================================================================== */

const STEP = { w: 232, h: 120, gap: 64, pad: 24 };

const STATE_SKIN = {
  COMMITTED: { edge: "#3fb37f", dot: "#4ade9a", fill: "#15201e" },
  APPROVED: { edge: "#5b8def", dot: "#7c9cff", fill: "#171f2c" },
  TIER2_REVIEWING: { edge: "#5b8def", dot: "#7c9cff", fill: "#171f2c" },
  TIER1_PASSED: { edge: "#5b8def", dot: "#7c9cff", fill: "#171f2c" },
  AWAITING_GATEKEEPER: { edge: "#5b8def", dot: "#7c9cff", fill: "#171f2c" },
  COMMITTING: { edge: "#5b8def", dot: "#7c9cff", fill: "#171f2c" },
  RUNNING: { edge: "#6f8ce0", dot: "#8aa6ff", fill: "#192333" },
  LEASED: { edge: "#6f8ce0", dot: "#8aa6ff", fill: "#192333" },
  READY: { edge: "#4a5265", dot: "#8b93a7", fill: "#181d25" },
  PENDING: { edge: "#4a5265", dot: "#8b93a7", fill: "#181d25" },
  REVISE: { edge: "#d9a33f", dot: "#f0bb58", fill: "#252218" },
  ESCALATED: { edge: "#d9a33f", dot: "#f0bb58", fill: "#252218" },
  STALE: { edge: "#d9a33f", dot: "#f0bb58", fill: "#252218" },
  LOST: { edge: "#d9a33f", dot: "#f0bb58", fill: "#252218" },
  FAILED: { edge: "#d2606c", dot: "#f0787f", fill: "#281c23" },
  TIMEOUT: { edge: "#d2606c", dot: "#f0787f", fill: "#281c23" },
  CANCELLED: { edge: "#4a5265", dot: "#8b93a7", fill: "#181d25" },
  SUPERSEDED: { edge: "#4a5265", dot: "#8b93a7", fill: "#181d25" },
};

const STATE_TEXT = {
  NOT_DECLARED: "待调度", COMMITTED: "已提交", TIER1_PASSED: "tier-1 通过", AWAITING_GATEKEEPER: "门禁中",
  TIER2_REVIEWING: "审查中", APPROVED: "已批准", COMMITTING: "提交中", RUNNING: "执行中",
  LEASED: "已租用", READY: "就绪", PENDING: "待处理", REVISE: "待修复", ESCALATED: "执行受阻",
  STALE: "已失效", LOST: "租约丢失", FAILED: "失败", TIMEOUT: "超时", CANCELLED: "已取消",
  SUPERSEDED: "已取代",
};

function stepSkin(state) {
  return STATE_SKIN[state] || STATE_SKIN.PENDING;
}

function stateText(state) {
  return STATE_TEXT[state] || state || "—";
}

const WORKSPACE = {
  selectedId: "", tab: "overview", runId: "", plan: null, specs: null,
  zoom: 1, layout: null, graphKey: "", inspectorKey: "", runs: [],
  patches: new Map(), fitted: false, request: 0, bound: false,
};

function buildStepModels(detail, route, plan = null) {
  const attemptsByNode = new Map();
  (route.nodes || []).filter((node) => node.kind === "attempt").forEach((node) => {
    if (!attemptsByNode.has(node.plan_node_id)) attemptsByNode.set(node.plan_node_id, []);
    attemptsByNode.get(node.plan_node_id).push(node);
  });
  const rows = new Map((detail.steps || []).map((step) => [step.node_id, step]));
  const plans = new Map(((plan && plan.nodes) || []).map((node) => [node.node_id, node]));
  const order = plans.size ? Array.from(plans.keys()) : (route.lanes || [])
    .filter((lane) => lane.index >= 0 && rows.has(lane.node_id)).map((lane) => lane.node_id);
  rows.forEach((_, id) => { if (!order.includes(id)) order.push(id); });
  return order.map((id, index) => {
    const definition = plans.get(id) || {};
    const declared = rows.has(id);
    const step = rows.get(id) || {
      step_id: "planned:" + id, node_id: id, state: "NOT_DECLARED", attempt: 0,
      max_attempts: definition.retry_max_attempts || 0, gates: [], artifacts: [],
      timeout_sec: definition.timeout_sec,
    };
    return {
      index: index + 1, step, plan: definition, declared,
      repairBranches: ((plan && plan.trunk && plan.trunk.branches) || [])
        .filter((branch) => branch.node_id === id || (branch.affected_node_ids || []).includes(id)),
      attempts: (attemptsByNode.get(id) || []).slice().sort((a, b) => a.attempt - b.attempt),
      artifact: (step.artifacts || []).slice(-1)[0] || null,
      gate: (step.gates || []).slice(-1)[0] || null,
    };
  });
}

// Longest dependency distance, not execution order. Independent nodes share a column.
// Invalid/missing dependencies are reported, never replaced by a made-up sequential edge.
function buildDagLayout(models) {
  const byId = new Map(models.map((model) => [model.step.node_id, model]));
  const children = new Map(models.map((model) => [model.step.node_id, []]));
  const indegree = new Map();
  const ranks = new Map(models.map((model) => [model.step.node_id, 0]));
  const edges = [];
  const missing = [];
  models.forEach((model) => {
    const id = model.step.node_id;
    const deps = Array.from(new Set(model.plan.deps || []));
    indegree.set(id, deps.filter((dep) => byId.has(dep)).length);
    deps.forEach((dep) => {
      if (!byId.has(dep)) { missing.push(dep); return; }
      children.get(dep).push(id);
      edges.push({ from: dep, to: id });
    });
  });
  const queue = models.filter((model) => indegree.get(model.step.node_id) === 0)
    .map((model) => model.step.node_id);
  let visited = 0;
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const id = queue[cursor]; visited += 1;
    children.get(id).forEach((child) => {
      ranks.set(child, Math.max(ranks.get(child), ranks.get(id) + 1));
      indegree.set(child, indegree.get(child) - 1);
      if (indegree.get(child) === 0) queue.push(child);
    });
  }
  const layers = [];
  models.forEach((model) => {
    const rank = ranks.get(model.step.node_id);
    if (!layers[rank]) layers[rank] = [];
    layers[rank].push(model);
  });
  const slots = new Map();
  layers.forEach((layer) => {
    const center = (model) => {
      const deps = (model.plan.deps || []).filter((id) => slots.has(id));
      return deps.length ? deps.reduce((sum, id) => sum + slots.get(id), 0) / deps.length : model.index;
    };
    layer.sort((a, b) => center(a) - center(b) || a.index - b.index);
    layer.forEach((model, row) => slots.set(model.step.node_id, row));
  });
  const rows = Math.max(1, ...layers.map((layer) => layer.length));
  const points = new Map();
  layers.forEach((layer, rank) => layer.forEach((model, row) => {
    points.set(model.step.node_id, {
      x: STEP.pad + rank * (STEP.w + STEP.gap),
      y: STEP.pad + ((rows - layer.length) / 2 + row) * (STEP.h + 54), model,
    });
  }));
  return {
    points, edges, missing, cyclic: visited !== models.length,
    width: STEP.pad * 2 + Math.max(1, layers.length) * STEP.w
      + Math.max(0, layers.length - 1) * STEP.gap,
    height: STEP.pad * 2 + rows * STEP.h + (rows - 1) * 54,
  };
}

function renderLane(models, route) {
  const track = $("#lane-track");
  if (!track) return;
  if (!models.length) {
    track.innerHTML = '<div class="graph-empty"><span class="empty-graph-symbol">◇</span>'
      + '<h3>计划还未生成</h3><p>步骤就绪后，这里会显示它们的依赖与进度。</p></div>';
    return;
  }
  const layout = buildDagLayout(models);
  WORKSPACE.layout = layout;
  const viewport = $("#lane");
  const oldLeft = viewport ? viewport.scrollLeft : 0;
  const oldTop = viewport ? viewport.scrollTop : 0;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${layout.width} ${layout.height}`);
  svg.setAttribute("class", "lane-svg");
  svg.setAttribute("role", "group");
  svg.setAttribute("aria-label", "步骤依赖与执行状态");
  svg.setAttribute("width", String(layout.width * WORKSPACE.zoom));
  svg.setAttribute("height", String(layout.height * WORKSPACE.zoom));
  const defs = document.createElementNS(ns, "defs");
  defs.innerHTML = '<marker id="lane-arrow" viewBox="0 0 10 10" refX="8" refY="5" '
    + 'markerWidth="5" markerHeight="5" orient="auto-start-reverse">'
    + '<path d="M 0 1 L 8 5 L 0 9 z" fill="#626f83"></path></marker>';
  svg.appendChild(defs);
  layout.edges.forEach((edge) => {
    const source = layout.points.get(edge.from);
    const target = layout.points.get(edge.to);
    const x1 = source.x + STEP.w + 3, y1 = source.y + STEP.h / 2;
    const x2 = target.x - 6, y2 = target.y + STEP.h / 2;
    const mid = (x1 + x2) / 2;
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`);
    path.setAttribute("class", "lane-edge");
    path.setAttribute("data-from", source.model.step.step_id);
    path.setAttribute("data-to", target.model.step.step_id);
    path.setAttribute("marker-end", "url(#lane-arrow)");
    const tip = document.createElementNS(ns, "title");
    tip.textContent = edge.from + " → " + edge.to;
    path.appendChild(tip); svg.appendChild(path);
  });
  layout.points.forEach((point) => svg.appendChild(stepNode(point.model, point.x, point.y)));
  track.innerHTML = ""; track.appendChild(svg);
  if (viewport) { viewport.scrollLeft = oldLeft; viewport.scrollTop = oldTop; }
  const count = $("#graph-count");
  if (count) count.textContent = models.length + " 步骤 · " + layout.edges.length + " 依赖";
  if (layout.cyclic || layout.missing.length) {
    showError("#execution-error", new Error("依赖数据不完整，请查看规格与计划后再判断执行关系。"));
  }
  highlightSelection();
}

function phaseIndex(model) {
  const state = model.step.state;
  if (state === "COMMITTED") return 4;
  if (["APPROVED", "COMMITTING"].includes(state)) return 3;
  if (["TIER1_PASSED", "TIER2_REVIEWING"].includes(state)) return 2;
  if (state === "AWAITING_GATEKEEPER") return 1;
  if (state === "ESCALATED" && model.gate) return model.gate.tier === 2 ? 2 : 1;
  return 0;
}

function phaseEvidenceMissing(model, index) {
  return (index === 1 || index === 2) && phaseIndex(model) > index
    && !(model.step.gates || []).some((gate) => gate.tier === index);
}

function nodeLabel(value, maxWidth = 194) {
  const text = String(value || "");
  let width = 0, result = "";
  for (const char of text) {
    width += char.codePointAt(0) > 255 ? 12 : 6.5;
    if (width > maxWidth - 12) return result + "…";
    result += char;
  }
  return result;
}

const EXPECTATION_STATES = new Set(["MET", "UNMET", "UNKNOWN", "BLOCKED", "STALE"]);

function expectationState(value) {
  return EXPECTATION_STATES.has(value) ? value : "UNKNOWN";
}

function expectationBadge(plan) {
  if (!plan || !plan.expectation_status) return "";
  const state = expectationState(plan.expectation_status);
  const score = typeof plan.expectation_score === "number" && Number.isFinite(plan.expectation_score)
    ? ` · ${Math.round(Math.min(1, Math.max(0, plan.expectation_score)) * 100)}% 证据覆盖` : "";
  return `<span class="expectation-state expectation-${state}" title="Evidence coverage only; not correctness probability or permission to deliver.">预期 ${state}${escapeHtml(score)}</span>`;
}

function renderExpectationEvidence(plan) {
  if (!plan || !plan.expectation_status) return "";
  return `<section class="expectation-evidence" aria-label="冻结预期与当前证据"><h3>冻结预期 · 当前主干证据</h3>`
    + expectationBadge(plan)
    + '<p class="expectation-disclaimer">证据覆盖率不是正确概率，也不代表交付许可。Evidence coverage only.</p>'
    + `<p class="inspector-caption">证据提交 ${hashCell(plan.expectation_commit)}</p>`
    + '<ul class="expectation-criteria">' + (plan.expectations || []).map((row) => {
      const state = expectationState(row.status);
      const evidence = row.evidence || {};
      const rows = Array.isArray(evidence.rows) ? evidence.rows : [];
      return `<li><span class="expectation-state expectation-${state}">${state}</span> `
        + `<strong>${escapeHtml(row.criterion_id || "")}</strong><p>${escapeHtml(row.statement || row.command || row.path || "未声明说明")}</p>`
        + (row.expect !== undefined ? `<p>预期值：<code>${escapeHtml(JSON.stringify(row.expect))}</code></p>` : "")
        + (rows.length ? `<details><summary>证据 · ${escapeHtml(evidence.source || "recorded")}</summary><pre>${escapeHtml(JSON.stringify(rows, null, 2))}</pre></details>`
          : '<span class="muted">尚无有效证据</span>') + '</li>';
    }).join("") + '</ul></section>';
}

function renderRepairLineage(branches) {
  if (!branches || !branches.length) return "";
  const labels = { STARTED: "STARTED · 隔离候选，尚未成为主干", REJECTED: "REJECTED · 已拒绝，保留原主干",
    PROMOTED: "PROMOTED · 已晋升主干" };
  return '<details class="evidence-disclosure repair-lineage" data-disclosure="repair-lineage"><summary>修复分支 · '
    + branches.length + '</summary>' + branches.slice().reverse().map((branch) => {
      const state = ["STARTED", "REJECTED", "PROMOTED"].includes(branch.status) ? branch.status : "STARTED";
      return `<div class="repair-branch repair-${state}"><strong>${escapeHtml(labels[state])}</strong>`
        + `<p>${escapeHtml(branch.branch_id)} · ${escapeHtml(branch.node_id || "")}</p>`
        + `<p>${branch.phase === "step" ? `单步隔离修复 · 第 ${Number(branch.attempt)} 次尝试` : "整轮目标修复"}</p>`
        + `<p>基线 ${hashCell(branch.base_commit)} → 候选 ${hashCell(branch.commit)}</p>`
        + (branch.reasons && branch.reasons.length ? `<p>${escapeHtml(Array.isArray(branch.reasons) ? branch.reasons.join("；") : branch.reasons)}</p>` : "")
        + (branch.validation ? `<details><summary>分支校验证据</summary><pre>${escapeHtml(JSON.stringify(branch.validation, null, 2))}</pre></details>` : "")
        + '</div>';
    }).join("") + '</details>';
}

function renderTrunkSummary(trunk) {
  if (!trunk || !trunk.enabled) return "";
  return '<section class="trunk-summary" aria-label="当前主干"><h3>当前主干</h3>'
    + `<p>${hashCell(trunk.commit)}</p><p class="expectation-disclaimer">${escapeHtml(trunk.coverage_disclaimer)}</p>`
    + renderRepairLineage(trunk.branches)
    + (trunk.snapshots && trunk.snapshots.length
      ? `<details class="evidence-disclosure" data-disclosure="trunk-snapshots"><summary>不可变主干快照 · ${trunk.snapshots.length}</summary>`
        + trunk.snapshots.slice().reverse().map((snapshot) => `<p>提交 ${hashCell(snapshot.commit)}<br>摘要 ${hashCell(snapshot.digest)}</p>`).join("") + '</details>' : "")
    + '</section>';
}

function stepNode(model, x, y) {
  const { step } = model;
  const skin = stepSkin(step.state);
  const ns = "http://www.w3.org/2000/svg";
  const group = document.createElementNS(ns, "g");
  group.setAttribute("class", "lane-node state-" + step.state
    + (model.attempts.length > 1 ? " retried" : ""));
  group.setAttribute("transform", `translate(${x},${y})`);
  group.setAttribute("tabindex", "0"); group.setAttribute("role", "button");
  group.setAttribute("data-step", step.step_id);
  group.setAttribute("aria-label", (model.plan.objective || step.node_id) + " · " + stateText(step.state)
    + (model.plan.expectation_status ? " · 预期 " + expectationState(model.plan.expectation_status) : ""));
  group.setAttribute("aria-pressed", String(WORKSPACE.selectedId === step.step_id));
  const add = (tag, attrs, text) => {
    const element = document.createElementNS(ns, tag);
    Object.entries(attrs).forEach(([key, value]) => element.setAttribute(key, String(value)));
    if (text !== undefined) element.textContent = text;
    group.appendChild(element); return element;
  };
  add("rect", { width: STEP.w, height: STEP.h, rx: 9, fill: skin.fill, stroke: skin.edge });
  add("text", { x: 16, y: 23, class: "lane-index" }, "STEP " + String(model.index).padStart(2, "0"));
  add("circle", { cx: STEP.w - 17, cy: 20, r: 3, fill: skin.dot });
  add("text", { x: 16, y: 46, class: "lane-title" }, nodeLabel(model.plan.objective || step.node_id));
  add("text", { x: 16, y: 66, class: "lane-state" }, stateText(step.state));
  add("text", { x: 16, y: 85, class: model.plan.expectation_status
    ? "lane-expectation expectation-" + expectationState(model.plan.expectation_status) : "lane-meta" },
    model.plan.expectation_status ? `预期 ${expectationState(model.plan.expectation_status)} · ${Math.round((model.plan.expectation_score || 0) * 100)}% 证据覆盖`
      : `尝试 ${step.attempt}/${step.max_attempts}` + (model.attempts.length > 1
        ? ` · 重试 ${model.attempts.length - 1}` : ""));
  const phase = phaseIndex(model);
  for (let i = 0; i < 4; i += 1) {
    add("rect", { x: 16 + i * 51, y: 100, width: 44, height: 3, rx: 1.5,
      fill: phaseEvidenceMissing(model, i) ? "#303845" : i < phase ? "#52977e" : (i === phase && !["PENDING", "READY", "NOT_DECLARED"].includes(step.state) ? "#8caafa" : "#303845") });
  }
  const tip = add("title", {}, [step.node_id, model.plan.objective || "", stateText(step.state),
    step.last_failure || "", "点击查看步骤总览"].filter(Boolean).join("\n"));
  tip.setAttribute("data-tooltip", "step");
  group.addEventListener("click", () => { if (!WORKSPACE.dragged) void selectStep(model); });
  group.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); void selectStep(model); }
    if (["ArrowRight", "ArrowLeft", "ArrowUp", "ArrowDown"].includes(event.key)) {
      event.preventDefault(); moveLaneSelection(group, ["ArrowRight", "ArrowDown"].includes(event.key) ? 1 : -1);
    }
  });
  return group;
}

function moveLaneSelection(current, delta) {
  const nodes = $$(".lane-node");
  const target = nodes[nodes.indexOf(current) + delta];
  if (target) { target.focus(); target.scrollIntoView({ block: "nearest", inline: "nearest" }); }
}

let stepModels = [];
let currentRoute = null;
let currentRunDetail = null;

function highlightSelection() {
  const selected = stepModels.find((model) => model.step.step_id === WORKSPACE.selectedId);
  const related = new Set(selected ? [selected.step.node_id, ...(selected.plan.deps || [])] : []);
  if (selected) stepModels.forEach((model) => {
    if ((model.plan.deps || []).includes(selected.step.node_id)) related.add(model.step.node_id);
  });
  $$(".lane-node").forEach((node) => {
    const model = stepModels.find((item) => item.step.step_id === node.dataset.step);
    const active = node.dataset.step === WORKSPACE.selectedId;
    node.classList.toggle("selected", active);
    node.classList.toggle("dimmed", Boolean(selected && model && !related.has(model.step.node_id)));
    node.setAttribute("aria-pressed", String(active));
  });
  $$(".lane-edge").forEach((edge) => edge.classList.toggle("related",
    edge.dataset.from === WORKSPACE.selectedId || edge.dataset.to === WORKSPACE.selectedId));
}

async function selectStep(model, preserveTab = false) {
  const changed = WORKSPACE.selectedId !== model.step.step_id;
  if (changed) { const scroll = $("#inspector-scroll"); if (scroll) scroll.scrollTop = 0; }
  WORKSPACE.selectedId = model.step.step_id;
  if (changed && !preserveTab) WORKSPACE.tab = "overview";
  highlightSelection();
  const tabs = $("#inspector-tabs"); if (tabs) tabs.hidden = false;
  const decisionPanel = $("#escalation-panel");
  if (currentRunDetail && (!decisionPanel || !decisionPanel.contains(document.activeElement))) {
    renderEscalations([model.step], currentRunDetail.run);
  }
  const title = $("#step-title");
  if (title) title.textContent = model.plan.objective || model.step.node_id;
  const sub = $("#step-sub");
  if (sub) sub.textContent = "STEP " + String(model.index).padStart(2, "0") + " / " + model.step.node_id;
  const out = $("#action-out");
  if (out && changed) out.hidden = true;
  renderStepActions(model, currentRoute ? currentRoute.status : "");
  if (changed) WORKSPACE.inspectorKey = "";
  await updateInspector(model);
}

async function updateInspector(model, force = false) {
  const key = JSON.stringify([model, WORKSPACE.tab]);
  if (!force && key === WORKSPACE.inspectorKey) return;
  WORKSPACE.inspectorKey = key;
  const scroll = $("#inspector-scroll");
  const oldScroll = scroll ? scroll.scrollTop : 0;
  const disclosures = $$("#step-body details[open]").map((element) => element.dataset.disclosure).filter(Boolean);
  const body = $("#step-body");
  if (body) {
    body.innerHTML = renderStepDetail(model, WORKSPACE.tab);
    body.setAttribute("aria-labelledby", "tab-" + WORKSPACE.tab);
  }
  $$("#inspector-tabs button").forEach((button) => {
    const active = button.dataset.tab === WORKSPACE.tab;
    button.classList.toggle("on", active); button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
  });
  $$("[data-node-link]").forEach((button) => button.addEventListener("click", () => {
    const target = stepModels.find((item) => item.step.node_id === button.dataset.nodeLink);
    if (target) { void selectStep(target); focusGraphNode(target); }
  }));
  const exportLink = $("#step-log-link");
  if (exportLink && model.declared !== false) exportLink.href = "/api/runs/"
    + encodeURIComponent(MODULE_RUN.id) + "/steps/" + encodeURIComponent(model.step.step_id) + "/log";
  $$("#step-body details[data-disclosure]").forEach((element) => { element.open = disclosures.includes(element.dataset.disclosure); });
  if (scroll) scroll.scrollTop = oldScroll;
  if (WORKSPACE.tab === "changes") await loadStepDiff(model);
}

function setGraphZoom(zoom) {
  WORKSPACE.zoom = Math.min(1.8, Math.max(.2, zoom));
  const layout = WORKSPACE.layout;
  const svg = $("#lane-track svg");
  if (svg && layout) {
    svg.setAttribute("width", String(layout.width * WORKSPACE.zoom));
    svg.setAttribute("height", String(layout.height * WORKSPACE.zoom));
  }
  const label = $("#graph-zoom");
  if (label) label.textContent = Math.round(WORKSPACE.zoom * 100) + "%";
}

function fitGraph() {
  const viewport = $("#lane");
  const layout = WORKSPACE.layout;
  if (!viewport || !layout || !viewport.clientWidth || !viewport.clientHeight) return;
  setGraphZoom(Math.min(1, (viewport.clientWidth - 76) / layout.width,
    (viewport.clientHeight - 76) / layout.height));
  viewport.scrollLeft = 0; viewport.scrollTop = 0;
}

function focusGraphNode(model) {
  const node = $$(".lane-node").find((element) => element.dataset.step === model.step.step_id);
  if (node) node.scrollIntoView({ block: "center", inline: "center", behavior: "smooth" });
}

function bindWorkspace() {
  if (WORKSPACE.bound) return;
  WORKSPACE.bound = true;
  const click = (id, fn) => { const el = document.getElementById(id); if (el) el.addEventListener("click", fn); };
  click("graph-zoom-in", () => setGraphZoom(WORKSPACE.zoom + .15));
  click("graph-zoom-out", () => setGraphZoom(WORKSPACE.zoom - .15));
  click("graph-fit", fitGraph);
  click("focus-step", () => {
    const model = stepModels.find((item) => ["RUNNING", "ESCALATED", "TIER2_REVIEWING", "AWAITING_GATEKEEPER", "LEASED"].includes(item.step.state))
      || stepModels.find((item) => item.step.step_id === WORKSPACE.selectedId) || stepModels[0];
    if (model) { setGraphZoom(1); void selectStep(model); focusGraphNode(model); }
  });
  click("inspector-close", () => { WORKSPACE.selectedId = ""; WORKSPACE.inspectorKey = ""; renderTaskOverview(); highlightSelection(); });
  $$("#inspector-tabs button").forEach((button, index, buttons) => {
    const choose = () => {
      const model = stepModels.find((item) => item.step.step_id === WORKSPACE.selectedId);
      if (!model) return;
      WORKSPACE.tab = button.dataset.tab;
      const scroll = $("#inspector-scroll"); if (scroll) scroll.scrollTop = 0;
      void updateInspector(model);
    };
    button.addEventListener("click", choose);
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1
        : (index + (event.key === "ArrowRight" ? 1 : -1) + buttons.length) % buttons.length;
      buttons[next].focus(); buttons[next].click();
    });
  });
  const viewport = $("#lane");
  if (viewport) {
    let drag = null;
    viewport.addEventListener("pointerdown", (event) => {
      if (event.button !== 0 || event.target.closest(".lane-node, a, button")) return;
      drag = { x: event.clientX, y: event.clientY, left: viewport.scrollLeft, top: viewport.scrollTop };
      WORKSPACE.dragged = false;
      viewport.setPointerCapture(event.pointerId);
    });
    viewport.addEventListener("pointermove", (event) => {
      if (!drag) return;
      if (Math.abs(event.clientX - drag.x) + Math.abs(event.clientY - drag.y) > 4) {
        WORKSPACE.dragged = true; viewport.classList.add("dragging");
      }
      viewport.scrollLeft = drag.left - event.clientX + drag.x;
      viewport.scrollTop = drag.top - event.clientY + drag.y;
    });
    const endDrag = () => { drag = null; viewport.classList.remove("dragging"); setTimeout(() => { WORKSPACE.dragged = false; }, 0); };
    viewport.addEventListener("pointerup", endDrag); viewport.addEventListener("pointercancel", endDrag);
    viewport.addEventListener("wheel", (event) => {
      if (!event.ctrlKey && !event.metaKey) return;
      event.preventDefault(); setGraphZoom(WORKSPACE.zoom + (event.deltaY < 0 ? .08 : -.08));
    }, { passive: false });
  }
}

function runStateLabel(state) {
  return ({ COMPLETED: "已完成", RUNNING: "执行中", AWAITING_APPROVAL: "等待审批", PARTIAL_FAILURE: "部分失败",
    FAILED: "失败", CANCELLED: "已取消", PENDING: "待执行" })[state] || state;
}

function syncRunNavigation(runId) {
  $$("[data-module]").forEach((link) => {
    link.href = "/" + link.dataset.module + (runId ? "/" + encodeURIComponent(runId) : "");
  });
}

/*: `replayBase(model)` is the commit this step replays from, or "" when the run never recorded
   one. A step that committed reports the commit it produced — replaying from it reuses the
   verified work up to and including this step and re-executes what follows. A step that never
   committed has only its base, which re-executes the step itself. The server refuses any other
   commit, so the UI must pick from exactly these two. */
function replayBase(model) {
  return model.step.result_commit || model.step.base_commit || "";
}

/*: `renderStepActions(model, runStatus)` takes the run status rather than reading module state.
   It used to read the `currentRoute` global, which made "恢复 is available" depend on something
   set in another function — and a preview that rendered the panel without going through
   `loadExecution` showed a parked run whose 恢复 was disabled, which is exactly the kind of
   silent disagreement the console is supposed to make impossible. */
function renderStepActions(model, runStatus) {
  const host = $("#step-actions");
  if (!host) return;
  const step = model.step;
  const resumable = runStatus === "AWAITING_APPROVAL" && step.execution_authorization_required === true;
  if (model.declared === false) { host.innerHTML = '<p class="muted">步骤尚未开始执行。</p>'; return; }
  const from = replayBase(model);
  const reuses = Boolean(step.result_commit);
  const actions = [
    {
      id: "resume",
      label: "恢复",
      hint: resumable
        ? "继续这个停在人工处置上的 run"
        : "run 当前不是停车状态；恢复只在 AWAITING_APPROVAL 时可用",
      enabled: resumable,
    },
    {
      id: "replay",
      label: "重现",
      hint: from
        ? `从提交 ${shortDigest(from, 12)} 起新开一次执行，`
          + (reuses ? "复用这一步已验证的产物" : "这一步会重新执行")
        : "这个 run 没有记录任何可重现的提交",
      enabled: Boolean(from),
    },
    {
      id: "rollback",
      label: "回滚到此处",
      hint: "只停住这个 run，不删除任何历史；重放需另行发起",
      enabled: Boolean(step.base_commit || step.result_commit),
    },
  ];
  host.innerHTML = actions.map((action) => action.enabled
    ? `<button type="button" class="action" data-act="${escapeHtml(action.id)}"
         title="${escapeHtml(action.hint)}">${escapeHtml(action.label)}</button>`
    : `<span class="action disabled" title="${escapeHtml(action.hint)}">${
        escapeHtml(action.label)}<span class="why">${escapeHtml(action.hint)}</span></span>`
  ).join("");
  $$(".action[data-act]", host).forEach((button) => {
    button.addEventListener("click", () => runStepAction(button.dataset.act, model));
  });
}

async function runStepAction(action, model) {
  const out = $("#action-out");
  const show = (message, kind) => {
    if (!out || (isWorkflow() && MODULE_RUN.id !== runId)) return;
    out.hidden = false;
    out.className = kind === "error" ? "callout bad" : "callout";
    out.textContent = message;
  };
  const runId = MODULE_RUN.id;
  let replayedRun = "";
  try {
    if (action === "resume") {
      await api(`/api/runs/${encodeURIComponent(runId)}/resume`, { method: "POST" });
      show("已受理恢复；路线图会自动刷新。");
    } else if (action === "replay") {
      const from = replayBase(model);
      const reason = window.prompt(
        `从 ${shortDigest(from, 12)} 重现「${model.step.node_id}」。原因会写入事件日志：`,
        `replay from ${model.step.node_id}`);
      if (!reason) return;
      const result = await api(`/api/runs/${encodeURIComponent(runId)}/replay`, {
        method: "POST",
        body: JSON.stringify({ reason, from_commit: from, use_model: false }),
      });
      if (isWorkflow()) replayedRun = result.run_id;
      show(`已从 ${String(result.replay_from_commit).slice(0, 12)} 起新开一次执行`
        + `（新 run ${shortDigest(result.run_id, 12)}）。`);
    } else if (action === "rollback") {
      const reason = window.prompt("回滚原因（会写入事件日志）", `rolled back from the console`);
      if (!reason) return;
      await api(`/api/runs/${encodeURIComponent(runId)}/rollback`, {
        method: "POST",
        body: JSON.stringify({ reason, to_commit: model.step.base_commit || "" }),
      });
      show("已停住这个 run；历史未被删除，重放需要显式发起。");
    }
    if (isWorkflow()) {
      if (MODULE_RUN.id !== runId) return;
      if (action === "replay" && replayedRun) await openWorkflowRun(replayedRun, "execute");
      else {
        if (WORKFLOW.pending) await WORKFLOW.pending;
        if (MODULE_RUN.id === runId) await loadWorkflow();
      }
    } else await loadExecution();
  } catch (error) {
    show(error.message, "error");
  }
}

function stepDuration(model) {
  const attempt = model.attempts.slice(-1)[0];
  if (!attempt || !attempt.started_at) return "—";
  if (!attempt.ended_at) return ["RUNNING", "LEASED", "AWAITING_GATEKEEPER", "TIER2_REVIEWING"].includes(model.step.state) ? "进行中" : "—";
  const seconds = Math.max(0, Math.round((Date.parse(attempt.ended_at) - Date.parse(attempt.started_at)) / 1000));
  if (!Number.isFinite(seconds)) return "—";
  return seconds < 60 ? seconds + " 秒" : Math.floor(seconds / 60) + " 分 " + seconds % 60 + " 秒";
}

function latestStepGates(model) {
  return [1, 2].map((tier) => (model.step.gates || []).slice().reverse()
    .find((gate) => gate.tier === tier)).filter(Boolean);
}

function dependencyMarkup(ids) {
  if (!ids.length) return '<span class="muted">无前置依赖，可独立执行</span>';
  return '<div class="dependency-list">' + ids.map((id) => {
    const model = stepModels.find((item) => item.step.node_id === id);
    const tone = model && model.step.state === "COMMITTED" ? "done" : "waiting";
    return `<button type="button" class="dependency-chip" data-node-link="${escapeHtml(id)}"><i class="legend-dot ${tone}"></i>${escapeHtml(model ? (model.plan.objective || id) : id)}</button>`;
  }).join("") + '</div>';
}

function renderStepDetail(model, tab = "overview") {
  const step = model.step;
  const artifact = model.artifact || {};
  const snapshot = artifact.snapshot || {};
  const observations = Array.isArray(snapshot.inspection_receipts) ? snapshot.inspection_receipts.slice(0, 3) : [];
  const gates = latestStepGates(model);
  const files = artifact.changed_files || [];
  if (tab === "changes") {
    return `<h3>改动文件 · ${files.length}</h3>`
      + (files.map((file) => `<div class="file-entry">${escapeHtml(file)}</div>`).join("")
        || '<p class="empty">尚未产生文件改动。</p>')
      + `<h3>代码 Diff</h3><p class="muted inspector-caption">${escapeHtml(snapshot.diff_stat || "当前步骤最新记录的补丁")}</p>`
      + '<div id="step-diff" class="diff-host"><p class="empty">正在加载补丁…</p></div>';
  }
  if (tab === "gates") {
    const passed = gates.reduce((n, gate) => n + (gate.checks || []).filter((check) => check.passed).length, 0);
    const total = gates.reduce((n, gate) => n + (gate.checks || []).length, 0);
    return `<h3>门禁逐条结论</h3><p class="muted inspector-caption">${total ? passed + " / " + total + " 项确定性检查通过" : "门禁尚未执行，或尚无确定性检查记录"}</p>`
      + (gates.map((gate) => `<div class="gate-head">Tier-${escapeHtml(gate.tier)} · ${escapeHtml(gate.decision)}</div>`
        + renderGateChecks(gate)
        + ((gate.reasons || []).length ? '<p class="summary-note">' + escapeHtml(gate.reasons.join("；")) + '</p>' : "")
        + ((gate.violations || []).length ? '<p class="summary-note warning">' + escapeHtml(gate.violations.join("；")) + '</p>' : "")
      ).join("") || '<p class="empty">通过执行后，确定性校验与语义审查的结果会显示在这里。</p>');
  }
  if (tab === "history") {
    return '<h3>尝试历史</h3>' + (model.attempts.map((attempt) =>
      `<details class="attempt-disclosure"><summary class="attempt-row sev-${attempt.failure ? "bad" : "ok"}"><span class="attempt-no">#${escapeHtml(attempt.attempt)}</span><span class="attempt-state">${escapeHtml(stateText(attempt.state))}</span><span class="attempt-gate">${escapeHtml([attempt.gate_tier1 && "T1 " + attempt.gate_tier1, attempt.gate_tier2 && "T2 " + attempt.gate_tier2].filter(Boolean).join(" · ") || "尚无门禁记录")}</span><span class="attempt-note">${escapeHtml(attempt.failure || attempt.detail || "展开查看事件")}</span></summary>${renderActivityRows(attempt.events || [])}</details>`
    ).join("") || '<p class="empty">尚无执行尝试。</p>')
      + '<h3>溯源</h3><dl class="inspector-facts">'
      + kvHtml([["执行者", escapeHtml(artifact.worker_id || "—")], ["模型", escapeHtml(artifact.model || "—")],
        ["隔离 / 镜像", escapeHtml(artifact.sandbox_image || "—")]])
      + '</dl>' + (model.declared === false ? "" : '<a id="step-log-link" class="inspector-log-link" target="_blank" rel="noopener noreferrer" href="#">打开完整执行记录 ↗</a>');
  }
  const phase = phaseIndex(model);
  const checkCount = gates.reduce((sum, gate) => sum + (gate.checks || []).length, 0);
  const checkPassed = gates.reduce((sum, gate) => sum + (gate.checks || []).filter((check) => check.passed).length, 0);
  const dependents = stepModels.filter((item) => (item.plan.deps || []).includes(step.node_id)).map((item) => item.step.node_id);
  const facts = [["改动文件", escapeHtml(files.length ? files.length + " 个文件" : "尚无产出")],
    ["门禁检查", escapeHtml(checkCount ? checkPassed + " / " + checkCount + " 通过" : "尚未执行")],
    ["模型", escapeHtml(artifact.model || "—")], ["执行者", escapeHtml(artifact.worker_id || "—")],
    ["超时限制", escapeHtml(step.timeout_sec ? step.timeout_sec + " 秒" : "—")]];
  const hashes = [["基线提交", hashCell(step.base_commit)], ["产物提交", hashCell(step.result_commit)], ["run", hashCell(step.run_id)],
    ["execution", hashCell(step.execution_id)], ["spec", hashCell(step.spec_digest)], ["artifact sha", hashCell(artifact.artifact_digest)],
    ["补丁 sha", hashCell(artifact.patch_digest)], ["代码基线 sha", hashCell(artifact.code_base_digest)], ["gated tree sha", hashCell(snapshot.gated_tree)],
    ["输入 artifact sha", hashCell(artifact.input_artifact_digest)], ["工具链 sha", hashCell(artifact.toolchain_digest)],
    ["依赖 sha", hashCell(artifact.dependency_digest)], ["日志引用", hashCell(artifact.execution_log_ref)]];
  return `<div class="overview-status"><span class="pill ${escapeHtml(step.state)}">${escapeHtml(stateText(step.state))}</span><span class="eyebrow">STEP ${String(model.index).padStart(2, "0")}</span></div>
    <p class="overview-objective">${escapeHtml(model.plan.intent || model.plan.objective || step.node_id)}</p>
    ${renderExpectationEvidence(model.plan)}
    ${renderRepairLineage(model.repairBranches)}
    <div class="step-lifecycle">${["执行", "校验", "审查", "提交"].map((label, index) => `<span title="${phaseEvidenceMissing(model, index) ? "没有本次门禁记录，请查看门禁与溯源" : ""}" class="lifecycle-stage ${phaseEvidenceMissing(model, index) ? "unrecorded" : index < phase ? "done" : index === phase && !["PENDING", "READY", "NOT_DECLARED"].includes(step.state) ? "current" : ""}">${escapeHtml(label)}</span>`).join("")}</div>
    <div class="overview-metrics"><div class="overview-metric"><small>当前尝试 / 上限</small><strong>${escapeHtml(step.attempt)} / ${escapeHtml(step.max_attempts)}</strong></div><div class="overview-metric"><small>最近执行耗时</small><strong>${escapeHtml(stepDuration(model))}</strong></div></div>
    ${step.last_failure ? `<p class="summary-note warning">${escapeHtml(step.last_failure)}</p>` : ""}
    ${snapshot.worker_summary ? `<h3>执行摘要</h3><p class="summary-note">${escapeHtml(snapshot.worker_summary)}</p>` : ""}
    <h3>执行信息</h3><dl class="inspector-facts">${kvHtml(facts)}</dl>
    <h3>前置依赖</h3>${dependencyMarkup(model.plan.deps || [])}
    ${dependents.length ? '<h3>后续步骤</h3>' + dependencyMarkup(dependents) : ""}
    <h3>预期产出</h3>${(model.plan.expected_artifacts || []).map((file) => `<div class="file-entry">${escapeHtml(file)}</div>`).join("") || '<span class="muted">计划未声明额外产物</span>'}
    ${observations.length ? '<details class="evidence-disclosure"><summary>编码侧读码记录 · ' + observations.length + ' 次</summary>' + observations.map(row => '<p><strong>' + escapeHtml(row.tool) + '</strong> · ' + escapeHtml(JSON.stringify(row.arguments || {})) + '</p><p class="muted">提交 ' + escapeHtml(row.commit) + ' · ' + escapeHtml(row.status) + '</p><code>' + escapeHtml(row.evidence_digest) + '</code>').join('') + '</details>' : ''}
    <details class="evidence-disclosure" data-disclosure="hashes"><summary>提交与摘要 · 技术溯源</summary><dl class="inspector-facts">${kvHtml(hashes)}</dl></details>`;
}

function hashCell(value) {
  const text = String(value || "");
  return text ? `<code class="digest" title="${escapeHtml(text)}">${escapeHtml(text)}</code>` : '<span class="muted">—</span>';
}

async function loadStepDiff(model) {
  const host = $("#step-diff"); if (!host) return;
  const runId = MODULE_RUN.id;
  const identity = runId + ":" + model.step.step_id + ":" + (model.artifact ? model.artifact.artifact_digest : "none");
  if (model.declared === false || !model.artifact) { host.innerHTML = '<p class="empty">尚无记录的补丁。</p>'; return; }
  try {
    let payload = WORKSPACE.patches.get(identity);
    if (!payload) {
      payload = await api(`/api/runs/${encodeURIComponent(runId)}/steps/${encodeURIComponent(model.step.step_id)}/patch`);
      WORKSPACE.patches.set(identity, payload);
    }
    // A delayed patch belongs only to the inspector that requested it.
    if (WORKSPACE.selectedId !== model.step.step_id || WORKSPACE.tab !== "changes" || MODULE_RUN.id !== runId || $("#step-diff") !== host) return;
    if (!payload.patch) { host.innerHTML = '<p class="empty">尚无记录的补丁。</p>'; return; }
    host.innerHTML = typeof Diff2Html === "undefined" ? `<pre class="diff">${colourDiff(payload.patch)}</pre>`
      : Diff2Html.html(payload.patch, { drawFileList: false, matching: "lines", outputFormat: "line-by-line", colorScheme: "dark" });
  } catch (error) {
    if ($("#step-diff") === host) host.innerHTML = `<p class="empty">${escapeHtml(error.message)}</p>`;
  }
}

const ACTIVITY_TEXT = {
  StepDeclared: "步骤已创建", StepActivated: "依赖已满足", StepLeaseAcquired: "开始一次执行", StepStarted: "正在执行",
  StepGatekeeperEntered: "进入门禁", StepTier1Decided: "确定性校验完成", StepTier2Decided: "语义审查完成",
  StepCommitRequested: "准备提交", StepCommitted: "已提交", StepExecutionFailed: "执行失败", StepCacheHit: "复用已验证产物",
  StepLeaseExpired: "租约到期", ApprovalRecorded: "已记录人工决定", RunCreated: "任务已创建", RunStarted: "任务开始执行",
  RunCompleted: "任务已完成", RunFailed: "任务失败", RunEscalated: "等待人工处理", RunResumed: "任务恢复",
  RunRolledBack: "任务已回滚", RunPartiallyFailed: "任务部分失败", RunRebaseRequired: "需要重基",
};

function renderActivityRows(events) {
  return events.slice(-40).reverse().map((event) => {
    const timestamp = event.timestamp || event.created_at || "";
    const type = event.event_type || event.type || "";
    const text = ACTIVITY_TEXT[type] || type;
    return `<div class="activity-line"><time>${escapeHtml(timestamp ? timestamp.slice(11, 19) : "—")}</time><span>${escapeHtml(text)}${event.step_id ? " · " + escapeHtml(event.step_id.split(":").slice(-1)[0]) : ""}</span></div>`;
  }).join("") || '<p class="empty">尚无活动记录</p>';
}

function renderTaskOverview() {
  const title = $("#step-title"); if (title) title.textContent = "任务总览";
  const sub = $("#step-sub"); if (sub) sub.textContent = "点击图中的步骤，展开它的执行详情。";
  const body = $("#step-body");
  const plan = WORKSPACE.plan;
  if (body && plan) {
    const specs = WORKSPACE.specs;
    body.innerHTML = '<div class="eyebrow">GOAL</div><p class="overview-objective">' + escapeHtml(plan.objective)
      + '</p><h3>执行计划</h3><dl class="inspector-facts">'
      + kvHtml([["步骤", escapeHtml(String((plan.nodes || []).length))], ["依赖", escapeHtml(String((plan.edges || []).length))],
        ["风险级别", escapeHtml(plan.risk_level)], ["审批", escapeHtml(specs && specs.approval ? specs.approval.statement || "查看规格与计划" : "查看规格与计划")]])
      + '</dl>' + renderTrunkSummary(plan.trunk)
      + ((specs && specs.specs) || []).map((card) => `<details class="evidence-disclosure"><summary>${escapeHtml(card.title || card.spec_type || "规格")}</summary><dl class="inspector-facts">${kvHtml((card.summary || []).map(([key, value]) => [key, escapeHtml(value)]))}</dl></details>`).join("")
      + '<p class="muted inspector-caption">点击任意节点查看目标、依赖、改动、门禁和记录。</p>';
  }
  const actions = $("#step-actions"); if (actions) actions.innerHTML = '<p class="muted">选中步骤后查看可用操作。</p>';
  const escalation = $("#escalation-panel"); if (escalation) escalation.hidden = true;
  const tabs = $("#inspector-tabs"); if (tabs) tabs.hidden = true;
}

function renderRunStats(route, models) {
  const target = $("#run-stats"); if (!target) return;
  const committed = models.filter((model) => model.step.state === "COMMITTED").length;
  const active = models.filter((model) => ["LEASED", "RUNNING", "AWAITING_GATEKEEPER", "TIER1_PASSED", "TIER2_REVIEWING", "APPROVED", "COMMITTING"].includes(model.step.state)).length;
  const retries = models.reduce((sum, model) => sum + Math.max(0, model.attempts.length - 1), 0);
  const attention = models.filter((model) => ["FAILED", "TIMEOUT", "LOST", "ESCALATED", "REVISE"].includes(model.step.state)).length;
  const tiles = [["状态", route.status, "status"], ["已完成", committed + "/" + models.length, "count"],
    ["执行中", active, "count"], ["需关注", attention, attention ? "warn" : "count"],
    ["重试", retries, "count"], ["总尝试", (route.nodes || []).filter((node) => node.kind === "attempt").length, "count"]];
  target.innerHTML = tiles.map(([label, value, kind]) => `<div class="stat stat-${kind}"><span class="stat-label">${escapeHtml(label)}</span><span class="stat-value">${escapeHtml(value)}</span></div>`).join("");
  const fill = $("#run-progress-fill"); if (fill) fill.style.width = (models.length ? committed / models.length * 100 : 0) + "%";
}

async function loadExecution() {
  const runId = MODULE_RUN.id; if (!runId) return;
  const request = ++WORKSPACE.request;
  try {
    const [detail, route, plan, runs, goalAudit, validation] = await Promise.all([
      api(`/api/runs/${encodeURIComponent(runId)}`), api(`/api/runs/${encodeURIComponent(runId)}/route`),
      api(`/api/runs/${encodeURIComponent(runId)}/plan`), api("/api/runs"),
      api(`/api/runs/${encodeURIComponent(runId)}/goal-audit`).catch(() => ({status: "UNAVAILABLE", stop_reason: "目标审计未连接。后端升级并重启后可查看，当前仍可跟踪步骤执行。"})),
      api(`/api/runs/${encodeURIComponent(runId)}/validations`).catch(() => null),
    ]);
    if (request !== WORKSPACE.request || MODULE_RUN.id !== runId) return;
    const changedRun = WORKSPACE.runId !== runId;
    if (changedRun) {
      WORKSPACE.runId = runId; WORKSPACE.selectedId = ""; WORKSPACE.tab = "overview";
      WORKSPACE.graphKey = ""; WORKSPACE.inspectorKey = ""; WORKSPACE.zoom = 1;
      WORKSPACE.fitted = false; WORKSPACE.specs = null; WORKSPACE.patches.clear();
    }
    currentRunDetail = detail; currentRoute = route; WORKSPACE.plan = plan;
    if (isWorkflow()) {
      WORKFLOW.run = detail.run; WORKFLOW.goal = goalAudit; WORKFLOW.validation = validation;
      WORKFLOW.available.execute = true;
      renderWorkflowProgress(); updateWorkflowSections();
    }
    updateGoalPanel("#goal-audit-workspace", goalAudit, true);
    updateValidationWorkspace(validation, runId);
    WORKSPACE.runs = (runs.runs || []).slice().reverse();
    stepModels = buildStepModels(detail, route, plan);
    showError("#execution-error", null);
    const heading = $("#workflow-title"); if (heading) heading.textContent = plan.objective || plan.goal_id;
    const note = $("#run-note"); if (note) note.innerHTML = pill(detail.run.status) + '<span>'
      + escapeHtml(plan.goal_id) + '</span><code>' + escapeHtml(shortDigest(runId, 18)) + '</code>';
    syncRunNavigation(runId); renderRunStats(route, stepModels);
    const graphKey = JSON.stringify(stepModels);
    if (graphKey !== WORKSPACE.graphKey) {
      WORKSPACE.graphKey = graphKey; renderLane(stepModels, route);
    }
    if (!WORKSPACE.fitted) { fitGraph(); WORKSPACE.fitted = true; }
    const notes = $("#route-notes"); if (notes) notes.textContent = (route.notes || []).join(" ");
    const events = (route.nodes || []).flatMap((node) => node.kind === "attempt" ? node.events || [] : [node]);
    events.sort((a, b) => String(a.timestamp || a.started_at || "").localeCompare(String(b.timestamp || b.started_at || "")));
    const activity = $("#workspace-activity"); if (activity) activity.innerHTML = renderActivityRows(events);
    const latest = events.slice(-1)[0]; const caption = $("#activity-latest");
    if (caption && latest) caption.textContent = ACTIVITY_TEXT[latest.event_type] || latest.label || latest.event_type || "执行记录已更新";
    if (changedRun) {
      WORKSPACE.selectedId = (stepModels.find((model) => ["RUNNING", "ESCALATED", "AWAITING_GATEKEEPER", "TIER2_REVIEWING"].includes(model.step.state)) || {}).step?.step_id || "";
      try { WORKSPACE.specs = await api(`/api/runs/${encodeURIComponent(runId)}/specs`); } catch (_) { /* optional evidence; the explicit specs page remains available */ }
      if (request !== WORKSPACE.request || MODULE_RUN.id !== runId) return;
    }
    const selected = stepModels.find((model) => model.step.step_id === WORKSPACE.selectedId);
    if (selected) {
      const tabs = $("#inspector-tabs"); if (tabs) tabs.hidden = false;
      await selectStep(selected, true);
    } else { WORKSPACE.selectedId = ""; renderTaskOverview(); }
  } catch (error) {
    if (request === WORKSPACE.request) showError("#execution-error", error);
    if (isWorkflow()) throw error;
  }
}

/* ---------------------------------------------------------------------- 审计 */

async function loadAudit() {
  const runId = MODULE_RUN.id;
  if (!runId) return;
  const [audit, detail, score, route] = await Promise.all([
    api(`/api/runs/${encodeURIComponent(runId)}/audit`),
    api(`/api/runs/${encodeURIComponent(runId)}`),
    api(`/api/runs/${encodeURIComponent(runId)}/score`).catch(() => null),
    api(`/api/runs/${encodeURIComponent(runId)}/route`),
  ]);
  if (MODULE_RUN.id !== runId) return;
  updateGoalPanel("#goal-audit", audit.goal_audit || (isWorkflow() ? WORKFLOW.goal : null) || {});
  updateValidationPanel(audit.independent_validation, runId, detail.run || {});
  if (isWorkflow()) {
    WORKFLOW.run = detail.run;
    if (audit.goal_audit) WORKFLOW.goal = audit.goal_audit;
    WORKFLOW.validation = audit.independent_validation || WORKFLOW.validation;
    WORKFLOW.available.audit = true;
    renderWorkflowLoop(WORKFLOW.goal || {}); renderWorkflowProgress(); updateWorkflowSections();
  }
  const main = $("#audit-main");
  if (MODULE_RUN.id !== runId) return;
  if (main) stableHtml(main, renderScore(score) || '<p class="empty">暂时没有评分记录。</p>');
  const summary = $("#audit-summary");
  if (summary) summary.innerHTML = summaryTiles([
    ["任务状态", runStateLabel((detail.run || {}).status || "UNKNOWN")],
    ["已提交步骤", (detail.steps || []).filter((s) => s.state === "COMMITTED").length + " / " + (detail.steps || []).length],
    ["改动文件", new Set((detail.steps || []).flatMap((s) => (s.artifacts || []).flatMap((a) => a.changed_files || []))).size],
    ["证据评分", score ? score.score + " / 100" : "暂无记录"],
  ]);

  const steps = (detail.steps || []).filter((step) => (step.artifacts || []).length);
  const picker = $("#diff-step");
  const previousStep = AUDIT.runId === runId && picker ? picker.value : "";
  AUDIT.runId = runId;
  if (picker) {
    stableHtml(picker, steps.map((step) => `<option value="${escapeHtml(step.step_id)}">${
      escapeHtml(step.node_id)} · ${escapeHtml(stateText(step.state))}</option>`).join("")
      || '<option value="">没有带补丁的步骤</option>');
    picker.onchange = () => loadDiff(picker.value);
  }
  if (steps.length) {
    const selected = steps.some((s) => s.step_id === previousStep) ? previousStep : steps[steps.length - 1].step_id;
    if (picker) picker.value = selected;
    await loadDiff(selected);
  }
  else renderDiffFor("");

  if (MODULE_RUN.id !== runId) return;
  const answer = $("#audit");
  if (answer) stableHtml(answer, renderAuditAnswer(audit, route));
  const jsonl = $("#export-jsonl");
  if (jsonl) jsonl.href = `/api/runs/${encodeURIComponent(runId)}/export?fmt=jsonl`;
  const csv = $("#export-csv");
  if (csv) csv.href = `/api/runs/${encodeURIComponent(runId)}/export?fmt=csv`;

  const body = $("#events tbody");
  if (body) {
    try {
      const response = await fetch(`/api/runs/${encodeURIComponent(runId)}/export?fmt=jsonl`);
      if (!response.ok) throw new Error("事件读取失败，请重试");
      const rows = parseJsonl(await response.text());
      if (MODULE_RUN.id !== runId) return;
      AUDIT.events = rows;
      renderFilteredEvents();
    } catch (error) {
      if (MODULE_RUN.id !== runId) return;
      body.innerHTML = `<tr><td colspan="6" class="muted">${escapeHtml(error.message)}</td></tr>`;
    }
  }
  try { renderIdentity(await api("/api/owners")); } catch (error) { /* informative only */ }
  try {
    const metrics = await api("/api/metrics");
    renderMetricBars(metrics, "#metrics-bars");
  } catch (error) { /* informative only */ }
}

async function loadDiff(stepId) {
  const request = ++AUDIT.diffRequest;
  const runId = MODULE_RUN.id;
  const summary = $("#diff-summary");
  if (!stepId) {
    renderDiffFor("");
    if (summary) summary.textContent = "";
    return;
  }
  try {
    const payload = await api(
      `/api/runs/${encodeURIComponent(runId)}/steps/${encodeURIComponent(stepId)}/patch`);
    if (request !== AUDIT.diffRequest || runId !== MODULE_RUN.id) return;
    if (summary) {
      summary.innerHTML = [
        payload.diff_stat ? escapeHtml(payload.diff_stat) : "",
        `artifact <code>${escapeHtml(shortDigest(payload.artifact_digest))}</code>`,
        escapeHtml((payload.changed_files || []).join(", ")),
      ].filter(Boolean).join(" · ");
    }
    renderDiffFor(payload.patch);
  } catch (error) {
    if (request !== AUDIT.diffRequest || runId !== MODULE_RUN.id) return;
    renderDiffFor("");
    if (summary) summary.textContent = error.message;
  }
}

/* ======================================================================
 * Module pages: shared shell
 * ====================================================================== */

const MODULE_RUN = { id: document.body.dataset.runId || window.DAEDALUS_RUN_ID || "" };

async function initRunPicker(onChange) {
  const picker = $("#run-picker");
  if (!picker) return "";
  let selected = MODULE_RUN.id;
  try {
    const payload = await api("/api/runs");
    const runs = (payload.runs || []).slice().reverse();
    picker.innerHTML = runs.map((run) => `<option value="${escapeHtml(run.run_id)}">${
      escapeHtml(ellipsis(run.objective || run.goal_id, 45))} · ${escapeHtml(runStateLabel(run.status))}</option>`).join("") || '<option value="">没有 run</option>';
    if (!selected && runs.length) selected = runs[0].run_id;
    picker.value = selected;
    picker.addEventListener("change", () => {
      MODULE_RUN.id = picker.value;
      const base = window.location.pathname.split("/").slice(0, 2).join("/");
      window.history.replaceState({}, "", `${base}/${picker.value}`);
      syncRunNavigation(picker.value);
      onChange(picker.value);
      updateRunNote(runs.find((candidate) => candidate.run_id === picker.value));
      refreshBadge();
    });
    updateRunNote(runs.find((candidate) => candidate.run_id === selected));
    if (!runs.length) {
      const note = $("#run-note");
      if (note) note.innerHTML = '还没有任务。<a href="/">创建第一个任务 →</a>';
    }
  } catch (error) {
    showError("#planning-error", error);
    showError("#execution-error", error);
    showError("#audit-error", error);
  }
  MODULE_RUN.id = selected;
  syncRunNavigation(selected);
  return selected;
}


/* ======================================================================
 * 提任务 · the front door
 *
 * One text field (the task) and one optional path field. Everything else is a click: the model
 * reads the repository, asks a few questions with concrete options, and the answers become the
 * boundaries of the spec. The control plane's role is visible at each step — it decides which
 * questions are legal, it adds the boundary question when the model skips it, and it validates
 * the spec before the operator can freeze it.
 * ====================================================================== */

const INTAKE = {
  repos: [],
  repo: "",
  objective: "",
  session: null,
  index: 0,
  specs: [],
};

function showIntakeStep(step) {
  if (isWorkflow()) {
    WORKFLOW.draftStage = step;
    updateWorkflowSections(); renderWorkflowProgress();
    if (step === "review") focusWorkflowStage("plan");
  }
  $$("[data-create-stage]").forEach((item) => {
    if (item.dataset.createStage === step) item.setAttribute("aria-current", "step");
    else item.removeAttribute("aria-current");
  });
  for (const name of ["task", "questions", "review", "recent"]) {
    const section = $(`#intake-step-${name}`);
    if (section) section.hidden = name !== step;
  }
}

function renderIntakeRepos() {
  const host = $("#intake-repos");
  if (!host) return;
  if (!INTAKE.repos.length) {
    host.innerHTML = `<p class="muted">这个工作区还没有跑过任何仓库。用下面的「其他路径…」
      填一个 Git 仓库的绝对路径。</p>`;
    return;
  }
  host.innerHTML = INTAKE.repos.map((repo) => `
    <button type="button" class="repo-card${repo.path === INTAKE.repo ? " on" : ""}"
            data-path="${escapeHtml(repo.path)}">
      <strong>${escapeHtml(repo.name)}</strong>
      <span class="muted">${escapeHtml(repo.source)}</span>
      <code>${escapeHtml(ellipsis(repo.path, 46))}</code>
    </button>`).join("");
  $$(".repo-card", host).forEach((card) => {
    card.addEventListener("click", () => {
      INTAKE.repo = card.dataset.path;
      renderIntakeRepos();
      const field = $("#intake-repo-path");
      if (field) field.classList.add("hidden");
    });
  });
}

function renderIntakeRecent(items) {
  const host = $("#intake-recent");
  const section = $("#intake-step-recent");
  if (!host || !section) return;
  const rows = items || [];
  if (!rows.length) { section.hidden = true; return; }
  section.hidden = false;
  host.innerHTML = `<table class="table"><thead><tr>
      <th>任务</th><th>仓库</th><th>状态</th><th>模型</th><th>digest</th><th>run</th>
    </tr></thead><tbody>${rows.map((row) => `<tr>
      <td>${escapeHtml(ellipsis(row.objective, 52))}</td>
      <td class="muted">${escapeHtml(ellipsis(row.repo_path, 30))}</td>
      <td>${pill(row.status)}</td>
      <td class="muted">${escapeHtml(row.model || "—")}</td>
      <td class="mono">${escapeHtml(shortDigest(row.spec_digest, 12))}</td>
      <td class="mono">${row.run_id
        ? `<a href="/execution/${encodeURIComponent(row.run_id)}">${escapeHtml(
            shortDigest(row.run_id, 16))}</a>`
        : "—"}</td>
    </tr>`).join("")}</tbody></table>`;
}

function renderIntakeError(target, error) {
  const host = $(target);
  if (!host) return;
  host.hidden = false;
  const detail = error && error.detail;
  const lines = typeof detail === "object" && detail
    ? [detail.message, ...(detail.rejections || [])]
    : [error.message || String(error)];
  host.innerHTML = lines.map((line) =>
    `<div>${escapeHtml(line)}</div>`).join("");
}

async function loadIntake() {
  try {
    const [repos, recent] = await Promise.all([
      api("/api/repos"),
      api("/api/intakes?limit=8").catch(() => ({ intakes: [] })),
    ]);
    INTAKE.repos = repos.repos || [];
    if (!INTAKE.repo && INTAKE.repos.length) INTAKE.repo = INTAKE.repos[0].path;
    renderIntakeRepos();
    renderIntakeRecent(recent.intakes);
    const note = $("#intake-model-note");
    if (note) {
      note.textContent = INTAKE.repos.length
        ? "模型会先只读地看一遍这个仓库，不会执行任何东西。"
        : "";
    }
  } catch (error) {
    renderIntakeError("#intake-error", error);
  }
}

async function startIntake() {
  if (MODEL_REPORT && !(MODEL_REPORT.roles || []).length) { await openModelSettings(); return; }
  const objective = ($("#intake-objective") ? $("#intake-objective").value : "").trim();
  const typed = $("#intake-repo-path");
  const repo = (typed && !typed.classList.contains("hidden") && typed.value.trim())
    || INTAKE.repo;
  const errorHost = $("#intake-error");
  if (errorHost) errorHost.hidden = true;
  if (!objective) {
    renderIntakeError("#intake-error", { message: "先写一句你想让它做什么" });
    return;
  }
  if (!repo) {
    renderIntakeError("#intake-error", { message: "先选一个仓库，或者填一个路径" });
    return;
  }
  const button = $("#intake-start");
  if (button) { button.disabled = true; button.textContent = "模型正在读仓库…"; }
  try {
    INTAKE.objective = objective;
    INTAKE.repo = repo;
    const payload = await api("/api/intakes", {
      method: "POST",
      body: JSON.stringify({ repo_path: repo, objective }),
    });
    INTAKE.session = payload.intake;
    INTAKE.index = 0;
    INTAKE.facts = payload.facts;
    const note = $("#intake-model-note");
    if (note) {
      note.textContent = `模型 ${payload.intake.model} 读完 ${
        payload.facts.manifests.join(" / ") || "仓库"} 之后问了 ${
        payload.intake.questions.length} 个问题。`;
    }
    if (!INTAKE.session.questions.length) {
      await deriveIntakeSpec();
      return;
    }
    showIntakeStep("questions");
    renderIntakeQuestion();
  } catch (error) {
    renderIntakeError("#intake-error", error);
  } finally {
    if (button) { button.disabled = false; button.textContent = "分析任务 →"; }
  }
}

function renderIntakeQuestion() {
  const session = INTAKE.session;
  const question = session.questions[INTAKE.index];
  if (!question) return;
  const total = session.questions.length;
  const answered = new Set((session.answers || []).map((row) => row.question_id));

  const progress = $("#intake-progress");
  if (progress) {
    progress.innerHTML = session.questions.map((item, position) => `
      <span class="dot${answered.has(item.id) ? " done" : ""}${
        position === INTAKE.index ? " now" : ""}"></span>`).join("")
      + `<span class="muted">第 ${INTAKE.index + 1} / ${total} 题</span>`;
  }
  const title = $("#intake-question-title");
  if (title) title.textContent = question.question;
  const sub = $("#intake-question-sub");
  if (sub) {
    const source = question.id === "boundary" && session.rejections.some(
      (line) => line.includes("控制面补充"))
      ? "控制面补充的问题"
      : "模型的问题";
    // The field's own spec, from the server. Hardcoding "SPEC-03" here described the acceptance
    // command and the retry ceiling as boundary fields, which they are not.
    sub.textContent = `${source} · 决定 ${question.field_spec} 的「${question.field_label}」`;
  }
  const why = $("#intake-question");
  if (why) why.innerHTML = question.why
    ? `<p class="muted">${escapeHtml(question.why)}</p>` : "";

  const options = $("#intake-options");
  if (options) {
    const chosen = new Map((session.answers || [])
      .map((row) => [row.question_id, row.label]));
    options.innerHTML = question.options.map((option, position) => `
      <button type="button" class="option-card${
        chosen.get(question.id) === option.label ? " on" : ""}"
        data-option="${escapeHtml(option.id)}">
        <span class="option-key">${position + 1}</span>
        <span class="option-body">
          <strong>${escapeHtml(option.label)}</strong>
          <span class="muted">${escapeHtml(option.effect)}</span>
        </span>
      </button>`).join("");
    $$(".option-card", options).forEach((card) => {
      card.addEventListener("click", () => answerIntake(question.id, card.dataset.option));
    });
  }
  const freeWrap = $("#intake-free-wrap");
  if (freeWrap) freeWrap.hidden = false;
  const back = $("#intake-back");
  if (back) back.disabled = INTAKE.index === 0;

  const rejections = $("#intake-rejections");
  const lines = session.rejections || [];
  if (rejections) {
    rejections.hidden = !lines.length;
    rejections.innerHTML = lines.length
      ? `<strong>控制面拦下了 ${lines.length} 条不合法的问题</strong>`
        + `<ul>${lines.map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul>`
      : "";
  }
}

async function answerIntake(questionId, optionId, freeText) {
  try {
    const body = { question_id: questionId };
    if (optionId) body.option_id = optionId;
    if (freeText) body.free_text = freeText;
    const payload = await api(
      `/api/intakes/${encodeURIComponent(INTAKE.session.intake_id)}/answers`,
      { method: "POST", body: JSON.stringify(body) },
    );
    INTAKE.session = payload.intake;
    const field = $("#intake-free-text");
    if (field) field.value = "";
    if (INTAKE.index < INTAKE.session.questions.length - 1) {
      INTAKE.index += 1;
      renderIntakeQuestion();
      return;
    }
    await deriveIntakeSpec();
  } catch (error) {
    renderIntakeError("#intake-error", error);
    showIntakeStep("task");
  }
}

async function skipIntakeQuestion() {
  const question = INTAKE.session.questions[INTAKE.index];
  try {
    const payload = await api(
      `/api/intakes/${encodeURIComponent(INTAKE.session.intake_id)}/answers`,
      { method: "POST", body: JSON.stringify({ question_id: question.id, skip: true }) },
    );
    INTAKE.session = payload.intake;
    if (INTAKE.index < INTAKE.session.questions.length - 1) {
      INTAKE.index += 1;
      renderIntakeQuestion();
    } else {
      await deriveIntakeSpec();
    }
  } catch (error) {
    renderIntakeError("#intake-error", error);
  }
}

async function deriveIntakeSpec() {
  const payload = await api(
    `/api/intakes/${encodeURIComponent(INTAKE.session.intake_id)}/spec`,
    { method: "POST" },
  );
  INTAKE.session = payload.intake;
  INTAKE.specs = payload.specs || [];
  showIntakeStep("review");
  const preview = $("#intake-plan-preview");
  const planCard = INTAKE.specs.find((card) => card.key === "spec_02");
  if (preview) preview.innerHTML = planCard ? renderIntakePlan(planCard.document) : "";

  const sub = $("#intake-review-sub");
  if (sub) {
    sub.textContent = `模型 ${payload.intake.model} 读你的任务和仓库之后提出的 spec；`
      + `digest ${shortDigest(payload.spec_digest, 16)}。控制面校验通过之后才能冻结。`;
  }
  const note = $("#intake-review-note");
  if (note) {
    const asked = (payload.intake.answers || []).map((row) => row.field);
    const unasked = payload.intake.unasked_policy_fields || [];
    const adjustments = payload.adjustments || [];
    const lines = [];
    if (asked.length) {
      lines.push(`由你点击决定：${asked.map(escapeHtml).join("、")}`);
    }
    if (unasked.length) {
      lines.push(`<strong>模型替你决定了</strong>：${unasked.map(escapeHtml).join("、")}`
        + `（这些字段没有问过你，用的是默认值）`);
    }
    if (adjustments.length) {
      lines.push(`控制面收紧了模型的提议：${adjustments.map(escapeHtml).join("；")}`);
    }
    if (INTAKE.session.rejections && INTAKE.session.rejections.length) {
      lines.push(`被拒绝的问题：${INTAKE.session.rejections.map(escapeHtml).join("；")}`);
    }
    note.innerHTML = lines.map((line) => `<div>${line}</div>`).join("");
  }
  const answers = $("#intake-answers");
  if (answers) {
    answers.innerHTML = (payload.intake.answers || []).map((row) => `
      <div class="answer-row">
        <span class="muted">${escapeHtml(row.field)}</span>
        <strong>${escapeHtml(row.label)}</strong>
        <code>${escapeHtml(typeof row.value === "string"
          ? row.value : JSON.stringify(row.value))}</code>
      </div>`).join("");
  }
  const document = $("#intake-document");
  if (document) {
    document.innerHTML = renderSpecCards({ specs: INTAKE.specs });
    wireSpecCards();
  }
}

async function freezeIntake() {
  const out = $("#intake-freeze-out");
  const button = $("#intake-freeze");
  const show = (message, bad) => {
    if (!out) return;
    out.hidden = false;
    out.className = bad ? "callout bad" : "callout";
    out.textContent = message;
  };
  if (button) { button.disabled = true; button.textContent = "正在创建 run…"; }
  try {
    const payload = await api(
      `/api/intakes/${encodeURIComponent(INTAKE.session.intake_id)}/freeze`,
      { method: "POST", body: JSON.stringify({spec_digest: INTAKE.session.spec_digest, use_model: true, enable_review: true}) },
    );
    show(`已冻结 spec ${shortDigest(payload.spec_digest, 12)}，run ${
      shortDigest(payload.run_id, 16)} 已受理。`);
    INTAKE.session = { ...INTAKE.session, status: "FROZEN", run_id: payload.run_id };
    if (isWorkflow()) await openWorkflowRun(payload.run_id, "execute");
    else window.location.href = `/execution/${encodeURIComponent(payload.run_id)}`;
  } catch (error) {
    show(error.detail ? (typeof error.detail === "string"
      ? error.detail : JSON.stringify(error.detail)) : error.message, true);
  } finally {
    if (button) { button.disabled = false; button.textContent = "确认并开始执行"; }
  }
}



/* Model connections: explicit global entry, native protocols and safe import. */
let MODEL_REPORT = null;
let MODEL_CATALOG = null;
let MODEL_IMPORT = null;
let MODEL_EDIT = null;
let MODEL_PANEL_BOUND = false;
const MODEL_ROLES = {planner: "规划", coder: "编码", reviewer: "审查"};

function renderModelPanel(report) {
  MODEL_REPORT = report;
  const roles = report.roles || [];
  const override = report.override || null;
  const host = $("#model-current");
  if (host) host.innerHTML = roles.length ? roles.map((role) => `<div class="model-row"><span class="model-role">${escapeHtml(role.role)}<small>${escapeHtml(MODEL_ROLES[role.role] || "")}</small></span><span class="model-endpoint"><strong>${escapeHtml(role.model)}</strong><code>${escapeHtml(role.base_url)}</code><small>${escapeHtml(role.api_format || "openai_chat")}</small></span><span class="model-fact"><b>来源</b>${escapeHtml(role.source)}</span><span class="model-fact"><b>密钥</b>${escapeHtml(role.key)}</span><span class="model-locality ${role.loopback ? "local" : "remote"}">${role.loopback ? "本机" : "非本机"}</span><button type="button" class="ghost small" data-model-edit="${escapeHtml(role.role)}">调整</button></div>`).join("") : '<p class="empty">这个工作区还没有配置任何模型角色。导入已有配置，或在下方选择服务商并填入模型与密钥。</p>';
  if (host) $$('[data-model-edit]', host).forEach((button) => button.addEventListener("click", () => editModelRole(button.dataset.modelEdit)));
  const unique = [...new Set(roles.map((role) => role.model))];
  const missing = report.missing_roles || [];
  const label = roles.length ? unique.join(" · ") + (missing.length ? " · 待配置：" + missing.map((r) => MODEL_ROLES[r] || r).join("、") : "") : "尚未配置模型，先导入或添加连接";
  for (const id of ["#workflow-model-label", "#model-top-status"]) if ($(id)) $(id).textContent = id === "#model-top-status" && roles.length ? (missing.length ? "待补全" : "已配置") : label;
  if ($("#model-summary")) $("#model-summary").textContent = roles.length ? `当前 ${roles.length} 个角色已配置，可分别调整。` : "导入配置，或选择服务商添加第一个模型。";
  if ($("#model-note")) $("#model-note").textContent = report.persisted ? "已安全保存，重启后自动恢复" : "当前会话连接";
  const storage = report.credential_store;
  if ($("#model-persist")) {
    $("#model-persist").disabled = !storage?.supported;
    if (!storage?.supported) $("#model-persist").checked = false;
  }
  if ($("#model-caveat")) $("#model-caveat").textContent = storage?.supported
    ? "安全保存使用系统钥匙串；连接配置与导出不包含密钥。已保存的连接会在重启后自动恢复。"
    : "当前后端未提供安全凭证存储，此处只能应用临时连接；密钥不会写入普通文件。";
  if ($("#model-reset")) $("#model-reset").hidden = !override && !Object.keys(report.overrides || {}).length && !storage?.restore_error;
  if ($("#model-reset")) $("#model-reset").textContent = report.persisted ? "清除已保存连接" : "恢复启动配置";
  const warning = $("#model-server-note");
  if (warning) {
    const message = storage?.restore_error || (!storage ? "当前后端尚未加载安全保存功能，请重启后端后再保存连接。" : "");
    warning.hidden = !message; warning.textContent = message;
  }
  const select = $("#model-role");
  if (select && select.options && select.options.length <= 1) {
    for (const name of new Set(["planner", "coder", "reviewer", ...roles.map((role) => role.role)])) {
      const option = document.createElement("option"); option.value = name; option.textContent = `${MODEL_ROLES[name] || name} · ${name}`; select.appendChild(option);
    }
  }
  updateModelLocality();
}

function modelForm() {
  const value = (id) => ($(id) ? ($htmlValue($(id))).trim() : "");
  let request_options = {};
  try { request_options = JSON.parse(value("#model-options") || "{}"); }
  catch { throw new Error("兼容参数必须是有效 JSON；不需要额外参数时留空即可。"); }
  const body = {base_url: value("#model-base-url"), model: value("#model-name"), api_key: value("#model-key"),
    timeout_sec: Number(value("#model-timeout") || 120), role: value("#model-role"),
    api_format: value("#model-protocol") || "openai_chat", provider: value("#model-provider") || "custom",
    api_key_env: value("#model-key-env"), request_options,
    acknowledge_remote: Boolean($("#model-ack") && $("#model-ack").checked),
    persist: Boolean($("#model-persist") && $("#model-persist").checked)};
  body.reuse_existing_key = Boolean(MODEL_EDIT && MODEL_EDIT.role === body.role && MODEL_EDIT.base_url === body.base_url && MODEL_EDIT.api_format === body.api_format && !body.api_key && !body.api_key_env);
  return body;
}

function $htmlValue(element) { return String(element.value || ""); }

function showModelOut(message, bad) {
  const out = $("#model-out"); if (!out) return;
  out.hidden = false; out.className = bad ? "callout bad" : "callout"; out.textContent = message;
}

function updateModelLocality() {
  const address = $("#model-base-url");
  const remote = address && !/^https?:\/\/(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0)(?=[:/]|$)/i.test($htmlValue(address));
  if ($("#model-ack-wrap")) $("#model-ack-wrap").hidden = !remote;
  if ($("#model-protocol-label")) $("#model-protocol-label").textContent = $htmlValue($("#model-protocol") || {}) || "OpenAI 兼容";
}

async function loadModelPanel() {
  try { renderModelPanel(await api("/api/model")); }
  catch (error) { showModelOut(error.message, true); }
}

async function loadModelCatalog() {
  if (MODEL_CATALOG) return;
  MODEL_CATALOG = await api("/static/model-providers.json");
  const select = $("#model-provider");
  if (select) {
    select.innerHTML = (MODEL_CATALOG.providers || []).map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.group + " · " + item.name)}</option>`).join("");
    select.value = "deepseek";
    if (!($htmlValue($("#model-base-url") || {}))) chooseModelProvider();
  }
}

function chooseModelProvider() {
  const selected = (MODEL_CATALOG?.providers || []).find((item) => item.id === $("#model-provider")?.value);
  if (!selected) return;
  for (const [id,value] of [["#model-base-url",selected.base_url],["#model-protocol",selected.api_format],["#model-key-env",""]]) if ($(id)) $(id).value = value;
  if ($("#model-provider-hint")) $("#model-provider-hint").textContent = selected.hint;
  if ($("#model-key-env")) $("#model-key-env").placeholder = selected.api_key_env || "本地服务通常无需密钥";
  if ($("#model-key")) $("#model-key").value = "";
  if ($("#model-name")) $("#model-name").value = "";
  if ($("#model-options")) $("#model-options").value = selected.request_options ? JSON.stringify(selected.request_options, null, 2) : "";
  if ($("#model-choices")) $("#model-choices").innerHTML = "";
  MODEL_EDIT = null;
  updateModelLocality();
}

async function openModelSettings() {
  const dialog = $("#model-settings-dialog"); if (!dialog) return;
  if (typeof dialog.showModal === "function" && !dialog.open) dialog.showModal(); else dialog.setAttribute("open", "");
  try { await loadModelCatalog(); await loadModelPanel(); }
  catch { showModelOut("无法读取模型服务商列表，请刷新页面后重试。", true); }
}

function closeModelSettings() {
  const dialog = $("#model-settings-dialog");
  if (dialog?.close) dialog.close(); else if (dialog) dialog.removeAttribute("open");
  clearModelSensitiveInputs();
}

function clearModelSensitiveInputs() {
  for (const id of ["#model-key", "#model-import-content", "#model-file"]) if ($(id)) $(id).value = "";
  MODEL_IMPORT = null;
  if ($("#model-import-preview-box")) $("#model-import-preview-box").hidden = true;
}

function editModelRole(name) {
  const role = MODEL_REPORT?.roles.find((item) => item.role === name); if (!role) return;
  for (const [id,value] of [["#model-provider",role.provider || "custom"],["#model-protocol",role.api_format || "openai_chat"],["#model-role",name],["#model-base-url",role.base_url],["#model-name",role.model],["#model-timeout",role.timeout_sec || 120],["#model-key", ""],["#model-key-env", role.api_key_env || ""],["#model-options", Object.keys(role.request_options || {}).length ? JSON.stringify(role.request_options, null, 2) : ""]]) if ($(id)) $(id).value = value;
  MODEL_EDIT = {role:name,base_url:role.base_url,api_format:role.api_format || "openai_chat"};
  if ($("#model-key")) $("#model-key").placeholder = "留空可保留此连接已有密钥";
  updateModelLocality();
  if ($("#model-ack")) $("#model-ack").checked = !role.loopback;
}

function requireModelProtocol(body) {
  if (!MODEL_REPORT?.supported_api_formats && body.api_format !== "openai_chat") throw new Error("后端尚未加载原生模型协议，请先重启服务加载本轮更新。");
}

async function testModelEndpoint() {
  try {
    const body = modelForm(); requireModelProtocol(body);
    showModelOut("正在调用模型验证连接…", false);
    const result = await api("/api/model/test", {method:"POST",body:JSON.stringify(body)});
    showModelOut(result.ok ? `连接成功 · ${result.latency_ms} ms · ${result.reported_model} · 回答：${result.reply}` : `${result.error} ${result.hint || ""}`, !result.ok);
  } catch (error) { showModelOut(error.message, true); }
}

async function saveModelEndpoint() {
  try {
    const body = modelForm(); requireModelProtocol(body);
    showModelOut(body.persist ? "正在安全保存到系统钥匙串…" : "正在应用临时连接…", false);
    const result = await api("/api/model", {method:"POST",body:JSON.stringify(body)});
    renderModelPanel(result);
    if (body.persist && !result.persisted) throw new Error("后端未确认安全保存，请重启加载新版后端并重新保存。");
    MODEL_EDIT = {role:body.role,base_url:body.base_url,api_format:body.api_format};
    if ($("#model-key")) $("#model-key").value = "";
    showModelOut(body.persist && result.persisted ? "连接已安全保存，新任务将使用此模型；重启后自动恢复。" : "已应用临时连接，重启后恢复已保存或启动时的配置。", false);
  } catch (error) { showModelOut(error.message, true); }
}

async function resetModelEndpoint() {
  try { renderModelPanel(await api("/api/model",{method:"DELETE"})); MODEL_EDIT = null; showModelOut("连接已清除，当前使用服务启动配置。",false); }
  catch(error) { showModelOut(error.message,true); }
}

async function discoverModels() {
  try {
    const body = modelForm(); requireModelProtocol(body); showModelOut("正在读取此账户可用的模型…",false);
    const result = await api("/api/model/models",{method:"POST",body:JSON.stringify(body)});
    if (!result.ok) throw new Error(`${result.error} ${result.hint || ""}`);
    const host = $("#model-choices");
    if (host) host.innerHTML = (result.models || []).map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)}</option>`).join("");
    showModelOut(`已读取 ${result.models.length} 个模型，点击模型 ID 输入框选择；也可直接手填。`,false);
  } catch(error) { showModelOut(error.message,true); }
}

async function previewModelImport(content, format = "auto") {
  try {
    if (!MODEL_REPORT?.supported_api_formats) throw new Error("配置导入需要新版后端，请先重启服务加载本轮更新。");
    const preview = await api("/api/model/import/preview",{method:"POST",body:JSON.stringify({content,format})});
    MODEL_IMPORT = {content,format};
    const host = $("#model-import-preview-box"); if (!host) return;
    host.hidden = false;
    host.innerHTML = `<h3>即将更新 ${preview.profiles.length} 组连接</h3>${preview.profiles.map((item) => `<div class="model-import-entry"><strong>${escapeHtml(item.role)}</strong><span>${escapeHtml(item.model)}</span><small>${escapeHtml(item.api_format)} · ${escapeHtml(item.base_url)}</small><small>${item.key_set ? "已带入密钥（不回显）" : escapeHtml(item.api_key_env ? "使用环境变量 " + item.api_key_env : "无密钥")}</small></div>`).join("")}${preview.remote_hosts.length ? '<label class="switch"><input type="checkbox" id="model-import-ack" />允许任务内容发送到上述非本机接口</label>' : '<input type="checkbox" id="model-import-ack" checked hidden />'}<button type="button" class="primary" id="model-import-apply">应用这些连接</button>`;
    $("#model-import-apply")?.addEventListener("click", applyModelImport);
    showModelOut("配置已解析。核对角色、模型和地址后再应用。",false);
  } catch(error) { MODEL_IMPORT = null; showModelOut(error.message,true); }
}

async function applyModelImport() {
  if (!MODEL_IMPORT) return;
  try {
    const request = {...MODEL_IMPORT,acknowledge_remote:Boolean($("#model-import-ack")?.checked),
      persist:Boolean($("#model-persist")?.checked)};
    const result = await api("/api/model/import",{method:"POST",body:JSON.stringify(request)});
    renderModelPanel(result);
    if (request.persist && !result.persisted) throw new Error("后端未确认安全保存，请重启加载新版后端并重新导入。");
    MODEL_IMPORT = null;
    if ($("#model-import-content")) $("#model-import-content").value = "";
    if ($("#model-import-preview-box")) $("#model-import-preview-box").hidden = true;
    showModelOut(request.persist ? "模型配置已安全保存，重启后自动恢复。" : "模型配置已临时应用到所列角色。",false);
  } catch(error) { showModelOut(error.message,true); }
}

async function downloadModelConfig(template = false) {
  try {
    const data = await api(template ? "/api/model/template" : "/api/model/export");
    const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:"application/json"}));
    const link = document.createElement("a"); link.href=url; link.download=template ? "daedalus-model-template.json" : "daedalus-models-without-keys.json"; link.click(); URL.revokeObjectURL(url);
    showModelOut(template ? "模板已下载；填入模型 ID 后即可导入。" : "已导出不含密钥的连接配置。",false);
  } catch(error) { showModelOut(error.message,true); }
}

function initModelPanel() {
  if (MODEL_PANEL_BOUND) return; MODEL_PANEL_BOUND = true;
  $$('[data-model-open]').forEach((button) => button.addEventListener("click",openModelSettings));
  const bind = (id, fn, event = "click") => { if ($(id)) $(id).addEventListener(event, fn); };
  bind("#model-close",closeModelSettings); bind("#model-test",testModelEndpoint); bind("#model-save",saveModelEndpoint); bind("#model-reset",resetModelEndpoint); bind("#model-discover",discoverModels);
  bind("#model-provider",chooseModelProvider,"change"); bind("#model-base-url",updateModelLocality,"input"); bind("#model-protocol",updateModelLocality,"change");
  bind("#model-settings-dialog",clearModelSensitiveInputs,"close");
  bind("#model-template",() => downloadModelConfig(true)); bind("#model-export",() => downloadModelConfig(false));
  bind("#model-paste-toggle",() => { if ($("#model-import-box")) $("#model-import-box").hidden = !$("#model-import-box").hidden; });
  bind("#model-import-preview",() => previewModelImport($htmlValue($("#model-import-content") || {})));
  bind("#model-import-file",() => $("#model-file")?.click());
  bind("#model-file",async (event) => {
    const file = event.target.files?.[0]; if (!file) return;
    if (file.size > 128 * 1024) { showModelOut("配置文件不能超过 128 KB。",true); return; }
    const extension = file.name.split(".").pop().toLowerCase();
    try { await previewModelImport(await file.text(), ["json","toml","env"].includes(extension) ? extension : "auto"); }
    catch { showModelOut("无法读取该配置文件。",true); }
    event.target.value = "";
  },"change");
  void loadModelPanel();
}


function initIntake() {
  $$("[data-objective]").forEach((button) => button.addEventListener("click", () => {
    const input = $("#intake-objective");
    if (input) { input.value = button.dataset.objective; input.focus(); }
  }));
  const start = $("#intake-start");
  if (start) start.addEventListener("click", startIntake);
  const other = $("#intake-other-repo");
  if (other) other.addEventListener("click", () => {
    const field = $("#intake-repo-path");
    if (!field) return;
    field.classList.toggle("hidden");
    if (!field.classList.contains("hidden")) field.focus();
  });
  const objective = $("#intake-objective");
  if (objective) {
    objective.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") startIntake();
    });
  }
  const back = $("#intake-back");
  if (back) back.addEventListener("click", () => {
    if (INTAKE.index > 0) { INTAKE.index -= 1; renderIntakeQuestion(); }
  });
  const skip = $("#intake-skip");
  if (skip) skip.addEventListener("click", skipIntakeQuestion);
  const free = $("#intake-free-submit");
  if (free) free.addEventListener("click", () => {
    const question = INTAKE.session.questions[INTAKE.index];
    const text = ($("#intake-free-text") ? $("#intake-free-text").value : "").trim();
    if (!text) return;
    answerIntake(question.id, "", text);
  });
  const edit = $("#intake-edit");
  if (edit) edit.addEventListener("click", () => {
    INTAKE.index = 0;
    showIntakeStep("questions");
    renderIntakeQuestion();
  });
  const freeze = $("#intake-freeze");
  if (freeze) freeze.addEventListener("click", freezeIntake);
  initModelPanel();
  loadIntake();
}

async function initModule() {
  const page = document.body.dataset.page;
  if (page === "intake") {
    // The intake is not a polling view: it is a conversation, and re-rendering it under the
    // operator's cursor would move the option they were about to click.
    initIntake();
    await refreshBadge();
    return;
  }
  const load = { planning: loadPlanning, execution: loadExecution, audit: loadAudit }[page];
  if (!load) return;
  let loadSequence = 0;
  const loader = async () => {
    const request = ++loadSequence;
    const runId = MODULE_RUN.id;
    try { await load(); if (request === loadSequence && runId === MODULE_RUN.id) showError(`#${page}-error`, null); }
    catch (error) { if (request === loadSequence && runId === MODULE_RUN.id) showError(`#${page}-error`, error); }
  };
  if (page === "audit") bindAuditViews();
  await initRunPicker(loader);
  if (!MODULE_RUN.id && page !== "execution") {
    for (const selector of ["#spec-cards", "#spec-approval", "#spec-registry", "#audit", "#diff", "#plan-map", "#audit-main"]) {
      const host = $(selector);
      if (host) host.innerHTML = '<p class="empty">创建任务后，这里将展示对应的计划与执行证据。</p>';
    }
  }
  if (page === "execution") bindWorkspace();
  await loader();
  if ($("#auto-refresh")) startPolling(loader);
  else {
    const refresh = $("#refresh");
    if (refresh) refresh.addEventListener("click", loader);
  }
  wireDiffMode();
  await refreshBadge();
}

/* Shared task journey: summaries first, evidence on demand. */
const BOARD = { runs: [] };
const AUDIT = { events: [], runId: "", diffRequest: 0 };
const PLANNING = { selected: "", runId: "" };
function summaryTiles(items) {
  return items.map(([label, value]) => `<div class="summary-tile"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");
}
function taskCategory(run) {
  if (run.status === "COMPLETED") return "done";
  if (["AWAITING_APPROVAL", "PARTIAL_FAILURE", "PARKED", "FAILED", "ESCALATED", "CANCELLED"].includes(run.status)) return "attention";
  return "active";
}
function filterTasks(runs, query, category) {
  return runs.filter((run) => (category === "all" || taskCategory(run) === category)
    && [run.objective, run.goal_id, run.run_id].join(" ").toLowerCase().includes(query.toLowerCase().trim()));
}
function renderTaskCards() {
  const host = $("#task-cards");
  if (!host) return;
  const runs = BOARD.runs;
  const summary = $("#task-summary");
  if (summary) summary.innerHTML = summaryTiles([["全部任务", runs.length], ["执行中", runs.filter((r) => taskCategory(r) === "active").length], ["需关注", runs.filter((r) => taskCategory(r) === "attention").length], ["已完成", runs.filter((r) => taskCategory(r) === "done").length]]);
  const query = $("#board-search");
  const filter = $("#board-filter");
  const shown = filterTasks(runs, query ? query.value : "", filter ? filter.value : "all").slice().reverse();
  host.innerHTML = shown.map((run) => {
    const total = Object.values(run.steps || {}).reduce((a, b) => a + b, 0);
    const done = (run.steps || {}).COMMITTED || 0;
    const percent = total ? Math.min(100, Math.round(done / total * 100)) : 0;
    const id = encodeURIComponent(run.run_id);
    return `<article class="task-card"><header><span class="task-state ${escapeHtml(taskCategory(run))}">${escapeHtml(runStateLabel(run.status))}</span><span class="muted">${escapeHtml(timeAgo(run.updated_at || run.created_at))}</span></header><h3><a href="/execution/${id}">${escapeHtml(run.objective || run.goal_id)}</a></h3><p class="muted">${escapeHtml(run.goal_id)} · ${done} / ${total} 个已声明步骤已提交</p><div class="bar" role="progressbar" aria-label="已声明步骤提交比例" aria-valuenow="${percent}" aria-valuemin="0" aria-valuemax="100"><span style="width:${percent}%"></span></div><footer><a href="/planning/${id}">查看计划</a><a href="/audit/${id}">变更审计</a><a class="task-open" href="/execution/${id}">打开工作台 ↗</a></footer></article>`;
  }).join("") || `<div class="empty-state"><h3>${runs.length ? "没有匹配的任务" : "从第一个目标开始"}</h3><p class="muted">${runs.length ? "试试其他关键词或切换状态筛选。" : "描述目标，确认计划，在工作台跟踪每一步。"}</p>${runs.length ? "" : '<a class="button primary" href="/">＋ 新建任务</a>'}</div>`;
}
function updateRunNote(run) {
  const note = $("#run-note");
  if (!note || !run) return;
  note.innerHTML = `<strong>${escapeHtml(run.objective || run.goal_id)}</strong><span class="task-state ${escapeHtml(taskCategory(run))}">${escapeHtml(runStateLabel(run.status))}</span><details class="inline-meta"><summary>任务标识</summary><code>${escapeHtml(run.run_id)}</code><br><code>${escapeHtml(run.spec_digest)}</code></details>`;
}
function renderPlanOverview(plan, detail) {
  const host = $("#plan-map");
  if (!host) return;
  const key = JSON.stringify([MODULE_RUN.id, plan, detail.steps]);
  if (PLANNING.renderKey === key) return;
  PLANNING.renderKey = key;
  const models = buildStepModels(detail, { nodes: [], lanes: [] }, plan);
  const layout = buildDagLayout(models);
  const summary = $("#plan-summary");
  if (summary) summary.innerHTML = summaryTiles([["计划步骤", models.length], ["依赖关系", layout.edges.length], ["已提交", models.filter((m) => m.step.state === "COMMITTED").length], ["起始步骤", models.filter((m) => !(m.plan.deps || []).length).length]]);
  if (!models.length) {
    host.innerHTML = '<p class="empty">计划尚未生成。稍后刷新查看步骤。</p>';
    $("#plan-detail").innerHTML = '<p class="empty">有计划后可查看步骤目标、依赖与验收标准。</p>';
    return;
  }
  if (PLANNING.runId !== MODULE_RUN.id) PLANNING.selected = "";
  PLANNING.runId = MODULE_RUN.id;
  const lines = layout.edges.map((edge) => {
    const a = layout.points.get(edge.from), b = layout.points.get(edge.to);
    const x = a.x + STEP.w, y = a.y + STEP.h / 2, end = b.y + STEP.h / 2;
    return `<path d="M ${x} ${y} C ${x + STEP.gap / 2} ${y}, ${b.x - STEP.gap / 2} ${end}, ${b.x} ${end}" marker-end="url(#plan-arrow)" />`;
  }).join("");
  host.innerHTML = `${layout.cyclic || layout.missing.length ? '<p class="alert">计划存在循环或缺失依赖，请检查规格。</p>' : ""}<div class="plan-canvas" style="width:${layout.width}px;height:${layout.height}px"><svg aria-hidden="true" width="${layout.width}" height="${layout.height}"><defs><marker id="plan-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8" /></marker></defs>${lines}</svg>${models.map((m) => {
    const point = layout.points.get(m.step.node_id);
    return `<button class="plan-node" data-plan-node="${escapeHtml(m.step.node_id)}" style="left:${point.x}px;top:${point.y}px;width:${STEP.w}px;height:${STEP.h}px" aria-pressed="false"><span class="muted">STEP ${String(m.index).padStart(2, "0")} · ${escapeHtml(stateText(m.step.state))}</span><strong>${escapeHtml(m.plan.objective || m.step.node_id)}</strong><span class="muted">${expectationBadge(m.plan) || ((m.plan.deps || []).length ? (m.plan.deps || []).length + " 个前置步骤" : "起始步骤")}</span></button>`;
  }).join("")}</div>`;
  const select = (id) => {
    const m = models.find((item) => item.step.node_id === id) || models[0];
    PLANNING.selected = m.step.node_id;
    $$("[data-plan-node]", host).forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.planNode === m.step.node_id)));
    const definition = Object.fromEntries(
      Object.entries(m.plan).filter(([key]) => !key.startsWith("expectation"))
    );
    $("#plan-detail").innerHTML = `<span class="eyebrow">STEP ${m.index} / ${models.length}</span>`
      + `<h3>${escapeHtml(m.plan.objective || m.step.node_id)}</h3><p>${escapeHtml(stateText(m.step.state))}</p>`
      + renderExpectationEvidence(m.plan) + renderRepairLineage(m.repairBranches)
      + `<h4>前置依赖</h4><p>${escapeHtml((m.plan.deps || []).join(" · ") || "无，可直接开始")}</p>`
      + `<h4>预期产物</h4>${renderDocument(m.plan.expected_artifacts || [])}`
      + `<h4>验收标准</h4>${renderDocument((m.plan.extra || {}).acceptance_criteria || m.plan.acceptance_criteria || "沿用目标规格中的验收标准")}`
      + `<details class="secondary-details"><summary>完整步骤定义</summary>${renderDocument(definition)}</details>`
      + `<a class="button" href="/execution/${encodeURIComponent(MODULE_RUN.id)}">进入工作台查看执行 →</a>`;
  };
  $$("[data-plan-node]", host).forEach((button) => button.addEventListener("click", () => select(button.dataset.planNode)));
  select(PLANNING.selected);
}
function renderIntakePlan(plan) {
  const nodes = (plan || {}).nodes || [];
  if (!nodes.length) return '<p class="muted">完整执行计划将在任务创建后展示。</p>';
  return `<h3>将执行 ${nodes.length} 个步骤</h3><div class="intake-plan-list">${nodes.map((node, index) => `<details><summary><span class="step-number">${index + 1}</span><strong>${escapeHtml(node.objective || node.node_id)}</strong><span class="muted">${(node.deps || []).length ? "依赖 " + (node.deps || []).length + " 步" : "起始"}</span></summary><div>${renderDocument(node)}</div></details>`).join("")}</div>`;
}
function bindAuditViews() {
  const buttons = $$("[data-audit-tab]");
  const select = (button) => {
    buttons.forEach((item) => { item.setAttribute("aria-selected", String(item === button)); item.tabIndex = item === button ? 0 : -1; });
    $$("[data-audit-view]").forEach((panel) => { panel.hidden = panel.dataset.auditView !== button.dataset.auditTab; });
  };
  buttons.forEach((button, index) => {
    button.addEventListener("click", () => select(button));
    button.addEventListener("keydown", (event) => {
      let next;
      if (event.key === "ArrowRight") next = (index + 1) % buttons.length;
      if (event.key === "ArrowLeft") next = (index + buttons.length - 1) % buttons.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = buttons.length - 1;
      if (next !== undefined) { event.preventDefault(); select(buttons[next]); buttons[next].focus(); }
    });
  });
  const search = $("#event-search");
  if (search) search.addEventListener("input", renderFilteredEvents);
}
function renderFilteredEvents() {
  const search = $("#event-search");
  const query = search ? search.value.trim().toLowerCase() : "";
  const rows = AUDIT.events.filter((row) => JSON.stringify(row).toLowerCase().includes(query));
  const body = $("#events tbody");
  if (body) stableHtml(body, renderEventTable(rows));
  const count = $("#event-count");
  if (count) count.textContent = `${rows.length} / ${AUDIT.events.length} 条事件${rows.length > 300 ? " · 展示最近 300 条，可导出全部" : ""}`;
}


function renderGoalAudit(view, compact = false) {
  const stages = view.stages || [];
  if (view.parent_run_id) return `<div class="goal-verdict"><strong>改进 Stage ${Number(view.stage_number)}</strong><a href="/execution/${encodeURIComponent(view.parent_run_id)}">返回主任务查看目标审计 →</a></div>`;
  const labels = { APPROVE: "目标审计通过", REVISE: "目标偏离 · 待改进", ESCALATE: "验收未通过 · 已停止", NOT_EVALUATED: "尚无目标审计记录", ITERATING: "正在按反馈改进", AUDITING: "正在审查完整目标", INTERRUPTED: "目标审计中断 · 需要恢复", UNAVAILABLE: "目标审计未连接" };
  const latest = stages[stages.length - 1];
  const acceptanceOnly = latest && latest.scope === "acceptance_only";
  const title = acceptanceOnly && view.status === "APPROVE" ? "原始验收通过 · 未做语义审查" : labels[view.status] || "尚无目标审计记录";
  const summary = `<div class="goal-verdict"><strong>${escapeHtml(title)}</strong><span class="muted">Stage ${Number(view.active_stage) || stages.length} / ${Number(view.max_stages) || 3} · 含首次执行</span></div>`;
  const history = stages.map((stage) => `<details class="goal-stage"><summary><span class="step-number">${Number(stage.stage)}</span><strong>${escapeHtml(labels[stage.decision] || stage.decision)}</strong><code>${escapeHtml(shortDigest(stage.commit))}</code></summary><p>${escapeHtml((stage.reasons || []).join("；"))}</p>${stage.scope === "acceptance_only" ? '<p class="muted">只证明声明的可执行验收，不等同于语义目标完全达成。</p>' : ""}${(stage.required_changes || []).length ? '<h4>下一轮改进要求</h4><ul>' + stage.required_changes.map((item) => `<li>${escapeHtml(item)}</li>`).join("") + '</ul>' : ""}${renderDocument(stage.semantic_criteria || stage.criteria || [])}</details>`).join("");
  const links = (view.iterations || []).filter((stage) => stage.exists !== false).map((stage) => `<a class="button ghost small" href="/execution/${encodeURIComponent(stage.run_id)}">打开 Stage ${Number(stage.stage)} ↗</a>`).join(" ");
  const body = `${view.stop_reason ? '<p class="alert">' + escapeHtml(view.stop_reason) + '</p>' : ""}${history || '<p class="muted">没有已记录的目标结论。步骤门禁通过或证据评分高，不代表本次目标已经达成。</p>'}<div class="controls">${links}</div>`;
  return compact ? `<details><summary>${summary}</summary>${body}</details>` : summary + body;
}
function updateGoalPanel(selector, view, compact = false) {
  const host = $(selector); if (!host) return;
  const key = JSON.stringify(view);
  if (host.dataset.renderKey === key) return;
  const open = host.querySelector("details")?.open;
  host.innerHTML = renderGoalAudit(view, compact);
  if (compact && open && host.querySelector("details")) host.querySelector("details").open = true;
  host.dataset.renderKey = key;
}


const VALIDATION_UI = { busy: false };
const VALIDATION_LABELS = { READY: "复核已通过 · 可交付", DELIVERED: "独立复核通过 · 已交付", PENDING: "等待独立复核", NOT_REQUESTED: "完成目标审计后开始复核" };

function updateValidationWorkspace(view, runId) {
  const host = $("#independent-validation-workspace"); if (!host) return;
  host.hidden = !view?.required;
  if (!view?.required) return;
  host.innerHTML = `<strong>${escapeHtml(VALIDATION_LABELS[view.status] || "独立复核待处理")}</strong><a href="${isWorkflow() ? "#flow-audit" : "/audit/" + encodeURIComponent(runId)}">查看验收与签批 →</a>`;
}

function updateValidationPanel(view, runId, run) {
  const panel = $("#independent-validation-panel");
  const host = $("#independent-validation"); if (!host || !panel) return;
  panel.hidden = !view?.required;
  if (!view?.required || VALIDATION_UI.busy) return;
  const key = JSON.stringify([runId, view, run.status]);
  if (host.dataset.renderKey === key) return;
  host.dataset.renderKey = key;
  const report = (view.reports || []).slice(-1)[0];
  const receipt = (view.attestations || []).slice(-1)[0];
  const parked = run.status === "AWAITING_APPROVAL" && view.request;
  const signed = receipt && receipt.validation_id === report?.validation_id && receipt.claim?.decision === "APPROVE";
  host.innerHTML = `<div class="validation-stages">${["重新验收", "独立签署", "交付"].map((label, i) => `<div class="${(i === 0 && report?.checks_passed) || (i === 1 && signed) || (i === 2 && view.status === "DELIVERED") ? "done" : ""}"><span>${Number(i + 1)}</span>${escapeHtml(label)}</div>`).join("")}</div><div class="goal-verdict"><strong>${escapeHtml(VALIDATION_LABELS[view.status] || view.status)}</strong><code>${escapeHtml(shortDigest(view.request?.commit))}</code></div>
    <p class="muted">从待交付提交创建干净工作区，重新执行原始验收。复核人须使用与作者、批准人不同的身份和密钥。</p>
    <div class="controls">${parked ? '<button type="button" id="validation-evaluate" class="button">' + (report ? '重新验收' : '开始验收') + '</button>' : ""}${view.ready && parked ? '<button type="button" id="validation-deliver" class="primary">继续交付 →</button>' : ""}</div>
    ${view.reason ? '<p class="muted validation-reason">' + escapeHtml(view.reason) + '</p>' : ""}
    ${report ? '<details class="goal-stage"><summary><strong>' + (report.checks_passed ? '验收通过' : '验收未通过') + '</strong><span>查看报告</span></summary><p>提交 <code>' + escapeHtml(report.commit) + '</code></p><p class="muted">有效期至 ' + escapeHtml(report.expires_at) + ' · 同一控制器，单独工作区</p>' + renderDocument(report.criteria || {}) + '</details>' : ""}
    ${receipt ? '<p>复核人 <strong>' + escapeHtml(receipt.validator_id) + '</strong> · ' + escapeHtml(receipt.claim?.decision) + ' · ' + escapeHtml(receipt.claim?.review_notes) + '</p>' : ""}
    ${parked && report?.checks_passed && !view.ready ? '<details class="goal-stage" open><summary><strong>签署独立复核</strong></summary><form id="validation-form" class="validation-form"><label class="field">复核人 ID<input name="validator_id" required autocomplete="off" placeholder="已登记的 reviewer 或 owner" /></label><label class="field">复核依据<textarea name="review_notes" required maxlength="4000" placeholder="说明检查了哪些目标、证据和结果"></textarea></label><label class="field">结论<select name="decision"><option value="APPROVE">批准交付</option><option value="REJECT">拒绝交付</option></select></label>' + (report.natural_language_criteria || []).map((id) => '<fieldset data-validation-criterion="' + escapeHtml(id) + '"><legend>' + escapeHtml(id) + '</legend><label class="field">目标判断<select name="criterion_status"><option value="UNKNOWN">尚未确认</option><option value="MET">已满足</option><option value="UNMET">未满足</option></select></label><label class="field">证据<textarea name="criterion_evidence" required maxlength="4000"></textarea></label></fieldset>').join("") + '<div class="controls"><button id="validation-review-file" type="button" class="ghost">下载复核内容</button></div><p class="muted">下载后在本机签名，将结果粘贴到下方。签名后修改复核内容，需要重新签名。</p><pre class="code">daedalus validation sign --workspace &lt;工作区&gt; --run-id ' + escapeHtml(runId) + ' --validation-id ' + escapeHtml(report.validation_id) + ' --validator-id &lt;复核人&gt; --review-file review.json</pre><label class="field">复核签名<input name="signature" required autocomplete="off" spellcheck="false" placeholder="64 位签名；请勿粘贴密钥" /></label><button class="primary" type="submit">提交复核</button></form></details>' : ""}<p id="validation-message" class="muted" role="status"></p>`;
  const message = $("#validation-message");
  const action = async (invoke) => {
    if (VALIDATION_UI.busy) return;
    VALIDATION_UI.busy = true;
    if (message) message.textContent = "处理中…";
    try {
      await invoke(); if (MODULE_RUN.id !== runId) return;
      host.dataset.renderKey = ""; VALIDATION_UI.busy = false;
      if (isWorkflow()) {
        if (WORKFLOW.pending) await WORKFLOW.pending;
        if (MODULE_RUN.id === runId) await loadWorkflow();
      } else await loadAudit();
    }
    catch (error) { if (MODULE_RUN.id === runId && message) message.textContent = error.message; }
    finally { if (MODULE_RUN.id === runId) VALIDATION_UI.busy = false; }
  };
  const evaluate = $("#validation-evaluate");
  if (evaluate) evaluate.onclick = () => action(() => api(`/api/runs/${encodeURIComponent(runId)}/validations/evaluate`, {method: "POST"}));
  const deliver = $("#validation-deliver");
  if (deliver) deliver.onclick = () => action(() => api(`/api/runs/${encodeURIComponent(runId)}/resume`, {method: "POST"}));
  const form = $("#validation-form");
  if (!form) return;
  const review = () => ({decision: form.elements.decision.value, review_notes: form.elements.review_notes.value,
    natural_language_assessments: $$("[data-validation-criterion]", form).map((row) => ({criterion_id: row.dataset.validationCriterion,
      status: row.querySelector('[name="criterion_status"]').value, evidence: row.querySelector('[name="criterion_evidence"]').value}))});
  const download = $("#validation-review-file");
  if (download) download.onclick = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(review(), null, 2)], {type: "application/json"}));
    const link = document.createElement("a"); link.href = url; link.download = "review.json"; link.click(); URL.revokeObjectURL(url);
  };
  form.onsubmit = (event) => { event.preventDefault(); action(() => api(`/api/runs/${encodeURIComponent(runId)}/validations/${encodeURIComponent(report.validation_id)}/attest`, {
    method: "POST", body: JSON.stringify({...review(), validator_id: form.elements.validator_id.value.trim(), signature: form.elements.signature.value.trim()}),
  })); };
}

/* The same page owns intake, planning, execution and the audit loop. */
function isWorkflow() { return document.body.dataset.page === "workflow"; }
const STABLE_HTML = new WeakMap();
function stableHtml(host, markup) {
  if (!host || STABLE_HTML.get(host) === markup) return false;
  host.innerHTML = markup; STABLE_HTML.set(host, markup); return true;
}
const WORKFLOW = {
  run: null, plan: null, specs: null, goal: null, validation: null, runs: [],
  draftStage: "task", available: {}, reads: null, pending: null, loadingRun: "", request: 0,
};

function workflowProgress(run, goal = {}, validation = {}, draftStage = "task") {
  const states = { task: "active", plan: "waiting", execute: "waiting", audit: "waiting" };
  const labels = { task: "描述目标", plan: "等待需求", execute: "等待确认规划", audit: "等待执行结果" };
  let current = "task", action = "从描述目标开始 ↓";
  if (!run) {
    if (draftStage === "questions") labels.task = "正在确认需求";
    if (draftStage === "review") {
      states.task = "done"; states.plan = "active"; labels.task = "需求已确认";
      labels.plan = "请确认执行计划"; current = "plan"; action = "确认规划并开始执行 ↓";
    }
    return { states, labels, current, action };
  }
  states.task = "done"; states.plan = "done"; labels.task = "需求已提交"; labels.plan = "规划已冻结";
  states.execute = "active"; labels.execute = "正在执行"; current = "execute"; action = "查看执行进度 ↓";
  const stage = Number(goal.active_stage || 1);
  if (stage > 1) labels.execute = `第 ${stage} 轮改进`;
  const goalPassed = goal.status === "APPROVE";
  const failed = ["FAILED", "PARTIAL_FAILURE", "CANCELLED", "ROLLED_BACK"].includes(run.status);
  if (run.status === "AWAITING_APPROVAL" && !goalPassed) {
    const goalBlocked = ["ESCALATE", "INTERRUPTED"].includes(goal.status);
    current = goalBlocked ? "audit" : "execute";
    states[current] = "attention"; labels[current] = "需要处理";
    action = goalBlocked ? "查看目标偏离与处理依据 ↓" : "查看待处理步骤 ↓";
  }
  if (goal.status === "AUDITING") { current = "audit"; states.audit = "active"; labels.audit = "正在审查完整目标"; }
  if (goalPassed) {
    states.execute = "done"; labels.execute = "执行已完成"; states.audit = "active";
    current = "audit"; action = "核对目标与交付结果 ↓"; labels.audit = "目标审计已记录";
    if (validation.required && validation.status !== "DELIVERED") {
      states.audit = validation.ready ? "active" : "attention";
      labels.audit = validation.ready ? "复核完成 · 可交付" : "等待独立复核";
      action = validation.ready ? "复核已通过，继续交付 ↓" : "完成独立交付复核 ↓";
    }
  }
  if (run.status === "COMPLETED") {
    states.execute = "done"; labels.execute = "执行已完成"; current = "audit";
    states.audit = goalPassed ? "done" : "attention";
    const latest = (goal.stages || []).slice(-1)[0];
    labels.audit = goalPassed ? (latest?.scope === "acceptance_only" ? "验收通过 · 查看目标结论" : "目标审计通过") : "执行完成 · 目标待核对";
    action = "查看审计结果与交付记录 ↓";
  }
  if (failed) {
    current = "audit"; states.execute = "attention"; states.audit = "attention";
    labels.execute = runStateLabel(run.status); labels.audit = "查看原因与后续处理"; action = "查看本轮结果与恢复操作 ↓";
  }
  return { states, labels, current, action };
}

function renderWorkflowProgress() {
  if (!isWorkflow()) return;
  const progress = workflowProgress(WORKFLOW.run, WORKFLOW.goal || {}, WORKFLOW.validation || {}, WORKFLOW.draftStage);
  $$("[data-flow-link]").forEach((link) => {
    const stage = link.dataset.flowLink;
    link.dataset.state = progress.states[stage];
    if (stage === progress.current) link.setAttribute("aria-current", "step"); else link.removeAttribute("aria-current");
  });
  $$("[data-flow-status]").forEach((host) => { host.textContent = progress.labels[host.dataset.flowStatus]; });
  for (const [stage, state] of Object.entries(progress.states)) {
    const section = $(`#flow-${stage}`); if (section) section.dataset.state = state;
  }
  const next = $("#workflow-next");
  if (next) { next.href = "#flow-" + progress.current; next.textContent = progress.action; }
  const hint = $("#workflow-loop-hint");
  if (hint) hint.textContent = Number(WORKFLOW.goal?.active_stage) > 1
    ? `↺ 正在对照原目标改进 · 第 ${Number(WORKFLOW.goal.active_stage)} / 3 轮`
    : "↺ 目标偏离后，按反馈进入下一轮执行 · 含首次最多 3 轮";
}

function updateWorkflowSections() {
  if (!isWorkflow()) return;
  const selected = Boolean(MODULE_RUN.id);
  const show = (id, visible) => { const host = document.getElementById(id); if (host) host.hidden = !visible; };
  show("workflow-create", !selected); show("workflow-submitted", selected);
  show("workflow-draft-plan", !selected && WORKFLOW.draftStage === "review");
  show("workflow-frozen-plan", selected && WORKFLOW.available.plan);
  show("workflow-plan-empty", selected ? !WORKFLOW.available.plan : WORKFLOW.draftStage !== "review");
  show("workflow-execution", selected && WORKFLOW.available.execute); show("workflow-execute-empty", !selected || !WORKFLOW.available.execute);
  show("workflow-audit", selected && WORKFLOW.available.audit); show("workflow-audit-empty", !selected || !WORKFLOW.available.audit);
  for (const id of ["export-jsonl", "export-csv"]) show(id, selected && WORKFLOW.available.audit);
}

function focusWorkflowStage(stage) {
  const section = document.getElementById("flow-" + stage);
  if (!section) return;
  section.scrollIntoView({ block: "start", behavior: "auto" });
  if (stage === "execute" && WORKFLOW.available.execute) fitGraph();
}

function renderWorkflowSubmitted() {
  if (!isWorkflow() || !MODULE_RUN.id) return;
  const plan = WORKFLOW.plan || {}, payload = WORKFLOW.specs || {};
  const goal = (payload.specs || []).find((card) => card.key === "spec_01")?.document || {};
  const title = plan.objective || WORKFLOW.run?.objective || WORKFLOW.run?.goal_id || MODULE_RUN.id;
  const heading = $("#workflow-title"); if (heading) heading.textContent = title;
  document.title = title + " · Daedalus";
  const subtitle = $("#workflow-subtitle"); if (subtitle) subtitle.textContent = "沿着同一条流程查看需求、计划、执行与审计，所有记录对应当前任务。";
  stableHtml($("#workflow-submitted"), `<h3 class="workflow-submitted-title">${escapeHtml(title)}</h3><div class="workflow-goal-facts"><span>目标 ${escapeHtml(plan.goal_id || "—")}</span><span>风险 ${escapeHtml(plan.risk_level || "—")}</span><span>当前任务 <code>${escapeHtml(shortDigest(MODULE_RUN.id, 24))}</code></span></div><details class="secondary-details"><summary>原始目标与验收标准</summary>${renderDocument(goal.acceptance_criteria || goal || [])}</details>`);
}

function renderWorkflowLoop(goal) {
  const host = $("#workflow-loop"); if (!host) return;
  if (goal.parent_run_id) {
    stableHtml(host, `<div class="workflow-loop-head"><div><h3>第 ${Number(goal.stage_number) || 2} 轮改进任务</h3><p>延续原始目标、执行边界与上一轮反馈。完整轮次记录保留在主任务中。</p></div><a class="button ghost small" href="/audit/${encodeURIComponent(goal.parent_run_id)}">查看主任务审计 →</a></div>`);
    return;
  }
  const stages = goal.stages || [], latest = stages.slice(-1)[0];
  if (!stages.length && (!goal.enabled || goal.status === "UNAVAILABLE")) {
    stableHtml(host, `<div class="workflow-loop-head"><div><h3>目标审计尚无记录</h3><p>${escapeHtml(goal.stop_reason || "当前任务尚未记录目标审计，执行完成不代表目标已达成。")}</p></div><a class="button ghost small" href="#flow-execute">回看执行依据</a></div>`);
    return;
  }
  const active = Number(goal.active_stage || 0);
  const statuses = { APPROVE: "已通过", REVISE: "目标偏离", ESCALATE: "验收未决" };
  const title = goal.status === "APPROVE" ? "本轮审计已完成" : goal.status === "ITERATING" ? "按审计反馈进入下一轮执行" : "执行 → 审计 → 改进";
  const stageLinks = [1, 2, 3].map((stage) => {
    const review = stages.find((item) => Number(item.stage) === stage);
    const child = (goal.iterations || []).find((item) => Number(item.stage) === stage && item.exists !== false);
    const target = stage === 1 ? (goal.parent_run_id || MODULE_RUN.id) : child?.run_id;
    const progressing = stage === active && ["AUDITING", "ITERATING"].includes(goal.status);
    const state = review?.decision === "APPROVE" ? "done" : review?.decision === "REVISE" || review?.decision === "ESCALATE" ? "attention" : progressing ? "active" : "waiting";
    const text = review ? statuses[review.decision] || review.decision : progressing ? "进行中" : stage === 1 && !stages.length ? "等待目标审计" : "尚未开始";
    return target ? `<a href="/execution/${encodeURIComponent(target)}" data-state="${escapeHtml(state)}">第 ${Number(stage)} 轮 <b>${escapeHtml(text)}</b></a>` : `<span>第 ${Number(stage)} 轮 · ${escapeHtml(text)}</span>`;
  }).join("");
  const feedback = latest && latest.decision !== "APPROVE" ? (latest.required_changes || latest.reasons || []).join("；") : goal.stop_reason || "";
  stableHtml(host, `<div class="workflow-loop-head"><div><h3>${escapeHtml(title)}</h3><p>目标偏离时保留审计反馈，再进入新 stage；含首次最多 3 轮。</p></div><a class="button ghost small" href="#flow-execute">↺ 回看执行</a></div><div class="workflow-stage-list">${stageLinks}</div>${feedback ? '<p class="workflow-feedback">改进依据：' + escapeHtml(feedback) + '</p>' : ""}`);
}

async function refreshWorkflowRuns() {
  const payload = await api("/api/runs");
  WORKFLOW.runs = (payload.runs || []).slice().reverse();
  const picker = $("#run-picker"); if (!picker) return;
  let options = '<option value="">＋ 新建任务</option>' + WORKFLOW.runs.map((run) => `<option value="${escapeHtml(run.run_id)}">${escapeHtml(ellipsis(run.objective || run.goal_id, 38))} · ${escapeHtml(runStateLabel(run.status))}</option>`).join("");
  if (MODULE_RUN.id && !WORKFLOW.runs.some((run) => run.run_id === MODULE_RUN.id)) options += `<option value="${escapeHtml(MODULE_RUN.id)}">${escapeHtml(shortDigest(MODULE_RUN.id, 24))} · 正在读取</option>`;
  stableHtml(picker, options); picker.value = MODULE_RUN.id;
}

function loadWorkflow() {
  const runId = MODULE_RUN.id;
  if (!runId) return refreshWorkflowRuns().catch((error) => showError("#workflow-error", error));
  if (WORKFLOW.pending && WORKFLOW.loadingRun === runId) return WORKFLOW.pending;
  const request = ++WORKFLOW.request, reads = new Map();
  WORKFLOW.reads = reads; WORKFLOW.loadingRun = runId;
  const task = (async () => {
    const jobs = [["planning", loadPlanning], ["execution", loadExecution], ["audit", loadAudit]];
    const results = await Promise.allSettled(jobs.map(([, load]) => load()));
    if (request !== WORKFLOW.request || MODULE_RUN.id !== runId) return;
    results.forEach((result, index) => showError(`#${jobs[index][0]}-error`, result.status === "rejected" ? result.reason : null));
    const failures = results.filter((result) => result.status === "rejected");
    showError("#workflow-error", failures.length ? new Error("部分任务信息暂时无法读取，可以刷新重试。已加载的阶段仍可查看。") : null);
    await refreshWorkflowRuns();
    renderWorkflowProgress(); updateWorkflowSections();
  })().catch((error) => { if (MODULE_RUN.id === runId) showError("#workflow-error", error); }).finally(() => {
    if (WORKFLOW.reads === reads) WORKFLOW.reads = null;
    if (WORKFLOW.pending === task) WORKFLOW.pending = null;
  });
  WORKFLOW.pending = task; return task;
}

async function openWorkflowRun(runId, focus = "") {
  const changed = MODULE_RUN.id !== runId;
  MODULE_RUN.id = runId;
  if (changed) {
    const knowledgePanel = $("#knowledge-panel"); if (knowledgePanel) knowledgePanel.open = false;
    const knowledgeRepo = $("#knowledge-repo"); if (knowledgeRepo) knowledgeRepo.value = "";
    WORKFLOW.request += 1;
    WORKFLOW.run = runId ? (WORKFLOW.runs.find((row) => row.run_id === runId) || {run_id: runId, status: "PENDING"}) : null;
    WORKFLOW.goal = null; WORKFLOW.validation = null;
    WORKFLOW.plan = null; WORKFLOW.specs = null; WORKFLOW.available = {}; WORKFLOW.diffKey = "";
    PLANNING.renderKey = ""; VALIDATION_UI.busy = false;
    const submitted = $("#workflow-submitted"); if (submitted) submitted.textContent = "正在读取任务需求…";
    const title = $("#workflow-title"); if (title && runId) title.textContent = WORKFLOW.run?.objective || WORKFLOW.run?.goal_id || "正在读取任务…";
    for (const id of ["workflow-error", "planning-error", "execution-error", "audit-error", "action-out"]) showError("#" + id, null);
  }
  const url = runId ? "/execution/" + encodeURIComponent(runId) : "/";
  window.history.replaceState({}, "", url + (focus ? "#flow-" + focus : ""));
  if (!runId) {
    const heading = $("#workflow-title"); if (heading) heading.textContent = "把目标变成可验收的结果";
    const subtitle = $("#workflow-subtitle"); if (subtitle) subtitle.textContent = "提交需求，确认规划，查看执行，再对照目标审计。所有步骤都在这里。";
    const note = $("#run-note"); if (note) note.textContent = "";
    document.title = "Daedalus · 任务全流程";
  }
  renderWorkflowProgress(); updateWorkflowSections();
  await loadWorkflow();
  if (focus && MODULE_RUN.id === runId) focusWorkflowStage(focus);
}

async function initWorkflow() {
  initKnowledge();
  initIntake(); bindWorkspace(); bindAuditViews(); wireDiffMode();
  const picker = $("#run-picker");
  if (picker) picker.addEventListener("change", () => void openWorkflowRun(picker.value, picker.value ? "execute" : "task"));
  const create = $("#workflow-new");
  if (create) create.addEventListener("click", () => {
    if (INTAKE.session?.status === "FROZEN") {
      INTAKE.session = null; INTAKE.specs = []; WORKFLOW.draftStage = "task";
      const input = $("#intake-objective"); if (input) input.value = "";
      showIntakeStep("task");
    }
    void openWorkflowRun("", "task");
  });
  document.addEventListener("click", (event) => {
    if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button > 0) return;
    const link = event.target.closest("a[href]"); if (!link || link.hasAttribute("download") || link.target === "_blank") return;
    const url = new URL(link.href, window.location.href);
    if (url.origin !== window.location.origin) return;
    // Native stage anchors scroll within this document; don't reinterpret the
    // current /execution/<id> pathname as a request to return to execution.
    if (url.pathname === window.location.pathname && /^#flow-(task|plan|execute|audit)$/.test(url.hash)) return;
    const match = url.pathname.match(/^\/(planning|execution|audit|runs)\/([^/]+)\/?$/);
    if (!match) return;
    event.preventDefault();
    const stage = url.hash.match(/^#flow-(task|plan|execute|audit)$/)?.[1]
      || { planning: "plan", execution: "execute", runs: "execute", audit: "audit" }[match[1]];
    const selected = decodeURIComponent(match[2]);
    if (selected === MODULE_RUN.id) {
      window.history.replaceState({}, "", "/execution/" + encodeURIComponent(selected) + "#flow-" + stage);
      focusWorkflowStage(stage);
    } else void openWorkflowRun(selected, stage);
  });
  updateWorkflowSections(); renderWorkflowProgress();
  await loadWorkflow();
  const hash = window.location.hash.match(/^#flow-(task|plan|execute|audit)$/)?.[1];
  if (hash || MODULE_RUN.id) focusWorkflowStage(hash || document.body.dataset.initialStage || "execute");
  startPolling(loadWorkflow);
  await refreshBadge();
}

function renderKnowledgeAction(action) {
  const names = {search:"检索资料",grep:"代码搜索",read:"读取上下文",expand:"扩展片段",symbol:"追踪定义与调用",follow_link:"跟随文档引用",finish:"结束调查",hybrid_retrieve:"混合召回与排序"};
  const counts = Object.entries(action.channels || {}).map(([key,count]) => `${({lexical:"关键词",code:"代码",vector:"语义"})[key] || key} ${count}`).join(" · ");
  const ranking = action.rerank ? (action.rerank.used ? `模型精排保留 ${action.rerank.ranked_ids.length} 条` : `精排未使用：${action.rerank.reason}`) : "";
  const detail = action.coarse_candidates ? `<details><summary>候选来源与排序</summary><p class="muted">${escapeHtml(counts)} · ${escapeHtml(ranking)}${action.vector_error ? " · 语义召回未就绪，保留其他搜索结果" : ""}</p><ol>${action.coarse_candidates.map((row) => `<li>${escapeHtml(row.title || row.id)} · ${escapeHtml(Object.keys(row.channel_ranks).map((key) => ({lexical:"关键词",code:"代码",vector:"语义"})[key] || key).join("、"))}</li>`).join("")}</ol></details>` : "";
  return `<li>${escapeHtml(names[action.action] || action.action)}${action.hits === undefined ? "" : ` · ${escapeHtml(String(action.hits))} 条命中`}${action.note ? ` · ${escapeHtml(action.note)}` : ""}${detail}</li>`;
}

function initKnowledge() {
  const panel = $("#knowledge-panel"); if (!panel) return;
  const repo = $("#knowledge-repo"), records = $("#knowledge-records"), traces = $("#knowledge-traces");
  const form = $("#knowledge-form"); let loading = false;
  const render = (data) => {
    repo.value = data.repo_path;
    $("#knowledge-summary").textContent = `${data.records.length} 条记忆 · ${data.traces.length} 次近期检索`;
    const runtime = data.retrieval_status;
    const statusLabels = {ready:"本地语义模型已就绪",configured:"已配置，深查时从本机加载模型",disabled:"本地语义检索未启用",missing_dependency:"缺少本地检索依赖，请先安装后准备模型",error:"本地语义检索暂不可用，请检查模型文件并重新准备"};
    $("#knowledge-retrieval-status").textContent = runtime ? (statusLabels[runtime.state] || runtime.state) : "当前后端尚未加载语义检索接口，重新加载服务后可准备模型。";
    $("#knowledge-retrieval-install").hidden = !runtime || runtime.dependency_installed;
    [$("#knowledge-retrieval-setup"),$("#knowledge-retrieval-index"),$("#knowledge-retrieval-disable")].forEach((button) => { button.dataset.retrievalUnavailable = String(!runtime); button.disabled = !runtime; });
    $("#knowledge-search-form").elements.mode.querySelectorAll("option").forEach((option) => { if (["hybrid","deep"].includes(option.value)) option.disabled = !runtime; });
    records.innerHTML = data.records.map((row) => `<details><summary>${escapeHtml(row.title)} · ${row.kind === "preference" ? "已确认偏好" : "资料"}</summary><p class="prewrap">${escapeHtml(row.text)}</p><button type="button" class="ghost small" data-knowledge-delete="${escapeHtml(row.id)}">删除此条记忆</button></details>`).join("") || '<p class="empty">尚未保存资料或偏好。已提交的项目文档与历史事件也会自动参与检索。</p>';
    traces.innerHTML = data.traces.map((trace) => `<details><summary>${escapeHtml(({planning:"规划",execution:"执行",regression:"回归",investigation:"按需深查",manual:"试查"})[trace.phase] || trace.phase)} · ${escapeHtml(({grep:"代码直接搜索",deep:"证据调查",hybrid:"混合召回",lexical:"词法检索"})[trace.route] || "早期词法检索")} · ${trace.actions.length} 个动作 · ${trace.citations.length} 条引用</summary><p class="muted">${escapeHtml(trace.created_at)} · ${trace.latency_ms} ms · ${escapeHtml(trace.stop_reason)}</p><ol>${trace.actions.map(renderKnowledgeAction).join("")}</ol>${trace.citations.map((c) => `<details><summary>${escapeHtml(c.title)} · ${escapeHtml(c.kind)}</summary><p class="muted">${escapeHtml(c.source)} · 摘要 ${escapeHtml(shortDigest(c.digest))}${c.line_start ? ` · 行 ${escapeHtml(String(c.line_start))}–${escapeHtml(String(c.line_end))}` : ""}</p><pre>${escapeHtml(c.text)}</pre></details>`).join("") || '<p class="empty">未命中相关依据。</p>'}</details>`).join("") || '<p class="empty">尚无搜索记录。</p>';
    records.querySelectorAll("[data-knowledge-delete]").forEach((button) => { button.onclick = () => act(async () => {
      await api(`/api/knowledge/${encodeURIComponent(button.dataset.knowledgeDelete)}?repo_path=${encodeURIComponent(repo.value.trim())}`, {method:"DELETE"}); await load(false);
    }); });
  };
  const act = async (fn) => {
    if (loading) return; loading = true;
    panel.querySelectorAll("button").forEach((b) => { b.disabled = true; });
    try { showError("#knowledge-error", null); await fn(); }
    catch (error) { showError("#knowledge-error", error); }
    finally { loading = false; panel.querySelectorAll("button").forEach((b) => { b.disabled = b.dataset.retrievalUnavailable === "true"; }); }
  };
  const load = async (current = true) => {
    if (current && MODULE_RUN.id) {
      const selected = MODULE_RUN.id, data = await api(`/api/runs/${encodeURIComponent(selected)}/knowledge`);
      if (selected === MODULE_RUN.id) render(data); return;
    }
    if (!repo.value.trim()) repo.value = $("#intake-repo-path")?.value.trim() || INTAKE.repo || "";
    if (!repo.value.trim()) throw new Error("请先选择任务项目，或填写 Git 仓库路径。");
    const selected = repo.value.trim(), data = await api(`/api/knowledge?repo_path=${encodeURIComponent(selected)}`);
    if (selected === repo.value.trim()) render(data);
  };
  panel.ontoggle = () => { if (panel.open) void act(() => load()); };
  $("#knowledge-load").onclick = () => act(() => load(false));
  $("#knowledge-retrieval-setup").onclick = () => act(async () => {
    $("#knowledge-retrieval-status").textContent = "正在准备本地模型，请保留此页；资料不会发送到下载服务。";
    await api("/api/knowledge/retrieval/setup", {method:"POST",body:JSON.stringify({enabled:true,download_models:true})}); await load(false);
  });
  $("#knowledge-retrieval-disable").onclick = () => act(async () => {
    await api("/api/knowledge/retrieval/setup", {method:"POST",body:JSON.stringify({enabled:false})}); await load(false);
  });
  $("#knowledge-retrieval-index").onclick = () => act(async () => {
    const result = await api("/api/knowledge/retrieval/index", {method:"POST",body:JSON.stringify({repo_path:repo.value.trim()})});
    $("#knowledge-index-result").textContent = `索引 ${result.indexed_chunks} 个片段 · 新生成 ${result.new_embeddings} · 复用 ${result.reused_embeddings}`; await load(false);
  });
  form.onsubmit = (event) => { event.preventDefault(); void act(async () => {
    await api("/api/knowledge", {method:"POST", body:JSON.stringify({repo_path:repo.value.trim(),kind:form.elements.kind.value,title:form.elements.title.value,text:form.elements.text.value,confirmed:true})});
    form.reset(); await load(false);
  }); };
  $("#knowledge-file").onchange = (event) => { void act(async () => {
    const file = event.target.files[0]; if (!file) return;
    if (file.size > 96000) throw new Error("请导入较短的文本，每条最多 24000 字符。");
    const text = await file.text(); if (text.length > 24000) throw new Error("每条资料最多 24000 字符，请分段导入。");
    form.elements.kind.value = "document"; form.elements.title.value = file.name.slice(0,160); form.elements.text.value = text;
  }); };
  $("#knowledge-search-form").onsubmit = (event) => { event.preventDefault(); void act(async () => {
    await api("/api/knowledge/retrieve", {method:"POST",body:JSON.stringify({repo_path:repo.value.trim(),query:event.target.elements.query.value,mode:event.target.elements.mode.value,use_model:event.target.elements.use_model.checked})}); await load(false);
  }); };
}
