/* Fixed review study. Page load and polling only GET; paid dispatch is an explicit click. */
(() => {
  'use strict';
  let job = '', timer;
  const el = id => document.getElementById('review-evaluation-' + id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  async function api(path, options) {
    const response = await fetch('/api/review-evaluations' + path, options);
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : '操作失败');
    return data;
  }
  async function refresh() {
    clearTimeout(timer);
    try {
      if (!job) job = (await api('')).jobs[0]?.job_id || '';
      if (!job) { el('status').textContent = '暂无复验记录'; return; }
      const row = await api('/' + encodeURIComponent(job));
      const count = row.report?.reviews?.length || row.progress?.reviews?.length || 0;
      const active = ['QUEUED', 'RUNNING'].includes(row.status);
      el('start').disabled = active; el('cancel').hidden = !active;
      el('status').textContent = `${row.status} · ${count}/40 项 · ${row.model} · ${row.report?.reported_tokens ?? row.reported_tokens ?? '统计中'} tokens`;
      const summary = row.report?.summary;
      if (summary) el('result').innerHTML = '<table class="table"><thead><tr><th>审查输入</th><th>正确放行 / 10</th><th>错误放行 / 10</th><th>错误要求修改</th><th>无效响应</th><th>tokens</th></tr></thead><tbody>' + Object.entries(summary).map(([key,s]) => `<tr><td>${key === 'with_context' ? '含依赖上下文' : '仅候选补丁'}</td><td>${esc(s.correct_candidates_approved)}</td><td>${esc(s.faulty_candidates_approved)}</td><td>${esc(s.faulty_candidates_revised)}</td><td>${esc(s.invalid_model_responses)}</td><td>${esc(s.reported_tokens)}</td></tr>`).join('') + '</tbody></table><a href="/api/review-evaluations/' + encodeURIComponent(job) + '/artifacts/report.json" download>下载完整报告</a> · <a href="/api/review-evaluations/' + encodeURIComponent(job) + '/artifacts/protocol.json" download>下载调用前协议</a>';
      if (active) timer = setTimeout(refresh, 3000);
    } catch (error) { el('status').textContent = error.message; }
  }
  document.addEventListener('DOMContentLoaded', () => {
    if (!el('start')) return;
    el('refresh').addEventListener('click', refresh);
    el('start').addEventListener('click', async () => {
      if (!window.confirm('使用已保存的 reviewer 运行40项审查；最多48次调用、100,000报告tokens。确认开始？')) return;
      el('start').disabled = true;
      try { job = (await api('', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm_paid_calls:true})})).job_id; await refresh(); }
      catch (error) { el('status').textContent = error.message; el('start').disabled = false; }
    });
    el('cancel').addEventListener('click', async () => {
      try { await api('/' + encodeURIComponent(job) + '/cancel', {method:'POST'}); await refresh(); }
      catch (error) { el('status').textContent = error.message; }
    });
    refresh();
  });
})();
