/* Loading this page never starts a model request. */
(() => {
  "use strict";
  const LABELS = {model:"一次性模型",single:"经典 Agent",daedalus:"Daedalus"};
  const TRIAL_STATES = {COMPLETED:"已完成",FAILED:"未交付",AWAITING_APPROVAL:"已停车，需人工审查",ERROR:"运行出错"};
  const CASES = {api_pagination:"分页接口与前端状态",sqlite_idempotency:"SQLite 并发幂等",manual_checkpoint:"人工断点恢复",versioned_context:"检索来源与版本",usage_export:"用量与安全导出",config_migration:"配置迁移与 CLI"};
  const STATES = {QUEUED:"排队中",RUNNING:"运行中",CANCELLING:"正在停止，等待当前请求结算",COMPLETE:"已完成",INCOMPLETE:"部分完成",INTERRUPTED:"已中断，未自动继续",BLOCKED:"连接或运行条件受阻",ERROR:"运行出错",ADMISSION_FAILED:"未能启动"};
  const KEY="daedalus-engineering-evaluation";
  const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const num = v => Number.isFinite(Number(v)) && Number(v)>=0 ? Number(v) : 0;
  const format = v => num(v).toLocaleString("zh-CN",{maximumFractionDigits:2});
  function knownTokens(row) {
    if(row.tokens!==null && row.tokens!==undefined) return num(row.tokens);
    return (row.call_records||[]).reduce((sum,c)=>sum+(c.usage_available ? num(c.prompt_tokens)+num(c.completion_tokens) : 0),0);
  }
  function hasUnknownUsage(row) {
    if(row.tokens!==null && row.tokens!==undefined) return false;
    if(row.dispatched_model_calls===0) return false;
    return (row.call_records||[]).some(call=>call.request_dispatched!==false && !call.usage_available);
  }
  function trialDetail(row) {
    const note=row.delivered ? "独立验收核对本组交付提交。" : "本组没有交付；独立验收检查当前保留提交，不代表最后一次被拒候选。";
    const output=row.evaluation_output || row.error || "公开、隐藏及改动范围结论见本行；完整过程保留在实验报告目录。";
    return `<details class="engineering-trial-detail"><summary>验收详情</summary><p>${esc(note)}</p><p>验收提交 ${esc(String(row.candidate_commit||"—").slice(0,12))}</p><pre>${esc(output)}</pre></details>`;
  }
  function render(job, catalog=[]) {
    const rows=job?.report?.trials || job?.progress || [];
    const scheduled=job?.request?.cases?.length || catalog.length;
    const cards=Object.entries(LABELS).map(([arm,label])=>{
      const subset=rows.filter(r=>r.arm===arm), unknown=subset.filter(hasUnknownUsage).length;
      const safe=subset.filter(r=>r.safe_delivery).length, unsafe=subset.filter(r=>r.unsafe_delivery).length;
      const tokens=subset.reduce((s,r)=>s+knownTokens(r),0), seconds=subset.reduce((s,r)=>s+num(r.wall_seconds),0);
      return `<article class="engineering-card"><strong>${label}</strong><p class="engineering-score">${safe}<span> / ${scheduled} 安全交付</span></p><p>已测 ${subset.length} · 待测 ${Math.max(0,scheduled-subset.length)} · 不安全交付 ${unsafe}</p><p>${format(tokens)} 已报告 tokens${unknown?` · ${unknown} 组用量部分未知`:""}</p><p>${format(seconds)} 秒 · ${subset.reduce((s,r)=>s+num(r.model_calls),0)} 次逻辑调用 · ${subset.reduce((s,r)=>s+num(r.inspections),0)} 次读码观察</p></article>`;
    }).join("");
    const table=rows.length ? '<table class="table"><thead><tr><th>任务</th><th>方式</th><th>状态</th><th>公开 / 隐藏 / 范围</th><th>tokens</th><th>秒</th></tr></thead><tbody>'+rows.map(r=>
      `<tr><td>${esc(CASES[r.case]||r.case)}</td><td>${esc(LABELS[r.arm]||r.arm)}</td><td>${esc(r.safe_delivery?"安全交付":r.unsafe_delivery?"交付未通过独立验收":(TRIAL_STATES[r.status]||r.status))}${trialDetail(r)}</td><td>${[r.public_passed,r.heldout_passed,r.policy_passed].map(v=>v===true?"✓":v===false?"✕":"—").join(" / ")}</td><td>${r.dispatched_model_calls===0?"未派发":format(knownTokens(r))}${hasUnknownUsage(r)?" + 未知":""}</td><td>${format(r.wall_seconds)}</td></tr>`
    ).join("")+'</tbody></table>' : '<p class="empty">尚无已完成样本。真实结果会逐项出现在这里。</p>';
    const warning=(job?.report_state==="UNREADABLE"||job?.progress_state==="UNREADABLE") ? '<p class="alert">结果文件无法完整读取；当前记录不构成完整验收结论，请刷新或检查导出文件。</p>' : '';
    return {cards,table:warning+table,count:rows.length,total:scheduled*3};
  }
  window.DaedalusEngineering = {render,knownTokens,hasUnknownUsage};
  async function init() {
    const root=document.getElementById("engineering-eval"); if(!root) return;
    root.addEventListener("toggle",()=>{if(root.open)root.scrollIntoView({block:"start"});});
    const $=id=>document.getElementById(id);
    let catalog=[],job=null,timer=null,submitting=false,errorText="";
    async function api(path,body) {
      const response=await fetch(path,{cache:"no-store",headers:{"Content-Type":"application/json"},...(body===undefined?{}:{method:"POST",body:JSON.stringify(body)})});
      const data=await response.json(); if(!response.ok) throw Error(typeof data.detail==="string"?data.detail:"请求未完成，请查看运行环境和模型设置"); return data;
    }
    function paint() {
      const view=render(job,catalog),active=job && ["QUEUED","RUNNING","CANCELLING"].includes(job.status);
      $("engineering-summary").innerHTML=view.cards; $("engineering-results").innerHTML=view.table;
      $("engineering-start").disabled=submitting||Boolean(active);
      $("engineering-cancel").disabled=!active||job.status==="CANCELLING";
      const protocol=job?.request ? ` · 实际模式：${job.effective_inference_profile||job.request.inference_profile||"configured"} · 系列上限 ${format(job.request.series_tokens)} tokens` : "";
      $("engineering-status").textContent=errorText || (job ? `${STATES[job.status]||job.status} · ${view.count} / ${view.total} 组已测 · ${job.model||""}${protocol}` : "尚未运行。可先查看已有记录。");
      $("engineering-downloads").innerHTML=job?.report ? ["report.html","report.json","trials.csv","protocol.json"].map(name=>`<a class="button ghost small" target="_blank" rel="noopener" href="/api/engineering-evaluations/${encodeURIComponent(job.job_id)}/artifacts/${name}">${esc(name)}</a>`).join("") : "";
      if(timer) clearTimeout(timer);
      if(active) timer=setTimeout(()=>void refresh().catch(showError),2000);
    }
    function showError(error){errorText=error.message;$("engineering-status").textContent=errorText;$("engineering-start").disabled=submitting||Boolean(job&&["QUEUED","RUNNING","CANCELLING"].includes(job.status));}
    async function refresh() {
      if(job) job=await api("/api/engineering-evaluations/"+encodeURIComponent(job.job_id));
      errorText="";
      paint();
    }
    async function load() {
      const data=await api("/api/engineering-evaluations");catalog=data.cases;
      $("engineering-cases").innerHTML=catalog.map(c=>`<label><input type="checkbox" value="${esc(c.key)}" checked> ${esc(CASES[c.key]||c.category)}</label>`).join("");
      $("engineering-history").innerHTML='<option value="">选择已有实验</option>'+data.jobs.map(j=>`<option value="${esc(j.job_id)}">${esc(j.created_at)} · ${esc(STATES[j.status]||j.status)}</option>`).join("");
      let selected=null;try{selected=localStorage.getItem(KEY);}catch(_){}
      const row=data.jobs.find(j=>j.job_id===selected)||data.jobs[0];
      if(row){job=row;$("engineering-history").value=row.job_id;await refresh();}else paint();
    }
    $("engineering-start").addEventListener("click",async()=>{
      if(submitting) return;
      const cases=[...$("engineering-cases").querySelectorAll("input:checked")].map(input=>input.value);
      if(!cases.length){showError(Error("至少选择一个验收任务"));return;}
      const series_tokens=Number($("engineering-token-limit").value),series_calls=Number($("engineering-call-limit").value);
      if(!Number.isInteger(series_tokens)||series_tokens<10000||series_tokens>300000||!Number.isInteger(series_calls)||series_calls<1||series_calls>144){showError(Error("请填写有效的本批用量和调用上限"));return;}
      submitting=true;errorText="";paint();$("engineering-status").textContent="正在创建同模型对照…";
      try{
        job=await api("/api/engineering-evaluations",{cases,max_calls:8,max_tokens:30000,series_tokens,series_calls,inference_profile:$("engineering-profile").value});
        try{localStorage.setItem(KEY,job.job_id);}catch(_){}
        await refresh();
      }catch(error){showError(error);}finally{submitting=false;paint();}
    });
    $("engineering-refresh").addEventListener("click",()=>void(job?refresh():load()).catch(showError));
    $("engineering-cancel").addEventListener("click",async()=>{if(!job)return;try{await api("/api/engineering-evaluations/"+encodeURIComponent(job.job_id)+"/cancel",{});await refresh();}catch(error){showError(error);}});
    $("engineering-history").addEventListener("change",async()=>{const id=$("engineering-history").value;if(!id)return;job={job_id:id};try{localStorage.setItem(KEY,id);}catch(_){}await refresh().catch(showError);});
    await load().catch(showError);
    if(window.location.hash==="#engineering-eval"){root.open=true;root.scrollIntoView({block:"start"});}
  }
  document.addEventListener("DOMContentLoaded",()=>void init());
})();
