/* Read-only progress after an explicit service operation. */
(() => {
  const node=document.getElementById("handoff");if(!node)return;
  let attempts=0;
  async function check(){
    try{
      const r=await fetch("/api/service",{cache:"no-store"});
      if(r.status===401){window.location.assign("/auth/login");return;}
      if(r.ok){const state=await r.json();if(state.session_id!==node.dataset.session){window.location.assign("/auth/setup");return;}}
    }catch(_){}
    if(++attempts<90)setTimeout(check,1000);
    else document.getElementById("handoff-status").textContent="尚未确认新服务，请查看服务日志后刷新；没有自动继续任务。";
  }
  setTimeout(check,1000);
})();
