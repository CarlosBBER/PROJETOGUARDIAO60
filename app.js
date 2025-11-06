// ===== Config API =====
const BASE_URL = location.origin; // mesmo host do server.js
const API_KEY  = "dev-123";

// ===== Helpers =====
const $  = (s)=>document.querySelector(s);
const $$ = (s)=>Array.from(document.querySelectorAll(s));
function toast(msg){
  const t=$("#toast"); t.textContent=msg; t.style.display="block";
  clearTimeout(toast._h); toast._h=setTimeout(()=>t.style.display="none",2000);
}
function show(name){
  $$(".screen").forEach(s=>s.classList.remove("active"));
  $(`#screen-${name}`)?.classList.add("active");
  $$(".tab").forEach(tab=>tab.classList.toggle("active", tab.dataset.goto===name));
}
async function apiJSON(path, opts={}){
  const r = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type":"application/json", "x-api-key": API_KEY, ...(opts.headers||{}) },
    ...opts
  });
  if(!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`);
  return r.json();
}

// ===== Login / Conta =====
async function doSignup(){
  const email = $("#login-email").value.trim();
  const pass  = $("#login-pass").value;
  if(!email || !pass) return toast("Informe e-mail e senha.");
  try{
    await fetch(`${BASE_URL}/auth/signup`,{
      method:"POST", headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ email, password: pass })
    });
    localStorage.setItem("gd60_session", JSON.stringify({ provider:"Conta", email }));
    $("#profile-provider").textContent = email;
    toast("Conta criada! ✔️");
    show("home");
  }catch(e){ toast("Erro ao criar conta (e-mail já existe?)"); }
}
async function doLogin(){
  const email = $("#login-email").value.trim();
  const pass  = $("#login-pass").value;
  if(!email || !pass) return toast("Informe e-mail e senha.");
  try{
    await fetch(`${BASE_URL}/auth/login`,{
      method:"POST", headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ email, password: pass })
    }).then(r=>{ if(!r.ok) throw new Error(); return r.json(); });
    localStorage.setItem("gd60_session", JSON.stringify({ provider:"Conta", email }));
    $("#profile-provider").textContent = email;
    toast("Bem-vindo! ✅");
    show("home");
  }catch{ toast("Credenciais inválidas."); }
}
function loginProvider(p){ localStorage.setItem("gd60_session", JSON.stringify({provider:p, at:new Date().toISOString()})); $("#profile-provider").textContent=p; show("home"); toast(`Entrou com ${p}`); }
function logout(){ localStorage.removeItem("gd60_session"); toast("Sessão encerrada."); show("login"); }

// ===== Dicas =====
async function loadTips(){
  const box = $("#tips-box"); box.innerHTML = `<div class="bubble">Carregando…</div>`;
  try{
    const tips = await apiJSON("/v1/tips");
    box.innerHTML = "";
    tips.forEach(t=>{
      const el = document.createElement("div");
      el.className="tip"; el.textContent = t;
      box.appendChild(el);
    });
  }catch(e){
    box.innerHTML = `<div class="bubble">Falha ao carregar dicas.</div>`;
  }
}

// ===== Alertas =====
function sevClass(s){ s=String(s||'low').toLowerCase(); return s==='high'?'high':s==='medium'?'medium':'low'; }
function humanType(t){ if(!t) return 'Alerta'; if(t==='REPORT_SUSPECT')return'Golpe reportado'; if(t==='LINK_SUSPECT')return'Link suspeito'; if(t==='LINK_SAFE')return'Marcado como seguro'; return t; }
async function loadAlerts(){
  const box = $("#alerts-list"); box.innerHTML = `<div class="bubble">Carregando…</div>`;
  try{
    const items = await apiJSON("/v1/alerts?status=new");
    if(!items.length){ box.innerHTML = `<div class="bubble">Sem alertas.</div>`; return; }
    box.innerHTML = "";
    items.forEach(a=>{
      const wrap = document.createElement("div");
      wrap.className = "card";
      wrap.innerHTML = `
        <div class="alert-icon">⚠️</div>
        <div class="alert-body">
          <p class="title">${humanType(a.type)}</p>
          <p class="desc">${a.description||"Sem descrição"}</p>
          <div class="meta">
            <span class="chip">Severidade: <span class="sev ${sevClass(a.severity)}">${String(a.severity||'low').toUpperCase()}</span></span>
            ${a.score!=null? `<span class="chip">Score: ${a.score}</span>` : ""}
            <button class="btn primary" data-ack="${a.id}">Marcar como lido</button>
          </div>
        </div>`;
      box.appendChild(wrap);
    });
    box.querySelectorAll("[data-ack]").forEach(b=>{
      b.addEventListener("click", async ()=>{
        try{ await apiJSON(`/v1/alerts/${b.dataset.ack}/ack`, { method:"PATCH" }); toast("Alerta reconhecido"); loadAlerts(); }
        catch{ toast("Falha ao reconhecer"); }
      });
    });
  }catch{ box.innerHTML = `<div class="bubble">Erro ao carregar alertas.</div>`; }
}

// ===== Ações =====
$("#btn-block")?.addEventListener("click", async ()=>{
  try{
    await apiJSON("/v1/reports",{ method:"POST", body: JSON.stringify({
      url:"http://wa.me/5511987654321",
      description:"Usuário marcou como golpe no app",
      reporterHash:"web-demo"
    })});
    toast("Golpe reportado. Ver alertas 👇");
    loadAlerts(); show("alerts");
  }catch{ toast("Falha ao enviar denúncia"); }
});

$("#btn-safe")?.addEventListener("click", async ()=>{
  try{
    await apiJSON("/v1/links/check", { method:"POST", body: JSON.stringify({ url:"https://www.gov.br" })});
    toast("Marcado como seguro.");
    loadAlerts(); show("alerts");
  }catch{ toast("Falha na checagem"); }
});

$("#btn-analyze")?.addEventListener("click", async ()=>{
  const url = prompt("Cole o link para análise:");
  if(!url) return;
  try{
    const r = await apiJSON("/v1/links/check",{ method:"POST", body: JSON.stringify({ url })});
    toast(`Resultado: ${r.severity.toUpperCase()} (score ${r.score})`);
    if(r.severity!=='low'){ loadAlerts(); show("alerts"); }
  }catch{ toast("Não foi possível analisar o link"); }
});

// ===== Navegação =====
$("#to-shield")?.addEventListener("click", ()=> show("shield"));
$("#to-tips")  ?.addEventListener("click", ()=> { show("tips"); loadTips(); });
$$(".tab").forEach(t=>t.addEventListener("click", ()=>{
  const g=t.dataset.goto; show(g);
  if(g==='alerts') loadAlerts();
  if(g==='tips')   loadTips();
}));

// ===== Login/Logout =====
$("#btn-signup")?.addEventListener("click", doSignup);
$("#btn-login") ?.addEventListener("click", doLogin);
$("#btn-google")?.addEventListener("click", ()=> loginProvider("Google"));
$("#btn-apple") ?.addEventListener("click", ()=> loginProvider("Apple"));
$("#btn-guest") ?.addEventListener("click", ()=> loginProvider("Visitante"));
$("#btn-logout")?.addEventListener("click", logout);

// ===== Boot =====
window.addEventListener("load", ()=>{
  const s = localStorage.getItem("gd60_session");
  if(s){ const obj=JSON.parse(s); $("#profile-provider").textContent = obj.email||obj.provider||"Visitante"; show("home"); }
  else { show("login"); }
  // carrega alertas se for direto
  loadAlerts();
});
