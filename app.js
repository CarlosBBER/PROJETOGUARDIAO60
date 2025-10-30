// ====== CONFIG DA API ======
const BASE_URL = "http://localhost:3000"; 
const API_KEY  = "dev-123";              
// ====== STATE ======
let API_ONLINE = false;

// ====== HELPERS ======
const $  = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
function showToast(msg){
  const t = $("#toast");
  t.textContent = msg;
  t.style.display = "block";
  clearTimeout(showToast._h);
  showToast._h = setTimeout(() => (t.style.display = "none"), 2400);
}

function showScreen(name){
  // esconde todas
  $$(".screen").forEach(el => el.classList.remove("active"));
  // mostra uma
  const target = $(`#screen-${name}`);
  if (target) target.classList.add("active");

  // atualiza tab ativa
  $$(".tabbar .tab").forEach(b => b.classList.toggle("active", b.dataset.goto === name));

  // cargas por tela
  if (name === "alerts") loadAlerts();
  if (name === "profile") updateApiStatus();
}

// navegação tabbar
$$(".tabbar .tab").forEach(btn => {
  btn.addEventListener("click", () => showScreen(btn.dataset.goto));
});

// botão da home → proteção
$("#to-shield")?.addEventListener("click", () => showScreen("shield"));

// ====== FETCH WRAPPER (com headers) ======
async function apiJSON(path, options = {}){
  const resp = await fetch(`${BASE_URL}${path}`, {
    headers: { "x-api-key": API_KEY, "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`HTTP ${resp.status} ${resp.statusText} - ${text}`);
  }
  return resp.json();
}

// ====== PING NA API ======
async function ping(){
  try{
    await fetch(`${BASE_URL}/health`, { cache:"no-store" });
    API_ONLINE = true;
    updateApiStatus();
  }catch{
    API_ONLINE = false;
    updateApiStatus();
  }
}
function updateApiStatus(){
  const el = $("#api-status");
  if (!el) return;
  el.textContent = API_ONLINE ? "online ✅" : "offline ❌";
}

// ====== AÇÕES DOS BOTÕES ======
$("#btn-block")?.addEventListener("click", async () => {
  if (!API_ONLINE) {
    showToast("API offline — simulando bloqueio");
    return;
  }
  try{
    await apiJSON("/v1/reports", {
      method: "POST",
      body: JSON.stringify({
        url: "http://wa.me/5511987654321",
        description: "Usuário marcou como golpe no app",
        reporterHash: "ui-demo",
        evidence: []
      })
    });
    showToast("Denúncia enviada ✅");
  }catch(err){
    console.error(err);
    showToast("Falha ao enviar denúncia");
  }
});

$("#btn-safe")?.addEventListener("click", async () => {
  if (!API_ONLINE) {
    showToast("API offline — simulando verificação");
    return;
  }
  try{
    const data = await apiJSON("/v1/links/check", {
      method: "POST",
      body: JSON.stringify({ url: "http://bit.ly/qualquercoisa" })
    });
    const msg = data.isSafe ? "Link marcado como seguro ✅" :
      `Cuidado! Severidade: ${String(data.severity || "").toUpperCase()} ⚠️`;
    showToast(msg);
  }catch(err){
    console.error(err);
    showToast("Falha ao checar link");
  }
});

async function loadAlerts(){
  const box = $("#alerts-list");
  box.innerHTML = `<div class="bubble">Carregando...</div>`;
  try{
    const items = API_ONLINE ? await apiJSON("/v1/alerts?status=new") : [];
    if (!items.length) {
      box.innerHTML = `<div class="bubble">Sem alertas novos.</div>`;
      return;
    }
    box.innerHTML = "";
    items.forEach(a => {
      const el = document.createElement("div");
      el.className = "alert-card";
      el.innerHTML = `
        <div class="alert-icon">⚠️</div>
        <div class="alert-body">
          <h3 style="margin:0 0 4px;">${a.type || "ALERTA"}</h3>
          <p style="margin:0 0 8px;">${a.description || "Sem descrição"}</p>
          <div style="display:flex; gap:8px; align-items:center;">
            <span class="bubble" style="margin:0;">Severidade: <strong>${(a.severity||"low").toUpperCase()}</strong></span>
            <button class="btn primary" data-ack="${a.id}">Marcar como lido</button>
          </div>
        </div>`;
      box.appendChild(el);
    });

    box.querySelectorAll("[data-ack]").forEach(btn => {
      btn.addEventListener("click", async () => {
        try{
          await apiJSON(`/v1/alerts/${btn.dataset.ack}/ack`, { method: "PATCH" });
          showToast("Alerta reconhecido ✅");
          loadAlerts();
        }catch(err){
          console.error(err);
          showToast("Falha ao reconhecer alerta");
        }
      });
    });

  }catch(err){
    console.error(err);
    box.innerHTML = `<div class="bubble">Erro ao carregar alertas.</div>`;
  }
}

ping();         
loadAlerts();     
