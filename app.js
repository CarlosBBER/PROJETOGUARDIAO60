// ===============================
// CONFIG
// ===============================
const API = "/v1";
const KEY = "dev-123";

// ===============================
// FUNÇÃO PADRÃO DE REQUISIÇÃO
// ===============================
async function api(path, data = null, method = "GET") {
  const opt = {
    method,
    headers: {
      "Content-Type": "application/json",
      "x-api-key": KEY,
    }
  };

  if (data) opt.body = JSON.stringify(data);

  const r = await fetch(API + path, opt);
  if (!r.ok) {
    const e = await r.text().catch(() => "");
    throw new Error(`API ${r.status} ${e}`);
  }
  return r.json();
}

// ===============================
// TOAST
// ===============================
function toast(msg) {
  const t = document.getElementById("toast");
  t.innerText = msg;
  t.style.display = "block";
  setTimeout(() => t.style.display = "none", 2500);
}

// ===============================
// NAVEGAR ENTRE TELAS
// ===============================
function show(id) {
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  document.getElementById("screen-" + id).classList.add("active");

  if (id === "alerts") loadAlerts();
}

// Tabbar
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    show(tab.dataset.goto);
  });
});

// ===============================
// LOGIN
// ===============================
document.getElementById("btn-login")?.addEventListener("click", async () => {
  const email = login-email.value;
  const pass = login-pass.value;

  try {
    await api("/auth/login", { email, password: pass }, "POST");
    show("home");
  } catch (e) {
    toast("Erro ao entrar: " + e.message);
  }
});

// ===============================
// SIGNUP
// ===============================
document.getElementById("btn-signup")?.addEventListener("click", async () => {
  const email = login-email.value;
  const pass = login-pass.value;

  try {
    await api("/auth/signup", { email, password: pass }, "POST");
    toast("Conta criada!");
  } catch (e) {
    toast("Erro ao criar conta: " + e.message);
  }
});

// ===============================
// CARREGAR DICAS
// ===============================
async function loadTips() {
  const box = document.getElementById("tips-box");
  box.innerHTML = "Carregando...";
  try {
    const tips = await api("/tips");
    box.innerHTML = tips.map(t => `<div class="tip">${t}</div>`).join("");
  } catch {
    box.innerHTML = "<div class='bubble'>Erro ao carregar dicas.</div>";
  }
}

document.getElementById("to-tips")?.addEventListener("click", () => {
  show("tips");
  loadTips();
});

// ===============================
// CARREGAR ALERTAS
// ===============================
async function loadAlerts() {
  const box = document.getElementById("alerts-list");
  box.innerHTML = "<div class='bubble'>Carregando...</div>";

  try {
    const rows = await api("/alerts");
    if (!rows.length) {
      box.innerHTML = "<div class='bubble'>Nenhum alerta encontrado.</div>";
      return;
    }

    box.innerHTML = rows.map(a => `
      <div class="alert-card ${a.severity}">
        <div class="title">${a.type}</div>
        <div class="desc">${a.description}</div>
        <div class="meta">
          Severidade: <strong>${a.severity}</strong> · Score: ${a.score}
        </div>
        <small>${new Date(a.created_at).toLocaleString()}</small>
      </div>
    `).join("");
  } catch (e) {
    box.innerHTML = "<div class='bubble'>Erro ao carregar alertas.</div>";
  }
}

// ===============================
// ANALISAR MENSAGEM
// ===============================
document.getElementById("btn-analyze-msg")?.addEventListener("click", async () => {
  const text = prompt("Cole a mensagem suspeita:");
  if (!text) return;

  try {
    const r = await api("/messages/analyze", { text }, "POST");
    toast(`Resultado: ${r.severity.toUpperCase()} (score ${r.score})`);
    loadAlerts();
  } catch (e) {
    toast("Erro ao analisar mensagem: " + e.message);
  }
});

// ===============================
// MARCAR COMO GOLPE
// ===============================
document.getElementById("btn-block")?.addEventListener("click", async () => {
  try {
    await api("/alerts/report", {}, "POST");
    toast("Registrado como golpe!");
    loadAlerts();
  } catch (e) {
    toast("Erro ao registrar golpe: " + e.message);
  }
});

// ===============================
// MARCAR COMO SEGURO
// ===============================
document.getElementById("btn-safe")?.addEventListener("click", async () => {
  try {
    await api("/alerts/safe", {}, "POST");
    toast("Registrado como seguro!");
    loadAlerts();
  } catch (e) {
    toast("Erro ao registrar segurança: " + e.message);
  }
});

// ===============================
// VERIFICAR MENSAGENS (ABRIR TELA)
// ===============================
document.getElementById("to-shield")?.addEventListener("click", () => {
  show("shield");
});
