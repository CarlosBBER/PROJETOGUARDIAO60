// app.js — Guardião60+ atualizado com alertas e acessibilidade

// ===== CONFIG =====
const API_KEY = "dev-123"; // mesma chave do .env
const API_BASE = "/v1";

// ===== FUNÇÕES DE ACESSIBILIDADE =====
document.addEventListener("DOMContentLoaded", () => {
  // alternar contraste
  document.getElementById("btn-contrast")?.addEventListener("click", () => {
    document.body.classList.toggle("high-contrast");
    localStorage.setItem("contrast", document.body.classList.contains("high-contrast"));
  });

  // alternar fonte maior
  document.getElementById("btn-font")?.addEventListener("click", () => {
    document.body.classList.toggle("big-font");
    localStorage.setItem("bigfont", document.body.classList.contains("big-font"));
  });

  // idioma
  document.getElementById("lang-select")?.addEventListener("change", (e) => {
    localStorage.setItem("lang", e.target.value);
    location.reload();
  });

  // restaurar preferências
  if (localStorage.getItem("contrast") === "true") document.body.classList.add("high-contrast");
  if (localStorage.getItem("bigfont") === "true") document.body.classList.add("big-font");
  const langSel = document.getElementById("lang-select");
  if (langSel && localStorage.getItem("lang")) langSel.value = localStorage.getItem("lang");

  // carregar alertas ao iniciar
  loadAlerts();
});

// ===== FUNÇÃO AUXILIAR =====
async function apiJSON(path, opts = {}) {
  const res = await fetch(API_BASE + path, {
    headers: {
      "x-api-key": API_KEY,
      "Content-Type": "application/json",
    },
    ...opts,
  });
  if (!res.ok) throw new Error(`Erro HTTP ${res.status}`);
  return res.json();
}

function toast(msg) {
  alert(msg); // simples — pode trocar por elemento bonito futuramente
}

// ===== ANALISAR MENSAGEM =====
document.getElementById("btn-analyze-msg")?.addEventListener("click", async () => {
  const text = prompt("Cole a mensagem suspeita aqui:");
  if (!text) return;
  try {
    const r = await apiJSON("/messages/analyze", {
      method: "POST",
      body: JSON.stringify({ text }),
    });
    toast(`Análise: ${r.severity.toUpperCase()} (score ${r.score})`);
    if (r.severity !== "low") {
      show("alerts");
      loadAlerts();
    }
  } catch (err) {
    toast("Não foi possível analisar a mensagem.");
    console.error(err);
  }
});

// ===== FUNÇÃO PARA CARREGAR ALERTAS =====
async function loadAlerts() {
  const container = document.getElementById("alerts-list");
  if (!container) return;

  container.innerHTML = "<p>Carregando alertas...</p>";

  try {
    const res = await fetch(`${API_BASE}/alerts?status=new`, {
      headers: { "x-api-key": API_KEY },
    });
    if (!res.ok) throw new Error("Erro ao carregar alertas");
    const data = await res.json();

    if (!data.length) {
      container.innerHTML = "<p>Nenhum alerta encontrado.</p>";
      return;
    }

    container.innerHTML = data
      .map(
        (a) => `
      <div class="alert-card ${a.severity}">
        <div class="alert-header">
          <strong>${a.type}</strong>
          <span class="severity-tag ${a.severity}">${a.severity}</span>
        </div>
        <p>${a.description || "(sem descrição)"}</p>
        ${
          a.url
            ? `<a href="${a.url}" target="_blank" rel="noopener">🔗 Ver link</a>`
            : ""
        }
        <small>
          Score: ${a.score ?? "N/A"}<br>
          Criado em: ${new Date(a.created_at).toLocaleString()}
        </small>
      </div>
    `
      )
      .join("");
  } catch (err) {
    console.error(err);
    container.innerHTML = "<p>Erro ao carregar alertas.</p>";
  }
}

// ===== ESTILOS AUXILIARES =====
const style = document.createElement("style");
style.textContent = `
  .high-contrast { background: #000 !important; color: #fff !important; }
  .big-font { font-size: 1.2em; }
  .alert-card {
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    padding: 12px;
    border-radius: 12px;
    margin: 8px auto;
    max-width: 700px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.05);
  }
  .alert-card.low { border-left: 6px solid #22c55e; }
  .alert-card.medium { border-left: 6px solid #facc15; }
  .alert-card.high { border-left: 6px solid #ef4444; }
  .alert-header { display: flex; justify-content: space-between; align-items: center; }
  .severity-tag { font-size: 0.8em; padding: 2px 6px; border-radius: 6px; text-transform: uppercase; color: #fff; }
  .severity-tag.low { background: #22c55e; }
  .severity-tag.medium { background: #facc15; color: #000; }
  .severity-tag.high { background: #ef4444; }
`;
document.head.appendChild(style);
