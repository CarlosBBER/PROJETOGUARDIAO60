// ====================== TROCA DE TELAS ======================
function openScreen(id) {
  // esconde todas as telas
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  document.getElementById(id).classList.add("active");

  // desativa tabs
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));

  // ativa tab correspondente
  if (id === "screen-login") document.getElementById("tab-login").classList.add("active");
  if (id === "screen-home") document.getElementById("tab-home").classList.add("active");
  if (id === "screen-messages") {
      document.getElementById("tab-messages").classList.add("active");
      loadMessages();
  }
  if (id === "screen-alerts") {
      document.getElementById("tab-alerts").classList.add("active");
      loadAlerts();
  }
}

let selectedMessageId = null;
let selectedMessageText = "";

// abrir modal
function openAnalyzeOptions(id, text) {
    selectedMessageId = id;
    selectedMessageText = text;

    document.getElementById("modal-message-text").innerText = text;
    document.getElementById("analyze-modal").style.display = "block";
}

// fechar modal
function closeModal() {
    document.getElementById("analyze-modal").style.display = "none";
}


// ====================== TOAST ======================
function showToast(msg) {
  const t = document.getElementById("toast");
  t.innerText = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2000);
}


// ====================== CADASTRO ======================
async function registerUser() {
  const email = document.getElementById("reg-email").value.trim();
  const pass = document.getElementById("reg-pass").value.trim();

  if (!email || !pass) {
      showToast("Preencha todos os campos!");
      return;
  }

  try {
      const res = await fetch("/users", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ email, password_hash: pass })
      });

      showToast("Conta criada com sucesso!");

      // aguarda o toast aparecer
      setTimeout(() => openScreen("screen-login"), 1200);

  } catch (err) {
      showToast("Erro ao criar conta.");
  }
}



// ====================== LOGIN ======================
async function loginUser() {
  const email = document.getElementById("login-email").value.trim();
  const pass = document.getElementById("login-pass").value.trim();

  if (!email || !pass) {
      showToast("Digite e-mail e senha.");
      return;
  }

  // por enquanto simulação
  showToast("Login realizado com sucesso!");

  // delay para mostrar o toast antes de trocar de tela
  setTimeout(() => openScreen("screen-home"), 1200);
}



// ====================== LISTAR MENSAGENS ======================
async function loadMessages() {
  const container = document.getElementById("messages-list");
  container.innerHTML = "Carregando...";

  try {
      const res = await fetch("/messages");
      const msgs = await res.json();

      container.innerHTML = "";
      msgs.forEach(m => {
          const card = document.createElement("div");
          card.className = "alert-card low";
          card.innerHTML = `
    <strong>De:</strong> ${m.sender}<br>
    <strong>Mensagem:</strong> ${m.body}<br>
    <strong>Recebida:</strong> ${m.received_at}<br><br>

    <button class="btn primary" style="margin-top:10px;"
        onclick="openAnalyzeOptions(${m.id}, '${m.body.replace(/'/g, "\\'")}')">
        🔍 Analisar mensagem
    </button>
`;
          container.appendChild(card);
      });
  } catch (err) {
      container.innerHTML = "Erro ao carregar mensagens";
      showToast("Erro ao conectar ao servidor.");
  }
}


// Listar alertas

async function loadAlerts() {
  const container = document.getElementById("alerts-list");
  container.innerHTML = "Carregando...";

  try {
      const res = await fetch("/alerts");
      const alerts = await res.json();

      container.innerHTML = "";

      if (alerts.length === 0) {
          container.innerHTML = "<p>Nenhum alerta encontrado.</p>";
          return;
      }

      alerts.forEach(alert => {
          const card = document.createElement("div");
          card.className = `alert-card ${alert.severity}`;

          card.innerHTML = `
              <strong>📝 Tipo:</strong> ${alert.type}<br>
              <strong>📌 Descrição:</strong> ${alert.description}<br>
              <strong>⚠ Severidade:</strong> ${alert.severity}<br>
              <strong>⭐ Score:</strong> ${alert.score}<br>
              <strong>📅 Criado em:</strong> ${new Date(alert.created_at).toLocaleString()}<br>
          `;

          container.appendChild(card);
      });

  } catch (err) {
      container.innerHTML = "Erro ao carregar alertas.";
      showToast("Erro ao conectar ao servidor.");
  }
}


// ====================== SALVAR ANÁLISE (OBSOLETA) ======================
// Removemos o uso dessa função, mas deixei caso queira reaproveitar depois.
// Agora usamos markAsScam() e markAsSafe().

async function saveAnalysis(texto) {
  const payload = {
      sender: "Usuário",
      body: texto
  };

  await fetch("/messages", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
  });

  showToast("Mensagem analisada e salva!");
}



// ====================== MARCAR COMO GOLPE ======================
async function markAsScam() {
    const payload = {
        type: "SCAM",
        description: selectedMessageText,
        severity: "high",
        score: 90,
        source: "user",
        message_id: selectedMessageId
    };

    await fetch("/alerts", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
    });

    showToast("Mensagem marcada como GOLPE!");
    closeModal();
}



// ====================== MARCAR COMO SEGURO ======================
async function markAsSafe() {
    const payload = {
        type: "SAFE",
        description: selectedMessageText,
        severity: "low",
        score: 10,
        source: "user",
        message_id: selectedMessageId
    };

    await fetch("/alerts", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
    });

    showToast("Mensagem marcada como SEGURA!");
    closeModal();
}
