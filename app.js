// app.js (cliente)
const API = '/v1';
const KEY = 'dev-123';

// universal API caller
async function api(path, data = null, method = 'GET', needKey = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (needKey) headers['x-api-key'] = KEY;

  const opt = { method, headers };
  if (data) opt.body = JSON.stringify(data);

  const url = window.location.origin + API + path;
  const r = await fetch(url, opt);
  const txt = await r.text().catch(() => null);
  if (!r.ok) throw new Error(`${r.status} ${txt || ''}`);
  try { return JSON.parse(txt || '{}'); } catch { return {}; }
}

// toast
function toast(msg, time = 3000) {
  const el = document.getElementById('toast');
  if (!el) return alert(msg);
  el.innerText = msg;
  el.style.display = 'block';
  setTimeout(() => el.style.display = 'none', time);
}

// simple screen switch
function show(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const el = document.getElementById('screen-' + id);
  if (el) el.classList.add('active');
  if (id === 'alerts') loadAlerts();
  if (id === 'shield') loadShieldMessage();
}

// tabs
document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    show(t.dataset.goto);
  });
});

// LOGIN
document.getElementById('btn-login')?.addEventListener('click', async () => {
  const email = document.getElementById('login-email').value.trim();
  const pass = document.getElementById('login-pass').value;
  if (!email || !pass) return toast('Preencha email e senha');
  try {
    await api('/auth/login', { email, password: pass }, 'POST', false);
    toast('Login OK');
    show('home');
    loadAlerts();
  } catch (e) {
    toast('Erro ao entrar: ' + e.message);
  }
});

// SIGNUP
document.getElementById('btn-signup')?.addEventListener('click', async () => {
  const email = document.getElementById('login-email').value.trim();
  const pass = document.getElementById('login-pass').value;
  if (!email || !pass) return toast('Preencha email e senha');
  try {
    await api('/auth/signup', { email, password: pass }, 'POST', false);
    toast('Conta criada!');
  } catch (e) {
    toast('Erro ao criar conta: ' + e.message);
  }
});

// LOGOUT
document.getElementById('btn-logout')?.addEventListener('click', () => {
  // no session stored (MVP) -> only go back to login
  show('login');
  toast('Desconectado');
});

// TIPS
async function loadTips() {
  const box = document.getElementById('tips-box');
  if (!box) return;
  box.innerHTML = '<div class="bubble">Carregando...</div>';
  try {
    const tips = await api('/tips', null, 'GET', true);
    box.innerHTML = tips.map(t => `<div class="tip">${t}</div>`).join('');
  } catch (e) {
    box.innerHTML = `<div class="bubble">Erro ao carregar dicas: ${e.message}</div>`;
  }
}
document.getElementById('to-tips')?.addEventListener('click', () => { loadTips(); show('tips'); });
document.getElementById('to-shield')?.addEventListener('click', () => show('shield'));

// ALERTS list
async function loadAlerts() {
  const box = document.getElementById('alerts-list');
  if (!box) return;
  box.innerHTML = '<div class="bubble">Carregando...</div>';
  try {
    // default: only 'new' alerts. Add ?status=all to show everything
    const rows = await api('/alerts?status=new', null, 'GET', true);
    if (!rows || !rows.length) {
      box.innerHTML = '<div class="bubble">Nenhum alerta novo.</div>';
      return;
    }
    box.innerHTML = rows.map(a => `
      <div class="alert-card ${a.severity}">
        <div class="title">${escapeHtml(a.type)}</div>
        <div class="desc">${escapeHtml(a.description || '')}</div>
        <div class="meta">Severidade: <strong class="chip">${a.severity}</strong> • Score: ${a.score ?? 'N/A'}</div>
        <small>${new Date(a.created_at).toLocaleString()}</small>
      </div>
    `).join('');
  } catch (e) {
    box.innerHTML = `<div class="bubble">Erro: ${e.message}</div>`;
  }
}

// shield (show next message to review)
let currentMessage = null;
async function loadShieldMessage() {
  const box = document.querySelector('#screen-shield .alert-box');
  if (!box) return;
  box.innerHTML = '<div class="bubble">Buscando próxima mensagem para analisar...</div>';
  try {
    const msg = await api('/messages/next', null, 'GET', true);
    if (!msg) {
      box.innerHTML = '<div class="alert-box"><p>Nenhuma mensagem pendente para análise.</p></div>';
      currentMessage = null;
      return;
    }
    currentMessage = msg;
    box.innerHTML = `
      <p class="alert-title">⚠️ Alerta!</p>
      <p>Mensagem suspeita detectada: <br><em id="shield-body">${escapeHtml(msg.body)}</em></p>
      <p style="font-size:0.9rem;color:#666;margin-top:.6rem">Recebida: ${msg.received_at ? new Date(msg.received_at).toLocaleString() : '—'}</p>
    `;
  } catch (e) {
    box.innerHTML = `<div class="bubble">Erro: ${e.message}</div>`;
  }
}

// MARK AS REPORT (golpe)
document.getElementById('btn-block')?.addEventListener('click', async () => {
  try {
    const body = { message_id: currentMessage ? currentMessage.id : undefined };
    await api('/alerts/report', body, 'POST', true);
    toast('Registrado como golpe!');
    loadAlerts();
    loadShieldMessage();
  } catch (e) {
    toast('Erro ao registrar golpe: ' + e.message);
  }
});

// MARK AS SAFE
document.getElementById('btn-safe')?.addEventListener('click', async () => {
  try {
    const body = { message_id: currentMessage ? currentMessage.id : undefined };
    await api('/alerts/safe', body, 'POST', true);
    toast('Registrado como seguro!');
    loadAlerts();
    loadShieldMessage();
  } catch (e) {
    toast('Erro ao marcar como seguro: ' + e.message);
  }
});

// ANALYZE (manual)
document.getElementById('btn-analyze-msg')?.addEventListener('click', async () => {
  const text = prompt('Cole a mensagem suspeita:');
  if (!text) return;
  try {
    const r = await api('/messages/analyze', { text }, 'POST', true);
    toast(`Resultado: ${r.severity.toUpperCase()} (score ${r.score})`, 4000);
    loadAlerts();
    loadShieldMessage();
  } catch (e) {
    toast('Erro ao analisar: ' + e.message);
  }
});

// Helper: escape html
function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[ch]);
}

// initial load
document.addEventListener('DOMContentLoaded', () => {
  loadTips();
  loadAlerts();
});
