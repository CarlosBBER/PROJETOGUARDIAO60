// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.GUARDIAO_API_KEY || 'dev-123';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

const app = express();
app.use(helmet());
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN }));
app.use(express.json());
app.use(express.static(path.join(__dirname))); // serve index.html, app.js, style.css etc

// MySQL pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'guardiao60',
  waitForConnections: true,
  connectionLimit: 10
});

pool.getConnection().then(c => { c.release(); console.log('MySQL conectado!') })
  .catch(err => console.error('MySQL connect error', err));

// --- Middleware para rotas protegidas por API KEY
function checkKey(req, res, next) {
  const k = req.header('x-api-key');
  if (!k || k !== API_KEY) return res.status(401).json({ error: 'unauthorized' });
  next();
}

// ---------------------------
// AUTH (não exige API key)
// ---------------------------
app.post('/v1/auth/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const [r] = await pool.execute(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [email, hash]
    );
    res.json({ id: r.insertId, email });
  } catch (e) {
    if (e && e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'email_exists' });
    console.error('signup error', e);
    res.status(500).json({ error: 'db_error' });
  }
});

app.post('/v1/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
  try {
    const [rows] = await pool.execute('SELECT id,email,password_hash FROM users WHERE email = ? LIMIT 1', [email]);
    if (!rows.length) return res.status(401).json({ error: 'invalid_credentials' });
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
    res.json({ id: rows[0].id, email: rows[0].email });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ error: 'db_error' });
  }
});

// ---------------------------
// Tips (protegido por API KEY)
// ---------------------------
app.get('/v1/tips', checkKey, (_req, res) => {
  res.json([
    "Desconfie de pedidos urgentes por PIX.",
    "Confirme sempre com familiares antes de enviar dinheiro.",
    "Links encurtados podem ocultar golpes.",
    "Jamais informe sua senha por mensagem.",
    "Golpes usam nomes de bancos para enganar.",
    "Evite clicar em links desconhecidos.",
    "Prêmios fáceis quase sempre são golpes.",
  ]);
});

// ---------------------------
// Alerts: listar (protegido)
// query: ?status=new|ack|all (default new)
// ---------------------------
app.get('/v1/alerts', checkKey, async (req, res) => {
  const status = (req.query.status === 'all') ? null : (req.query.status || 'new');
  try {
    let rows;
    if (status) {
      [rows] = await pool.execute(
        'SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC',
        [status]
      );
    } else {
      [rows] = await pool.execute('SELECT * FROM alerts ORDER BY created_at DESC');
    }
    res.json(rows);
  } catch (e) {
    console.error('/v1/alerts', e);
    res.status(500).json({ error: 'db_error' });
  }
});

// ---------------------------
// Get next unprocessed message (to show on "shield")
// ---------------------------
app.get('/v1/messages/next', checkKey, async (_req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM messages WHERE processed = 0 ORDER BY received_at IS NULL, received_at ASC, created_at ASC LIMIT 1'
    );
    res.json(rows[0] || null);
  } catch (e) {
    console.error('/v1/messages/next', e);
    res.status(500).json({ error: 'db_error' });
  }
});

// ---------------------------
// Submit message (manual or from queue) -> inserted into messages
// body: { sender, body, received_at }
// ---------------------------
app.post('/v1/messages/submit', checkKey, async (req, res) => {
  const { sender, body, received_at } = req.body || {};
  if (!body) return res.status(400).json({ error: 'missing_body' });
  try {
    const [r] = await pool.execute(
      'INSERT INTO messages (sender, body, received_at) VALUES (?,?,?)',
      [sender || null, body, received_at || null]
    );
    res.json({ id: r.insertId });
  } catch (e) {
    console.error('/v1/messages/submit', e);
    res.status(500).json({ error: 'db_error' });
  }
});

// ---------------------------
// Analyze text (ad-hoc) -> returns severity and score AND creates message+alert
// body: { text }
// ---------------------------
function heuristicForText(text) {
  const riskyWords = ['pix','urgente','senha','código','bloqueio','transferência','hospital','acidente','ajuda','você ganhou','prêmio','boleto'];
  let score = 0;
  const found = [];
  const lower = String(text || '').toLowerCase();
  riskyWords.forEach(w => {
    if (lower.includes(w)) { score += 15; found.push(w); }
  });
  // heuristics: URLs, numbers, exclamation urgency
  if (/\bhttps?:\/\//i.test(text)) { score += 20; found.push('url'); }
  if (/\b\d{6,}\b/.test(text)) { score += 10; found.push('long_number'); }
  if (/[!]{2,}/.test(text) || /urgent|imediato/.test(lower)) { score += 10; found.push('urgency'); }
  score = Math.min(100, score);
  const severity = score >= 80 ? 'high' : score >= 50 ? 'medium' : 'low';
  return { score, severity, reasons: found };
}

app.post('/v1/messages/analyze', checkKey, async (req, res) => {
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: 'missing_text' });
  try {
    // 1) save message
    const [r] = await pool.execute(
      'INSERT INTO messages (sender, body, received_at, processed) VALUES (?,?,NULL,1)',
      ['analyzer', text]
    );
    const messageId = r.insertId;

    // 2) analyze
    const result = heuristicForText(text);

    // 3) if medium/high create alert
    if (result.severity === 'medium' || result.severity === 'high') {
      await pool.execute(
        'INSERT INTO alerts (type, description, severity, score, source, message_id, status) VALUES (?,?,?,?,?,?,?)',
        ['TEXT_ANALYSIS', text.slice(0, 1000), result.severity, result.score, 'auto', messageId, 'new']
      );
    }

    // 4) store result_json in messages row (optional)
    await pool.execute(
      'UPDATE messages SET processed = 1, processed_at = NOW(), result_json = ? WHERE id = ?',
      [JSON.stringify(result), messageId]
    );

    res.json({ score: result.score, severity: result.severity, reasons: result.reasons, messageId });
  } catch (e) {
    console.error('/v1/messages/analyze', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/v1/alerts/report', checkKey, async (req, res) => {
  const { message_id } = req.body || {};
  try {
    let description = 'Marcado como golpe pelo usuário';
    if (message_id) {
      const [rows] = await pool.execute('SELECT body FROM messages WHERE id = ? LIMIT 1', [message_id]);
      if (rows && rows.length) description = rows[0].body.slice(0, 1000);
    }
    const [r] = await pool.execute(
      `INSERT INTO alerts (type, description, severity, score, source, message_id, status)
       VALUES (?,?,?,?,?,?,?)`,
      ['REPORT', description, 'high', 90, 'user', message_id || null, 'new']
    );
    if (message_id) {
      await pool.execute('UPDATE messages SET processed = 1, processed_at = NOW() WHERE id = ?', [message_id]);
    }
    res.json({ success: true, id: r.insertId });
  } catch (e) {
    console.error('/v1/alerts/report', e);
    res.status(500).json({ error: 'db_error' });
  }
});

app.post('/v1/alerts/safe', checkKey, async (req, res) => {
  const { message_id } = req.body || {};
  try {
    let description = 'Marcado como seguro pelo usuário';
    if (message_id) {
      const [rows] = await pool.execute('SELECT body FROM messages WHERE id = ? LIMIT 1', [message_id]);
      if (rows && rows.length) description = rows[0].body.slice(0, 1000);
    }
    const [r] = await pool.execute(
      `INSERT INTO alerts (type, description, severity, score, source, message_id, status)
       VALUES (?,?,?,?,?,?,?)`,
      ['SAFE', description, 'low', 10, 'user', message_id || null, 'new']
    );
    if (message_id) {
      await pool.execute('UPDATE messages SET processed = 1, processed_at = NOW() WHERE id = ?', [message_id]);
    }
    res.json({ success: true, id: r.insertId });
  } catch (e) {
    console.error('/v1/alerts/safe', e);
    res.status(500).json({ error: 'db_error' });
  }
});

// ============================
// GET 
// ============================
app.get("/v1/messages/next", checkKey, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT * FROM messages WHERE processed = 0 ORDER BY created_at ASC LIMIT 1"
    );

    if (!rows.length) return res.json(null);

    res.json(rows[0]);
  } catch (err) {
    console.error("ERRO /v1/messages/next", err);
    res.status(500).json({ error: "db_error" });
  }
});


// 404 fallback
app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

// Start
app.listen(PORT, () => {
  console.log('======================================');
  console.log(` SERVIDOR RODANDO EM http://localhost:${PORT}`);
  console.log('======================================');
});
