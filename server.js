require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const pino = require("pino");
const pinoHttp = require("pino-http");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.GUARDIAO_API_KEY || "dev-123";

// LOGGER
const logger = pino({
  transport: { target: "pino-pretty" }
});

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(pinoHttp({ logger }));
app.use(express.static(__dirname));

// MYSQL
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "guardiao60",
});

db.getConnection().then(c => {
  c.release();
  console.log("MySQL conectado!");
});

// MIDDLEWARE API KEY
function checkKey(req, res, next) {
  if (req.headers["x-api-key"] !== API_KEY) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

// ========================
// AUTENTICAÇÃO
// ========================
app.post("/v1/auth/signup", async (req, res) => {
  const { email, password } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);

    const [r] = await db.execute(
      "INSERT INTO users (email, password_hash) VALUES (?,?)",
      [email, hash]
    );

    res.json({ id: r.insertId, email });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "email_exists" });
    }
    console.log(err);
    res.status(500).json({ error: "db_error" });
  }
});

app.post("/v1/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await db.execute(
    "SELECT id, email, password_hash FROM users WHERE email=?",
    [email]
  );

  if (!rows.length) return res.status(401).json({ error: "invalid_credentials" });

  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: "invalid_credentials" });

  res.json({ id: rows[0].id, email });
});

// ========================
// DICAS
// ========================
app.get("/v1/tips", checkKey, (req, res) => {
  res.json([
    "Nunca compartilhe códigos de SMS.",
    "Desconfie de pedidos urgentes por PIX.",
    "Confirme sempre com familiares antes de enviar dinheiro.",
    "Links encurtados podem ocultar golpes.",
    "Jamais informe sua senha por mensagem.",
    "Golpes usam nomes de bancos para enganar.",
    "Evite clicar em links desconhecidos.",
    "Ative verificação em duas etapas.",
    "Prêmios fáceis quase sempre são golpes."
  ]);
});

// ========================
// LISTAR ALERTAS
// ========================
app.get("/v1/alerts", checkKey, async (req, res) => {
  const [rows] = await db.execute(
    "SELECT * FROM alerts ORDER BY id DESC"
  );
  res.json(rows);
});

// ========================
// MARCAR COMO GOLPE
// ========================
app.post("/v1/alerts/report", checkKey, async (req, res) => {
  const [r] = await db.execute(
    `INSERT INTO alerts (type, description, severity, score, status)
     VALUES ('REPORT', 'Marcado como golpe', 'high', 90, 'new')`
  );
  res.json({ success: true, id: r.insertId });
});

// ========================
// MARCAR COMO SEGURO
// ========================
app.post("/v1/alerts/safe", checkKey, async (req, res) => {
  const [r] = await db.execute(
    `INSERT INTO alerts (type, description, severity, score, status)
     VALUES ('SAFE', 'Marcado como seguro', 'low', 10, 'new')`
  );
  res.json({ success: true, id: r.insertId });
});

// ========================
// ANALISAR MENSAGEM
// ========================
app.post("/v1/messages/analyze", checkKey, async (req, res) => {
  const { text } = req.body;
  const riskyWords = ["pix", "urgente", "senha", "bloqueio", "código", "acidente", "hospital", "ajuda", "transferência"];

  let score = 0;
  riskyWords.forEach(w => {
    if (text.toLowerCase().includes(w)) score += 15;
  });

  const severity = score >= 80 ? "high" : score >= 50 ? "medium" : "low";

  await db.execute(
    `INSERT INTO alerts (type, description, severity, score, status)
     VALUES ('TEXT_ANALYSIS', ?, ?, ?, 'new')`,
    [text, severity, score]
  );

  res.json({ score, severity });
});

// 404
app.use((_req,res)=>res.status(404).json({error:"not_found"}));

// INICIAR SERVIDOR
app.listen(PORT, () => {
  console.log("======================================");
  console.log(` SERVIDOR RODANDO EM http://localhost:${PORT}`);
  console.log("======================================");
});
