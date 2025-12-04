// server.js
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const path = require("path");

const app = express();
app.use(express.json());
app.use(cors());

// ======== SERVIR FRONT-END ========
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ======== CONFIG DB (CONEXÃO ÚNICA) ========
const dbConfig = {
    host: "localhost",
    user: "root",
    password: "root",
    database: "guardiao60"
};

// Criar pool (melhor que createConnection)
const db = mysql.createPool(dbConfig);

// --------------------- USERS ---------------------

app.post("/users", async (req, res) => {
    const { email, password_hash } = req.body;

    try {
        await db.query(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            [email, password_hash]
        );

        res.json({ message: "Usuário criado com sucesso" });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --------------------- MESSAGES ---------------------

app.get("/messages", async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM messages ORDER BY created_at DESC");
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get("/messages/:id", async (req, res) => {
    try {
        const [rows] = await db.query(
            "SELECT * FROM messages WHERE id = ?",
            [req.params.id]
        );
        res.json(rows[0] || {});
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post("/messages", async (req, res) => {
    const { sender, body } = req.body;

    try {
        await db.query(
            "INSERT INTO messages (sender, body, received_at) VALUES (?, ?, NOW())",
            [sender, body]
        );

        res.json({ message: "Mensagem salva!" });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --------------------- ALERTAS ---------------------

// Listar todos os alertas
app.get("/alerts", async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM alerts ORDER BY created_at DESC");
        res.json(rows);
    } catch (err) {
        console.error("Erro ao carregar alertas:", err);
        res.status(500).json({ error: "Erro ao carregar alertas" });
    }
});

// Criar alerta
app.post("/alerts", async (req, res) => {
    try {
        const { type, description, severity, score, source, message_id } = req.body;

        await db.query(
            `INSERT INTO alerts (type, description, severity, score, source, message_id)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [type, description, severity, score, source, message_id]
        );

        res.json({ success: true, message: "Alerta criado com sucesso" });

    } catch (err) {
        console.error("Erro ao criar alerta:", err);
        res.status(500).json({ error: "Erro ao criar alerta" });
    }
});

// --------------------- INICIAR SERVIDOR ---------------------
app.listen(3000, () => {
    console.log("Servidor rodando em http://localhost:3000");
});
