// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const pino = require('pino');
const pinoHttp = require('pino-http');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const path = require('path');

const env = {
  PORT: Number(process.env.PORT || 3000),
  API_KEY: process.env.GUARDIAO_API_KEY || 'dev-123',
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
  HELMET_ENABLED: String(process.env.HELMET_ENABLED || 'true').toLowerCase()==='true',
  MAX_JSON_SIZE: process.env.MAX_JSON_SIZE || '1mb',
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  PRETTY_LOGS: String(process.env.PRETTY_LOGS || 'true').toLowerCase()==='true',
  RATE_LIMIT_POINTS: Number(process.env.RATE_LIMIT_POINTS || 60),
  RATE_LIMIT_DURATION: Number(process.env.RATE_LIMIT_DURATION || 60),
  SCORE_HIGH_MIN: Number(process.env.SCORE_HIGH_MIN || 80),
  SCORE_MEDIUM_MIN: Number(process.env.SCORE_MEDIUM_MIN || 50),
  SAFE_BROWSING_KEY: process.env.SAFE_BROWSING_KEY || '',
  OPENPHISH_FEED_URL: process.env.OPENPHISH_FEED_URL || '',
  DB: {
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'guardiao60',
    waitForConnections: true,
    connectionLimit: 10
  }
};

const logger = pino({
  level: env.LOG_LEVEL,
  transport: env.PRETTY_LOGS ? { target: 'pino-pretty', options: { colorize: true } } : undefined
});

const app = express();
if (env.HELMET_ENABLED) app.use(helmet());
app.use(cors({ origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN }));
app.use(express.json({ limit: env.MAX_JSON_SIZE }));
app.use(pinoHttp({ logger }));

// static (frontend)
app.use(express.static(path.join(__dirname)));

const pool = mysql.createPool(env.DB);
pool.getConnection().then(c => { c.release(); logger.info('[mysql] conectado'); })
  .catch(err => logger.error({ err }, '[mysql] erro ao conectar'));

// rate-limit e api-key
const limiter = new RateLimiterMemory({ points: env.RATE_LIMIT_POINTS, duration: env.RATE_LIMIT_DURATION });
const rateLimit = (req, res, next) => limiter.consume(req.ip||'global').then(()=>next()).catch(()=>res.status(429).json({error:'too_many_requests'}));
const apiKey = (req,res,next) => {
  const k = req.header('x-api-key'); if(!k || k!==env.API_KEY) return res.status(401).json({error:'unauthorized'}); next();
};

// utils heurística
const SHORTENERS = ['bit.ly','tinyurl.com','t.co','is.gd','goo.gl','cutt.ly','ow.ly','rebrand.ly'];
const SUSPICIOUS = ['pix','premio','brinde','ganhou','suporte','senha','bloqueio','liberar','cartão','banco','itau','nubank','correios','receita','fgts'];
const normalizeUrl = (input)=>{
  try{
    const u = new URL(String(input).trim());
    u.hash = '';
    ['utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','fbclid'].forEach(p=>u.searchParams.delete(p));
    u.hostname = u.hostname.toLowerCase();
    return u.toString();
  }catch{ return null; }
};
function heuristicScore(uObj){
  let score = 0; const reasons=[];
  const host = uObj.hostname.toLowerCase();
  if (SHORTENERS.some(s=>host.endsWith(s))) { score+=25; reasons.push('url_shortener'); }
  const dots = host.split('.').length-1; if (dots>=3) { score+=10; reasons.push('many_subdomains'); }
  if (/\.(top|xyz|click|link|fit|rest|gq|ml|cf|tk)$/i.test(host)) { score+=15; reasons.push('uncommon_tld'); }
  const full = uObj.toString().toLowerCase();
  if (SUSPICIOUS.some(k=>full.includes(k))) { score+=20; reasons.push('suspicious_keywords'); }
  if (uObj.protocol==='http:') { score+=10; reasons.push('no_https'); }
  return { score: Math.max(0,Math.min(100,score)), reasons };
}
const severityFromScore = (s)=> s>=env.SCORE_HIGH_MIN ? 'high' : s>=env.SCORE_MEDIUM_MIN ? 'medium' : 'low';

// integrações (stubs no MVP)
async function checkSafeBrowsing(url){
  if(!env.SAFE_BROWSING_KEY) return {hit:false, source:'safe_browsing:stub'};
  try{
    const body={client:{clientId:'guardiao60',clientVersion:'1.0'},
      threatInfo:{ threatTypes:["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes:["ANY_PLATFORM"], threatEntryTypes:["URL"], threatEntries:[{url}] }};
    const r= await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${env.SAFE_BROWSING_KEY}`, body, {timeout:4000});
    return { hit: !!(r.data && r.data.matches && r.data.matches.length), source:'safe_browsing' };
  }catch{ return {hit:false, source:'safe_browsing:error'} }
}
async function checkOpenPhish(url){
  if(!env.OPENPHISH_FEED_URL) return {hit:false, source:'openphish:stub'};
  try{
    const r = await axios.get(env.OPENPHISH_FEED_URL, {timeout:4000});
    return { hit: typeof r.data==='string' && r.data.includes(url), source:'openphish' };
  }catch{ return {hit:false, source:'openphish:error'} }
}

// ---------- Rotas ----------
app.get('/health', (_req,res)=>res.json({status:'ok'}));

// Dicas (simples)
app.get('/v1/tips', apiKey, (_req,res)=>{
  res.json([
    "Nunca envie senhas ou códigos por mensagem.",
    "Bancos não pedem PIX ou dados por WhatsApp.",
    "Desconfie de links encurtados (bit.ly, tinyurl...).",
    "Confirme com familiares antes de transferir dinheiro.",
    "Desconfie de urgência e prêmios fáceis."
  ]);
});

// Analisar link
app.post('/v1/links/check', rateLimit, apiKey, async (req,res)=>{
  const norm = normalizeUrl(req.body?.url||'');
  if(!norm) return res.status(400).json({error:'invalid_url'});
  const u = new URL(norm);
  const local = heuristicScore(u);
  let score = local.score; const reasons=[...local.reasons]; const sources=['local'];
  const s1 = await checkSafeBrowsing(norm); if(s1.hit){ score = Math.max(score, 90); reasons.push('safe_browsing_match'); sources.push(s1.source); }
  const s2 = await checkOpenPhish(norm);    if(s2.hit){ score = Math.max(score, 95); reasons.push('openphish_match');    sources.push(s2.source); }
  const severity = severityFromScore(score);
  const isSafe = severity==='low';

  const conn = await pool.getConnection();
  try{
    const [r] = await conn.execute(
      'INSERT INTO link_checks (url,is_safe,score,reasons,sources) VALUES (?,?,?,?,?)',
      [norm, isSafe?1:0, score, JSON.stringify(reasons), JSON.stringify(sources)]
    );
    const savedId = r.insertId;

    if(!isSafe){
      await conn.execute(
        'INSERT INTO alerts (type,url,description,severity,score,status) VALUES (?,?,?,?,?,?)',
        ['LINK_SUSPECT', norm, 'Link com indícios de phishing', severity, score, 'new']
      );
    }

    res.json({ url:norm, isSafe, score, severity, reasons, sources, savedId });
  } finally { conn.release(); }
});

// Denúncia
app.post('/v1/reports', rateLimit, apiKey, async (req,res)=>{
  const { url, description, reporterHash, evidence } = req.body || {};
  const norm = url ? normalizeUrl(url) : null;
  let score = 0, severity = 'low';

  if(norm){
    const u = new URL(norm);
    const local = heuristicScore(u);
    score = local.score;
    const s1 = await checkSafeBrowsing(norm); if(s1.hit) score = Math.max(score, 90);
    const s2 = await checkOpenPhish(norm);    if(s2.hit) score = Math.max(score, 95);
    severity = severityFromScore(score);
  }

  const riskyText = String(description||'').toLowerCase();
  const textSuggestsRisk = ['pix','senha','cobrança','bloqueio','link','golpe','phishing'].some(k=>riskyText.includes(k));

  const conn = await pool.getConnection();
  try{
    const [r] = await conn.execute(
      'INSERT INTO reports (url,description,reporter_hash,evidence) VALUES (?,?,?,?)',
      [norm, description||null, reporterHash||null, evidence?JSON.stringify(evidence):null]
    );
    const savedId = r.insertId;

    if ((norm && (severity==='medium' || severity==='high')) || textSuggestsRisk) {
      await conn.execute(
        'INSERT INTO alerts (type,url,description,severity,score,status) VALUES (?,?,?,?,?,?)',
        ['REPORT_SUSPECT', norm, description||'Denúncia recebida', norm?severity:'medium', norm?score:null, 'new']
      );
    }

    res.json({ id:savedId, url:norm, description, reporterHash, evidence });
  } finally { conn.release(); }
});

// Alertas
app.get('/v1/alerts', apiKey, async (req,res)=>{
  const status = req.query.status==='ack' ? 'ack' : 'new';
  const [rows] = await pool.execute(
    'SELECT id,type,url,description,severity,score,status,created_at FROM alerts WHERE status=? ORDER BY created_at DESC',
    [status]
  );
  res.json(rows);
});
app.patch('/v1/alerts/:id/ack', apiKey, async (req,res)=>{
  const id = Number(req.params.id);
  const [r] = await pool.execute('UPDATE alerts SET status="ack", ack_at=NOW() WHERE id=?',[id]);
  if (r.affectedRows===0) return res.status(404).json({error:'not_found'});
  res.json({ ok:true, id });
});

// Auth: signup/login
app.post('/auth/signup', async (req,res)=>{
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({error:'missing_fields'});
  const hash = await bcrypt.hash(password, 10);
  try{
    const [r] = await pool.execute('INSERT INTO users (email,password_hash) VALUES (?,?)',[email,hash]);
    res.json({ id:r.insertId, email });
  }catch(e){
    if (e && e.code==='ER_DUP_ENTRY') return res.status(409).json({error:'email_exists'});
    throw e;
  }
});
app.post('/auth/login', async (req,res)=>{
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({error:'missing_fields'});
  const [rows] = await pool.execute('SELECT id,email,password_hash FROM users WHERE email=? LIMIT 1',[email]);
  if(!rows.length) return res.status(401).json({error:'invalid_credentials'});
  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if(!ok) return res.status(401).json({error:'invalid_credentials'});
  res.json({ id: rows[0].id, email: rows[0].email }); // (MVP) sem JWT
});

// 404 e erro
app.use((_req,res)=>res.status(404).json({error:'not_found'}));
app.use((err,_req,res,_next)=>{ logger.error(err); res.status(500).json({error:'internal_error'}) });

app.listen(env.PORT, ()=> logger.info(`[server] http://localhost:${env.PORT}`));
