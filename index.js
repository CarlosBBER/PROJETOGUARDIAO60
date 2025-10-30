require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const pino = require('pino');
const pinoHttp = require('pino-http');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const { PrismaClient } = require('@prisma/client');
const axios = require('axios');

// ==== ENVs ====
const env = {
  PORT: Number(process.env.PORT || 3000),
  API_KEY: process.env.GUARDIAO_API_KEY || 'dev-123',
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
  HELMET_ENABLED: String(process.env.HELMET_ENABLED || 'true').toLowerCase() === 'true',
  MAX_JSON_SIZE: process.env.MAX_JSON_SIZE || '1mb',
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  PRETTY_LOGS: String(process.env.PRETTY_LOGS || 'true').toLowerCase() === 'true',
  RATE_LIMIT_POINTS: Number(process.env.RATE_LIMIT_POINTS || 60),
  RATE_LIMIT_DURATION: Number(process.env.RATE_LIMIT_DURATION || 60),
  SCORE_HIGH_MIN: Number(process.env.SCORE_HIGH_MIN || 80),
  SCORE_MEDIUM_MIN: Number(process.env.SCORE_MEDIUM_MIN || 50),
  SAFE_BROWSING_KEY: process.env.SAFE_BROWSING_KEY || '',
  OPENPHISH_FEED_URL: process.env.OPENPHISH_FEED_URL || ''
};

// ==== Logger ====
const logger = pino({
  level: env.LOG_LEVEL,
  transport: env.PRETTY_LOGS ? { target: 'pino-pretty', options: { colorize: true } } : undefined
});

// ==== App base ====
const app = express();
if (env.HELMET_ENABLED) app.use(helmet());
app.use(cors({ origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN }));
app.use(express.json({ limit: env.MAX_JSON_SIZE }));
app.use(pinoHttp({ logger }));

// ==== Proteções /v1/* ====
const limiter = new RateLimiterMemory({ points: env.RATE_LIMIT_POINTS, duration: env.RATE_LIMIT_DURATION });
const rateLimit = (req, res, next) =>
  limiter.consume(req.ip || 'global').then(() => next()).catch(() => res.status(429).json({ error: 'too_many_requests' }));

const apiKey = (req, res, next) => {
  const key = req.header('x-api-key');
  if (!key || key !== env.API_KEY) return res.status(401).json({ error: 'unauthorized' });
  next();
};

// ==== Prisma (MySQL) ====
const prisma = new PrismaClient();
prisma.$connect().then(() => logger.info('[prisma] conectado')).catch(err => logger.error({ err }, '[prisma] falha ao conectar'));

// ==== Utilidades / Heurísticas ====
// normalização simples de URL (remove tracking e padroniza host)
function normalizeUrl(input) {
  try {
    const u = new URL(String(input).trim());
    u.hash = '';
    ['utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','fbclid'].forEach(p => u.searchParams.delete(p));
    u.hostname = u.hostname.toLowerCase();
    return u.toString();
  } catch {
    return null;
  }
}

const SUSPICIOUS_KEYWORDS = ['pix','premio','brinde','ganhou','suporte','senha','bloqueio','liberar','cartão','banco','itau','nubank','correios','receita','fgts'];
const SHORTENERS = ['bit.ly','tinyurl.com','t.co','is.gd','goo.gl','cutt.ly','ow.ly','rebrand.ly'];

function heuristicScore(urlObj) {
  let score = 0;
  const reasons = [];
  const host = urlObj.hostname.toLowerCase();

  if (SHORTENERS.some(s => host.endsWith(s))) { score += 25; reasons.push('url_shortener'); }
  const dots = host.split('.').length - 1;
  if (dots >= 3) { score += 10; reasons.push('many_subdomains'); }
  if (/\.(top|xyz|click|link|fit|rest|gq|ml|cf|tk)$/i.test(host)) { score += 15; reasons.push('uncommon_tld'); }
  const full = urlObj.toString().toLowerCase();
  if (SUSPICIOUS_KEYWORDS.some(k => full.includes(k))) { score += 20; reasons.push('suspicious_keywords'); }
  if (urlObj.protocol === 'http:') { score += 10; reasons.push('no_https'); }

  score = Math.max(0, Math.min(100, score));
  return { score, reasons };
}

function severityFromScore(score, minMed = env.SCORE_MEDIUM_MIN, minHigh = env.SCORE_HIGH_MIN) {
  if (score >= minHigh) return 'high';
  if (score >= minMed) return 'medium';
  return 'low';
}

// ==== Integrações externas (stubs seguros no MVP) ====
async function checkSafeBrowsing(url) {
  if (!env.SAFE_BROWSING_KEY) return { hit: false, source: 'safe_browsing:stub' };
  try {
    const body = {
      client: { clientId: "guardiao60", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    const resp = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${env.SAFE_BROWSING_KEY}`,
      body, { timeout: 4000 }
    );
    const hit = !!(resp.data && resp.data.matches && resp.data.matches.length);
    return { hit, source: 'safe_browsing' };
  } catch {
    return { hit: false, source: 'safe_browsing:error' };
  }
}

async function checkOpenPhish(url) {
  if (!env.OPENPHISH_FEED_URL) return { hit: false, source: 'openphish:stub' };
  try {
    const resp = await axios.get(env.OPENPHISH_FEED_URL, { timeout: 4000 });
    const hit = typeof resp.data === 'string' && resp.data.includes(url);
    return { hit, source: 'openphish' };
  } catch {
    return { hit: false, source: 'openphish:error' };
  }
}

// ==== Rotas públicas ====
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ==== LINKS ====
// POST /v1/links/check { url } → { url,isSafe,score,severity,reasons[],sources[] }
app.post('/v1/links/check', rateLimit, apiKey, async (req, res) => {
  const norm = normalizeUrl(req.body?.url || '');
  if (!norm) return res.status(400).json({ error: 'invalid_url' });

  const u = new URL(norm);
  const local = heuristicScore(u);
  const ext1 = await checkSafeBrowsing(norm);
  const ext2 = await checkOpenPhish(norm);

  let score = local.score;
  const reasons = [...local.reasons];
  const sources = ['local'];

  if (ext1.hit) { score = Math.max(score, 90); reasons.push('safe_browsing_match'); sources.push(ext1.source); }
  if (ext2.hit) { score = Math.max(score, 95); reasons.push('openphish_match'); sources.push(ext2.source); }

  const severity = severityFromScore(score);
  const isSafe = severity === 'low';

  const saved = await prisma.linkCheck.create({
    data: { url: norm, isSafe, score, reasons, sources }
  });

  if (!isSafe) {
    await prisma.alert.create({
      data: {
        type: 'LINK_SUSPECT',
        url: norm,
        description: 'Link com indícios de phishing',
        severity,
        score,
        status: 'new'
      }
    });
  }

  res.json({ url: norm, isSafe, score, severity, reasons, sources, savedId: saved.id });
});

// ==== REPORTS ====
// POST /v1/reports → { url?, description?, reporterHash?, evidence?[] } → { id,... }
app.post('/v1/reports', rateLimit, apiKey, async (req, res) => {
  const { url, description, reporterHash, evidence } = req.body || {};
  let norm = null;
  let severity = 'low';
  let score = 0;

  if (url) {
    norm = normalizeUrl(url);
    if (!norm) return res.status(400).json({ error: 'invalid_url' });

    const u = new URL(norm);
    const local = heuristicScore(u);
    const ext1 = await checkSafeBrowsing(norm);
    const ext2 = await checkOpenPhish(norm);

    score = local.score;
    if (ext1.hit) score = Math.max(score, 90);
    if (ext2.hit) score = Math.max(score, 95);
    severity = severityFromScore(score);
  }

  const saved = await prisma.report.create({
    data: {
      url: norm,
      description: description || null,
      reporterHash: reporterHash || null,
      evidence: Array.isArray(evidence) ? evidence : null
    }
  });

  const riskyText = (description || '').toLowerCase();
  const textSuggestsRisk = ['pix','senha','cobrança','bloqueio','link','golpe','phishing']
    .some(k => riskyText.includes(k));

  if ((norm && (severity === 'medium' || severity === 'high')) || textSuggestsRisk) {
    await prisma.alert.create({
      data: {
        type: 'REPORT_SUSPECT',
        url: norm,
        description: description || 'Denúncia recebida',
        severity: norm ? severity : 'medium',
        score: norm ? score : null,
        status: 'new'
      }
    });
  }

  res.json(saved);
});

// GET /v1/reports/:id
app.get('/v1/reports/:id', rateLimit, apiKey, async (req, res) => {
  const id = Number(req.params.id);
  const report = await prisma.report.findUnique({ where: { id } });
  if (!report) return res.status(404).json({ error: 'not_found' });
  res.json(report);
});

// ==== ALERTS ====
// GET /v1/alerts?status=new|ack
app.get('/v1/alerts', rateLimit, apiKey, async (req, res) => {
  const status = req.query.status === 'ack' ? 'ack' : 'new';
  const items = await prisma.alert.findMany({
    where: { status },
    orderBy: { createdAt: 'desc' }
  });
  res.json(items);
});

// PATCH /v1/alerts/:id/ack
app.patch('/v1/alerts/:id/ack', rateLimit, apiKey, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const updated = await prisma.alert.update({
      where: { id },
      data: { status: 'ack', ackAt: new Date() }
    });
    res.json(updated);
  } catch {
    res.status(404).json({ error: 'not_found' });
  }
});

// 404 + erros
app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
app.use((err, _req, res, _next) => {
  logger.error(err);
  res.status(500).json({ error: 'internal_error' });
});

// Start
app.listen(env.PORT, () => {
  console.log(`[server] Guardião60+ em http://localhost:${env.PORT}`);
});
