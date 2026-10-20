require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "15kb" }));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const COOKIE_SECRET = process.env.COOKIE_SECRET || "";
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";

if (ADMIN_PASSWORD.length < 12) {
  console.error("Configure ADMIN_PASSWORD com pelo menos 12 caracteres.");
  process.exit(1);
}
if (COOKIE_SECRET.length < 32) {
  console.error("Configure COOKIE_SECRET com pelo menos 32 caracteres.");
  process.exit(1);
}

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "licenses.db"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE,
    key_preview TEXT NOT NULL,
    duration TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    expires_at INTEGER,
    revoked_at INTEGER
  );
`);

const durations = {
  "1_week": { label: "1 semana (7 dias)", ms: 7 * 24 * 60 * 60 * 1000 },
  "1_month": { label: "1 mês (30 dias)", ms: 30 * 24 * 60 * 60 * 1000 },
  "4_months": { label: "4 meses (120 dias)", ms: 120 * 24 * 60 * 60 * 1000 }
};

const hashKey = key => crypto.createHash("sha256").update(key).digest("hex");
const safeEqual = (a, b) => {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};

function getCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch {}
  }
  return out;
}
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", COOKIE_SECRET).update(body).digest("base64url");
  return `${body}.${signature}`;
}
function verify(token) {
  if (!token || !token.includes(".")) return null;
  const [body, signature] = token.split(".");
  const expected = crypto.createHmac("sha256", COOKIE_SECRET).update(body).digest("base64url");
  if (!safeEqual(signature, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return data.exp > Date.now() ? data : null;
  } catch { return null; }
}
function setCookie(res, name, value, maxAgeSeconds) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${maxAgeSeconds}`
  ];
  if (COOKIE_SECURE) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}
function clearCookie(res, name) {
  const parts = [`${name}=`, "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=0"];
  if (COOKIE_SECURE) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 10,
  standardHeaders: true, legacyHeaders: false
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 30,
  standardHeaders: true, legacyHeaders: false
});

function adminOnly(req, res, next) {
  const session = verify(getCookies(req).tobi_admin);
  if (!session || session.role !== "admin") {
    return res.status(401).json({ error: "Entre na área administrativa." });
  }
  next();
}
function getActiveLicense(req) {
  const session = verify(getCookies(req).tobi_access);
  if (!session || session.role !== "license") return null;
  const row = db.prepare("SELECT * FROM licenses WHERE id = ?").get(session.id);
  if (!row || row.revoked_at || !row.activated_at || !row.expires_at || row.expires_at <= Date.now()) return null;
  return row;
}
function licenseOnly(req, res, next) {
  const license = getActiveLicense(req);
  if (!license) {
    return res.status(401).json({ error: "Sua licença é inválida, expirou ou foi revogada. Entre novamente com uma chave válida." });
  }
  req.license = license;
  next();
}

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "admin.html")));
app.use("/assets", express.static(path.join(__dirname, "assets")));

app.post("/api/admin/login", adminLimiter, (req, res) => {
  const password = req.body?.password;
  if (typeof password !== "string" || !safeEqual(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: "Senha administrativa incorreta." });
  }
  setCookie(res, "tobi_admin", sign({ role: "admin", exp: Date.now() + 8 * 60 * 60 * 1000 }), 8 * 60 * 60);
  res.json({ ok: true });
});
app.post("/api/admin/logout", adminOnly, (req, res) => {
  clearCookie(res, "tobi_admin");
  res.json({ ok: true });
});
app.get("/api/admin/licenses", adminOnly, (req, res) => {
  const rows = db.prepare(
    "SELECT id, key_preview, duration, created_at, activated_at, expires_at, revoked_at FROM licenses ORDER BY id DESC LIMIT 500"
  ).all();
  res.json({
    licenses: rows.map(row => ({
      ...row,
      duration_label: durations[row.duration]?.label || row.duration,
      status: row.revoked_at ? "revogada"
        : !row.activated_at ? "aguardando ativação"
        : row.expires_at <= Date.now() ? "expirada" : "ativa"
    }))
  });
});
app.post("/api/admin/licenses", adminOnly, (req, res) => {
  const duration = req.body?.duration;
  if (!durations[duration]) {
    return res.status(400).json({ error: "Escolha 1 semana, 1 mês ou 4 meses." });
  }
  const createdAt = Date.now();
  const key = `TOBI-${crypto.randomBytes(4).toString("hex").toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
  const result = db.prepare(
    "INSERT INTO licenses (key_hash, key_preview, duration, created_at, activated_at, expires_at) VALUES (?, ?, ?, ?, NULL, NULL)"
  ).run(hashKey(key), `...${key.slice(-4)}`, duration, createdAt);
  // A chave completa é exibida apenas nesta resposta; o banco guarda apenas o hash.
  res.json({
    ok: true,
    license: {
      id: result.lastInsertRowid,
      key,
      duration_label: durations[duration].label,
      created_at: createdAt,
      expires_at: null
    }
  });
});
app.post("/api/admin/licenses/:id/revoke", adminOnly, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "ID inválido." });
  const result = db.prepare(
    "UPDATE licenses SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"
  ).run(Date.now(), id);
  if (!result.changes) return res.status(404).json({ error: "Licença não encontrada ou já revogada." });
  res.json({ ok: true });
});

app.post("/api/login", loginLimiter, (req, res) => {
  const submitted = req.body?.key;
  if (typeof submitted !== "string" || submitted.length < 10 || submitted.length > 100) {
    return res.status(400).json({ error: "Digite uma chave de licença válida." });
  }
  let row = db.prepare("SELECT * FROM licenses WHERE key_hash = ?").get(hashKey(submitted.trim().toUpperCase()));
  if (!row || row.revoked_at) return res.status(401).json({ error: "Chave inválida ou revogada." });

  // A validade começa no primeiro uso. Reentradas não reiniciam a contagem.
  if (!row.activated_at) {
    const now = Date.now();
    const expiresAt = now + durations[row.duration].ms;
    db.prepare(
      "UPDATE licenses SET activated_at = ?, expires_at = ? WHERE id = ? AND activated_at IS NULL"
    ).run(now, expiresAt, row.id);
    row = db.prepare("SELECT * FROM licenses WHERE id = ?").get(row.id);
  }
  if (!row.expires_at || row.expires_at <= Date.now()) {
    return res.status(401).json({ error: "Esta licença expirou." });
  }
  const seconds = Math.max(1, Math.floor((row.expires_at - Date.now()) / 1000));
  setCookie(res, "tobi_access", sign({ role: "license", id: row.id, exp: row.expires_at }), seconds);
  res.json({ ok: true, expires_at: row.expires_at });
});
app.post("/api/logout", (req, res) => {
  clearCookie(res, "tobi_access");
  res.json({ ok: true });
});
app.get("/api/me", licenseOnly, (req, res) => {
  res.json({
    ok: true,
    activated_at: req.license.activated_at,
    expires_at: req.license.expires_at,
    duration: durations[req.license.duration].label
  });
});
app.get("/painel", licenseOnly, (req, res) => res.sendFile(path.join(__dirname, "painel.html")));
app.get("/style.css", licenseOnly, (req, res) => res.sendFile(path.join(__dirname, "style.css")));
app.get("/script.js", licenseOnly, (req, res) => res.sendFile(path.join(__dirname, "script.js")));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Erro interno. Verifique os logs do servidor." });
});
app.listen(PORT, () => console.log(`Tobi Hack rodando na porta ${PORT}`));
