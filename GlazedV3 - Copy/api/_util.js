const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

function getEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader("Location", location);
  res.end();
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function setCookie(res, name, value, opts = {}) {
  const parts = [];
  parts.push(`${name}=${encodeURIComponent(value)}`);
  parts.push(`Path=/`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  parts.push("Secure");
  parts.push("SameSite=Lax");
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  setCookie(res, name, "", { maxAge: 0 });
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function b64urlJson(obj) {
  return b64url(JSON.stringify(obj));
}
function fromB64url(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64").toString("utf8");
}

function signSession(payload) {
  const secret = getEnv("SESSION_SECRET");
  const body = b64urlJson(payload);
  const sig = crypto.createHmac("sha256", secret).update(body).digest();
  return `${body}.${b64url(sig)}`;
}

function verifySession(token) {
  try {
    const secret = getEnv("SESSION_SECRET");
    const [body, sig] = String(token || "").split(".");
    if (!body || !sig) return null;

    const expected = crypto.createHmac("sha256", secret).update(body).digest();
    const expectedB64 = b64url(expected);
    if (sig !== expectedB64) return null;

    const payload = JSON.parse(fromB64url(body));
    if (!payload || !payload.sub || !payload.exp) return null;
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function isOwner(discordId) {
  const raw = process.env.OWNER_DISCORD_IDS || "";
  const list = raw.split(",").map(s => s.trim()).filter(Boolean);
  return list.includes(String(discordId));
}

function requireOwner(req, res) {
  const cookies = parseCookies(req);
  const sess = verifySession(cookies.krystal_session);
  if (!sess) {
    json(res, 401, { error: "not_authenticated" });
    return null;
  }
  if (!isOwner(sess.sub)) {
    json(res, 403, { error: "not_owner" });
    return null;
  }
  return sess;
}

function getBaseUrl(req) {
  // Always prefer BASE_URL for stable OAuth redirect.
  const base = process.env.BASE_URL;
  if (base) return base.replace(/\/+$/, "");
  const proto = (req.headers["x-forwarded-proto"] || "https").toString();
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

function getSupabase() {
  const url = getEnv("SUPABASE_URL");
  const key = getEnv("SUPABASE_SERVICE_ROLE_KEY");
  return createClient(url, key, { auth: { persistSession: false } });
}

module.exports = {
  json, redirect,
  parseCookies, setCookie, clearCookie,
  signSession, verifySession,
  requireOwner, isOwner,
  getBaseUrl,
  getSupabase
};
