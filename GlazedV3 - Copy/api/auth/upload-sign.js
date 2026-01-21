const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  return createClient(url, key, { auth: { persistSession: false } });
}

function parseCookies(req) {
  const raw = req.headers.cookie || "";
  const out = {};
  raw.split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function b64urlToBuf(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function verify(token, secret) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts;
  const data = `${h}.${p}`;
  const expected = crypto.createHmac("sha256", secret).update(data).digest();
  const actual = b64urlToBuf(sig);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return null;
  const payload = JSON.parse(b64urlToBuf(p).toString("utf8"));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp) return null;
  return payload;
}

function requireOwner(req, res) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) { json(res, 500, { error: "missing_session_secret" }); return null; }
  const cookies = parseCookies(req);
  const payload = verify(cookies.kc_owner, secret);
  if (!payload) { json(res, 401, { error: "unauthorized" }); return null; }
  const ownerIds = (process.env.DISCORD_OWNER_IDS || "").split(",").map(s => s.trim()).filter(Boolean);
  if (!ownerIds.includes(payload.sub)) { json(res, 403, { error: "forbidden" }); return null; }
  return payload;
}

module.exports = async (req, res) => {
  try {
    if (req.method !== "POST") return json(res, 405, { error: "method_not_allowed" });
    if (!requireOwner(req, res)) return;

    const supabase = getSupabase();
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      let payload;
      try { payload = JSON.parse(body || "{}"); }
      catch { return json(res, 400, { error: "bad_json" }); }

      const original = String(payload.file_name || "").trim();
      if (!original) return json(res, 400, { error: "missing_file_name" });

      const stamp = Date.now();
      const safe = original.replace(/[^a-zA-Z0-9._-]/g, "_");
      const path = `${stamp}_${safe}`;

      const { data, error } = await supabase.storage.from("mods").createSignedUploadUrl(path);
      if (error) return json(res, 500, { error: "sign_error", details: error.message });

      const publicUrl = `${process.env.SUPABASE_URL}/storage/v1/object/public/mods/${encodeURIComponent(path)}`;

      return json(res, 200, {
        path,
        signed_url: data.signedUrl,
        token: data.token,
        public_url: publicUrl
      });
    });
  } catch (e) {
    return json(res, 500, { error: "server_error", details: String(e.message || e) });
  }
};
