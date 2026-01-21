const crypto = require("crypto");

function parseCookies(req) {
  const raw = req.headers.cookie || "";
  const out = {};
  raw.split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
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

module.exports = async (req, res) => {
  try {
    if (req.method !== "GET") return json(res, 405, { error: "method_not_allowed" });
    const secret = process.env.SESSION_SECRET;
    if (!secret) return json(res, 200, { authenticated: false });

    const cookies = parseCookies(req);
    const token = cookies.kc_owner;
    const payload = verify(token, secret);
    if (!payload) return json(res, 200, { authenticated: false });

    return json(res, 200, {
      authenticated: true,
      user: { id: payload.sub, username: payload.username, avatar: payload.avatar || null }
    });
  } catch {
    return json(res, 200, { authenticated: false });
  }
};
