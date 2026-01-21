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

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`];
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader("Location", location);
  res.end();
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function signSession(payloadObj, secret) {
  const payload = Buffer.from(JSON.stringify(payloadObj));
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const h = b64url(header);
  const p = b64url(payload);
  const data = `${h}.${p}`;
  const sig = crypto.createHmac("sha256", secret).update(data).digest();
  return `${data}.${b64url(sig)}`;
}

module.exports = async (req, res) => {
  const host = req.headers.host || "";
  const isHttps = true;

  try {
    const clientId = process.env.DISCORD_CLIENT_ID;
    const clientSecret = process.env.DISCORD_CLIENT_SECRET;
    const redirectUri = process.env.DISCORD_REDIRECT_URI;
    const ownerIds = (process.env.DISCORD_OWNER_IDS || "").split(",").map(s => s.trim()).filter(Boolean);
    const sessionSecret = process.env.SESSION_SECRET;

    if (!clientId || !clientSecret || !redirectUri || !sessionSecret) {
      return redirect(res, "/?auth=server_misconfig");
    }

    const url = new URL(req.url, `https://${host}`);
    const code = url.searchParams.get("code") || "";
    const state = url.searchParams.get("state") || "";

    const cookies = parseCookies(req);
    const expectedState = cookies.kc_state || "";
    const returnTo = cookies.kc_return ? decodeURIComponent(cookies.kc_return) : "/owner";

    // clear state cookies
    setCookie(res, "kc_state", "", { path: "/", httpOnly: true, sameSite: "Lax", secure: isHttps, maxAge: 0 });
    setCookie(res, "kc_return", "", { path: "/", httpOnly: true, sameSite: "Lax", secure: isHttps, maxAge: 0 });

    if (!code || !state || state !== expectedState) {
      return redirect(res, "/?auth=bad_state");
    }

    // exchange code -> token
    const body = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri
    });

    const tokRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const tok = await tokRes.json().catch(() => null);
    if (!tokRes.ok || !tok || !tok.access_token) return redirect(res, "/?auth=token_failed");

    const meRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tok.access_token}` }
    });
    const me = await meRes.json().catch(() => null);
    if (!meRes.ok || !me || !me.id) return redirect(res, "/?auth=me_failed");

    if (!ownerIds.includes(me.id)) {
      return redirect(res, "/?auth=not_owner");
    }

    const now = Math.floor(Date.now() / 1000);
    const session = signSession(
      { sub: me.id, username: me.username, avatar: me.avatar || null, iat: now, exp: now + 60 * 60 * 8 },
      sessionSecret
    );

    setCookie(res, "kc_owner", session, { path: "/", httpOnly: true, sameSite: "Lax", secure: isHttps, maxAge: 60 * 60 * 8 });

    return redirect(res, returnTo || "/owner");
  } catch {
    return redirect(res, "/?auth=server_error");
  }
};
