const crypto = require("crypto");

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`];
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

module.exports = async (req, res) => {
  try {
    if (req.method !== "GET") return json(res, 405, { error: "method_not_allowed" });

    const host = req.headers.host || "";
    const isHttps = true; // Vercel is https
    const clientId = process.env.DISCORD_CLIENT_ID;
    const redirectUri = process.env.DISCORD_REDIRECT_URI;

    if (!clientId || !redirectUri) return json(res, 500, { error: "missing_discord_env" });

    const u = new URL(req.url, `https://${host}`);
    const returnTo = u.searchParams.get("returnTo") || "/owner";

    const state = crypto.randomBytes(24).toString("hex");
    // store state + returnTo in cookies
    setCookie(res, "kc_state", state, { path: "/", httpOnly: true, sameSite: "Lax", secure: isHttps, maxAge: 10 * 60 });
    setCookie(res, "kc_return", encodeURIComponent(returnTo), { path: "/", httpOnly: true, sameSite: "Lax", secure: isHttps, maxAge: 10 * 60 });

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "identify",
      state
    });

    const authUrl = `https://discord.com/api/oauth2/authorize?${params.toString()}`;
    return json(res, 200, { url: authUrl });
  } catch (e) {
    return json(res, 500, { error: "server_error" });
  }
};
