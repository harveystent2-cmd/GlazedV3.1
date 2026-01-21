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
  const isHttps = true;
  if (req.method !== "POST") return json(res, 405, { error: "method_not_allowed" });
  setCookie(res, "kc_owner", "", { path: "/", httpOnly: true, sameSite: "Lax", secure: isHttps, maxAge: 0 });
  return json(res, 200, { ok: true });
};
