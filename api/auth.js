import crypto from "node:crypto";

const PRE_COOKIE = "manager_pre_auth";
const SESSION_COOKIE = "manager_session";
const SESSION_MAX_AGE = 60 * 60 * 12;
const PRE_MAX_AGE = 60 * 10;

function env(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      ...extraHeaders
    }
  });
}

function token(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", env("AUTH_SIGNING_SECRET"))
    .update(encoded)
    .digest("base64url");
  return `${encoded}.${signature}`;
}

function verify(value) {
  if (!value || !value.includes(".")) return null;
  try {
    const [encoded, signature] = value.split(".");
    const expected = crypto.createHmac("sha256", env("AUTH_SIGNING_SECRET"))
      .update(encoded)
      .digest("base64url");
    if (signature.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    return payload.exp > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

function getCookies(request) {
  const raw = request.headers.get("cookie") || "";
  const result = {};
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const key = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    result[key] = decodeURIComponent(value);
  }
  return result;
}

function makeCookie(name, value, maxAge, secure) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

function deleteCookie(name, secure) {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

function isSecure(request) {
  return new URL(request.url).protocol === "https:";
}

function responseWithCookies(data, status, cookies) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
  });
  for (const value of cookies) headers.append("Set-Cookie", value);
  return new Response(JSON.stringify(data), { status, headers });
}

export function requireAdmin(request) {
  const cookies = getCookies(request);
  const session = verify(cookies[SESSION_COOKIE]);
  return !!session && session.type === "session";
}

export async function GET(request) {
  try {
    const cookies = getCookies(request);
    return json({
      authenticated: !!verify(cookies[SESSION_COOKIE]),
      preAuthenticated: !!verify(cookies[PRE_COOKIE])
    });
  } catch (error) {
    return json({ authenticated: false, preAuthenticated: false, error: error.message }, 500);
  }
}

export async function POST(request) {
  try {
    const body = await request.json();
    const secure = isSecure(request);

    if (body.action === "secret") {
      if (body.code !== env("ADMIN_SECRET")) {
        return json({ error: "Incorrect secret code." }, 401);
      }
      const preToken = token({ type: "pre", exp: Date.now() + PRE_MAX_AGE * 1000 });
      return responseWithCookies({ ok: true }, 200, [makeCookie(PRE_COOKIE, preToken, PRE_MAX_AGE, secure)]);
    }

    if (body.action === "login") {
      const cookies = getCookies(request);
      if (!verify(cookies[PRE_COOKIE])) {
        return json({ error: "Security verification required." }, 403);
      }
      if (body.user !== env("ADMIN_USER") || body.pass !== env("ADMIN_PASS")) {
        return json({ error: "Invalid username or password." }, 401);
      }
      const sessionToken = token({ type: "session", exp: Date.now() + SESSION_MAX_AGE * 1000 });
      return responseWithCookies({ ok: true }, 200, [
        makeCookie(SESSION_COOKIE, sessionToken, SESSION_MAX_AGE, secure),
        deleteCookie(PRE_COOKIE, secure)
      ]);
    }

    if (body.action === "logout") {
      return responseWithCookies({ ok: true }, 200, [
        deleteCookie(SESSION_COOKIE, secure),
        deleteCookie(PRE_COOKIE, secure)
      ]);
    }

    return json({ error: "Unknown action" }, 400);
  } catch (error) {
    return json({ error: error.message || "Server error" }, 500);
  }
}
