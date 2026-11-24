import crypto from "node:crypto";
import { db, now, audit } from "./db.js";
import { hashPassword, verifyPassword, randomToken, sha256, timingSafeEqual } from "./crypto.js";
import {
  SESSION_HOURS,
  LOGIN_RATE_WINDOW_MS,
  LOGIN_IP_MAX,
  LOGIN_ACCOUNT_MAX,
} from "./config.js";
import { createRateLimiter } from "./lib/ratelimit.js";

const SESSION_COOKIE = "kestrel_session";
const CSRF_COOKIE = "kestrel_csrf";

export function seedAdmin() {
  const count = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
  if (count > 0) return null;
  const email = process.env.KESTREL_ADMIN_EMAIL || "admin@kestrel.local";
  const password = process.env.KESTREL_ADMIN_PASSWORD || crypto.randomBytes(12).toString("base64url");
  const userId = crypto.randomUUID();
  db.prepare(
    "INSERT INTO users(id, email, name, password_hash, role, created_at) VALUES(?, ?, ?, ?, 'admin', ?)",
  ).run(userId, email, "Administrator", hashPassword(password), now());
  const workspaceId = crypto.randomUUID();
  db.prepare("INSERT INTO workspaces(id, name, created_at) VALUES(?, 'Default', ?)").run(
    workspaceId,
    now(),
  );
  db.prepare(
    "INSERT INTO workspace_members(workspace_id, user_id, role) VALUES(?, ?, 'admin')",
  ).run(workspaceId, userId);
  return { email, password };
}

export function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function bearer(req) {
  const header = String(req.headers.authorization || "");
  return header.startsWith("Bearer ") ? header.slice(7) : null;
}

export function authenticate(req) {
  const token = bearer(req);
  if (token) {
    const hash = sha256(token);
    const row = db
      .prepare(
        `SELECT t.id AS token_id, t.scopes_json, u.* FROM api_tokens t
         JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?`,
      )
      .get(hash);
    if (row) {
      db.prepare("UPDATE api_tokens SET last_used = ? WHERE id = ?").run(now(), row.token_id);
      return { user: row, scopes: JSON.parse(row.scopes_json || "[]"), via: "token" };
    }
    const agent = db
      .prepare("SELECT * FROM agent_identities WHERE token_hash = ? AND enabled = 1")
      .get(hash);
    if (agent) {
      db.prepare("UPDATE agent_identities SET last_seen = ? WHERE id = ?").run(now(), agent.id);
      return {
        user: {
          id: agent.id,
          email: `${agent.name.toLowerCase().replace(/\W+/g, ".")}@agent.local`,
          name: agent.name,
          role: "analyst",
          agent: true,
        },
        scopes: JSON.parse(agent.scopes_json || "[]"),
        via: "agent",
      };
    }
    return null;
  }
  const cookies = parseCookies(req);
  const sid = cookies[SESSION_COOKIE];
  if (!sid) return null;
  const row = db
    .prepare(
      `SELECT s.id AS session_id, s.csrf, s.expires_at, u.* FROM sessions s
       JOIN users u ON u.id = s.user_id WHERE s.id = ?`,
    )
    .get(sid);
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare("DELETE FROM sessions WHERE id = ?").run(sid);
    return null;
  }
  return { user: row, csrf: row.csrf, via: "cookie" };
}

export function requireAuth(req, res, next) {
  const auth = authenticate(req);
  if (!auth) return res.status(401).json({ error: "authentication required" });
  req.auth = auth;
  req.user = auth.user;
  next();
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "authentication required" });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "insufficient role" });
    next();
  };
}

export function requireCsrf(req, res, next) {
  if (req.auth?.via === "token" || req.auth?.via === "agent") return next();
  const header = String(req.headers["x-csrf-token"] || "");
  const expected = req.auth?.csrf || "";
  if (!expected || !header || !timingSafeEqual(header, expected)) {
    return res.status(403).json({ error: "csrf validation failed" });
  }
  next();
}

export function createSession(req, res, user) {
  const sid = randomToken(32);
  const csrf = randomToken(24);
  const expires = new Date(Date.now() + SESSION_HOURS * 3600_000);
  db.prepare(
    `INSERT INTO sessions(id, user_id, csrf, ip, user_agent, created_at, expires_at)
     VALUES(?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    sid,
    user.id,
    csrf,
    req.ip || "",
    String(req.headers["user-agent"] || "").slice(0, 300),
    now(),
    expires.toISOString(),
  );
  res.cookie(SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: "lax",
    secure: req.secure,
    expires,
    path: "/",
  });
  res.cookie(CSRF_COOKIE, csrf, {
    httpOnly: false,
    sameSite: "lax",
    secure: req.secure,
    expires,
    path: "/",
  });
  db.prepare("UPDATE users SET last_login = ? WHERE id = ?").run(now(), user.id);
  return csrf;
}

export function destroySession(req, res) {
  const cookies = parseCookies(req);
  if (cookies[SESSION_COOKIE]) {
    db.prepare("DELETE FROM sessions WHERE id = ?").run(cookies[SESSION_COOKIE]);
  }
  const options = { path: "/", sameSite: "lax", secure: req.secure };
  res.clearCookie(SESSION_COOKIE, options);
  res.clearCookie(CSRF_COOKIE, options);
}

// Two independent budgets: one per client IP (stops spraying across many
// accounts) and one per IP + account (stops repeated guessing at one account).
const loginIpLimiter = createRateLimiter({ windowMs: LOGIN_RATE_WINDOW_MS, max: LOGIN_IP_MAX });
const loginAccountLimiter = createRateLimiter({ windowMs: LOGIN_RATE_WINDOW_MS, max: LOGIN_ACCOUNT_MAX });

function loginPairKey(req) {
  const ip = req.ip || "unknown";
  const email = String(req.body?.email || "").trim().toLowerCase().slice(0, 320);
  return email ? `${ip}|${email}` : null;
}

export function loginRateLimit(req, res, next) {
  const ipResult = loginIpLimiter.hit(`ip:${req.ip || "unknown"}`);
  const pair = loginPairKey(req);
  const accountResult = pair ? loginAccountLimiter.hit(`pair:${pair}`) : null;
  const blockedByAccount = accountResult && !accountResult.allowed;
  if (!ipResult.allowed || blockedByAccount) {
    const retryAfterMs = Math.max(
      ipResult.allowed ? 0 : ipResult.retryAfterMs,
      blockedByAccount ? accountResult.retryAfterMs : 0,
    );
    res.setHeader("Retry-After", String(Math.max(1, Math.ceil(retryAfterMs / 1000))));
    return res.status(429).json({ error: "too many login attempts, try again later" });
  }
  next();
}

export function resetLoginAttempts(req) {
  const pair = loginPairKey(req);
  if (pair) loginAccountLimiter.reset(`pair:${pair}`);
}

export function sweepLoginLimiters() {
  loginIpLimiter.sweep();
  loginAccountLimiter.sweep();
}

export function login(req, res) {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  // Bound the input so oversized bodies cannot turn into expensive scrypt work.
  if (!email || email.length > 320 || password.length > 1024) {
    return res.status(400).json({ error: "invalid credentials" });
  }
  const user = db.prepare("SELECT * FROM users WHERE lower(email) = ?").get(email);
  if (!user || !verifyPassword(password, user.password_hash)) {
    audit(null, "auth.login_failed", "user", user?.id || null, req.ip, { email });
    return res.status(401).json({ error: "invalid credentials" });
  }
  resetLoginAttempts(req);
  const csrf = createSession(req, res, user);
  audit(user.id, "auth.login", "user", user.id, req.ip);
  res.json({
    csrf,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
}

export function logout(req, res) {
  if (req.user) audit(req.user.id, "auth.logout", "user", req.user.id, req.ip);
  destroySession(req, res);
  res.json({ ok: true });
}

export function publicUser(user) {
  return user
    ? { id: user.id, email: user.email, name: user.name, role: user.role, created_at: user.created_at }
    : null;
}

export function createApiToken(userId, name, scopes = ["read"]) {
  const token = `kst_${randomToken(32)}`;
  db.prepare(
    "INSERT INTO api_tokens(id, user_id, name, token_hash, scopes_json, created_at) VALUES(?, ?, ?, ?, ?, ?)",
  ).run(crypto.randomUUID(), userId, name, sha256(token), JSON.stringify(scopes), now());
  return token;
}
