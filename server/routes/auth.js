import express from "express";
import { db, now, audit } from "../db.js";
import {
  login,
  logout,
  loginRateLimit,
  requireAuth,
  requireCsrf,
  publicUser,
  createApiToken,
} from "../auth.js";
import { verifyPassword, hashPassword } from "../crypto.js";

const router = express.Router();

router.post("/login", loginRateLimit, login);
router.post("/logout", requireAuth, requireCsrf, logout);

router.get("/me", requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user), csrf: req.auth.csrf || null });
});

router.post("/password", requireAuth, requireCsrf, (req, res) => {
  const current = String(req.body?.current || "");
  const next = String(req.body?.next || "");
  if (next.length < 12) return res.status(400).json({ error: "password must be at least 12 characters" });
  const row = db.prepare("SELECT password_hash FROM users WHERE id = ?").get(req.user.id);
  if (!verifyPassword(current, row.password_hash)) return res.status(400).json({ error: "current password is wrong" });
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hashPassword(next), req.user.id);
  db.prepare("DELETE FROM sessions WHERE user_id = ? AND id != ?").run(req.user.id, req.auth.session_id || "");
  audit(req.user.id, "auth.password", "user", req.user.id, req.ip);
  res.json({ ok: true });
});

router.get("/tokens", requireAuth, (req, res) => {
  res.json(
    db.prepare("SELECT id, name, scopes_json, last_used, created_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id)
      .map((t) => ({ ...t, scopes: JSON.parse(t.scopes_json) })),
  );
});

router.post("/tokens", requireAuth, requireCsrf, (req, res) => {
  const name = String(req.body?.name || "API token").slice(0, 80);
  const scopes = Array.isArray(req.body?.scopes) ? req.body.scopes.filter((s) => ["read", "write"].includes(s)) : ["read"];
  const token = createApiToken(req.user.id, name, scopes);
  audit(req.user.id, "token.create", "api_token", null, req.ip, { name, scopes });
  res.json({ token, name, scopes });
});

router.delete("/tokens/:id", requireAuth, requireCsrf, (req, res) => {
  db.prepare("DELETE FROM api_tokens WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
  res.json({ ok: true });
});

export default router;
