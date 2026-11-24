import express from "express";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { db, now, audit, setting, setSetting } from "../db.js";
import { requireRole } from "../auth.js";
import { hashPassword, verifyPassword } from "../crypto.js";
import { llmConfig, saveLLMConfig, testProfile, llmStats } from "../llm.js";
import { publicEngines } from "../engines/index.js";
import { DATA_DIR, VERSION } from "../config.js";

const router = express.Router();

router.get("/settings", (req, res) => {
  res.json({
    llm: llmConfig(),
    general: {
      licensePolicy: setting("licensePolicy", { deny: ["AGPL-3.0", "GPL-3.0", "SSPL-1.0"], allow: [] }),
      defaults: {
        fuzzIterations: setting("defaults.fuzzIterations", 220),
        requireApproval: setting("defaults.requireApproval", false),
      },
      version: VERSION,
    },
  });
});

router.put("/settings/llm", requireRole("admin"), (req, res) => {
  const cfg = saveLLMConfig(req.body || {});
  audit(req.user.id, "settings.llm", "settings", "llm", req.ip, { enabled: cfg.enabled, profiles: cfg.profiles.length });
  res.json(cfg);
});

router.post("/settings/llm/test", requireRole("admin"), async (req, res) => {
  try {
    const result = await testProfile(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.put("/settings/general", requireRole("admin"), (req, res) => {
  if (req.body?.licensePolicy) {
    setSetting("licensePolicy", {
      deny: Array.isArray(req.body.licensePolicy.deny) ? req.body.licensePolicy.deny.slice(0, 50) : [],
      allow: Array.isArray(req.body.licensePolicy.allow) ? req.body.licensePolicy.allow.slice(0, 50) : [],
    });
  }
  if (req.body?.defaults) {
    if (req.body.defaults.fuzzIterations) setSetting("defaults.fuzzIterations", Math.max(20, Math.min(3000, Number(req.body.defaults.fuzzIterations))));
    if (typeof req.body.defaults.requireApproval === "boolean") setSetting("defaults.requireApproval", req.body.defaults.requireApproval);
  }
  audit(req.user.id, "settings.general", "settings", "general", req.ip);
  res.json({ ok: true });
});

router.get("/engines", (req, res) => {
  res.json(publicEngines());
});

router.get("/users", (req, res) => {
  res.json(
    db.prepare("SELECT id, email, name, role, created_at, last_login FROM users ORDER BY created_at").all(),
  );
});

router.post("/users", requireRole("admin"), (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const name = String(req.body?.name || "").trim().slice(0, 120);
  const role = ["admin", "analyst", "viewer"].includes(req.body?.role) ? req.body.role : "viewer";
  const password = String(req.body?.password || "");
  if (!email.includes("@") || name.length < 2 || password.length < 12) {
    return res.status(400).json({ error: "valid email, name and 12+ char password required" });
  }
  if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(email)) return res.status(409).json({ error: "email exists" });
  const id = crypto.randomUUID();
  db.prepare("INSERT INTO users(id, email, name, password_hash, role, created_at) VALUES(?, ?, ?, ?, ?, ?)").run(
    id, email, name, hashPassword(password), role, now(),
  );
  const workspace = db.prepare("SELECT id FROM workspaces LIMIT 1").get();
  if (workspace) db.prepare("INSERT OR IGNORE INTO workspace_members(workspace_id, user_id, role) VALUES(?, ?, ?)").run(workspace.id, id, role);
  audit(req.user.id, "user.create", "user", id, req.ip, { email, role });
  res.status(201).json({ id });
});

router.patch("/users/:id", requireRole("admin"), (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "user not found" });
  if (req.body?.role && ["admin", "analyst", "viewer"].includes(req.body.role)) {
    db.prepare("UPDATE users SET role = ? WHERE id = ?").run(req.body.role, user.id);
  }
  if (req.body?.name) db.prepare("UPDATE users SET name = ? WHERE id = ?").run(String(req.body.name).slice(0, 120), user.id);
  if (req.body?.password && String(req.body.password).length >= 12) {
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hashPassword(String(req.body.password)), user.id);
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(user.id);
  }
  audit(req.user.id, "user.update", "user", user.id, req.ip, req.body);
  res.json({ ok: true });
});

router.delete("/users/:id", requireRole("admin"), (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "cannot delete yourself" });
  db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
  audit(req.user.id, "user.delete", "user", req.params.id, req.ip);
  res.json({ ok: true });
});

router.get("/audit", requireRole("admin"), (req, res) => {
  const rows = db
    .prepare(
      `SELECT a.*, u.email FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
       ORDER BY a.created_at DESC LIMIT 300`,
    )
    .all();
  res.json(rows);
});

router.get("/stats", (req, res) => {
  const counts = {};
  for (const table of ["scans", "findings", "assets", "projects", "users", "plugins"]) {
    counts[table] = db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
  }
  let dbSize = 0;
  try {
    dbSize = fs.statSync(path.join(DATA_DIR, "kestrel.db")).size;
  } catch {
    /* ignore */
  }
  res.json({ counts, dbSize, llm: llmStats(), version: VERSION });
});

router.get("/search", (req, res) => {
  const q = `%${String(req.query.q || "")}%`;
  if (String(req.query.q || "").length < 2) return res.json({ scans: [], findings: [], projects: [] });
  const workspaceIds = db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ?").all(req.user.id).map((r) => r.workspace_id);
  if (!workspaceIds.length) return res.json({ scans: [], findings: [], projects: [] });
  const ph = workspaceIds.map(() => "?").join(",");
  res.json({
    scans: db.prepare(`SELECT id, name, target FROM scans WHERE workspace_id IN (${ph}) AND (name LIKE ? OR target LIKE ?) LIMIT 8`).all(...workspaceIds, q, q),
    findings: db
      .prepare(`SELECT f.id, f.title, f.severity, f.scan_id FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.workspace_id IN (${ph}) AND f.title LIKE ? LIMIT 8`)
      .all(...workspaceIds, q),
    projects: db.prepare(`SELECT p.id, p.name FROM projects p WHERE p.workspace_id IN (${ph}) AND p.name LIKE ? LIMIT 8`).all(...workspaceIds, q),
  });
});

export default router;
