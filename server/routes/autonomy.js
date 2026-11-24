import express from "express";
import crypto from "node:crypto";
import { z } from "zod";
import { db, now, audit } from "../db.js";
import { requireRole } from "../auth.js";
import { randomToken, sha256 } from "../crypto.js";
import {
  approveGoal, autonomyStats, createGoal, decide, getGoal, getPolicy, listGoals, rejectGoal, savePolicy, startGoal,
} from "../autonomy.js";
import { TARGET_TYPES } from "../config.js";

const router = express.Router();

function workspaces(userId) {
  return db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ?").all(userId).map((r) => r.workspace_id);
}

const goalSchema = z.object({
  title: z.string().max(160).optional(),
  objective: z.string().min(8).max(8000),
  target: z.string().min(1).max(2000),
  targetType: z.enum(TARGET_TYPES),
  projectId: z.string().uuid().nullable().optional(),
  workspaceId: z.string().uuid().optional(),
  autonomyLevel: z.enum(["observe", "propose", "supervised", "autonomous"]).optional(),
  maxRequests: z.number().int().positive().optional(),
  maxCost: z.number().nonnegative().optional(),
});

router.get("/autonomy/policy", (req, res) => {
  const ws = workspaces(req.user.id);
  if (!ws.length) return res.status(400).json({ error: "no workspace" });
  res.json(getPolicy(ws[0]));
});

router.put("/autonomy/policy", requireRole("admin"), (req, res) => {
  const ws = workspaces(req.user.id);
  if (!ws.length) return res.status(400).json({ error: "no workspace" });
  const policy = savePolicy(ws[0], req.body || {});
  audit(req.user.id, "autonomy.policy", "policy", ws[0], req.ip, policy);
  res.json(policy);
});

router.get("/autonomy/stats", (req, res) => {
  res.json(autonomyStats(workspaces(req.user.id)));
});

router.get("/goals", (req, res) => {
  res.json(listGoals(workspaces(req.user.id)));
});

router.post("/goals", requireRole("admin", "analyst"), async (req, res) => {
  if (req.auth?.via === "agent" && !req.auth.scopes.includes("goals")) {
    return res.status(403).json({ error: "agent token lacks goals scope" });
  }
  const parsed = goalSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  try {
    const goal = await createGoal(
      { ...parsed.data, workspaceId: parsed.data.workspaceId || workspaces(req.user.id)[0] },
      req.auth.via === "agent" ? `agent:${req.user.name}` : `human:${req.user.email}`,
      req.user.id,
    );
    audit(req.user.id, "goal.create", "goal", goal.id, req.ip, { targetType: goal.target_type });
    res.status(201).json(goal);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get("/goals/:id", (req, res) => {
  const goal = getGoal(req.params.id);
  if (!goal || !workspaces(req.user.id).includes(goal.workspace_id)) return res.status(404).json({ error: "goal not found" });
  res.json(goal);
});

router.post("/goals/:id/approve", requireRole("admin", "analyst"), async (req, res) => {
  try {
    const goal = await approveGoal(req.params.id, req.auth.via === "agent" ? `agent:${req.user.name}` : `human:${req.user.email}`);
    res.json(goal);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post("/goals/:id/reject", requireRole("admin", "analyst"), (req, res) => {
  try {
    res.json(rejectGoal(req.params.id, `human:${req.user.email}`, String(req.body?.reason || "")));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post("/goals/:id/start", requireRole("admin", "analyst"), async (req, res) => {
  try {
    res.json(await startGoal(req.params.id, `human:${req.user.email}`));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post("/goals/:id/decisions", requireRole("admin", "analyst"), (req, res) => {
  const goal = getGoal(req.params.id);
  if (!goal) return res.status(404).json({ error: "goal not found" });
  const id = decide(
    goal.id,
    goal.scan_id,
    req.auth.via === "agent" ? `agent:${req.user.name}` : `human:${req.user.email}`,
    String(req.body?.kind || "note"),
    String(req.body?.rationale || ""),
    String(req.body?.confidence || "medium"),
    req.body?.data || {},
  );
  res.status(201).json({ id });
});

router.get("/decisions", (req, res) => {
  const ws = workspaces(req.user.id);
  if (!ws.length) return res.json([]);
  const ph = ws.map(() => "?").join(",");
  res.json(
    db
      .prepare(
        `SELECT d.*, g.title AS goal_title FROM decisions d JOIN goals g ON g.id = d.goal_id
         WHERE g.workspace_id IN (${ph}) ORDER BY d.created_at DESC LIMIT 200`,
      )
      .all(...ws),
  );
});

router.get("/webhooks", (req, res) => {
  const ws = workspaces(req.user.id);
  if (!ws.length) return res.json([]);
  const ph = ws.map(() => "?").join(",");
  res.json(
    db.prepare(`SELECT id, url, events_json, enabled, last_status, last_fired, created_at FROM webhooks WHERE workspace_id IN (${ph})`).all(...ws)
      .map((h) => ({ ...h, events: JSON.parse(h.events_json) })),
  );
});

router.post("/webhooks", requireRole("admin"), (req, res) => {
  const url = String(req.body?.url || "");
  if (!/^https?:\/\//.test(url)) return res.status(400).json({ error: "http(s) URL required" });
  const ws = workspaces(req.user.id)[0];
  const id = crypto.randomUUID();
  const secret = randomToken(24);
  db.prepare("INSERT INTO webhooks(id, workspace_id, url, events_json, secret, created_at) VALUES(?, ?, ?, ?, ?, ?)").run(
    id, ws, url, JSON.stringify(req.body?.events || ["*"]), secret, now(),
  );
  res.status(201).json({ id, secret });
});

router.patch("/webhooks/:id", requireRole("admin"), (req, res) => {
  db.prepare("UPDATE webhooks SET enabled = ? WHERE id = ?").run(req.body?.enabled ? 1 : 0, req.params.id);
  res.json({ ok: true });
});

router.delete("/webhooks/:id", requireRole("admin"), (req, res) => {
  db.prepare("DELETE FROM webhooks WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

router.get("/agent-identities", (req, res) => {
  res.json(db.prepare("SELECT id, name, kind, description, scopes_json, enabled, created_at, last_seen FROM agent_identities ORDER BY created_at DESC").all());
});

router.post("/agent-identities", requireRole("admin"), (req, res) => {
  const name = String(req.body?.name || "").trim().slice(0, 80);
  if (!name) return res.status(400).json({ error: "name required" });
  const token = `kag_${randomToken(32)}`;
  const id = crypto.randomUUID();
  db.prepare("INSERT INTO users(id, email, name, password_hash, role, created_at) VALUES(?, ?, ?, '!', 'analyst', ?)").run(
    id, `${id}@agent.local`, name, now(),
  );
  db.prepare(
    "INSERT INTO agent_identities(id, name, kind, description, token_hash, scopes_json, created_at) VALUES(?, ?, 'agent', ?, ?, ?, ?)",
  ).run(id, name, String(req.body?.description || "").slice(0, 500), sha256(token), JSON.stringify(req.body?.scopes || ["read", "write", "goals"]), now());
  const ws = workspaces(req.user.id)[0];
  if (ws) db.prepare("INSERT OR IGNORE INTO workspace_members(workspace_id, user_id, role) VALUES(?, ?, 'analyst')").run(ws, id);
  res.status(201).json({ id, token });
});

router.delete("/agent-identities/:id", requireRole("admin"), (req, res) => {
  db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
  db.prepare("DELETE FROM agent_identities WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

export default router;
