import express from "express";
import crypto from "node:crypto";
import fs from "node:fs";
import { z } from "zod";
import { db, now, audit, setting } from "../db.js";
import { normalizeScope } from "../scope.js";
import { enqueue } from "../queue.js";
import { emit, replay, subscribe } from "../events.js";
import { listFindings, scanStats, attackPaths, severityCounts } from "../store.js";
import { createReport } from "../reports.js";
import { requireRole } from "../auth.js";
import { TARGET_TYPES, AGENT_LABELS } from "../config.js";
import { llmStats } from "../llm.js";
import { queueStats } from "../queue.js";
import { autonomyStats } from "../autonomy.js";

const router = express.Router();

const scanSchema = z.object({
  name: z.string().min(1).max(160),
  targetType: z.enum(TARGET_TYPES),
  target: z.string().min(1).max(2000),
  projectId: z.string().uuid().nullable().optional(),
  workspaceId: z.string().uuid().optional(),
  scope: z.any().optional(),
  config: z.any().optional(),
  requireApproval: z.boolean().optional(),
});

function membership(userId, workspaceId) {
  return db.prepare("SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?").get(workspaceId, userId);
}

function loadScan(req, res) {
  const scan = db
    .prepare(
      `SELECT s.* FROM scans s JOIN workspace_members m ON m.workspace_id = s.workspace_id
       WHERE s.id = ? AND m.user_id = ?`,
    )
    .get(req.params.id, req.user.id);
  if (!scan) {
    res.status(404).json({ error: "scan not found" });
    return null;
  }
  return scan;
}

router.get("/scans", (req, res) => {
  const where = ["m.user_id = ?"];
  const params = [req.user.id];
  if (req.query.status) {
    where.push("s.status = ?");
    params.push(String(req.query.status));
  }
  if (req.query.projectId) {
    where.push("s.project_id = ?");
    params.push(String(req.query.projectId));
  }
  if (req.query.q) {
    where.push("(s.name LIKE ? OR s.target LIKE ?)");
    params.push(`%${req.query.q}%`, `%${req.query.q}%`);
  }
  const limit = Math.min(200, Number(req.query.limit || 60));
  const rows = db
    .prepare(
      `SELECT s.*, p.name AS project_name,
       (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.status != 'duplicate') AS findings
       FROM scans s JOIN workspace_members m ON m.workspace_id = s.workspace_id
       LEFT JOIN projects p ON p.id = s.project_id
       WHERE ${where.join(" AND ")} ORDER BY s.created_at DESC LIMIT ?`,
    )
    .all(...params, limit);
  res.json(rows);
});

router.post("/scans", requireRole("admin", "analyst"), (req, res) => {
  const parsed = scanSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  const input = parsed.data;
  const workspaceId =
    input.workspaceId ||
    db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1").get(req.user.id)?.workspace_id;
  if (!workspaceId || !membership(req.user.id, workspaceId)) return res.status(403).json({ error: "no workspace access" });
  let project = null;
  if (input.projectId) {
    project = db.prepare("SELECT * FROM projects WHERE id = ?").get(input.projectId);
    if (!project) return res.status(400).json({ error: "project not found" });
  }
  if (["code", "binary"].includes(input.targetType) && !project) {
    return res.status(400).json({ error: "projectId required for code and binary scans" });
  }
  if (["web", "api"].includes(input.targetType)) {
    try {
      const url = new URL(input.target);
      if (!["http:", "https:"].includes(url.protocol)) throw new Error("http(s) only");
    } catch {
      return res.status(400).json({ error: "target must be an http(s) URL" });
    }
  }
  const scope = normalizeScope(input.scope || {});
  if (["web", "api"].includes(input.targetType) && !scope.allow.length) {
    scope.allow.push({ type: "domain", value: new URL(input.target).hostname });
  }
  const config = {
    engines: [],
    requireApproval: Boolean(input.requireApproval),
    fuzzIterations: Number(setting("defaults.fuzzIterations", 220)),
    labMaxFunctions: 6,
    ...(input.config || {}),
  };
  if (input.requireApproval) config.requireApproval = true;
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO scans(id, project_id, workspace_id, name, target_type, target, scope_json, config_json, status, created_by, created_at)
     VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)`,
  ).run(
    id,
    project?.id || null,
    workspaceId,
    input.name,
    input.targetType,
    input.target,
    JSON.stringify(scope),
    JSON.stringify(config),
    req.user.id,
    now(),
  );
  audit(req.user.id, "scan.create", "scan", id, req.ip, { targetType: input.targetType, target: input.target });
  enqueue("scan.run", { scanId: id }, id);
  res.status(201).json({ id });
});

router.get("/scans/:id", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  const project = scan.project_id ? db.prepare("SELECT id, name FROM projects WHERE id = ?").get(scan.project_id) : null;
  const agents = db.prepare("SELECT * FROM agent_runs WHERE scan_id = ? ORDER BY started_at").all(scan.id);
  const approvals = db.prepare("SELECT * FROM approvals WHERE scan_id = ? ORDER BY requested_at DESC").all(scan.id);
  const fuzz = db.prepare("SELECT * FROM fuzz_runs WHERE scan_id = ? ORDER BY started_at DESC").all(scan.id);
  const reports = db.prepare("SELECT id, format, sha256, hmac, created_at FROM reports WHERE scan_id = ? ORDER BY created_at DESC").all(scan.id);
  const llm = db.prepare("SELECT COUNT(*) AS calls, COALESCE(SUM(cost),0) AS cost, COALESCE(SUM(tokens_in+tokens_out),0) AS tokens FROM llm_calls WHERE scan_id = ? AND status='ok'").get(scan.id);
  res.json({
    ...scan,
    scope: JSON.parse(scan.scope_json),
    config: JSON.parse(scan.config_json),
    project,
    stats: scanStats(scan.id),
    agents,
    approvals,
    fuzz,
    reports,
    llm,
    paths: attackPaths(scan.id),
  });
});

router.post("/scans/:id/start", requireRole("admin", "analyst"), (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  if (!["queued", "failed", "cancelled"].includes(scan.status)) return res.status(400).json({ error: "scan already running" });
  db.prepare("UPDATE scans SET status = 'queued', error = NULL, progress = 0, phase = 'queued' WHERE id = ?").run(scan.id);
  enqueue("scan.run", { scanId: scan.id }, scan.id);
  res.json({ ok: true });
});

router.post("/scans/:id/cancel", requireRole("admin", "analyst"), (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  db.prepare("UPDATE scans SET status = 'cancelled', finished_at = ? WHERE id = ?").run(now(), scan.id);
  emit(scan.id, "scan.cancelling", "Cancellation requested", {}, { agent: "orchestrator", level: "warn" });
  audit(req.user.id, "scan.cancel", "scan", scan.id, req.ip);
  res.json({ ok: true });
});

router.post("/scans/:id/retest", requireRole("admin", "analyst"), (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO scans(id, project_id, workspace_id, name, target_type, target, scope_json, config_json, status, created_by, created_at, parent_scan_id)
     VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)`,
  ).run(
    id,
    scan.project_id,
    scan.workspace_id,
    `${scan.name} · retest`,
    scan.target_type,
    scan.target,
    scan.scope_json,
    scan.config_json,
    req.user.id,
    now(),
    scan.id,
  );
  enqueue("scan.run", { scanId: id }, id);
  audit(req.user.id, "scan.retest", "scan", id, req.ip, { parent: scan.id });
  res.status(201).json({ id });
});

router.delete("/scans/:id", requireRole("admin", "analyst"), (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  db.prepare("DELETE FROM scans WHERE id = ?").run(scan.id);
  audit(req.user.id, "scan.delete", "scan", scan.id, req.ip);
  res.json({ ok: true });
});

router.get("/scans/:id/findings", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  const filters = {
    severity: req.query.severity ? String(req.query.severity).split(",") : undefined,
    status: req.query.status,
    engine: req.query.engine,
    q: req.query.q,
    verified: req.query.verified === "true" ? true : req.query.verified === "false" ? false : undefined,
    limit: req.query.limit,
  };
  res.json(listFindings(scan.id, filters));
});

router.get("/scans/:id/assets", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  res.json(db.prepare("SELECT * FROM assets WHERE scan_id = ? ORDER BY kind, value").all(scan.id));
});

router.get("/scans/:id/graph", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  const assets = db.prepare("SELECT id, kind, value FROM assets WHERE scan_id = ? LIMIT 400").all(scan.id);
  const findings = db
    .prepare("SELECT id, title, severity, asset_id, cvss FROM findings WHERE scan_id = ? AND status != 'duplicate' LIMIT 400")
    .all(scan.id);
  const edges = findings.filter((f) => f.asset_id).map((f) => ({ from: f.asset_id, to: f.id, kind: "finding" }));
  res.json({ assets, findings, edges });
});

router.get("/scans/:id/paths", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  res.json(attackPaths(scan.id));
});

router.get("/scans/:id/events", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  res.json(replay(scan.id, Number(req.query.after || 0), 500));
});

router.get("/scans/:id/stream", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();
  const after = Number(req.headers["last-event-id"] || req.query.after || 0);
  for (const event of replay(scan.id, after, 500)) {
    res.write(`id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`);
  }
  const unsubscribe = subscribe(scan.id, res);
  req.on("close", unsubscribe);
});

router.get("/scans/:id/coverage", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  const rows = db
    .prepare(
      `SELECT file, COUNT(*) AS findings, SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END) AS verified,
       MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS weight
       FROM findings WHERE scan_id = ? AND file IS NOT NULL GROUP BY file ORDER BY weight DESC, findings DESC`,
    )
    .all(scan.id);
  res.json(rows);
});

router.get("/scans/:id/fuzz", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  const runs = db.prepare("SELECT * FROM fuzz_runs WHERE scan_id = ? ORDER BY started_at DESC").all(scan.id);
  const crashes = db
    .prepare("SELECT c.* FROM fuzz_crashes c JOIN fuzz_runs r ON r.id = c.fuzz_run_id WHERE r.scan_id = ? ORDER BY c.created_at DESC LIMIT 200")
    .all(scan.id);
  res.json({ runs, crashes });
});

router.post("/scans/:id/approvals/:approvalId", requireRole("admin", "analyst"), (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  const decision = req.body?.decision === "approved" ? "approved" : "rejected";
  db.prepare("UPDATE approvals SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND scan_id = ?").run(
    decision,
    now(),
    req.user.id,
    req.params.approvalId,
    scan.id,
  );
  emit(scan.id, "approval", `Approval ${decision}`, { approvalId: req.params.approvalId, decision }, { agent: "orchestrator" });
  res.json({ ok: true });
});

router.post("/scans/:id/reports", (req, res) => {
  const scan = loadScan(req, res);
  if (!scan) return;
  const format = ["md", "html", "json", "sarif"].includes(req.body?.format) ? req.body.format : "md";
  const report = createReport(scan.id, format, req.user.id);
  res.status(201).json(report);
});

router.get("/reports/:id/download", (req, res) => {
  const report = db
    .prepare(
      `SELECT r.* FROM reports r JOIN scans s ON s.id = r.scan_id
       JOIN workspace_members m ON m.workspace_id = s.workspace_id
       WHERE r.id = ? AND m.user_id = ?`,
    )
    .get(req.params.id, req.user.id);
  if (!report || !fs.existsSync(report.path)) return res.status(404).json({ error: "report not found" });
  res.download(report.path, `kestrel-${report.scan_id.slice(0, 8)}.${report.format}`);
});

router.get("/dashboard", (req, res) => {
  const workspaceIds = db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ?").all(req.user.id).map((r) => r.workspace_id);
  if (!workspaceIds.length) return res.json({ empty: true });
  const placeholders = workspaceIds.map(() => "?").join(",");
  const totals = db
    .prepare(
      `SELECT COUNT(*) AS scans,
       COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END),0) AS running
       FROM scans WHERE workspace_id IN (${placeholders})`,
    )
    .get(...workspaceIds);
  const findings = db
    .prepare(
      `SELECT f.severity, COUNT(*) AS n FROM findings f JOIN scans s ON s.id = f.scan_id
       WHERE s.workspace_id IN (${placeholders}) AND f.status != 'duplicate' GROUP BY f.severity`,
    )
    .all(...workspaceIds);
  const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const row of findings) severity[row.severity] = row.n;
  const recent = db
    .prepare(
      `SELECT s.id, s.name, s.target, s.target_type, s.status, s.risk_score, s.created_at,
       (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.status != 'duplicate') AS findings
       FROM scans s WHERE s.workspace_id IN (${placeholders}) ORDER BY s.created_at DESC LIMIT 8`,
    )
    .all(...workspaceIds);
  const trend = db
    .prepare(
      `SELECT substr(s.created_at,1,10) AS day, COUNT(f.id) AS findings,
       COALESCE(SUM(CASE WHEN f.severity IN ('critical','high') THEN 1 ELSE 0 END),0) AS severe
       FROM scans s LEFT JOIN findings f ON f.scan_id = s.id
       WHERE s.workspace_id IN (${placeholders}) AND s.created_at >= ?
       GROUP BY day ORDER BY day`,
    )
    .all(...workspaceIds, new Date(Date.now() - 14 * 86400_000).toISOString());
  const topRules = db
    .prepare(
      `SELECT f.rule_id, f.engine, COUNT(*) AS n FROM findings f JOIN scans s ON s.id = f.scan_id
       WHERE s.workspace_id IN (${placeholders}) AND f.status != 'duplicate'
       GROUP BY f.rule_id ORDER BY n DESC LIMIT 8`,
    )
    .all(...workspaceIds);
  const recentFindings = db
    .prepare(
      `SELECT f.id, f.title, f.severity, f.scan_id, f.engine, f.created_at FROM findings f
       JOIN scans s ON s.id = f.scan_id WHERE s.workspace_id IN (${placeholders})
       AND f.status != 'duplicate' ORDER BY f.created_at DESC LIMIT 10`,
    )
    .all(...workspaceIds);
  const agents = db
    .prepare(
      `SELECT a.agent, a.status, COUNT(*) AS n FROM agent_runs a JOIN scans s ON s.id = a.scan_id
       WHERE s.workspace_id IN (${placeholders}) AND a.started_at >= ? GROUP BY a.agent, a.status`,
    )
    .all(...workspaceIds, new Date(Date.now() - 86400_000).toISOString());
  res.json({
    totals,
    severity,
    recent,
    trend,
    topRules,
    recentFindings,
    agents,
    queue: queueStats(),
    llm: llmStats(),
    agentLabels: AGENT_LABELS,
    autonomy: autonomyStats(workspaceIds),
  });
});

router.get("/assets", (req, res) => {
  const workspaceIds = db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ?").all(req.user.id).map((r) => r.workspace_id);
  if (!workspaceIds.length) return res.json([]);
  const ph = workspaceIds.map(() => "?").join(",");
  const rows = db
    .prepare(
      `SELECT a.*, s.name AS scan_name FROM assets a JOIN scans s ON s.id = a.scan_id
       WHERE s.workspace_id IN (${ph}) ORDER BY a.first_seen DESC LIMIT 500`,
    )
    .all(...workspaceIds);
  res.json(rows);
});

router.get("/fuzz", (req, res) => {
  const workspaceIds = db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ?").all(req.user.id).map((r) => r.workspace_id);
  if (!workspaceIds.length) return res.json({ runs: [], crashes: [] });
  const ph = workspaceIds.map(() => "?").join(",");
  const runs = db
    .prepare(
      `SELECT r.*, s.name AS scan_name FROM fuzz_runs r JOIN scans s ON s.id = r.scan_id
       WHERE s.workspace_id IN (${ph}) ORDER BY r.started_at DESC LIMIT 100`,
    )
    .all(...workspaceIds);
  const crashes = db
    .prepare(
      `SELECT c.*, r.target, s.id AS scan_id FROM fuzz_crashes c JOIN fuzz_runs r ON r.id = c.fuzz_run_id
       JOIN scans s ON s.id = r.scan_id WHERE s.workspace_id IN (${ph}) ORDER BY c.created_at DESC LIMIT 200`,
    )
    .all(...workspaceIds);
  res.json({ runs, crashes });
});

router.get("/reports", (req, res) => {
  const workspaceIds = db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ?").all(req.user.id).map((r) => r.workspace_id);
  if (!workspaceIds.length) return res.json([]);
  const ph = workspaceIds.map(() => "?").join(",");
  res.json(
    db
      .prepare(
        `SELECT r.id, r.scan_id, r.format, r.sha256, r.hmac, r.created_at, s.name AS scan_name
         FROM reports r JOIN scans s ON s.id = r.scan_id WHERE s.workspace_id IN (${ph})
         ORDER BY r.created_at DESC LIMIT 200`,
      )
      .all(...workspaceIds),
  );
});

export default router;
