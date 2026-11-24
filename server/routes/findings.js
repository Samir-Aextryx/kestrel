import express from "express";
import fsp from "node:fs/promises";
import path from "node:path";
import { db, now, audit } from "../db.js";
import { getFinding, updateFinding, listFindings } from "../store.js";
import { requireRole } from "../auth.js";
import { retestFinding } from "../retest.js";

const router = express.Router();

function loadFinding(req, res) {
  const finding = db
    .prepare(
      `SELECT f.* FROM findings f JOIN scans s ON s.id = f.scan_id
       JOIN workspace_members m ON m.workspace_id = s.workspace_id
       WHERE f.id = ? AND m.user_id = ?`,
    )
    .get(req.params.id, req.user.id);
  if (!finding) {
    res.status(404).json({ error: "finding not found" });
    return null;
  }
  return finding;
}

router.get("/findings", (req, res) => {
  const workspaceIds = db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ?").all(req.user.id).map((r) => r.workspace_id);
  if (!workspaceIds.length) return res.json([]);
  const where = [`s.workspace_id IN (${workspaceIds.map(() => "?").join(",")})`, "f.status != 'duplicate'"];
  const params = [...workspaceIds];
  if (req.query.severity) {
    const list = String(req.query.severity).split(",");
    where.push(`f.severity IN (${list.map(() => "?").join(",")})`);
    params.push(...list);
  }
  if (req.query.status) {
    where.push("f.status = ?");
    params.push(String(req.query.status));
  }
  if (req.query.engine) {
    where.push("f.engine = ?");
    params.push(String(req.query.engine));
  }
  if (req.query.q) {
    where.push("(f.title LIKE ? OR f.file LIKE ? OR f.rule_id LIKE ?)");
    const q = `%${req.query.q}%`;
    params.push(q, q, q);
  }
  const limit = Math.min(500, Number(req.query.limit || 200));
  const rows = db
    .prepare(
      `SELECT f.*, s.name AS scan_name, a.value AS asset_value, a.kind AS asset_kind
       FROM findings f JOIN scans s ON s.id = f.scan_id LEFT JOIN assets a ON a.id = f.asset_id
       WHERE ${where.join(" AND ")}
       ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
       f.cvss DESC, f.created_at DESC LIMIT ?`,
    )
    .all(...params, limit);
  res.json(
    rows.map((r) => ({
      id: r.id,
      scanId: r.scan_id,
      scanName: r.scan_name,
      title: r.title,
      severity: r.severity,
      cvss: r.cvss,
      confidence: r.confidence,
      status: r.status,
      engine: r.engine,
      ruleId: r.rule_id,
      file: r.file,
      line: r.line,
      assetValue: r.asset_value,
      verified: Boolean(r.verified),
      createdAt: r.created_at,
    })),
  );
});

router.get("/findings/:id", (req, res) => {
  const row = loadFinding(req, res);
  if (!row) return;
  const finding = getFinding(row.id);
  const scan = db.prepare("SELECT id, name, target, target_type, project_id FROM scans WHERE id = ?").get(row.scan_id);
  res.json({ ...finding, scan });
});

router.patch("/findings/:id", requireRole("admin", "analyst"), (req, res) => {
  const row = loadFinding(req, res);
  if (!row) return;
  const patch = {};
  if (req.body.status && ["open", "confirmed", "false_positive", "fixed", "accepted_risk", "triaged"].includes(req.body.status)) {
    patch.status = req.body.status;
  }
  if (req.body.severity && ["critical", "high", "medium", "low", "info"].includes(req.body.severity)) patch.severity = req.body.severity;
  if (req.body.confidence && ["high", "medium", "low"].includes(req.body.confidence)) patch.confidence = req.body.confidence;
  if (typeof req.body.remediation === "string") patch.remediation = req.body.remediation.slice(0, 6000);
  if (typeof req.body.verified === "boolean") patch.verified = req.body.verified ? 1 : 0;
  const updated = updateFinding(row.id, patch, req.user.id);
  audit(req.user.id, "finding.update", "finding", row.id, req.ip, patch);
  res.json(updated);
});

router.post("/findings/:id/retest", requireRole("admin", "analyst"), async (req, res) => {
  const row = loadFinding(req, res);
  if (!row) return;
  const result = await retestFinding(row.id, req.user.id);
  audit(req.user.id, "finding.retest", "finding", row.id, req.ip, { ok: result.ok });
  res.json(result);
});

router.get("/findings/:id/evidence", (req, res) => {
  const row = loadFinding(req, res);
  if (!row) return;
  res.json(db.prepare("SELECT id, kind, sha256, content, created_at FROM evidence WHERE finding_id = ?").all(row.id));
});

router.get("/rules", (req, res) => {
  res.json(db.prepare("SELECT * FROM rule_stats ORDER BY runs DESC LIMIT 300").all());
});

export default router;
