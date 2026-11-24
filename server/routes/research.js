import express from "express";
import fsp from "node:fs/promises";
import path from "node:path";
import { db } from "../db.js";
import { safeJoin } from "../lib/util.js";

const router = express.Router();

function workspaces(userId) {
  return db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ?").all(userId).map((r) => r.workspace_id);
}

function scanAccess(userId, scanId) {
  return db
    .prepare(
      `SELECT s.* FROM scans s JOIN workspace_members m ON m.workspace_id = s.workspace_id
       WHERE s.id = ? AND m.user_id = ?`,
    )
    .get(scanId, userId);
}

router.get("/research", (req, res) => {
  const scan = scanAccess(req.user.id, String(req.query.scanId || ""));
  if (!scan) return res.status(404).json({ error: "scan not found" });
  const hypotheses = db
    .prepare(
      `SELECT h.*, f.title AS finding_title, f.severity AS finding_severity
       FROM research_hypotheses h LEFT JOIN findings f ON f.id = h.finding_id
       WHERE h.scan_id = ? ORDER BY CASE h.status WHEN 'confirmed' THEN 0 WHEN 'testing' THEN 1 ELSE 2 END,
       h.exploitability DESC LIMIT 500`,
    )
    .all(scan.id)
    .map((h) => ({ ...h, evidence: JSON.parse(h.evidence_json || "{}") }));
  const corpus = scan.project_id
    ? db.prepare("SELECT COUNT(*) AS entries, COALESCE(SUM(hits),0) AS hits FROM research_corpus WHERE project_id = ?").get(scan.project_id)
    : { entries: 0, hits: 0 };
  const byFamily = db
    .prepare("SELECT family, status, COUNT(*) AS n FROM research_hypotheses WHERE scan_id = ? GROUP BY family, status")
    .all(scan.id);
  res.json({
    scanId: scan.id,
    confirmed: hypotheses.filter((h) => h.status === "confirmed").length,
    rejected: hypotheses.filter((h) => h.status === "rejected").length,
    errors: hypotheses.filter((h) => h.status === "error").length,
    hypotheses,
    byFamily,
    corpus,
  });
});

router.get("/research/overview", (req, res) => {
  const ws = workspaces(req.user.id);
  if (!ws.length) return res.json({ confirmed: [], families: [], corpus: { entries: 0 } });
  const ph = ws.map(() => "?").join(",");
  const confirmed = db
    .prepare(
      `SELECT h.id, h.family, h.function, h.file, h.exploitability, h.confidence, h.finding_id,
       f.title, f.severity, f.cvss, s.id AS scan_id, s.name AS scan_name
       FROM research_hypotheses h JOIN scans s ON s.id = h.scan_id
       LEFT JOIN findings f ON f.id = h.finding_id
       WHERE s.workspace_id IN (${ph}) AND h.status = 'confirmed'
       ORDER BY h.exploitability DESC, h.created_at DESC LIMIT 100`,
    )
    .all(...ws);
  const families = db
    .prepare(
      `SELECT h.family, COUNT(*) AS n FROM research_hypotheses h JOIN scans s ON s.id = h.scan_id
       WHERE s.workspace_id IN (${ph}) AND h.status = 'confirmed' GROUP BY h.family ORDER BY n DESC`,
    )
    .all(...ws);
  res.json({ confirmed, families, corpus: db.prepare("SELECT COUNT(*) AS entries FROM research_corpus").get() });
});

router.get("/research/corpus", (req, res) => {
  const projectId = String(req.query.projectId || "");
  res.json(db.prepare("SELECT * FROM research_corpus WHERE project_id = ? ORDER BY coverage DESC LIMIT 500").all(projectId));
});

router.get("/findings/:id/poc", async (req, res) => {
  const finding = db
    .prepare(
      `SELECT f.*, s.project_id FROM findings f JOIN scans s ON s.id = f.scan_id
       JOIN workspace_members m ON m.workspace_id = s.workspace_id
       WHERE f.id = ? AND m.user_id = ?`,
    )
    .get(req.params.id, req.user.id);
  if (!finding) return res.status(404).json({ error: "finding not found" });
  const evidence = JSON.parse(finding.evidence_json || "{}");
  if (!evidence.poc) return res.status(404).json({ error: "no PoC bundle" });
  const project = finding.project_id ? db.prepare("SELECT path FROM projects WHERE id = ?").get(finding.project_id) : null;
  if (!project) return res.status(404).json({ error: "project missing" });
  try {
    const full = safeJoin(project.path, evidence.poc);
    const bundle = JSON.parse(await fsp.readFile(full, "utf8"));
    const codePath = evidence.pocCode ? safeJoin(project.path, evidence.pocCode) : null;
    const code = codePath ? await fsp.readFile(codePath, "utf8").catch(() => null) : null;
    res.json({ ...bundle, code, sha256: evidence.pocSha256 });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

export default router;
