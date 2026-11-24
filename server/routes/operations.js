import express from "express";
import { db } from "../db.js";
import { publicPayloads } from "../lib/payloads.js";

const router = express.Router();

function scanAccess(userId, scanId) {
  return db
    .prepare(
      `SELECT s.* FROM scans s JOIN workspace_members m ON m.workspace_id = s.workspace_id
       WHERE s.id = ? AND m.user_id = ?`,
    )
    .get(scanId, userId);
}

router.get("/payloads", (req, res) => {
  res.json(publicPayloads());
});

router.get("/operations", (req, res) => {
  const scan = scanAccess(req.user.id, String(req.query.scanId || ""));
  if (!scan) return res.status(404).json({ error: "scan not found" });
  const nodes = db.prepare("SELECT * FROM system_nodes WHERE scan_id = ? ORDER BY kind, created_at").all(scan.id);
  const credentials = db.prepare("SELECT * FROM credentials WHERE scan_id = ? ORDER BY valid DESC, created_at").all(scan.id);
  const runs = db.prepare("SELECT * FROM exploit_runs WHERE scan_id = ? ORDER BY created_at DESC LIMIT 300").all(scan.id);
  const counts = Object.fromEntries(
    db.prepare("SELECT kind, COUNT(*) AS n FROM system_nodes WHERE scan_id = ? GROUP BY kind").all(scan.id).map((r) => [r.kind, r.n]),
  );
  res.json({
    scanId: scan.id,
    nodes,
    credentials,
    runs,
    counts,
    confirmed: runs.filter((r) => r.status === "confirmed").length,
    foothold: nodes.some((n) => n.kind === "host" || n.kind === "user"),
  });
});

export default router;
