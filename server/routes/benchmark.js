import express from "express";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { db, now } from "../db.js";
import { ROOT, PROJECTS_DIR } from "../config.js";
import { enqueue } from "../queue.js";
import { requireRole } from "../auth.js";
import { runScan } from "../scan.js";
import { walkFiles } from "../lib/util.js";
import { listFindings } from "../store.js";

const router = express.Router();

// The fixture ships placeholders, not live-looking credentials: GitHub push
// protection would reject the repository otherwise. The benchmark materialises
// the synthetic values at scan time so the secrets engine still sees them.
const FIXTURE_SECRETS = {
  "@AWS_ACCESS_KEY_ID@": "AKIA" + "IOSFODNN7EXAMPLE",
  "@AWS_SECRET_ACCESS_KEY@": "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
  "@DATABASE_URL@": "postgres://admin:supersecret@localhost:5432/app",
  "@STRIPE_SECRET_KEY@": "sk_live_" + "51Habcdefghijklmnopqrstuvwxyz0123456789",
  "@GITHUB_TOKEN@": "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
};

async function materializeFixtureSecrets(dir) {
  try {
    const template = path.join(dir, "env.fixture");
    let text = await fsp.readFile(template, "utf8");
    for (const [marker, value] of Object.entries(FIXTURE_SECRETS)) {
      text = text.split(marker).join(value);
    }
    await fsp.writeFile(path.join(dir, ".env"), text);
    await fsp.rm(template, { force: true });
  } catch {
    /* fixtures without secrets are fine */
  }
}

router.get("/benchmarks", (req, res) => {
  res.json(db.prepare("SELECT * FROM benchmarks ORDER BY created_at DESC LIMIT 50").all());
});

router.get("/benchmarks/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM benchmarks WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "not found" });
  const findings = row.scan_id ? listFindings(row.scan_id, { limit: 500 }) : [];
  res.json({ ...row, findings });
});

router.post("/benchmarks/run", requireRole("admin", "analyst"), (req, res) => {
  const id = crypto.randomUUID();
  enqueue("benchmark.run", { benchmarkId: id, userId: req.user.id }, null);
  res.status(202).json({ id });
});

export async function runBenchmark({ benchmarkId, userId }) {
  const fixture = path.join(ROOT, "fixtures", "vulnlab");
  const expected = JSON.parse(fs.readFileSync(path.join(fixture, "expected.json"), "utf8"));
  const projectId = crypto.randomUUID();
  const dir = path.join(PROJECTS_DIR, `bench-${projectId}`);
  await fsp.cp(fixture, dir, { recursive: true });
  await materializeFixtureSecrets(dir);
  const workspace = db.prepare("SELECT id FROM workspaces LIMIT 1").get();
  db.prepare(
    "INSERT INTO projects(id, workspace_id, name, kind, path, meta_json, created_by, created_at) VALUES(?, ?, ?, 'code', ?, ?, ?, ?)",
  ).run(projectId, workspace.id, `Benchmark ${expected.name}`, dir, JSON.stringify({ benchmark: true }), userId, now());
  const files = await walkFiles(dir);
  const insert = db.prepare("INSERT OR IGNORE INTO project_files(project_id, path, size, sha256, language) VALUES(?, ?, ?, ?, ?)");
  for (const file of files) insert.run(projectId, file.rel, file.size, "bench", file.lang);
  const scanId = crypto.randomUUID();
  db.prepare(
    `INSERT INTO scans(id, project_id, workspace_id, name, target_type, target, scope_json, config_json, status, created_by, created_at)
     VALUES(?, ?, ?, ?, 'code', ?, '{}', ?, 'queued', ?, ?)`,
  ).run(
    scanId,
    projectId,
    workspace.id,
    `Benchmark run ${expected.name}`,
    dir,
    JSON.stringify({ fuzzIterations: 120, labMaxFunctions: 32, llmReview: false }),
    userId,
    now(),
  );
  await runScan(scanId);
  const findings = listFindings(scanId, { limit: 500 }).filter((f) => f.status !== "duplicate" && f.status !== "false_positive");
  const matched = new Set();
  let tp = 0;
  const misses = [];
  for (const item of expected.expected) {
    const hit = findings.find(
      (f) =>
        !matched.has(f.id) &&
        (item.ruleId.endsWith("*") ? f.ruleId.startsWith(item.ruleId.slice(0, -1)) : f.ruleId === item.ruleId) &&
        f.file === item.file &&
        (!item.line || Math.abs((f.line || 0) - item.line) <= 12),
    );
    if (hit) {
      matched.add(hit.id);
      tp += 1;
    } else {
      misses.push(item);
    }
  }
  const fpFindings = findings.filter(
    (f) =>
      !matched.has(f.id) &&
      expected.expected.some((e) => e.ruleId === f.ruleId) &&
      !["info", "reporter", "sbom", "correlator"].includes(f.engine) &&
      f.severity !== "info",
  );
  const fp = fpFindings.length;
  const fn = misses.length;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  db.prepare(
    "INSERT INTO benchmarks(id, name, scan_id, precision, recall, f1, tp, fp, fn, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  ).run(
    benchmarkId,
    expected.name,
    scanId,
    Math.round(precision * 1000) / 10,
    Math.round(recall * 1000) / 10,
    Math.round(f1 * 1000) / 10,
    tp,
    fp,
    fn,
    now(),
  );
  return { tp, fp, fn, precision, recall, f1, misses };
}

export default router;
