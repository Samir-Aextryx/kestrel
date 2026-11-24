import crypto from "node:crypto";
import { db, now } from "./db.js";
import {
  CONFIDENCE_WEIGHT,
  SEVERITIES,
  SEVERITY_WEIGHT,
} from "./config.js";
import {
  clamp,
  cvssFromVector,
  findingHash,
  fingerprint,
  normalizeSeverity,
  severityFromScore,
  severityScore,
  truncate,
} from "./lib/util.js";
import { sha256 } from "./crypto.js";
import { emit } from "./events.js";

export function addAsset(scan, kind, value, meta = {}) {
  if (!value) return null;
  const clean = String(value).slice(0, 2000);
  const existing = db
    .prepare("SELECT * FROM assets WHERE scan_id = ? AND kind = ? AND value = ?")
    .get(scan.id, kind, clean);
  if (existing) return existing.id;
  const id = crypto.randomUUID();
  db.prepare(
    "INSERT INTO assets(id, scan_id, project_id, kind, value, meta_json, first_seen) VALUES(?, ?, ?, ?, ?, ?, ?)",
  ).run(id, scan.id, scan.project_id, kind, clean, JSON.stringify(meta), now());
  emit(scan.id, "asset", `${kind}: ${clean}`, { id, kind, value: clean }, { agent: "recon" });
  return id;
}

function ruleWeight(ruleId) {
  const row = db.prepare("SELECT weight FROM rule_stats WHERE rule_id = ?").get(ruleId);
  return row?.weight ?? 1;
}

export function addFinding(scan, raw, agent = "engine") {
  const severity = normalizeSeverity(raw.severity);
  const confidence = ["high", "medium", "low"].includes(raw.confidence) ? raw.confidence : "medium";
  const cvss = raw.cvss ?? cvssFromVector(raw.cvssVector) ?? severityScore(severity);
  const fp = raw.fingerprint || fingerprint(raw.engine, raw.ruleId, raw.file, raw.line, raw.match || raw.title);
  const existing = db
    .prepare("SELECT * FROM findings WHERE scan_id = ? AND fingerprint = ?")
    .get(scan.id, fp);
  if (existing) {
    const mergedEvidence = { ...JSON.parse(existing.evidence_json || "{}"), ...(raw.evidence || {}) };
    db.prepare(
      "UPDATE findings SET evidence_json = ?, confidence = ?, updated_at = ? WHERE id = ?",
    ).run(
      JSON.stringify(mergedEvidence),
      confidence === "high" ? "high" : existing.confidence,
      now(),
      existing.id,
    );
    return { id: existing.id, duplicate: true };
  }
  let assetId = null;
  if (raw.assetValue) assetId = addAsset(scan, raw.assetKind || "endpoint", raw.assetValue, raw.assetMeta);
  const id = crypto.randomUUID();
  const finding = {
    id,
    scan_id: scan.id,
    project_id: scan.project_id,
    asset_id: assetId,
    engine: String(raw.engine || agent).slice(0, 60),
    rule_id: String(raw.ruleId || "unknown").slice(0, 120),
    title: String(raw.title || "Untitled finding").slice(0, 300),
    description: String(raw.description || "").slice(0, 12_000),
    severity,
    cvss: clamp(Number(cvss) || 0, 0, 10),
    cvss_vector: raw.cvssVector || null,
    cwe: raw.cwe || null,
    owasp: raw.owasp || null,
    confidence,
    status: "open",
    fingerprint: fp,
    file: raw.file || null,
    line: raw.line || null,
    column: raw.column || null,
    snippet: raw.snippet ? truncate(raw.snippet, 6000) : null,
    evidence_json: JSON.stringify(raw.evidence || {}),
    taint_json: raw.taint ? JSON.stringify(raw.taint) : null,
    remediation: raw.remediation ? String(raw.remediation).slice(0, 6000) : null,
    references_json: JSON.stringify((raw.references || []).slice(0, 12)),
    tags_json: JSON.stringify((raw.tags || []).slice(0, 20)),
    hash: "",
    created_at: now(),
    updated_at: now(),
  };
  finding.hash = findingHash(finding);
  db.prepare(
    `INSERT INTO findings(
      id, scan_id, project_id, asset_id, engine, rule_id, title, description, severity, cvss,
      cvss_vector, cwe, owasp, confidence, status, fingerprint, file, line, column, snippet,
      evidence_json, taint_json, remediation, references_json, tags_json, hash, created_at, updated_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    finding.id,
    finding.scan_id,
    finding.project_id,
    finding.asset_id,
    finding.engine,
    finding.rule_id,
    finding.title,
    finding.description,
    finding.severity,
    finding.cvss,
    finding.cvss_vector,
    finding.cwe,
    finding.owasp,
    finding.confidence,
    finding.status,
    finding.fingerprint,
    finding.file,
    finding.line,
    finding.column,
    finding.snippet,
    finding.evidence_json,
    finding.taint_json,
    finding.remediation,
    finding.references_json,
    finding.tags_json,
    finding.hash,
    finding.created_at,
    finding.updated_at,
  );
  if (raw.evidence) {
    const content = JSON.stringify(raw.evidence);
    db.prepare(
      "INSERT INTO evidence(id, finding_id, kind, sha256, content, meta_json, created_at) VALUES(?, ?, 'json', ?, ?, '{}', ?)",
    ).run(crypto.randomUUID(), id, sha256(content), truncate(content, 60_000), now());
  }
  db.prepare(
    `INSERT INTO rule_stats(rule_id, runs, weight, updated_at) VALUES(?, 1, 1, ?)
     ON CONFLICT(rule_id) DO UPDATE SET runs = runs + 1, updated_at = excluded.updated_at`,
  ).run(finding.rule_id, now());
  emit(scan.id, "finding", `[${severity.toUpperCase()}] ${finding.title}`, {
    id,
    severity,
    confidence,
    file: finding.file,
    line: finding.line,
    engine: finding.engine,
    ruleId: finding.rule_id,
  }, { agent });
  return { id, duplicate: false };
}

export function listFindings(scanId, filters = {}) {
  const where = ["f.scan_id = ?"];
  const params = [scanId];
  if (filters.severity) {
    where.push(`f.severity IN (${filters.severity.map(() => "?").join(",")})`);
    params.push(...filters.severity);
  }
  if (filters.status) {
    where.push("f.status = ?");
    params.push(filters.status);
  }
  if (filters.engine) {
    where.push("f.engine = ?");
    params.push(filters.engine);
  }
  if (filters.verified !== undefined) {
    where.push("f.verified = ?");
    params.push(filters.verified ? 1 : 0);
  }
  if (filters.q) {
    where.push("(f.title LIKE ? OR f.file LIKE ? OR f.rule_id LIKE ?)");
    const q = `%${filters.q}%`;
    params.push(q, q, q);
  }
  const limit = Math.min(500, Number(filters.limit || 200));
  return db
    .prepare(
      `SELECT f.*, a.value AS asset_value, a.kind AS asset_kind FROM findings f
       LEFT JOIN assets a ON a.id = f.asset_id
       WHERE ${where.join(" AND ")}
       ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
       f.cvss DESC, f.created_at DESC LIMIT ?`,
    )
    .all(...params, limit)
    .map(hydrateFinding);
}

export function hydrateFinding(row) {
  if (!row) return null;
  const evidence = JSON.parse(row.evidence_json || "{}");
  return {
    id: row.id,
    scanId: row.scan_id,
    projectId: row.project_id,
    assetId: row.asset_id,
    assetValue: row.asset_value,
    assetKind: row.asset_kind,
    engine: row.engine,
    ruleId: row.rule_id,
    title: row.title,
    description: row.description,
    severity: row.severity,
    cvss: row.cvss,
    cvssVector: row.cvss_vector,
    cwe: row.cwe,
    owasp: row.owasp,
    confidence: row.confidence,
    status: row.status,
    fingerprint: row.fingerprint,
    file: row.file,
    line: row.line,
    column: row.column,
    snippet: row.snippet,
    evidence,
    taint: row.taint_json ? JSON.parse(row.taint_json) : null,
    remediation: row.remediation,
    references: JSON.parse(row.references_json || "[]"),
    verified: Boolean(row.verified),
    verification: row.verification_json ? JSON.parse(row.verification_json) : null,
    tags: JSON.parse(row.tags_json || "[]"),
    hash: row.hash,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    zeroDayScore: Number(evidence.zeroDayScore || 0),
    exploitability: Number(evidence.exploitability || 0),
  };
}

export function getFinding(id) {
  const row = db
    .prepare(
      `SELECT f.*, a.value AS asset_value, a.kind AS asset_kind FROM findings f
       LEFT JOIN assets a ON a.id = f.asset_id WHERE f.id = ?`,
    )
    .get(id);
  if (!row) return null;
  const finding = hydrateFinding(row);
  finding.evidenceRows = db
    .prepare("SELECT id, kind, sha256, content, created_at FROM evidence WHERE finding_id = ? ORDER BY created_at")
    .all(id);
  return finding;
}

export function updateFinding(id, patch, actor = null) {
  const allowed = ["status", "severity", "confidence", "remediation", "verified", "verification_json"];
  const sets = [];
  const params = [];
  for (const [key, value] of Object.entries(patch)) {
    if (!allowed.includes(key)) continue;
    sets.push(`${key} = ?`);
    params.push(value);
  }
  if (!sets.length) return getFinding(id);
  sets.push("updated_at = ?");
  params.push(now());
  db.prepare(`UPDATE findings SET ${sets.join(", ")} WHERE id = ?`).run(...params, id);
  if (patch.status === "false_positive") {
    const row = db.prepare("SELECT rule_id FROM findings WHERE id = ?").get(id);
    if (row) {
      db.prepare(
        `UPDATE rule_stats SET false_positive = false_positive + 1,
         weight = MAX(0.35, weight * 0.94), updated_at = ? WHERE rule_id = ?`,
      ).run(now(), row.rule_id);
    }
  }
  if (patch.status === "confirmed") {
    const row = db.prepare("SELECT rule_id FROM findings WHERE id = ?").get(id);
    if (row) {
      db.prepare(
        `UPDATE rule_stats SET verified = verified + 1,
         weight = MIN(1.6, weight * 1.03), updated_at = ? WHERE rule_id = ?`,
      ).run(now(), row.rule_id);
    }
  }
  return getFinding(id);
}

export function recomputeRisk(scanId) {
  const rows = db
    .prepare("SELECT severity, confidence, verified, rule_id FROM findings WHERE scan_id = ? AND status != 'false_positive'")
    .all(scanId);
  let sum = 0;
  for (const row of rows) {
    sum +=
      (SEVERITY_WEIGHT[row.severity] || 0.2) *
      (CONFIDENCE_WEIGHT[row.confidence] || 0.5) *
      (row.verified ? 1.25 : 1) *
      ruleWeight(row.rule_id);
  }
  const score = Math.round(100 * (1 - Math.exp(-sum / 42)) * 10) / 10;
  db.prepare("UPDATE scans SET risk_score = ? WHERE id = ?").run(score, scanId);
  return score;
}

export function severityCounts(scanId) {
  const rows = db
    .prepare("SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? AND status != 'false_positive' GROUP BY severity")
    .all(scanId);
  const out = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const row of rows) out[row.severity] = row.n;
  return out;
}

export function scanStats(scanId) {
  const findings = db
    .prepare("SELECT COUNT(*) AS n, SUM(verified) AS verified FROM findings WHERE scan_id = ?")
    .get(scanId);
  const assets = db.prepare("SELECT COUNT(*) AS n FROM assets WHERE scan_id = ?").get(scanId);
  const fuzz = db
    .prepare("SELECT COALESCE(SUM(execs),0) AS execs, COALESCE(MAX(coverage),0) AS coverage, COALESCE(SUM(crashes),0) AS crashes FROM fuzz_runs WHERE scan_id = ?")
    .get(scanId);
  return {
    findings: findings.n,
    verified: findings.verified || 0,
    assets: assets.n,
    fuzzExecs: fuzz.execs,
    coverage: fuzz.coverage,
    crashes: fuzz.crashes,
    severity: severityCounts(scanId),
  };
}

export function attackPaths(scanId) {
  const rows = db
    .prepare(
      `SELECT f.id, f.title, f.severity, f.cvss, f.asset_id, a.value AS asset, f.tags_json
       FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
       WHERE f.scan_id = ? AND f.status != 'false_positive' ORDER BY f.cvss DESC LIMIT 40`,
    )
    .all(scanId);
  const paths = [];
  const byTag = new Map();
  for (const row of rows) {
    for (const tag of JSON.parse(row.tags_json || "[]")) {
      if (!byTag.has(tag)) byTag.set(tag, []);
      byTag.get(tag).push(row);
    }
  }
  for (const [tag, items] of byTag) {
    if (items.length < 2) continue;
    const score = items.reduce((acc, i) => acc + i.cvss, 0);
    paths.push({
      id: sha256(`${scanId}:${tag}`).slice(0, 16),
      name: tag,
      score: Math.round(score * 10) / 10,
      steps: items.slice(0, 6).map((i) => ({
        id: i.id,
        title: i.title,
        severity: i.severity,
        asset: i.asset,
      })),
    });
  }
  const chainTags = ["entry", "execution", "credential", "lateral", "exfiltration", "impact"];
  const chain = rows
    .filter((r) => JSON.parse(r.tags_json || "[]").some((t) => chainTags.includes(t)))
    .slice(0, 8);
  if (chain.length >= 2) {
    paths.unshift({
      id: sha256(`${scanId}:chain`).slice(0, 16),
      name: "Observed attack chain",
      score: Math.round(chain.reduce((a, i) => a + i.cvss, 0) * 10) / 10,
      steps: chain.map((i) => ({ id: i.id, title: i.title, severity: i.severity, asset: i.asset })),
    });
  }
  return paths.sort((a, b) => b.score - a.score).slice(0, 8);
}

export function severityLabel(score) {
  return severityFromScore(score);
}
