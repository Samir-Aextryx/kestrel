import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { db, now } from "./db.js";
import { REPORTS_DIR } from "./config.js";
import { hmac, sha256 } from "./crypto.js";
import { attackPaths, listFindings, scanStats } from "./store.js";

const SEV_COLOR = {
  critical: "#ff4d6d",
  high: "#ff8a3d",
  medium: "#ffd166",
  low: "#5eead4",
  info: "#8b9bb4",
};

function scanBundle(scanId) {
  const scan = db.prepare("SELECT * FROM scans WHERE id = ?").get(scanId);
  if (!scan) throw new Error("scan not found");
  const project = scan.project_id ? db.prepare("SELECT * FROM projects WHERE id = ?").get(scan.project_id) : null;
  const findings = listFindings(scanId, { limit: 500 }).filter((f) => f.status !== "duplicate");
  const stats = scanStats(scanId);
  const agents = db.prepare("SELECT agent, status, summary, started_at, finished_at FROM agent_runs WHERE scan_id = ?").all(scanId);
  const paths = attackPaths(scanId);
  const fuzz = db.prepare("SELECT * FROM fuzz_runs WHERE scan_id = ?").all(scanId);
  return { scan, project, findings, stats, agents, paths, fuzz };
}

function markdown(bundle, summary) {
  const { scan, project, findings, stats, paths } = bundle;
  const lines = [
    `# KESTREL Security Report`,
    "",
    `**Scan:** ${scan.name}`,
    `**Target:** \`${scan.target}\``,
    `**Type:** ${scan.target_type}`,
    `**Project:** ${project?.name || "—"}`,
    `**Status:** ${scan.status}`,
    `**Risk score:** ${scan.risk_score}/100`,
    `**Generated:** ${now()}`,
    "",
    `> ${summary}`,
    "",
    "## Summary",
    "",
    `| Severity | Count |`,
    `| --- | ---: |`,
    ...Object.entries(stats.severity).map(([sev, n]) => `| ${sev} | ${n} |`),
    `| **Total** | **${stats.findings}** |`,
    "",
    `Verified: ${stats.verified} · Assets: ${stats.assets} · Fuzz executions: ${stats.fuzzExecs} · Crashes: ${stats.crashes}`,
    "",
  ];
  if (paths.length) {
    lines.push("## Attack paths", "");
    for (const p of paths) {
      lines.push(`### ${p.name} (score ${p.score})`, "");
      p.steps.forEach((s, i) => lines.push(`${i + 1}. **${s.severity.toUpperCase()}** ${s.title}${s.asset ? ` — \`${s.asset}\`` : ""}`));
      lines.push("");
    }
  }
  lines.push("## Findings", "");
  for (const f of findings) {
    lines.push(
      `### [${f.severity.toUpperCase()}] ${f.title}`,
      "",
      `- **Rule:** \`${f.ruleId}\` · **Engine:** ${f.engine} · **CVSS:** ${f.cvss}${f.cvssVector ? ` (${f.cvssVector})` : ""}`,
      `- **Location:** \`${f.file || f.assetValue || "—"}${f.line ? `:${f.line}` : ""}\``,
      `- **Confidence:** ${f.confidence} · **Verified:** ${f.verified ? "yes" : "no"} · **Status:** ${f.status}`,
      `- **CWE:** ${f.cwe || "—"} · **OWASP:** ${f.owasp || "—"}`,
      "",
      f.description,
      "",
    );
    if (f.snippet) lines.push("```", f.snippet, "```", "");
    if (f.taint) {
      lines.push(`**Taint:** \`${f.taint.source?.code || ""}\` → \`${f.taint.sink?.code || ""}\``, "");
    }
    if (f.remediation) lines.push(`**Remediation:** ${f.remediation}`, "");
    if (f.evidence && Object.keys(f.evidence).length) {
      lines.push("<details><summary>Evidence</summary>", "", "```json", JSON.stringify(f.evidence, null, 2).slice(0, 8000), "```", "</details>", "");
    }
    lines.push("---", "");
  }
  lines.push("## Method", "", "KESTREL combines deterministic static analysis, live surface checks, coverage-guided fuzzing, a differential zero-day lab, verification and human triage. Findings are evidence-linked; unverified items are marked.", "");
  return lines.join("\n");
}

function html(bundle, summary) {
  const { scan, project, findings, stats, paths } = bundle;
  const esc = (v) => String(v ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KESTREL — ${esc(scan.name)}</title>
<style>
:root{--bg:#07090c;--panel:#0d1218;--line:#1d2835;--text:#e6edf6;--muted:#8b9bb4;--lime:#b6f36b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 ui-sans-serif,system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:48px 24px}h1{font-size:32px;margin:0 0 8px}h2{margin-top:40px;border-bottom:1px solid var(--line);padding-bottom:8px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:24px 0}
.meta div{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.meta b{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.risk{font-size:40px;color:var(--lime);font-weight:700}.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--sev);border-radius:10px;padding:18px;margin:16px 0}
.chip{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700;text-transform:uppercase;background:color-mix(in srgb,var(--sev) 18%,transparent);color:var(--sev)}
code,pre{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}pre{background:#05070a;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}
.muted{color:var(--muted)}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:8px;text-align:left}
.path{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}footer{margin-top:48px;color:var(--muted);font-size:12px}
</style></head><body><main>
<div class="muted">KESTREL · evidence-first security research</div>
<h1>${esc(scan.name)}</h1>
<p class="muted">${esc(scan.target)} · ${esc(project?.name || "")} · ${esc(now())}</p>
<div class="meta">
<div><b>Risk score</b><span class="risk">${scan.risk_score}</span>/100</div>
<div><b>Findings</b>${stats.findings}</div>
<div><b>Verified</b>${stats.verified}</div>
<div><b>Assets</b>${stats.assets}</div>
<div><b>Fuzz executions</b>${stats.fuzzExecs}</div>
</div>
<p>${esc(summary)}</p>
<h2>Severity distribution</h2><table><tr><th>Severity</th><th>Count</th></tr>
${Object.entries(stats.severity).map(([s, n]) => `<tr><td>${s}</td><td>${n}</td></tr>`).join("")}</table>
${paths.length ? `<h2>Attack paths</h2>${paths.map((p) => `<div class="path"><b>${esc(p.name)}</b> <span class="muted">score ${p.score}</span><ol>${p.steps.map((s) => `<li><b>${s.severity}</b> ${esc(s.title)} ${s.asset ? `<code>${esc(s.asset)}</code>` : ""}</li>`).join("")}</ol></div>`).join("")}` : ""}
<h2>Findings</h2>
${findings.map((f) => `<div class="finding" style="--sev:${SEV_COLOR[f.severity]}"><span class="chip">${f.severity}</span>
<h3>${esc(f.title)}</h3>
<p class="muted"><code>${esc(f.ruleId)}</code> · ${esc(f.engine)} · CVSS ${f.cvss} · ${esc(f.file || f.assetValue || "")}${f.line ? `:${f.line}` : ""} · ${f.verified ? "verified" : "unverified"}</p>
<p>${esc(f.description)}</p>
${f.snippet ? `<pre>${esc(f.snippet)}</pre>` : ""}
${f.remediation ? `<p><b>Remediation:</b> ${esc(f.remediation)}</p>` : ""}
${f.evidence && Object.keys(f.evidence).length ? `<details><summary>Evidence</summary><pre>${esc(JSON.stringify(f.evidence, null, 2).slice(0, 8000))}</pre></details>` : ""}
</div>`).join("")}
<footer>Generated by KESTREL. Method: static analysis, live checks, coverage fuzzing, differential lab, verification. Unverified findings are marked.</footer>
</main></body></html>`;
}

function sarif(bundle) {
  const { scan, findings } = bundle;
  const rules = [...new Map(findings.map((f) => [f.ruleId, f])).values()].map((f) => ({
    id: f.ruleId,
    name: f.title.replace(/\W+/g, "_").slice(0, 80),
    shortDescription: { text: f.title },
    fullDescription: { text: f.description },
    helpUri: f.references?.[0] || "https://cwe.mitre.org/",
    properties: { tags: f.tags, cwe: f.cwe, owasp: f.owasp, engine: f.engine },
  }));
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "KESTREL",
              version: "1.0.0",
              informationUri: "https://kestrel.local",
              rules,
            },
          },
          automationDetails: { id: scan.id },
          results: findings.map((f) => ({
            ruleId: f.ruleId,
            level: { critical: "error", high: "error", medium: "warning", low: "note", info: "note" }[f.severity],
            message: { text: `${f.description}\n\nRemediation: ${f.remediation || "—"}` },
            locations: f.file
              ? [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line || 1 } } }]
              : [],
            partialFingerprints: { kestrel: f.fingerprint },
            properties: { severity: f.severity, cvss: f.cvss, confidence: f.confidence, verified: f.verified, cwe: f.cwe },
          })),
        },
      ],
    },
    null,
    2,
  );
}

export function createReport(scanId, format, userId = null) {
  const bundle = scanBundle(scanId);
  const summary =
    `KESTREL completed a ${bundle.scan.target_type} assessment with ${bundle.stats.findings} findings ` +
    `(${bundle.stats.severity.critical} critical, ${bundle.stats.severity.high} high). ` +
    `${bundle.stats.verified} findings were independently verified. Risk score: ${bundle.scan.risk_score}/100.`;
  let content;
  let ext;
  if (format === "md") {
    content = markdown(bundle, summary);
    ext = "md";
  } else if (format === "html") {
    content = html(bundle, summary);
    ext = "html";
  } else if (format === "sarif") {
    content = sarif(bundle);
    ext = "sarif";
  } else {
    content = JSON.stringify(
      {
        generatedAt: now(),
        summary,
        scan: bundle.scan,
        project: bundle.project,
        stats: bundle.stats,
        attackPaths: bundle.paths,
        findings: bundle.findings,
        agents: bundle.agents,
        fuzzRuns: bundle.fuzz,
      },
      null,
      2,
    );
    ext = "json";
  }
  const id = crypto.randomUUID();
  const filename = `${scanId}-${id.slice(0, 8)}.${ext}`;
  const full = path.join(REPORTS_DIR, filename);
  fs.writeFileSync(full, content);
  const digest = sha256(content);
  const signature = hmac(digest);
  db.prepare(
    "INSERT INTO reports(id, scan_id, format, path, sha256, hmac, created_by, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
  ).run(id, scanId, format, full, digest, signature, userId, now());
  return { id, format, filename, sha256: digest, hmac: signature, size: Buffer.byteLength(content) };
}
