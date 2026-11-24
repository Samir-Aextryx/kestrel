import crypto from "node:crypto";
import fsp from "node:fs/promises";
import path from "node:path";
import { db, now } from "./db.js";
import { AGENTS, AGENT_LABELS } from "./config.js";
import { ScopeGate, normalizeScope } from "./scope.js";
import { emit } from "./events.js";
import { addAsset, addFinding, recomputeRisk, scanStats } from "./store.js";
import { walkFiles } from "./lib/util.js";
import { sha256 } from "./crypto.js";
import { ENGINE_MAP, enginesFor } from "./engines/index.js";
import { runAgent } from "./agents/index.js";
import { complete, wrapUntrusted } from "./llm.js";

const ENGINE_AGENT = {
  secrets: "secrets",
  "sast-js": "code",
  "sast-python": "code",
  "sast-go": "code",
  "patch-diff": "code",
  interproc: "code",
  invariant: "zeroday",
  network: "recon",
  auth: "recon",
  exploit: "exploit",
  foothold: "foothold",
  credentials: "credentials",
  dependencies: "supply",
  sbom: "supply",
  licenses: "supply",
  iac: "iac",
  container: "iac",
  api: "api",
  graphql: "api",
  web: "recon",
  tls: "recon",
  "fuzz-js": "fuzz",
  "fuzz-python": "fuzz",
  zeroday: "zeroday",
  binary: "code",
};

export function planFor(scan, config = {}) {
  const selected = Array.isArray(config.engines) && config.engines.length
    ? config.engines.filter((id) => ENGINE_MAP.has(id))
    : enginesFor(scan.target_type, {}).map((e) => e.id);
  const agents = new Set(["orchestrator"]);
  for (const engine of selected) {
    const agent = ENGINE_AGENT[engine];
    if (agent) agents.add(agent);
  }
  agents.add("verifier");
  if (["web", "api", "mixed"].includes(scan.target_type)) {
    agents.add("exploit");
    agents.add("foothold");
  }
  agents.add("credentials");
  agents.add("plugins");
  agents.add("critic");
  agents.add("correlator");
  agents.add("reporter");
  agents.add("optimizer");
  return { agents: [...agents], engines: selected };
}

function agentRow(scanId, agent) {
  const id = crypto.randomUUID();
  db.prepare(
    "INSERT INTO agent_runs(id, scan_id, agent, status, started_at) VALUES(?, ?, ?, 'running', ?)",
  ).run(id, scanId, agent, now());
  return id;
}

function finishAgent(id, status, summary = "") {
  db.prepare("UPDATE agent_runs SET status = ?, summary = ?, finished_at = ? WHERE id = ?").run(
    status,
    summary.slice(0, 2000),
    now(),
    id,
  );
}

async function waitForApproval(scan, action, payload) {
  const id = crypto.randomUUID();
  db.prepare(
    "INSERT INTO approvals(id, scan_id, action, payload_json, status, requested_at) VALUES(?, ?, ?, ?, 'pending', ?)",
  ).run(id, scan.id, action, JSON.stringify(payload), now());
  emit(scan.id, "approval", `Approval required: ${action}`, { approvalId: id, action, ...payload }, {
    agent: "orchestrator",
    level: "warn",
  });
  const deadline = Date.now() + 10 * 60_000;
  while (Date.now() < deadline) {
    if (scan.status === "cancelled") return false;
    const row = db.prepare("SELECT status FROM approvals WHERE id = ?").get(id);
    if (row?.status === "approved") return true;
    if (row?.status === "rejected") return false;
    await new Promise((r) => setTimeout(r, 1000));
  }
  db.prepare("UPDATE approvals SET status = 'expired', decided_at = ? WHERE id = ?").run(now(), id);
  return false;
}

function buildContext(scan, project, config, files, scope, webUrl) {
  const ctx = {
    scan,
    project,
    config,
    files,
    scope,
    webUrl,
    root: project?.path || null,
    signal: { aborted: false },
    add: (finding) => addFinding(scan, finding, finding.engine || "agent"),
    addAsset: (kind, value, meta) => addAsset(scan, kind, value, meta),
    addHypothesis(hypothesis) {
      const id = hypothesis.id || crypto.randomUUID();
      db.prepare(
        `INSERT INTO research_hypotheses(id, scan_id, finding_id, file, function, param, family, oracle,
         status, confidence, exploitability, evidence_json, created_at)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        id,
        scan.id,
        hypothesis.findingId || null,
        hypothesis.file,
        hypothesis.function,
        hypothesis.param || null,
        hypothesis.family,
        hypothesis.oracle,
        hypothesis.status,
        hypothesis.confidence,
        hypothesis.exploitability || 0,
        JSON.stringify(hypothesis.evidence || {}),
        now(),
      );
      emit(scan.id, "research", `Hypothesis ${hypothesis.status}: ${hypothesis.function} / ${hypothesis.family}`, {
        hypothesisId: id,
        status: hypothesis.status,
        family: hypothesis.family,
      }, { agent: "zeroday" });
      return id;
    },
    emit: (level, message, data) => emit(scan.id, "agent", message, data || {}, { agent: ctx.agent, level }),
    llm: complete,
    async writeArtifact(name, content) {
      const dir = path.join(ctx.root, ".kestrel", "artifacts");
      await fsp.mkdir(dir, { recursive: true });
      const rel = path.posix.join(".kestrel/artifacts", name);
      await fsp.writeFile(path.join(dir, name), content);
      return { rel, sha256: sha256(content) };
    },
  };
  return ctx;
}

export async function runScan(scanId) {
  const scan = db.prepare("SELECT * FROM scans WHERE id = ?").get(scanId);
  if (!scan) return;
  if (!["queued", "running"].includes(scan.status)) return;
  const project = scan.project_id ? db.prepare("SELECT * FROM projects WHERE id = ?").get(scan.project_id) : null;
  const config = JSON.parse(scan.config_json || "{}");
  const scopeJson = JSON.parse(scan.scope_json || "{}");
  db.prepare("UPDATE scans SET status = 'running', started_at = COALESCE(started_at, ?), phase = 'planning' WHERE id = ?").run(
    now(),
    scanId,
  );
  emit(scanId, "scan.started", "Scan started", { targetType: scan.target_type, target: scan.target }, {
    agent: "orchestrator",
  });

  let files = [];
  if (project?.path) {
    try {
      files = await walkFiles(project.path);
    } catch (err) {
      emit(scanId, "warn", `Project files unavailable: ${err.message}`, {}, { agent: "orchestrator", level: "warn" });
    }
  }
  const scope = new ScopeGate(normalizeScope(scopeJson), { signal: null });
  const webUrl = ["web", "mixed", "api"].includes(scan.target_type)
    ? config.webUrl || (scan.target.startsWith("http") ? scan.target : null)
    : null;
  const ctx = buildContext(scan, project, config, files, scope, webUrl);
  const plan = planFor(scan, config);
  const active = plan.agents.filter((a) => AGENTS.includes(a));

  if (config.requireApproval && (webUrl || active.includes("fuzz") || active.includes("zeroday"))) {
    const approved = await waitForApproval(scan, "active-testing", {
      target: webUrl || scan.target,
      engines: plan.engines,
      requestBudget: scope.maxRequests,
    });
    if (!approved) {
      db.prepare("UPDATE scans SET status = 'cancelled', finished_at = ?, phase = 'approval-rejected' WHERE id = ?").run(now(), scanId);
      emit(scanId, "scan.cancelled", "Approval rejected or expired", {}, { agent: "orchestrator", level: "warn" });
      return;
    }
    emit(scanId, "approval", "Active testing approved", {}, { agent: "orchestrator" });
  }

  let completed = 0;
  try {
    for (const agent of active) {
      const fresh = db.prepare("SELECT status FROM scans WHERE id = ?").get(scanId);
      if (fresh?.status === "cancelled") {
        ctx.signal.aborted = true;
        break;
      }
      const rowId = agentRow(scanId, agent);
      db.prepare("UPDATE scans SET phase = ? WHERE id = ?").run(agent, scanId);
      emit(scanId, "agent.started", `${AGENT_LABELS[agent] || agent} started`, { agent }, { agent });
      try {
        const summary = await runAgent(agent, ctx, plan);
        finishAgent(rowId, "done", summary || "");
        emit(scanId, "agent.done", `${AGENT_LABELS[agent] || agent} finished`, { agent, summary }, { agent });
      } catch (err) {
        finishAgent(rowId, "failed", err.message);
        emit(scanId, "agent.failed", `${AGENT_LABELS[agent] || agent} failed: ${err.message}`, { agent }, {
          agent,
          level: "error",
        });
      }
      completed += 1;
      db.prepare("UPDATE scans SET progress = ? WHERE id = ?").run(
        Math.round((completed / active.length) * 92),
        scanId,
      );
      recomputeRisk(scanId);
    }
    const final = db.prepare("SELECT status FROM scans WHERE id = ?").get(scanId);
    if (final?.status === "cancelled") {
      db.prepare("UPDATE scans SET finished_at = ?, phase = 'cancelled' WHERE id = ?").run(now(), scanId);
      emit(scanId, "scan.cancelled", "Scan cancelled", {}, { agent: "orchestrator", level: "warn" });
      return;
    }
    const risk = recomputeRisk(scanId);
    const stats = scanStats(scanId);
    db.prepare(
      "UPDATE scans SET status = 'done', progress = 100, phase = 'complete', finished_at = ?, risk_score = ?, stats_json = ? WHERE id = ?",
    ).run(now(), risk, JSON.stringify(stats), scanId);
    emit(scanId, "scan.done", `Scan complete · risk ${risk}/100 · ${stats.findings} findings`, { risk, stats }, {
      agent: "orchestrator",
    });
  } catch (err) {
    db.prepare("UPDATE scans SET status = 'failed', error = ?, finished_at = ?, phase = 'failed' WHERE id = ?").run(
      err.message.slice(0, 2000),
      now(),
      scanId,
    );
    emit(scanId, "scan.failed", `Scan failed: ${err.message}`, {}, { agent: "orchestrator", level: "error" });
  }
}

export async function llmReviewFindings(ctx, findings) {
  if (!findings.length) return [];
  const budget = ctx.config.llmReview !== false;
  if (!budget) return [];
  const batch = findings.slice(0, 10).map((f) => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    file: f.file,
    line: f.line,
    snippet: (f.snippet || "").slice(0, 1200),
    engine: f.engine,
  }));
  const result = await ctx.llm({
    agent: "critic",
    scanId: ctx.scan.id,
    system:
      "You are a senior application-security reviewer. Judge whether each finding is a real, reachable issue or a false positive. " +
      "Be conservative: only mark false_positive when the code clearly sanitizes or the sink is not reachable. " +
      "Return JSON: {\"verdicts\":[{\"id\":\"...\",\"verdict\":\"confirm|false_positive|needs_review\",\"confidence\":\"high|medium|low\",\"reason\":\"...\"}]}",
    user: wrapUntrusted("findings", JSON.stringify(batch), 30_000),
    maxTokens: 1600,
  });
  if (!result.ok || !Array.isArray(result.data?.verdicts)) return [];
  return result.data.verdicts;
}
