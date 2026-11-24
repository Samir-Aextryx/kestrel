import crypto from "node:crypto";
import { db, now } from "./db.js";
import { enqueue } from "./queue.js";
import { emit } from "./events.js";
import { complete, wrapUntrusted } from "./llm.js";
import { normalizeScope } from "./scope.js";
import { enginesFor, ENGINE_MAP } from "./engines/index.js";
import { scanStats } from "./store.js";
import { fireGoalWebhooks } from "./webhooks.js";

const DEFAULT_POLICY = {
  level: "supervised",
  max_concurrent: 2,
  max_requests: 500,
  max_cost: 1.5,
  max_duration_min: 60,
  allowed_types: ["code", "web", "api", "iac", "container", "binary", "mixed"],
  allowed_domains: [],
  auto_approve: 0,
  escalate_on: ["critical", "scope-expansion", "budget-80"],
};

export function getPolicy(workspaceId) {
  let row = db.prepare("SELECT * FROM policies WHERE workspace_id = ?").get(workspaceId);
  if (!row) {
    db.prepare(
      `INSERT INTO policies(workspace_id, level, max_concurrent, max_requests, max_cost, max_duration_min,
       allowed_types_json, allowed_domains_json, auto_approve, escalate_on_json, updated_at)
       VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      workspaceId,
      DEFAULT_POLICY.level,
      DEFAULT_POLICY.max_concurrent,
      DEFAULT_POLICY.max_requests,
      DEFAULT_POLICY.max_cost,
      DEFAULT_POLICY.max_duration_min,
      JSON.stringify(DEFAULT_POLICY.allowed_types),
      JSON.stringify(DEFAULT_POLICY.allowed_domains),
      DEFAULT_POLICY.auto_approve,
      JSON.stringify(DEFAULT_POLICY.escalate_on),
      now(),
    );
    row = db.prepare("SELECT * FROM policies WHERE workspace_id = ?").get(workspaceId);
  }
  return {
    workspaceId,
    level: row.level,
    maxConcurrent: row.max_concurrent,
    maxRequests: row.max_requests,
    maxCost: row.max_cost,
    maxDurationMin: row.max_duration_min,
    allowedTypes: JSON.parse(row.allowed_types_json),
    allowedDomains: JSON.parse(row.allowed_domains_json),
    autoApprove: Boolean(row.auto_approve),
    escalateOn: JSON.parse(row.escalate_on_json),
    updatedAt: row.updated_at,
  };
}

export function savePolicy(workspaceId, input) {
  getPolicy(workspaceId);
  const level = ["observe", "propose", "supervised", "autonomous"].includes(input.level) ? input.level : "supervised";
  db.prepare(
    `UPDATE policies SET level = ?, max_concurrent = ?, max_requests = ?, max_cost = ?, max_duration_min = ?,
     allowed_types_json = ?, allowed_domains_json = ?, auto_approve = ?, escalate_on_json = ?, updated_at = ?
     WHERE workspace_id = ?`,
  ).run(
    level,
    Math.max(1, Math.min(8, Number(input.maxConcurrent || 2))),
    Math.max(10, Math.min(20000, Number(input.maxRequests || 500))),
    Math.max(0, Math.min(100, Number(input.maxCost || 1.5))),
    Math.max(5, Math.min(1440, Number(input.maxDurationMin || 60))),
    JSON.stringify((input.allowedTypes || DEFAULT_POLICY.allowed_types).filter((t) => ["code", "web", "api", "iac", "container", "binary", "mixed"].includes(t))),
    JSON.stringify((input.allowedDomains || []).slice(0, 100)),
    input.autoApprove ? 1 : 0,
    JSON.stringify((input.escalateOn || DEFAULT_POLICY.escalate_on).slice(0, 20)),
    now(),
    workspaceId,
  );
  return getPolicy(workspaceId);
}

export function decide(goalId, scanId, actor, kind, rationale, confidence = "medium", data = {}) {
  const id = crypto.randomUUID();
  db.prepare(
    "INSERT INTO decisions(id, goal_id, scan_id, actor, kind, rationale, confidence, data_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
  ).run(id, goalId, scanId, actor, kind, String(rationale).slice(0, 6000), confidence, JSON.stringify(data), now());
  return id;
}

export function emitGoal(goalId, type, message, data = {}) {
  db.prepare("INSERT INTO goal_events(goal_id, type, message, data_json, created_at) VALUES(?, ?, ?, ?, ?)").run(
    goalId, type, String(message).slice(0, 2000), JSON.stringify(data), now(),
  );
  fireGoalWebhooks(goalId, { type, message, data, at: now() });
}

function defaultEngines(type, objective = "") {
  const all = enginesFor(type, {}).map((e) => e.id);
  const text = objective.toLowerCase();
  const picks = new Set();
  const add = (...ids) => ids.forEach((id) => all.includes(id) && picks.add(id));
  if (/secret|credential|key|token/.test(text)) add("secrets");
  if (/inject|taint|source|code|review|logic|auth/.test(text)) add("sast-js", "sast-python", "sast-go", "patch-diff");
  if (/depend|cve|supply|package|license|sbom/.test(text)) add("dependencies", "sbom", "licenses");
  if (/docker|container|image/.test(text)) add("container", "iac");
  if (/k8s|kubernetes|terraform|cloud|ci|pipeline|nginx/.test(text)) add("iac");
  if (/api|openapi|graphql|endpoint/.test(text)) add("api", "graphql");
  if (/web|header|tls|cookie|cors|surface/.test(text)) add("web", "tls");
  if (/fuzz|crash|robust/.test(text)) add("fuzz-js", "fuzz-python");
  if (/zero.?day|unknown|confirm|exploit|lab/.test(text)) add("zeroday");
  if (/binary|elf|pe|hardening/.test(text)) add("binary");
  return picks.size ? [...picks] : all;
}

async function planGoal(input, policy, actor) {
  const fallback = {
    engines: defaultEngines(input.targetType, input.objective),
    scope: input.targetType === "web" || input.targetType === "api"
      ? { allow: [new URL(input.target).hostname], ports: [443, 80], schemes: ["https", "http"], maxRequests: policy.maxRequests }
      : {},
    successCriteria: [
      "All selected engines complete or fail with a recorded reason",
      "Every high/critical finding is verified or explicitly unverified",
      "A signed report is generated",
    ],
    rationale: "Deterministic plan: all engines valid for the surface, policy budget applied.",
    estimatedRequests: input.targetType === "web" || input.targetType === "api" ? Math.min(policy.maxRequests, 350) : 0,
  };
  const result = await complete({
    agent: "orchestrator",
    system:
      "You are the autonomous planning controller of an authorized security-research platform. " +
      "Given an objective and hard policy, choose a minimal but sufficient engine set and a strict scope. " +
      "Only use engine IDs from the supplied list. Prefer fewer engines when the objective is narrow. " +
      'Return JSON: {"engines":["..."],"scope":{"allow":["host or cidr"],"ports":[443],"maxRequests":300},' +
      '"successCriteria":["..."],"rationale":"...","estimatedRequests":300}',
    user: wrapUntrusted(
      "goal",
      JSON.stringify({
        objective: input.objective,
        target: input.target,
        targetType: input.targetType,
        policy: { maxRequests: policy.maxRequests, maxCost: policy.maxCost, allowedTypes: policy.allowedTypes },
        availableEngines: defaultEngines(input.targetType, input.objective),
      }),
      12_000,
    ),
    maxTokens: 900,
  });
  if (!result.ok || !Array.isArray(result.data?.engines)) return fallback;
  const allowed = new Set(defaultEngines(input.targetType, input.objective));
  const engines = result.data.engines.filter((id) => allowed.has(id) && ENGINE_MAP.has(id));
  if (!engines.length) return fallback;
  const scope = result.data.scope && typeof result.data.scope === "object" ? result.data.scope : fallback.scope;
  return {
    engines,
    scope,
    successCriteria: Array.isArray(result.data.successCriteria) ? result.data.successCriteria.slice(0, 8) : fallback.successCriteria,
    rationale: String(result.data.rationale || "Model-selected plan").slice(0, 2000),
    estimatedRequests: Number(result.data.estimatedRequests || fallback.estimatedRequests),
    model: result.profile?.model,
  };
}

export async function createGoal(input, actor = "human", userId = null) {
  const workspaceId = input.workspaceId || db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1").get(userId)?.workspace_id;
  if (!workspaceId) throw new Error("no workspace");
  const policy = getPolicy(workspaceId);
  if (!policy.allowedTypes.includes(input.targetType)) throw new Error(`surface ${input.targetType} is not allowed by policy`);
  if (["web", "api"].includes(input.targetType)) {
    const url = new URL(input.target);
    if (policy.allowedDomains.length && !policy.allowedDomains.some((d) => url.hostname === d || url.hostname.endsWith(`.${d}`))) {
      throw new Error(`host ${url.hostname} is outside the policy allow-list`);
    }
  }
  if (["code", "binary", "iac", "mixed"].includes(input.targetType) && !input.projectId) {
    throw new Error("projectId is required for this surface");
  }
  const plan = await planGoal(input, policy, actor);
  const scope = normalizeScope({
    ...plan.scope,
    maxRequests: Math.min(policy.maxRequests, Number(input.maxRequests || plan.scope.maxRequests || policy.maxRequests)),
  });
  const id = crypto.randomUUID();
  const level = input.autonomyLevel || policy.level;
  const status = level === "observe" ? "planned" : "awaiting_approval";
  db.prepare(
    `INSERT INTO goals(id, workspace_id, title, objective, target, target_type, autonomy_level, status,
     constraints_json, plan_json, created_by, actor, deadline, budget_json, created_at, updated_at)
     VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    workspaceId,
    String(input.title || input.objective).slice(0, 160),
    String(input.objective).slice(0, 8000),
    input.target,
    input.targetType,
    level,
    status,
    JSON.stringify({ maxRequests: scope.maxRequests, maxCost: Math.min(policy.maxCost, Number(input.maxCost || policy.maxCost)), maxDurationMin: policy.maxDurationMin }),
    JSON.stringify({ ...plan, scope, projectId: input.projectId || null }),
    userId,
    actor,
    new Date(Date.now() + policy.maxDurationMin * 60_000).toISOString(),
    JSON.stringify({ maxRequests: scope.maxRequests, maxCost: Math.min(policy.maxCost, Number(input.maxCost || policy.maxCost)) }),
    now(),
    now(),
  );
  decide(id, null, actor, "plan", plan.rationale, "medium", { engines: plan.engines, scope, model: plan.model });
  emitGoal(id, "goal.created", `Goal created: ${input.title || input.objective}`, { status });
  if (level === "autonomous" || (level === "supervised" && policy.autoApprove)) {
    await startGoal(id, "policy:auto-approve");
  }
  return getGoal(id);
}

export async function startGoal(goalId, actor = "human") {
  const goal = db.prepare("SELECT * FROM goals WHERE id = ?").get(goalId);
  if (!goal) throw new Error("goal not found");
  if (!["planned", "awaiting_approval", "proposed"].includes(goal.status)) return getGoal(goalId);
  const policy = getPolicy(goal.workspace_id);
  const running = db.prepare("SELECT COUNT(*) AS n FROM goals WHERE workspace_id = ? AND status = 'running'").get(goal.workspace_id).n;
  if (running >= policy.maxConcurrent) {
    decide(goalId, null, actor, "defer", `Concurrency limit ${policy.maxConcurrent} reached; goal stays queued.`, "high");
    return getGoal(goalId);
  }
  const plan = JSON.parse(goal.plan_json);
  const budget = JSON.parse(goal.budget_json);
  const projectId = plan.projectId || null;
  const scanId = crypto.randomUUID();
  const scope = plan.scope || {};
  db.prepare(
    `INSERT INTO scans(id, project_id, workspace_id, name, target_type, target, scope_json, config_json, status, created_by, created_at)
     VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)`,
  ).run(
    scanId,
    projectId,
    goal.workspace_id,
    `[Goal] ${goal.title}`.slice(0, 160),
    goal.target_type,
    goal.target,
    JSON.stringify(scope),
    JSON.stringify({
      engines: plan.engines,
      goalId,
      autonomy: true,
      requireApproval: false,
      fuzzIterations: 160,
      labMaxFunctions: 6,
      maxCost: budget.maxCost,
    }),
    goal.created_by,
    now(),
  );
  db.prepare("UPDATE goals SET status = 'running', scan_id = ?, updated_at = ? WHERE id = ?").run(scanId, now(), goalId);
  decide(goalId, scanId, actor, "start", `Goal approved and scan ${scanId} queued with ${plan.engines.length} engines.`, "high", { scanId });
  enqueue("scan.run", { scanId }, scanId);
  return getGoal(goalId);
}

export function approveGoal(goalId, actor = "human") {
  const goal = db.prepare("SELECT * FROM goals WHERE id = ?").get(goalId);
  if (!goal) throw new Error("goal not found");
  decide(goalId, null, actor, "approve", "Goal approved by operator.", "high");
  return startGoal(goalId, actor);
}

export function rejectGoal(goalId, actor = "human", reason = "") {
  db.prepare("UPDATE goals SET status = 'rejected', outcome = ?, updated_at = ? WHERE id = ?").run(reason.slice(0, 2000), now(), goalId);
  decide(goalId, null, actor, "reject", reason || "Goal rejected.", "high");
  return getGoal(goalId);
}

export function getGoal(goalId) {
  const goal = db.prepare("SELECT * FROM goals WHERE id = ?").get(goalId);
  if (!goal) return null;
  return {
    ...goal,
    plan: JSON.parse(goal.plan_json),
    constraints: JSON.parse(goal.constraints_json),
    budget: JSON.parse(goal.budget_json),
    spent: JSON.parse(goal.spent_json),
    decisions: db.prepare("SELECT * FROM decisions WHERE goal_id = ? ORDER BY created_at").all(goalId),
    scan: goal.scan_id ? db.prepare("SELECT id, status, progress, phase, risk_score FROM scans WHERE id = ?").get(goal.scan_id) : null,
  };
}

export function listGoals(workspaceIds) {
  if (!workspaceIds.length) return [];
  const ph = workspaceIds.map(() => "?").join(",");
  return db
    .prepare(
      `SELECT g.*, (SELECT COUNT(*) FROM decisions d WHERE d.goal_id = g.id) AS decisions
       FROM goals g WHERE g.workspace_id IN (${ph}) ORDER BY g.created_at DESC LIMIT 100`,
    )
    .all(...workspaceIds)
    .map((g) => ({ ...g, plan: JSON.parse(g.plan_json), budget: JSON.parse(g.budget_json) }));
}

export async function autonomyTick() {
  const goals = db.prepare("SELECT * FROM goals WHERE status IN ('planned','awaiting_approval','running')").all();
  for (const goal of goals) {
    const policy = getPolicy(goal.workspace_id);
    if (goal.status === "planned" && (goal.autonomy_level === "autonomous" || (goal.autonomy_level === "supervised" && policy.autoApprove))) {
      await startGoal(goal.id, "policy:tick");
      continue;
    }
    if (goal.status === "awaiting_approval") {
      const age = Date.now() - new Date(goal.created_at).getTime();
      if (age > 30 * 60_000) {
        const existing = db.prepare("SELECT 1 FROM decisions WHERE goal_id = ? AND kind = 'escalate'").get(goal.id);
        if (!existing) decide(goal.id, null, "policy:tick", "escalate", "Goal has waited 30 minutes without a decision.", "high");
      }
      continue;
    }
    if (goal.status !== "running" || !goal.scan_id) continue;
    const scan = db.prepare("SELECT * FROM scans WHERE id = ?").get(goal.scan_id);
    if (!scan) continue;
    if (scan.status === "done") {
      const stats = scanStats(scan.id);
      const outcome = `${stats.findings} findings, ${stats.verified} verified, risk ${scan.risk_score}/100`;
      db.prepare("UPDATE goals SET status = 'complete', outcome = ?, updated_at = ? WHERE id = ?").run(outcome, now(), goal.id);
      decide(goal.id, scan.id, "policy:tick", "complete", `Goal completed: ${outcome}.`, "high", stats);
      emitGoal(goal.id, "goal.complete", `Goal complete: ${goal.title}`, { outcome });
      continue;
    }
    if (scan.status === "failed") {
      const retries = db.prepare("SELECT COUNT(*) AS n FROM decisions WHERE goal_id = ? AND kind = 'retry'").get(goal.id).n;
      if (retries < 1) {
        decide(goal.id, scan.id, "policy:tick", "retry", `Scan failed (${scan.error || "unknown"}); one automatic retry.`, "medium");
        const newScan = crypto.randomUUID();
        db.prepare(
          `INSERT INTO scans(id, project_id, workspace_id, name, target_type, target, scope_json, config_json, status, created_by, created_at)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)`,
        ).run(newScan, scan.project_id, scan.workspace_id, `${scan.name} · retry`, scan.target_type, scan.target, scan.scope_json, scan.config_json, goal.created_by, now());
        db.prepare("UPDATE goals SET scan_id = ?, updated_at = ? WHERE id = ?").run(newScan, now(), goal.id);
        enqueue("scan.run", { scanId: newScan }, newScan);
      } else {
        db.prepare("UPDATE goals SET status = 'failed', error = ?, updated_at = ? WHERE id = ?").run(scan.error || "scan failed", now(), goal.id);
        decide(goal.id, scan.id, "policy:tick", "fail", "Retry exhausted; goal failed.", "high");
      }
      continue;
    }
    const budget = JSON.parse(goal.budget_json);
    const llmCost = db.prepare("SELECT COALESCE(SUM(cost),0) AS c FROM llm_calls WHERE scan_id = ?").get(scan.id).c;
    const stats = scanStats(scan.id);
    db.prepare("UPDATE goals SET spent_json = ? WHERE id = ?").run(
      JSON.stringify({ requests: 0, cost: llmCost, findings: stats.findings, verified: stats.verified }),
      goal.id,
    );
    if (llmCost > budget.maxCost) {
      db.prepare("UPDATE scans SET status = 'cancelled', finished_at = ? WHERE id = ?").run(now(), scan.id);
      db.prepare("UPDATE goals SET status = 'budget_exceeded', updated_at = ? WHERE id = ?").run(now(), goal.id);
      decide(goal.id, scan.id, "policy:tick", "budget-stop", `Model cost ${llmCost.toFixed(3)} exceeded budget ${budget.maxCost}.`, "high");
      emit(scan.id, "scan.cancelled", "Cancelled by autonomy budget", {}, { agent: "orchestrator", level: "warn" });
    }
    if (goal.deadline && Date.now() > new Date(goal.deadline).getTime()) {
      db.prepare("UPDATE scans SET status = 'cancelled', finished_at = ? WHERE id = ?").run(now(), scan.id);
      db.prepare("UPDATE goals SET status = 'timed_out', updated_at = ? WHERE id = ?").run(now(), goal.id);
      decide(goal.id, scan.id, "policy:tick", "timeout", "Goal deadline exceeded.", "high");
    }
  }
}

export function autonomyStats(workspaceIds) {
  if (!workspaceIds.length) return { goals: 0, running: 0, awaiting: 0, decisions: 0 };
  const ph = workspaceIds.map(() => "?").join(",");
  return {
    goals: db.prepare(`SELECT COUNT(*) AS n FROM goals WHERE workspace_id IN (${ph})`).get(...workspaceIds).n,
    running: db.prepare(`SELECT COUNT(*) AS n FROM goals WHERE workspace_id IN (${ph}) AND status = 'running'`).get(...workspaceIds).n,
    awaiting: db.prepare(`SELECT COUNT(*) AS n FROM goals WHERE workspace_id IN (${ph}) AND status = 'awaiting_approval'`).get(...workspaceIds).n,
    decisions: db.prepare(`SELECT COUNT(*) AS n FROM decisions d JOIN goals g ON g.id = d.goal_id WHERE g.workspace_id IN (${ph})`).get(...workspaceIds).n,
  };
}
