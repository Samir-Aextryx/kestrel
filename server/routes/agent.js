import express from "express";
import crypto from "node:crypto";
import { db, now } from "../db.js";
import { randomToken, sha256 } from "../crypto.js";
import { createGoal } from "../autonomy.js";
import { requireRole } from "../auth.js";

const router = express.Router();

const TOOLS = [
  "kestrel_create_goal",
  "kestrel_start_research",
  "kestrel_get_goal",
  "kestrel_list_goals",
  "kestrel_approve_goal",
  "kestrel_get_scan",
  "kestrel_list_findings",
  "kestrel_get_research",
  "kestrel_get_poc",
  "kestrel_get_operations",
  "kestrel_list_credentials",
  "kestrel_list_payloads",
  "kestrel_retest_finding",
  "kestrel_export_report",
  "kestrel_get_coverage",
  "kestrel_get_policy",
  "kestrel_add_decision",
];

export function agentManifest(req) {
  const origin = `${req.protocol}://${req.get("host")}`;
  return {
    name: "kestrel",
    version: "1.1.0",
    description: "Autonomous, evidence-first security research. Goal-first API, MCP, signed reports.",
    origin,
    auth: { type: "bearer", header: "Authorization", prefix: "Bearer ", tokenPrefix: "kag_" },
    endpoints: {
      mcp: `${origin}/api/mcp`,
      goals: `${origin}/api/goals`,
      research: `${origin}/api/research/overview`,
      openapi: `${origin}/api/openapi.json`,
      health: `${origin}/api/health`,
    },
    tools: TOOLS,
    autonomyLevels: ["observe", "propose", "supervised", "autonomous"],
    quickstart: {
      method: "POST",
      path: "/api/agent/quickstart",
      body: { objective: "string", target: "string", targetType: "code|web|api|container|iac|binary|mixed", projectId: "optional" },
    },
    transports: ["http-jsonrpc", "rest", "sse"],
    limits: { maxConcurrentGoals: 8, maxRequestsPerGoal: 20000, maxCostPerGoal: 100 },
  };
}

router.get("/agent/manifest", (req, res) => res.json(agentManifest(req)));

router.get("/llms.txt", (req, res) => {
  const m = agentManifest(req);
  res.type("text/plain").send(`# KESTREL agent interface

KESTREL is an authorized security-research platform. Create a goal, not a scan.
The planner derives a hard scope and an engine set; a verifier reproduces findings.

## Connect
1. POST ${m.endpoints.goals.replace("/goals", "/agent/quickstart")} with objective, target, targetType.
2. Use the returned agent token as: Authorization: Bearer kag_...
3. Poll GET /api/goals/{id} or subscribe to the returned SSE URL.
4. Read findings with GET /api/scans/{scanId}/findings.
5. Download PoC bundles with GET /api/findings/{findingId}/poc.

## MCP
POST ${m.endpoints.mcp} with JSON-RPC 2.0. Tools: ${TOOLS.join(", ")}.

## Rules
- Scope is enforced by DNS pinning, allow/deny lists, port/scheme policy and a request budget.
- Findings marked verified survived a differential replay.
- Unverified findings are labeled.
- Reports are HMAC-signed.
`);
});

router.get("/agent/capabilities", (req, res) => {
  res.json(agentManifest(req));
});

router.post("/agent/quickstart", requireRole("admin", "analyst"), async (req, res) => {
  const { objective, target, targetType, projectId, autonomyLevel, maxRequests, maxCost } = req.body || {};
  if (!objective || !target || !targetType) return res.status(400).json({ error: "objective, target and targetType are required" });
  const workspace = db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1").get(req.user.id)?.workspace_id;
  if (!workspace) return res.status(400).json({ error: "no workspace" });
  const agentId = crypto.randomUUID();
  const name = `quickstart-${new Date().toISOString().slice(0, 16).replace(/\W/g, "")}`;
  const token = `kag_${randomToken(32)}`;
  db.prepare("INSERT INTO users(id, email, name, password_hash, role, created_at) VALUES(?, ?, ?, '!', 'analyst', ?)").run(
    agentId, `${agentId}@agent.local`, name, now(),
  );
  db.prepare(
    "INSERT INTO agent_identities(id, name, kind, description, token_hash, scopes_json, created_at) VALUES(?, ?, 'agent', ?, ?, ?, ?)",
  ).run(agentId, name, "Created by agent quickstart", sha256(token), JSON.stringify(["read", "write", "goals"]), now());
  db.prepare("INSERT OR IGNORE INTO workspace_members(workspace_id, user_id, role) VALUES(?, ?, 'analyst')").run(workspace, agentId);
  try {
    const goal = await createGoal(
      {
        title: String(objective).slice(0, 120),
        objective,
        target,
        targetType,
        projectId: projectId || null,
        workspaceId: workspace,
        autonomyLevel: autonomyLevel || "supervised",
        maxRequests,
        maxCost,
      },
      `agent:${name}`,
      agentId,
    );
    const origin = `${req.protocol}://${req.get("host")}`;
    res.status(201).json({
      agent: { id: agentId, name, token },
      goal,
      endpoints: {
        goal: `${origin}/api/goals/${goal.id}`,
        scan: goal.scan_id ? `${origin}/api/scans/${goal.scan_id}` : null,
        stream: goal.scan_id ? `${origin}/api/scans/${goal.scan_id}/stream` : null,
        findings: goal.scan_id ? `${origin}/api/scans/${goal.scan_id}/findings` : null,
        research: goal.scan_id ? `${origin}/api/research?scanId=${goal.scan_id}` : null,
        mcp: `${origin}/api/mcp`,
      },
      mcpConfig: {
        mcpServers: {
          kestrel: {
            type: "http",
            url: `${origin}/api/mcp`,
            headers: { Authorization: `Bearer ${token}` },
          },
        },
      },
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

export default router;
