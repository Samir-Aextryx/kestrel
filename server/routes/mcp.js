import express from "express";
import { db } from "../db.js";
import { requireAuth } from "../auth.js";
import { approveGoal, createGoal, decide, getGoal, getPolicy, listGoals } from "../autonomy.js";
import { getFinding, listFindings, scanStats } from "../store.js";
import { createReport } from "../reports.js";
import { attackPaths } from "../store.js";
import { retestFinding } from "../retest.js";
import fsp from "node:fs/promises";
import path from "node:path";
import { safeJoin } from "../lib/util.js";
import { publicPayloads } from "../lib/payloads.js";

const router = express.Router();

const TOOLS = [
  {
    name: "kestrel_create_goal",
    description: "Create an autonomous research goal. The planner selects engines and a hard scope from the objective. Depending on policy the goal starts immediately or waits for approval.",
    inputSchema: {
      type: "object",
      required: ["objective", "target", "targetType"],
      properties: {
        objective: { type: "string", description: "What should be proven or found" },
        target: { type: "string", description: "URL, image reference or project id" },
        targetType: { type: "string", enum: ["code", "web", "api", "container", "iac", "binary", "mixed"] },
        projectId: { type: "string" },
        autonomyLevel: { type: "string", enum: ["observe", "propose", "supervised", "autonomous"] },
        maxRequests: { type: "number" },
        maxCost: { type: "number" },
      },
    },
  },
  {
    name: "kestrel_get_goal",
    description: "Read a goal, its plan, decisions, budget and linked scan.",
    inputSchema: { type: "object", required: ["goalId"], properties: { goalId: { type: "string" } } },
  },
  {
    name: "kestrel_list_goals",
    description: "List recent goals in accessible workspaces.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "kestrel_approve_goal",
    description: "Approve a waiting goal and start its scan.",
    inputSchema: { type: "object", required: ["goalId"], properties: { goalId: { type: "string" } } },
  },
  {
    name: "kestrel_get_scan",
    description: "Read scan status, stats and attack paths.",
    inputSchema: { type: "object", required: ["scanId"], properties: { scanId: { type: "string" } } },
  },
  {
    name: "kestrel_list_findings",
    description: "List findings for a scan, optionally filtered by severity.",
    inputSchema: {
      type: "object",
      required: ["scanId"],
      properties: {
        scanId: { type: "string" },
        severity: { type: "array", items: { type: "string" } },
        verified: { type: "boolean" },
        limit: { type: "number" },
      },
    },
  },
  {
    name: "kestrel_retest_finding",
    description: "Replay a finding's verification (file line, HTTP request or manifest version).",
    inputSchema: { type: "object", required: ["findingId"], properties: { findingId: { type: "string" } } },
  },
  {
    name: "kestrel_export_report",
    description: "Generate a signed report (md, html, json, sarif) and return its id.",
    inputSchema: {
      type: "object",
      required: ["scanId"],
      properties: { scanId: { type: "string" }, format: { type: "string", enum: ["md", "html", "json", "sarif"] } },
    },
  },
  {
    name: "kestrel_get_coverage",
    description: "Read per-file finding coverage for a scan.",
    inputSchema: { type: "object", required: ["scanId"], properties: { scanId: { type: "string" } } },
  },
  {
    name: "kestrel_get_policy",
    description: "Read the current autonomy policy and hard caps.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "kestrel_start_research",
    description: "Create and immediately start a research goal (supervised by default) with the zero-day lab and verifier.",
    inputSchema: {
      type: "object",
      required: ["objective", "target", "targetType"],
      properties: {
        objective: { type: "string" },
        target: { type: "string" },
        targetType: { type: "string", enum: ["code", "web", "api", "container", "iac", "binary", "mixed"] },
        projectId: { type: "string" },
        maxRequests: { type: "number" },
        maxCost: { type: "number" },
      },
    },
  },
  {
    name: "kestrel_get_research",
    description: "Read hypotheses, confirmed zero-days, family counts and corpus stats for a scan.",
    inputSchema: { type: "object", required: ["scanId"], properties: { scanId: { type: "string" } } },
  },
  {
    name: "kestrel_list_hypotheses",
    description: "List research hypotheses for a scan, optionally by status or family.",
    inputSchema: {
      type: "object",
      required: ["scanId"],
      properties: { scanId: { type: "string" }, status: { type: "string" }, family: { type: "string" } },
    },
  },
  {
    name: "kestrel_get_poc",
    description: "Read the reproducible PoC bundle and source for a confirmed finding.",
    inputSchema: { type: "object", required: ["findingId"], properties: { findingId: { type: "string" } } },
  },
  {
    name: "kestrel_get_operations",
    description: "Read system nodes, credentials, exploit runs and foothold status for a scan.",
    inputSchema: { type: "object", required: ["scanId"], properties: { scanId: { type: "string" } } },
  },
  {
    name: "kestrel_list_credentials",
    description: "List credentials found or validated for a scan.",
    inputSchema: { type: "object", required: ["scanId"], properties: { scanId: { type: "string" } } },
  },
  {
    name: "kestrel_list_payloads",
    description: "List the built-in safe exploit payload families.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "kestrel_add_decision",
    description: "Append a machine decision with rationale to a goal.",
    inputSchema: {
      type: "object",
      required: ["goalId", "kind", "rationale"],
      properties: { goalId: { type: "string" }, kind: { type: "string" }, rationale: { type: "string" } },
    },
  },
];

function workspaces(userId) {
  return db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ?").all(userId).map((r) => r.workspace_id);
}

function assertScan(userId, scanId) {
  const scan = db
    .prepare(
      `SELECT s.* FROM scans s JOIN workspace_members m ON m.workspace_id = s.workspace_id
       WHERE s.id = ? AND m.user_id = ?`,
    )
    .get(scanId, userId);
  if (!scan) throw new Error("scan not found");
  return scan;
}

async function callTool(name, args, req) {
  const actor = req.auth.via === "agent" ? `agent:${req.user.name}` : `human:${req.user.email}`;
  switch (name) {
    case "kestrel_create_goal":
      return createGoal({ ...args, workspaceId: workspaces(req.user.id)[0] }, actor, req.user.id);
    case "kestrel_get_goal": {
      const goal = getGoal(args.goalId);
      if (!goal || !workspaces(req.user.id).includes(goal.workspace_id)) throw new Error("goal not found");
      return goal;
    }
    case "kestrel_list_goals":
      return listGoals(workspaces(req.user.id));
    case "kestrel_approve_goal":
      return approveGoal(args.goalId, actor);
    case "kestrel_get_scan": {
      const scan = assertScan(req.user.id, args.scanId);
      return {
        ...scan,
        stats: scanStats(scan.id),
        paths: attackPaths(scan.id),
      };
    }
    case "kestrel_list_findings":
      assertScan(req.user.id, args.scanId);
      return listFindings(args.scanId, {
        severity: args.severity,
        verified: args.verified,
        limit: args.limit || 100,
      });
    case "kestrel_retest_finding": {
      const finding = getFinding(args.findingId);
      if (!finding) throw new Error("finding not found");
      return retestFinding(finding.id, actor);
    }
    case "kestrel_export_report": {
      assertScan(req.user.id, args.scanId);
      return createReport(args.scanId, args.format || "json", req.user.id);
    }
    case "kestrel_get_coverage": {
      assertScan(req.user.id, args.scanId);
      return db
        .prepare(
          `SELECT file, COUNT(*) AS findings, SUM(verified) AS verified FROM findings
           WHERE scan_id = ? AND file IS NOT NULL GROUP BY file ORDER BY findings DESC`,
        )
        .all(args.scanId);
    }
    case "kestrel_get_policy":
      return getPolicy(workspaces(req.user.id)[0]);
    case "kestrel_start_research": {
      const goal = await createGoal(
        { ...args, autonomyLevel: args.autonomyLevel || "supervised", workspaceId: workspaces(req.user.id)[0] },
        actor,
        req.user.id,
      );
      if (goal.status === "awaiting_approval" || goal.status === "planned") return approveGoal(goal.id, actor);
      return goal;
    }
    case "kestrel_get_research": {
      assertScan(req.user.id, args.scanId);
      const hypotheses = db
        .prepare("SELECT * FROM research_hypotheses WHERE scan_id = ? ORDER BY exploitability DESC LIMIT 500")
        .all(args.scanId)
        .map((h) => ({ ...h, evidence: JSON.parse(h.evidence_json || "{}") }));
      return {
        confirmed: hypotheses.filter((h) => h.status === "confirmed").length,
        rejected: hypotheses.filter((h) => h.status === "rejected").length,
        hypotheses,
      };
    }
    case "kestrel_list_hypotheses": {
      assertScan(req.user.id, args.scanId);
      const where = ["scan_id = ?"];
      const params = [args.scanId];
      if (args.status) {
        where.push("status = ?");
        params.push(args.status);
      }
      if (args.family) {
        where.push("family = ?");
        params.push(args.family);
      }
      return db.prepare(`SELECT * FROM research_hypotheses WHERE ${where.join(" AND ")} ORDER BY exploitability DESC LIMIT 500`).all(...params);
    }
    case "kestrel_get_poc": {
      const finding = getFinding(args.findingId);
      if (!finding) throw new Error("finding not found");
      const scan = assertScan(req.user.id, finding.scanId);
      const project = scan.project_id ? db.prepare("SELECT path FROM projects WHERE id = ?").get(scan.project_id) : null;
      if (!project || !finding.evidence?.poc) throw new Error("no PoC bundle");
      const bundle = JSON.parse(await fsp.readFile(safeJoin(project.path, finding.evidence.poc), "utf8"));
      const code = finding.evidence.pocCode
        ? await fsp.readFile(safeJoin(project.path, finding.evidence.pocCode), "utf8").catch(() => null)
        : null;
      return { ...bundle, code };
    }
    case "kestrel_get_operations": {
      assertScan(req.user.id, args.scanId);
      return {
        nodes: db.prepare("SELECT * FROM system_nodes WHERE scan_id = ? ORDER BY kind").all(args.scanId),
        credentials: db.prepare("SELECT * FROM credentials WHERE scan_id = ?").all(args.scanId),
        runs: db.prepare("SELECT * FROM exploit_runs WHERE scan_id = ? ORDER BY created_at DESC LIMIT 300").all(args.scanId),
      };
    }
    case "kestrel_list_credentials": {
      assertScan(req.user.id, args.scanId);
      return db.prepare("SELECT * FROM credentials WHERE scan_id = ? ORDER BY valid DESC").all(args.scanId);
    }
    case "kestrel_list_payloads":
      return publicPayloads();
    case "kestrel_add_decision":
      return { id: decide(args.goalId, null, actor, args.kind, args.rationale, "medium") };
    default:
      throw new Error(`unknown tool ${name}`);
  }
}

router.post("/mcp", requireAuth, async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};
  if (jsonrpc !== "2.0") return res.status(400).json({ jsonrpc: "2.0", id, error: { code: -32600, message: "invalid request" } });
  try {
    if (method === "initialize") {
      return res.json({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "kestrel", version: "1.0.0" },
        },
      });
    }
    if (method === "ping") return res.json({ jsonrpc: "2.0", id, result: {} });
    if (method === "tools/list") return res.json({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    if (method === "tools/call") {
      const name = params?.name;
      if (!TOOLS.some((t) => t.name === name)) throw new Error(`unknown tool ${name}`);
      const result = await callTool(name, params?.arguments || {}, req);
      return res.json({
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          structuredContent: result,
        },
      });
    }
    res.json({ jsonrpc: "2.0", id, error: { code: -32601, message: "method not found" } });
  } catch (err) {
    res.json({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: err.message }], isError: true } });
  }
});

router.get("/mcp", (req, res) => {
  res.json({ name: "kestrel", version: "1.0.0", transport: "http-jsonrpc", tools: TOOLS.map((t) => t.name) });
});

export default router;
