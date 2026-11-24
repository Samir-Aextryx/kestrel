import express from "express";
import cookieParser from "cookie-parser";
import path from "node:path";
import fs from "node:fs";
import {
  PORT,
  HOST,
  ROOT,
  IS_PROD,
  VERSION,
  TRUST_PROXY,
  API_RATE_MAX,
  API_RATE_WINDOW_MS,
  AUDIT_RETENTION_DAYS,
} from "./config.js";
import { seedAdmin, requireAuth, requireCsrf, publicUser, sweepLoginLimiters } from "./auth.js";
import { db, audit } from "./db.js";
import { recoverJobs, queueStats, registerJob, pruneJobs, stop as stopQueue } from "./queue.js";
import { heartbeat } from "./events.js";
import { runScan } from "./scan.js";
import { createRateLimiter } from "./lib/ratelimit.js";
import authRoutes from "./routes/auth.js";
import projectRoutes from "./routes/projects.js";
import scanRoutes from "./routes/scans.js";
import findingRoutes from "./routes/findings.js";
import systemRoutes from "./routes/system.js";
import pluginRoutes from "./routes/plugins.js";
import benchmarkRoutes from "./routes/benchmark.js";
import { runBenchmark } from "./routes/benchmark.js";
import autonomyRoutes from "./routes/autonomy.js";
import mcpRoutes from "./routes/mcp.js";
import openapiRoutes from "./routes/openapi.js";
import researchRoutes from "./routes/research.js";
import agentRoutes, { agentManifest } from "./routes/agent.js";
import operationRoutes from "./routes/operations.js";
import { installBuiltinPlugins } from "./plugins.js";
import { autonomyTick } from "./autonomy.js";

const app = express();
app.disable("x-powered-by");
// Off by default: only trust X-Forwarded-For when a real proxy is in front.
app.set("trust proxy", TRUST_PROXY);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  );
  if (req.secure) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));
app.use(cookieParser());

app.get("/api/health", (req, res) => {
  res.json({ ok: true, version: VERSION, uptime: process.uptime(), queue: queueStats() });
});

const apiLimiter = createRateLimiter({ windowMs: API_RATE_WINDOW_MS, max: API_RATE_MAX });
const apiRateLimit = apiLimiter.middleware();
app.use("/api", (req, res, next) => {
  // API responses can contain findings, tokens and evidence: never cache them.
  res.setHeader("Cache-Control", "no-store");
  apiRateLimit(req, res, next);
});

app.get("/.well-known/agent.json", (req, res) => res.json(agentManifest(req)));
app.get("/llms.txt", (req, res) => {
  const m = agentManifest(req);
  res.type("text/plain").send(`# KESTREL agent interface\n\nGoal-first security research. MCP: ${m.endpoints.mcp}\nTools: ${m.tools.join(", ")}\nAuth: Authorization: Bearer kag_...\n`);
});

app.use("/api", openapiRoutes);
app.use("/api/auth", authRoutes);

app.use("/api", requireAuth);
app.use("/api", (req, res, next) => {
  if (req.auth?.via !== "agent") return next();
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  if (!req.auth.scopes.includes("write")) return res.status(403).json({ error: "agent token lacks write scope" });
  next();
});
app.use("/api", (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  return requireCsrf(req, res, next);
});

app.get("/api/me", (req, res) => {
  res.json({ user: publicUser(req.user), csrf: req.auth.csrf || null });
});

app.use("/api", projectRoutes);
app.use("/api", scanRoutes);
app.use("/api", findingRoutes);
app.use("/api", systemRoutes);
app.use("/api", pluginRoutes);
app.use("/api", benchmarkRoutes);
app.use("/api", autonomyRoutes);
app.use("/api", mcpRoutes);
app.use("/api", researchRoutes);
app.use("/api", agentRoutes);
app.use("/api", operationRoutes);

app.use("/api", (req, res) => res.status(404).json({ error: "not found" }));

const publicDir = path.join(ROOT, "server", "public");
if (fs.existsSync(publicDir)) {
  app.use(
    express.static(publicDir, {
      index: false,
      maxAge: IS_PROD ? "1y" : 0,
      immutable: IS_PROD,
      setHeaders(res, file) {
        if (file.endsWith("index.html")) res.setHeader("Cache-Control", "no-cache");
      },
    }),
  );
  app.get(/^\/(?!api).*/, (req, res) => {
    res.sendFile(path.join(publicDir, "index.html"));
  });
} else {
  app.get("/", (req, res) => {
    res.type("text/plain").send("KESTREL API is running. Build the UI with `npm run build`.");
  });
}

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  const status = err.status || 500;
  res.status(status).json({ error: status === 500 ? "internal error" : err.message });
});

registerJob("scan.run", async (payload) => {
  await runScan(payload.scanId);
});
registerJob("benchmark.run", async (payload) => {
  await runBenchmark(payload);
});

const seeded = seedAdmin();
installBuiltinPlugins();
recoverJobs();
setInterval(heartbeat, 20_000).unref();
setInterval(() => autonomyTick().catch((err) => console.error("[autonomy]", err.message)), 15_000).unref();
setInterval(() => {
  db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(new Date().toISOString());
}, 3600_000).unref();
setInterval(() => {
  apiLimiter.sweep();
  sweepLoginLimiters();
}, 60_000).unref();
setInterval(() => {
  const removed = pruneJobs();
  if (removed) console.log(`[queue] pruned ${removed} finished job(s)`);
}, 3600_000).unref();
setInterval(() => {
  db.prepare("DELETE FROM audit_log WHERE created_at < ?").run(
    new Date(Date.now() - AUDIT_RETENTION_DAYS * 86_400_000).toISOString(),
  );
}, 24 * 3600_000).unref();

const server = app.listen(PORT, HOST, () => {
  console.log(`\n  KESTREL ${VERSION}`);
  console.log(`  → http://${HOST}:${PORT}\n`);
  if (seeded) {
    console.log("  First-run administrator created:");
    console.log(`  email:    ${seeded.email}`);
    console.log(`  password: ${seeded.password}`);
    console.log("  Store the password now; it is not printed again.\n");
  }
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n${signal}: shutting down…`);
  const hardStop = setTimeout(() => process.exit(1), 15_000);
  hardStop.unref();
  server.close();
  server.closeIdleConnections?.();
  const drained = await stopQueue({ timeoutMs: 10_000 });
  if (!drained) {
    console.warn("[queue] drain timed out; unfinished jobs will be recovered on next start");
  }
  process.exit(drained ? 0 : 1);
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
