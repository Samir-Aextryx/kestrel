import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(here, "..");
export const DATA_DIR = process.env.KESTREL_DATA_DIR
  ? path.resolve(process.env.KESTREL_DATA_DIR)
  : path.join(ROOT, "data");
export const PROJECTS_DIR = path.join(DATA_DIR, "projects");
export const REPORTS_DIR = path.join(DATA_DIR, "reports");
export const TMP_DIR = path.join(DATA_DIR, "tmp");
export const PLUGINS_DIR = path.join(ROOT, "plugins");
export const PORT = Number(process.env.PORT || 8787);
export const HOST = process.env.HOST || "127.0.0.1";
export const IS_PROD = process.env.NODE_ENV === "production";
export const VERSION = "1.0.0";
export const MAX_UPLOAD_BYTES = 80 * 1024 * 1024;
export const MAX_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_FILES = 8000;
export const SESSION_HOURS = 12;
export const SCAN_CONCURRENCY = Math.max(1, Number(process.env.KESTREL_SCAN_CONCURRENCY || 2));
export const ENGINE_TIMEOUT_MS = Number(process.env.KESTREL_ENGINE_TIMEOUT_MS || 120_000);
export const LLM_TIMEOUT_MS = Number(process.env.KESTREL_LLM_TIMEOUT_MS || 90_000);

function positiveNumber(name, fallback) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

// Express "trust proxy". Default off: trusting X-Forwarded-For without a real
// reverse proxy lets clients spoof their IP and bypass rate limits.
export const TRUST_PROXY = (() => {
  const raw = String(process.env.KESTREL_TRUST_PROXY || "").trim();
  if (!raw || raw === "false" || raw === "0") return false;
  if (raw === "true") return true;
  const hops = Number(raw);
  return Number.isInteger(hops) && hops >= 0 ? hops : raw;
})();

export const API_RATE_WINDOW_MS = positiveNumber("KESTREL_API_RATE_WINDOW_MS", 60_000);
export const API_RATE_MAX = positiveNumber("KESTREL_API_RATE_MAX", 600);
export const LOGIN_RATE_WINDOW_MS = positiveNumber("KESTREL_LOGIN_RATE_WINDOW_MS", 15 * 60_000);
export const LOGIN_IP_MAX = positiveNumber("KESTREL_LOGIN_IP_MAX", 60);
export const LOGIN_ACCOUNT_MAX = positiveNumber("KESTREL_LOGIN_ACCOUNT_MAX", 10);
export const JOB_MAX_ATTEMPTS = Math.max(1, positiveNumber("KESTREL_JOB_MAX_ATTEMPTS", 3));
export const JOB_RETRY_DELAY_MS = positiveNumber("KESTREL_JOB_RETRY_DELAY_MS", 5000);
export const JOB_RETENTION_DAYS = positiveNumber("KESTREL_JOB_RETENTION_DAYS", 14);
export const AUDIT_RETENTION_DAYS = positiveNumber("KESTREL_AUDIT_RETENTION_DAYS", 180);

for (const dir of [DATA_DIR, PROJECTS_DIR, REPORTS_DIR, TMP_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

export function masterKey() {
  const file = path.join(DATA_DIR, "master.key");
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, crypto.randomBytes(32), { mode: 0o600 });
  }
  return fs.readFileSync(file);
}

export function reportKey() {
  const file = path.join(DATA_DIR, "report.key");
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, crypto.randomBytes(32), { mode: 0o600 });
  }
  return fs.readFileSync(file);
}

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const SEVERITY_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 0.2 };
export const CONFIDENCE_WEIGHT = { high: 1, medium: 0.65, low: 0.35 };

export const TARGET_TYPES = [
  "code",
  "web",
  "api",
  "container",
  "iac",
  "binary",
  "mixed",
];

export const AGENTS = [
  "orchestrator",
  "recon",
  "code",
  "secrets",
  "supply",
  "iac",
  "api",
  "fuzz",
  "zeroday",
  "exploit",
  "foothold",
  "credentials",
  "plugins",
  "verifier",
  "critic",
  "correlator",
  "reporter",
  "optimizer",
];

export const AGENT_LABELS = {
  orchestrator: "Orchestrator",
  recon: "Recon",
  code: "Code Analyst",
  secrets: "Secret Hunter",
  supply: "Supply Chain",
  iac: "Cloud & IaC",
  api: "API Analyst",
  fuzz: "Fuzz Strategist",
  zeroday: "Zero-Day Lab",
  exploit: "Exploit Verifier",
  foothold: "Foothold Operator",
  credentials: "Credential Analyst",
  plugins: "Plugin Runtime",
  verifier: "Verifier",
  critic: "Critic",
  correlator: "Correlator",
  reporter: "Reporter",
  optimizer: "Optimizer",
};
