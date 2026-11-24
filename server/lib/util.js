import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import AdmZip from "adm-zip";
import { MAX_FILES, MAX_FILE_BYTES } from "../config.js";
import { sha256 } from "../crypto.js";

export const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "out",
  ".next",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
  ".idea",
  ".vscode",
  "target",
  "bin",
  "obj",
  ".cache",
]);

const LANG_BY_EXT = {
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".py": "python",
  ".go": "go",
  ".rb": "ruby",
  ".php": "php",
  ".java": "java",
  ".kt": "kotlin",
  ".cs": "csharp",
  ".rs": "rust",
  ".c": "c",
  ".h": "c",
  ".cpp": "cpp",
  ".hpp": "cpp",
  ".swift": "swift",
  ".scala": "scala",
  ".sh": "shell",
  ".ps1": "powershell",
  ".sql": "sql",
  ".yml": "yaml",
  ".yaml": "yaml",
  ".json": "json",
  ".toml": "toml",
  ".xml": "xml",
  ".html": "html",
  ".css": "css",
  ".tf": "terraform",
  ".tfvars": "terraform",
  ".dockerfile": "dockerfile",
  ".md": "markdown",
  ".env": "dotenv",
};

export function languageOf(file) {
  const base = path.basename(file).toLowerCase();
  if (base === "dockerfile" || base.startsWith("dockerfile.")) return "dockerfile";
  if (base === "makefile") return "makefile";
  if (base === ".env" || base.startsWith(".env.")) return "dotenv";
  return LANG_BY_EXT[path.extname(base)] || "text";
}

export function isTextLanguage(lang) {
  return !["binary", "text"].includes(lang);
}

export async function walkFiles(root, options = {}) {
  const maxFiles = options.maxFiles || MAX_FILES;
  const maxBytes = options.maxBytes || MAX_FILE_BYTES;
  const files = [];
  const stack = [root];
  while (stack.length && files.length < maxFiles) {
    const dir = stack.pop();
    let entries;
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.name.startsWith(".kestrel")) continue;
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      let stat;
      try {
        stat = await fsp.stat(full);
      } catch {
        continue;
      }
      if (stat.size > maxBytes) continue;
      files.push({
        abs: full,
        rel: path.relative(root, full).split(path.sep).join("/"),
        size: stat.size,
        lang: languageOf(full),
      });
      if (files.length >= maxFiles) break;
    }
  }
  return files;
}

export function safeJoin(root, rel) {
  const resolved = path.resolve(root, rel);
  const normalizedRoot = path.resolve(root);
  if (resolved !== normalizedRoot && !resolved.startsWith(normalizedRoot + path.sep)) {
    throw new Error(`path escapes root: ${rel}`);
  }
  return resolved;
}

export function extractZip(buffer, destination) {
  const zip = new AdmZip(buffer);
  const entries = zip.getEntries();
  if (entries.length > MAX_FILES * 1.5) throw new Error("archive has too many entries");
  let total = 0;
  for (const entry of entries) {
    const name = entry.entryName.replace(/\\/g, "/");
    if (name.startsWith("__MACOSX/") || name.endsWith("/")) continue;
    const target = safeJoin(destination, name);
    if (entry.header.size > MAX_FILE_BYTES * 2) continue;
    total += entry.header.size;
    if (total > 200 * 1024 * 1024) throw new Error("archive expands beyond 200 MiB");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, entry.getData());
  }
  return entries.length;
}

export function flattenProjectRoot(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  if (entries.length === 1 && entries[0].isDirectory()) {
    const inner = path.join(dir, entries[0].name);
    if (fs.readdirSync(inner).length > 0) return inner;
  }
  return dir;
}

export function lineAt(text, line) {
  return String(text).split(/\r?\n/)[line - 1] || "";
}

export function snippetAt(text, line, radius = 3) {
  const lines = String(text).split(/\r?\n/);
  const start = Math.max(0, line - 1 - radius);
  const end = Math.min(lines.length, line + radius);
  return lines
    .slice(start, end)
    .map((value, idx) => `${String(start + idx + 1).padStart(5)} | ${value}`)
    .join("\n");
}

export function fingerprint(engine, ruleId, file, line, extra = "") {
  const normalized = `${engine}|${ruleId}|${file || ""}|${line || 0}|${String(extra).replace(/\s+/g, " ").trim().slice(0, 240)}`;
  return sha256(normalized);
}

export function findingHash(finding) {
  return sha256(
    JSON.stringify({
      engine: finding.engine,
      rule: finding.ruleId,
      file: finding.file,
      line: finding.line,
      title: finding.title,
      evidence: finding.evidence,
    }),
  );
}

const CVSS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27 },
  UI: { N: 0.85, R: 0.62 },
  S: { U: 0, C: 0 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};

export function cvssFromVector(vector) {
  const parts = Object.fromEntries(
    String(vector || "")
      .split("/")
      .map((p) => p.split(":"))
      .filter((p) => p.length === 2),
  );
  if (!parts.AV || !parts.AC || !parts.PR || !parts.UI || !parts.S || !parts.C || !parts.I || !parts.A) {
    return null;
  }
  const changed = parts.S === "C";
  const pr = changed ? { N: 0.85, L: 0.68, H: 0.5 }[parts.PR] : CVSS.PR[parts.PR];
  const iss = 1 - (1 - CVSS.C[parts.C]) * (1 - CVSS.I[parts.I]) * (1 - CVSS.A[parts.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploit = 8.22 * CVSS.AV[parts.AV] * CVSS.AC[parts.AC] * pr * CVSS.UI[parts.UI];
  if (impact <= 0) return 0;
  const base = changed
    ? Math.min(10, 1.08 * (impact + exploit))
    : Math.min(10, impact + exploit);
  return Math.ceil(base * 10) / 10;
}

export function severityFromScore(score) {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

export function severityScore(severity) {
  return { critical: 9.5, high: 7.8, medium: 5.4, low: 2.6, info: 0.3 }[severity] ?? 0;
}

export function redactSecret(value) {
  const s = String(value);
  if (s.length <= 8) return `${s.slice(0, 2)}${"•".repeat(Math.max(2, s.length - 2))}`;
  return `${s.slice(0, 4)}${"•".repeat(Math.min(18, s.length - 8))}${s.slice(-4)}`;
}

export function entropy(value) {
  const counts = new Map();
  for (const ch of String(value)) counts.set(ch, (counts.get(ch) || 0) + 1);
  let e = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    e -= p * Math.log2(p);
  }
  return e;
}

export function normalizeSeverity(value) {
  const v = String(value || "").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(v)) return v;
  return "medium";
}

export function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

export function parseJsonLoose(text) {
  if (!text) return null;
  const cleaned = String(text)
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/```\s*$/, "")
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(cleaned.slice(start, end + 1));
      } catch {
        return null;
      }
    }
    return null;
  }
}

export function truncate(value, max = 4000) {
  const s = String(value ?? "");
  return s.length > max ? `${s.slice(0, max)}\n…[truncated ${s.length - max} chars]` : s;
}

export function randomId() {
  return crypto.randomUUID();
}

export function mimeOf(file) {
  const ext = path.extname(file).toLowerCase();
  return (
    {
      ".html": "text/html",
      ".css": "text/css",
      ".js": "text/javascript",
      ".json": "application/json",
      ".svg": "image/svg+xml",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".webp": "image/webp",
      ".ico": "image/x-icon",
      ".woff2": "font/woff2",
    }[ext] || "application/octet-stream"
  );
}

export function slug(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 60);
}
