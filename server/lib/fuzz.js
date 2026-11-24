import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import crypto from "node:crypto";
import { ROOT, TMP_DIR } from "../config.js";

const TOKENS = [
  "", "a", "A", "0", "-1", "1", "2", "255", "65535", "2147483647", "2147483648",
  "true", "false", "null", "undefined", "NaN", "Infinity", "-Infinity",
  " ", "  ", "\t", "\n", "\r\n", "\0", "%00", "%2e%2e%2f", "../", "../../",
  "../../../../etc/passwd", "..\\..\\windows\\win.ini", "/etc/passwd", "C:\\Windows\\win.ini",
  "'", "\"", "`", "' OR 1=1--", "\" OR \"\"=\"", "1; SELECT 1", "'; DROP TABLE users;--",
  "$(id)", "`id`", "| id", "&& id", "; id", "ping -c 1 127.0.0.1",
  "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><svg/onload=alert(1)>",
  "javascript:alert(1)", "{{7*7}}", "${7*7}", "#{7*7}", "%3Cscript%3E",
  "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
  "https://example.com", "//evil.example", "http://[::1]:80/",
  "__proto__", "constructor", "prototype", "toString", "valueOf",
  "admin", "root", "test@example.com", "A".repeat(64), "A".repeat(1024), "A".repeat(8192),
  "😀", "ü", "日本語", "\u202e", "a".repeat(100) + "!",
  "{}", "[]", '{"a":1}', '{"__proto__":{"polluted":true}}', "[1,2,3]",
  "0e0", "1e309", "0x10", "010", "1.1.1.1", "::1", "a-b_c.d",
];

const NAME_HINTS = {
  path: ["file", "path", "filename", "dir", "folder", "name"],
  url: ["url", "uri", "endpoint", "host", "target", "link"],
  sql: ["sql", "query", "where", "filter"],
  cmd: ["cmd", "command", "exec", "args", "shell"],
  html: ["html", "markup", "template", "content"],
  body: ["body", "data", "payload", "input", "json", "obj", "options"],
  number: ["id", "count", "limit", "size", "page", "offset", "port", "n", "num", "index"],
};

function hint(name = "") {
  const lower = name.toLowerCase();
  for (const [kind, words] of Object.entries(NAME_HINTS)) {
    if (words.some((w) => lower === w || lower.includes(w))) return kind;
  }
  return "any";
}

function tokenFor(kind) {
  const pool = {
    path: TOKENS.filter((t) => /etc|win\.ini|\.\.|%2e|\/|\\/.test(t)),
    url: TOKENS.filter((t) => /http|file:|::1|169\.254/.test(t)),
    sql: TOKENS.filter((t) => /OR|SELECT|DROP|'/.test(t)),
    cmd: TOKENS.filter((t) => /id|\||&&|;|ping/.test(t)),
    html: TOKENS.filter((t) => /script|img|svg|javascript/.test(t)),
    body: TOKENS.filter((t) => /^\{|^\[|proto/.test(t)),
    number: ["0", "-1", "1", "2", "255", "65535", "2147483647", "2147483648", "1e309", "NaN"],
    any: TOKENS,
  }[kind] || TOKENS;
  return pool[Math.floor(Math.random() * pool.length)];
}

export function generateValue(kind, depth = 0) {
  const roll = Math.random();
  if (depth < 2 && roll < 0.12) {
    const obj = {};
    const count = 1 + Math.floor(Math.random() * 3);
    for (let i = 0; i < count; i += 1) {
      obj[Math.random() < 0.2 ? "__proto__" : `k${i}`] = generateValue("any", depth + 1);
    }
    return obj;
  }
  if (depth < 2 && roll < 0.2) {
    return Array.from({ length: Math.floor(Math.random() * 4) }, () => generateValue("any", depth + 1));
  }
  if (roll < 0.28) return Math.floor(Math.random() * 1000) - 10;
  if (roll < 0.32) return Math.random() < 0.5;
  if (roll < 0.36) return null;
  if (roll < 0.39) return undefined;
  return tokenFor(kind);
}

export function seedCorpus(params) {
  const kinds = params.map((p) => hint(p));
  const seeds = [];
  const make = (values) => values.slice(0, params.length);
  seeds.push(make(params.map(() => "")));
  seeds.push(make(params.map((_, i) => (kinds[i] === "number" ? 1 : "a"))));
  seeds.push(make(params.map((_, i) => tokenFor(kinds[i]))));
  for (const token of TOKENS.slice(0, 40)) {
    seeds.push(make(params.map((_, i) => (kinds[i] === "number" && /^\d+$/.test(token) ? Number(token) : token))));
  }
  return seeds;
}

export function mutate(args, params) {
  const next = structuredClone(args);
  const idx = next.length ? Math.floor(Math.random() * next.length) : 0;
  const kind = hint(params[idx] || "");
  const op = Math.random();
  if (op < 0.35) next[idx] = tokenFor(kind);
  else if (op < 0.55 && typeof next[idx] === "string") {
    const pos = Math.floor(Math.random() * (next[idx].length + 1));
    next[idx] = next[idx].slice(0, pos) + tokenFor(kind) + next[idx].slice(pos);
  } else if (op < 0.7 && typeof next[idx] === "string" && next[idx].length) {
    const pos = Math.floor(Math.random() * next[idx].length);
    next[idx] = next[idx].slice(0, pos) + next[idx].slice(pos + 1);
  } else if (op < 0.85 && typeof next[idx] === "string") {
    next[idx] = next[idx].repeat(2);
  } else {
    next[idx] = generateValue(kind);
  }
  return next;
}

export function coverageKey(coverage) {
  return (coverage?.offsets || []).join(",");
}

export class Harness {
  constructor({ runtime, modulePath, fnName, env = {} }) {
    this.runtime = runtime;
    this.modulePath = modulePath;
    this.fnName = fnName;
    this.env = env;
    this.pending = new Map();
    this.stderr = "";
    this.seq = 0;
    this.child = null;
    this.start();
  }

  start() {
    const isNode = this.runtime === "node";
    const harness = isNode
      ? path.join(ROOT, "engines", "harness", "js-fuzz.mjs")
      : path.join(ROOT, "engines", "harness", "py-fuzz.py");
    const cmd = isNode ? process.execPath : process.env.KESTREL_PYTHON || "python";
    const args = isNode
      ? ["--max-old-space-size=256", harness, this.modulePath, this.fnName]
      : [harness, this.modulePath, this.fnName];
    this.generation = (this.generation || 0) + 1;
    const generation = this.generation;
    this.exited = false;
    this.child = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, ...this.env },
      windowsHide: true,
    });
    this.child.stderr.on("data", (chunk) => {
      this.stderr = (this.stderr + chunk).slice(-8000);
    });
    const rl = readline.createInterface({ input: this.child.stdout });
    rl.on("line", (line) => {
      if (generation !== this.generation) return;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        return;
      }
      const entry = this.pending.get(msg.id);
      if (!entry) return;
      this.pending.delete(msg.id);
      clearTimeout(entry.timer);
      entry.resolve(msg);
    });
    this.child.on("exit", (code, signal) => {
      // A restarted harness must not reject requests that belong to its
      // replacement; only the current generation owns `pending`.
      if (generation !== this.generation) return;
      for (const [, entry] of this.pending) {
        clearTimeout(entry.timer);
        entry.reject(Object.assign(new Error(`harness exited code=${code} signal=${signal}`), {
          code,
          signal,
          stderr: this.stderr,
        }));
      }
      this.pending.clear();
      this.exited = true;
    });
  }

  run(args, timeoutMs = 2000) {
    if (this.exited) this.start();
    this.seq += 1;
    const id = this.seq;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.kill();
        reject(Object.assign(new Error("timeout"), { timeout: true, stderr: this.stderr }));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(`${JSON.stringify({ id, args, timeoutMs: Math.max(200, timeoutMs - 250) })}\n`);
    });
  }

  kill() {
    try {
      this.child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
    this.exited = true;
  }

  close() {
    // SIGTERM is not reliable for child processes on Windows; SIGKILL maps to
    // TerminateProcess and guarantees the harness does not outlive the scan.
    try {
      this.child.stdin.end();
    } catch {
      /* ignore */
    }
    try {
      this.child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
    this.exited = true;
  }
}

export function makeCoverageDir() {
  const dir = path.join(TMP_DIR, `cov-${crypto.randomUUID()}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function cleanup(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
}

export function classifyCrash(result) {
  if (!result?.error) return null;
  const name = result.error.name || "";
  const message = result.error.message || "";
  if (/KESTREL_TIMEOUT/.test(message)) return { kind: "hang", severity: "medium" };
  if (/RangeError|Maximum call stack|heap|out of memory/i.test(`${name} ${message}`)) {
    return { kind: "resource", severity: "medium" };
  }
  if (/TypeError|ReferenceError/.test(name)) return { kind: "exception", severity: "low" };
  if (/SyntaxError|URIError/.test(name)) return { kind: "parse", severity: "low" };
  return { kind: "exception", severity: "low" };
}

export function poCFor(fnName, args) {
  return `const target = await import("./target.js");\ntry {\n  await target.${fnName}(...${JSON.stringify(args, null, 2)});\n} catch (error) {\n  console.error(error);\n}`;
}
