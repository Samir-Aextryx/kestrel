import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import v8 from "node:v8";
import { pathToFileURL } from "node:url";
import http from "node:http";
import https from "node:https";
import childProcess from "node:child_process";
import readline from "node:readline";
import { syncBuiltinESMExports } from "node:module";

const [modulePath, fnName, mode = "fuzz"] = process.argv.slice(2);
const coverageDir = process.env.NODE_V8_COVERAGE;
const targetUrl = pathToFileURL(modulePath).href;
const effects = [];
let active = false;
let seq = 0;

function record(effect) {
  if (!active) return;
  if (effects.length < 40) effects.push(effect);
}

const orig = {
  readFileSync: fs.readFileSync,
  readFile: fs.readFile,
  writeFileSync: fs.writeFileSync,
  openSync: fs.openSync,
  mkdirSync: fs.mkdirSync,
  renameSync: fs.renameSync,
  unlinkSync: fs.unlinkSync,
  createReadStream: fs.createReadStream,
  createWriteStream: fs.createWriteStream,
  execSync: childProcess.execSync,
  spawnSync: childProcess.spawnSync,
  exec: childProcess.exec,
  httpRequest: http.request,
  httpsRequest: https.request,
  httpGet: http.get,
  httpsGet: https.get,
  fetch: globalThis.fetch,
};

fs.readFileSync = function patchedReadFileSync(p, ...args) {
  record({ type: "fs", op: "read", path: String(p) });
  return orig.readFileSync.call(this, p, ...args);
};
fs.readFile = function patchedReadFile(p, ...args) {
  record({ type: "fs", op: "read", path: String(p) });
  return orig.readFile.call(this, p, ...args);
};
fs.promises.readFile = async function patchedReadFileAsync(p, ...args) {
  record({ type: "fs", op: "read", path: String(p) });
  return fsp.readFile(p, ...args);
};
fs.writeFileSync = function patchedWriteFileSync(p, ...args) {
  record({ type: "fs", op: "write", path: String(p) });
  return orig.writeFileSync.call(this, p, ...args);
};
fs.openSync = function patchedOpenSync(p, ...args) {
  record({ type: "fs", op: "open", path: String(p) });
  return orig.openSync.call(this, p, ...args);
};
fs.mkdirSync = function patchedMkdirSync(p, ...args) {
  record({ type: "fs", op: "mkdir", path: String(p) });
  return orig.mkdirSync.call(this, p, ...args);
};
fs.renameSync = function patchedRenameSync(a, b, ...rest) {
  record({ type: "fs", op: "rename", path: `${a} -> ${b}` });
  return orig.renameSync.call(this, a, b, ...rest);
};
fs.unlinkSync = function patchedUnlinkSync(p, ...args) {
  record({ type: "fs", op: "unlink", path: String(p) });
  return orig.unlinkSync.call(this, p, ...args);
};
fs.createReadStream = function patchedReadStream(p, ...args) {
  record({ type: "fs", op: "read", path: String(p) });
  return orig.createReadStream.call(this, p, ...args);
};
fs.createWriteStream = function patchedWriteStream(p, ...args) {
  record({ type: "fs", op: "write", path: String(p) });
  return orig.createWriteStream.call(this, p, ...args);
};
childProcess.execSync = function patchedExecSync(cmd, ...args) {
  record({ type: "exec", command: String(cmd).slice(0, 300) });
  return orig.execSync.call(this, cmd, ...args);
};
childProcess.spawnSync = function patchedSpawnSync(cmd, args, ...rest) {
  record({ type: "exec", command: `${cmd} ${Array.isArray(args) ? args.join(" ") : ""}`.slice(0, 300) });
  return orig.spawnSync.call(this, cmd, args, ...rest);
};
childProcess.exec = function patchedExec(cmd, ...args) {
  record({ type: "exec", command: String(cmd).slice(0, 300) });
  return orig.exec.call(this, cmd, ...args);
};
for (const [name, original] of [["http", orig.httpRequest], ["https", orig.httpsRequest]]) {
  const transport = name === "http" ? http : https;
  transport.request = function patchedRequest(...args) {
    try {
      const first = args[0];
      const url = typeof first === "string" ? first : first?.href || `${first?.protocol || name + ":"}//${first?.hostname || first?.host}${first?.path || ""}`;
      record({ type: "network", url: String(url).slice(0, 300) });
    } catch {
      /* ignore */
    }
    return original.apply(this, args);
  };
}
if (orig.fetch) {
  globalThis.fetch = async function patchedFetch(input, ...args) {
    record({ type: "network", url: String(input?.url || input).slice(0, 300) });
    return orig.fetch.call(this, input, ...args);
  };
}
http.get = function patchedGet(...args) {
  try {
    record({ type: "network", url: String(args[0]?.href || args[0]).slice(0, 300) });
  } catch {
    /* ignore */
  }
  return orig.httpGet.apply(this, args);
};
https.get = function patchedGet(...args) {
  try {
    record({ type: "network", url: String(args[0]?.href || args[0]).slice(0, 300) });
  } catch {
    /* ignore */
  }
  return orig.httpsGet.apply(this, args);
};
syncBuiltinESMExports();

function seenCoverageFiles() {
  try {
    return new Set(fs.readdirSync(coverageDir));
  } catch {
    return new Set();
  }
}

function readCoverage(before) {
  let files = [];
  try {
    files = fs.readdirSync(coverageDir).filter((f) => !before.has(f));
  } catch {
    return { offsets: [], total: 0 };
  }
  const offsets = new Set();
  let total = 0;
  for (const file of files) {
    const full = path.join(coverageDir, file);
    try {
      const data = JSON.parse(fs.readFileSync(full, "utf8"));
      for (const script of data.result || []) {
        if (!script.url.startsWith(targetUrl)) continue;
        for (const fn of script.functions || []) {
          for (const range of fn.ranges || []) {
            total += 1;
            if (range.count > 0) offsets.add(range.startOffset);
          }
        }
      }
    } catch {
      /* partial file */
    }
    try {
      fs.unlinkSync(full);
    } catch {
      /* ignore */
    }
  }
  return { offsets: [...offsets], total };
}

function safe(value, depth = 0) {
  if (value === undefined) return { __type: "undefined" };
  if (value === null) return null;
  if (typeof value === "bigint") return { __type: "bigint", value: String(value) };
  if (typeof value === "function") return { __type: "function", name: value.name };
  if (typeof value === "string") return value.length > 2000 ? `${value.slice(0, 2000)}…` : value;
  if (typeof value !== "object") return value;
  if (depth > 3) return { __type: "object" };
  if (Buffer.isBuffer(value)) return { __type: "buffer", length: value.length };
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => safe(v, depth + 1));
  if (value instanceof Error) return { __type: "error", name: value.name, message: value.message };
  const out = {};
  for (const key of Object.keys(value).slice(0, 20)) {
    try {
      out[key] = safe(value[key], depth + 1);
    } catch {
      out[key] = { __type: "unreadable" };
    }
  }
  return out;
}

async function invoke(fn, args, timeoutMs) {
  active = true;
  effects.length = 0;
  const started = process.hrtime.bigint();
  let result;
  let error = null;
  try {
    result = await Promise.race([
      Promise.resolve(fn(...args)),
      new Promise((_, reject) => setTimeout(() => reject(new Error("KESTREL_TIMEOUT")), timeoutMs)),
    ]);
  } catch (err) {
    error = { name: err?.name || "Error", message: String(err?.message || err).slice(0, 1000) };
  }
  const elapsedUs = Number(process.hrtime.bigint() - started) / 1000;
  active = false;
  return {
    result: safe(result),
    error,
    effects: effects.slice(),
    elapsedUs,
    polluted: { polluted: ({}).polluted, proto: Object.prototype.polluted },
    protoPolluted: result && typeof result === "object" ? Object.getPrototypeOf(result)?.polluted : undefined,
  };
}

const mod = await import(`${targetUrl}?kestrel=${Date.now()}`);
const fn = mod[fnName] || mod.default?.[fnName] || (typeof mod.default === "function" ? mod.default : null);
if (typeof fn !== "function") {
  process.stdout.write(`${JSON.stringify({ fatal: `function ${fnName} not found` })}\n`);
  process.exit(2);
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  let item;
  try {
    item = JSON.parse(line);
  } catch {
    continue;
  }
  seq += 1;
  const before = seenCoverageFiles();
  const outcome = await invoke(fn, item.args || [], Math.min(5000, item.timeoutMs || 1500));
  v8.takeCoverage();
  const coverage = readCoverage(before);
  process.stdout.write(`${JSON.stringify({ id: item.id ?? seq, ...outcome, coverage })}\n`);
}
process.exit(0);
