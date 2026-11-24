import fsp from "node:fs/promises";
import fs from "node:fs";
import path from "node:path";
import { db, now } from "../db.js";
import { listFindings } from "../store.js";
import { entropy } from "../lib/util.js";

function buildReachability(files) {
  const byRel = new Map(files.map((f) => [f.rel, f]));
  const entry = new Set();
  for (const file of files) {
    if (/(?:^|\/)(?:index|app|server|main|manage|cli)\.[a-z]+$/.test(file.rel)) entry.add(file.rel);
    if (/(?:^|\/)cmd\/[^/]+\/main\.go$/.test(file.rel)) entry.add(file.rel);
  }
  try {
    const pkg = files.find((f) => f.rel === "package.json");
    if (pkg) {
      const doc = JSON.parse(fs.readFileSync(pkg.abs, "utf8"));
      for (const value of [doc.main, ...(Array.isArray(doc.bin) ? doc.bin : Object.values(doc.bin || {}))]) {
        if (typeof value === "string") entry.add(value.replace(/^\.\//, ""));
      }
    }
  } catch {
    /* ignore */
  }
  const importedBy = new Map();
  for (const file of files) {
    let text;
    try {
      text = fs.readFileSync(file.abs, "utf8");
    } catch {
      continue;
    }
    const re = /(?:import\s+(?:[^'"]*from\s+)?|require\(|from\s+)['"](\.[^'"]+)['"]/g;
    let m;
    while ((m = re.exec(text))) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(file.rel), m[1]));
      const candidates = [target, `${target}.js`, `${target}.ts`, `${target}.py`, `${target}/index.js`, `${target}/index.ts`];
      for (const candidate of candidates) {
        if (!byRel.has(candidate)) continue;
        if (!importedBy.has(candidate)) importedBy.set(candidate, new Set());
        importedBy.get(candidate).add(file.rel);
        break;
      }
    }
  }
  const reachable = new Set(entry);
  const queue = [...entry];
  while (queue.length) {
    const current = queue.shift();
    for (const parent of importedBy.get(current) || []) {
      if (!reachable.has(parent)) {
        reachable.add(parent);
        queue.push(parent);
      }
    }
  }
  return reachable;
}

function isTestFile(rel) {
  return /(?:^|\/)(?:tests?|spec|__tests__|fixtures?|examples?)\//i.test(rel) || /\.(?:test|spec)\.[a-z]+$/i.test(rel);
}

export default {
  async run(ctx) {
    const findings = listFindings(ctx.scan.id, { limit: 400 }).filter((f) => !f.verified);
    const reachable = buildReachability(ctx.files);
    let verified = 0;
    let rejected = 0;
    let checked = 0;
    for (const finding of findings) {
      if (ctx.signal.aborted) break;
      checked += 1;
      const verification = { method: "static", at: now(), checks: [] };
      let ok = false;
      if (finding.engine === "zeroday") {
        ok = true;
        verification.method = "dynamic";
      } else if (finding.engine === "fuzz-js" || finding.engine === "fuzz-python") {
        ok = true;
        verification.method = "dynamic";
      } else if (finding.engine === "secrets") {
        const text = finding.evidence?.lineText || finding.snippet || "";
        const ent = entropy(text);
        verification.checks.push({ check: "entropy", value: Math.round(ent * 100) / 100, pass: ent > 2.2 });
        ok = ent > 2.2 && !/example|changeme|placeholder/i.test(text);
      } else if (finding.engine === "dependencies") {
        const file = ctx.files.find((f) => f.rel === finding.file);
        if (file) {
          const text = await fsp.readFile(file.abs, "utf8");
          const present = text.includes(finding.evidence?.package || "") && text.includes(finding.evidence?.version || "");
          verification.checks.push({ check: "manifest-still-contains-version", pass: present });
          ok = present;
        }
      } else if (finding.engine === "web" || finding.engine === "tls") {
        const url = finding.evidence?.request?.url || finding.assetValue;
        if (url && ctx.scope.requests < ctx.scope.maxRequests) {
          try {
            const res = await ctx.scope.fetch(url, { timeout: 10_000 });
            const expectedStatus = finding.evidence?.response?.status;
            const pass = expectedStatus ? res.status === expectedStatus : res.status < 500;
            verification.checks.push({ check: "replay", status: res.status, expectedStatus, pass });
            ok = pass;
            verification.method = "replay";
          } catch (err) {
            verification.checks.push({ check: "replay", pass: false, error: err.message });
          }
        }
      } else if (finding.file) {
        const file = ctx.files.find((f) => f.rel === finding.file);
        if (file && finding.line) {
          const text = await fsp.readFile(file.abs, "utf8");
          const lines = text.split(/\r?\n/);
          const line = lines[finding.line - 1] || "";
          const lineOk = Boolean(line.trim());
          const reach = reachable.has(finding.file);
          const test = isTestFile(finding.file);
          verification.checks.push({ check: "line-exists", pass: lineOk });
          verification.checks.push({ check: "reachable-from-entry", pass: reach });
          verification.checks.push({ check: "test-file", pass: !test });
          ok = lineOk && (reach || test);
          if (test) verification.note = "test or fixture file";
        }
      }
      if (ok) verified += 1;
      else rejected += 1;
      db.prepare("UPDATE findings SET verified = ?, verification_json = ?, updated_at = ? WHERE id = ?").run(
        ok ? 1 : 0,
        JSON.stringify(verification),
        now(),
        finding.id,
      );
    }
    ctx.emit("info", `Verification: ${verified} confirmed, ${rejected} unconfirmed of ${checked}`);
    return `${verified}/${checked} verified`;
  },
};
