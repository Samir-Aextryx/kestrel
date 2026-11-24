import fsp from "node:fs/promises";
import path from "node:path";
import { parse } from "@babel/parser";
import { Harness, makeCoverageDir, cleanup } from "../lib/fuzz.js";
import { snippetAt } from "../lib/util.js";

function jsFunctions(source, rel) {
  let ast;
  try {
    ast = parse(source, { sourceType: "unambiguous", errorRecovery: true, plugins: ["jsx", "typescript"] });
  } catch {
    return [];
  }
  const out = [];
  const visit = (node) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) return node.forEach(visit);
    if (node.type === "FunctionDeclaration" && node.id?.name && node.params.length) {
      out.push({ name: node.id.name, rel, line: node.loc?.start.line || 1, params: node.params.map((p) => p.name).filter(Boolean), body: source.slice(node.start, node.end), runtime: "node" });
    }
    for (const key of Object.keys(node)) {
      if (["loc", "start", "end", "type", "extra"].includes(key)) continue;
      if (node[key] && typeof node[key] === "object") visit(node[key]);
    }
  };
  visit(ast);
  return out;
}

function pyFunctions(source, rel) {
  const lines = source.split("\n");
  const out = [];
  lines.forEach((line, idx) => {
    const m = line.match(/^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/);
    if (!m) return;
    const params = m[2].split(",").map((p) => p.trim().split(":")[0].split("=")[0].trim()).filter((p) => p && p !== "self");
    if (!params.length) return;
    let end = lines.length;
    for (let i = idx + 1; i < lines.length; i += 1) {
      if (/^(?:async\s+)?def\s+/.test(lines[i])) {
        end = i;
        break;
      }
    }
    out.push({ name: m[1], rel, line: idx + 1, params, body: lines.slice(idx, end).join("\n"), runtime: "python" });
  });
  return out;
}

const GUARDS = [
  { re: /(\w+)(?:\.length)?\s*(<=|<|>=|>)\s*(\d+)/g, kind: "length" },
  { re: /len\(\s*(\w+)\s*\)\s*(<=|<|>=|>)\s*(\d+)/g, kind: "length" },
  { re: /(\w+)\s*(<=|<|>=|>)\s*(\d+)/g, kind: "number" },
  { re: /(?:\/\^?([^/]+)\$?\/)\.test\(\s*(\w+)\s*\)/g, kind: "regex" },
];

function mine(body) {
  const out = [];
  for (const guard of GUARDS) {
    guard.re.lastIndex = 0;
    let m;
    while ((m = guard.re.exec(body))) {
      if (guard.kind === "regex") out.push({ param: m[2], kind: "regex", pattern: m[1] });
      else out.push({ param: m[1], kind: guard.kind, op: m[2], value: Number(m[3]) });
    }
  }
  return out;
}

function boundaryValues(guard) {
  if (guard.kind === "regex") return ["", "a", "a".repeat(64), "A1!", "ü"];
  const n = guard.value;
  return [String(n - 1), String(n), String(n + 1), "0", "-1", String(n * 1000)];
}

export default {
  id: "invariant",
  name: "Invariant Miner",
  description: "Mines length/numeric/regex guards and executes boundary inputs to expose off-by-one and guard failures.",
  category: "research",
  targetTypes: ["code", "mixed"],
  dynamic: true,
  cost: "medium",
  async run(ctx) {
    if (ctx.config.invariants === false) return;
    const functions = [];
    for (const file of ctx.files) {
      if (["javascript", "typescript"].includes(file.lang)) functions.push(...jsFunctions(await fsp.readFile(file.abs, "utf8"), file.rel));
      else if (file.lang === "python") functions.push(...pyFunctions(await fsp.readFile(file.abs, "utf8"), file.rel));
      if (functions.length > 300) break;
    }
    let count = 0;
    for (const fn of functions.slice(0, 24)) {
      if (ctx.signal?.aborted) break;
      const guards = mine(fn.body).filter((g) => fn.params.includes(g.param));
      if (!guards.length) continue;
      const covDir = fn.runtime === "node" ? makeCoverageDir() : null;
      const harness = new Harness({
        runtime: fn.runtime,
        modulePath: path.join(ctx.root, fn.rel),
        fnName: fn.name,
        env: covDir ? { NODE_V8_COVERAGE: covDir } : {},
      });
      try {
        for (const guard of guards.slice(0, 4)) {
          const idx = fn.params.indexOf(guard.param);
          const base = fn.params.map((p, i) => (i === idx ? (guard.kind === "regex" ? "a" : String(guard.value)) : hint(p) ? 1 : ""));
          let baseline;
          try {
            baseline = await harness.run(base, 2500);
          } catch {
            continue;
          }
          for (const value of boundaryValues(guard)) {
            const args = [...base];
            args[idx] = guard.kind === "regex" ? value : Number(value);
            let result;
            try {
              result = await harness.run(args, 2500);
            } catch {
              continue;
            }
            const crashed = Boolean(result.error) && !baseline.error;
            const changed = JSON.stringify(result.result) !== JSON.stringify(baseline.result);
            if (!crashed && !changed) continue;
            const severity = crashed ? "medium" : "low";
            const source = await fsp.readFile(path.join(ctx.root, fn.rel), "utf8");
            ctx.add({
              engine: "invariant",
              ruleId: crashed ? "boundary-crash" : "boundary-behavior",
              title: crashed ? `Boundary input crashes ${fn.name}()` : `Boundary input changes ${fn.name}() behavior`,
              description:
                `Mined guard \`${guard.kind === "regex" ? `/${guard.pattern}/.test(${guard.param})` : `${guard.param} ${guard.op} ${guard.value}`}\` ` +
                `and executed boundary value \`${value}\`. ${crashed ? "The function threw while the baseline succeeded." : "The result diverged from the baseline."}`,
              severity,
              confidence: "medium",
              file: fn.rel,
              line: fn.line,
              snippet: snippetAt(source, fn.line, 3),
              cwe: crashed ? "CWE-754" : "CWE-1284",
              owasp: "A04:2021",
              tags: ["invariant", "boundary", "dynamic"],
              evidence: { guard, value, args, baseline: baseline.result, observed: result.result, error: result.error },
              remediation: "Make the boundary explicit, validate before use, and add a regression test at N-1/N/N+1.",
              references: ["https://cwe.mitre.org/data/definitions/1284.html"],
            });
            count += 1;
            break;
          }
        }
      } finally {
        harness.close();
        if (covDir) cleanup(covDir);
      }
    }
    ctx.emit("info", `Invariant miner: ${count} boundary anomalies`);
  },
};

function hint(name) {
  return /count|limit|size|n|id|port|index/i.test(name);
}
