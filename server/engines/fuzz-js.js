import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { parse } from "@babel/parser";
import { db, now } from "../db.js";
import {
  Harness,
  classifyCrash,
  cleanup,
  coverageKey,
  generateValue,
  makeCoverageDir,
  mutate,
  seedCorpus,
} from "../lib/fuzz.js";
import { sha256 } from "../crypto.js";
import { snippetAt } from "../lib/util.js";

const JS_EXT = new Set(["javascript", "typescript"]);

function paramsOf(fn) {
  const names = [];
  for (const param of fn.params || []) {
    if (param.type === "Identifier") names.push(param.name);
    else if (param.type === "AssignmentPattern" && param.left.type === "Identifier") names.push(param.left.name);
    else if (param.type === "RestElement") names.push("rest");
    else names.push("arg");
  }
  return names;
}

function discover(source, rel) {
  let ast;
  try {
    ast = parse(source, {
      sourceType: "unambiguous",
      errorRecovery: true,
      plugins: ["jsx", "typescript", "decorators-legacy", "classProperties", "topLevelAwait"],
    });
  } catch {
    return [];
  }
  const out = [];
  const push = (name, fn, node) => {
    if (!name || !fn || (fn.params || []).length > 3) return;
    out.push({ name, params: paramsOf(fn), line: node.loc?.start.line || 1 });
  };
  const visit = (node) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (!node.type) return;
    if (node.type === "ExportNamedDeclaration") {
      if (node.declaration?.type === "FunctionDeclaration") {
        push(node.declaration.id?.name, node.declaration, node);
      }
      if (node.declaration?.type === "VariableDeclaration") {
        for (const decl of node.declaration.declarations) {
          if (decl.id?.type === "Identifier" && /Function|Arrow/.test(decl.init?.type || "")) {
            push(decl.id.name, decl.init, decl);
          }
        }
      }
    }
    if (node.type === "ExportDefaultDeclaration" && /Function|Arrow/.test(node.declaration?.type || "")) {
      push("default", node.declaration, node);
    }
    if (node.type === "AssignmentExpression") {
      const left = node.left;
      if (left?.type === "MemberExpression" && !left.computed && left.object?.name === "module" && left.property?.name === "exports" && node.right?.type === "ObjectExpression") {
        for (const prop of node.right.properties) {
          if (prop.value && /Function|Arrow/.test(prop.value.type)) push(prop.key?.name, prop.value, prop);
        }
      }
    }
    for (const key of Object.keys(node)) {
      if (["loc", "start", "end", "extra", "type"].includes(key)) continue;
      const value = node[key];
      if (value && typeof value === "object") visit(value);
    }
  };
  visit(ast);
  return out.map((f) => ({ ...f, rel }));
}

async function minimize(harness, args, timeoutMs) {
  let best = args;
  let changed = true;
  let rounds = 0;
  while (changed && rounds < 12) {
    changed = false;
    rounds += 1;
    for (let i = 0; i < best.length; i += 1) {
      if (typeof best[i] === "string" && best[i].length > 4) {
        const shorter = best[i].slice(0, Math.floor(best[i].length / 2));
        const candidate = [...best];
        candidate[i] = shorter;
        try {
          const result = await harness.run(candidate, timeoutMs);
          if (result.error) {
            best = candidate;
            changed = true;
          }
        } catch {
          best = candidate;
          changed = true;
        }
      }
    }
  }
  return best;
}

export default {
  id: "fuzz-js",
  name: "JS/TS Coverage Fuzzer",
  description: "V8-coverage-guided mutation fuzzing of exported functions with crash minimization and sandboxed effects.",
  category: "fuzz",
  targetTypes: ["code", "mixed"],
  dynamic: true,
  cost: "high",
  async run(ctx) {
    const maxFunctions = Math.min(20, Number(ctx.config.fuzzMaxFunctions || 6));
    const iterations = Math.min(3000, Number(ctx.config.fuzzIterations || 220));
    const timeoutMs = Math.min(5000, Number(ctx.config.fuzzTimeoutMs || 1500));
    const functions = [];
    for (const file of ctx.files) {
      if (!JS_EXT.has(file.lang)) continue;
      const source = await fsp.readFile(file.abs, "utf8");
      functions.push(...discover(source, file.rel));
      if (functions.length >= maxFunctions * 3) break;
    }
    const selected = functions.slice(0, maxFunctions);
    if (!selected.length) {
      ctx.emit("info", "No exported functions with ≤3 parameters found for fuzzing");
      return;
    }
    ctx.emit("info", `Fuzzing ${selected.length} exported functions (${iterations} iterations each)`);
    for (const fn of selected) {
      if (ctx.signal?.aborted) break;
      const runId = crypto.randomUUID();
      db.prepare(
        "INSERT INTO fuzz_runs(id, scan_id, target, engine, status, config_json, started_at) VALUES(?, ?, ?, 'fuzz-js', 'running', ?, ?)",
      ).run(runId, ctx.scan.id, `${fn.rel}:${fn.name}`, JSON.stringify({ iterations, timeoutMs }), now());
      const covDir = makeCoverageDir();
      const harness = new Harness({
        runtime: "node",
        modulePath: path.join(ctx.root, fn.rel),
        fnName: fn.name,
        env: { NODE_V8_COVERAGE: covDir },
      });
      const corpus = seedCorpus(fn.params);
      const seenCoverage = new Set();
      const crashes = new Map();
      let execs = 0;
      let totalRanges = 0;
      let fatal = null;
      let importFailed = false;
      try {
        for (const args of corpus.slice(0, 24)) {
          try {
            const result = await harness.run(args, timeoutMs);
            execs += 1;
            totalRanges = Math.max(totalRanges, result.coverage?.total || 0);
            const key = coverageKey(result.coverage);
            if (key) seenCoverage.add(key);
          } catch {
            /* seed crash */
          }
        }
        for (let i = 0; i < iterations; i += 1) {
          if (ctx.signal?.aborted) break;
          const base = corpus[Math.floor(Math.random() * corpus.length)] || fn.params.map(() => "");
          const args = mutate(base, fn.params);
          let result;
          try {
            result = await harness.run(args, timeoutMs);
          } catch (err) {
            if (err.code === 2 || /function .* not found/.test(err.stderr || "")) {
              fatal = err.message;
              break;
            }
            if (/ERR_MODULE_NOT_FOUND|ModuleNotFoundError|Cannot find module/.test(err.stderr || "")) {
              importFailed = true;
              fatal = (err.stderr || "").match(/(?:Cannot find (?:package|module) '[^']+'|ModuleNotFoundError[^\n]*)/)?.[0] || "module import failed";
              break;
            }
            const crash = { args, kind: err.timeout ? "hang" : "process", stack: err.stderr || err.message };
            const sig = sha256(`${fn.rel}:${fn.name}:${crash.kind}:${crash.stack.slice(0, 300)}`).slice(0, 16);
            if (!crashes.has(sig)) crashes.set(sig, crash);
            continue;
          }
          execs += 1;
          totalRanges = Math.max(totalRanges, result.coverage?.total || 0);
          const key = coverageKey(result.coverage);
          if (key && !seenCoverage.has(key)) {
            seenCoverage.add(key);
            corpus.push(args);
          }
          if (result.error) {
            const cls = classifyCrash(result);
            if (cls && cls.kind !== "exception") {
              const sig = sha256(`${fn.rel}:${fn.name}:${result.error.name}:${result.error.message}`).slice(0, 16);
              if (!crashes.has(sig)) crashes.set(sig, { args, ...cls, stack: result.error.message });
            }
          }
          if (i % 25 === 0) {
            const coverage = totalRanges ? Math.round((seenCoverage.size / Math.max(1, totalRanges)) * 1000) / 10 : 0;
            db.prepare("UPDATE fuzz_runs SET iterations = ?, execs = ?, coverage = ?, corpus_size = ?, crashes = ? WHERE id = ?").run(
              i, execs, coverage, corpus.length, crashes.size, runId,
            );
            ctx.emit("progress", `${fn.name}: ${i}/${iterations} · ${seenCoverage.size} edges · ${crashes.size} crashes`, {
              fuzzRunId: runId,
            });
          }
        }
        const coverage = totalRanges ? Math.round((seenCoverage.size / Math.max(1, totalRanges)) * 1000) / 10 : 0;
        db.prepare(
          "UPDATE fuzz_runs SET status = ?, iterations = ?, execs = ?, coverage = ?, corpus_size = ?, crashes = ?, finished_at = ? WHERE id = ?",
        ).run(importFailed ? "failed" : "done", iterations, execs, coverage, corpus.length, crashes.size, now(), runId);
        if (importFailed) {
          ctx.emit("warn", `Fuzzing ${fn.name} skipped: ${fatal}`);
          continue;
        }
        let idx = 0;
        for (const [sig, crash] of [...crashes.entries()].slice(0, 5)) {
          idx += 1;
          let minimized = crash.args;
          try {
            minimized = await minimize(harness, crash.args, timeoutMs);
          } catch {
            /* keep original */
          }
          const input = JSON.stringify(minimized);
          db.prepare(
            "INSERT INTO fuzz_crashes(id, fuzz_run_id, input, signal, stack, minimized, sha256, created_at) VALUES(?, ?, ?, ?, ?, 1, ?, ?)",
          ).run(crypto.randomUUID(), runId, input, crash.kind, String(crash.stack).slice(0, 6000), sha256(input), now());
          ctx.add({
            engine: "fuzz-js",
            ruleId: `fuzz-${crash.kind}`,
            title: `Fuzzer ${crash.kind === "hang" ? "hang" : "crash"} in ${fn.name}()`,
            description:
              `Coverage-guided fuzzing reached an unhandled ${crash.kind} in \`${fn.rel}:${fn.name}\` after ${execs} executions. ` +
              `Minimized input: \`${input.slice(0, 500)}\`.`,
            severity: crash.kind === "hang" ? "medium" : "low",
            confidence: "high",
            file: fn.rel,
            line: fn.line,
            snippet: snippetAt(await fsp.readFile(path.join(ctx.root, fn.rel), "utf8"), fn.line, 3),
            cwe: crash.kind === "hang" ? "CWE-400" : "CWE-754",
            owasp: "A05:2021",
            cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
            tags: ["fuzzing", "robustness"],
            evidence: { fuzzRunId: runId, input: minimized, signal: crash.kind, stack: crash.stack, execs, coverage, signature: sig },
            remediation: "Handle the input class explicitly, add a regression test with the minimized case and bound resource use.",
            references: ["https://cwe.mitre.org/data/definitions/754.html"],
          });
        }
        ctx.emit("info", `${fn.name}: ${execs} execs, ${coverage}% edge coverage, ${crashes.size} crashes`);
      } catch (err) {
        fatal = err.message;
        db.prepare("UPDATE fuzz_runs SET status = 'failed', iterations = ?, finished_at = ? WHERE id = ?").run(iterations, now(), runId);
        ctx.emit("warn", `Fuzzing ${fn.name} failed: ${err.message}`);
      } finally {
        harness.close();
        cleanup(covDir);
      }
      if (fatal) ctx.emit("debug", `Fuzzer fatal for ${fn.name}: ${fatal}`);
    }
  },
};
