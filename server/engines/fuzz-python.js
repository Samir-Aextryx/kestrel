import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { db, now } from "../db.js";
import {
  Harness,
  classifyCrash,
  coverageKey,
  mutate,
  seedCorpus,
} from "../lib/fuzz.js";
import { sha256 } from "../crypto.js";
import { snippetAt } from "../lib/util.js";

function discover(source, rel) {
  const out = [];
  const lines = source.split("\n");
  lines.forEach((line, idx) => {
    const m = line.match(/^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/);
    if (!m) return;
    if (m[1].startsWith("_") && m[1] !== "__init__") return;
    const params = m[2]
      .split(",")
      .map((p) => p.trim().split(":")[0].split("=")[0].trim())
      .filter((p) => p && p !== "self" && p !== "cls" && !p.startsWith("*"));
    if (params.length > 3) return;
    out.push({ name: m[1], params, line: idx + 1, rel });
  });
  return out;
}

export default {
  id: "fuzz-python",
  name: "Python Coverage Fuzzer",
  description: "Line-coverage-guided mutation fuzzing with exception, hang and resource-crash detection.",
  category: "fuzz",
  targetTypes: ["code", "mixed"],
  dynamic: true,
  cost: "high",
  async run(ctx) {
    const maxFunctions = Math.min(20, Number(ctx.config.fuzzMaxFunctions || 5));
    const iterations = Math.min(2000, Number(ctx.config.fuzzIterations || 160));
    const timeoutMs = Math.min(5000, Number(ctx.config.fuzzTimeoutMs || 2500));
    const functions = [];
    for (const file of ctx.files) {
      if (file.lang !== "python") continue;
      functions.push(...discover(await fsp.readFile(file.abs, "utf8"), file.rel));
      if (functions.length >= maxFunctions * 3) break;
    }
    const selected = functions.slice(0, maxFunctions);
    if (!selected.length) {
      ctx.emit("info", "No top-level Python functions with ≤3 parameters found");
      return;
    }
    ctx.emit("info", `Fuzzing ${selected.length} Python functions (${iterations} iterations each)`);
    for (const fn of selected) {
      if (ctx.signal?.aborted) break;
      const runId = crypto.randomUUID();
      db.prepare(
        "INSERT INTO fuzz_runs(id, scan_id, target, engine, status, config_json, started_at) VALUES(?, ?, ?, 'fuzz-python', 'running', ?, ?)",
      ).run(runId, ctx.scan.id, `${fn.rel}:${fn.name}`, JSON.stringify({ iterations, timeoutMs }), now());
      const harness = new Harness({
        runtime: "python",
        modulePath: path.join(ctx.root, fn.rel),
        fnName: fn.name,
      });
      const corpus = seedCorpus(fn.params);
      const seen = new Set();
      const crashes = new Map();
      let execs = 0;
      let total = 0;
      try {
        for (const args of corpus.slice(0, 20)) {
          try {
            const result = await harness.run(args, timeoutMs);
            execs += 1;
            total = Math.max(total, result.coverage?.total || 0);
            const key = coverageKey(result.coverage);
            if (key) seen.add(key);
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
            const crash = { args, kind: err.timeout ? "hang" : "process", stack: err.stderr || err.message };
            const sig = sha256(`${fn.rel}:${fn.name}:${crash.kind}:${crash.stack.slice(0, 300)}`).slice(0, 16);
            if (!crashes.has(sig)) crashes.set(sig, crash);
            continue;
          }
          execs += 1;
          total = Math.max(total, result.coverage?.total || 0);
          const key = coverageKey(result.coverage);
          if (key && !seen.has(key)) {
            seen.add(key);
            corpus.push(args);
          }
          if (result.error) {
            const cls = classifyCrash(result);
            if (cls && cls.kind !== "exception") {
              const sig = sha256(`${fn.rel}:${fn.name}:${result.error.name}:${result.error.message}`).slice(0, 16);
              if (!crashes.has(sig)) crashes.set(sig, { args, ...cls, stack: result.error.trace || result.error.message });
            }
          }
          if (i % 20 === 0) {
            const coverage = total ? Math.round((seen.size / Math.max(1, total)) * 1000) / 10 : 0;
            db.prepare("UPDATE fuzz_runs SET iterations = ?, execs = ?, coverage = ?, corpus_size = ?, crashes = ? WHERE id = ?").run(
              i, execs, coverage, corpus.length, crashes.size, runId,
            );
            ctx.emit("progress", `${fn.name}: ${i}/${iterations} · ${seen.size} lines · ${crashes.size} crashes`, {
              fuzzRunId: runId,
            });
          }
        }
        const coverage = total ? Math.round((seen.size / Math.max(1, total)) * 1000) / 10 : 0;
        db.prepare(
          "UPDATE fuzz_runs SET status = 'done', iterations = ?, execs = ?, coverage = ?, corpus_size = ?, crashes = ?, finished_at = ? WHERE id = ?",
        ).run(iterations, execs, coverage, corpus.length, crashes.size, now(), runId);
        let idx = 0;
        for (const [sig, crash] of [...crashes.entries()].slice(0, 5)) {
          idx += 1;
          const input = JSON.stringify(crash.args);
          db.prepare(
            "INSERT INTO fuzz_crashes(id, fuzz_run_id, input, signal, stack, minimized, sha256, created_at) VALUES(?, ?, ?, ?, ?, 0, ?, ?)",
          ).run(crypto.randomUUID(), runId, input, crash.kind, String(crash.stack).slice(0, 6000), sha256(input), now());
          ctx.add({
            engine: "fuzz-python",
            ruleId: `fuzz-${crash.kind}`,
            title: `Fuzzer ${crash.kind === "hang" ? "hang" : "crash"} in ${fn.name}()`,
            description:
              `Coverage-guided fuzzing reached an unhandled ${crash.kind} in \`${fn.rel}:${fn.name}\` after ${execs} executions. ` +
              `Input: \`${input.slice(0, 500)}\`.`,
            severity: crash.kind === "hang" ? "medium" : "low",
            confidence: "high",
            file: fn.rel,
            line: fn.line,
            snippet: snippetAt(await fsp.readFile(path.join(ctx.root, fn.rel), "utf8"), fn.line, 3),
            cwe: crash.kind === "hang" ? "CWE-400" : "CWE-754",
            owasp: "A05:2021",
            cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
            tags: ["fuzzing", "robustness"],
            evidence: { fuzzRunId: runId, input: crash.args, signal: crash.kind, stack: crash.stack, execs, coverage, signature: sig },
            remediation: "Handle the input class explicitly and add a regression test with the minimized case.",
            references: ["https://cwe.mitre.org/data/definitions/754.html"],
          });
        }
        ctx.emit("info", `${fn.name}: ${execs} execs, ${coverage}% line coverage, ${crashes.size} crashes`);
      } catch (err) {
        db.prepare("UPDATE fuzz_runs SET status = 'failed', finished_at = ? WHERE id = ?").run(now(), runId);
        ctx.emit("warn", `Fuzzing ${fn.name} failed: ${err.message}`);
      } finally {
        harness.close();
      }
    }
  },
};
