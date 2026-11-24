#!/usr/bin/env node
// Runs the curated vulnerability benchmark end to end and prints precision,
// recall and the misses. Exit code 0 only when there are no misses and no
// unexpected findings.
import crypto from "node:crypto";

const { seedAdmin } = await import("../server/auth.js");
const { runBenchmark } = await import("../server/routes/benchmark.js");

const seeded = seedAdmin();
if (seeded) console.log(`created administrator ${seeded.email}`);

const result = await runBenchmark({ benchmarkId: crypto.randomUUID(), userId: null });
const pct = (value) => `${(value * 100).toFixed(1)}%`;

console.log(`\nKESTREL benchmark: tp=${result.tp} fp=${result.fp} fn=${result.fn}`);
console.log(`precision=${pct(result.precision)} recall=${pct(result.recall)} f1=${pct(result.f1)}`);
if (result.misses.length) {
  console.log("misses:");
  for (const miss of result.misses) {
    console.log(`  - ${miss.ruleId} ${miss.file}${miss.line ? `:${miss.line}` : ""}`);
  }
}
process.exit(result.fp === 0 && result.fn === 0 ? 0 : 1);
