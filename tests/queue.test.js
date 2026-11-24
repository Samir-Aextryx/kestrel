import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const dataDir = await mkdtemp(path.join(os.tmpdir(), "kestrel-queue-"));
process.env.KESTREL_DATA_DIR = dataDir;
process.env.KESTREL_SCAN_CONCURRENCY = "1";
process.env.KESTREL_JOB_MAX_ATTEMPTS = "2";
process.env.KESTREL_JOB_RETRY_DELAY_MS = "10";

const { db } = await import("../server/db.js");
const queue = await import("../server/queue.js");

test.after(async () => {
  await queue.stop({ timeoutMs: 1_000 });
  db.close();
  await rm(dataDir, { recursive: true, force: true });
});

function job(id) {
  return db.prepare("SELECT * FROM jobs WHERE id = ?").get(id);
}

async function waitFor(predicate, timeoutMs = 5_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("timed out waiting for condition");
}

const insert = db.prepare(
  `INSERT INTO jobs(id, type, scan_id, payload_json, status, attempts, run_at, locked_at, created_at)
   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
);

test("jobs run once and are marked done", async () => {
  let runs = 0;
  queue.registerJob("test.ok", async (payload) => {
    assert.deepEqual(payload, { answer: 42 });
    runs += 1;
  });
  const id = queue.enqueue("test.ok", { answer: 42 });
  await waitFor(() => job(id)?.status === "done");
  assert.equal(runs, 1);
  assert.equal(job(id).attempts, 1);
});

test("failing jobs stop after the attempt limit", async () => {
  let attempts = 0;
  queue.registerJob("test.fail", async () => {
    attempts += 1;
    throw new Error("boom");
  });
  const id = queue.enqueue("test.fail");
  await waitFor(() => job(id)?.status === "failed", 10_000);
  assert.equal(attempts, 2);
  assert.equal(job(id).attempts, 2);
});

test("recovery requeues interrupted work but respects the attempt limit", () => {
  const nowIso = new Date().toISOString();
  const future = new Date(Date.now() + 3_600_000).toISOString();
  insert.run("rec-1", "test.never", null, "{}", "running", 1, future, future, nowIso);
  insert.run("rec-2", "test.never", null, "{}", "running", 2, future, future, nowIso);

  const result = queue.recoverJobs();
  assert.equal(job("rec-1").status, "queued");
  assert.equal(job("rec-2").status, "failed");
  assert.ok(result.requeued >= 1);
  assert.ok(result.failed >= 1);
});

test("pruning keeps recent finished jobs and drops old ones", () => {
  const nowIso = new Date().toISOString();
  const old = new Date(Date.now() - 5 * 86_400_000).toISOString();
  insert.run("prune-old", "test.never", null, "{}", "done", 1, old, old, old);
  insert.run("prune-new", "test.never", null, "{}", "done", 1, nowIso, nowIso, nowIso);

  const removed = queue.pruneJobs(1);
  assert.ok(removed >= 1);
  assert.equal(job("prune-old"), undefined);
  assert.ok(job("prune-new"));
});

test("queue stats expose running, queued and failed counts", () => {
  const stats = queue.queueStats();
  assert.equal(typeof stats.running, "number");
  assert.equal(typeof stats.queued, "number");
  assert.ok(stats.failed >= 1);
});
