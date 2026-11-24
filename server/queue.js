import crypto from "node:crypto";
import { db, now } from "./db.js";
import {
  SCAN_CONCURRENCY,
  JOB_MAX_ATTEMPTS,
  JOB_RETRY_DELAY_MS,
  JOB_RETENTION_DAYS,
} from "./config.js";

const handlers = new Map();
const inflight = new Set();
let running = 0;
let timer = null;
let stopping = false;

export function registerJob(type, handler) {
  handlers.set(type, handler);
}

export function enqueue(type, payload = {}, scanId = null) {
  const id = crypto.randomUUID();
  db.prepare(
    "INSERT INTO jobs(id, type, scan_id, payload_json, status, run_at, created_at) VALUES(?, ?, ?, ?, 'queued', ?, ?)",
  ).run(id, type, scanId, JSON.stringify(payload), now(), now());
  kick();
  return id;
}

// Claim and mark running in one statement so a job can never be picked up twice.
function claim() {
  return (
    db
    .prepare(
      `UPDATE jobs
          SET status = 'running', attempts = attempts + 1, locked_at = ?
        WHERE id = (
          SELECT id FROM jobs
           WHERE status = 'queued' AND run_at <= ?
           ORDER BY created_at, id
           LIMIT 1
        )
        RETURNING *`,
    )
    .get(now(), now()) || null
  );
}

async function runJob(job) {
  running += 1;
  try {
    const handler = handlers.get(job.type);
    if (!handler) throw new Error(`no handler for ${job.type}`);
    await handler(JSON.parse(job.payload_json || "{}"), job);
    db.prepare("UPDATE jobs SET status = 'done' WHERE id = ?").run(job.id);
  } catch (err) {
    const retry = job.attempts < JOB_MAX_ATTEMPTS;
    db.prepare("UPDATE jobs SET status = ?, run_at = ? WHERE id = ?").run(
      retry ? "queued" : "failed",
      new Date(Date.now() + JOB_RETRY_DELAY_MS).toISOString(),
      job.id,
    );
    console.error(`[job ${job.type} ${job.id}] attempt ${job.attempts}/${JOB_MAX_ATTEMPTS} failed`, err);
  } finally {
    running -= 1;
  }
}

function pump() {
  if (stopping) return;
  while (running < SCAN_CONCURRENCY) {
    const job = claim();
    if (!job) return;
    const task = runJob(job);
    inflight.add(task);
    task.finally(() => {
      inflight.delete(task);
      kick();
    }).catch(() => {});
  }
}

export function kick() {
  if (stopping || timer) return;
  timer = setTimeout(() => {
    timer = null;
    pump();
  }, 25);
}

export function recoverJobs() {
  const stale = db.prepare("SELECT id, attempts FROM jobs WHERE status = 'running'").all();
  const requeue = db.prepare("UPDATE jobs SET status = 'queued', locked_at = NULL WHERE id = ?");
  const abandon = db.prepare("UPDATE jobs SET status = 'failed', locked_at = NULL WHERE id = ?");
  let requeued = 0;
  let failed = 0;
  for (const job of stale) {
    if (job.attempts < JOB_MAX_ATTEMPTS) {
      requeue.run(job.id);
      requeued += 1;
    } else {
      abandon.run(job.id);
      failed += 1;
    }
  }
  kick();
  return { requeued, failed };
}

export function pruneJobs(retentionDays = JOB_RETENTION_DAYS) {
  const cutoff = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
  const info = db
    .prepare("DELETE FROM jobs WHERE status IN ('done', 'failed') AND created_at < ?")
    .run(cutoff);
  return Number(info.changes || 0);
}

// Stop claiming new jobs and wait (bounded) for running handlers to finish so a
// graceful shutdown does not leave work half-written.
export function stop({ timeoutMs = 10_000 } = {}) {
  stopping = true;
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  if (!inflight.size) return Promise.resolve(true);
  return new Promise((resolve) => {
    const deadline = setTimeout(() => resolve(false), timeoutMs);
    Promise.allSettled([...inflight]).then(() => {
      clearTimeout(deadline);
      resolve(true);
    });
  });
}

export function queueStats() {
  return {
    running,
    queued: db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE status = 'queued'").get().n,
    failed: db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE status = 'failed'").get().n,
  };
}
