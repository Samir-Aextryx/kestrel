import { db, now } from "./db.js";
import { fireWebhooks } from "./webhooks.js";

const subscribers = new Map();

export function emit(scanId, type, message, data = {}, opts = {}) {
  const last = db
    .prepare("SELECT COALESCE(MAX(seq), 0) AS seq FROM events WHERE scan_id = ?")
    .get(scanId).seq;
  const seq = last + 1;
  const agent = opts.agent || null;
  const level = opts.level || "info";
  db.prepare(
    `INSERT INTO events(scan_id, seq, type, agent, level, message, data_json, created_at)
     VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(scanId, seq, type, agent, level, String(message).slice(0, 4000), JSON.stringify(data), now());
  const payload = {
    id: seq,
    scanId,
    type,
    agent,
    level,
    message,
    data,
    at: now(),
  };
  for (const res of subscribers.get(scanId) || []) {
    try {
      res.write(`id: ${seq}\ndata: ${JSON.stringify(payload)}\n\n`);
    } catch {
      /* dropped */
    }
  }
  fireWebhooks(scanId, payload);
  return payload;
}

export function subscribe(scanId, res) {
  if (!subscribers.has(scanId)) subscribers.set(scanId, new Set());
  subscribers.get(scanId).add(res);
  return () => subscribers.get(scanId)?.delete(res);
}

export function replay(scanId, after = 0, limit = 500) {
  return db
    .prepare("SELECT * FROM events WHERE scan_id = ? AND seq > ? ORDER BY seq LIMIT ?")
    .all(scanId, after, limit)
    .map((row) => ({
      id: row.seq,
      scanId: row.scan_id,
      type: row.type,
      agent: row.agent,
      level: row.level,
      message: row.message,
      data: JSON.parse(row.data_json || "{}"),
      at: row.created_at,
    }));
}

export function heartbeat() {
  for (const [scanId, set] of subscribers) {
    for (const res of set) {
      try {
        res.write(`: ping ${Date.now()}\n\n`);
      } catch {
        set.delete(res);
      }
    }
    if (!set.size) subscribers.delete(scanId);
  }
}
