import crypto from "node:crypto";
import { db, now } from "./db.js";

async function deliver(hook, payload) {
  const body = JSON.stringify(payload);
  const signature = crypto.createHmac("sha256", hook.secret).update(body).digest("hex");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(hook.url, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        "user-agent": "Kestrel-Webhook/1.0",
        "x-kestrel-event": payload.type,
        "x-kestrel-signature": `sha256=${signature}`,
      },
      body,
    });
    db.prepare("UPDATE webhooks SET last_status = ?, last_fired = ? WHERE id = ?").run(res.status, now(), hook.id);
  } catch (err) {
    db.prepare("UPDATE webhooks SET last_status = ?, last_fired = ? WHERE id = ?").run(0, now(), hook.id);
    console.error(`[webhook ${hook.id}]`, err.message);
  } finally {
    clearTimeout(timer);
  }
}

export function fireWebhooks(scanId, payload) {
  if (!scanId) return;
  const scan = db.prepare("SELECT workspace_id FROM scans WHERE id = ?").get(scanId);
  if (!scan) return;
  const hooks = db.prepare("SELECT * FROM webhooks WHERE workspace_id = ? AND enabled = 1").all(scan.workspace_id);
  for (const hook of hooks) {
    const events = JSON.parse(hook.events_json || "[]");
    if (!events.includes("*") && !events.includes(payload.type)) continue;
    deliver(hook, { ...payload, scanId, deliveredAt: now() });
  }
}

export function fireGoalWebhooks(goalId, payload) {
  const goal = db.prepare("SELECT workspace_id FROM goals WHERE id = ?").get(goalId);
  if (!goal) return;
  const hooks = db.prepare("SELECT * FROM webhooks WHERE workspace_id = ? AND enabled = 1").all(goal.workspace_id);
  for (const hook of hooks) {
    const events = JSON.parse(hook.events_json || "[]");
    if (!events.includes("*") && !events.includes(payload.type)) continue;
    deliver(hook, { ...payload, goalId, deliveredAt: now() });
  }
}
