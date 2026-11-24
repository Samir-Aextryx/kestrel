import { ENGINE_MAP } from "../engines/index.js";

export async function runEngines(ctx, ids) {
  const results = [];
  for (const id of ids) {
    if (ctx.signal.aborted) break;
    const engine = ENGINE_MAP.get(id);
    if (!engine) continue;
    const started = Date.now();
    ctx.emit("info", `Engine ${engine.name} started`);
    try {
      await engine.run(ctx);
      results.push({ id, ok: true, ms: Date.now() - started });
    } catch (err) {
      ctx.emit("warn", `Engine ${engine.name} failed: ${err.message}`);
      results.push({ id, ok: false, error: err.message, ms: Date.now() - started });
    }
  }
  return results;
}

export function summarize(results) {
  const ok = results.filter((r) => r.ok).length;
  return `${ok}/${results.length} engines completed`;
}
