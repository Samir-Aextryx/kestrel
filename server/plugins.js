import fs from "node:fs";
import path from "node:path";
import { Worker } from "node:worker_threads";
import { db, now } from "./db.js";
import { PLUGINS_DIR, ROOT } from "./config.js";
import { safeJoin } from "./lib/util.js";

export function installBuiltinPlugins() {
  if (!fs.existsSync(PLUGINS_DIR)) return;
  for (const entry of fs.readdirSync(PLUGINS_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(PLUGINS_DIR, entry.name);
    const manifestPath = path.join(dir, "plugin.json");
    if (!fs.existsSync(manifestPath)) continue;
    try {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      if (!manifest.id || !manifest.entry) continue;
      const exists = db.prepare("SELECT 1 FROM plugins WHERE id = ?").get(manifest.id);
      if (exists) continue;
      db.prepare(
        "INSERT INTO plugins(id, name, version, description, path, enabled, permissions_json, target_types_json, installed_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(
        manifest.id,
        manifest.name || manifest.id,
        manifest.version || "1.0.0",
        manifest.description || "",
        dir,
        manifest.enabled ? 1 : 0,
        JSON.stringify(manifest.permissions || []),
        JSON.stringify(manifest.targetTypes || ["code"]),
        now(),
      );
    } catch {
      /* skip invalid */
    }
  }
}

export function listPlugins() {
  return db.prepare("SELECT * FROM plugins ORDER BY name").all().map((p) => ({
    ...p,
    permissions: JSON.parse(p.permissions_json),
    targetTypes: JSON.parse(p.target_types_json),
  }));
}

export function runPlugin(plugin, ctx, timeoutMs = 60_000) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(ROOT, "server", "plugin-runner.js"), {
      workerData: {
        entry: path.join(plugin.path, JSON.parse(fs.readFileSync(path.join(plugin.path, "plugin.json"), "utf8")).entry),
        config: ctx.config,
        files: ctx.files.map((f) => f.rel),
        targetType: ctx.scan.target_type,
        target: ctx.scan.target,
        permissions: JSON.parse(plugin.permissions_json || "[]"),
      },
      resourceLimits: { maxOldGenerationSizeMb: 256 },
    });
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error(`plugin ${plugin.id} timed out`));
    }, timeoutMs);
    worker.on("message", async (msg) => {
      if (msg.type === "finding") {
        ctx.add({ ...msg.finding, engine: `plugin:${plugin.id}` });
        return;
      }
      if (msg.type === "emit") {
        ctx.emit(msg.level || "info", `[${plugin.name}] ${msg.message}`);
        return;
      }
      if (msg.type === "rpc") {
        try {
          let result;
          if (msg.method === "readFile") {
            if (!JSON.parse(plugin.permissions_json || "[]").includes("fs")) throw new Error("fs permission missing");
            const full = safeJoin(ctx.root, msg.args.rel);
            result = fs.readFileSync(full, "utf8");
          } else if (msg.method === "http") {
            if (!JSON.parse(plugin.permissions_json || "[]").includes("net")) throw new Error("net permission missing");
            const res = await ctx.scope.fetch(msg.args.url, msg.args.options || {});
            result = { status: res.status, headers: res.headers, text: res.text.slice(0, 100_000) };
          } else if (msg.method === "addAsset") {
            ctx.addAsset(msg.args.kind, msg.args.value, msg.args.meta);
            result = true;
          }
          worker.postMessage({ type: "rpc-result", id: msg.id, result });
        } catch (err) {
          worker.postMessage({ type: "rpc-result", id: msg.id, error: err.message });
        }
      }
    });
    worker.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    worker.on("exit", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`plugin exited ${code}`));
    });
  });
}
