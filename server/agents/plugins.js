import { db } from "../db.js";
import { runPlugin } from "../plugins.js";

export default {
  async run(ctx) {
    const plugins = db
      .prepare("SELECT * FROM plugins WHERE enabled = 1")
      .all()
      .filter((p) => JSON.parse(p.target_types_json || "[]").includes(ctx.scan.target_type) || JSON.parse(p.target_types_json || "[]").includes("mixed"));
    let count = 0;
    for (const plugin of plugins) {
      if (ctx.signal.aborted) break;
      ctx.emit("info", `Plugin ${plugin.name} started`);
      try {
        await runPlugin(plugin, ctx);
        count += 1;
      } catch (err) {
        ctx.emit("warn", `Plugin ${plugin.name} failed: ${err.message}`);
      }
    }
    return `${count}/${plugins.length} plugins`;
  },
};
