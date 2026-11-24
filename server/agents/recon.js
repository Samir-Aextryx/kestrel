import { runEngines, summarize } from "./base.js";

export default {
  async run(ctx) {
    const ids = ["web", "tls", "network", "auth"].filter((id) => ctx.config.engines?.includes(id) || !ctx.config.engines?.length);
    const results = await runEngines(ctx, ids);
    return summarize(results);
  },
};
