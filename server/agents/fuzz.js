import { runEngines, summarize } from "./base.js";

export default {
  async run(ctx) {
    return summarize(await runEngines(ctx, ["fuzz-js", "fuzz-python"]));
  },
};
