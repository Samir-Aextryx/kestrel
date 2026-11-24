import { AGENT_LABELS } from "../config.js";
import { wrapUntrusted } from "../llm.js";

export default {
  async run(ctx, plan) {
    ctx.emit("info", `Plan: ${plan.engines.length} engines across ${plan.agents.length} agents`);
    ctx.emit("plan", "Execution plan created", {
      agents: plan.agents.map((a) => ({ id: a, label: AGENT_LABELS[a] || a })),
      engines: plan.engines,
      targetType: ctx.scan.target_type,
    });
    if (ctx.webUrl) {
      const url = new URL(ctx.webUrl);
      ctx.addAsset("domain", url.hostname);
      ctx.addAsset("url", url.toString());
      ctx.emit("info", `Scope gate: ${ctx.scope.allow.length} allow rules, ${ctx.scope.requests}/${ctx.scope.maxRequests} request budget`);
    }
    if (ctx.files.length) ctx.emit("info", `Inventory: ${ctx.files.length} text/binary files`);
    if (ctx.config.llmPlan !== false) {
      const result = await ctx.llm({
        agent: "orchestrator",
        scanId: ctx.scan.id,
        system:
          "You are the planning agent of an authorized security-research platform. " +
          "Given target metadata, produce a concise plan with the three highest-value investigation directions. " +
          'Return JSON: {"directions":[{"title":"...","why":"...","engines":["..."]}],"riskNote":"..."}',
        user: wrapUntrusted(
          "target",
          JSON.stringify({
            type: ctx.scan.target_type,
            target: ctx.scan.target,
            files: ctx.files.length,
            engines: plan.engines,
            config: ctx.config,
          }),
          8000,
        ),
        maxTokens: 700,
      });
      if (result.ok && Array.isArray(result.data?.directions)) {
        ctx.emit("plan", "AI plan refinement", {
          directions: result.data.directions.slice(0, 5),
          riskNote: result.data.riskNote,
          model: result.profile?.model,
        });
        return `AI plan: ${result.data.directions.map((d) => d.title).join("; ")}`;
      }
    }
    return "Deterministic plan";
  },
};
