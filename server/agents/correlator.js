import { attackPaths } from "../store.js";

export default {
  async run(ctx) {
    const paths = attackPaths(ctx.scan.id);
    if (!paths.length) {
      ctx.emit("info", "No multi-step attack paths found");
      return "0 paths";
    }
    for (const path of paths.slice(0, 4)) {
      const top = path.steps[0];
      const severity = path.score >= 20 ? "critical" : path.score >= 12 ? "high" : "medium";
      ctx.add({
        engine: "correlator",
        ruleId: `attack-path-${path.name.toLowerCase().replace(/\W+/g, "-")}`,
        title: `Attack path: ${path.name}`,
        description:
          `The correlator linked ${path.steps.length} findings into one chain (score ${path.score}). ` +
          `Steps: ${path.steps.map((s) => s.title).join(" → ")}.`,
        severity,
        confidence: "medium",
        cwe: "CWE-1059",
        owasp: "A04:2021",
        tags: ["attack-path", "chain"],
        evidence: { pathId: path.id, steps: path.steps },
        remediation: "Fix the earliest link in the chain first; it usually removes the downstream impact.",
        references: [],
        assetValue: top?.asset || undefined,
        assetKind: "url",
      });
    }
    ctx.emit("info", `Correlated ${paths.length} attack paths`);
    return `${paths.length} paths`;
  },
};
