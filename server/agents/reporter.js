import { createReport } from "../reports.js";
import { scanStats } from "../store.js";
import { wrapUntrusted } from "../llm.js";

export default {
  async run(ctx) {
    const stats = scanStats(ctx.scan.id);
    let summary = null;
    if (ctx.config.llmReport !== false) {
      const result = await ctx.llm({
        agent: "reporter",
        scanId: ctx.scan.id,
        system:
          "Write a concise executive summary (max 120 words) for a security report. " +
          "State the risk, the most important verified issue classes and the first remediation priority. " +
          "No marketing language. Return JSON: {\"summary\":\"...\"}",
        user: wrapUntrusted(
          "scan stats",
          JSON.stringify({
            target: ctx.scan.target,
            type: ctx.scan.target_type,
            risk: ctx.scan.risk_score,
            severity: stats.severity,
            verified: stats.verified,
            assets: stats.assets,
          }),
          4000,
        ),
        maxTokens: 400,
      });
      if (result.ok && result.data?.summary) summary = result.data.summary;
    }
    const formats = ["md", "html", "json", "sarif"];
    const created = [];
    for (const format of formats) {
      const report = createReport(ctx.scan.id, format, ctx.scan.created_by);
      created.push(`${format}:${report.id}`);
      ctx.emit("report", `Report ready (${format})`, { reportId: report.id, format, sha256: report.sha256 });
    }
    if (summary) {
      ctx.add({
        engine: "reporter",
        ruleId: "executive-summary",
        title: "Executive summary",
        description: summary,
        severity: "info",
        confidence: "high",
        cwe: "CWE-1059",
        owasp: "A04:2021",
        tags: ["report"],
        evidence: { formats },
        remediation: "Use the report exports for stakeholder communication.",
        references: [],
      });
    }
    return `${created.length} reports`;
  },
};
