import { runEngines, summarize } from "./base.js";
import { wrapUntrusted } from "../llm.js";
import { listFindings } from "../store.js";
import { parseJsonLoose } from "../lib/util.js";

async function aiReview(ctx) {
  if (ctx.config.llmCodeReview === false) return;
  const risky = ctx.files
    .filter((f) => ["javascript", "typescript", "python", "go"].includes(f.lang))
    .slice(0, 8);
  if (!risky.length) return;
  const snippets = [];
  for (const file of risky) {
    const text = await (await import("node:fs/promises")).readFile(file.abs, "utf8");
    snippets.push({ file: file.rel, content: text.slice(0, 6000) });
  }
  const result = await ctx.llm({
    agent: "code",
    scanId: ctx.scan.id,
    system:
      "You are a senior code auditor. Find only concrete, reachable security defects that a taint engine could miss: " +
      "authorization gaps, race conditions, unsafe defaults, logic flaws, crypto misuse. " +
      "Do not repeat generic advice. Every finding needs a real line number and a short code quote. " +
      'Return JSON: {"findings":[{"file":"...","line":1,"title":"...","severity":"critical|high|medium|low","cwe":"CWE-...","description":"...","remediation":"...","quote":"..."}]}',
    user: wrapUntrusted("source files", JSON.stringify(snippets), 40_000),
    maxTokens: 2200,
  });
  if (!result.ok) return;
  const data = result.data || parseJsonLoose(result.text);
  if (!Array.isArray(data?.findings)) return;
  let added = 0;
  for (const item of data.findings.slice(0, 12)) {
    if (!item.file || !item.line || !item.title) continue;
    const file = ctx.files.find((f) => f.rel === item.file);
    if (!file) continue;
    const text = await (await import("node:fs/promises")).readFile(file.abs, "utf8");
    const lines = text.split(/\r?\n/);
    const line = Math.min(lines.length, Math.max(1, Number(item.line)));
    if (item.quote && !lines.slice(Math.max(0, line - 4), line + 3).join("\n").includes(item.quote.slice(0, 40))) {
      continue;
    }
    ctx.add({
      engine: "ai-review",
      ruleId: `ai-${(item.cwe || "logic").toLowerCase()}`,
      title: item.title.slice(0, 240),
      description: `${item.description || ""}\n\nAI review (${result.profile?.model || "model"}); line verified against source.`,
      severity: ["critical", "high", "medium", "low"].includes(item.severity) ? item.severity : "medium",
      confidence: "medium",
      file: item.file,
      line,
      snippet: lines.slice(Math.max(0, line - 3), line + 2).map((l, i) => `${String(Math.max(1, line - 2) + i).padStart(5)} | ${l}`).join("\n"),
      cwe: item.cwe || "CWE-1059",
      owasp: "A04:2021",
      tags: ["ai-review"],
      evidence: { quote: item.quote, model: result.profile?.model },
      remediation: item.remediation || "Review and apply the suggested control.",
      references: [],
    });
    added += 1;
  }
  ctx.emit("info", `AI review added ${added} findings`);
}

export default {
  async run(ctx) {
    const results = await runEngines(ctx, ["sast-js", "sast-python", "sast-go", "interproc", "binary", "patch-diff"]);
    await aiReview(ctx);
    const count = listFindings(ctx.scan.id, { limit: 500 }).length;
    return `${summarize(results)} · ${count} findings so far`;
  },
};
