import { db, now } from "../db.js";
import { listFindings } from "../store.js";
import { wrapUntrusted } from "../llm.js";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function normalizeTitle(title) {
  return String(title).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function downgrade(sev) {
  return { critical: "high", high: "medium", medium: "low", low: "info", info: "info" }[sev] || sev;
}

async function aiCritique(ctx, findings) {
  if (ctx.config.llmCritic === false) return { applied: 0 };
  const batch = findings
    .filter((f) => ["critical", "high"].includes(f.severity) && !f.verified)
    .slice(0, 10);
  if (!batch.length) return { applied: 0 };
  const result = await ctx.llm({
    agent: "critic",
    scanId: ctx.scan.id,
    system:
      "You are a skeptical senior reviewer. Decide whether each finding is real and reachable, or a false positive. " +
      "Only mark false_positive when the snippet proves sanitization or unreachability. " +
      'Return JSON: {"verdicts":[{"id":"...","verdict":"confirm|false_positive|needs_review","confidence":"high|medium|low","reason":"..."}]}',
    user: wrapUntrusted(
      "findings",
      JSON.stringify(
        batch.map((f) => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          engine: f.engine,
          file: f.file,
          line: f.line,
          snippet: (f.snippet || "").slice(0, 1500),
        })),
      ),
      30_000,
    ),
    maxTokens: 1500,
  });
  if (!result.ok || !Array.isArray(result.data?.verdicts)) return { applied: 0 };
  let applied = 0;
  for (const verdict of result.data.verdicts) {
    const finding = batch.find((f) => f.id === verdict.id);
    if (!finding) continue;
    if (verdict.verdict === "false_positive") {
      db.prepare("UPDATE findings SET status = 'false_positive', confidence = 'low', updated_at = ? WHERE id = ?").run(now(), finding.id);
      applied += 1;
    } else if (verdict.verdict === "confirm") {
      db.prepare(
        "UPDATE findings SET verified = 1, confidence = ?, verification_json = ?, updated_at = ? WHERE id = ?",
      ).run(
        verdict.confidence === "high" ? "high" : "medium",
        JSON.stringify({ method: "ai-critic", reason: verdict.reason, model: result.profile?.model, at: now() }),
        now(),
        finding.id,
      );
      applied += 1;
    } else {
      db.prepare("UPDATE findings SET tags_json = ?, updated_at = ? WHERE id = ?").run(
        JSON.stringify([...finding.tags, "needs-review"]),
        now(),
        finding.id,
      );
    }
  }
  return { applied, model: result.profile?.model };
}

export default {
  async run(ctx) {
    const findings = listFindings(ctx.scan.id, { limit: 500 });
    const groups = new Map();
    for (const finding of findings) {
      const key = `${finding.file || ""}|${finding.line || 0}|${normalizeTitle(finding.title)}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(finding);
    }
    let duplicates = 0;
    for (const group of groups.values()) {
      if (group.length < 2) continue;
      group.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.cvss - a.cvss);
      const keep = group[0];
      for (const other of group.slice(1)) {
        db.prepare("UPDATE findings SET status = 'duplicate', dedupe_of = ?, updated_at = ? WHERE id = ?").run(keep.id, now(), other.id);
        duplicates += 1;
      }
    }
    let downgraded = 0;
    for (const finding of findings) {
      const isTest = /(?:^|\/)(?:tests?|spec|__tests__|fixtures?|examples?)\//i.test(finding.file || "");
      const isGenerated = /(?:^|\/)(?:dist|build|vendor|generated|\.kestrel)\//i.test(finding.file || "");
      if (isTest || isGenerated) {
        const nextSeverity = downgrade(finding.severity);
        const tags = [...new Set([...finding.tags, isTest ? "test-only" : "generated"])];
        db.prepare("UPDATE findings SET severity = ?, confidence = 'low', tags_json = ?, updated_at = ? WHERE id = ?").run(
          nextSeverity,
          JSON.stringify(tags),
          now(),
          finding.id,
        );
        downgraded += 1;
      }
      const expected = finding.cvss >= 9 ? "critical" : finding.cvss >= 7 ? "high" : finding.cvss >= 4 ? "medium" : "low";
      if (SEV_ORDER[expected] < SEV_ORDER[finding.severity] && !isTest) {
        db.prepare("UPDATE findings SET severity = ?, updated_at = ? WHERE id = ?").run(expected, now(), finding.id);
      }
    }
    const ai = await aiCritique(ctx, findings);
    const confirmed = db.prepare("SELECT COUNT(*) AS n FROM findings WHERE scan_id = ? AND verified = 1").get(ctx.scan.id).n;
    ctx.emit("info", `Critic: ${duplicates} duplicates merged, ${downgraded} downgraded, ${ai.applied} AI verdicts`);
    return `${confirmed} confirmed · ${duplicates} duplicates · ${ai.applied} AI verdicts`;
  },
};
