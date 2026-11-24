const PATTERNS = [
  { re: /(?:TODO|FIXME|XXX|HACK)[^\n]*(?:auth|security|sanit|escape|validate|csrf|token|secret|permission|race|limit)/gi, rule: "security-todo", title: "Security TODO", sev: "info", cwe: "CWE-1059" },
  { re: /(?:eslint-disable(?:-next-line)?|@ts-ignore|@ts-expect-error|# type: ignore|# noqa)[^\n]*/g, rule: "suppressed-diagnostic", title: "Suppressed diagnostic", sev: "info", cwe: "CWE-1059" },
  { re: /(?:nosec|nolint|checkov:skip|tfsec:ignore|trivy:ignore)/gi, rule: "security-suppression", title: "Security scanner suppression", sev: "low", cwe: "CWE-1059" },
];

export default {
  async run(ctx) {
    let count = 0;
    for (const rel of ctx.files) {
      if (!/\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rb|php|java|tf|ya?ml)$/i.test(rel)) continue;
      let text;
      try {
        text = await ctx.readFile(rel);
      } catch {
        continue;
      }
      const lines = text.split(/\r?\n/);
      lines.forEach((line, idx) => {
        for (const pattern of PATTERNS) {
          pattern.re.lastIndex = 0;
          if (!pattern.re.test(line)) continue;
          count += 1;
          ctx.add({
            ruleId: pattern.rule,
            title: pattern.title,
            description: `Marker in \`${rel}:${idx + 1}\`: \`${line.trim().slice(0, 240)}\`. Verify the follow-up is still tracked.`,
            severity: pattern.sev,
            confidence: "high",
            file: rel,
            line: idx + 1,
            snippet: lines.slice(Math.max(0, idx - 2), idx + 2).map((l, i) => `${Math.max(1, idx - 1) + i} | ${l}`).join("\n"),
            cwe: pattern.cwe,
            owasp: "A04:2021",
            tags: ["todo", "maintenance"],
            evidence: { line: line.trim() },
            remediation: "Resolve the item or link it to a tracked issue.",
            references: ["https://cwe.mitre.org/data/definitions/1059.html"],
          });
        }
      });
    }
    ctx.emit("info", `Found ${count} security markers`);
  },
};
