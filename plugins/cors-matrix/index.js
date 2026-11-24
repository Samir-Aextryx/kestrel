const ORIGINS = ["https://evil.example", "null", "https://kestrel.test"];

export default {
  async run(ctx) {
    if (!ctx.target?.startsWith("http")) return;
    for (const origin of ORIGINS) {
      try {
        const res = await ctx.http(ctx.target, {
          method: "GET",
          headers: { origin, accept: "text/html" },
          timeout: 10_000,
        });
        const allow = res.headers["access-control-allow-origin"];
        const creds = res.headers["access-control-allow-credentials"];
        if (!allow) continue;
        if (allow === origin || allow === "*") {
          ctx.add({
            ruleId: "cors-reflect",
            title: `CORS reflects ${origin}`,
            description: `Origin \`${origin}\` is allowed (${allow}) with credentials=${creds || "false"}.`,
            severity: creds === "true" ? "high" : "low",
            confidence: "high",
            cwe: "CWE-942",
            owasp: "A05:2021",
            tags: ["cors", "dynamic"],
            evidence: { origin, allow, credentials: creds, status: res.status },
            remediation: "Use a strict origin allow-list and add `Vary: Origin`.",
            references: ["https://cwe.mitre.org/data/definitions/942.html"],
            assetValue: ctx.target,
            assetKind: "url",
          });
        }
      } catch (err) {
        ctx.emit("debug", `CORS probe failed for ${origin}: ${err.message}`);
      }
    }
  },
};
