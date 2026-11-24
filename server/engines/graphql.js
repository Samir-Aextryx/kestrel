import fsp from "node:fs/promises";

function cvss(sev) {
  return {
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev];
}

const INTROSPECTION = `query KestrelIntrospection { __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } } } } }`;

export default {
  id: "graphql",
  name: "GraphQL Analyst",
  description: "Schema authorization, unbounded lists, introspection and input-shape review.",
  category: "api",
  targetTypes: ["api", "code", "mixed"],
  cost: "low",
  async run(ctx) {
    const schemas = ctx.files.filter((f) => /\.(?:graphql|gql)$/i.test(f.rel));
    let count = 0;
    for (const file of schemas) {
      const text = await fsp.readFile(file.abs, "utf8");
      count += 1;
      const add = (raw, line = 1) => ctx.add({
        engine: "graphql",
        file: file.rel,
        line,
        snippet: text.split("\n").slice(Math.max(0, line - 2), line + 2).join("\n"),
        owasp: "A01:2021",
        cvssVector: cvss(raw.severity),
        references: [`https://cwe.mitre.org/data/definitions/${String(raw.cwe).replace("CWE-", "")}.html`],
        ...raw,
      });
      const lines = text.split("\n");
      lines.forEach((line, idx) => {
        if (/^\s*type\s+Mutation\b/.test(line)) {
          const block = text.slice(text.indexOf(line), text.indexOf("}", text.indexOf(line)));
          if (!/@auth|@authenticated|@hasRole|@isAuthenticated/i.test(block)) {
            add({
              ruleId: "graphql-mutation-no-auth",
              title: "Mutation type without auth directive",
              description: "No authorization directive is visible on the mutation type. Auth may still be enforced in resolvers, but the schema does not express it.",
              severity: "medium", confidence: "low", cwe: "CWE-306", tags: ["auth", "graphql"],
              evidence: { type: "Mutation" },
              remediation: "Apply an auth directive or document resolver-level enforcement.",
            }, idx + 1);
          }
        }
        if (/^\s*\w+\s*:\s*\[[A-Z]\w*!?\]!?\s*$/.test(line) && !/@connection|first:|last:|limit/i.test(line)) {
          add({
            ruleId: "graphql-unbounded-list",
            title: "List field without pagination arguments",
            description: "A list field returns an unbounded collection, enabling expensive queries.",
            severity: "low", confidence: "medium", cwe: "CWE-770", tags: ["dos", "graphql"],
            evidence: { field: line.trim() },
            remediation: "Add cursor pagination and a maximum page size.",
          }, idx + 1);
        }
        if (/\b(?:Any|JSON|JSONObject)\b/.test(line) && /:/.test(line)) {
          add({
            ruleId: "graphql-any-scalar",
            title: "Arbitrary JSON scalar in schema",
            description: "Untyped JSON weakens validation and can carry nested attack payloads.",
            severity: "low", confidence: "medium", cwe: "CWE-1059", tags: ["contract", "graphql"],
            evidence: { field: line.trim() },
            remediation: "Use concrete input types or validate the scalar in the resolver.",
          }, idx + 1);
        }
        if (/Upload\b/.test(line)) {
          add({
            ruleId: "graphql-upload",
            title: "File upload scalar present",
            description: "Uploads need size, MIME and content validation.",
            severity: "info", confidence: "high", cwe: "CWE-434", tags: ["upload", "graphql"],
            evidence: { field: line.trim() },
            remediation: "Enforce size limits, magic-byte checks and store outside the web root.",
          }, idx + 1);
        }
      });
    }
    if (ctx.webUrl) {
      const endpoint = new URL("/graphql", ctx.webUrl).toString();
      try {
        const res = await ctx.scope.fetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ query: INTROSPECTION }),
          accept: "application/json",
        });
        if (res.status === 200 && res.text.includes("__schema")) {
          count += 1;
          ctx.addAsset("endpoint", endpoint, { introspection: true });
          ctx.add({
            engine: "graphql",
            ruleId: "graphql-introspection",
            title: "GraphQL introspection enabled",
            description: "The full schema is enumerable by unauthenticated clients.",
            severity: "low", confidence: "high", cwe: "CWE-200", owasp: "A05:2021",
            cvssVector: cvss("low"), tags: ["graphql", "exposure"],
            evidence: { request: { url: endpoint, query: INTROSPECTION }, response: { status: res.status, body: res.text.slice(0, 3000) } },
            remediation: "Disable introspection in production or restrict it to authenticated users.",
            references: ["https://cwe.mitre.org/data/definitions/200.html"],
            assetValue: endpoint,
          });
        }
      } catch {
        /* no endpoint */
      }
    }
    if (count) ctx.emit("info", `Reviewed ${count} GraphQL schema sources`);
  },
};
