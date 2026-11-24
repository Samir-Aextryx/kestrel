import fsp from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";

function cvss(sev) {
  return {
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev];
}

const SECRET_FIELDS = /password|passwd|secret|token|api[_-]?key|private[_-]?key|credit[_-]?card|ssn/i;

function operations(doc) {
  const out = [];
  for (const [route, item] of Object.entries(doc.paths || {})) {
    for (const method of ["get", "post", "put", "patch", "delete", "options", "head"]) {
      if (item?.[method]) out.push({ route, method, op: item[method], item });
    }
  }
  return out;
}

function walkSchemas(schema, cb, seen = new Set()) {
  if (!schema || typeof schema !== "object" || seen.has(schema)) return;
  seen.add(schema);
  cb(schema);
  for (const value of Object.values(schema)) {
    if (value && typeof value === "object") walkSchemas(value, cb, seen);
  }
}

export default {
  id: "api",
  name: "API Contract Analyst",
  description: "OpenAPI/Swagger authorization, data exposure, input-bound and error-contract review.",
  category: "api",
  targetTypes: ["api", "code", "mixed"],
  cost: "low",
  async run(ctx) {
    const docs = [];
    for (const file of ctx.files) {
      if (!/\.(?:json|ya?ml)$/i.test(file.rel)) continue;
      if (!/(?:openapi|swagger)/i.test(path.basename(file.rel))) continue;
      const text = await fsp.readFile(file.abs, "utf8");
      try {
        const doc = file.rel.endsWith(".json") ? JSON.parse(text) : YAML.parse(text);
        if (doc?.paths) docs.push({ doc, file: file.rel, text });
      } catch {
        /* ignore malformed */
      }
    }
    if (ctx.webUrl && !docs.length) {
      for (const candidate of ["/openapi.json", "/swagger.json", "/v3/api-docs"]) {
        try {
          const res = await ctx.scope.fetch(new URL(candidate, ctx.webUrl).toString(), { accept: "application/json" });
          if (res.status === 200) {
            const doc = JSON.parse(res.text);
            if (doc?.paths) {
              docs.push({ doc, file: candidate, text: res.text });
              break;
            }
          }
        } catch {
          /* ignore */
        }
      }
    }
    if (!docs.length) {
      ctx.emit("info", "No OpenAPI/Swagger contract found");
      return;
    }
    for (const { doc, file, text } of docs) {
      const add = (raw, line = 1) => {
        ctx.add({
          engine: "api",
          file,
          line,
          snippet: text.split("\n").slice(Math.max(0, line - 3), line + 2).join("\n"),
          ...raw,
        });
      };
      ctx.emit("info", `Reviewing API contract ${file} (${Object.keys(doc.paths || {}).length} paths)`);
      for (const server of doc.servers || []) {
        if (String(server.url || "").startsWith("http://")) {
          add({
            ruleId: "api-http-server",
            title: "API server uses plaintext HTTP",
            description: `Server URL ${server.url} is unencrypted.`,
            severity: "medium", confidence: "high", cwe: "CWE-319", owasp: "A02:2021",
            cvssVector: cvss("medium"), tags: ["tls"], evidence: { server },
            remediation: "Use HTTPS for all declared servers.",
            references: ["https://cwe.mitre.org/data/definitions/319.html"],
          });
        }
      }
      const schemes = doc.components?.securitySchemes || doc.securityDefinitions || {};
      if (!Object.keys(schemes).length) {
        add({
          ruleId: "api-no-security-scheme",
          title: "No security scheme defined",
          description: "The contract defines no authentication mechanism, so operations are likely anonymous or inconsistently protected.",
          severity: "high", confidence: "medium", cwe: "CWE-306", owasp: "A01:2021",
          cvssVector: cvss("high"), tags: ["auth"], evidence: { file },
          remediation: "Define OAuth2/OIDC or bearer auth and apply it globally, overriding only public operations.",
          references: ["https://cwe.mitre.org/data/definitions/306.html"],
        });
      }
      const globalSecurity = Array.isArray(doc.security) && doc.security.length > 0;
      for (const { route, method, op } of operations(doc)) {
        const line = Math.max(1, text.split("\n").findIndex((l) => l.includes(route)) + 1);
        if (!globalSecurity && !(op.security || []).length) {
          add({
            ruleId: "api-operation-no-auth",
            title: `${method.toUpperCase()} ${route} has no security requirement`,
            description: "The operation inherits no global auth and declares none locally.",
            severity: "high", confidence: "medium", cwe: "CWE-306", owasp: "A01:2021",
            cvssVector: cvss("high"), tags: ["auth", "entry"], evidence: { route, method },
            remediation: "Add a security requirement or document why the operation is public.",
            references: ["https://cwe.mitre.org/data/definitions/306.html"],
          }, line);
        }
        for (const param of [...(op.parameters || []), ...(op.item?.parameters || [])]) {
          if (param.in === "path" && !param.required) {
            add({
              ruleId: "api-path-param-optional",
              title: `Path parameter ${param.name} not marked required`,
              description: "Path parameters are always present; the contract is inaccurate.",
              severity: "low", confidence: "high", cwe: "CWE-1059", owasp: "A04:2021",
              cvssVector: cvss("low"), tags: ["contract"], evidence: { param: param.name },
              remediation: "Set `required: true`.",
              references: ["https://cwe.mitre.org/data/definitions/1059.html"],
            }, line);
          }
          if (!param.schema) {
            add({
              ruleId: "api-param-no-schema",
              title: `Parameter ${param.name} has no schema`,
              description: "Without a schema, generated clients and validators cannot enforce type or bounds.",
              severity: "low", confidence: "high", cwe: "CWE-1059", owasp: "A04:2021",
              cvssVector: cvss("low"), tags: ["contract"], evidence: { param: param.name },
              remediation: "Add a typed schema with bounds and pattern.",
              references: ["https://cwe.mitre.org/data/definitions/1059.html"],
            }, line);
          }
        }
        if (op.requestBody && !op.requestBody.content) {
          add({
            ruleId: "api-body-no-content",
            title: `${method.toUpperCase()} ${route} request body has no content schema`,
            description: "The body contract is untyped.",
            severity: "low", confidence: "high", cwe: "CWE-1059", owasp: "A04:2021",
            cvssVector: cvss("low"), tags: ["contract"], evidence: { route },
            remediation: "Declare media types and schemas for the body.",
            references: ["https://cwe.mitre.org/data/definitions/1059.html"],
          }, line);
        }
        if (["post", "put", "patch"].includes(method) && !op.requestBody) {
          add({
            ruleId: "api-mutation-no-body",
            title: `${method.toUpperCase()} ${route} has no request body`,
            description: "A mutating operation without a body may rely on untyped query parameters.",
            severity: "info", confidence: "medium", cwe: "CWE-1059", owasp: "A04:2021",
            cvssVector: cvss("low"), tags: ["contract"], evidence: { route },
            remediation: "Document the expected body or move parameters explicitly.",
            references: ["https://cwe.mitre.org/data/definitions/1059.html"],
          }, line);
        }
        const responses = op.responses || {};
        if (!responses["401"] && !responses["403"] && (op.security || globalSecurity)) {
          add({
            ruleId: "api-no-auth-response",
            title: `${method.toUpperCase()} ${route} lacks 401/403 responses`,
            description: "Authentication failures are not part of the contract.",
            severity: "low", confidence: "medium", cwe: "CWE-1059", owasp: "A04:2021",
            cvssVector: cvss("low"), tags: ["contract"], evidence: { route },
            remediation: "Document 401 and 403 responses.",
            references: ["https://cwe.mitre.org/data/definitions/1059.html"],
          }, line);
        }
        if (!responses["429"] && ["post", "put", "patch"].includes(method)) {
          add({
            ruleId: "api-no-rate-limit-response",
            title: `${method.toUpperCase()} ${route} lacks a 429 response`,
            description: "Rate limiting is not part of the contract.",
            severity: "info", confidence: "low", cwe: "CWE-770", owasp: "A04:2021",
            cvssVector: cvss("low"), tags: ["contract", "dos"], evidence: { route },
            remediation: "Document 429 and Retry-After behavior.",
            references: ["https://cwe.mitre.org/data/definitions/770.html"],
          }, line);
        }
      }
      walkSchemas(doc.components?.schemas || {}, (schema) => {
        if (schema.type === "string" && !schema.maxLength && !schema.enum && !schema.format) {
          add({
            ruleId: "api-unbounded-string",
            title: "String schema without maxLength",
            description: "Unbounded strings can inflate storage and parsing cost.",
            severity: "low", confidence: "low", cwe: "CWE-770", owasp: "A04:2021",
            cvssVector: cvss("low"), tags: ["contract", "dos"], evidence: { schema: schema.title || schema },
            remediation: "Set maxLength and a pattern where applicable.",
            references: ["https://cwe.mitre.org/data/definitions/770.html"],
          });
        }
        if (schema.type === "array" && !schema.maxItems) {
          add({
            ruleId: "api-unbounded-array",
            title: "Array schema without maxItems",
            description: "Large arrays can exhaust memory or trigger expensive batch work.",
            severity: "low", confidence: "low", cwe: "CWE-770", owasp: "A04:2021",
            cvssVector: cvss("low"), tags: ["contract", "dos"], evidence: { schema: schema.title || schema },
            remediation: "Set maxItems and document pagination.",
            references: ["https://cwe.mitre.org/data/definitions/770.html"],
          });
        }
        if (schema.additionalProperties === true) {
          add({
            ruleId: "api-additional-properties",
            title: "Schema allows arbitrary additional properties",
            description: "Unknown keys can reach mass-assignment logic.",
            severity: "medium", confidence: "medium", cwe: "CWE-915", owasp: "A08:2021",
            cvssVector: cvss("medium"), tags: ["contract", "mass-assignment"], evidence: { schema: schema.title || schema },
            remediation: "Set `additionalProperties: false` or filter allowed keys.",
            references: ["https://cwe.mitre.org/data/definitions/915.html"],
          });
        }
        for (const [name, prop] of Object.entries(schema.properties || {})) {
          if (SECRET_FIELDS.test(name) && prop.type === "string" && !prop.writeOnly && !prop.readOnly) {
            add({
              ruleId: "api-secret-field-exposed",
              title: `Sensitive field ${name} lacks writeOnly/readOnly`,
              description: "Password/token fields can leak in responses if they are not marked writeOnly.",
              severity: "medium", confidence: "medium", cwe: "CWE-200", owasp: "A01:2021",
              cvssVector: cvss("medium"), tags: ["contract", "exposure"], evidence: { field: name },
              remediation: "Mark write-only secrets `writeOnly: true` and format them as `password`.",
              references: ["https://cwe.mitre.org/data/definitions/200.html"],
            });
          }
        }
      });
    }
  },
};
