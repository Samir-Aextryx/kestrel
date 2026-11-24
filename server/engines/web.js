import { snippetAt } from "../lib/util.js";

function cvss(sev) {
  return {
    critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev];
}

const HEADER_CHECKS = [
  { header: "content-security-policy", rule: "missing-csp", title: "Missing Content-Security-Policy", sev: "medium", cwe: "CWE-693", desc: "Without CSP, any HTML injection is more likely to become script execution.", fix: "Deploy a nonce-based CSP and remove unsafe-inline/unsafe-eval." },
  { header: "strict-transport-security", rule: "missing-hsts", title: "Missing HSTS", sev: "medium", cwe: "CWE-319", desc: "The first request can be downgraded to plaintext.", fix: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`." },
  { header: "x-content-type-options", rule: "missing-nosniff", title: "Missing X-Content-Type-Options", sev: "low", cwe: "CWE-693", desc: "Browsers may MIME-sniff responses into executable types.", fix: "Send `X-Content-Type-Options: nosniff`." },
  { header: "x-frame-options", rule: "missing-frame-options", title: "Missing clickjacking protection", sev: "low", cwe: "CWE-1021", desc: "The page can be framed by another origin.", fix: "Send `X-Frame-Options: DENY` or a CSP frame-ancestors directive." },
  { header: "referrer-policy", rule: "missing-referrer-policy", title: "Missing Referrer-Policy", sev: "low", cwe: "CWE-200", desc: "URLs and query strings can leak to third parties.", fix: "Send `Referrer-Policy: strict-origin-when-cross-origin`." },
  { header: "permissions-policy", rule: "missing-permissions-policy", title: "Missing Permissions-Policy", sev: "info", cwe: "CWE-693", desc: "Browser features are enabled by default for embedded content.", fix: "Disable unused features explicitly." },
  { header: "cross-origin-opener-policy", rule: "missing-coop", title: "Missing Cross-Origin-Opener-Policy", sev: "low", cwe: "CWE-693", desc: "Cross-window isolation is weaker than necessary.", fix: "Send `Cross-Origin-Opener-Policy: same-origin`." },
];

const EXPOSED_PATHS = [
  { path: "/.git/HEAD", rule: "exposed-git", title: "Exposed Git metadata", sev: "high", cwe: "CWE-538", match: /ref:\s+refs\//, desc: "Git metadata allows full source reconstruction.", fix: "Block `.git/` at the proxy or deploy a build artifact." },
  { path: "/.env", rule: "exposed-env", title: "Exposed .env file", sev: "critical", cwe: "CWE-538", match: /^[A-Z0-9_]+=/m, desc: "Environment files usually contain credentials.", fix: "Serve only from a directory without dotfiles." },
  { path: "/.DS_Store", rule: "exposed-dsstore", title: "Exposed .DS_Store", sev: "low", cwe: "CWE-538", match: /Bud1/, desc: "Directory names are disclosed.", fix: "Exclude .DS_Store from deployments." },
  { path: "/server-status", rule: "exposed-server-status", title: "Apache server-status exposed", sev: "medium", cwe: "CWE-200", match: /Apache Server Status/, desc: "Request and worker details are public.", fix: "Restrict server-status to localhost." },
  { path: "/actuator/env", rule: "exposed-actuator", title: "Spring Actuator env exposed", sev: "high", cwe: "CWE-200", match: /propertySources|activeProfiles/, desc: "Configuration and sometimes secrets are exposed.", fix: "Secure actuator endpoints and restrict exposure." },
  { path: "/swagger-ui.html", rule: "exposed-swagger", title: "Swagger UI exposed", sev: "low", cwe: "CWE-200", match: /swagger/i, desc: "The full API surface is documented publicly.", fix: "Restrict docs to authenticated users in production." },
  { path: "/openapi.json", rule: "exposed-openapi", title: "OpenAPI document exposed", sev: "low", cwe: "CWE-200", match: /"openapi"|"swagger"/, desc: "The API schema is publicly enumerable.", fix: "Restrict or version the schema endpoint." },
  { path: "/graphql", rule: "graphql-endpoint", title: "GraphQL endpoint discovered", sev: "info", cwe: "CWE-200", match: /GraphQL|query/, desc: "GraphQL endpoints need depth, complexity and auth controls.", fix: "Disable introspection in production and enforce query limits." },
  { path: "/package.json", rule: "exposed-package-json", title: "package.json exposed", sev: "low", cwe: "CWE-538", match: /"dependencies"|"name"/, desc: "Dependency versions help target known CVEs.", fix: "Serve only bundled assets." },
  { path: "/Dockerfile", rule: "exposed-dockerfile", title: "Dockerfile exposed", sev: "low", cwe: "CWE-538", match: /FROM\s+\S+/i, desc: "Build details and base images are disclosed.", fix: "Exclude build files from the web root." },
  { path: "/backup.zip", rule: "exposed-backup", title: "Backup archive exposed", sev: "high", cwe: "CWE-538", match: /^PK/, desc: "Backups often contain source and credentials.", fix: "Move backups outside the web root." },
  { path: "/phpinfo.php", rule: "exposed-phpinfo", title: "phpinfo exposed", sev: "medium", cwe: "CWE-200", match: /PHP Version|phpinfo/, desc: "Full PHP configuration is disclosed.", fix: "Remove phpinfo from production." },
  { path: "/.well-known/security.txt", rule: "security-txt", title: "security.txt present", sev: "info", cwe: "CWE-1059", match: /Contact:/i, desc: "A disclosure contact is published.", fix: "Keep the contact and expiry current." },
];

function headerValue(headers, name) {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(", ") : value || "";
}

function add(ctx, raw) {
  ctx.add({
    engine: "web",
    assetKind: "url",
    ...raw,
  });
}

export default {
  id: "web",
  name: "Web Surface Analyst",
  description: "Live header, cookie, CORS, TLS-adjacent, technology and exposed-file analysis with request/response evidence.",
  category: "web",
  targetTypes: ["web", "mixed"],
  dynamic: true,
  cost: "medium",
  async run(ctx) {
    const { scope, emit } = ctx;
    const target = ctx.webUrl;
    if (!target) {
      emit("warn", "No web URL configured; skipping live surface analysis");
      return;
    }
    const base = new URL(target);
    ctx.addAsset("domain", base.hostname);
    ctx.addAsset("url", base.toString());
    let res;
    try {
      res = await scope.fetchFollow(target, { accept: "text/html,application/xhtml+xml" });
    } catch (err) {
      emit("warn", `Target fetch failed: ${err.message}`);
      return;
    }
    const headers = res.headers;
    const body = res.text.slice(0, 200_000);
    const evidence = {
      request: { method: "GET", url: res.url, headers: { accept: "text/html" } },
      response: { status: res.status, headers, body: body.slice(0, 8000) },
      sha256: res.headers.etag || "",
      elapsedMs: res.elapsedMs,
    };
    emit("info", `Fetched ${target} → HTTP ${res.status} in ${res.elapsedMs}ms`);

    if (res.status >= 500) {
      add(ctx, {
        ruleId: "server-error",
        title: `Server error on entry point (HTTP ${res.status})`,
        description: "The root document returns a server error. Error pages often disclose stack traces.",
        severity: "medium", confidence: "high", cwe: "CWE-755", owasp: "A05:2021",
        cvssVector: cvss("medium"), tags: ["availability"], evidence,
        remediation: "Fix the error and serve a sanitized error page.",
        references: ["https://cwe.mitre.org/data/definitions/755.html"],
        assetValue: target,
      });
    }

    if (base.protocol === "http:") {
      add(ctx, {
        ruleId: "plaintext-http",
        title: "Site served over plaintext HTTP",
        description: "Credentials, session cookies and content travel unencrypted.",
        severity: "high", confidence: "high", cwe: "CWE-319", owasp: "A02:2021",
        cvssVector: cvss("high"), tags: ["tls"], evidence,
        remediation: "Redirect all traffic to HTTPS and enable HSTS.",
        references: ["https://cwe.mitre.org/data/definitions/319.html"],
        assetValue: target,
      });
    }

    for (const check of HEADER_CHECKS) {
      if (headerValue(headers, check.header)) continue;
      if (check.header === "strict-transport-security" && base.protocol !== "https:") continue;
      add(ctx, {
        ruleId: check.rule,
        title: check.title,
        description: check.desc,
        severity: check.sev, confidence: "high", cwe: check.cwe, owasp: "A05:2021",
        cvssVector: cvss(check.sev), tags: ["headers"], evidence,
        remediation: check.fix,
        references: [`https://cwe.mitre.org/data/definitions/${check.cwe.replace("CWE-", "")}.html`],
        assetValue: target,
      });
    }

    const csp = headerValue(headers, "content-security-policy");
    if (/unsafe-inline/i.test(csp)) {
      add(ctx, {
        ruleId: "csp-unsafe-inline",
        title: "CSP allows unsafe-inline",
        description: "Inline scripts can execute, reducing CSP protection against XSS.",
        severity: "medium", confidence: "high", cwe: "CWE-693", owasp: "A05:2021",
        cvssVector: cvss("medium"), tags: ["headers", "xss"], evidence,
        remediation: "Move inline scripts to files or add per-response nonces/hashes.",
        references: ["https://cwe.mitre.org/data/definitions/693.html"],
        assetValue: target,
      });
    }
    if (/unsafe-eval/i.test(csp)) {
      add(ctx, {
        ruleId: "csp-unsafe-eval",
        title: "CSP allows unsafe-eval",
        description: "eval and Function constructor remain available to injected code.",
        severity: "low", confidence: "high", cwe: "CWE-693", owasp: "A05:2021",
        cvssVector: cvss("low"), tags: ["headers"], evidence,
        remediation: "Remove unsafe-eval and precompile dynamic templates.",
        references: ["https://cwe.mitre.org/data/definitions/693.html"],
        assetValue: target,
      });
    }
    const hsts = headerValue(headers, "strict-transport-security");
    const maxAge = Number(hsts.match(/max-age=(\d+)/i)?.[1] || 0);
    if (hsts && maxAge > 0 && maxAge < 15_552_000) {
      add(ctx, {
        ruleId: "hsts-short",
        title: "HSTS max-age below six months",
        description: `max-age is ${maxAge}s. Short windows leave room for downgrade after expiry.`,
        severity: "low", confidence: "high", cwe: "CWE-319", owasp: "A02:2021",
        cvssVector: cvss("low"), tags: ["headers", "tls"], evidence,
        remediation: "Raise max-age to at least 31536000 and add includeSubDomains.",
        references: ["https://cwe.mitre.org/data/definitions/319.html"],
        assetValue: target,
      });
    }

    const cors = headerValue(headers, "access-control-allow-origin");
    const credentials = headerValue(headers, "access-control-allow-credentials");
    if (cors === "*" && credentials === "true") {
      add(ctx, {
        ruleId: "cors-wildcard-credentials",
        title: "CORS wildcard with credentials",
        description: "Browsers reject credentialed requests to `*`; the configuration is inconsistent and often worked around insecurely.",
        severity: "medium", confidence: "high", cwe: "CWE-942", owasp: "A05:2021",
        cvssVector: cvss("medium"), tags: ["cors"], evidence,
        remediation: "Reflect a validated origin from an allow-list and set `Vary: Origin`.",
        references: ["https://cwe.mitre.org/data/definitions/942.html"],
        assetValue: target,
      });
    } else if (cors === "*") {
      add(ctx, {
        ruleId: "cors-wildcard",
        title: "CORS allows every origin",
        description: "Any site can read responses that do not require credentials.",
        severity: "low", confidence: "high", cwe: "CWE-942", owasp: "A05:2021",
        cvssVector: cvss("low"), tags: ["cors"], evidence,
        remediation: "Restrict origins to first-party applications.",
        references: ["https://cwe.mitre.org/data/definitions/942.html"],
        assetValue: target,
      });
    }

    const setCookie = headers["set-cookie"] || [];
    for (const cookie of Array.isArray(setCookie) ? setCookie : [setCookie]) {
      const name = cookie.split("=")[0];
      const missing = [];
      if (!/httponly/i.test(cookie)) missing.push("HttpOnly");
      if (!/secure/i.test(cookie)) missing.push("Secure");
      if (!/samesite/i.test(cookie)) missing.push("SameSite");
      if (missing.length) {
        add(ctx, {
          ruleId: "cookie-flags",
          title: `Cookie ${name} missing ${missing.join(", ")}`,
          description: "Weak cookie flags expose the session to script access, plaintext transport or CSRF.",
          severity: "medium", confidence: "high", cwe: "CWE-614", owasp: "A05:2021",
          cvssVector: cvss("medium"), tags: ["session"], evidence: { ...evidence, cookie: cookie.slice(0, 500) },
          remediation: "Set HttpOnly, Secure and SameSite=Lax (or Strict) on session cookies.",
          references: ["https://cwe.mitre.org/data/definitions/614.html"],
          assetValue: target,
        });
      }
    }

    const powered = headerValue(headers, "x-powered-by");
    const server = headerValue(headers, "server");
    if (powered || /[0-9]+\.[0-9]+/.test(server)) {
      add(ctx, {
        ruleId: "version-disclosure",
        title: "Technology version disclosure",
        description: `Headers reveal implementation details (${[powered, server].filter(Boolean).join(" / ")}).`,
        severity: "info", confidence: "high", cwe: "CWE-200", owasp: "A05:2021",
        cvssVector: cvss("low"), tags: ["fingerprint"], evidence,
        remediation: "Remove X-Powered-By and minimize the Server header.",
        references: ["https://cwe.mitre.org/data/definitions/200.html"],
        assetValue: target,
      });
    }

    const tech = [];
    if (/wp-content|wordpress/i.test(body)) tech.push("WordPress");
    if (/_next\//.test(body)) tech.push("Next.js");
    if (/__NUXT__/.test(body)) tech.push("Nuxt");
    if (/ng-version=/.test(body)) tech.push("Angular");
    if (/data-reactroot|react/i.test(body)) tech.push("React");
    if (/laravel_session/i.test(setCookie.join(";"))) tech.push("Laravel");
    if (/JSESSIONID/.test(setCookie.join(";"))) tech.push("Java");
    if (/PHPSESSID/.test(setCookie.join(";"))) tech.push("PHP");
    if (/django/i.test(setCookie.join(";"))) tech.push("Django");
    for (const t of tech) ctx.addAsset("technology", t, { url: target });

    const forms = [...body.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)];
    for (const form of forms) {
      const tag = form[0].slice(0, form[0].indexOf(">") + 1);
      if (/method=["']?post/i.test(tag) && !/csrf|_token|authenticity_token/i.test(form[1])) {
        add(ctx, {
          ruleId: "form-no-csrf",
          title: "POST form without CSRF token",
          description: "A state-changing form does not contain a recognizable anti-CSRF field.",
          severity: "medium", confidence: "medium", cwe: "CWE-352", owasp: "A01:2021",
          cvssVector: cvss("medium"), tags: ["csrf"], evidence: { form: tag.slice(0, 400) },
          remediation: "Add a per-session CSRF token and validate it server-side.",
          references: ["https://cwe.mitre.org/data/definitions/352.html"],
          assetValue: target,
        });
      }
    }

    const scripts = [...body.matchAll(/<script\b[^>]*src=["']([^"']+)["'][^>]*>/gi)];
    for (const script of scripts) {
      const src = script[1];
      if (/^https?:\/\//.test(src) && !new URL(src).hostname.endsWith(base.hostname)) {
        if (!/integrity=/i.test(script[0])) {
          add(ctx, {
            ruleId: "missing-sri",
            title: "Third-party script without Subresource Integrity",
            description: `External script ${src} is loaded without an integrity hash.`,
            severity: "medium", confidence: "high", cwe: "CWE-353", owasp: "A08:2021",
            cvssVector: cvss("medium"), tags: ["supply-chain", "client"], evidence: { script: script[0].slice(0, 400) },
            remediation: "Add `integrity` and `crossorigin` attributes, or self-host the dependency.",
            references: ["https://cwe.mitre.org/data/definitions/353.html"],
            assetValue: target,
          });
        }
      }
    }

    if (base.protocol === "https:" && /http:\/\/[^"'\s>]+/.test(body)) {
      add(ctx, {
        ruleId: "mixed-content",
        title: "Mixed content references",
        description: "The HTTPS page references plaintext HTTP resources.",
        severity: "low", confidence: "medium", cwe: "CWE-319", owasp: "A02:2021",
        cvssVector: cvss("low"), tags: ["tls", "client"], evidence: { match: body.match(/http:\/\/[^"'\s>]+/)?.[0] },
        remediation: "Switch all subresources to HTTPS or protocol-relative URLs.",
        references: ["https://cwe.mitre.org/data/definitions/319.html"],
        assetValue: target,
      });
    }

    for (const probe of EXPOSED_PATHS) {
      const url = new URL(probe.path, base).toString();
      try {
        const r = await scope.fetch(url, { accept: "*/*", timeout: 8000 });
        if (r.status !== 200) continue;
        if (probe.match && !probe.match.test(r.text.slice(0, 4000))) continue;
        ctx.addAsset("endpoint", url, { status: r.status });
        add(ctx, {
          ruleId: probe.rule,
          title: probe.title,
          description: probe.desc,
          severity: probe.sev, confidence: "high", cwe: probe.cwe, owasp: "A05:2021",
          cvssVector: cvss(probe.sev), tags: ["exposure"],
          evidence: {
            request: { method: "GET", url },
            response: { status: r.status, headers: r.headers, body: r.text.slice(0, 2000) },
          },
          remediation: probe.fix,
          references: [`https://cwe.mitre.org/data/definitions/${probe.cwe.replace("CWE-", "")}.html`],
          assetValue: url,
        });
      } catch {
        /* out of budget or unreachable */
      }
    }

    try {
      const opt = await scope.fetch(target, { method: "OPTIONS", timeout: 8000 });
      const allow = headerValue(opt.headers, "allow");
      if (allow) ctx.addAsset("http-methods", allow, { url: target });
      if (/\bTRACE\b/.test(allow)) {
        add(ctx, {
          ruleId: "trace-enabled",
          title: "HTTP TRACE enabled",
          description: "TRACE can echo request headers and is rarely needed.",
          severity: "info", confidence: "high", cwe: "CWE-693", owasp: "A05:2021",
          cvssVector: cvss("low"), tags: ["config"], evidence: { allow },
          remediation: "Disable TRACE at the server/proxy.",
          references: ["https://cwe.mitre.org/data/definitions/693.html"],
          assetValue: target,
        });
      }
    } catch {
      /* ignore */
    }
  },
};
