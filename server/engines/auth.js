import crypto from "node:crypto";
import { db } from "../db.js";

const CREDS = [
  ["admin", "admin"],
  ["admin", "password"],
  ["admin", "admin123"],
  ["root", "root"],
  ["test", "test"],
];

const JWT_SECRETS = ["secret", "password", "changeme", "jwt", "dev", "test", "kestrel", "supersecret", "secretkey"];

function cvss(sev) {
  return {
    critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
  }[sev];
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function formOf(html, base) {
  for (const match of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = match[1];
    const body = match[2];
    if (!/type=["']?password/i.test(body)) continue;
    const action = attrs.match(/action=["']([^"']+)["']/i)?.[1] || base;
    const method = /method=["']?post/i.test(attrs) ? "POST" : "GET";
    const fields = {};
    for (const input of body.matchAll(/<input\b([^>]*)>/gi)) {
      const name = input[1].match(/name=["']([^"']+)["']/i)?.[1];
      if (!name) continue;
      const value = input[1].match(/value=["']([^"']*)["']/i)?.[1] || "";
      fields[name] = value;
    }
    const userField = Object.keys(fields).find((n) => /user|email|login|name/i.test(n)) || "username";
    const passField = Object.keys(fields).find((n) => /pass/i.test(n)) || "password";
    return { action: new URL(action, base).toString(), method, fields, userField, passField };
  }
  return null;
}

function cookieHeader(headers) {
  const raw = headers["set-cookie"];
  if (!raw) return "";
  return (Array.isArray(raw) ? raw : [raw]).map((c) => c.split(";")[0]).join("; ");
}

export default {
  id: "auth",
  name: "Authentication Analyst",
  description: "Basic-auth and form default credentials, JWT weak-secret cracking and alg:none acceptance.",
  category: "auth",
  targetTypes: ["web", "api", "mixed"],
  dynamic: true,
  cost: "medium",
  async run(ctx) {
    const target = ctx.webUrl;
    if (!target) return;
    let res;
    try {
      res = await ctx.scope.fetch(target, { accept: "text/html", timeout: 12_000 });
    } catch (err) {
      ctx.emit("warn", `Auth probe skipped: ${err.message}`);
      return;
    }
    const base = new URL(target);
    const cookies = cookieHeader(res.headers);
    const add = (raw) => ctx.add({ engine: "auth", assetKind: "url", assetValue: target, ...raw });

    if (res.status === 401 && /basic/i.test(String(res.headers["www-authenticate"] || ""))) {
      for (const [user, pass] of CREDS) {
        try {
          const attempt = await ctx.scope.fetch(target, {
            headers: { authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}` },
            timeout: 10_000,
          });
          if (attempt.status >= 200 && attempt.status < 400) {
            add({
              ruleId: "default-basic-creds",
              title: `Default Basic auth credentials accepted (${user}:${pass})`,
              description: "The endpoint accepts a well-known default credential pair.",
              severity: "high",
              confidence: "high",
              cwe: "CWE-1392",
              owasp: "A07:2021",
              cvssVector: cvss("high"),
              tags: ["auth", "default-creds"],
              evidence: { username: user, password: pass, status: attempt.status },
              remediation: "Rotate the default password and enforce a credential policy.",
              references: ["https://cwe.mitre.org/data/definitions/1392.html"],
            });
            ctx.addAsset("credential", `${user}:${pass}`, { kind: "basic", valid: true });
            db.prepare(
              "INSERT INTO credentials(id, scan_id, kind, username, secret, source, valid, meta_json, created_at) VALUES(?, ?, 'basic', ?, ?, 'http', 1, '{}', ?)",
            ).run(crypto.randomUUID(), ctx.scan.id, user, pass, new Date().toISOString());
            break;
          }
        } catch {
          /* continue */
        }
      }
    }

    const form = formOf(res.text, target);
    if (form) {
      for (const [user, pass] of CREDS) {
        try {
          const body = new URLSearchParams({ ...form.fields, [form.userField]: user, [form.passField]: pass }).toString();
          const attempt = await ctx.scope.fetch(form.action, {
            method: form.method,
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              ...(cookies ? { cookie: cookies } : {}),
            },
            body,
            timeout: 12_000,
          });
          const success =
            (attempt.status >= 300 && attempt.status < 400) ||
            (!/type=["']?password/i.test(attempt.text) && !/invalid|incorrect|failed/i.test(attempt.text.slice(0, 4000)));
          if (success) {
            add({
              ruleId: "default-form-creds",
              title: `Default form credentials accepted (${user}:${pass})`,
              description: `The login form at ${form.action} accepted a default credential pair.`,
              severity: "high",
              confidence: "medium",
              cwe: "CWE-1392",
              owasp: "A07:2021",
              cvssVector: cvss("high"),
              tags: ["auth", "default-creds", "login"],
              evidence: { username: user, password: pass, status: attempt.status, action: form.action },
              remediation: "Rotate the default password, add MFA and rate limiting.",
              references: ["https://cwe.mitre.org/data/definitions/1392.html"],
            });
            ctx.addAsset("credential", `${user}:${pass}`, { kind: "form", valid: true, action: form.action });
            db.prepare(
              "INSERT INTO credentials(id, scan_id, kind, username, secret, source, valid, meta_json, created_at) VALUES(?, ?, 'form', ?, ?, ?, 1, ?, ?)",
            ).run(crypto.randomUUID(), ctx.scan.id, user, pass, form.action, JSON.stringify({ action: form.action }), new Date().toISOString());
            break;
          }
        } catch {
          /* continue */
        }
        await new Promise((r) => setTimeout(r, 250));
      }
    }

    const jwtMatch = `${cookies}\n${res.text}`.match(/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/);
    if (jwtMatch) {
      const token = jwtMatch[0];
      const [header, payload, signature] = token.split(".");
      const cookieName = (Array.isArray(res.headers["set-cookie"]) ? res.headers["set-cookie"] : [res.headers["set-cookie"] || ""])
        .map((c) => c.split("=")[0])
        .find((name) => name && /token|jwt|session|auth/i.test(name)) || "token";
      for (const secret of JWT_SECRETS) {
        const expected = crypto.createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url");
        if (expected === signature) {
          add({
            ruleId: "jwt-weak-secret",
            title: `JWT signed with weak secret "${secret}"`,
            description: "The HS256 signature matches a common dictionary secret. Anyone can mint tokens.",
            severity: "critical",
            confidence: "high",
            cwe: "CWE-326",
            owasp: "A02:2021",
            cvssVector: cvss("critical"),
            tags: ["auth", "jwt", "crypto"],
            evidence: { secret, cookieName, payload: Buffer.from(payload, "base64url").toString("utf8").slice(0, 500) },
            remediation: "Use a long random secret or asymmetric keys, and rotate the current key.",
            references: ["https://cwe.mitre.org/data/definitions/326.html"],
          });
          ctx.addAsset("credential", `jwt-secret:${secret}`, { kind: "jwt", valid: true });
          break;
        }
      }
      const none = `${b64url(JSON.stringify({ alg: "none", typ: "JWT" }))}.${payload}.`;
      try {
        const attempt = await ctx.scope.fetch(target, {
          headers: { cookie: `${cookieName}=${none}` },
          timeout: 10_000,
        });
        if (attempt.status >= 200 && attempt.status < 400 && !/type=["']?password/i.test(attempt.text)) {
          add({
            ruleId: "jwt-alg-none",
            title: "JWT alg:none accepted",
            description: "A forged unsigned token was accepted by the target.",
            severity: "critical",
            confidence: "medium",
            cwe: "CWE-347",
            owasp: "A02:2021",
            cvssVector: cvss("critical"),
            tags: ["auth", "jwt"],
            evidence: { cookieName, status: attempt.status, token: none.slice(0, 300) },
            remediation: "Pin the expected algorithm and reject tokens without a signature.",
            references: ["https://cwe.mitre.org/data/definitions/347.html"],
          });
        }
      } catch {
        /* ignore */
      }
    }
    ctx.emit("info", "Authentication analysis complete");
  },
};
