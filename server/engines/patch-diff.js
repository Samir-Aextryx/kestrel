import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fsp from "node:fs/promises";
import path from "node:path";
import { db } from "../db.js";

const exec = promisify(execFile);

const REGRESSIONS = [
  { re: /^-\s*.*(?:auth|authenticate|requireAuth|login_required|jwt\.verify|csrf|sanitize|escape|validate|helmet|rateLimit|limit)/i, rule: "removed-control", title: "Security control removed", sev: "high", cwe: "CWE-693", desc: "A line that referenced a security control was removed." },
  { re: /^\+\s*.*\beval\s*\(/, rule: "added-eval", title: "eval() introduced", sev: "medium", cwe: "CWE-95", desc: "Dynamic code evaluation was added." },
  { re: /^\+\s*.*\.innerHTML\s*=/, rule: "added-innerhtml", title: "innerHTML assignment introduced", sev: "medium", cwe: "CWE-79", desc: "Raw HTML assignment was added." },
  { re: /^\+\s*.*(?:exec|execSync|system)\s*\(/, rule: "added-exec", title: "Shell execution introduced", sev: "medium", cwe: "CWE-78", desc: "A process execution sink was added." },
  { re: /^\+\s*.*(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify)/, rule: "tls-off", title: "TLS verification disabled", sev: "medium", cwe: "CWE-295", desc: "Certificate verification was turned off." },
  { re: /^\+\s*.*(?:Access-Control-Allow-Origin|origin\s*:\s*['"]\*['"]|cors\()/, rule: "cors-change", title: "CORS configuration changed", sev: "low", cwe: "CWE-942", desc: "CORS behavior was modified; verify the origin policy." },
  { re: /^\+\s*.*@csrf_exempt/, rule: "csrf-exempt", title: "CSRF exemption added", sev: "medium", cwe: "CWE-352", desc: "An endpoint was exempted from CSRF protection." },
  { re: /^\+\s*.*(?:md5|sha1)\s*\(/, rule: "weak-hash", title: "Weak hash introduced", sev: "low", cwe: "CWE-328", desc: "MD5/SHA-1 was added." },
  { re: /^\+\s*.*(?:TODO|FIXME|XXX).*(?:auth|security|validate|sanitize|escape)/i, rule: "security-todo", title: "Security TODO added", sev: "info", cwe: "CWE-1059", desc: "A security follow-up was left in the code." },
  { re: /^\+\s*.*(?:httpOnly|secure|sameSite)\s*:\s*(?:false|['"]none['"])/i, rule: "cookie-weak", title: "Cookie security weakened", sev: "medium", cwe: "CWE-614", desc: "A cookie flag was disabled or relaxed." },
];

async function gitDiff(root, base) {
  const { stdout } = await exec("git", ["diff", "--unified=0", "--no-color", base, "--", "."], {
    cwd: root,
    maxBuffer: 32 * 1024 * 1024,
    timeout: 45_000,
  });
  return stdout;
}

export default {
  id: "patch-diff",
  name: "Patch Diff Analyst",
  description: "Security regression review of Git diffs and comparison against a parent scan.",
  category: "research",
  targetTypes: ["code", "mixed"],
  cost: "low",
  async run(ctx) {
    if (ctx.scan.parent_scan_id) {
      const parent = db.prepare("SELECT id FROM scans WHERE id = ?").get(ctx.scan.parent_scan_id);
      if (parent) {
        const rows = db
          .prepare(
            `SELECT f.* FROM findings f WHERE f.scan_id = ?
             AND f.severity IN ('critical','high') AND f.fingerprint NOT IN
             (SELECT fingerprint FROM findings WHERE scan_id = ?)`,
          )
          .all(ctx.scan.id, parent.id);
        for (const row of rows) {
          ctx.add({
            engine: "patch-diff",
            ruleId: "regression-vs-parent",
            title: `New ${row.severity} finding since parent scan: ${row.title}`,
            description: "This finding did not exist in the parent scan and represents a regression.",
            severity: row.severity,
            confidence: "high",
            file: row.file,
            line: row.line,
            cwe: row.cwe,
            owasp: row.owasp,
            tags: ["regression"],
            evidence: { parentScan: parent.id, fingerprint: row.fingerprint },
            remediation: "Triage the regression before merging.",
            references: [],
          });
        }
        ctx.emit("info", `Compared against parent scan: ${rows.length} regressions`);
        return;
      }
    }
    let diff;
    try {
      await fsp.access(path.join(ctx.root, ".git"));
      diff = await gitDiff(ctx.root, ctx.config.diffBase || "HEAD~1");
    } catch (err) {
      ctx.emit("info", `No Git diff available (${err.message.slice(0, 120)})`);
      return;
    }
    if (!diff.trim()) {
      ctx.emit("info", "Diff is empty");
      return;
    }
    let file = null;
    let line = 0;
    let count = 0;
    for (const raw of diff.split(/\r?\n/)) {
      if (raw.startsWith("+++ b/")) {
        file = raw.slice(6);
        continue;
      }
      const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
      if (hunk) {
        line = Number(hunk[1]);
        continue;
      }
      if (!file || !raw.startsWith("+") || raw.startsWith("+++")) continue;
      for (const rule of REGRESSIONS) {
        if (!rule.re.test(raw)) continue;
        count += 1;
        ctx.add({
          engine: "patch-diff",
          ruleId: rule.rule,
          title: rule.title,
          description: `${rule.desc}\n\nChanged line: \`${raw.slice(1).trim().slice(0, 400)}\``,
          severity: rule.sev,
          confidence: "medium",
          file,
          line,
          cwe: rule.cwe,
          owasp: "A05:2021",
          tags: ["diff", "regression"],
          evidence: { diffLine: raw.slice(1).trim(), base: ctx.config.diffBase || "HEAD~1" },
          remediation: "Review the change in context and confirm the control is still effective.",
          references: [`https://cwe.mitre.org/data/definitions/${rule.cwe.replace("CWE-", "")}.html`],
        });
        break;
      }
      line += 1;
    }
    ctx.emit("info", `Reviewed diff against ${ctx.config.diffBase || "HEAD~1"}: ${count} security-relevant changes`);
  },
};
