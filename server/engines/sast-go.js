import fsp from "node:fs/promises";
import { snippetAt } from "../lib/util.js";

const SOURCE_RE = /(?:r\.URL\.Query\(\)\.Get|c\.Query|c\.Param|c\.PostForm|r\.FormValue|r\.Header\.Get|os\.Args|flag\.Arg)\(/;
const ASSIGN_RE = /^\s*(\w+)\s*:?=\s*(.+)$/;
const SANITIZER_RE = /(?:strconv\.(?:Atoi|ParseInt|ParseFloat)|filepath\.Base|url\.QueryEscape|template\.HTMLEscapeString|html\.EscapeString|uuid\.Parse)\(/;

function cvss(sev) {
  return {
    critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev];
}

export default {
  id: "sast-go",
  name: "Go Taint Analyst",
  description: "Go source taint tracking for command, SQL, path, SSRF and template sinks plus TLS/crypto hardening.",
  category: "sast",
  targetTypes: ["code", "mixed"],
  cost: "medium",
  async run(ctx) {
    let files = 0;
    for (const file of ctx.files) {
      if (file.lang !== "go") continue;
      files += 1;
      const text = await fsp.readFile(file.abs, "utf8");
      const lines = text.split(/\r?\n/);
      const tainted = new Map();
      const report = (ruleId, line, data) => {
        ctx.add({
          engine: "sast-go",
          ruleId,
          file: file.rel,
          line,
          snippet: snippetAt(text, line, 3),
          ...data,
        });
      };
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        const lineNo = i + 1;
        const assign = line.match(ASSIGN_RE);
        if (assign && SOURCE_RE.test(assign[2]) && !SANITIZER_RE.test(assign[2])) {
          tainted.set(assign[1], { line: lineNo, code: line.trim() });
        }
        const taintedVar = (expr) => {
          for (const [name, source] of tainted) {
            if (new RegExp(`\\b${name}\\b`).test(expr)) return source;
          }
          return null;
        };
        if (SOURCE_RE.test(line) && /(?:exec\.Command|db\.(?:Query|Exec)|os\.Open|http\.Get|filepath\.Join)/.test(line)) {
          const source = { line: lineNo, code: line.trim() };
          if (/exec\.Command/.test(line)) {
            report("command-injection", lineNo, {
              title: "Command execution with request-derived argument",
              description: "Request data is passed to exec.Command. Arguments are safe from shell expansion, but option injection remains possible.",
              severity: "high", confidence: "medium", cwe: "CWE-78", owasp: "A03:2021",
              cvssVector: cvss("high"), tags: ["execution"],
              taint: { source, sink: { line: lineNo, code: line.trim() }, steps: [] },
              evidence: { code: line.trim() },
              remediation: "Validate against an allow-list and use `--` before positional arguments to stop option injection.",
              references: ["https://cwe.mitre.org/data/definitions/78.html"],
            });
          }
          if (/db\.(?:Query|Exec)/.test(line)) {
            report("sql-injection", lineNo, {
              title: "SQL query with request-derived text",
              description: "A query is built from request data. Verify placeholders are used for every value.",
              severity: "critical", confidence: "medium", cwe: "CWE-89", owasp: "A03:2021",
              cvssVector: cvss("critical"), tags: ["database", "entry"],
              taint: { source, sink: { line: lineNo, code: line.trim() }, steps: [] },
              evidence: { code: line.trim() },
              remediation: "Use `$1`/`?` placeholders and pass values as separate arguments.",
              references: ["https://cwe.mitre.org/data/definitions/89.html"],
            });
          }
          if (/os\.Open/.test(line)) {
            report("path-traversal", lineNo, {
              title: "File open with request-derived path",
              description: "A request value reaches os.Open without a proven root confinement.",
              severity: "high", confidence: "medium", cwe: "CWE-22", owasp: "A01:2021",
              cvssVector: cvss("high"), tags: ["filesystem"],
              taint: { source, sink: { line: lineNo, code: line.trim() }, steps: [] },
              evidence: { code: line.trim() },
              remediation: "Clean the path, join against a fixed root and verify the prefix.",
              references: ["https://cwe.mitre.org/data/definitions/22.html"],
            });
          }
          if (/http\.Get/.test(line)) {
            report("ssrf", lineNo, {
              title: "SSRF via http.Get",
              description: "A request-controlled URL is fetched server-side.",
              severity: "high", confidence: "high", cwe: "CWE-918", owasp: "A10:2021",
              cvssVector: cvss("high"), tags: ["network"],
              taint: { source, sink: { line: lineNo, code: line.trim() }, steps: [] },
              evidence: { code: line.trim() },
              remediation: "Allow-list hosts and schemes, reject private IPs and cap redirects.",
              references: ["https://cwe.mitre.org/data/definitions/918.html"],
            });
          }
        }
        const source = taintedVar(line);
        if (source) {
          if (/\bexec\.Command\(/.test(line)) {
            report("command-injection", lineNo, {
              title: "Command execution with tainted variable",
              description: `\`${source.code}\` flows into exec.Command.`,
              severity: "high", confidence: "high", cwe: "CWE-78", owasp: "A03:2021",
              cvssVector: cvss("high"), tags: ["execution"],
              taint: { source, sink: { line: lineNo, code: line.trim() }, steps: [] },
              evidence: { code: line.trim() },
              remediation: "Allow-list values and separate options from positional arguments.",
              references: ["https://cwe.mitre.org/data/definitions/78.html"],
            });
          }
          if (/db\.(?:Query|Exec)\(/.test(line) && /(?:fmt\.Sprintf|\+)/.test(line)) {
            report("sql-injection", lineNo, {
              title: "SQL string built with tainted variable",
              description: `\`${source.code}\` is concatenated into a SQL statement.`,
              severity: "critical", confidence: "high", cwe: "CWE-89", owasp: "A03:2021",
              cvssVector: cvss("critical"), tags: ["database", "entry"],
              taint: { source, sink: { line: lineNo, code: line.trim() }, steps: [] },
              evidence: { code: line.trim() },
              remediation: "Use placeholders and separate arguments.",
              references: ["https://cwe.mitre.org/data/definitions/89.html"],
            });
          }
          if (/filepath\.Join\(/.test(line) && !/filepath\.Clean/.test(line)) {
            report("path-traversal", lineNo, {
              title: "filepath.Join with tainted segment",
              description: "filepath.Join cleans separators but does not stop `..` escaping the root.",
              severity: "medium", confidence: "medium", cwe: "CWE-22", owasp: "A01:2021",
              cvssVector: cvss("medium"), tags: ["filesystem"],
              taint: { source, sink: { line: lineNo, code: line.trim() }, steps: [] },
              evidence: { code: line.trim() },
              remediation: "Resolve with filepath.Abs and verify the result starts with the intended root.",
              references: ["https://cwe.mitre.org/data/definitions/22.html"],
            });
          }
          if (/template\.HTML\(/.test(line)) {
            report("xss", lineNo, {
              title: "template.HTML with tainted value",
              description: "The value bypasses contextual escaping.",
              severity: "medium", confidence: "medium", cwe: "CWE-79", owasp: "A03:2021",
              cvssVector: cvss("medium"), tags: ["xss"],
              taint: { source, sink: { line: lineNo, code: line.trim() }, steps: [] },
              evidence: { code: line.trim() },
              remediation: "Sanitize with bluemonday before converting to template.HTML.",
              references: ["https://cwe.mitre.org/data/definitions/79.html"],
            });
          }
        }
      }
      if (/InsecureSkipVerify:\s*true/.test(text)) {
        report("tls-verify-disabled", 1, {
          title: "TLS verification disabled",
          description: "InsecureSkipVerify accepts any certificate.",
          severity: "medium", confidence: "high", cwe: "CWE-295", owasp: "A02:2021",
          cvssVector: cvss("medium"), tags: ["tls"], evidence: { file: file.rel },
          remediation: "Pin the expected CA and enable verification in production.",
          references: ["https://cwe.mitre.org/data/definitions/295.html"],
        });
      }
      if (/math\/rand/.test(text) && /(?:token|nonce|secret|session)/i.test(text)) {
        report("insecure-random", 1, {
          title: "math/rand for security value",
          description: "math/rand is predictable. Tokens should use crypto/rand.",
          severity: "medium", confidence: "medium", cwe: "CWE-338", owasp: "A02:2021",
          cvssVector: cvss("medium"), tags: ["crypto"], evidence: { file: file.rel },
          remediation: "Use crypto/rand and encode with base64.RawURLEncoding.",
          references: ["https://cwe.mitre.org/data/definitions/338.html"],
        });
      }
      if (/md5\.New|sha1\.New/.test(text)) {
        report("weak-hash", 1, {
          title: "Weak hash algorithm",
          description: "MD5/SHA-1 are collision-prone.",
          severity: "low", confidence: "high", cwe: "CWE-328", owasp: "A02:2021",
          cvssVector: cvss("low"), tags: ["crypto"], evidence: { file: file.rel },
          remediation: "Use SHA-256+ for integrity and Argon2id/bcrypt for passwords.",
          references: ["https://cwe.mitre.org/data/definitions/328.html"],
        });
      }
      if (/http\.ListenAndServe\(/.test(text) && !/ListenAndServeTLS/.test(text)) {
        report("plaintext-http", 1, {
          title: "HTTP server without TLS",
          description: "http.ListenAndServe serves plaintext unless a TLS terminator is guaranteed.",
          severity: "low", confidence: "low", cwe: "CWE-319", owasp: "A02:2021",
          cvssVector: cvss("low"), tags: ["tls"], evidence: { file: file.rel },
          remediation: "Use ListenAndServeTLS or document the trusted TLS terminator.",
          references: ["https://cwe.mitre.org/data/definitions/319.html"],
        });
      }
      if (/os\.Chmod\([^)]*0?777\)/.test(text)) {
        report("world-writable", 1, {
          title: "World-writable file permissions",
          description: "Mode 0777 lets any local user modify the file.",
          severity: "low", confidence: "high", cwe: "CWE-732", owasp: "A01:2021",
          cvssVector: cvss("low"), tags: ["filesystem"], evidence: { file: file.rel },
          remediation: "Use 0640/0600 unless executable by everyone is required.",
          references: ["https://cwe.mitre.org/data/definitions/732.html"],
        });
      }
      if (/io\.ReadAll\(/.test(text) && !/LimitReader/.test(text)) {
        report("unbounded-read", 1, {
          title: "Unbounded response read",
          description: "io.ReadAll without io.LimitReader can exhaust memory on large responses.",
          severity: "low", confidence: "medium", cwe: "CWE-400", owasp: "A05:2021",
          cvssVector: cvss("low"), tags: ["dos"], evidence: { file: file.rel },
          remediation: "Wrap the reader in io.LimitReader with an explicit byte budget.",
          references: ["https://cwe.mitre.org/data/definitions/400.html"],
        });
      }
    }
    ctx.emit("info", `Analyzed ${files} Go files`);
  },
};
