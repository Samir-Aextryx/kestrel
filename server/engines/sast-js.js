import fsp from "node:fs/promises";
import { parse } from "@babel/parser";
import { snippetAt } from "../lib/util.js";

const JS_EXT = new Set(["javascript", "typescript"]);
const SOURCE_ROOTS = new Set(["req", "request", "ctx", "event", "location", "window"]);
const SANITIZERS = new Set([
  "parseInt", "parseFloat", "Number", "Boolean", "encodeURIComponent", "encodeURI",
  "escape", "decodeURIComponent", "basename", "normalize", "sanitize", "sanitizeHtml",
  "escapeHtml", "escapeHtml4", "xss", "validator.escape", "DOMPurify.sanitize",
]);
const STRING_METHODS = new Set([
  "toString", "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "slice",
  "substring", "substr", "replace", "replaceAll", "split", "join", "concat", "padStart",
  "padEnd", "normalize", "at",
]);
const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "all", "use", "route"]);

function nameOf(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") {
    const obj = nameOf(node.object);
    const prop = node.computed ? "" : nameOf(node.property);
    return obj && prop ? `${obj}.${prop}` : obj || prop;
  }
  if (node.type === "CallExpression") return nameOf(node.callee);
  if (node.type === "ThisExpression") return "this";
  return "";
}

function codeOf(source, node) {
  return source.slice(node.start, Math.min(node.end, node.start + 300)).replace(/\s+/g, " ").trim();
}

function lineOf(node) {
  return node.loc?.start.line || 1;
}

function isRouteHandler(fn, parent) {
  if (!parent) return false;
  if (parent.type === "CallExpression") {
    const callee = nameOf(parent.callee);
    const last = callee.split(".").pop();
    if (ROUTE_METHODS.has(last)) return true;
  }
  if (parent.type === "VariableDeclarator" && parent.init === fn) {
    return /handler|route|controller|middleware/i.test(nameOf(parent.id));
  }
  return false;
}

function isSource(node) {
  const n = nameOf(node);
  if (!n) return false;
  const root = n.split(".")[0];
  if (SOURCE_ROOTS.has(root)) {
    if (n.startsWith("window.") && !/location|name|postMessage/.test(n)) return false;
    return true;
  }
  if (n === "process.argv" || n.startsWith("process.argv.")) return true;
  if (n === "document.URL" || n === "document.referrer" || n === "document.cookie") return true;
  if (n === "event.data" || n === "event.detail") return true;
  if (n === "import.meta.url") return true;
  return false;
}

function isSanitized(node) {
  const n = nameOf(node);
  if (!n) return false;
  if (SANITIZERS.has(n) || SANITIZERS.has(n.split(".").pop())) return true;
  if (node.type === "CallExpression") {
    const callee = nameOf(node.callee);
    if (SANITIZERS.has(callee) || SANITIZERS.has(callee.split(".").pop())) return true;
  }
  return false;
}

function makeTaint(node, source, parent = null) {
  return {
    source: { line: lineOf(node), code: codeOf(source, node), name: nameOf(node) },
    sink: null,
    steps: parent ? [{ line: lineOf(parent), code: codeOf(source, parent) }] : [],
  };
}

function mergeTaint(a, b) {
  if (!a) return b;
  if (!b) return a;
  return { ...a, steps: [...a.steps, ...b.steps].slice(0, 8) };
}

function taintOf(node, scope, source, seen = new Set()) {
  if (!node || seen.has(node)) return null;
  seen.add(node);
  if (isSanitized(node)) return null;
  if (isSource(node)) return makeTaint(node, source);
  switch (node.type) {
    case "Identifier":
      return scope.get(node.name) || null;
    case "MemberExpression":
    case "OptionalMemberExpression":
    case "ChainExpression":
      return taintOf(node.expression || node.object, scope, source, seen);
    case "CallExpression": {
      const callee = nameOf(node.callee);
      const last = callee.split(".").pop();
      if (STRING_METHODS.has(last) || last === "JSON.parse" || last === "parse") {
        return taintOf(node.arguments[0], scope, source, seen);
      }
      if (callee === "JSON.parse") return taintOf(node.arguments[0], scope, source, seen);
      let t = taintOf(node.callee, scope, source, seen);
      for (const arg of node.arguments) t = mergeTaint(t, taintOf(arg, scope, source, seen));
      return t;
    }
    case "TemplateLiteral": {
      let t = null;
      for (const expr of node.expressions) t = mergeTaint(t, taintOf(expr, scope, source, seen));
      return t;
    }
    case "BinaryExpression":
    case "LogicalExpression":
      return mergeTaint(
        taintOf(node.left, scope, source, seen),
        taintOf(node.right, scope, source, seen),
      );
    case "ConditionalExpression":
      return mergeTaint(
        taintOf(node.consequent, scope, source, seen),
        taintOf(node.alternate, scope, source, seen),
      );
    case "AssignmentExpression":
      return taintOf(node.right, scope, source, seen);
    case "AwaitExpression":
    case "TSAsExpression":
    case "TSNonNullExpression":
    case "TSTypeAssertion":
    case "ParenthesizedExpression":
      return taintOf(node.expression, scope, source, seen);
    case "SequenceExpression":
      return taintOf(node.expressions[node.expressions.length - 1], scope, source, seen);
    default:
      return null;
  }
}

function bindPattern(pattern, taint, scope) {
  if (!taint || !pattern) return;
  if (pattern.type === "Identifier") {
    scope.set(pattern.name, taint);
    return;
  }
  if (pattern.type === "ObjectPattern") {
    for (const prop of pattern.properties) {
      if (prop.type === "RestElement") bindPattern(prop.argument, taint, scope);
      else bindPattern(prop.value, taint, scope);
    }
    return;
  }
  if (pattern.type === "ArrayPattern") {
    for (const el of pattern.elements) bindPattern(el, taint, scope);
  }
}

const SINK_RULES = {
  eval: { rule: "code-injection", title: "Dynamic code execution with tainted input", sev: "high", cwe: "CWE-95", owasp: "A03:2021", tags: ["execution"], arg: 0 },
  Function: { rule: "code-injection", title: "Function constructor with tainted input", sev: "high", cwe: "CWE-95", owasp: "A03:2021", tags: ["execution"], arg: 0 },
  exec: { rule: "command-injection", title: "OS command injection", sev: "critical", cwe: "CWE-78", owasp: "A03:2021", tags: ["execution", "entry"], arg: 0 },
  execSync: { rule: "command-injection", title: "OS command injection", sev: "critical", cwe: "CWE-78", owasp: "A03:2021", tags: ["execution", "entry"], arg: 0 },
  spawn: { rule: "command-injection", title: "Process spawn with tainted argument", sev: "high", cwe: "CWE-78", owasp: "A03:2021", tags: ["execution"], arg: 0, medium: true },
  spawnSync: { rule: "command-injection", title: "Process spawn with tainted argument", sev: "high", cwe: "CWE-78", owasp: "A03:2021", tags: ["execution"], arg: 0, medium: true },
  execFile: { rule: "command-injection", title: "execFile with tainted argument", sev: "medium", cwe: "CWE-78", owasp: "A03:2021", tags: ["execution"], arg: 0, medium: true },
  readFile: { rule: "path-traversal", title: "File read with tainted path", sev: "high", cwe: "CWE-22", owasp: "A01:2021", tags: ["filesystem"], arg: 0 },
  readFileSync: { rule: "path-traversal", title: "File read with tainted path", sev: "high", cwe: "CWE-22", owasp: "A01:2021", tags: ["filesystem"], arg: 0 },
  writeFile: { rule: "path-traversal", title: "File write with tainted path", sev: "high", cwe: "CWE-22", owasp: "A01:2021", tags: ["filesystem"], arg: 0 },
  writeFileSync: { rule: "path-traversal", title: "File write with tainted path", sev: "high", cwe: "CWE-22", owasp: "A01:2021", tags: ["filesystem"], arg: 0 },
  createReadStream: { rule: "path-traversal", title: "Stream read with tainted path", sev: "high", cwe: "CWE-22", owasp: "A01:2021", tags: ["filesystem"], arg: 0 },
  createWriteStream: { rule: "path-traversal", title: "Stream write with tainted path", sev: "high", cwe: "CWE-22", owasp: "A01:2021", tags: ["filesystem"], arg: 0 },
  sendFile: { rule: "path-traversal", title: "sendFile with tainted path", sev: "high", cwe: "CWE-22", owasp: "A01:2021", tags: ["filesystem"], arg: 0 },
  download: { rule: "path-traversal", title: "download with tainted path", sev: "medium", cwe: "CWE-22", owasp: "A01:2021", tags: ["filesystem"], arg: 0 },
  fetch: { rule: "ssrf", title: "Server-side request with tainted URL", sev: "high", cwe: "CWE-918", owasp: "A10:2021", tags: ["network"], arg: 0 },
  "axios.get": { rule: "ssrf", title: "Server-side request with tainted URL", sev: "high", cwe: "CWE-918", owasp: "A10:2021", tags: ["network"], arg: 0 },
  "axios.post": { rule: "ssrf", title: "Server-side request with tainted URL", sev: "high", cwe: "CWE-918", owasp: "A10:2021", tags: ["network"], arg: 0 },
  "axios.request": { rule: "ssrf", title: "Server-side request with tainted URL", sev: "high", cwe: "CWE-918", owasp: "A10:2021", tags: ["network"], arg: 0 },
  got: { rule: "ssrf", title: "Server-side request with tainted URL", sev: "high", cwe: "CWE-918", owasp: "A10:2021", tags: ["network"], arg: 0 },
  redirect: { rule: "open-redirect", title: "Open redirect", sev: "medium", cwe: "CWE-601", owasp: "A01:2021", tags: ["network"], arg: 0 },
  query: { rule: "sql-injection", title: "SQL query built from tainted input", sev: "critical", cwe: "CWE-89", owasp: "A03:2021", tags: ["database", "entry"], arg: 0, db: true },
  execute: { rule: "sql-injection", title: "SQL execute with tainted input", sev: "critical", cwe: "CWE-89", owasp: "A03:2021", tags: ["database", "entry"], arg: 0, db: true },
  raw: { rule: "sql-injection", title: "Raw SQL with tainted input", sev: "high", cwe: "CWE-89", owasp: "A03:2021", tags: ["database"], arg: 0, db: true },
  find: { rule: "nosql-injection", title: "NoSQL query with tainted filter", sev: "high", cwe: "CWE-943", owasp: "A03:2021", tags: ["database"], arg: 0, medium: true },
  findOne: { rule: "nosql-injection", title: "NoSQL query with tainted filter", sev: "high", cwe: "CWE-943", owasp: "A03:2021", tags: ["database"], arg: 0, medium: true },
  merge: { rule: "prototype-pollution", title: "Prototype pollution via deep merge", sev: "high", cwe: "CWE-1321", owasp: "A08:2021", tags: ["logic"], arg: 1, medium: true },
  defaultsDeep: { rule: "prototype-pollution", title: "Prototype pollution via defaultsDeep", sev: "high", cwe: "CWE-1321", owasp: "A08:2021", tags: ["logic"], arg: 1, medium: true },
  deserialize: { rule: "insecure-deserialization", title: "Insecure deserialization", sev: "high", cwe: "CWE-502", owasp: "A08:2021", tags: ["execution"], arg: 0 },
  unserialize: { rule: "insecure-deserialization", title: "Insecure deserialization", sev: "high", cwe: "CWE-502", owasp: "A08:2021", tags: ["execution"], arg: 0 },
};

function remediationFor(rule) {
  return {
    "code-injection": "Avoid eval/new Function for untrusted data, or evaluate in an isolated VM with a strict allow-list.",
    "command-injection": "Use execFile/spawn with an argument array instead of a shell string. Validate against an allow-list and quote arguments.",
    "path-traversal": "Resolve the path against a fixed root, reject `..` after normalization, and verify the result stays inside the root.",
    "ssrf": "Parse the URL, allow-list schemes/hosts, resolve DNS, reject private and metadata addresses, and re-validate redirects.",
    "open-redirect": "Allow only relative paths or compare the target against a fixed host allow-list.",
    "sql-injection": "Use parameterized queries. Never interpolate request data into SQL text.",
    "nosql-injection": "Coerce scalar fields and reject object operators (`$ne`, `$gt`) unless explicitly allowed.",
    "prototype-pollution": "Merge into a null-prototype object, block `__proto__`/`constructor`/`prototype`, or use a hardened merge library.",
    "insecure-deserialization": "Prefer JSON with schema validation; for serializer formats, pin a safe library and verify integrity.",
  }[rule] || "Validate and canonicalize untrusted input before the sink.";
}

function cvssFor(sev, network = true) {
  const av = network ? "N" : "L";
  if (sev === "critical") return `CVSS:3.1/AV:${av}/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`;
  if (sev === "high") return `CVSS:3.1/AV:${av}/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L`;
  if (sev === "medium") return `CVSS:3.1/AV:${av}/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`;
  return `CVSS:3.1/AV:${av}/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`;
}

export default {
  id: "sast-js",
  name: "JS/TS Taint Analyst",
  description: "AST data-flow analysis across sources, propagators and 30+ dangerous sinks, plus framework misconfiguration rules.",
  category: "sast",
  targetTypes: ["code", "mixed"],
  cost: "medium",
  async run(ctx) {
    const { files, add, emit, root } = ctx;
    let parsed = 0;
    let failed = 0;
    for (const file of files) {
      if (!JS_EXT.has(file.lang)) continue;
      const source = await fsp.readFile(file.abs, "utf8");
      let ast;
      try {
        ast = parse(source, {
          sourceType: "unambiguous",
          errorRecovery: true,
          allowReturnOutsideFunction: true,
          plugins: [
            "jsx", "typescript", "decorators-legacy", "classProperties", "classPrivateProperties",
            "classPrivateMethods", "dynamicImport", "importAttributes", "topLevelAwait",
            "optionalChaining", "nullishCoalescingOperator", "objectRestSpread",
          ],
        });
        parsed += 1;
      } catch (err) {
        failed += 1;
        emit("debug", `Parse failed ${file.rel}: ${err.message}`);
        continue;
      }
      const scopes = [new Map()];
      const seen = new Set();
      const report = (ruleId, node, data) => {
        const key = `${ruleId}:${lineOf(node)}`;
        if (seen.has(key)) return;
        seen.add(key);
        const line = lineOf(node);
        add({
          engine: "sast-js",
          ruleId,
          file: file.rel,
          line,
          column: node.loc?.start.column + 1,
          snippet: snippetAt(source, line, 3),
          ...data,
        });
      };
      const visit = (node, parent) => {
        if (!node || typeof node !== "object") return;
        if (Array.isArray(node)) {
          for (const child of node) visit(child, parent);
          return;
        }
        if (!node.type) return;
        const scope = scopes[scopes.length - 1];
        const enterFunction = () => {
          const next = new Map(scope);
          if (isRouteHandler(node, parent)) {
            for (const param of node.params) {
              if (param.type === "Identifier") {
                next.set(param.name, {
                  source: { line: lineOf(param), code: `parameter ${param.name}`, name: param.name },
                  sink: null,
                  steps: [],
                });
              }
            }
          }
          scopes.push(next);
        };
        const isFn =
          node.type === "FunctionDeclaration" ||
          node.type === "FunctionExpression" ||
          node.type === "ArrowFunctionExpression" ||
          node.type === "ObjectMethod" ||
          node.type === "ClassMethod";
        if (isFn) enterFunction();
        try {
          if (node.type === "VariableDeclarator" && node.id && node.init) {
            const taint = taintOf(node.init, scope, source);
            if (taint) bindPattern(node.id, taint, scope);
          }
          if (node.type === "AssignmentExpression") {
            const taint = taintOf(node.right, scope, source);
            if (taint && node.left.type === "Identifier") scope.set(node.left.name, taint);
            const target = nameOf(node.left);
            if (taint && /\.(innerHTML|outerHTML)$/.test(target)) {
              report("dom-xss", node, {
                title: "DOM XSS via innerHTML",
                description: `Tainted data reaches \`${target}\` without HTML sanitization.`,
                severity: "high",
                confidence: "high",
                cwe: "CWE-79",
                owasp: "A03:2021",
                cvssVector: cvssFor("high"),
                taint: { ...taint, sink: { line: lineOf(node), code: codeOf(source, node) } },
                evidence: { sink: codeOf(source, node) },
                remediation: "Use textContent for text, or sanitize HTML with DOMPurify before assignment.",
                references: ["https://cwe.mitre.org/data/definitions/79.html"],
                tags: ["xss", "client"],
              });
            }
            if (taint && /^(window\.)?location(\.href)?$/.test(target)) {
              report("open-redirect", node, {
                title: "Client-side redirect to tainted URL",
                description: "Untrusted input is assigned to the location object.",
                severity: "medium",
                confidence: "medium",
                cwe: "CWE-601",
                owasp: "A01:2021",
                cvssVector: cvssFor("medium"),
                taint: { ...taint, sink: { line: lineOf(node), code: codeOf(source, node) } },
                remediation: remediationFor("open-redirect"),
                references: ["https://cwe.mitre.org/data/definitions/601.html"],
                tags: ["redirect", "client"],
              });
            }
          }
          if (node.type === "CallExpression" || node.type === "NewExpression") {
            const full = nameOf(node.callee);
            const last = full.split(".").pop();
            const rule = SINK_RULES[full] || SINK_RULES[last];
            if (rule) {
              const arg = node.arguments[rule.arg ?? 0];
              let taint = arg ? taintOf(arg, scope, source) : null;
              if (taint && rule.db) {
                const parameterized =
                  node.arguments.length > 1 &&
                  (arg.type === "StringLiteral" || arg.type === "TemplateLiteral") &&
                  !(arg.type === "TemplateLiteral" && arg.expressions.length);
                if (parameterized) taint = null;
              }
              if (taint) {
                const network = rule.tags.includes("network");
                report(rule.rule, node, {
                  title: rule.title,
                  description:
                    `Tainted data from \`${taint.source.code}\` flows into \`${full}()\` at line ${lineOf(node)}. ` +
                    `The value crosses a trust boundary without an effective canonicalizer.`,
                  severity: rule.sev,
                  confidence: rule.medium ? "medium" : "high",
                  cwe: rule.cwe,
                  owasp: rule.owasp,
                  cvssVector: cvssFor(rule.sev, network),
                  taint: { ...taint, sink: { line: lineOf(node), code: codeOf(source, node) } },
                  evidence: { sink: codeOf(source, node), source: taint.source.code },
                  remediation: remediationFor(rule.rule),
                  references: [`https://cwe.mitre.org/data/definitions/${String(rule.cwe).replace("CWE-", "")}.html`],
                  tags: rule.tags,
                });
              }
            }
            if (last === "verify" && /jwt/.test(full) && !node.arguments[2]) {
              report("jwt-no-algorithms", node, {
                title: "JWT verification without pinned algorithms",
                description: "jwt.verify is called without an explicit `algorithms` option. Depending on the library, this can enable algorithm confusion.",
                severity: "medium",
                confidence: "medium",
                cwe: "CWE-347",
                owasp: "A02:2021",
                cvssVector: cvssFor("medium"),
                evidence: { call: codeOf(source, node) },
                remediation: "Pass `{ algorithms: ['RS256'] }` (or the exact expected algorithm) and validate issuer/audience.",
                references: ["https://cwe.mitre.org/data/definitions/347.html"],
                tags: ["auth", "jwt"],
              });
            }
            if (last === "createHash") {
              const algo = node.arguments[0]?.value;
              if (algo === "md5" || algo === "sha1") {
                report("weak-hash", node, {
                  title: `Weak hash algorithm (${algo})`,
                  description: `\`${algo}\` is collision-prone and unsuitable for signatures, integrity or password storage.`,
                  severity: "low",
                  confidence: "high",
                  cwe: "CWE-328",
                  owasp: "A02:2021",
                  cvssVector: cvssFor("low"),
                  evidence: { call: codeOf(source, node) },
                  remediation: "Use SHA-256+ for integrity, and Argon2id/scrypt/bcrypt for passwords.",
                  references: ["https://cwe.mitre.org/data/definitions/328.html"],
                  tags: ["crypto"],
                });
              }
            }
            if (last === "createCipheriv" && node.arguments[1]?.type === "StringLiteral") {
              const iv = node.arguments[1].value;
              if (iv.length < 12) {
                report("short-iv", node, {
                  title: "Short or static IV",
                  description: "A literal IV is reused for every encryption. GCM needs 12 random bytes per message.",
                  severity: "medium",
                  confidence: "medium",
                  cwe: "CWE-329",
                  owasp: "A02:2021",
                  cvssVector: cvssFor("medium"),
                  evidence: { iv },
                  remediation: "Generate a fresh `crypto.randomBytes(12)` IV for every encryption and store it with the ciphertext.",
                  references: ["https://cwe.mitre.org/data/definitions/329.html"],
                  tags: ["crypto"],
                });
              }
            }
            if (last === "hash" && /bcrypt/.test(full) && node.arguments[1]?.type === "NumericLiteral") {
              if (node.arguments[1].value < 10) {
                report("weak-bcrypt-cost", node, {
                  title: "Low bcrypt cost factor",
                  description: `Cost ${node.arguments[1].value} is below the recommended minimum of 10.`,
                  severity: "low",
                  confidence: "high",
                  cwe: "CWE-916",
                  owasp: "A02:2021",
                  cvssVector: cvssFor("low"),
                  evidence: { call: codeOf(source, node) },
                  remediation: "Use a cost of 12 or higher and rehash on login when raising it.",
                  references: ["https://cwe.mitre.org/data/definitions/916.html"],
                  tags: ["crypto", "auth"],
                });
              }
            }
            if (last === "random" && /Math/.test(full)) {
              const parentName = parent?.type === "VariableDeclarator" ? nameOf(parent.id) : nameOf(parent);
              const lineText = source.split(/\r?\n/)[lineOf(node) - 1] || "";
              if (/token|secret|nonce|session/i.test(parentName) || /token|secret|nonce/i.test(codeOf(source, parent || node)) || /token|secret|nonce/i.test(lineText)) {
                report("insecure-random", node, {
                  title: "Math.random for security token",
                  description: "Math.random is not cryptographically secure and can be predicted.",
                  severity: "medium",
                  confidence: "medium",
                  cwe: "CWE-338",
                  owasp: "A02:2021",
                  cvssVector: cvssFor("medium"),
                  evidence: { call: codeOf(source, node) },
                  remediation: "Use `crypto.randomBytes()` / `crypto.randomUUID()`.",
                  references: ["https://cwe.mitre.org/data/definitions/338.html"],
                  tags: ["crypto"],
                });
              }
            }
            if (last === "cookie" && /res|reply|response/.test(full)) {
              const opts = node.arguments[2];
              const text = opts ? codeOf(source, opts) : "";
              if (!/httpOnly/i.test(text) || !/secure/i.test(text) || !/sameSite/i.test(text)) {
                report("insecure-cookie", node, {
                  title: "Session cookie missing security attributes",
                  description: "A cookie is set without httpOnly, secure and sameSite. Missing flags expose it to script access, plaintext transport or CSRF.",
                  severity: "medium",
                  confidence: "medium",
                  cwe: "CWE-614",
                  owasp: "A05:2021",
                  cvssVector: cvssFor("medium"),
                  evidence: { call: codeOf(source, node) },
                  remediation: "Set `{ httpOnly: true, secure: true, sameSite: 'lax' }` and a scoped path.",
                  references: ["https://cwe.mitre.org/data/definitions/614.html"],
                  tags: ["session"],
                });
              }
            }
            if (last === "postMessage" && node.arguments[1]?.value === "*") {
              report("postmessage-wildcard", node, {
                title: "postMessage to wildcard origin",
                description: "Messages are broadcast to any origin. A malicious embedding page can read sensitive payloads.",
                severity: "low",
                confidence: "high",
                cwe: "CWE-345",
                owasp: "A08:2021",
                cvssVector: cvssFor("low"),
                evidence: { call: codeOf(source, node) },
                remediation: "Pass the exact target origin instead of `*`.",
                references: ["https://cwe.mitre.org/data/definitions/345.html"],
                tags: ["client"],
              });
            }
            if (last === "assign" && /Object/.test(full) && node.arguments[1]) {
              const taint = taintOf(node.arguments[1], scope, source);
              if (taint && node.arguments[0]?.type === "ObjectExpression" && !node.arguments[0].properties.length) {
                report("prototype-pollution", node, {
                  title: "Prototype pollution via Object.assign",
                  description: "A tainted object is merged into a plain object. A `__proto__` key can alter the prototype chain.",
                  severity: "medium",
                  confidence: "medium",
                  cwe: "CWE-1321",
                  owasp: "A08:2021",
                  cvssVector: cvssFor("medium"),
                  taint: { ...taint, sink: { line: lineOf(node), code: codeOf(source, node) } },
                  evidence: { call: codeOf(source, node) },
                  remediation: "Use `Object.assign(Object.create(null), input)` or a hardened deep-merge.",
                  references: ["https://cwe.mitre.org/data/definitions/1321.html"],
                  tags: ["logic"],
                });
              }
            }
            if (last === "json" && /express/.test(full) && !node.arguments[0]) {
              report("body-limit", node, {
                title: "JSON body parser without size limit",
                description: "express.json() defaults to 100kb, but an explicit limit documents and enforces the intended budget.",
                severity: "info",
                confidence: "medium",
                cwe: "CWE-400",
                owasp: "A05:2021",
                cvssVector: cvssFor("low"),
                evidence: { call: codeOf(source, node) },
                remediation: "Set an explicit `limit` and handle 413 responses.",
                references: ["https://cwe.mitre.org/data/definitions/400.html"],
                tags: ["config"],
              });
            }
          }
          if (node.type === "NewExpression" && nameOf(node.callee) === "Function") {
            const taint = node.arguments[0] ? taintOf(node.arguments[0], scope, source) : null;
            if (taint) {
              report("code-injection", node, {
                title: "Function constructor with tainted input",
                description: "Tainted code is compiled with the Function constructor.",
                severity: "high",
                confidence: "high",
                cwe: "CWE-95",
                owasp: "A03:2021",
                cvssVector: cvssFor("high"),
                taint: { ...taint, sink: { line: lineOf(node), code: codeOf(source, node) } },
                evidence: { call: codeOf(source, node) },
                remediation: remediationFor("code-injection"),
                references: ["https://cwe.mitre.org/data/definitions/95.html"],
                tags: ["execution"],
              });
            }
          }
          if (node.type === "JSXAttribute" && node.name?.name === "dangerouslySetInnerHTML") {
            report("dangerously-set-innerhtml", node, {
              title: "dangerouslySetInnerHTML",
              description: "Raw HTML is injected into the React tree. Verify the source is sanitized.",
              severity: "medium",
              confidence: "medium",
              cwe: "CWE-79",
              owasp: "A03:2021",
              cvssVector: cvssFor("medium"),
              evidence: { code: codeOf(source, node) },
              remediation: "Sanitize with DOMPurify before passing to dangerouslySetInnerHTML.",
              references: ["https://cwe.mitre.org/data/definitions/79.html"],
              tags: ["xss", "client"],
            });
          }
          if (node.type === "JSXAttribute" && node.name?.name === "target" && node.value?.value === "_blank") {
            const attrs = parent?.attributes || [];
            const rel = attrs.find((a) => a.name?.name === "rel");
            if (!rel || !/noopener|noreferrer/.test(rel.value?.value || "")) {
              report("reverse-tabnabbing", node, {
                title: "target=_blank without rel=noopener",
                description: "The opened page can access window.opener and navigate the original tab.",
                severity: "low",
                confidence: "high",
                cwe: "CWE-1022",
                owasp: "A01:2021",
                cvssVector: cvssFor("low"),
                evidence: { code: codeOf(source, node) },
                remediation: "Add `rel=\"noopener noreferrer\"`.",
                references: ["https://cwe.mitre.org/data/definitions/1022.html"],
                tags: ["client"],
              });
            }
          }
          if (node.type === "ObjectProperty" && node.key?.name === "rejectUnauthorized" && node.value?.value === false) {
            report("tls-verify-disabled", node, {
              title: "TLS certificate verification disabled",
              description: "rejectUnauthorized:false accepts expired, self-signed and attacker certificates.",
              severity: "medium",
              confidence: "high",
              cwe: "CWE-295",
              owasp: "A02:2021",
              cvssVector: cvssFor("medium"),
              evidence: { code: codeOf(source, node) },
              remediation: "Pin the expected CA and enable verification in production.",
              references: ["https://cwe.mitre.org/data/definitions/295.html"],
              tags: ["tls"],
            });
          }
          if (node.type === "RegExpLiteral") {
            const pattern = node.pattern || "";
            if (/\([^)]*[+*][^)]*\)[+*{]/.test(pattern) && pattern.length > 12) {
              report("redos", node, {
                title: "Potential catastrophic backtracking (ReDoS)",
                description: "A nested quantifier can cause exponential backtracking on crafted input.",
                severity: "low",
                confidence: "low",
                cwe: "CWE-1333",
                owasp: "A05:2021",
                cvssVector: cvssFor("low"),
                evidence: { pattern },
                remediation: "Bound the input length, simplify the expression, or use RE2.",
                references: ["https://cwe.mitre.org/data/definitions/1333.html"],
                tags: ["dos"],
              });
            }
          }
          for (const key of Object.keys(node)) {
            if (["loc", "start", "end", "extra", "leadingComments", "trailingComments", "innerComments", "type"].includes(key)) continue;
            const value = node[key];
            if (value && typeof value === "object") visit(value, node);
          }
        } finally {
          if (isFn) scopes.pop();
        }
      };
      visit(ast, null);
      const text = source;
      if (/express\(\)/.test(text) && !/helmet/.test(text)) {
        add({
          engine: "sast-js",
          ruleId: "missing-helmet",
          file: file.rel,
          line: 1,
          title: "Express app without Helmet",
          description: "No Helmet middleware was found. Security headers (CSP, HSTS, nosniff, frameguard) are likely missing.",
          severity: "low",
          confidence: "medium",
          cwe: "CWE-693",
          owasp: "A05:2021",
          cvssVector: cvssFor("low"),
          evidence: { file: file.rel },
          remediation: "Add `app.use(helmet())` and configure a CSP appropriate for the app.",
          references: ["https://cwe.mitre.org/data/definitions/693.html"],
          tags: ["config", "headers"],
        });
      }
      if (/(?:app|router)\.(post|put|patch|delete)\(/.test(text) && !/csrf/i.test(text)) {
        add({
          engine: "sast-js",
          ruleId: "missing-csrf",
          file: file.rel,
          line: 1,
          title: "State-changing routes without visible CSRF protection",
          description: "Mutating HTTP routes were found, but no CSRF middleware or token check is referenced in this file.",
          severity: "medium",
          confidence: "low",
          cwe: "CWE-352",
          owasp: "A01:2021",
          cvssVector: cvssFor("medium"),
          evidence: { file: file.rel },
          remediation: "Use SameSite cookies plus a per-session CSRF token for state-changing requests.",
          references: ["https://cwe.mitre.org/data/definitions/352.html"],
          tags: ["auth", "csrf"],
        });
      }
    }
    emit("info", `Parsed ${parsed} JS/TS files (${failed} parse failures)`);
  },
};
