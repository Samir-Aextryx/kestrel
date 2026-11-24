import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { parse } from "@babel/parser";
import { db, now } from "../db.js";
import { Harness, makeCoverageDir, cleanup } from "../lib/fuzz.js";
import { snippetAt } from "../lib/util.js";

const SINK_RE = /(?:eval|Function|execSync|execFile|spawnSync|spawn|exec|readFileSync|readFile|writeFileSync|writeFile|createReadStream|createWriteStream|sendFile|download|fetch|axios|got|redirect|query|execute|raw|merge|assign|deserialize|unserialize|pickle|yaml\.load|render_template_string|open|subprocess|os\.system|urllib|requests|innerHTML|dangerouslySetInnerHTML)/g;

const FAMILIES = [
  {
    id: "path-traversal",
    roles: ["path", "file", "filename", "dir", "folder", "name"],
    benign: "package.json",
    sanitized: "package.json",
    malicious: ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/etc/passwd"],
    oracle: "fs-escape",
    cwe: "CWE-22",
    title: "Confirmed path traversal",
    severity: "high",
    remediation: "Resolve against a fixed root, normalize, and verify the result stays inside the root.",
  },
  {
    id: "command-injection",
    roles: ["cmd", "command", "exec", "shell", "arg"],
    benign: "echo kestrel",
    sanitized: "echo kestrel",
    malicious: ["echo kestrel; id", "echo kestrel && id", "echo `id`", "echo $(id)"],
    oracle: "exec-marker",
    cwe: "CWE-78",
    title: "Confirmed command injection",
    severity: "critical",
    remediation: "Use execFile/spawn with an argument array, or quote with shlex.quote and allow-list the binary.",
  },
  {
    id: "ssrf",
    roles: ["url", "uri", "endpoint", "host", "target", "link"],
    benign: "https://example.com",
    sanitized: "https://example.com",
    malicious: ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8787/api/health", "file:///etc/passwd"],
    oracle: "network-private",
    cwe: "CWE-918",
    title: "Confirmed SSRF to private or metadata address",
    severity: "high",
    remediation: "Allow-list schemes and hosts, reject private/link-local addresses, and re-check redirects.",
  },
  {
    id: "sql-injection",
    roles: ["sql", "query", "where", "filter"],
    benign: "alice",
    sanitized: "alice",
    malicious: ["' OR 1=1--", "1; SELECT 1", "alice' UNION SELECT NULL--"],
    oracle: "sql-error-diff",
    cwe: "CWE-89",
    title: "SQL injection candidate reached the database layer",
    severity: "high",
    remediation: "Use bound parameters for every value.",
  },
  {
    id: "prototype-pollution",
    roles: ["body", "data", "obj", "options", "input", "json", "config", "base", "patch", "target", "source"],
    benign: { a: 1 },
    sanitized: { a: 1 },
    malicious: [JSON.parse('{"__proto__":{"polluted":"kestrel"}}'), JSON.parse('{"constructor":{"prototype":{"polluted":"kestrel"}}}')],
    oracle: "prototype",
    cwe: "CWE-1321",
    title: "Confirmed prototype pollution",
    severity: "high",
    remediation: "Merge into a null-prototype object and block __proto__/constructor/prototype keys.",
  },
  {
    id: "xss",
    roles: ["html", "content", "template", "name", "title", "message"],
    benign: "hello",
    sanitized: "hello",
    malicious: ["<img src=x onerror=alert(1)>", "<script>alert(1)</script>"],
    oracle: "html-unescaped",
    cwe: "CWE-79",
    title: "Unescaped HTML in function output",
    severity: "medium",
    remediation: "Escape by context or sanitize with DOMPurify/bleach before rendering.",
  },
  {
    id: "redos",
    roles: ["text", "input", "value", "str", "string", "email"],
    benign: "a",
    sanitized: "a",
    malicious: [`${"a".repeat(4000)}!`, `${"a".repeat(8000)}!`],
    oracle: "timing",
    cwe: "CWE-1333",
    title: "Super-linear parsing time (ReDoS candidate)",
    severity: "medium",
    remediation: "Bound input length, simplify nested quantifiers, or use RE2.",
  },
  {
    id: "code-injection",
    roles: ["expr", "code", "script", "source", "value"],
    benign: "1",
    sanitized: "1",
    malicious: ["__import__('os').getcwd()", "process.cwd()", "1+1"],
    oracle: "eval-result",
    cwe: "CWE-95",
    title: "Dynamic code evaluation confirmed",
    severity: "high",
    remediation: "Use ast.literal_eval for data, or a restricted namespace/VM for expressions.",
  },
  {
    id: "insecure-deserialization",
    roles: ["data", "raw", "blob", "payload", "pickle", "value"],
    benign: "(dp0\n.",
    sanitized: "(dp0\n.",
    malicious: ["(dp0\nS'kestrel'\np1\nI7\ns.", "(dp0\nS'kestrel'\np1\nI7\ns."],
    oracle: "deserialize",
    cwe: "CWE-502",
    title: "Insecure deserialization confirmed",
    severity: "high",
    remediation: "Prefer JSON or signed pickles; never unpickle untrusted bytes without integrity.",
  },
  {
    id: "open-redirect",
    roles: ["next", "url", "redirect", "return", "target"],
    benign: "/home",
    sanitized: "/home",
    malicious: ["https://evil.example/login", "//evil.example/login"],
    oracle: "redirect",
    cwe: "CWE-601",
    title: "Open redirect confirmed",
    severity: "medium",
    remediation: "Allow only relative paths or compare the host against an allow-list.",
  },
  {
    id: "xxe",
    roles: ["xml", "data", "raw", "body"],
    benign: "<root><a>1</a></root>",
    sanitized: "<root><a>1</a></root>",
    malicious: ['<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'],
    oracle: "xxe",
    cwe: "CWE-611",
    title: "XML external entity expansion confirmed",
    severity: "high",
    remediation: "Disable external entities and network access in the parser.",
  },
  {
    id: "csv-injection",
    roles: ["csv", "value", "name", "field"],
    benign: "hello",
    sanitized: "hello",
    malicious: ["=cmd|' /C calc'!A0", "+1+1", "@SUM(A1:A2)"],
    oracle: "csv-formula",
    cwe: "CWE-1236",
    title: "CSV formula injection",
    severity: "low",
    remediation: "Prefix cells starting with = + - @ with a single quote.",
  },
  {
    id: "crlf-injection",
    roles: ["header", "name", "value", "filename"],
    benign: "hello",
    sanitized: "hello",
    malicious: ["hello\r\nX-Injected: 1", "hello%0d%0aX-Injected:1"],
    oracle: "crlf",
    cwe: "CWE-113",
    title: "CRLF/header injection",
    severity: "medium",
    remediation: "Strip CR/LF from header values or encode them.",
  },
  {
    id: "mass-assignment",
    roles: ["body", "data", "input", "update", "patch"],
    benign: { name: "a" },
    sanitized: { name: "a" },
    malicious: [{ name: "a", isAdmin: true }, { name: "a", role: "admin" }],
    oracle: "mass-assign",
    cwe: "CWE-915",
    title: "Mass assignment of privileged field",
    severity: "high",
    remediation: "Allow-list writable fields or use a DTO/schema.",
  },
  {
    id: "integer-boundary",
    roles: ["id", "count", "limit", "size", "n", "num", "index", "port"],
    benign: "1",
    sanitized: "1",
    malicious: ["-1", "2147483648", "1e309", "0x10"],
    oracle: "numeric-anomaly",
    cwe: "CWE-190",
    title: "Numeric boundary anomaly",
    severity: "low",
    remediation: "Validate range, coerce explicitly, and reject non-finite values.",
  },
  {
    id: "race-condition",
    roles: ["id", "key", "name"],
    benign: "kestrel-race",
    sanitized: "kestrel-race",
    malicious: ["kestrel-race"],
    oracle: "race",
    cwe: "CWE-362",
    title: "Repeated calls produced inconsistent results",
    severity: "medium",
    remediation: "Guard shared state with a lock, atomic operation, or compare-and-swap; verify under real concurrency.",
  },
  {
    id: "ssti",
    roles: ["template", "tpl", "view", "page", "markup"],
    benign: "hello",
    sanitized: "hello",
    malicious: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
    oracle: "template-eval",
    cwe: "CWE-1336",
    title: "Server-side template injection confirmed",
    severity: "critical",
    remediation: "Never build templates from user input; render a fixed template and pass values as data.",
  },
  {
    id: "nosql-injection",
    roles: ["filter", "criteria", "where", "search", "query"],
    benign: { user: "alice" },
    sanitized: { user: "alice" },
    malicious: [{ $ne: null }, { user: { $ne: null } }, { $gt: "" }],
    oracle: "nosql-match",
    cwe: "CWE-943",
    title: "NoSQL operator injection candidate",
    severity: "high",
    remediation: "Coerce and validate query fields; reject keys starting with $ and never pass request bodies as filters.",
  },
];

// Sink kinds inferred from the function body (parameter -> dangerous call)
// mapped to the attack families worth trying for that parameter. This is what
// lets the lab test a parameter called `x` that flows into fs.readFileSync.
const SINK_FAMILIES = {
  fs: ["path-traversal"],
  exec: ["command-injection"],
  network: ["ssrf"],
  eval: ["code-injection"],
  sql: ["sql-injection"],
  merge: ["prototype-pollution", "mass-assignment"],
  redirect: ["open-redirect"],
  deserialize: ["insecure-deserialization"],
  template: ["ssti", "xss"],
  html: ["xss"],
  regex: ["redos"],
  header: ["crlf-injection"],
  xml: ["xxe"],
};

const SINK_BY_NAME = new Map(
  Object.entries({
    readFile: "fs",
    readFileSync: "fs",
    writeFile: "fs",
    writeFileSync: "fs",
    createReadStream: "fs",
    createWriteStream: "fs",
    sendFile: "fs",
    download: "fs",
    open: "fs",
    openSync: "fs",
    unlink: "fs",
    unlinkSync: "fs",
    rename: "fs",
    renameSync: "fs",
    exec: "exec",
    execSync: "exec",
    execFile: "exec",
    execFileSync: "exec",
    spawn: "exec",
    spawnSync: "exec",
    fork: "exec",
    fetch: "network",
    axios: "network",
    got: "network",
    request: "network",
    urlopen: "network",
    eval: "eval",
    runInNewContext: "eval",
    runInThisContext: "eval",
    runInContext: "eval",
    query: "sql",
    execute: "sql",
    raw: "sql",
    merge: "merge",
    assign: "merge",
    extend: "merge",
    defaults: "merge",
    setWith: "merge",
    redirect: "redirect",
    render: "template",
    renderFile: "template",
    compile: "template",
    deserialize: "deserialize",
    unserialize: "deserialize",
    setHeader: "header",
    writeHead: "header",
    appendHeader: "header",
  }),
);

function memberPath(node) {
  const parts = [];
  let current = node;
  while (current?.type === "MemberExpression" && !current.computed) {
    parts.unshift(current.property.name);
    current = current.object;
  }
  if (current?.type === "Identifier") parts.unshift(current.name);
  return parts;
}

function calleeSinkKind(node) {
  if (!node) return null;
  if (node.type === "NewExpression") {
    const name = node.callee?.name;
    if (name === "RegExp") return "regex";
    if (name === "Function") return "eval";
    return null;
  }
  if (node.type === "Identifier") return SINK_BY_NAME.get(node.name) || null;
  if (node.type !== "MemberExpression") return null;
  const parts = memberPath(node);
  const prop = parts[parts.length - 1];
  const object = parts.length > 1 ? parts[parts.length - 2] : "";
  if (!prop) return null;
  if (["axios", "got", "request", "superagent", "http", "https", "net"].includes(object)) {
    if (["get", "post", "put", "patch", "delete", "head", "request"].includes(prop)) return "network";
  }
  if (["fs", "fsPromises"].includes(object)) return "fs";
  if (["child_process", "cp"].includes(object)) return "exec";
  if (["db", "knex", "pool", "client", "connection", "sequelize", "conn", "prisma"].includes(object)) {
    if (["query", "execute", "raw", "$queryRaw", "$executeRaw"].includes(prop)) return "sql";
  }
  if (object === "Object" && prop === "assign") return "merge";
  if (object === "_" && ["merge", "assign", "extend", "defaults", "set", "setWith"].includes(prop)) return "merge";
  if (prop === "redirect") return "redirect";
  if (["render", "renderFile", "renderString", "compile"].includes(prop)) return "template";
  if (object === "yaml" && ["load", "loadAll"].includes(prop)) return "deserialize";
  if (object === "pickle" && ["load", "loads"].includes(prop)) return "deserialize";
  if (["setHeader", "writeHead", "appendHeader"].includes(prop)) return "header";
  return null;
}

function collectIdentifiers(node, out = new Set()) {
  if (!node || typeof node !== "object") return out;
  if (Array.isArray(node)) {
    for (const child of node) collectIdentifiers(child, out);
    return out;
  }
  if (node.type === "Identifier") {
    out.add(node.name);
    return out;
  }
  if (node.type === "MemberExpression") {
    collectIdentifiers(node.object, out);
    if (node.computed) collectIdentifiers(node.property, out);
    return out;
  }
  for (const key of Object.keys(node)) {
    if (["loc", "start", "end", "type", "extra", "key", "property", "label"].includes(key)) continue;
    const value = node[key];
    if (value && typeof value === "object") collectIdentifiers(value, out);
  }
  return out;
}

// Lightweight intraprocedural taint: tracks which locals are derived from each
// parameter, then marks a sink kind when such a local reaches a dangerous call.
function collectJsSinks(fnNode, params) {
  const taint = new Map(params.map((param) => [param, new Set([param])]));
  const sinks = new Map(params.map((param) => [param, new Set()]));
  const mark = (kind, argNode) => {
    const used = collectIdentifiers(argNode);
    for (const [param, names] of taint) {
      for (const name of used) {
        if (names.has(name)) {
          sinks.get(param).add(kind);
          break;
        }
      }
    }
  };
  const visit = (node) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) return node.forEach(visit);
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier" && node.init) {
      const used = collectIdentifiers(node.init);
      for (const names of taint.values()) {
        for (const name of used) {
          if (names.has(name)) {
            names.add(node.id.name);
            break;
          }
        }
      }
    }
    if (node.type === "AssignmentExpression") {
      if (node.left?.type === "Identifier") {
        const used = collectIdentifiers(node.right);
        for (const names of taint.values()) {
          for (const name of used) {
            if (names.has(name)) {
              names.add(node.left.name);
              break;
            }
          }
        }
      } else if (node.left?.type === "MemberExpression") {
        const prop = node.left.property?.name;
        if (prop === "innerHTML" || prop === "outerHTML") mark("html", node.right);
      }
    }
    if (node.type === "CallExpression" || node.type === "NewExpression") {
      const kind = calleeSinkKind(node.type === "NewExpression" ? node : node.callee);
      if (kind) for (const arg of node.arguments || []) mark(kind, arg);
    }
    for (const key of Object.keys(node)) {
      if (["loc", "start", "end", "type", "extra"].includes(key)) continue;
      const value = node[key];
      if (value && typeof value === "object") visit(value);
    }
  };
  visit(fnNode.body || fnNode);
  const out = new Map();
  for (const [param, kinds] of sinks) if (kinds.size) out.set(param, [...kinds]);
  return out;
}

export function familiesForParam(fn, index) {
  const param = fn.params[index];
  if (!param) return [];
  const ids = new Set();
  for (const family of FAMILIES) {
    if (family.roles.some((role) => hintMatch(param, [role]))) ids.add(family.id);
  }
  const inferred =
    fn.sinks instanceof Map ? fn.sinks.get(param) ?? fn.sinks.get(index) : fn.sinks?.[index];
  for (const kind of inferred || []) {
    for (const id of SINK_FAMILIES[kind] || []) ids.add(id);
  }
  return FAMILIES.filter((family) => ids.has(family.id));
}

function isFunctionNode(node) {
  return Boolean(
    node &&
      ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ObjectMethod", "ClassMethod"].includes(
        node.type,
      ),
  );
}

export function jsFunctions(source, rel) {
  let ast;
  try {
    ast = parse(source, { sourceType: "unambiguous", errorRecovery: true, plugins: ["jsx", "typescript", "topLevelAwait"] });
  } catch {
    return [];
  }
  const out = [];
  const declared = new Map();
  const add = (name, fn, node) => {
    if (!name || !isFunctionNode(fn) || out.some((entry) => entry.name === name)) return;
    const params = (fn.params || []).map((p) => p.name || p.left?.name).filter(Boolean);
    if (!params.length || params.length > 3) return;
    out.push({
      name,
      params,
      line: node.loc?.start.line || 1,
      endLine: node.loc?.end.line || node.loc?.start.line || 1,
      rel,
      runtime: "node",
      sinks: collectJsSinks(fn, params),
    });
  };
  const visit = (node) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) return node.forEach(visit);
    if (node.type === "FunctionDeclaration" && node.id?.name) declared.set(node.id.name, { fn: node, node });
    if (node.type === "VariableDeclarator" && node.id?.name && isFunctionNode(node.init)) {
      declared.set(node.id.name, { fn: node.init, node });
    }
    if (node.type === "ExportNamedDeclaration") {
      if (node.declaration?.type === "FunctionDeclaration") add(node.declaration.id?.name, node.declaration, node);
      if (node.declaration?.type === "VariableDeclaration") {
        for (const d of node.declaration.declarations) {
          if (d.id?.name && isFunctionNode(d.init)) add(d.id.name, d.init, d);
        }
      }
    }
    if (node.type === "ExportDefaultDeclaration" && isFunctionNode(node.declaration)) {
      add("default", node.declaration, node);
    }
    for (const key of Object.keys(node)) {
      if (["loc", "start", "end", "type", "extra"].includes(key)) continue;
      if (node[key] && typeof node[key] === "object") visit(node[key]);
    }
  };
  visit(ast);
  // CommonJS: module.exports = { name, alias: fn } / exports.name = fn
  const visitCjs = (node) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) return node.forEach(visitCjs);
    if (node.type === "AssignmentExpression" && node.left?.type === "MemberExpression") {
      const parts = memberPath(node.left);
      const isCjs = parts[0] === "exports" || (parts[0] === "module" && parts[1] === "exports");
      if (isCjs) {
        const exportName = parts[parts.length - 1];
        const right = node.right;
        if (right?.type === "ObjectExpression") {
          for (const prop of right.properties) {
            const key = prop.key?.name || prop.key?.value;
            if (!key) continue;
            const value = isFunctionNode(prop) ? prop : prop.value;
            if (isFunctionNode(value)) add(key, value, prop);
            else if (value?.type === "Identifier" && declared.has(value.name)) {
              const target = declared.get(value.name);
              add(key, target.fn, target.node);
            }
          }
        } else if (isFunctionNode(right)) {
          add(exportName === "exports" ? "default" : exportName, right, node);
        } else if (right?.type === "Identifier" && declared.has(right.name) && exportName !== "exports") {
          const target = declared.get(right.name);
          add(exportName, target.fn, target.node);
        }
      }
    }
    for (const key of Object.keys(node)) {
      if (["loc", "start", "end", "type", "extra"].includes(key)) continue;
      if (node[key] && typeof node[key] === "object") visitCjs(node[key]);
    }
  };
  visitCjs(ast);
  return out;
}

const PY_SINK_PATTERNS = [
  ["fs", /\bopen\s*\(|Path\s*\(|read_text\s*\(|read_bytes\s*\(|shutil\./],
  ["exec", /subprocess\.(?:run|call|check_output|check_call|Popen)|os\.(?:system|popen)|commands\./],
  ["network", /requests\.(?:get|post|put|patch|delete|request)|urlopen\s*\(|httpx\.|aiohttp/],
  ["eval", /\beval\s*\(|\bexec\s*\(/],
  ["sql", /\.execute\s*\(|\.executemany\s*\(|\.raw\s*\(/],
  ["deserialize", /pickle\.loads?\s*\(|yaml\.load\s*\(|unserialize\s*\(/],
  ["template", /render_template_string\s*\(|render_template\s*\(|Template\s*\(|Environment\s*\(/],
  ["redirect", /\bredirect\s*\(/],
  ["xml", /etree\.parse\s*\(|minidom\.parse\s*\(|lxml\.etree|ElementTree\.fromstring\s*\(/],
  ["regex", /re\.(?:match|search|compile|findall|sub)\s*\(/],
  ["header", /set_header\s*\(|add_header\s*\(|headers\s*\[/],
];

function pyParamSinks(body, param) {
  const matcher = new RegExp(`\\b${param}\\b`);
  const kinds = new Set();
  for (const line of body.split(/\r?\n/)) {
    if (!matcher.test(line)) continue;
    for (const [kind, pattern] of PY_SINK_PATTERNS) if (pattern.test(line)) kinds.add(kind);
  }
  return [...kinds];
}

export function pyFunctions(source, rel) {
  const lines = source.split("\n");
  const out = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(/^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/);
    if (!match || match[2].startsWith("_")) continue;
    const indent = match[1].length;
    const name = match[2];
    // Signatures may span lines; accumulate until the parentheses balance.
    let signature = lines[index].slice(lines[index].indexOf("(") + 1);
    let last = index;
    let depth =
      (lines[index].match(/\(/g) || []).length - (lines[index].match(/\)/g) || []).length;
    while (depth > 0 && last + 1 < lines.length) {
      last += 1;
      const addition = lines[last].trim();
      depth += (addition.match(/\(/g) || []).length - (addition.match(/\)/g) || []).length;
      signature += ` ${addition}`;
    }
    const close = signature.lastIndexOf(")");
    if (close >= 0) signature = signature.slice(0, close);
    const params = signature
      .split(",")
      .map((p) => p.trim().split(":")[0].split("=")[0].trim())
      .filter((p) => p && p !== "self" && p !== "cls" && !p.startsWith("*") && /^[A-Za-z_]\w*$/.test(p));
    if (!params.length || params.length > 3) continue;
    let endLine = lines.length;
    for (let probe = last + 1; probe < lines.length; probe += 1) {
      if (!lines[probe].trim()) continue;
      const lineIndent = lines[probe].match(/^\s*/)[0].length;
      if (lineIndent <= indent) {
        endLine = probe;
        break;
      }
    }
    const body = lines.slice(index, endLine).join("\n");
    const sinks = new Map();
    params.forEach((param, paramIndex) => {
      const kinds = pyParamSinks(body, param);
      if (kinds.length) sinks.set(paramIndex, kinds);
    });
    out.push({ name, params, line: index + 1, endLine, rel, runtime: "python", sinks });
  }
  return out;
}

function hintMatch(param, hints) {
  const lower = param.toLowerCase();
  return hints.some((h) => lower === h || lower.includes(h));
}

function fillArgs(params, primary, value, family) {
  return params.map((param, idx) => {
    if (idx === primary) return value;
    if (family === "prototype-pollution" || family === "mass-assignment") return {};
    if (hintMatch(param, ["count", "limit", "size", "n", "id", "port", "index"])) return 1;
    if (hintMatch(param, ["body", "data", "obj", "options", "config"])) return {};
    return "";
  });
}

function effectsOf(result) {
  return Array.isArray(result?.effects) ? result.effects : [];
}

export const ORACLES = {
  "fs-escape": (mal, ben) => {
    const escape = /(?:^|[/\\])\.\.(?:[/\\]|$)|etc[/\\]passwd|win\.ini/i;
    const bad = effectsOf(mal).find((e) => e.type === "fs" && escape.test(e.path));
    const leaked = /root:x:0:0|\[extensions\]|daemon:x:/i.test(JSON.stringify(mal.result ?? ""));
    const good =
      effectsOf(ben).some((e) => e.type === "fs" && escape.test(e.path)) ||
      /root:x:0:0|\[extensions\]/i.test(JSON.stringify(ben.result ?? ""));
    return (bad || leaked) && !good ? { evidence: { effect: bad, leaked }, strong: true } : null;
  },
  "exec-marker": (mal, ben) => {
    const injection = /(?:;|&&|\||`|\$\(|\bid\b)/;
    const bad = effectsOf(mal).find((e) => e.type === "exec" && injection.test(e.command));
    const executed = /uid=\d+|gid=\d+|nt authority\\system/i.test(JSON.stringify(mal.result ?? ""));
    const good =
      effectsOf(ben).some((e) => e.type === "exec" && injection.test(e.command)) ||
      /uid=\d+|gid=\d+/i.test(JSON.stringify(ben.result ?? ""));
    return (bad || executed) && !good ? { evidence: { effect: bad, executed }, strong: true } : null;
  },
  "network-private": (mal) => {
    const bad = effectsOf(mal).find((e) => e.type === "network" && /169\.254|127\.0\.0\.1|localhost|file:/.test(e.url));
    return bad ? { evidence: { effect: bad }, strong: true } : null;
  },
  "sql-error-diff": (mal, ben) => {
    if (!mal.error) return null;
    const message = String(mal.error.message || "");
    if (!/SQL|syntax|near|column|table|UNION|sqlite|postgres|mysql|odbc/i.test(message)) return null;
    // The benign/sanitized input may legitimately succeed; only an identical
    // error on both inputs means the hostile input taught us nothing.
    if (ben.error && ben.error.message === mal.error.message) return null;
    return message
      ? { evidence: { error: mal.error.message, benignError: ben.error?.message ?? null }, strong: false }
      : null;
  },
  prototype: (mal) => {
    if (mal.polluted?.polluted === "kestrel" || mal.polluted?.proto === "kestrel" || mal.protoPolluted === "kestrel") {
      return { evidence: { polluted: mal.polluted, protoPolluted: mal.protoPolluted }, strong: true };
    }
    return null;
  },
  "html-unescaped": (mal, ben) => {
    const out = JSON.stringify(mal.result || "");
    const base = JSON.stringify(ben.result || "");
    return /<img|<script|onerror/i.test(out) && !/<img|<script|onerror/i.test(base)
      ? { evidence: { output: out.slice(0, 500) }, strong: false }
      : null;
  },
  timing: (mal, ben) => {
    if (!mal.elapsedUs || !ben.elapsedUs) return null;
    const ratio = mal.elapsedUs / Math.max(1, ben.elapsedUs);
    return ratio > 20 && mal.elapsedUs > 50_000
      ? { evidence: { ratio: Math.round(ratio), maliciousUs: Math.round(mal.elapsedUs), benignUs: Math.round(ben.elapsedUs) }, strong: false }
      : null;
  },
  "eval-result": (mal, ben) => {
    if (mal.error || ben.error) return null;
    const a = JSON.stringify(mal.result);
    const b = JSON.stringify(ben.result);
    return a && b && a !== b && (/[/\\]/.test(a) || a === "2")
      ? { evidence: { maliciousResult: a.slice(0, 300), benignResult: b.slice(0, 300) }, strong: false }
      : null;
  },
  deserialize: (mal) => {
    const result = mal.result;
    return result && result.kestrel === 7 ? { evidence: { result }, strong: true } : null;
  },
  redirect: (mal) => {
    const out = JSON.stringify(mal.result || "");
    return out.includes("evil.example") ? { evidence: { result: out.slice(0, 300) }, strong: false } : null;
  },
  xxe: (mal, ben) => {
    const bad = effectsOf(mal).find((e) => e.type === "fs" || e.type === "network");
    const good = effectsOf(ben).some((e) => e.type === "fs" || e.type === "network");
    return bad && !good ? { evidence: { effect: bad }, strong: true } : null;
  },
  "csv-formula": (mal) => {
    const out = JSON.stringify(mal.result || "");
    return /^"[=+\-@]/.test(out) || /^"[=+\-@]/.test(out.slice(1))
      ? { evidence: { output: out.slice(0, 200) }, strong: false }
      : null;
  },
  crlf: (mal) => {
    const out = JSON.stringify(mal.result || "");
    return /\\r\\n|%0d%0a/i.test(out) ? { evidence: { output: out.slice(0, 300) }, strong: false } : null;
  },
  "mass-assign": (mal) => {
    const out = JSON.stringify(mal.result || "");
    return /"isAdmin":true|"role":"admin"/.test(out) ? { evidence: { output: out.slice(0, 300) }, strong: false } : null;
  },
  "numeric-anomaly": (mal, ben) => {
    const out = JSON.stringify(mal.result ?? "");
    const base = JSON.stringify(ben.result ?? "");
    if (out === base) return null;
    return /NaN|Infinity|-1|4294967296|2147483648/.test(out) ? { evidence: { output: out.slice(0, 200), benign: base.slice(0, 200) }, strong: false } : null;
  },
  race: (mal) => {
    if (!Array.isArray(mal.concurrent)) return null;
    const values = mal.concurrent.map((r) => JSON.stringify(r.result ?? r.error?.message ?? ""));
    const unique = new Set(values);
    return unique.size > 1 ? { evidence: { results: [...unique].slice(0, 6) }, strong: false } : null;
  },
  "template-eval": (mal, ben) => {
    const out = JSON.stringify(mal.result ?? "");
    const base = JSON.stringify(ben.result ?? "");
    return /\b49\b/.test(out) && !/\b49\b/.test(base)
      ? { evidence: { output: out.slice(0, 500) }, strong: false }
      : null;
  },
  "nosql-match": (mal, ben) => {
    const size = (value) => {
      if (Array.isArray(value)) return value.length;
      if (value && typeof value === "object") return Object.keys(value).length;
      return value ? 1 : 0;
    };
    const hostile = size(mal.result);
    const benignSize = size(ben.result);
    if (!hostile || benignSize) return null;
    if (mal.error) return null;
    return { evidence: { output: JSON.stringify(mal.result).slice(0, 400), benign: JSON.stringify(ben.result).slice(0, 200) }, strong: false };
  },
};

function severityFor(score) {
  if (score >= 8) return "critical";
  if (score >= 6.5) return "high";
  if (score >= 4.5) return "medium";
  return "low";
}

const HANG_FAMILY = {
  id: "hang",
  oracle: "hang",
  cwe: "CWE-400",
  title: "Hostile input hangs the function (possible ReDoS or unbounded work)",
  severity: "medium",
  remediation: "Bound input length and total work, avoid nested quantifiers, and enforce per-request timeouts.",
};

function exploitability(family, { sanitizedStillVulnerable, strong, paramCount, deterministic }) {
  const base = { critical: 9, high: 7, medium: 5, low: 3 }[family.severity] || 4;
  let score = base;
  if (sanitizedStillVulnerable) score += 1;
  if (strong) score += 0.5;
  if (paramCount > 1) score -= 1;
  if (!deterministic) score -= 1;
  return Math.max(0, Math.min(10, Math.round(score * 10) / 10));
}

function pocSource(fn, family, args, runtime) {
  if (runtime === "python") {
    return `#!/usr/bin/env python3
# KESTREL PoC — ${family.title}
import importlib.util
spec = importlib.util.spec_from_file_location("target", "./${fn.rel}")
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)
print(target.${fn.name}(*${JSON.stringify(args)}))
`;
  }
  return `// KESTREL PoC — ${family.title}
const target = await import("./${fn.rel}");
try {
  console.log(await target.${fn.name}(...${JSON.stringify(args, null, 2)}));
} catch (error) {
  console.error(error);
}
`;
}

async function loadCorpus(root) {
  try {
    return JSON.parse(await fsp.readFile(path.join(root, ".kestrel", "lab-corpus.json"), "utf8"));
  } catch {
    return {};
  }
}

async function saveCorpus(root, corpus) {
  try {
    const dir = path.join(root, ".kestrel");
    await fsp.mkdir(dir, { recursive: true });
    await fsp.writeFile(path.join(dir, "lab-corpus.json"), JSON.stringify(corpus, null, 2));
  } catch {
    /* ignore */
  }
}

async function runHypothesis(ctx, fn, paramIndex, family, harness, timeout) {
  const param = fn.params[paramIndex];
  const benignArgs = fillArgs(fn.params, paramIndex, family.benign, family.id);
  const sanitizedArgs = fillArgs(fn.params, paramIndex, family.sanitized, family.id);
  const hypothesisId = crypto.randomUUID();

  // Benign and sanitized baselines only depend on the function and family, so
  // run them once per hypothesis instead of once per hostile payload.
  let benign;
  let sanitized;
  try {
    benign = await harness.run(benignArgs, timeout);
    sanitized = await harness.run(sanitizedArgs, timeout);
  } catch (err) {
    ctx.addHypothesis({
      id: hypothesisId,
      file: fn.rel,
      function: fn.name,
      param,
      family: family.id,
      oracle: family.oracle,
      status: "error",
      confidence: "low",
      exploitability: 0,
      evidence: { family: family.id, param, error: err.message, phase: "baseline" },
    });
    return null;
  }

  const results = [];
  let oracleHit = null;
  let sanitizedHit = null;
  let deterministic = true;
  let lastError = null;
  let hang = null;

  for (const payload of family.malicious) {
    const args = fillArgs(fn.params, paramIndex, payload, family.id);
    try {
      const first = await harness.run(args, timeout);
      if (first.error?.message === "KESTREL_TIMEOUT") {
        hang = { payload, args };
        break;
      }
      const second = await harness.run(args, timeout);
      if (family.id === "race-condition") {
        const concurrent = [];
        for (let i = 0; i < 6; i += 1) concurrent.push(await harness.run(args, timeout));
        first.concurrent = concurrent;
      }
      const hit = ORACLES[family.oracle]?.(first, benign);
      const hitAgain = ORACLES[family.oracle]?.(second, benign);
      if (hit && hitAgain) {
        oracleHit = hit;
        sanitizedHit = ORACLES[family.oracle]?.(sanitized, benign);
        deterministic = true;
        results.push({ payload, args, benign, sanitized, first, second, hit });
        break;
      }
      if (hit && !hitAgain) deterministic = false;
      results.push({ payload, args, benign, sanitized, first, second, hit });
    } catch (err) {
      // The harness kills the child on a synchronous hang; that timeout is a
      // finding signal, not an infrastructure error.
      if (err?.timeout) {
        hang = { payload, args };
        break;
      }
      lastError = err.message;
    }
  }

  let effectiveFamily = family;
  let effectiveHit = oracleHit;
  let hangRun = null;
  if (!oracleHit && hang) {
    effectiveFamily = HANG_FAMILY;
    effectiveHit = {
      evidence: { payload: String(hang.payload).slice(0, 240), timeoutMs: timeout },
      strong: false,
    };
    sanitizedHit = null;
    deterministic = true;
    hangRun = {
      args: hang.args,
      benign,
      sanitized,
      first: {
        result: null,
        error: { name: "Timeout", message: `no response within ${timeout} ms` },
        effects: [],
        elapsedUs: timeout * 1000,
      },
    };
  }

  const evidence = {
    family: effectiveFamily.id,
    param,
    oracle: effectiveFamily.oracle,
    deterministic,
    sanitizedStillVulnerable: Boolean(sanitizedHit),
    attempts: results.length,
    lastError,
  };
  if (!effectiveHit) {
    ctx.addHypothesis({
      id: hypothesisId,
      file: fn.rel,
      function: fn.name,
      param,
      family: family.id,
      oracle: family.oracle,
      status: lastError && !results.length ? "error" : "rejected",
      confidence: "low",
      exploitability: 0,
      evidence: { ...evidence, error: lastError },
    });
    return null;
  }
  const score = exploitability(effectiveFamily, {
    sanitizedStillVulnerable: Boolean(sanitizedHit),
    strong: Boolean(effectiveHit.strong),
    paramCount: fn.params.length,
    deterministic,
  });
  const confidence = deterministic && effectiveHit.strong ? "high" : deterministic ? "medium" : "low";
  const zeroDayScore = Math.round(score * 7 + (confidence === "high" ? 20 : confidence === "medium" ? 10 : 0) + (deterministic ? 10 : 0));
  const run = hangRun || results[results.length - 1];
  const source = await fsp.readFile(path.join(ctx.root, fn.rel), "utf8");
  const result = ctx.add({
    engine: "zeroday",
    ruleId: `lab-${effectiveFamily.id}`,
    title: `${effectiveFamily.title} in ${fn.name}()`,
    description:
      `The zero-day lab executed \`${fn.name}\` with a benign, a sanitized and a hostile input. ` +
      `The hostile input produced \`${effectiveFamily.oracle}\` while the benign input did not. ` +
      (sanitizedHit ? "The sanitized baseline still triggered the oracle, so the sanitizer is ineffective. " : "") +
      (deterministic ? "The effect reproduced on both runs. " : "The effect was not deterministic. ") +
      `Exploitability ${score}/10, zero-day score ${zeroDayScore}/100.`,
    severity: severityFor(score),
    confidence,
    file: fn.rel,
    line: fn.line,
    snippet: snippetAt(source, fn.line, 4),
    cwe: effectiveFamily.cwe,
    owasp: effectiveFamily.id === "ssrf" ? "A10:2021" : "A03:2021",
    cvssVector: effectiveFamily.severity === "critical"
      ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      : effectiveFamily.severity === "high"
        ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
        : "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    tags: ["zero-day", "dynamic", "confirmed", effectiveFamily.id],
    taint: {
      source: { line: fn.line, code: `parameter ${param}`, name: param },
      sink: { line: fn.line, code: `${fn.name}(${JSON.stringify(run.args).slice(0, 220)})` },
      steps: [],
    },
    evidence: {
      runtime: fn.runtime,
      function: fn.name,
      param,
      oracle: effectiveFamily.oracle,
      detection: effectiveHit.evidence,
      benignArgs,
      sanitizedArgs,
      maliciousArgs: run.args,
      benign: { result: run.benign.result, error: run.benign.error, effects: run.benign.effects, elapsedUs: Math.round(run.benign.elapsedUs) },
      sanitized: { result: run.sanitized.result, error: run.sanitized.error, effects: run.sanitized.effects },
      malicious: { result: run.first.result, error: run.first.error, effects: run.first.effects, elapsedUs: Math.round(run.first.elapsedUs) },
      deterministic,
      exploitability: score,
      zeroDayScore,
    },
    remediation: effectiveFamily.remediation,
    references: [`https://cwe.mitre.org/data/definitions/${effectiveFamily.cwe.replace("CWE-", "")}.html`],
  });
  const findingId = result?.id;
  if (findingId) {
    const bundle = {
      findingId,
      family: effectiveFamily.id,
      title: effectiveFamily.title,
      file: fn.rel,
      function: fn.name,
      runtime: fn.runtime,
      args: run.args,
      benignArgs,
      sanitizedArgs,
      oracle: effectiveFamily.oracle,
      expected: effectiveHit.evidence,
      deterministic,
      exploitability: score,
      zeroDayScore,
      createdAt: now(),
    };
    const json = JSON.stringify(bundle, null, 2);
    const artifact = await ctx.writeArtifact(`poc-${findingId}.json`, json);
    const code = pocSource(fn, family, run.args, fn.runtime);
    const codeArtifact = await ctx.writeArtifact(`poc-${findingId}.${fn.runtime === "python" ? "py" : "mjs"}`, code);
    const current = db.prepare("SELECT evidence_json FROM findings WHERE id = ?").get(findingId);
    db.prepare("UPDATE findings SET verified = 1, verification_json = ?, tags_json = ?, evidence_json = ? WHERE id = ?").run(
      JSON.stringify({ method: "differential-lab", at: now(), confidence, deterministic }),
      JSON.stringify(["zero-day", "dynamic", "confirmed", effectiveFamily.id, "poc"]),
      JSON.stringify({ ...JSON.parse(current?.evidence_json || "{}"), poc: artifact.rel, pocCode: codeArtifact.rel, pocSha256: artifact.sha256 }),
      findingId,
    );
    ctx.addHypothesis({
      id: hypothesisId,
      findingId,
      file: fn.rel,
      function: fn.name,
      param,
      family: effectiveFamily.id,
      oracle: effectiveFamily.oracle,
      status: "confirmed",
      confidence,
      exploitability: score,
      evidence: { ...evidence, detection: effectiveHit.evidence, poc: artifact.rel, zeroDayScore },
    });
  }
  return { findingId, score, zeroDayScore, args: run.args, familyId: effectiveFamily.id };
}

export default {
  id: "zeroday",
  name: "Zero-Day Lab",
  description:
    "Differential hypothesis engine: 18 attack families, sink-aware parameter inference, effect oracles, deterministic replay, PoC bundles and exploitability scoring.",
  category: "research",
  targetTypes: ["code", "mixed"],
  dynamic: true,
  cost: "high",
  async run(ctx) {
    if (ctx.config.zeroDay === false) {
      ctx.emit("info", "Zero-day lab disabled by config");
      return;
    }
    const maxFunctions = Math.min(32, Number(ctx.config.labMaxFunctions || 8));
    const candidates = [];
    for (const file of ctx.files) {
      if (file.lang === "javascript" || file.lang === "typescript") {
        candidates.push(...jsFunctions(await fsp.readFile(file.abs, "utf8"), file.rel));
      } else if (file.lang === "python") {
        candidates.push(...pyFunctions(await fsp.readFile(file.abs, "utf8"), file.rel));
      }
      if (candidates.length >= maxFunctions * 4) break;
    }
    if (!candidates.length) {
      ctx.emit("info", "No exported functions suitable for dynamic lab testing");
      return;
    }
    const sast = db.prepare("SELECT file, line, rule_id FROM findings WHERE scan_id = ? AND file IS NOT NULL").all(ctx.scan.id);
    const score = (fn) => {
      let value = 0;
      fn.params.forEach((_, index) => {
        value += familiesForParam(fn, index).length * 2;
      });
      if (sast.some((s) => s.file === fn.rel && s.line >= fn.line && s.line <= fn.endLine)) value += 5;
      return value;
    };
    for (const fn of candidates) {
      try {
        const text = await fsp.readFile(path.join(ctx.root, fn.rel), "utf8");
        const body = text.split(/\r?\n/).slice(fn.line - 1, fn.endLine).join("\n");
        fn.sinkScore = (body.match(SINK_RE) || []).length;
      } catch {
        fn.sinkScore = 0;
      }
    }
    const rank = (fn) => score(fn) + fn.sinkScore * 2;
    candidates.sort((a, b) => rank(b) - rank(a));
    const byFile = new Map();
    for (const candidate of candidates.filter((c) => score(c) > 0)) {
      if (!byFile.has(candidate.rel)) byFile.set(candidate.rel, []);
      byFile.get(candidate.rel).push(candidate);
    }
    for (const queue of byFile.values()) queue.sort((a, b) => rank(b) - rank(a));
    const queues = [...byFile.values()];
    const ordered = [];
    while (queues.some((q) => q.length) && ordered.length < maxFunctions) {
      for (const queue of queues) {
        if (queue.length && ordered.length < maxFunctions) ordered.push(queue.shift());
      }
    }
    ctx.emit("info", `Zero-day lab evaluating ${ordered.length} functions across ${queues.length} files`);
    const corpus = await loadCorpus(ctx.root);
    let confirmed = 0;
    let tested = 0;
    for (const fn of ordered) {
      if (ctx.signal?.aborted) break;
      const covDir = fn.runtime === "node" ? makeCoverageDir() : null;
      const harness = new Harness({
        runtime: fn.runtime,
        modulePath: path.join(ctx.root, fn.rel),
        fnName: fn.name,
        env: covDir ? { NODE_V8_COVERAGE: covDir } : {},
      });
      const key = `${fn.rel}:${fn.name}`;
      const seeds = corpus[key] || [];
      try {
        for (const seed of seeds.slice(-20)) {
          try {
            await harness.run(seed.args, 3000);
          } catch {
            /* seed may fail */
          }
        }
        for (let idx = 0; idx < fn.params.length; idx += 1) {
          const relevant = familiesForParam(fn, idx);
          for (const family of relevant) {
            if (ctx.signal?.aborted) break;
            tested += 1;
            const timeout = family.id === "ssrf" || family.id === "xxe" ? 8000 : 3500;
            const result = await runHypothesis(ctx, fn, idx, family, harness, timeout);
            if (result) {
              confirmed += 1;
              corpus[key] = [...(corpus[key] || []), { args: result.args, hits: 1 }].slice(-40);
              ctx.emit("finding", `Lab confirmed ${result.familyId || family.id} in ${fn.name}() · ${result.zeroDayScore}/100`, {
                function: fn.name,
                family: result.familyId || family.id,
                score: result.zeroDayScore,
              });
            }
          }
        }
        corpus[key] = (corpus[key] || []).slice(-40);
      } finally {
        harness.close();
        if (covDir) cleanup(covDir);
      }
    }
    await saveCorpus(ctx.root, corpus);
    ctx.emit("info", `Zero-day lab: ${tested} hypotheses, ${confirmed} confirmed`);
  },
};
