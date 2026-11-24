import fsp from "node:fs/promises";
import { parse } from "@babel/parser";
import { snippetAt } from "../lib/util.js";

const SINKS = {
  exec: ["CWE-78", "critical", "command execution"],
  execSync: ["CWE-78", "critical", "command execution"],
  spawn: ["CWE-78", "high", "process spawn"],
  spawnSync: ["CWE-78", "high", "process spawn"],
  eval: ["CWE-95", "high", "dynamic evaluation"],
  Function: ["CWE-95", "high", "dynamic evaluation"],
  readFileSync: ["CWE-22", "high", "file read"],
  readFile: ["CWE-22", "high", "file read"],
  writeFileSync: ["CWE-22", "high", "file write"],
  writeFile: ["CWE-22", "high", "file write"],
  fetch: ["CWE-918", "high", "outbound request"],
  redirect: ["CWE-601", "medium", "redirect"],
  query: ["CWE-89", "critical", "SQL query"],
  execute: ["CWE-89", "critical", "SQL execute"],
  merge: ["CWE-1321", "high", "deep merge"],
  assign: ["CWE-1321", "medium", "object assign"],
  deserialize: ["CWE-502", "high", "deserialization"],
  render_template_string: ["CWE-1336", "high", "template compilation"],
  open: ["CWE-22", "high", "file open"],
  system: ["CWE-78", "critical", "shell execution"],
};

function nameOf(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") {
    const obj = nameOf(node.object);
    const prop = node.computed ? "" : nameOf(node.property);
    return obj && prop ? `${obj}.${prop}` : obj || prop;
  }
  if (node.type === "CallExpression") return nameOf(node.callee);
  return "";
}

function code(source, node) {
  return source.slice(node.start, Math.min(node.end, node.start + 240)).replace(/\s+/g, " ").trim();
}

function tainted(node, taintedNames) {
  if (!node) return false;
  if (node.type === "Identifier") return taintedNames.has(node.name);
  if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") return tainted(node.object, taintedNames);
  if (node.type === "TemplateLiteral") return node.expressions.some((e) => tainted(e, taintedNames));
  if (node.type === "BinaryExpression" || node.type === "LogicalExpression") return tainted(node.left, taintedNames) || tainted(node.right, taintedNames);
  if (node.type === "CallExpression") return node.arguments.some((a) => tainted(a, taintedNames));
  if (node.type === "AssignmentExpression") return tainted(node.right, taintedNames);
  if (node.type === "AwaitExpression") return tainted(node.argument, taintedNames);
  return false;
}

function collectJs(source, rel) {
  let ast;
  try {
    ast = parse(source, { sourceType: "unambiguous", errorRecovery: true, plugins: ["jsx", "typescript", "topLevelAwait"] });
  } catch {
    return [];
  }
  const functions = [];
  const walk = (node, parent) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) return node.forEach((n) => walk(n, parent));
    if (!node.type) return;
    const isFn = node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression";
    if (isFn) {
      const name = node.id?.name || (parent?.type === "VariableDeclarator" ? nameOf(parent.id) : "");
      if (name) {
        functions.push({
          name,
          rel,
          line: node.loc?.start.line || 1,
          params: node.params.map((p) => p.name || p.left?.name || "").filter(Boolean),
          calls: [],
          sinks: [],
          body: node.body,
        });
      }
    }
    for (const key of Object.keys(node)) {
      if (["loc", "start", "end", "type", "extra"].includes(key)) continue;
      if (node[key] && typeof node[key] === "object") walk(node[key], node);
    }
  };
  walk(ast, null);
  for (const fn of functions) {
    const visit = (node) => {
      if (!node || typeof node !== "object") return;
      if (Array.isArray(node)) return node.forEach(visit);
      if (node.type === "CallExpression" || node.type === "NewExpression") {
        const full = nameOf(node.callee);
        const last = full.split(".").pop();
        if (SINKS[last]) fn.sinks.push({ name: full, last, node, args: node.arguments });
        else if (full) fn.calls.push({ name: full, args: node.arguments, node });
      }
      for (const key of Object.keys(node)) {
        if (["loc", "start", "end", "type", "extra"].includes(key)) continue;
        if (node[key] && typeof node[key] === "object") visit(node[key]);
      }
    };
    visit(fn.body);
  }
  return functions;
}

function collectPython(source, rel) {
  const lines = source.split("\n");
  const functions = [];
  lines.forEach((line, idx) => {
    const m = line.match(/^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/);
    if (!m) return;
    const params = m[2].split(",").map((p) => p.trim().split(":")[0].split("=")[0].trim()).filter((p) => p && p !== "self");
    let end = lines.length;
    for (let i = idx + 1; i < lines.length; i += 1) {
      if (/^(?:async\s+)?def\s+/.test(lines[i])) {
        end = i;
        break;
      }
    }
    const body = lines.slice(idx, end);
    const calls = [];
    const sinks = [];
    body.forEach((text, offset) => {
      for (const match of text.matchAll(/([A-Za-z_][\w.]*)\s*\(([^)]*)\)/g)) {
        const full = match[1];
        const last = full.split(".").pop();
        if (SINKS[last]) sinks.push({ name: full, last, line: idx + offset + 1, argsText: match[2] });
        else calls.push({ name: full, line: idx + offset + 1, argsText: match[2] });
      }
    });
    functions.push({ name: m[1], rel, line: idx + 1, params, calls, sinks, python: true });
  });
  return functions;
}

export default {
  id: "interproc",
  name: "Interprocedural Taint",
  description: "Cross-function taint propagation from exported entry points into sinks in callees, with a call path.",
  category: "sast",
  targetTypes: ["code", "mixed"],
  cost: "medium",
  async run(ctx) {
    const functions = [];
    for (const file of ctx.files) {
      if (["javascript", "typescript"].includes(file.lang)) {
        functions.push(...collectJs(await fsp.readFile(file.abs, "utf8"), file.rel));
      } else if (file.lang === "python") {
        functions.push(...collectPython(await fsp.readFile(file.abs, "utf8"), file.rel));
      }
      if (functions.length > 600) break;
    }
    const byName = new Map();
    for (const fn of functions) {
      if (!byName.has(fn.name)) byName.set(fn.name, []);
      byName.get(fn.name).push(fn);
    }
    const reported = new Set();
    let count = 0;
    const analyze = async (fn, taintedParams, path, depth) => {
      if (depth > 4 || count > 120) return;
      for (const sink of fn.sinks) {
        const arg = sink.args?.[0];
        const argText = sink.argsText || "";
        const hit = arg ? tainted(arg, taintedParams) : [...taintedParams].some((p) => new RegExp(`\\b${p}\\b`).test(argText));
        if (!hit) continue;
        const key = `${fn.rel}:${fn.line}:${sink.last}:${path.join(">")}`;
        if (reported.has(key)) continue;
        reported.add(key);
        count += 1;
        const [cwe, severity, label] = SINKS[sink.last];
        const source = await fsp.readFile(fn.rel ? (fn.rel.startsWith(ctx.root) ? fn.rel : `${ctx.root}/${fn.rel}`) : "", "utf8").catch(() => "");
        ctx.add({
          engine: "interproc",
          ruleId: `interproc-${sink.last}`,
          title: `Interprocedural taint reaches ${label}`,
          description:
            `Tainted parameter data flows across ${path.length} call boundary(ies): \`${path.join(" → ")}\` ` +
            `and reaches \`${sink.name}()\`. The intra-file engine would miss this path.`,
          severity,
          confidence: "medium",
          file: fn.rel,
          line: fn.line,
          snippet: source ? snippetAt(source, fn.line, 3) : "",
          cwe,
          owasp: "A03:2021",
          tags: ["interprocedural", "taint", "call-path"],
          taint: {
            source: { line: fn.line, code: `parameter ${[...taintedParams][0] || "input"}`, name: [...taintedParams][0] },
            sink: { line: fn.line, code: sink.argsText ? `${sink.name}(${sink.argsText})` : sink.name },
            steps: path.map((name, i) => ({ line: fn.line, code: name, order: i })),
          },
          evidence: { path, sink: sink.name, arg: argText.slice(0, 300) },
          remediation: "Validate at the boundary and keep the value parameterized until the sink.",
          references: [`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`],
        });
      }
      for (const call of fn.calls) {
        const targets = byName.get(call.name.split(".").pop()) || [];
        for (const target of targets.slice(0, 3)) {
          if (target === fn) continue;
          const nextTainted = new Set(taintedParams);
          target.params.forEach((param, idx) => {
            if (call.args?.[idx] && tainted(call.args[idx], taintedParams)) nextTainted.add(param);
          });
          if (!nextTainted.size) continue;
          await analyze(target, nextTainted, [...path, target.name], depth + 1);
        }
      }
    };
    for (const fn of functions) {
      if (!fn.params.length) continue;
      await analyze(fn, new Set(fn.params), [fn.name], 0);
    }
    ctx.emit("info", `Interprocedural taint: ${count} cross-function paths`);
  },
};
