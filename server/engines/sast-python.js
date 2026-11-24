import { spawn } from "node:child_process";
import path from "node:path";
import { ROOT } from "../config.js";

const PY_EXT = new Set(["python"]);

function runPython(files) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.KESTREL_PYTHON || "python", [path.join(ROOT, "engines", "py", "sast.py")], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("python analyzer timeout"));
    }, 90_000);
    child.stdout.on("data", (chunk) => {
      out += chunk;
    });
    child.stderr.on("data", (chunk) => {
      err += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0 && !out) return reject(new Error(err.slice(0, 500) || `python exited ${code}`));
      const findings = [];
      for (const line of out.split(/\r?\n/)) {
        if (!line.trim()) continue;
        try {
          findings.push(JSON.parse(line));
        } catch {
          /* ignore */
        }
      }
      resolve(findings);
    });
    child.stdin.write(JSON.stringify({ files }));
    child.stdin.end();
  });
}

export default {
  id: "sast-python",
  name: "Python Taint Analyst",
  description: "Python AST data-flow analysis for injection, traversal, SSRF, deserialization, SSTI and framework misconfigurations.",
  category: "sast",
  targetTypes: ["code", "mixed"],
  cost: "medium",
  async run(ctx) {
    const files = ctx.files
      .filter((f) => PY_EXT.has(f.lang))
      .map((f) => ({ abs: f.abs, rel: f.rel }));
    if (!files.length) return;
    const findings = await runPython(files);
    for (const finding of findings) {
      ctx.add({
        ...finding,
        owasp: finding.owasp || "A03:2021",
        references: finding.references || [],
      });
    }
    ctx.emit("info", `Analyzed ${files.length} Python files, ${findings.length} candidates`);
  },
};
