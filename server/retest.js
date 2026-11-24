import fsp from "node:fs/promises";
import path from "node:path";
import { db, now } from "./db.js";
import { getFinding } from "./store.js";
import { ScopeGate, normalizeScope } from "./scope.js";

export async function retestFinding(findingId, actor = null) {
  const finding = getFinding(findingId);
  if (!finding) throw new Error("finding not found");
  const scan = db.prepare("SELECT * FROM scans WHERE id = ?").get(finding.scanId);
  const project = scan?.project_id ? db.prepare("SELECT * FROM projects WHERE id = ?").get(scan.project_id) : null;
  const checks = [];
  let ok = false;
  if (finding.file && project) {
    try {
      const text = await fsp.readFile(path.join(project.path, finding.file), "utf8");
      const line = text.split(/\r?\n/)[finding.line - 1] || "";
      checks.push({ check: "line-still-present", pass: Boolean(line.trim()) });
      ok = Boolean(line.trim());
    } catch {
      checks.push({ check: "file-exists", pass: false });
    }
  } else if (finding.engine === "web" || finding.engine === "tls") {
    const url = finding.evidence?.request?.url || finding.assetValue;
    if (url && scan) {
      try {
        const gate = new ScopeGate(normalizeScope(JSON.parse(scan.scope_json || "{}")));
        const res = await gate.fetch(url, { timeout: 10_000 });
        const expected = finding.evidence?.response?.status;
        ok = expected ? res.status === expected : res.status < 500;
        checks.push({ check: "replay", status: res.status, expected, pass: ok });
      } catch (err) {
        checks.push({ check: "replay", pass: false, error: err.message });
      }
    }
  } else if (finding.engine === "dependencies" && project) {
    try {
      const text = await fsp.readFile(path.join(project.path, finding.file), "utf8");
      ok = text.includes(finding.evidence?.package) && text.includes(finding.evidence?.version);
      checks.push({ check: "version-still-present", pass: ok });
    } catch {
      checks.push({ check: "manifest-exists", pass: false });
    }
  }
  const verification = { method: "manual-retest", at: now(), checks, actor };
  db.prepare("UPDATE findings SET verified = ?, verification_json = ?, updated_at = ? WHERE id = ?").run(
    ok ? 1 : 0, JSON.stringify(verification), now(), finding.id,
  );
  return { ok, checks, verification };
}
