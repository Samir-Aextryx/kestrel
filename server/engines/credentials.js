import crypto from "node:crypto";
import { db, now } from "../db.js";

const WORDLIST = [
  "password", "123456", "123456789", "qwerty", "12345678", "111111", "123123", "abc123", "password1",
  "admin", "admin123", "root", "toor", "letmein", "welcome", "monkey", "dragon", "master", "sunshine",
  "princess", "football", "baseball", "shadow", "superman", "michael", "jennifer", "hunter", "trustno1",
  "passw0rd", "p@ssw0rd", "changeme", "secret", "test", "guest", "demo", "dev", "staging", "prod",
  "kestrel", "security", "cyber", "company", "office", "summer2026", "winter2026", "spring2026",
  "qwerty123", "1q2w3e4r", "zaq12wsx", "iloveyou", "starwars", "whatever", "freedom", "hello",
];

function digest(algo, value) {
  return crypto.createHash(algo).update(value).digest("hex");
}

export default {
  id: "credentials",
  name: "Credential Analyst",
  description: "Cracks weak MD5/SHA1 hashes with a local wordlist and consolidates valid credentials from auth and post-exploitation.",
  category: "auth",
  targetTypes: ["code", "web", "api", "mixed"],
  cost: "low",
  async run(ctx) {
    let cracked = 0;
    const findings = db
      .prepare("SELECT * FROM findings WHERE scan_id = ? AND engine = 'secrets'")
      .all(ctx.scan.id);
    for (const finding of findings) {
      const evidence = JSON.parse(finding.evidence_json || "{}");
      const line = evidence.lineText || "";
      const hash = line.match(/\b([a-f0-9]{32}|[a-f0-9]{40})\b/i)?.[1];
      if (!hash) continue;
      const algo = hash.length === 32 ? "md5" : "sha1";
      for (const word of WORDLIST) {
        if (digest(algo, word) !== hash.toLowerCase()) continue;
        cracked += 1;
        db.prepare(
          "INSERT INTO credentials(id, scan_id, kind, username, secret, source, valid, meta_json, created_at) VALUES(?, ?, 'hash', ?, ?, ?, 1, ?, ?)",
        ).run(crypto.randomUUID(), ctx.scan.id, hash, word, finding.file, JSON.stringify({ algo, findingId: finding.id }), now());
        ctx.add({
          engine: "credentials",
          ruleId: "weak-hash-cracked",
          title: `${algo.toUpperCase()} hash cracked: "${word}"`,
          description: `The ${algo} hash in \`${finding.file}\` matches the wordlist entry \`${word}\`.`,
          severity: algo === "md5" ? "medium" : "low",
          confidence: "high",
          file: finding.file,
          line: finding.line,
          cwe: "CWE-916",
          owasp: "A02:2021",
          tags: ["credential", "hash", "cracked"],
          evidence: { hash, algo, password: word },
          remediation: "Migrate to Argon2id/scrypt/bcrypt and force a password reset.",
          references: ["https://cwe.mitre.org/data/definitions/916.html"],
        });
        break;
      }
    }
    const valid = db.prepare("SELECT COUNT(*) AS n FROM credentials WHERE scan_id = ? AND valid = 1").get(ctx.scan.id).n;
    ctx.emit("info", `Credential analyst: ${cracked} hashes cracked, ${valid} valid credentials`);
  },
};
