import fsp from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { entropy, redactSecret, snippetAt } from "../lib/util.js";

const exec = promisify(execFile);

const RULES = [
  { id: "aws-access-key", name: "AWS Access Key ID", re: /\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "aws-secret-key", name: "AWS Secret Access Key", re: /(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi, group: 1, sev: "critical", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "github-token", name: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "scm"] },
  { id: "gitlab-token", name: "GitLab token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "scm"] },
  { id: "slack-token", name: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential"] },
  { id: "slack-webhook", name: "Slack webhook URL", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, sev: "medium", cwe: "CWE-798", tags: ["credential"] },
  { id: "stripe-secret", name: "Stripe secret key", re: /\bsk_(live|test)_[A-Za-z0-9]{20,}\b/g, sev: "critical", cwe: "CWE-798", tags: ["credential", "payment"] },
  { id: "stripe-webhook", name: "Stripe webhook secret", re: /\bwhsec_[A-Za-z0-9]{20,}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "payment"] },
  { id: "openai-key", name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "ai"] },
  { id: "anthropic-key", name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "ai"] },
  { id: "huggingface-token", name: "Hugging Face token", re: /\bhf_[A-Za-z0-9]{30,}\b/g, sev: "medium", cwe: "CWE-798", tags: ["credential", "ai"] },
  { id: "google-api-key", name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, sev: "medium", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "gcp-service-account", name: "GCP service account key", re: /"type"\s*:\s*"service_account"/g, sev: "high", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "azure-storage-key", name: "Azure storage key", re: /AccountKey=([A-Za-z0-9+/=]{40,})/g, group: 1, sev: "critical", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "npm-token", name: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "supply-chain"] },
  { id: "pypi-token", name: "PyPI token", re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "supply-chain"] },
  { id: "private-key", name: "Private key block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, sev: "critical", cwe: "CWE-321", tags: ["credential", "crypto"] },
  { id: "jwt", name: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, sev: "medium", cwe: "CWE-798", tags: ["credential"] },
  { id: "sendgrid-key", name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "email"] },
  { id: "mailgun-key", name: "Mailgun API key", re: /\bkey-[0-9a-zA-Z]{32}\b/g, sev: "medium", cwe: "CWE-798", tags: ["credential", "email"] },
  { id: "twilio-key", name: "Twilio API key", re: /\bSK[0-9a-fA-F]{32}\b/g, sev: "medium", cwe: "CWE-798", tags: ["credential"] },
  { id: "digitalocean-token", name: "DigitalOcean token", re: /\bdop_v1_[a-f0-9]{64}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "cloudflare-token", name: "Cloudflare API token", re: /\b[A-Za-z0-9_-]{40}\b(?=.*cloudflare)/gi, sev: "medium", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "heroku-key", name: "Heroku API key", re: /heroku[a-z0-9_ .\-,]{0,25}[:=]\s*["']?([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})["']?/gi, group: 1, sev: "medium", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "vercel-token", name: "Vercel token", re: /\bvercel_[A-Za-z0-9]{24,}\b/g, sev: "medium", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "supabase-key", name: "Supabase service key", re: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "database"] },
  { id: "firebase-key", name: "Firebase server key", re: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/g, sev: "medium", cwe: "CWE-798", tags: ["credential", "cloud"] },
  { id: "shopify-token", name: "Shopify access token", re: /\bshpat_[a-fA-F0-9]{32}\b/g, sev: "high", cwe: "CWE-798", tags: ["credential", "commerce"] },
  { id: "telegram-token", name: "Telegram bot token", re: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g, sev: "medium", cwe: "CWE-798", tags: ["credential"] },
  { id: "discord-webhook", name: "Discord webhook URL", re: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g, sev: "medium", cwe: "CWE-798", tags: ["credential"] },
  { id: "db-uri", name: "Database URI with credentials", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s]+:([^@\s]+)@[^\s"']+/g, group: 1, sev: "high", cwe: "CWE-798", tags: ["credential", "database"] },
  { id: "basic-auth-url", name: "URL with basic auth", re: /\bhttps?:\/\/[^/\s:]+:[^@\s]+@[^\s"']+/g, sev: "medium", cwe: "CWE-798", tags: ["credential"] },
  { id: "smtp-password", name: "SMTP password", re: /smtp[_-]?pass(?:word)?\s*[:=]\s*["']?([^"'\s]{8,})["']?/gi, group: 1, sev: "medium", cwe: "CWE-798", tags: ["credential", "email"] },
  { id: "encryption-key", name: "Encryption key assignment", re: /(?:encryption[_-]?key|aes[_-]?key|secret[_-]?key)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{16,})["']/gi, group: 1, sev: "high", cwe: "CWE-321", tags: ["credential", "crypto"] },
  { id: "generic-api-key", name: "Generic API key", re: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']/gi, group: 1, sev: "medium", cwe: "CWE-798", tags: ["credential"], entropy: 3.2 },
  { id: "password-assignment", name: "Hardcoded password", re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{6,})["']/gi, group: 1, sev: "medium", cwe: "CWE-798", tags: ["credential"], entropy: 2.2 },
];

const PLACEHOLDERS = /^(?:x{4,}|changeme|change_me|example|your[_-]?key|todo|placeholder|test|dummy|password|secret|<.*>|\$\{.*\})$/i;
const TEXT_EXT = new Set([
  "javascript", "typescript", "python", "go", "ruby", "php", "java", "kotlin", "csharp", "rust",
  "shell", "powershell", "yaml", "json", "toml", "xml", "html", "dotenv", "markdown", "terraform", "text",
]);

function scanText(text, rel, add) {
  const lines = text.split(/\r?\n/);
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let match;
    let guard = 0;
    while ((match = rule.re.exec(text)) && guard < 500) {
      guard += 1;
      const value = match[rule.group || 0];
      if (!value || value.length < 6) continue;
      if (PLACEHOLDERS.test(value.trim())) continue;
      if (rule.entropy && entropy(value) < rule.entropy) continue;
      const before = text.slice(0, match.index);
      const line = before.split("\n").length;
      if (lines[line - 1]?.includes("kestrel:allow")) continue;
      const redacted = redactSecret(value);
      add({
        engine: "secrets",
        ruleId: rule.id,
        title: `${rule.name} committed in source`,
        description:
          `A value matching **${rule.name}** was found in \`${rel}\`. ` +
          `Hardcoded credentials survive repository forks, CI logs and build artifacts. ` +
          `The value is redacted below; rotate it if the repository is shared.`,
        severity: rule.sev,
        confidence: rule.entropy ? "medium" : "high",
        file: rel,
        line,
        column: match.index - before.lastIndexOf("\n"),
        snippet: snippetAt(text, line, 2),
        cwe: rule.cwe,
        owasp: "A02:2021",
        cvssVector: rule.sev === "critical" ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        evidence: {
          match: redacted,
          rawLength: value.length,
          entropy: Math.round(entropy(value) * 100) / 100,
          lineText: (lines[line - 1] || "").trim().slice(0, 300),
        },
        remediation:
          `Move the value into an environment variable or secret manager, rotate it, ` +
          `and add a pre-commit hook (gitleaks/trufflehog) to prevent recurrence. ` +
          `For client-side bundles, verify the key is intended to be public.`,
        references: ["https://cwe.mitre.org/data/definitions/798.html"],
        tags: ["secret", ...rule.tags],
      });
    }
  }
}

async function scanGitHistory(root, add, emit) {
  try {
    await fsp.access(path.join(root, ".git"));
  } catch {
    return;
  }
  try {
    const { stdout } = await exec(
      "git",
      ["log", "--all", "-p", "--unified=0", "--format=commit:%H", "-n", "120", "--", "."],
      { cwd: root, maxBuffer: 24 * 1024 * 1024, timeout: 45_000 },
    );
    if (!stdout.trim()) return;
    emit("info", "Scanning 120 commits of Git history for leaked credentials");
    let commit = "unknown";
    const added = [];
    for (const line of stdout.split(/\r?\n/)) {
      if (line.startsWith("commit:")) commit = line.slice(7, 19);
      else if (line.startsWith("+") && !line.startsWith("+++")) added.push(`${commit} ${line.slice(1)}`);
    }
    scanText(added.join("\n"), ".git history", (finding) => {
      finding.title = `${finding.title} (historical)`;
      finding.description += "\n\nThis value appears in Git history and may still be valid even if removed from HEAD.";
      finding.tags.push("history");
      finding.evidence.commit = finding.snippet?.match(/^\s*\d+ \| ([a-f0-9]{12})/)?.[1];
      add(finding);
    });
  } catch (err) {
    emit("warn", `Git history scan skipped: ${err.message}`);
  }
}

export default {
  id: "secrets",
  name: "Secret Hunter",
  description: "45 credential signatures, entropy analysis, placeholder filtering and Git history.",
  category: "secrets",
  targetTypes: ["code", "iac", "mixed", "container"],
  cost: "low",
  async run(ctx) {
    const { files, root, add, emit } = ctx;
    let count = 0;
    for (const file of files) {
      if (!TEXT_EXT.has(file.lang)) continue;
      let text;
      try {
        text = await fsp.readFile(file.abs, "utf8");
      } catch {
        continue;
      }
      scanText(text, file.rel, (f) => {
        count += 1;
        add(f);
      });
    }
    emit("info", `Scanned ${files.length} files, ${count} credential candidates`);
    await scanGitHistory(root, add, emit);
  },
};
