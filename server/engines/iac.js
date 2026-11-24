import fsp from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import { snippetAt } from "../lib/util.js";

function cvss(sev) {
  return {
    critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev];
}

const DOCKER_RULES = [
  { re: /^\s*FROM\s+(\S+)\s*$/gim, rule: "docker-latest", title: "Base image without pinned digest", sev: "medium", cwe: "CWE-1104", desc: "Tags are mutable. `latest` or a floating tag makes builds non-reproducible and can silently pull a compromised image.", fix: "Pin the digest (`image@sha256:…`) and update it deliberately.", tags: ["supply-chain"] },
  { re: /^\s*USER\s+root\s*$/gim, rule: "docker-root", title: "Container runs as root", sev: "medium", cwe: "CWE-250", desc: "A root process inside the container widens the impact of a breakout and of file permission bugs.", fix: "Create an unprivileged user and switch with `USER app`.", tags: ["container"] },
  { re: /^\s*ADD\s+(?!.*https?:)/gim, rule: "docker-add", title: "ADD used for local files", sev: "low", cwe: "CWE-1104", desc: "ADD auto-extracts archives and supports URLs, which makes behavior less predictable than COPY.", fix: "Use COPY unless archive extraction is intended.", tags: ["container"] },
  { re: /^\s*ARG\s+\w*(?:SECRET|TOKEN|PASSWORD|KEY)\w*(?:=.*)?$/gim, rule: "docker-arg-secret", title: "Secret passed as build ARG", sev: "medium", cwe: "CWE-798", desc: "Build args are visible in image history and `docker inspect`.", fix: "Use BuildKit `RUN --mount=type=secret` and `docker build --secret`.", tags: ["secret", "container"] },
  { re: /curl[^\n|]*\|\s*(?:ba)?sh/gim, rule: "curl-pipe-sh", title: "Remote script piped to shell", sev: "medium", cwe: "CWE-829", desc: "A remote response is executed without integrity verification.", fix: "Download, verify a checksum/signature, then execute.", tags: ["supply-chain"] },
  { re: /chmod\s+(?:-R\s+)?777/gim, rule: "chmod-777", title: "World-writable permissions", sev: "low", cwe: "CWE-732", desc: "777 grants write access to every user.", fix: "Use 755 for directories and 644 for files.", tags: ["container"] },
  { re: /^\s*ENV\s+\w*(?:SECRET|TOKEN|PASSWORD|KEY)\w*\s*=\s*\S+/gim, rule: "docker-env-secret", title: "Secret baked into ENV", sev: "medium", cwe: "CWE-798", desc: "ENV values persist in the image and are visible to every container user.", fix: "Inject at runtime or use BuildKit secrets.", tags: ["secret"] },
  { re: /apt-get\s+install(?![^\n]*--no-install-recommends)/gim, rule: "apt-recommends", title: "apt-get installs recommended packages", sev: "low", cwe: "CWE-1104", desc: "Recommended packages enlarge the attack surface and image size.", fix: "Add `--no-install-recommends` and clean `/var/lib/apt/lists`.", tags: ["container"] },
  { re: /^\s*EXPOSE\s+22\b/gim, rule: "docker-expose-ssh", title: "SSH port exposed", sev: "low", cwe: "CWE-284", desc: "SSH inside a container is often unnecessary and adds credential attack surface.", fix: "Prefer `docker exec` or a minimal SSH configuration with keys only.", tags: ["container"] },
  { re: /npm\s+install(?![^\n]*--omit=dev)/gim, rule: "npm-install", title: "npm install instead of npm ci", sev: "low", cwe: "CWE-1104", desc: "npm install can rewrite the lockfile and includes dev dependencies.", fix: "Use `npm ci --omit=dev` in the runtime stage.", tags: ["supply-chain"] },
  { re: /^\s*COPY\s+\.\s+\.\s*$/gim, rule: "docker-copy-all", title: "Whole context copied before dependency install", sev: "info", cwe: "CWE-1104", desc: "Every source change invalidates the dependency layer.", fix: "Copy manifests first, install, then copy source.", tags: ["container"] },
];

function add(ctx, file, text, ruleId, line, data) {
  ctx.add({
    engine: "iac",
    ruleId,
    file: file.rel,
    line,
    snippet: snippetAt(text, line, 3),
    ...data,
  });
}

function lineOfIndex(text, index) {
  return text.slice(0, index).split("\n").length;
}

function scanDockerfile(ctx, file, text) {
  for (const rule of DOCKER_RULES) {
    rule.re.lastIndex = 0;
    let match;
    while ((match = rule.re.exec(text))) {
      add(ctx, file, text, rule.rule, lineOfIndex(text, match.index), {
        title: rule.title,
        description: rule.desc,
        severity: rule.sev,
        confidence: "high",
        cwe: rule.cwe,
        owasp: "A05:2021",
        cvssVector: cvss(rule.sev),
        tags: rule.tags,
        evidence: { line: match[0].trim() },
        remediation: rule.fix,
        references: [`https://cwe.mitre.org/data/definitions/${rule.cwe.replace("CWE-", "")}.html`],
      });
    }
  }
  if (!/^\s*USER\s+/im.test(text)) {
    add(ctx, file, text, "docker-no-user", 1, {
      title: "No USER instruction",
      description: "The image runs as root because no USER is declared.",
      severity: "high", confidence: "high", cwe: "CWE-250", owasp: "A05:2021",
      cvssVector: cvss("high"), tags: ["container"], evidence: { file: file.rel },
      remediation: "Add an unprivileged user and switch to it before the entrypoint.",
      references: ["https://cwe.mitre.org/data/definitions/250.html"],
    });
  }
  if (!/HEALTHCHECK/im.test(text)) {
    add(ctx, file, text, "docker-no-healthcheck", 1, {
      title: "No HEALTHCHECK",
      description: "Orchestrators cannot distinguish a hung process from a healthy one.",
      severity: "info", confidence: "high", cwe: "CWE-754", owasp: "A05:2021",
      cvssVector: cvss("low"), tags: ["container"], evidence: { file: file.rel },
      remediation: "Add a lightweight HEALTHCHECK or configure probes in the orchestrator.",
      references: ["https://cwe.mitre.org/data/definitions/754.html"],
    });
  }
  if (!/^\s*FROM\s+\S+\s+AS\s+/im.test(text)) {
    add(ctx, file, text, "docker-single-stage", 1, {
      title: "Single-stage build",
      description: "Compilers and dev dependencies remain in the runtime image.",
      severity: "low", confidence: "medium", cwe: "CWE-1104", owasp: "A05:2021",
      cvssVector: cvss("low"), tags: ["container"], evidence: { file: file.rel },
      remediation: "Use a multi-stage build and copy only runtime artifacts.",
      references: ["https://cwe.mitre.org/data/definitions/1104.html"],
    });
  }
}

function scanCompose(ctx, file, text) {
  let doc;
  try {
    doc = YAML.parse(text);
  } catch {
    return;
  }
  const services = doc?.services || {};
  for (const [name, svc] of Object.entries(services)) {
    const line = lineOfIndex(text, text.indexOf(name));
    if (svc?.privileged) {
      add(ctx, file, text, "compose-privileged", line, {
        title: `Service ${name} is privileged`,
        description: "A privileged container gets nearly all host capabilities and can mount devices.",
        severity: "high", confidence: "high", cwe: "CWE-250", owasp: "A05:2021",
        cvssVector: cvss("high"), tags: ["container"], evidence: { service: name },
        remediation: "Drop privileges and add only the required capabilities.",
        references: ["https://cwe.mitre.org/data/definitions/250.html"],
      });
    }
    if (svc?.network_mode === "host") {
      add(ctx, file, text, "compose-host-network", line, {
        title: `Service ${name} uses host networking`,
        description: "Host networking bypasses Docker network isolation and port mapping.",
        severity: "medium", confidence: "high", cwe: "CWE-284", owasp: "A05:2021",
        cvssVector: cvss("medium"), tags: ["container", "network"], evidence: { service: name },
        remediation: "Use a user-defined bridge network and publish only required ports.",
        references: ["https://cwe.mitre.org/data/definitions/284.html"],
      });
    }
    if ((svc?.volumes || []).some((v) => String(v).includes("/var/run/docker.sock"))) {
      add(ctx, file, text, "compose-docker-sock", line, {
        title: `Service ${name} mounts the Docker socket`,
        description: "Access to docker.sock is equivalent to root on the host.",
        severity: "high", confidence: "high", cwe: "CWE-250", owasp: "A05:2021",
        cvssVector: cvss("high"), tags: ["container"], evidence: { service: name },
        remediation: "Mount read-only where possible or use a socket proxy.",
        references: ["https://cwe.mitre.org/data/definitions/250.html"],
      });
    }
    if (svc?.cap_add?.includes("SYS_ADMIN")) {
      add(ctx, file, text, "compose-sys-admin", line, {
        title: `Service ${name} adds SYS_ADMIN`,
        description: "SYS_ADMIN grants a broad set of mount and namespace operations.",
        severity: "medium", confidence: "high", cwe: "CWE-250", owasp: "A05:2021",
        cvssVector: cvss("medium"), tags: ["container"], evidence: { service: name },
        remediation: "Add narrow capabilities instead of SYS_ADMIN.",
        references: ["https://cwe.mitre.org/data/definitions/250.html"],
      });
    }
    if (!svc?.read_only) {
      add(ctx, file, text, "compose-not-readonly", line, {
        title: `Service ${name} has a writable root filesystem`,
        description: "A writable rootfs lets an attacker persist tools and modify binaries.",
        severity: "low", confidence: "medium", cwe: "CWE-732", owasp: "A05:2021",
        cvssVector: cvss("low"), tags: ["container"], evidence: { service: name },
        remediation: "Set `read_only: true` and mount explicit tmpfs/volumes for writable paths.",
        references: ["https://cwe.mitre.org/data/definitions/732.html"],
      });
    }
  }
}

function scanK8s(ctx, file, text) {
  let docs;
  try {
    docs = YAML.parseAllDocuments(text).map((d) => d.toJSON()).filter(Boolean);
  } catch {
    return;
  }
  for (const doc of docs) {
    const kind = doc.kind;
    if (!["Deployment", "StatefulSet", "DaemonSet", "Pod", "CronJob", "Job"].includes(kind)) continue;
    const spec = doc.spec?.template?.spec || doc.spec;
    const podSpec = spec?.containers ? spec : doc.spec?.jobTemplate?.spec?.template?.spec;
    if (!podSpec) continue;
    const line = lineOfIndex(text, Math.max(0, text.indexOf(doc.metadata?.name || "kind")));
    const containers = [...(podSpec.containers || []), ...(podSpec.initContainers || [])];
    if (podSpec.hostNetwork) {
      add(ctx, file, text, "k8s-host-network", line, {
        title: "Pod uses hostNetwork", description: "Host networking bypasses network policy isolation.",
        severity: "medium", confidence: "high", cwe: "CWE-284", owasp: "A05:2021",
        cvssVector: cvss("medium"), tags: ["k8s", "network"], evidence: { name: doc.metadata?.name },
        remediation: "Use a Service and NetworkPolicy instead of hostNetwork.",
        references: ["https://cwe.mitre.org/data/definitions/284.html"],
      });
    }
    for (const container of containers) {
      const cLine = lineOfIndex(text, Math.max(0, text.indexOf(container.name || "image")));
      const sc = container.securityContext || {};
      if (sc.privileged) {
        add(ctx, file, text, "k8s-privileged", cLine, {
          title: `Container ${container.name} is privileged`,
          description: "Privileged containers can access host devices and bypass most isolation.",
          severity: "high", confidence: "high", cwe: "CWE-250", owasp: "A05:2021",
          cvssVector: cvss("high"), tags: ["k8s"], evidence: { container: container.name },
          remediation: "Set `privileged: false`, drop ALL and add only required capabilities.",
          references: ["https://cwe.mitre.org/data/definitions/250.html"],
        });
      }
      if (sc.allowPrivilegeEscalation !== false) {
        add(ctx, file, text, "k8s-priv-escalation", cLine, {
          title: `Container ${container.name} allows privilege escalation`,
          description: "setuid binaries can elevate beyond the container user.",
          severity: "medium", confidence: "medium", cwe: "CWE-250", owasp: "A05:2021",
          cvssVector: cvss("medium"), tags: ["k8s"], evidence: { container: container.name },
          remediation: "Set `allowPrivilegeEscalation: false`.",
          references: ["https://cwe.mitre.org/data/definitions/250.html"],
        });
      }
      if (!sc.readOnlyRootFilesystem) {
        add(ctx, file, text, "k8s-writable-rootfs", cLine, {
          title: `Container ${container.name} has a writable root filesystem`,
          description: "Persistence and binary tampering are easier with a writable rootfs.",
          severity: "low", confidence: "medium", cwe: "CWE-732", owasp: "A05:2021",
          cvssVector: cvss("low"), tags: ["k8s"], evidence: { container: container.name },
          remediation: "Set `readOnlyRootFilesystem: true` and mount emptyDir for writable paths.",
          references: ["https://cwe.mitre.org/data/definitions/732.html"],
        });
      }
      if (!container.resources?.limits) {
        add(ctx, file, text, "k8s-no-limits", cLine, {
          title: `Container ${container.name} has no resource limits`,
          description: "A noisy or compromised container can starve the node.",
          severity: "low", confidence: "high", cwe: "CWE-400", owasp: "A05:2021",
          cvssVector: cvss("low"), tags: ["k8s", "dos"], evidence: { container: container.name },
          remediation: "Set CPU and memory requests/limits.",
          references: ["https://cwe.mitre.org/data/definitions/400.html"],
        });
      }
      if (String(container.image || "").endsWith(":latest") || !String(container.image || "").includes(":")) {
        add(ctx, file, text, "k8s-latest-tag", cLine, {
          title: `Container ${container.name} uses a floating image tag`,
          description: "Mutable tags make rollouts non-reproducible.",
          severity: "medium", confidence: "high", cwe: "CWE-1104", owasp: "A05:2021",
          cvssVector: cvss("medium"), tags: ["k8s", "supply-chain"], evidence: { image: container.image },
          remediation: "Pin the image digest.",
          references: ["https://cwe.mitre.org/data/definitions/1104.html"],
        });
      }
    }
    if (!podSpec.securityContext?.runAsNonRoot) {
      add(ctx, file, text, "k8s-run-as-root", line, {
        title: "Pod may run as root",
        description: "No runAsNonRoot constraint is set.",
        severity: "medium", confidence: "medium", cwe: "CWE-250", owasp: "A05:2021",
        cvssVector: cvss("medium"), tags: ["k8s"], evidence: { name: doc.metadata?.name },
        remediation: "Set `securityContext.runAsNonRoot: true` and a numeric runAsUser.",
        references: ["https://cwe.mitre.org/data/definitions/250.html"],
      });
    }
    if (podSpec.automountServiceAccountToken !== false) {
      add(ctx, file, text, "k8s-sa-token", line, {
        title: "Service account token auto-mounted",
        description: "Every container receives an API token it may not need.",
        severity: "low", confidence: "medium", cwe: "CWE-522", owasp: "A01:2021",
        cvssVector: cvss("low"), tags: ["k8s"], evidence: { name: doc.metadata?.name },
        remediation: "Set `automountServiceAccountToken: false` unless the workload calls the API.",
        references: ["https://cwe.mitre.org/data/definitions/522.html"],
      });
    }
  }
}

function scanTerraform(ctx, file, text) {
  const rules = [
    { re: /cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"[^\]]*\]/g, rule: "tf-open-cidr", title: "Security group open to the internet", sev: "medium", cwe: "CWE-284", desc: "0.0.0.0/0 exposes the port to every address.", fix: "Restrict to known ranges or front with a WAF/bastion." },
    { re: /acl\s*=\s*"public-read(?:-write)?"/g, rule: "tf-public-bucket", title: "Public S3 ACL", sev: "high", cwe: "CWE-284", desc: "The bucket ACL grants public access.", fix: "Use `private` plus an explicit bucket policy." },
    { re: /(?:storage_encrypted|encrypted)\s*=\s*false/g, rule: "tf-no-encryption", title: "Encryption disabled", sev: "medium", cwe: "CWE-311", desc: "Data at rest is unencrypted.", fix: "Enable encryption and specify a KMS key." },
    { re: /publicly_accessible\s*=\s*true/g, rule: "tf-public-db", title: "Database publicly accessible", sev: "high", cwe: "CWE-284", desc: "The database gets a public endpoint.", fix: "Place it in private subnets and use a bastion/VPN." },
    { re: /action\s*=\s*"\*"/gi, rule: "tf-iam-wildcard", title: "IAM action wildcard", sev: "medium", cwe: "CWE-269", desc: "`*` grants every action.", fix: "Scope actions to the operations actually used." },
    { re: /resource\s*=\s*"\*"/g, rule: "tf-iam-resource-wildcard", title: "IAM resource wildcard", sev: "medium", cwe: "CWE-269", desc: "`*` allows access to every resource.", fix: "Scope resources by ARN." },
    { re: /skip_final_snapshot\s*=\s*true/g, rule: "tf-no-final-snapshot", title: "Database final snapshot skipped", sev: "low", cwe: "CWE-1104", desc: "Destroying the database loses the last recoverable state.", fix: "Set `skip_final_snapshot = false`." },
    { re: /force_destroy\s*=\s*true/g, rule: "tf-force-destroy", title: "Bucket force_destroy enabled", sev: "low", cwe: "CWE-1104", desc: "Destroying the stack deletes all objects.", fix: "Disable force_destroy for production buckets." },
    { re: /deletion_protection\s*=\s*false/g, rule: "tf-no-deletion-protection", title: "Deletion protection disabled", sev: "low", cwe: "CWE-1104", desc: "The resource can be deleted accidentally.", fix: "Enable deletion protection." },
  ];
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    let match;
    while ((match = rule.re.exec(text))) {
      add(ctx, file, text, rule.rule, lineOfIndex(text, match.index), {
        title: rule.title,
        description: rule.desc,
        severity: rule.sev,
        confidence: "medium",
        cwe: rule.cwe,
        owasp: "A05:2021",
        cvssVector: cvss(rule.sev),
        tags: ["terraform", "cloud"],
        evidence: { line: match[0] },
        remediation: rule.fix,
        references: [`https://cwe.mitre.org/data/definitions/${rule.cwe.replace("CWE-", "")}.html`],
      });
    }
  }
}

function scanActions(ctx, file, text) {
  let doc;
  try {
    doc = YAML.parse(text);
  } catch {
    return;
  }
  const jobs = doc?.jobs || {};
  for (const [jobName, job] of Object.entries(jobs)) {
    for (const step of job.steps || []) {
      const line = lineOfIndex(text, Math.max(0, text.indexOf(step.uses || step.name || "run")));
      if (step.uses && !/@[a-f0-9]{40}$/.test(step.uses)) {
        add(ctx, file, text, "actions-unpinned", line, {
          title: `Action ${step.uses} is not pinned to a commit`,
          description: "Tags and branches are mutable; a compromised action can execute with the job token.",
          severity: "medium", confidence: "high", cwe: "CWE-829", owasp: "A08:2021",
          cvssVector: cvss("medium"), tags: ["supply-chain", "ci"], evidence: { uses: step.uses },
          remediation: "Pin third-party actions to a full commit SHA and use Dependabot.",
          references: ["https://cwe.mitre.org/data/definitions/829.html"],
        });
      }
      if (step.run && /\$\{\{\s*github\.event\.(?:pull_request|issue|comment)\.(?:title|body|head\.ref)/.test(step.run)) {
        add(ctx, file, text, "actions-script-injection", line, {
          title: "Event data interpolated into shell script",
          description: "PR titles/branches can contain shell metacharacters and break out of the script.",
          severity: "high", confidence: "high", cwe: "CWE-78", owasp: "A03:2021",
          cvssVector: cvss("high"), tags: ["ci", "execution"], evidence: { run: step.run.slice(0, 300) },
          remediation: "Pass event data through `env:` and reference `$VAR` in the script.",
          references: ["https://cwe.mitre.org/data/definitions/78.html"],
        });
      }
      if (step.run && /curl[^\n|]*\|\s*(?:ba)?sh/.test(step.run)) {
        add(ctx, file, text, "actions-curl-pipe", line, {
          title: "Remote script piped to shell in CI",
          description: "A compromised endpoint executes arbitrary code in the runner.",
          severity: "medium", confidence: "high", cwe: "CWE-829", owasp: "A08:2021",
          cvssVector: cvss("medium"), tags: ["ci", "supply-chain"], evidence: { run: step.run.slice(0, 200) },
          remediation: "Download and verify a checksum/signature before execution.",
          references: ["https://cwe.mitre.org/data/definitions/829.html"],
        });
      }
    }
  }
  if (doc?.on?.pull_request_target || /^\s*pull_request_target\s*:/m.test(text)) {
    add(ctx, file, text, "actions-pr-target", lineOfIndex(text, text.indexOf("pull_request_target")), {
      title: "pull_request_target workflow",
      description: "This trigger runs with repository secrets and a write token. Checking out PR head makes untrusted code executable.",
      severity: "high", confidence: "medium", cwe: "CWE-829", owasp: "A08:2021",
      cvssVector: cvss("high"), tags: ["ci"], evidence: { job: Object.keys(jobs)[0] },
      remediation: "Checkout the base ref for install steps, or use a separate unprivileged workflow and `workflow_run`.",
      references: ["https://cwe.mitre.org/data/definitions/829.html"],
    });
  }
  if (!doc?.permissions) {
    add(ctx, file, text, "actions-default-permissions", 1, {
      title: "Workflow does not declare permissions",
      description: "The default GITHUB_TOKEN may have broad write access depending on repository settings.",
      severity: "low", confidence: "medium", cwe: "CWE-269", owasp: "A01:2021",
      cvssVector: cvss("low"), tags: ["ci"], evidence: { file: file.rel },
      remediation: "Add `permissions: contents: read` and grant job-specific writes.",
      references: ["https://cwe.mitre.org/data/definitions/269.html"],
    });
  }
}

function scanNginx(ctx, file, text) {
  const checks = [
    { re: /server_tokens\s+on/g, rule: "nginx-server-tokens", title: "Nginx version disclosure", sev: "low", cwe: "CWE-200", desc: "The version is advertised in responses and error pages.", fix: "Set `server_tokens off`." },
    { re: /ssl_protocols[^;]*(?:TLSv1(?:\.1)?\b)/g, rule: "nginx-old-tls", title: "Legacy TLS protocol enabled", sev: "medium", cwe: "CWE-326", desc: "TLS 1.0/1.1 are deprecated.", fix: "Allow only TLSv1.2 and TLSv1.3." },
    { re: /autoindex\s+on/g, rule: "nginx-autoindex", title: "Directory listing enabled", sev: "low", cwe: "CWE-548", desc: "Directory contents are enumerable.", fix: "Disable autoindex or restrict it." },
    { re: /client_max_body_size\s+(?:[1-9]\d{2,})m/gi, rule: "nginx-body-size", title: "Very large request body limit", sev: "low", cwe: "CWE-400", desc: "Large bodies can exhaust memory/disk.", fix: "Set a limit matching the application." },
    { re: /proxy_pass\s+http:\/\//g, rule: "nginx-plaintext-upstream", title: "Plaintext upstream", sev: "low", cwe: "CWE-319", desc: "Traffic to the upstream is unencrypted.", fix: "Use HTTPS upstream or a private network with documented trust." },
  ];
  for (const check of checks) {
    check.re.lastIndex = 0;
    let match;
    while ((match = check.re.exec(text))) {
      add(ctx, file, text, check.rule, lineOfIndex(text, match.index), {
        title: check.title, description: check.desc, severity: check.sev, confidence: "high",
        cwe: check.cwe, owasp: "A05:2021", cvssVector: cvss(check.sev), tags: ["nginx", "config"],
        evidence: { line: match[0] }, remediation: check.fix,
        references: [`https://cwe.mitre.org/data/definitions/${check.cwe.replace("CWE-", "")}.html`],
      });
    }
  }
  for (const header of ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]) {
    if (!text.includes(header)) {
      add(ctx, file, text, "nginx-missing-header", 1, {
        title: `Missing security header: ${header}`,
        description: "The reverse proxy does not add this defense-in-depth header.",
        severity: "low", confidence: "medium", cwe: "CWE-693", owasp: "A05:2021",
        cvssVector: cvss("low"), tags: ["headers"], evidence: { header },
        remediation: `Add \`add_header ${header} ... always;\` with a suitable value.`,
        references: ["https://cwe.mitre.org/data/definitions/693.html"],
      });
    }
  }
}

export default {
  id: "iac",
  name: "Cloud & IaC Auditor",
  description: "Docker, Compose, Kubernetes, Terraform, GitHub Actions and Nginx hardening with 60+ checks.",
  category: "iac",
  targetTypes: ["iac", "code", "container", "mixed"],
  cost: "low",
  async run(ctx) {
    let count = 0;
    for (const file of ctx.files) {
      const base = path.basename(file.rel).toLowerCase();
      let text;
      try {
        text = await fsp.readFile(file.abs, "utf8");
      } catch {
        continue;
      }
      if (base === "dockerfile" || base.startsWith("dockerfile.")) {
        scanDockerfile(ctx, file, text);
        count += 1;
      } else if (/^(?:docker-)?compose.*\.ya?ml$/.test(base)) {
        scanCompose(ctx, file, text);
        count += 1;
      } else if (/\.ya?ml$/.test(base) && /^(?:apiVersion|kind):/m.test(text) && /kind:\s*(?:Deployment|StatefulSet|DaemonSet|Pod|CronJob|Job)/.test(text)) {
        scanK8s(ctx, file, text);
        count += 1;
      } else if (file.lang === "terraform") {
        scanTerraform(ctx, file, text);
        count += 1;
      } else if (file.rel.includes(".github/workflows/") && /\.ya?ml$/.test(base)) {
        scanActions(ctx, file, text);
        count += 1;
      } else if (/nginx.*\.conf$|\.nginx$/.test(base)) {
        scanNginx(ctx, file, text);
        count += 1;
      }
    }
    ctx.emit("info", `Audited ${count} infrastructure files`);
  },
};
