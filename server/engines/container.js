import fsp from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

function cvss(sev) {
  return {
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev];
}

export default {
  id: "container",
  name: "Container Inspector",
  description: "Docker image configuration, history and runtime hardening inspection.",
  category: "container",
  targetTypes: ["container", "mixed"],
  cost: "medium",
  async run(ctx) {
    const image = ctx.scan.target_type === "container" ? ctx.scan.target : ctx.config.image;
    if (!image) {
      ctx.emit("info", "No container image configured");
      return;
    }
    let inspect;
    try {
      const { stdout } = await exec("docker", ["image", "inspect", image], { timeout: 30_000, maxBuffer: 8 * 1024 * 1024 });
      inspect = JSON.parse(stdout)[0];
    } catch (err) {
      ctx.emit("warn", `docker image inspect failed for ${image}: ${err.message.slice(0, 200)}`);
      return;
    }
    const config = inspect.Config || {};
    const add = (raw) => ctx.add({ engine: "container", assetKind: "image", assetValue: image, ...raw });
    ctx.addAsset("image", image, { id: inspect.Id, created: inspect.Created });
    if (!config.User || config.User === "root" || config.User === "0") {
      add({
        ruleId: "image-root-user",
        title: "Image runs as root",
        description: "No unprivileged USER is configured.",
        severity: "high", confidence: "high", cwe: "CWE-250", owasp: "A05:2021",
        cvssVector: cvss("high"), tags: ["container"], evidence: { user: config.User || "root" },
        remediation: "Set a numeric non-root USER in the Dockerfile.",
        references: ["https://cwe.mitre.org/data/definitions/250.html"],
      });
    }
    for (const env of config.Env || []) {
      if (/(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)=/i.test(env)) {
        add({
          ruleId: "image-env-secret",
          title: "Secret baked into image environment",
          description: `Environment variable ${env.split("=")[0]} is stored in image metadata.`,
          severity: "medium", confidence: "high", cwe: "CWE-798", owasp: "A02:2021",
          cvssVector: cvss("medium"), tags: ["secret", "container"], evidence: { variable: env.split("=")[0] },
          remediation: "Inject at runtime through the orchestrator's secret store.",
          references: ["https://cwe.mitre.org/data/definitions/798.html"],
        });
      }
    }
    if (!config.Healthcheck) {
      add({
        ruleId: "image-no-healthcheck",
        title: "Image has no HEALTHCHECK",
        description: "Hung processes look healthy to the orchestrator.",
        severity: "info", confidence: "high", cwe: "CWE-754", owasp: "A05:2021",
        cvssVector: cvss("low"), tags: ["container"], evidence: { image },
        remediation: "Add a HEALTHCHECK or configure probes.",
        references: ["https://cwe.mitre.org/data/definitions/754.html"],
      });
    }
    if (Array.isArray(config.Entrypoint) && config.Entrypoint[0] === "/bin/sh" && config.Entrypoint[1] === "-c") {
      add({
        ruleId: "image-shell-entrypoint",
        title: "Shell-form entrypoint",
        description: "The entrypoint runs through a shell, so PID 1 is the shell and signals may not propagate.",
        severity: "low", confidence: "high", cwe: "CWE-754", owasp: "A05:2021",
        cvssVector: cvss("low"), tags: ["container"], evidence: { entrypoint: config.Entrypoint },
        remediation: "Use exec-form JSON arrays.",
        references: ["https://cwe.mitre.org/data/definitions/754.html"],
      });
    }
    try {
      const { stdout } = await exec("docker", ["history", "--no-trunc", "--format", "{{.CreatedBy}}", image], {
        timeout: 30_000,
        maxBuffer: 8 * 1024 * 1024,
      });
      const lines = stdout.split(/\r?\n/).filter(Boolean);
      for (const line of lines) {
        const m = line.match(/(?:PASSWORD|SECRET|TOKEN|API_KEY)=([^\s]+)/i);
        if (m && !m[1].startsWith("$")) {
          add({
            ruleId: "image-history-secret",
            title: "Secret visible in image history",
            description: "A build instruction contains a literal credential. It remains in the layer history.",
            severity: "high", confidence: "medium", cwe: "CWE-798", owasp: "A02:2021",
            cvssVector: cvss("high"), tags: ["secret", "container"], evidence: { instruction: line.slice(0, 400) },
            remediation: "Rebuild with BuildKit secrets and rotate the value.",
            references: ["https://cwe.mitre.org/data/definitions/798.html"],
          });
        }
      }
    } catch {
      /* history optional */
    }
    ctx.emit("info", `Inspected image ${image} (${(inspect.RepoTags || []).join(", ") || "untagged"})`);
  },
};
