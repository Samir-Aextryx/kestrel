import fsp from "node:fs/promises";
import path from "node:path";
import { setting } from "../db.js";

const COPYLEFT = /^(?:A?GPL|LGPL|MPL|EPL|CDDL|OSL|CC-BY-SA)/i;
const PERMISSIVE = /^(?:MIT|ISC|BSD|Apache|Unlicense|CC0|0BSD|WTFPL)/i;

export default {
  id: "licenses",
  name: "License Policy",
  description: "Dependency license inventory against a configurable allow/deny policy.",
  category: "supply",
  targetTypes: ["code", "mixed"],
  cost: "low",
  async run(ctx) {
    const policy = setting("licensePolicy", { deny: ["AGPL-3.0", "GPL-3.0", "SSPL-1.0"], allow: [] });
    const deny = (policy.deny || []).map((v) => v.toLowerCase());
    const allow = (policy.allow || []).map((v) => v.toLowerCase());
    let count = 0;
    for (const file of ctx.files) {
      const base = path.basename(file.rel).toLowerCase();
      if (!["package.json", "composer.json"].includes(base)) continue;
      let doc;
      try {
        doc = JSON.parse(await fsp.readFile(file.abs, "utf8"));
      } catch {
        continue;
      }
      const deps = { ...(doc.dependencies || {}), ...(doc.devDependencies || {}) };
      for (const name of Object.keys(deps)) {
        count += 1;
        let license = "";
        try {
          const pkg = JSON.parse(await fsp.readFile(path.join(ctx.root, "node_modules", name, "package.json"), "utf8"));
          license = typeof pkg.license === "string" ? pkg.license : pkg.license?.type || "";
        } catch {
          continue;
        }
        if (!license) {
          ctx.add({
            engine: "licenses",
            ruleId: "license-unknown",
            title: `Unknown license: ${name}`,
            description: "The installed package declares no license. Redistribution terms are unclear.",
            severity: "low", confidence: "medium", cwe: "CWE-1059", owasp: "A06:2021",
            file: file.rel, line: 1, tags: ["license", "compliance"],
            evidence: { package: name },
            remediation: "Verify the license with the maintainer or replace the package.",
            references: ["https://spdx.org/licenses/"],
          });
          continue;
        }
        const lower = license.toLowerCase();
        const denied = deny.some((d) => lower.includes(d)) && !allow.some((a) => lower.includes(a));
        if (denied) {
          ctx.add({
            engine: "licenses",
            ruleId: "license-denied",
            title: `Denied license ${license}: ${name}`,
            description: "The package license is on the deny list and can impose copyleft obligations on distribution.",
            severity: "medium", confidence: "high", cwe: "CWE-1059", owasp: "A06:2021",
            file: file.rel, line: 1, tags: ["license", "compliance"],
            evidence: { package: name, license },
            remediation: "Replace the package, isolate it behind a service boundary, or approve the license.",
            references: ["https://spdx.org/licenses/"],
          });
        } else if (!PERMISSIVE.test(license) && !COPYLEFT.test(license)) {
          ctx.add({
            engine: "licenses",
            ruleId: "license-review",
            title: `License needs review: ${license} (${name})`,
            description: "The license is neither clearly permissive nor a known copyleft family.",
            severity: "info", confidence: "medium", cwe: "CWE-1059", owasp: "A06:2021",
            file: file.rel, line: 1, tags: ["license", "compliance"],
            evidence: { package: name, license },
            remediation: "Review the terms with legal and record the decision.",
            references: ["https://spdx.org/licenses/"],
          });
        }
      }
    }
    ctx.emit("info", `Checked ${count} installed packages against the license policy`);
  },
};
