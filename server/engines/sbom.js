import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

function parsePackageJson(text) {
  try {
    const doc = JSON.parse(text);
    return Object.entries({ ...(doc.dependencies || {}), ...(doc.devDependencies || {}) }).map(([name, version]) => ({
      name,
      version: String(version).replace(/^[\^~>=< ]+/, ""),
      scope: doc.devDependencies?.[name] ? "optional" : "required",
    }));
  } catch {
    return [];
  }
}

function parseRequirements(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.match(/^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)/))
    .filter(Boolean)
    .map((m) => ({ name: m[1], version: m[2], scope: "required" }));
}

function parseGoMod(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.match(/^\s*([a-zA-Z0-9./_-]+)\s+v([0-9][^\s]*)/))
    .filter(Boolean)
    .map((m) => ({ name: m[1], version: m[2], scope: "required" }));
}

export default {
  id: "sbom",
  name: "SBOM Generator",
  description: "CycloneDX 1.6 software bill of materials with hashes and dependency scope.",
  category: "supply",
  targetTypes: ["code", "mixed", "container"],
  cost: "low",
  async run(ctx) {
    const components = [];
    const seen = new Set();
    for (const file of ctx.files) {
      const base = path.basename(file.rel).toLowerCase();
      let text;
      try {
        text = await fsp.readFile(file.abs, "utf8");
      } catch {
        continue;
      }
      let parsed = [];
      let type = "library";
      let ecosystem = "";
      if (base === "package.json") {
        parsed = parsePackageJson(text);
        ecosystem = "npm";
      } else if (base === "requirements.txt") {
        parsed = parseRequirements(text);
        ecosystem = "pypi";
      } else if (base === "go.mod") {
        parsed = parseGoMod(text);
        ecosystem = "golang";
      }
      for (const dep of parsed) {
        const key = `${ecosystem}:${dep.name}@${dep.version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        components.push({
          type,
          name: dep.name,
          version: dep.version,
          scope: dep.scope,
          purl: `pkg:${ecosystem}/${dep.name}@${dep.version}`,
          properties: [{ name: "kestrel:manifest", value: file.rel }],
        });
      }
    }
    if (!components.length) {
      ctx.emit("info", "No dependency manifests for SBOM");
      return;
    }
    const bom = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ vendor: "KESTREL", name: "kestrel-sbom", version: "1.0.0" }],
        component: {
          type: "application",
          name: ctx.project?.name || "scan-target",
          version: "0.0.0",
        },
      },
      components,
    };
    const json = JSON.stringify(bom, null, 2);
    const artifact = await ctx.writeArtifact("sbom.cdx.json", json);
    ctx.addAsset("artifact", artifact.rel, { kind: "sbom", components: components.length, sha256: artifact.sha256 });
    ctx.add({
      engine: "sbom",
      ruleId: "sbom-generated",
      title: `SBOM generated (${components.length} components)`,
      description: "A CycloneDX 1.6 SBOM was generated and hashed for downstream consumption.",
      severity: "info",
      confidence: "high",
      cwe: "CWE-1059",
      owasp: "A06:2021",
      tags: ["sbom", "supply-chain"],
      evidence: { artifact: artifact.rel, sha256: artifact.sha256, components: components.length },
      remediation: "Archive the SBOM with the release and diff it between versions.",
      references: ["https://cyclonedx.org/specification/overview/"],
    });
    ctx.emit("info", `SBOM written: ${artifact.rel}`);
  },
};
