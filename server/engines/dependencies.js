import fsp from "node:fs/promises";
import path from "node:path";
import semver from "semver";
import { snippetAt } from "../lib/util.js";

const ECOSYSTEMS = {
  npm: "npm",
  PyPI: "PyPI",
  Go: "Go",
  Maven: "Maven",
  RubyGems: "RubyGems",
  Packagist: "Packagist",
  "crates.io": "crates.io",
};

const LOCAL_DB = [
  { eco: "npm", name: "lodash", below: "4.17.21", cve: "CVE-2021-23337", sev: "high", cvss: 7.4, cwe: "CWE-1321", title: "Prototype pollution in lodash", fixed: "4.17.21" },
  { eco: "npm", name: "minimist", below: "1.2.6", cve: "CVE-2021-44906", sev: "critical", cvss: 9.8, cwe: "CWE-1321", title: "Prototype pollution in minimist", fixed: "1.2.6" },
  { eco: "npm", name: "axios", below: "1.6.0", cve: "CVE-2023-45857", sev: "medium", cvss: 6.5, cwe: "CWE-352", title: "XSRF token leakage in axios", fixed: "1.6.0" },
  { eco: "npm", name: "express", below: "4.19.2", cve: "CVE-2024-29041", sev: "medium", cvss: 6.1, cwe: "CWE-601", title: "Open redirect in Express", fixed: "4.19.2" },
  { eco: "npm", name: "jsonwebtoken", below: "9.0.0", cve: "CVE-2022-23529", sev: "high", cvss: 7.6, cwe: "CWE-502", title: "Insecure key handling in jsonwebtoken", fixed: "9.0.0" },
  { eco: "npm", name: "node-fetch", below: "2.6.7", cve: "CVE-2022-0235", sev: "high", cvss: 6.1, cwe: "CWE-200", title: "Cookie leakage on redirect in node-fetch", fixed: "2.6.7" },
  { eco: "npm", name: "semver", below: "7.5.2", cve: "CVE-2022-25883", sev: "high", cvss: 7.5, cwe: "CWE-1333", title: "ReDoS in semver", fixed: "7.5.2" },
  { eco: "npm", name: "qs", below: "6.11.1", cve: "CVE-2022-24999", sev: "high", cvss: 7.5, cwe: "CWE-1321", title: "Prototype pollution in qs", fixed: "6.11.1" },
  { eco: "npm", name: "ejs", below: "3.1.10", cve: "CVE-2024-33883", sev: "high", cvss: 7.5, cwe: "CWE-1321", title: "Prototype pollution in ejs", fixed: "3.1.10" },
  { eco: "npm", name: "handlebars", below: "4.7.7", cve: "CVE-2021-23369", sev: "critical", cvss: 9.8, cwe: "CWE-1321", title: "Remote code execution in handlebars", fixed: "4.7.7" },
  { eco: "npm", name: "next", below: "14.2.5", cve: "CVE-2024-34351", sev: "high", cvss: 7.5, cwe: "CWE-918", title: "SSRF in Next.js server actions", fixed: "14.2.5" },
  { eco: "npm", name: "jquery", below: "3.5.0", cve: "CVE-2020-11022", sev: "medium", cvss: 6.1, cwe: "CWE-79", title: "XSS in jQuery htmlPrefilter", fixed: "3.5.0" },
  { eco: "PyPI", name: "pyyaml", below: "5.4", cve: "CVE-2020-14343", sev: "critical", cvss: 9.8, cwe: "CWE-502", title: "Arbitrary code execution in PyYAML", fixed: "5.4" },
  { eco: "PyPI", name: "requests", below: "2.31.0", cve: "CVE-2023-32681", sev: "medium", cvss: 6.1, cwe: "CWE-200", title: "Proxy-Authorization header leak in requests", fixed: "2.31.0" },
  { eco: "PyPI", name: "django", below: "4.2.14", cve: "CVE-2024-38875", sev: "medium", cvss: 5.3, cwe: "CWE-400", title: "Denial of service in Django", fixed: "4.2.14" },
  { eco: "PyPI", name: "jinja2", below: "3.1.4", cve: "CVE-2024-34064", sev: "medium", cvss: 5.4, cwe: "CWE-79", title: "XSS in Jinja2 xmlattr filter", fixed: "3.1.4" },
  { eco: "PyPI", name: "cryptography", below: "41.0.6", cve: "CVE-2023-49083", sev: "medium", cvss: 5.9, cwe: "CWE-476", title: "NULL dereference in cryptography", fixed: "41.0.6" },
  { eco: "PyPI", name: "pillow", below: "10.3.0", cve: "CVE-2024-28219", sev: "high", cvss: 7.8, cwe: "CWE-787", title: "Buffer overflow in Pillow", fixed: "10.3.0" },
  { eco: "PyPI", name: "numpy", below: "1.22.0", cve: "CVE-2021-41496", sev: "high", cvss: 7.5, cwe: "CWE-787", title: "Buffer overflow in NumPy", fixed: "1.22.0" },
  { eco: "Go", name: "golang.org/x/text", below: "0.3.8", cve: "CVE-2022-32149", sev: "high", cvss: 7.5, cwe: "CWE-400", title: "Panic on invalid language tag", fixed: "0.3.8" },
  { eco: "Go", name: "golang.org/x/net", below: "0.17.0", cve: "CVE-2023-44487", sev: "high", cvss: 7.5, cwe: "CWE-400", title: "HTTP/2 rapid reset DoS", fixed: "0.17.0" },
  { eco: "Maven", name: "org.springframework:spring-core", below: "5.3.26", cve: "CVE-2022-22965", sev: "critical", cvss: 9.8, cwe: "CWE-94", title: "Spring4Shell RCE", fixed: "5.3.26" },
  { eco: "Maven", name: "org.apache.logging.log4j:log4j-core", below: "2.17.1", cve: "CVE-2021-44832", sev: "high", cvss: 8.8, cwe: "CWE-502", title: "Log4Shell follow-up RCE", fixed: "2.17.1" },
  { eco: "Maven", name: "com.fasterxml.jackson.core:jackson-databind", below: "2.13.4.2", cve: "CVE-2022-42004", sev: "high", cvss: 7.5, cwe: "CWE-502", title: "Deserialization gadget in jackson-databind", fixed: "2.13.4.2" },
  { eco: "Maven", name: "org.apache.commons:commons-text", below: "1.10.0", cve: "CVE-2022-42889", sev: "critical", cvss: 9.8, cwe: "CWE-94", title: "Text4Shell RCE", fixed: "1.10.0" },
  { eco: "RubyGems", name: "rack", below: "2.2.6.4", cve: "CVE-2023-27539", sev: "medium", cvss: 5.3, cwe: "CWE-400", title: "ReDoS in Rack", fixed: "2.2.6.4" },
  { eco: "RubyGems", name: "nokogiri", below: "1.13.10", cve: "CVE-2022-24836", sev: "high", cvss: 7.5, cwe: "CWE-1333", title: "ReDoS in Nokogiri", fixed: "1.13.10" },
  { eco: "Packagist", name: "guzzlehttp/guzzle", below: "7.4.5", cve: "CVE-2022-31090", sev: "medium", cvss: 6.5, cwe: "CWE-200", title: "Authorization header leak in Guzzle", fixed: "7.4.5" },
  { eco: "Packagist", name: "laravel/framework", below: "9.32.0", cve: "CVE-2022-40482", sev: "medium", cvss: 5.3, cwe: "CWE-200", title: "Information disclosure in Laravel", fixed: "9.32.0" },
  { eco: "crates.io", name: "time", below: "0.3.36", cve: "CVE-2020-26235", sev: "medium", cvss: 5.3, cwe: "CWE-400", title: "Segfault in time crate", fixed: "0.3.36" },
];

const MANIFESTS = new Set([
  "package.json", "package-lock.json", "npm-shrinkwrap.json", "requirements.txt", "pyproject.toml",
  "poetry.lock", "Pipfile.lock", "go.mod", "go.sum", "pom.xml", "Gemfile", "Gemfile.lock",
  "composer.json", "composer.lock", "Cargo.toml", "Cargo.lock",
]);

function cvss(sev) {
  return {
    critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev] || "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N";
}

function parseManifest(rel, text) {
  const base = path.basename(rel).toLowerCase();
  const deps = [];
  const push = (name, version, eco, line, dev = false) => {
    if (!name || !version) return;
    const clean = String(version).replace(/^[\^~>=< ]+/, "").split(" ")[0].replace(/[",']/g, "");
    if (!clean || clean === "*" || clean === "latest" || clean.includes("${")) return;
    deps.push({ name: String(name).toLowerCase(), version: clean, eco, line, dev });
  };
  if (base === "package.json" || base === "composer.json") {
    let doc;
    try {
      doc = JSON.parse(text);
    } catch {
      return deps;
    }
    for (const key of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
      for (const [name, version] of Object.entries(doc[key] || {})) {
        const line = text.split("\n").findIndex((l) => l.includes(`"${name}"`)) + 1;
        push(name, version, base === "package.json" ? "npm" : "Packagist", line, key !== "dependencies");
      }
    }
  } else if (base === "package-lock.json" || base === "npm-shrinkwrap.json" || base === "composer.lock") {
    let doc;
    try {
      doc = JSON.parse(text);
    } catch {
      return deps;
    }
    if (doc.packages) {
      for (const [p, meta] of Object.entries(doc.packages)) {
        if (!p.startsWith("node_modules/") || !meta.version) continue;
        push(p.replace(/^node_modules\//, ""), meta.version, "npm", 0, Boolean(meta.dev));
      }
    }
    for (const pkg of doc.packages || []) {
      if (pkg.name && pkg.version) push(pkg.name, pkg.version, "Packagist", 0);
    }
  } else if (base === "requirements.txt") {
    text.split("\n").forEach((line, idx) => {
      const m = line.match(/^\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|~=)\s*([A-Za-z0-9_.+-]+)/);
      if (m) push(m[1], m[2], "PyPI", idx + 1);
    });
  } else if (base === "pyproject.toml" || base === "poetry.lock" || base === "Pipfile.lock") {
    const re = /^\s*["']?([A-Za-z0-9_.-]+)["']?\s*(?:==|>=|~=)\s*["']?([A-Za-z0-9_.+-]+)/gm;
    let m;
    while ((m = re.exec(text))) push(m[1], m[2], "PyPI", text.slice(0, m.index).split("\n").length);
    const lockRe = /name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g;
    while ((m = lockRe.exec(text))) push(m[1], m[2], "PyPI", 0);
  } else if (base === "go.mod") {
    text.split("\n").forEach((line, idx) => {
      const m = line.match(/^\s*([a-zA-Z0-9./_-]+)\s+v([0-9][^\s]*)/);
      if (m) push(m[1], m[2], "Go", idx + 1);
    });
  } else if (base === "pom.xml") {
    const re = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>/g;
    let m;
    while ((m = re.exec(text))) push(`${m[1]}:${m[2]}`, m[3], "Maven", text.slice(0, m.index).split("\n").length);
  } else if (base === "gemfile.lock") {
    const re = /^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)/gm;
    let m;
    while ((m = re.exec(text))) push(m[1], m[2], "RubyGems", text.slice(0, m.index).split("\n").length);
  } else if (base === "cargo.toml" || base === "cargo.lock") {
    const re = /name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g;
    let m;
    while ((m = re.exec(text))) push(m[1], m[2], "crates.io", 0);
  }
  return deps;
}

async function queryOsv(deps) {
  const queries = deps.map((d) => ({
    package: { name: d.name, ecosystem: ECOSYSTEMS[d.eco] },
    version: d.version,
  }));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20_000);
  try {
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      signal: controller.signal,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ queries }),
    });
    if (!res.ok) throw new Error(`OSV ${res.status}`);
    const data = await res.json();
    return (data.results || []).map((result, idx) => ({ dep: deps[idx], vulns: result.vulns || [] }));
  } finally {
    clearTimeout(timer);
  }
}

function osvSeverity(vuln) {
  const sev = vuln.database_specific?.severity?.toUpperCase();
  if (sev === "CRITICAL") return "critical";
  if (sev === "HIGH") return "high";
  if (sev === "MODERATE" || sev === "MEDIUM") return "medium";
  if (sev === "LOW") return "low";
  const vector = (vuln.severity || []).find((s) => s.type === "CVSS_V3")?.score;
  if (vector) {
    const m = vector.match(/\/C:([HML])/);
    if (m?.[1] === "H") return "high";
  }
  return "medium";
}

export default {
  id: "dependencies",
  name: "Supply Chain Analyst",
  description: "Manifest and lockfile inventory with OSV enrichment, local advisory fallback and reachability hints.",
  category: "supply",
  targetTypes: ["code", "mixed"],
  cost: "medium",
  async run(ctx) {
    const deps = [];
    const manifests = [];
    for (const file of ctx.files) {
      if (!MANIFESTS.has(path.basename(file.rel).toLowerCase())) continue;
      const text = await fsp.readFile(file.abs, "utf8");
      manifests.push(file.rel);
      for (const dep of parseManifest(file.rel, text)) deps.push({ ...dep, file: file.rel });
    }
    const unique = new Map();
    for (const dep of deps) {
      const key = `${dep.eco}:${dep.name}@${dep.version}`;
      if (!unique.has(key)) unique.set(key, dep);
    }
    const list = [...unique.values()];
    ctx.emit("info", `Inventoried ${list.length} unique packages from ${manifests.length} manifests`);
    if (!list.length) return;

    let osv = [];
    let osvOk = false;
    try {
      osv = await queryOsv(list);
      osvOk = true;
      ctx.emit("info", `OSV returned advisory data for ${osv.filter((o) => o.vulns.length).length} packages`);
    } catch (err) {
      ctx.emit("warn", `OSV unavailable (${err.message}); using bundled advisory snapshot`);
    }

    const reported = new Set();
    const osvPackages = new Set();
    for (const { dep, vulns } of osv) {
      if (vulns.length) osvPackages.add(`${dep.eco}:${dep.name}`);
      for (const vuln of vulns) {
        const key = `${dep.name}:${vuln.id}`;
        if (reported.has(key)) continue;
        reported.add(key);
        const severity = osvSeverity(vuln);
        const fixed = (vuln.affected || [])
          .flatMap((a) => a.ranges || [])
          .flatMap((r) => r.events || [])
          .find((e) => e.fixed)?.fixed;
        ctx.add({
          engine: "dependencies",
          ruleId: `osv:${vuln.id}`,
          title: `${dep.name} ${dep.version}: ${vuln.summary || vuln.id}`,
          description:
            `The resolved version **${dep.name}@${dep.version}** is affected by **${vuln.id}**. ` +
            `${vuln.details ? vuln.details.slice(0, 1200) : ""}\n\n` +
            `Source: OSV. ${fixed ? `Fixed in ${fixed}.` : "No fixed version is published."}`,
          severity,
          confidence: "high",
          file: dep.file,
          line: dep.line || 1,
          snippet: snippetAt(await fsp.readFile(path.join(ctx.root, dep.file), "utf8"), dep.line || 1, 2),
          cwe: "CWE-1104",
          owasp: "A06:2021",
          cvssVector: cvss(severity),
          tags: ["dependency", "supply-chain", dep.eco.toLowerCase()],
          evidence: { package: dep.name, version: dep.version, advisory: vuln.id, aliases: vuln.aliases || [], fixed },
          remediation: fixed
            ? `Upgrade ${dep.name} to ${fixed} or later, then run the test suite and regenerate the lockfile.`
            : `Track ${vuln.id}; pin a patched fork or apply the vendor patch.`,
          references: [`https://osv.dev/vulnerability/${vuln.id}`, ...(vuln.aliases || []).slice(0, 3).map((a) => `https://nvd.nist.gov/vuln/detail/${a}`)],
        });
      }
    }

    for (const dep of list) {
      for (const advisory of LOCAL_DB) {
        if (advisory.eco !== dep.eco || advisory.name !== dep.name) continue;
        if (osvPackages.has(`${dep.eco}:${dep.name}`)) continue;
        if (reported.has(`${dep.name}:${advisory.cve}`)) continue;
        let vulnerable = false;
        try {
          vulnerable = semver.valid(semver.coerce(dep.version)) ? semver.lt(semver.coerce(dep.version), advisory.below) : false;
        } catch {
          vulnerable = false;
        }
        if (!vulnerable) continue;
        reported.add(`${dep.name}:${advisory.cve}`);
        ctx.add({
          engine: "dependencies",
          ruleId: `local:${advisory.cve}`,
          title: `${dep.name} ${dep.version}: ${advisory.title}`,
          description:
            `The resolved version **${dep.name}@${dep.version}** is below the patched version **${advisory.fixed}**. ` +
            `Known issue: ${advisory.title} (${advisory.cve}).`,
          severity: advisory.sev,
          confidence: "high",
          file: dep.file,
          line: dep.line || 1,
          cwe: advisory.cwe,
          owasp: "A06:2021",
          cvssVector: cvss(advisory.sev),
          tags: ["dependency", "supply-chain", dep.eco.toLowerCase()],
          evidence: { package: dep.name, version: dep.version, advisory: advisory.cve, fixed: advisory.fixed, source: "bundled" },
          remediation: `Upgrade ${dep.name} to ${advisory.fixed} or later.`,
          references: [`https://nvd.nist.gov/vuln/detail/${advisory.cve}`],
        });
      }
    }
    if (!osvOk) ctx.emit("info", "Bundled advisory snapshot used; run again online for full coverage");
  },
};
