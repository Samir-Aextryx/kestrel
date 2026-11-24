import net from "node:net";
import tls from "node:tls";

const COMMON = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 2375, 3000, 3306, 3389, 5432, 5672, 6379, 8000, 8080, 8443, 9000, 9200, 11211, 27017];

const SERVICE = [
  [/ssh-/i, "ssh"], [/smtp/i, "smtp"], [/imap/i, "imap"], [/pop3/i, "pop3"],
  [/redis/i, "redis"], [/memcached/i, "memcached"], [/mysql/i, "mysql"],
  [/postgres/i, "postgres"], [/mongodb|mongo/i, "mongodb"], [/rabbitmq/i, "rabbitmq"],
  [/elastic|opensearch/i, "elasticsearch"], [/docker/i, "docker"], [/http/i, "http"],
  [/ftp/i, "ftp"], [/telnet/i, "telnet"], [/rdp/i, "rdp"], [/smb/i, "smb"],
];

function cvss(sev) {
  return {
    critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev];
}

function connect(host, port, timeout = 1200) {
  return new Promise((resolve) => {
    const secure = [443, 8443, 9443].includes(port);
    const socket = secure
      ? tls.connect({ host, port, rejectUnauthorized: false, timeout })
      : net.connect({ host, port, timeout });
    let data = "";
    const done = (open) => {
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve({ open, banner: data.slice(0, 1200) });
    };
    socket.setTimeout(timeout, () => done(false));
    socket.on("error", () => done(false));
    socket.on("connect", () => {
      const probe = port === 6379 ? "PING\r\n" : port === 11211 ? "stats\r\n" : `HEAD / HTTP/1.0\r\nHost: kestrel\r\n\r\n`;
      socket.write(probe);
      setTimeout(() => done(true), 450);
    });
    socket.on("data", (chunk) => {
      data += chunk.toString("latin1");
    });
  });
}

function serviceOf(banner, port) {
  for (const [re, name] of SERVICE) if (re.test(banner)) return name;
  return { 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 443: "https", 445: "smb", 3306: "mysql", 5432: "postgres", 6379: "redis", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb" }[port] || "unknown";
}

export default {
  id: "network",
  name: "Network & Service Map",
  description: "Scope-pinned TCP connect scan, banner fingerprint and anonymous access checks for common services.",
  category: "network",
  targetTypes: ["web", "mixed"],
  dynamic: true,
  cost: "medium",
  async run(ctx) {
    if (!ctx.webUrl) return;
    const url = new URL(ctx.webUrl);
    let resolved;
    try {
      resolved = await ctx.scope.resolve(url.toString());
    } catch (err) {
      ctx.emit("warn", `Network scan skipped: ${err.message}`);
      return;
    }
    const ports = [...new Set([...ctx.scope.ports, ...COMMON])].filter((p) => p > 0 && p < 65536).slice(0, 40);
    ctx.emit("info", `Probing ${ports.length} TCP ports on ${resolved.ip}`);
    const results = [];
    for (let i = 0; i < ports.length; i += 8) {
      const batch = ports.slice(i, i + 8);
      const probed = await Promise.all(batch.map(async (port) => ({ port, ...(await connect(resolved.ip, port)) })));
      results.push(...probed);
    }
    const open = results.filter((r) => r.open);
    for (const item of open) {
      const service = serviceOf(item.banner, item.port);
      ctx.addAsset("port", `${resolved.host}:${item.port}`, { service });
      ctx.addAsset("service", service, { port: item.port });
      const dangerous = ["redis", "mongodb", "elasticsearch", "memcached", "docker", "telnet", "smb", "rdp"].includes(service);
      ctx.add({
        engine: "network",
        ruleId: `open-${service}`,
        title: `Exposed ${service.toUpperCase()} service on port ${item.port}`,
        description: `TCP port ${item.port} is reachable and fingerprints as ${service}.${dangerous ? " This service class is a common foothold or data-exposure target." : ""}`,
        severity: dangerous ? "medium" : "info",
        confidence: "high",
        cwe: "CWE-284",
        owasp: "A05:2021",
        cvssVector: cvss(dangerous ? "medium" : "low"),
        tags: ["network", "service", service],
        evidence: { host: resolved.host, ip: resolved.ip, port: item.port, banner: item.banner.slice(0, 600) },
        remediation: "Restrict the port to trusted networks or put it behind an authenticated proxy.",
        references: ["https://cwe.mitre.org/data/definitions/284.html"],
        assetValue: `${resolved.host}:${item.port}`,
        assetKind: "port",
      });
      if (service === "redis" && /\+PONG/.test(item.banner)) {
        ctx.add({
          engine: "network",
          ruleId: "redis-anonymous",
          title: "Redis accepts unauthenticated commands",
          description: "Redis answered PING without AUTH. Unauthenticated Redis often allows data theft and sometimes RCE via module loading or cron writes.",
          severity: "high",
          confidence: "high",
          cwe: "CWE-306",
          owasp: "A01:2021",
          cvssVector: cvss("high"),
          tags: ["network", "redis", "anonymous"],
          evidence: { host: resolved.host, port: item.port, response: item.banner.slice(0, 300) },
          remediation: "Enable requirepass, bind to private interfaces and disable dangerous commands.",
          references: ["https://cwe.mitre.org/data/definitions/306.html"],
          assetValue: `${resolved.host}:${item.port}`,
          assetKind: "port",
        });
      }
      if (service === "memcached" && /STAT/.test(item.banner)) {
        ctx.add({
          engine: "network",
          ruleId: "memcached-anonymous",
          title: "Memcached exposes statistics without auth",
          description: "Memcached has no native auth; exposed instances leak keys and can be abused for amplification.",
          severity: "medium",
          confidence: "high",
          cwe: "CWE-306",
          owasp: "A01:2021",
          cvssVector: cvss("medium"),
          tags: ["network", "memcached"],
          evidence: { port: item.port, response: item.banner.slice(0, 300) },
          remediation: "Bind to localhost/private networks and firewall UDP/TCP 11211.",
          references: ["https://cwe.mitre.org/data/definitions/306.html"],
          assetValue: `${resolved.host}:${item.port}`,
          assetKind: "port",
        });
      }
    }
    if (open.some((o) => serviceOf(o.banner, o.port) === "http" && o.port !== 80 && o.port !== 443)) {
      ctx.emit("info", "Alternate HTTP ports found; API/web engines can be pointed at them explicitly");
    }
    ctx.emit("info", `Network map: ${open.length} open ports`);
  },
};
