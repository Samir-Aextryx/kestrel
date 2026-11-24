import tls from "node:tls";
import net from "node:net";

function cvss(sev) {
  return {
    high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev];
}

function probe(host, port, servername) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: net.isIP(host) ? undefined : servername || host,
        rejectUnauthorized: false,
        timeout: 12_000,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        const result = {
          protocol: socket.getProtocol(),
          cipher: socket.getCipher(),
          authorized: socket.authorized,
          authorizationError: socket.authorizationError,
          cert,
        };
        socket.end();
        resolve(result);
      },
    );
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("TLS timeout"));
    });
    socket.on("error", reject);
  });
}

export default {
  id: "tls",
  name: "TLS Inspector",
  description: "Certificate chain, expiry, SAN, key strength, protocol and cipher analysis.",
  category: "tls",
  targetTypes: ["web", "mixed"],
  dynamic: true,
  cost: "low",
  async run(ctx) {
    const target = ctx.webUrl;
    if (!target) return;
    const url = new URL(target);
    if (url.protocol !== "https:") {
      ctx.emit("info", "Target is HTTP; TLS inspection skipped");
      return;
    }
    const host = url.hostname;
    const port = Number(url.port || 443);
    let result;
    try {
      const resolved = await ctx.scope.resolve(url.toString());
      result = await probe(resolved.ip, port, host);
    } catch (err) {
      ctx.emit("warn", `TLS probe failed: ${err.message}`);
      return;
    }
    const cert = result.cert || {};
    const add = (raw) => ctx.add({ engine: "tls", assetKind: "domain", assetValue: host, ...raw });
    ctx.addAsset("tls", `${host}:${port}`, { protocol: result.protocol });

    if (!result.authorized) {
      add({
        ruleId: "tls-untrusted",
        title: "TLS certificate is not trusted",
        description: `Chain validation failed: ${result.authorizationError || "unknown"}.`,
        severity: "high", confidence: "high", cwe: "CWE-295", owasp: "A02:2021",
        cvssVector: cvss("high"), tags: ["tls"],
        evidence: { error: result.authorizationError, issuer: cert.issuer, subject: cert.subject },
        remediation: "Serve the full chain with a publicly trusted certificate.",
        references: ["https://cwe.mitre.org/data/definitions/295.html"],
      });
    }
    if (result.protocol === "TLSv1" || result.protocol === "TLSv1.1") {
      add({
        ruleId: "tls-old-protocol",
        title: `Legacy protocol ${result.protocol}`,
        description: "TLS 1.0/1.1 are deprecated and lack modern primitives.",
        severity: "medium", confidence: "high", cwe: "CWE-326", owasp: "A02:2021",
        cvssVector: cvss("medium"), tags: ["tls"], evidence: { protocol: result.protocol },
        remediation: "Allow only TLS 1.2 and 1.3.",
        references: ["https://cwe.mitre.org/data/definitions/326.html"],
      });
    }
    const cipher = result.cipher || {};
    if (/RC4|3DES|DES|NULL|EXPORT|MD5/i.test(cipher.name || "")) {
      add({
        ruleId: "tls-weak-cipher",
        title: `Weak cipher ${cipher.name}`,
        description: "The negotiated cipher is considered weak.",
        severity: "medium", confidence: "high", cwe: "CWE-327", owasp: "A02:2021",
        cvssVector: cvss("medium"), tags: ["tls"], evidence: { cipher },
        remediation: "Prefer AEAD suites (AES-GCM/ChaCha20-Poly1305).",
        references: ["https://cwe.mitre.org/data/definitions/327.html"],
      });
    }
    const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
    if (validTo) {
      const days = Math.round((validTo.getTime() - Date.now()) / 86_400_000);
      if (days < 0) {
        add({
          ruleId: "tls-expired",
          title: "TLS certificate expired",
          description: `Certificate expired ${Math.abs(days)} days ago.`,
          severity: "critical", confidence: "high", cwe: "CWE-298", owasp: "A02:2021",
          cvssVector: cvss("high"), tags: ["tls"], evidence: { validTo: cert.valid_to },
          remediation: "Renew and automate certificate rotation.",
          references: ["https://cwe.mitre.org/data/definitions/298.html"],
        });
      } else if (days < 21) {
        add({
          ruleId: "tls-expiring",
          title: "TLS certificate expires soon",
          description: `Only ${days} days remain.`,
          severity: "medium", confidence: "high", cwe: "CWE-298", owasp: "A02:2021",
          cvssVector: cvss("medium"), tags: ["tls"], evidence: { validTo: cert.valid_to },
          remediation: "Renew now and automate rotation.",
          references: ["https://cwe.mitre.org/data/definitions/298.html"],
        });
      }
    }
    const san = cert.subjectaltname || "";
    if (san && !san.split(", ").some((entry) => entry.replace(/^DNS:/, "") === host)) {
      add({
        ruleId: "tls-san-mismatch",
        title: "Certificate SAN does not match host",
        description: `The certificate covers ${san.slice(0, 300)}.`,
        severity: "high", confidence: "high", cwe: "CWE-297", owasp: "A02:2021",
        cvssVector: cvss("high"), tags: ["tls"], evidence: { san, host },
        remediation: "Reissue the certificate with the correct DNS names.",
        references: ["https://cwe.mitre.org/data/definitions/297.html"],
      });
    }
    if (cert.pubkey?.type === "RSA" && Number(cert.pubkey.size) < 2048) {
      add({
        ruleId: "tls-weak-key",
        title: `Weak RSA key (${cert.pubkey.size} bit)`,
        description: "RSA keys below 2048 bits are no longer sufficient.",
        severity: "high", confidence: "high", cwe: "CWE-326", owasp: "A02:2021",
        cvssVector: cvss("high"), tags: ["tls"], evidence: { key: cert.pubkey },
        remediation: "Use RSA-2048+ or ECDSA P-256+.",
        references: ["https://cwe.mitre.org/data/definitions/326.html"],
      });
    }
    ctx.emit("info", `TLS ${result.protocol} / ${cipher.name || "unknown"} for ${host}`);
  },
};
