import dns from "node:dns/promises";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import { performance } from "node:perf_hooks";
import { sha256 } from "./crypto.js";

const PRIVATE_V4 = [
  ["10.0.0.0", 8],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["100.64.0.0", 10],
  ["0.0.0.0", 8],
  ["192.0.0.0", 24],
  ["198.18.0.0", 15],
  ["240.0.0.0", 4],
];

function ipv4ToInt(ip) {
  return ip.split(".").reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

function inCidr4(ip, cidr) {
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw ?? 32);
  if (!net.isIPv4(ip) || !net.isIPv4(base) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

function expandV6(ip) {
  if (!net.isIPv6(ip)) return null;
  let value = ip.toLowerCase().split("%")[0];
  if (value.includes(".")) {
    const last = value.split(":").pop();
    const parts = last.split(".").map(Number);
    value = value.slice(0, value.lastIndexOf(":")) + ":" +
      ((parts[0] << 8) | parts[1]).toString(16) + ":" + ((parts[2] << 8) | parts[3]).toString(16);
  }
  const halves = value.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const fill = 8 - left.length - right.length;
  if (fill < 0) return null;
  const groups = [...left, ...Array(fill).fill("0"), ...right];
  if (groups.length !== 8) return null;
  return groups.reduce((acc, group) => (acc << 16n) + BigInt(parseInt(group || "0", 16)), 0n);
}

function inCidr6(ip, cidr) {
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw ?? 128);
  const a = expandV6(ip);
  const b = expandV6(base);
  if (a === null || b === null || bits < 0 || bits > 128) return false;
  if (bits === 0) return true;
  const shift = BigInt(128 - bits);
  return (a >> shift) === (b >> shift);
}

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    return PRIVATE_V4.some(([base, bits]) => inCidr4(ip, `${base}/${bits}`));
  }
  if (net.isIPv6(ip)) {
    const value = expandV6(ip);
    if (value === null) return true;
    if (value === 0n || value === 1n) return true;
    if ((value >> 118n) === 0x3ffn) return true; // fe80::/10
    if ((value >> 121n) === 0x7en) return true; // fc00::/7
    if (value >> 120n === 0xffn) return true; // multicast
    if (value >> 32n === 0xffffn) {
      const v4 = `${Number((value >> 24n) & 255n)}.${Number((value >> 16n) & 255n)}.${Number((value >> 8n) & 255n)}.${Number(value & 255n)}`;
      return isPrivateIp(v4);
    }
    return false;
  }
  return true;
}

function hostMatches(host, rule) {
  const h = host.toLowerCase().replace(/\.$/, "");
  let r = String(rule).toLowerCase().trim().replace(/\.$/, "");
  if (!r) return false;
  if (r.startsWith("*.")) r = r.slice(2);
  if (r.startsWith(".")) r = r.slice(1);
  return h === r || h.endsWith(`.${r}`);
}

export class ScopeError extends Error {
  constructor(message, code = "scope") {
    super(message);
    this.code = code;
  }
}

export class ScopeGate {
  constructor(scope = {}, options = {}) {
    this.allow = Array.isArray(scope.allow) ? scope.allow : [];
    this.deny = Array.isArray(scope.deny) ? scope.deny : [];
    this.ports = Array.isArray(scope.ports) && scope.ports.length ? scope.ports.map(Number) : [80, 443];
    this.schemes = Array.isArray(scope.schemes) && scope.schemes.length ? scope.schemes : ["http", "https"];
    this.allowPrivate = Boolean(scope.allowPrivate);
    this.maxRequests = Number(scope.maxRequests || 500);
    this.ratePerSec = Number(scope.ratePerSec || 8);
    this.maxBytes = Number(scope.maxBytes || 2 * 1024 * 1024);
    this.requests = 0;
    this.hostLast = new Map();
    this.evidence = [];
    this.signal = options.signal;
    this.userAgent = options.userAgent || "Kestrel/1.0 (authorized security research)";
  }

  checkHost(host, ip) {
    if (this.deny.some((rule) => hostMatches(host, rule.value ?? rule))) {
      throw new ScopeError(`host ${host} is denied by scope`);
    }
    if (this.allow.length) {
      const ok = this.allow.some((rule) => {
        const type = rule.type || "domain";
        const value = rule.value ?? rule;
        if (type === "cidr") return inCidr4(ip, value) || inCidr6(ip, value);
        if (type === "ip") return ip === value;
        if (type === "url") {
          try {
            return hostMatches(host, new URL(value).hostname);
          } catch {
            return false;
          }
        }
        return hostMatches(host, value);
      });
      if (!ok) throw new ScopeError(`host ${host} (${ip}) is outside the allow-list`);
    }
    if (!this.allowPrivate && isPrivateIp(ip)) {
      throw new ScopeError(`ip ${ip} is private and allowPrivate is disabled`);
    }
  }

  async resolve(url) {
    const parsed = new URL(url);
    if (!this.schemes.includes(parsed.protocol.replace(":", ""))) {
      throw new ScopeError(`scheme ${parsed.protocol} is not allowed`);
    }
    const port = Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80));
    if (!this.ports.includes(port)) throw new ScopeError(`port ${port} is not allowed`);
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    let ips;
    if (net.isIP(host)) {
      ips = [host];
    } else {
      try {
        const records = await dns.lookup(host, { all: true, verbatim: true });
        ips = [...new Set(records.map((r) => r.address))];
      } catch (err) {
        throw new ScopeError(`DNS resolution failed for ${host}: ${err.code || err.message}`, "dns");
      }
    }
    if (!ips.length) throw new ScopeError(`no addresses for ${host}`, "dns");
    for (const ip of ips) this.checkHost(host, ip);
    return { parsed, host, port, ip: ips[0], ips };
  }

  async throttle(host) {
    const minGap = 1000 / Math.max(1, this.ratePerSec);
    const last = this.hostLast.get(host) || 0;
    const wait = Math.max(0, last + minGap - Date.now());
    if (wait) await new Promise((r) => setTimeout(r, wait));
    this.hostLast.set(host, Date.now());
  }

  async fetch(url, options = {}) {
    if (this.requests >= this.maxRequests) {
      throw new ScopeError(`request budget exhausted (${this.maxRequests})`, "budget");
    }
    const { parsed, host, port, ip } = await this.resolve(url);
    await this.throttle(host);
    this.requests += 1;
    const started = performance.now();
    const body = options.body ? Buffer.from(options.body) : null;
    const headers = {
      "user-agent": this.userAgent,
      accept: options.accept || "*/*",
      ...(options.headers || {}),
      host: parsed.host,
    };
    if (body) headers["content-length"] = String(body.length);
    const transport = parsed.protocol === "https:" ? https : http;
    const result = await new Promise((resolve, reject) => {
      const req = transport.request(
        {
          protocol: parsed.protocol,
          hostname: host,
          port,
          path: `${parsed.pathname}${parsed.search}`,
          method: options.method || "GET",
          headers,
          servername: net.isIP(host) ? undefined : host,
          lookup: (_h, _o, cb) => cb(null, ip, net.isIP(ip) === 6 ? 6 : 4),
          timeout: options.timeout || 15_000,
          rejectUnauthorized: options.rejectUnauthorized !== false,
        },
        (res) => {
          const chunks = [];
          let size = 0;
          res.on("data", (chunk) => {
            size += chunk.length;
            if (size <= this.maxBytes) chunks.push(chunk);
            else res.destroy();
          });
          res.on("end", () => {
            const buf = Buffer.concat(chunks);
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: buf,
              text: buf.toString("utf8"),
              truncated: size > this.maxBytes,
              elapsedMs: Math.round(performance.now() - started),
              ip,
              url,
            });
          });
        },
      );
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", reject);
      if (body) req.write(body);
      req.end();
    });
    this.evidence.push({
      request: {
        method: options.method || "GET",
        url,
        headers,
        body: body ? body.toString("utf8").slice(0, 16_384) : null,
      },
      response: {
        status: result.status,
        headers: result.headers,
        body: result.text.slice(0, 32_768),
        truncated: result.truncated,
      },
      sha256: sha256(`${url}\n${result.status}\n${result.text}`),
      elapsedMs: result.elapsedMs,
      at: new Date().toISOString(),
    });
    if (this.evidence.length > 60) this.evidence.shift();
    return result;
  }

  async fetchFollow(url, options = {}) {
    let current = url;
    for (let i = 0; i < 6; i += 1) {
      const res = await this.fetch(current, { ...options, method: options.method || "GET" });
      if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) {
        current = new URL(res.headers.location, current).toString();
        if (res.status === 303) options.method = "GET";
        continue;
      }
      return res;
    }
    throw new ScopeError("too many redirects", "redirect");
  }
}

export function normalizeScope(input = {}) {
  const allow = [];
  for (const raw of input.allow || []) {
    if (!raw) continue;
    if (typeof raw === "string") {
      if (raw.includes("/") && net.isIP(raw.split("/")[0])) allow.push({ type: "cidr", value: raw });
      else if (net.isIP(raw)) allow.push({ type: "ip", value: raw });
      else if (/^https?:\/\//.test(raw)) allow.push({ type: "url", value: raw });
      else allow.push({ type: "domain", value: raw.replace(/^\*\./, "") });
    } else if (raw.value) {
      allow.push({ type: raw.type || "domain", value: String(raw.value) });
    }
  }
  const deny = (input.deny || []).filter(Boolean).map((v) =>
    typeof v === "string" ? { type: "domain", value: v } : { type: v.type || "domain", value: String(v.value) },
  );
  return {
    allow,
    deny,
    ports: (input.ports || [80, 443]).map(Number).filter((p) => p > 0 && p < 65536),
    schemes: (input.schemes || ["http", "https"]).filter((s) => ["http", "https"].includes(s)),
    allowPrivate: Boolean(input.allowPrivate),
    maxRequests: Math.min(20_000, Math.max(1, Number(input.maxRequests ?? 500))),
    ratePerSec: Math.min(100, Math.max(1, Number(input.ratePerSec ?? 8))),
    maxBytes: Math.min(10 * 1024 * 1024, Math.max(1024, Number(input.maxBytes ?? 2 * 1024 * 1024))),
  };
}
