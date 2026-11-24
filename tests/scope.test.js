import test from "node:test";
import assert from "node:assert/strict";
import { ScopeGate, ScopeError, isPrivateIp, normalizeScope } from "../server/scope.js";

test("private ranges are recognized", () => {
  assert.equal(isPrivateIp("127.0.0.1"), true);
  assert.equal(isPrivateIp("10.2.3.4"), true);
  assert.equal(isPrivateIp("172.20.1.1"), true);
  assert.equal(isPrivateIp("192.168.1.1"), true);
  assert.equal(isPrivateIp("169.254.169.254"), true);
  assert.equal(isPrivateIp("8.8.8.8"), false);
  assert.equal(isPrivateIp("::1"), true);
  assert.equal(isPrivateIp("fd00::1"), true);
  assert.equal(isPrivateIp("2606:4700::1111"), false);
});

test("allow-list matches subdomains but not siblings", () => {
  const gate = new ScopeGate({ allow: [{ type: "domain", value: "example.com" }], allowPrivate: true });
  assert.doesNotThrow(() => gate.checkHost("example.com", "1.1.1.1"));
  assert.doesNotThrow(() => gate.checkHost("api.example.com", "1.1.1.1"));
  assert.throws(() => gate.checkHost("example.org", "1.1.1.1"), ScopeError);
  assert.throws(() => gate.checkHost("badexample.com", "1.1.1.1"), ScopeError);
});

test("deny wins over allow", () => {
  const gate = new ScopeGate({
    allow: [{ type: "domain", value: "example.com" }],
    deny: [{ type: "domain", value: "admin.example.com" }],
    allowPrivate: true,
  });
  assert.throws(() => gate.checkHost("admin.example.com", "1.1.1.1"), ScopeError);
});

test("private addresses require explicit permission", () => {
  const gate = new ScopeGate({ allow: [{ type: "cidr", value: "10.0.0.0/8" }] });
  assert.throws(() => gate.checkHost("internal", "10.1.2.3"), ScopeError);
  const allowed = new ScopeGate({ allow: [{ type: "cidr", value: "10.0.0.0/8" }], allowPrivate: true });
  assert.doesNotThrow(() => allowed.checkHost("internal", "10.1.2.3"));
  assert.doesNotThrow(() => allowed.checkHost("internal", "10.2.3.4"));
  assert.throws(() => allowed.checkHost("other", "192.168.1.1"), ScopeError);
});

test("normalizeScope clamps budgets and normalizes entries", () => {
  const scope = normalizeScope({ allow: ["example.com", "10.0.0.0/8"], maxRequests: 999999, ratePerSec: 0 });
  assert.equal(scope.allow.length, 2);
  assert.equal(scope.allow[0].type, "domain");
  assert.equal(scope.allow[1].type, "cidr");
  assert.equal(scope.maxRequests, 20000);
  assert.equal(scope.ratePerSec, 1);
});
