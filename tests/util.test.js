import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { cvssFromVector, entropy, fingerprint, normalizeSeverity, redactSecret, safeJoin } from "../server/lib/util.js";

test("CVSS 3.1 base score", () => {
  assert.equal(cvssFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvssFromVector("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"), 2.6);
  assert.equal(cvssFromVector("bad"), null);
});

test("entropy distinguishes random from repeated", () => {
  assert.ok(entropy("aB3$xZ9!qW2@") > entropy("aaaaaaaaaaaa"));
});

test("fingerprints are stable and line-sensitive", () => {
  const a = fingerprint("sast", "rule", "a.js", 10, "x");
  const b = fingerprint("sast", "rule", "a.js", 10, "x");
  const c = fingerprint("sast", "rule", "a.js", 11, "x");
  assert.equal(a, b);
  assert.notEqual(a, c);
});

test("severity normalization and redaction", () => {
  assert.equal(normalizeSeverity("HIGH"), "high");
  assert.equal(normalizeSeverity("weird"), "medium");
  const redacted = redactSecret("AKIA" + "IOSFODNN7EXAMPLE");
  assert.ok(redacted.startsWith("AKIA"));
  assert.ok(!redacted.includes("IOSFODNN7"));
});

test("safeJoin blocks traversal", () => {
  const root = path.resolve("tmp-root");
  assert.ok(safeJoin(root, "src/index.js").endsWith("index.js"));
  assert.throws(() => safeJoin(root, path.join("..", "..", "etc", "passwd")));
  if (process.platform === "win32") assert.throws(() => safeJoin(root, "..\\..\\etc\\passwd"));
});
