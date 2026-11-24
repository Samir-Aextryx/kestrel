import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const dataDir = await mkdtemp(path.join(os.tmpdir(), "kestrel-crypto-"));
process.env.KESTREL_DATA_DIR = dataDir;

const { encryptSecret, decryptSecret, hashPassword, verifyPassword, timingSafeEqual } = await import(
  "../server/crypto.js"
);

test.after(() => rm(dataDir, { recursive: true, force: true }));

test("secrets round-trip through AES-256-GCM", () => {
  const plain = "sk-test-ümlaut-🚀-0123456789";
  const blob = encryptSecret(plain);
  assert.match(blob, /^v1\./);
  assert.equal(decryptSecret(blob), plain);
  assert.equal(encryptSecret(""), "");
  assert.equal(decryptSecret(""), "");
});

test("tampered ciphertext fails closed", () => {
  const blob = encryptSecret("sensitive");
  const [version, iv, tag, data] = blob.split(".");
  const flipped = `${version}.${iv}.${tag.slice(0, -2)}AA.${data}`;
  assert.equal(decryptSecret(flipped), "");

  const corruptedData = `${version}.${iv}.${tag}.${data.slice(0, -2)}AA`;
  assert.equal(decryptSecret(corruptedData), "");
});

test("password hashes verify only the right password", () => {
  const stored = hashPassword("correct horse battery staple");
  assert.equal(verifyPassword("correct horse battery staple", stored), true);
  assert.equal(verifyPassword("wrong", stored), false);
  assert.equal(verifyPassword("whatever", "not-a-hash"), false);
});

test("timingSafeEqual handles length mismatches", () => {
  assert.equal(timingSafeEqual("abc", "abc"), true);
  assert.equal(timingSafeEqual("abc", "abcd"), false);
  assert.equal(timingSafeEqual("", "a"), false);
});
