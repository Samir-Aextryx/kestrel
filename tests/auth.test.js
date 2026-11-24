import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const dataDir = await mkdtemp(path.join(os.tmpdir(), "kestrel-auth-"));
process.env.KESTREL_DATA_DIR = dataDir;
process.env.KESTREL_LOGIN_ACCOUNT_MAX = "3";
process.env.KESTREL_LOGIN_IP_MAX = "8";

const { parseCookies, requireCsrf, loginRateLimit, resetLoginAttempts, login } = await import(
  "../server/auth.js"
);
const { db } = await import("../server/db.js");

test.after(async () => {
  db.close();
  try {
    await rm(dataDir, { recursive: true, force: true });
  } catch {
    // open handles can keep the temp directory busy on Windows; harmless
  }
});

function makeReq(overrides = {}) {
  return {
    ip: "10.0.0.1",
    body: {},
    headers: {},
    auth: { via: "cookie", csrf: "csrf-token" },
    ...overrides,
  };
}

function makeRes() {
  return {
    statusCode: 200,
    headers: {},
    body: null,
    setHeader(key, value) {
      this.headers[key.toLowerCase()] = value;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

function run(middleware, req) {
  const res = makeRes();
  let called = false;
  middleware(req, res, () => {
    called = true;
  });
  return { res, called };
}

test("parseCookies decodes values and ignores malformed pairs", () => {
  const req = { headers: { cookie: "a=1; b=hello%20world; broken; c=" } };
  assert.deepEqual(parseCookies(req), { a: "1", b: "hello world", c: "" });
});

test("csrf accepts a matching header and rejects missing or wrong tokens", () => {
  assert.equal(run(requireCsrf, makeReq({ headers: { "x-csrf-token": "csrf-token" } })).called, true);

  const missing = run(requireCsrf, makeReq());
  assert.equal(missing.called, false);
  assert.equal(missing.res.statusCode, 403);

  const wrong = run(requireCsrf, makeReq({ headers: { "x-csrf-token": "nope" } }));
  assert.equal(wrong.called, false);
  assert.equal(wrong.res.statusCode, 403);
});

test("csrf is not required for bearer and agent tokens", () => {
  assert.equal(run(requireCsrf, makeReq({ auth: { via: "token", scopes: ["write"] } })).called, true);
  assert.equal(run(requireCsrf, makeReq({ auth: { via: "agent", scopes: ["write"] } })).called, true);
});

test("login throttling is per account and per IP", () => {
  const email = "victim@example.com";
  for (let i = 0; i < 3; i += 1) {
    assert.equal(run(loginRateLimit, makeReq({ ip: "10.1.0.1", body: { email } })).called, true);
  }
  const blocked = run(loginRateLimit, makeReq({ ip: "10.1.0.1", body: { email } }));
  assert.equal(blocked.called, false);
  assert.equal(blocked.res.statusCode, 429);
  assert.ok(blocked.res.headers["retry-after"]);

  // A different account from the same IP still has budget left.
  assert.equal(
    run(loginRateLimit, makeReq({ ip: "10.1.0.1", body: { email: "other@example.com" } })).called,
    true,
  );

  // A different IP does not inherit the account budget.
  assert.equal(run(loginRateLimit, makeReq({ ip: "10.1.0.2", body: { email } })).called, true);
});

test("per-IP budget blocks spraying across many accounts", () => {
  const ip = "10.2.0.1";
  for (let i = 0; i < 8; i += 1) {
    assert.equal(
      run(loginRateLimit, makeReq({ ip, body: { email: `user${i}@example.com` } })).called,
      true,
    );
  }
  const blocked = run(loginRateLimit, makeReq({ ip, body: { email: "user8@example.com" } }));
  assert.equal(blocked.called, false);
  assert.equal(blocked.res.statusCode, 429);
});

test("successful login resets the account budget", () => {
  const ip = "10.3.0.1";
  const body = { email: "reset@example.com" };
  for (let i = 0; i < 3; i += 1) {
    run(loginRateLimit, makeReq({ ip, body }));
  }
  resetLoginAttempts(makeReq({ ip, body }));
  for (let i = 0; i < 3; i += 1) {
    assert.equal(run(loginRateLimit, makeReq({ ip, body })).called, true);
  }
});

test("login rejects oversized credentials without touching the database", () => {
  const res = makeRes();
  login(makeReq({ body: { email: `${"a".repeat(400)}@example.com`, password: "x" } }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, "invalid credentials");
});
