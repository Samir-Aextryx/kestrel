import test from "node:test";
import assert from "node:assert/strict";
import { createRateLimiter } from "../server/lib/ratelimit.js";

test("fixed window allows up to max and resets after the window", () => {
  let clock = 1_000;
  const limiter = createRateLimiter({ windowMs: 1_000, max: 3, now: () => clock });

  assert.equal(limiter.hit("a").allowed, true);
  assert.equal(limiter.hit("a").allowed, true);
  assert.equal(limiter.hit("a").allowed, true);
  const blocked = limiter.hit("a");
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.remaining, 0);
  assert.ok(blocked.retryAfterMs > 0);

  clock += 1_000;
  assert.equal(limiter.hit("a").allowed, true);
});

test("keys have independent budgets", () => {
  const limiter = createRateLimiter({ windowMs: 60_000, max: 1 });
  assert.equal(limiter.hit("a").allowed, true);
  assert.equal(limiter.hit("a").allowed, false);
  assert.equal(limiter.hit("b").allowed, true);
});

test("evicted and expired buckets are forgotten", () => {
  let clock = 0;
  const limiter = createRateLimiter({ windowMs: 1_000, max: 1, maxKeys: 2, now: () => clock });
  limiter.hit("a");
  limiter.hit("b");
  limiter.hit("c"); // evicts the oldest bucket ("a")
  assert.equal(limiter.size, 2);
  assert.equal(limiter.hit("a").allowed, true);

  clock += 1_000;
  assert.equal(limiter.sweep(), 0);
});

test("reset clears a single key", () => {
  const limiter = createRateLimiter({ windowMs: 60_000, max: 1 });
  limiter.hit("a");
  assert.equal(limiter.hit("a").allowed, false);
  limiter.reset("a");
  assert.equal(limiter.hit("a").allowed, true);
});
