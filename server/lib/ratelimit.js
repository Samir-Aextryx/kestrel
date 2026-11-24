// Fixed-window rate limiter with bounded memory.
//
// Buckets are pruned when they expire, and the key space is capped so a flood
// of unique keys (spoofed IPs, random emails) cannot grow the map without
// bound. When the cap is reached the oldest live bucket is evicted; this trades
// a small amount of accuracy under extreme load for predictable memory use.

export function createRateLimiter({ windowMs, max, maxKeys = 10_000, now = Date.now } = {}) {
  if (!Number.isFinite(windowMs) || windowMs <= 0) throw new Error("windowMs must be positive");
  if (!Number.isFinite(max) || max <= 0) throw new Error("max must be positive");
  const buckets = new Map();

  function prune(t) {
    for (const [key, bucket] of buckets) {
      if (t >= bucket.reset) buckets.delete(key);
    }
  }

  function evictOldest() {
    const oldest = buckets.keys().next();
    if (!oldest.done) buckets.delete(oldest.value);
  }

  function hit(key) {
    const t = now();
    if (buckets.size >= maxKeys) prune(t);
    while (buckets.size >= maxKeys) evictOldest();

    let bucket = buckets.get(key);
    if (!bucket || t >= bucket.reset) {
      bucket = { count: 0, reset: t + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    return {
      allowed: bucket.count <= max,
      count: bucket.count,
      remaining: Math.max(0, max - bucket.count),
      reset: bucket.reset,
      retryAfterMs: Math.max(0, bucket.reset - t),
    };
  }

  function reset(key) {
    buckets.delete(key);
  }

  function sweep() {
    prune(now());
    return buckets.size;
  }

  function middleware(keyFn = (req) => req.ip || "unknown") {
    return (req, res, next) => {
      const result = hit(keyFn(req));
      res.setHeader("X-RateLimit-Limit", String(max));
      res.setHeader("X-RateLimit-Remaining", String(result.remaining));
      res.setHeader("X-RateLimit-Reset", String(Math.ceil(result.reset / 1000)));
      if (!result.allowed) {
        res.setHeader("Retry-After", String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))));
        return res.status(429).json({ error: "rate limit exceeded" });
      }
      next();
    };
  }

  return {
    hit,
    reset,
    sweep,
    middleware,
    get size() {
      return buckets.size;
    },
  };
}
