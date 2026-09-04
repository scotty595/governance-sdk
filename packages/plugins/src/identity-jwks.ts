/**
 * governance-sdk — JWKS resolution for externally issued JWTs
 *
 * Fetches an IdP's JWKS document and caches the keys it can use, bounded by
 * both a key count and a TTL. Split from `identity-jwt-keys.ts` to keep each
 * file under 300 LOC. Zero dependencies: `fetch` and `crypto.subtle` only.
 */

import {
  cacheKeyFor,
  importJwk,
  lookupIn,
  type JsonWebKeySet,
  type JwtHeader,
  type KeyCache,
  type ResolvedVerificationKey,
} from "./identity-jwt-keys.js";

export interface JwksResolverOptions {
  /** The IdP's JWKS endpoint, e.g. `https://login.example.com/.well-known/jwks.json`. */
  jwksUri: string;
  /** Injected `fetch`. Defaults to the global one; required where there is none. */
  fetch?: typeof globalThis.fetch;
  /** How long a fetched key stays usable. Default 300_000 (5 minutes). */
  cacheTtlMs?: number;
  /** Maximum keys cached; the oldest is evicted when full. Default 20. */
  maxKeys?: number;
  /** Minimum gap between unknown-`kid` refetches. Default 30_000. */
  minRefetchIntervalMs?: number;
  /** Unknown-`kid` refetches allowed per {@link refetchWindowMs}. Default 5. */
  maxRefetchesPerWindow?: number;
  /** Rolling window for the refetch budget. Default 600_000 (10 minutes). */
  refetchWindowMs?: number;
  /** Abort a JWKS request after this long. Default 5_000. */
  timeoutMs?: number;
  /** Clock in milliseconds. Default `Date.now`. Override in tests. */
  now?: () => number;
}

export interface JwksResolverStats {
  /** Keys currently cached (may include entries not yet swept). */
  cachedKeys: number;
  /** JWKS requests actually issued. */
  fetches: number;
  /** Unknown-`kid` refetches refused by the rate limiter. */
  throttledRefetches: number;
}

/** A {@link JwtKeyResolver} with cache introspection attached. */
export interface JwksResolver {
  (header: JwtHeader): Promise<ResolvedVerificationKey | undefined>;
  stats(): JwksResolverStats;
  /** Drop every cached key — e.g. after a rotation you already know about. */
  clear(): void;
}

/**
 * Resolve keys from a live JWKS endpoint, cached by `kid`.
 *
 * Rate limiting, because an unknown `kid` is attacker-controlled: any request
 * can name a `kid` nobody has, and a naive resolver turns that into one
 * outbound request per token — a free amplifier pointed at your IdP. Three
 * limits apply:
 *
 *   1. **Coalescing** — concurrent misses share one in-flight request, so a
 *      burst of N unknown kids costs one fetch, not N.
 *   2. **Cooldown** — at most one fetch per `minRefetchIntervalMs`, whatever
 *      the reason for the miss.
 *   3. **Budget** — once the cache is warm, at most `maxRefetchesPerWindow`
 *      refetches per `refetchWindowMs`, so a slow drip that always waits out
 *      the cooldown still cannot fetch forever.
 *
 * A refused refetch is not an error: the resolver returns `undefined` and the
 * verifier reports `"No key resolved for kid"`. A genuine rotation is picked
 * up on the next allowed refetch or when the TTL expires the cache; size
 * `minRefetchIntervalMs` against how fast your IdP rotates.
 */
export function createJwksResolver(options: JwksResolverOptions): JwksResolver {
  const {
    jwksUri,
    cacheTtlMs = 300_000,
    maxKeys = 20,
    minRefetchIntervalMs = 30_000,
    maxRefetchesPerWindow = 5,
    refetchWindowMs = 600_000,
    timeoutMs = 5_000,
    now = () => Date.now(),
  } = options;
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("createJwksResolver: no global fetch; pass options.fetch");
  }
  if (!Number.isInteger(maxKeys) || maxKeys < 1) {
    throw new Error("createJwksResolver: maxKeys must be a positive integer");
  }

  // Insertion-ordered: Map iteration yields oldest-first, which drives eviction.
  const cache: KeyCache = new Map();
  const recentRefetches: number[] = [];
  let lastFetchAt = Number.NEGATIVE_INFINITY;
  let lastError: Error | undefined;
  let inFlight: Promise<void> | undefined;
  let fetches = 0;
  let throttledRefetches = 0;

  function sweep(t: number): void {
    for (const [id, entry] of cache) {
      if (t - entry.fetchedAt >= cacheTtlMs) cache.delete(id);
    }
  }

  function store(jwk: JsonWebKeySet["keys"][number], key: ResolvedVerificationKey, t: number): void {
    const id = cacheKeyFor(jwk, key);
    cache.delete(id); // re-adding moves the entry to the newest position
    if (cache.size >= maxKeys) {
      for (const oldest of cache.keys()) {
        cache.delete(oldest);
        break;
      }
    }
    cache.set(id, { key, fetchedAt: t });
  }

  async function fetchAndCache(t: number): Promise<void> {
    // Counted before the request, so a failing IdP is rate-limited too.
    lastFetchAt = t;
    fetches++;
    try {
      const signal = timeoutSignal(timeoutMs);
      const res = await fetchImpl(jwksUri, signal ? { signal } : {});
      if (!res.ok) throw new Error(`JWKS endpoint returned ${res.status}`);
      const doc: unknown = await res.json();
      if (doc === null || typeof doc !== "object" || !Array.isArray((doc as JsonWebKeySet).keys)) {
        throw new Error("JWKS document has no `keys` array");
      }
      for (const jwk of (doc as JsonWebKeySet).keys) {
        if (jwk === null || typeof jwk !== "object") continue;
        // One unusable key does not invalidate the document — IdPs publish
        // encryption keys and curves we do not implement alongside the rest.
        const imported = await importJwk(jwk).catch(() => undefined);
        if (imported) store(jwk, imported, t);
      }
      lastError = undefined;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      throw lastError;
    }
  }

  async function refresh(): Promise<void> {
    if (inFlight) {
      await inFlight;
      return;
    }
    const t = now();
    // The cooldown applies to every miss, warm or cold: an empty cache in
    // front of a broken IdP would otherwise fetch once per request. While
    // throttled after a *failed* fetch, that failure is what the caller sees —
    // "the IdP is down" is the truth, "unknown kid" would be a guess.
    if (t - lastFetchAt < minRefetchIntervalMs) return throttle();
    // The budget applies only to refetches — a warm cache asked for a `kid`
    // it does not hold, which is the path an attacker steers. A cold cache
    // (start-up, or every key past its TTL) may always fetch, subject to the
    // cooldown, and that fetch does not count against the budget.
    if (cache.size > 0) {
      while (recentRefetches.length > 0 && (recentRefetches[0] ?? 0) <= t - refetchWindowMs) recentRefetches.shift();
      if (recentRefetches.length >= maxRefetchesPerWindow) return throttle();
      recentRefetches.push(t);
    }
    const pending = fetchAndCache(t);
    inFlight = pending.then(
      () => undefined,
      () => undefined,
    );
    try {
      await pending;
    } finally {
      inFlight = undefined;
    }
  }

  function throttle(): void {
    throttledRefetches++;
    if (lastError) throw lastError;
  }

  const resolve = async (header: JwtHeader): Promise<ResolvedVerificationKey | undefined> => {
    sweep(now());
    const hit = lookupIn(cache, header);
    if (hit) return hit;
    await refresh();
    sweep(now());
    return lookupIn(cache, header);
  };

  return Object.assign(resolve, {
    stats: (): JwksResolverStats => ({ cachedKeys: cache.size, fetches, throttledRefetches }),
    clear: (): void => cache.clear(),
  });
}

// ─── Internals ───────────────────────────────────────────────

function timeoutSignal(ms: number): AbortSignal | undefined {
  return typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
    ? AbortSignal.timeout(ms)
    : undefined;
}
