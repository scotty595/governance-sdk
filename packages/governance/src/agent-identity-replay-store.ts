/**
 * governance-sdk — Replay store for Ed25519 agent-identity tokens
 *
 * `verifyAgentIdentity({ replayStore })` records each accepted token's `jti`
 * and rejects any `jti` it has already seen, closing the "re-present a valid
 * token within its TTL" window. Implement {@link IdentityReplayStore} over
 * shared storage (Redis `SET NX EX`, a Postgres unique index, …) for
 * multi-process deployments; {@link createMemoryReplayStore} is a bounded,
 * single-process default. Split from `agent-identity-ed25519-token.ts` to
 * keep each file under 300 LOC.
 */

/**
 * Pluggable store of seen token IDs (`jti`).
 *
 * `verifyAgentIdentity` calls `has(jti)` after the signature verifies and
 * `add(jti, exp)` only when every other check passed. `expiresAtEpochSeconds`
 * already includes the verifier's clock-skew allowance — a store may drop
 * the entry once that instant has passed. Stores shared between processes
 * should make `add` atomic (e.g. `SET NX`) since `has` → `add` is two calls.
 */
export interface IdentityReplayStore {
  has(jti: string): boolean | Promise<boolean>;
  add(jti: string, expiresAtEpochSeconds: number): void | Promise<void>;
}

export interface MemoryReplayStoreOptions {
  /**
   * Maximum `jti` entries retained. Default 10_000. When full, expired
   * entries are swept first; if still full the oldest entry is evicted, which
   * re-opens the replay window for that one token — size this above the
   * number of tokens you accept per TTL window.
   */
  maxEntries?: number;
  /** Clock in UNIX seconds. Default `Date.now() / 1000`. Override in tests. */
  now?: () => number;
}

/** Synchronous, in-memory {@link IdentityReplayStore} with introspection helpers. */
export interface MemoryReplayStore extends IdentityReplayStore {
  has(jti: string): boolean;
  add(jti: string, expiresAtEpochSeconds: number): void;
  /** Entries currently held (may include expired entries not yet swept). */
  size(): number;
  /** Drop every entry. */
  clear(): void;
}

/**
 * Bounded in-memory replay store. Single-process only — every replica holds
 * its own view, so a token replayed against a different replica is not
 * detected. `has` and `add` are synchronous, so a verifier that calls them
 * back-to-back has no interleaving window between the check and the record.
 */
export function createMemoryReplayStore(options: MemoryReplayStoreOptions = {}): MemoryReplayStore {
  const { maxEntries = 10_000, now = () => Math.floor(Date.now() / 1000) } = options;
  if (!Number.isInteger(maxEntries) || maxEntries < 1) {
    throw new Error("createMemoryReplayStore: maxEntries must be a positive integer");
  }

  // Insertion-ordered: Map iteration yields oldest-first, which drives eviction.
  const entries = new Map<string, number>();

  function sweepExpired(): void {
    const t = now();
    for (const [jti, exp] of entries) {
      if (exp < t) entries.delete(jti);
    }
  }

  return {
    has(jti) {
      const exp = entries.get(jti);
      if (exp === undefined) return false;
      if (exp < now()) {
        entries.delete(jti);
        return false;
      }
      return true;
    },

    add(jti, expiresAtEpochSeconds) {
      if (expiresAtEpochSeconds < now()) return; // already dead — nothing to protect
      entries.delete(jti); // re-adding moves the entry to the newest position
      if (entries.size >= maxEntries) sweepExpired();
      if (entries.size >= maxEntries) {
        for (const oldest of entries.keys()) {
          entries.delete(oldest);
          break;
        }
      }
      entries.set(jti, expiresAtEpochSeconds);
    },

    size: () => entries.size,
    clear: () => entries.clear(),
  };
}
