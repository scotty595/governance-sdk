/**
 * Session ledger — the accumulator behind budgets and rate limits.
 *
 * Six presets (`rateLimit`, `tokenBudget`, `costBudget`, `concurrentLimit`
 * and friends) are declarative gates over counters on the enforcement
 * context. Before this module the SDK never incremented those counters, so
 * `rateLimit(100, 60_000)` was a no-op unless the host populated
 * `ctx.recentActionCount` by hand — a footgun dressed as a feature.
 *
 * The ledger keeps, per session key, the timestamps of recent allowed
 * actions and the running token and cost totals reported through
 * `recordOutcome()`. `createGovernance()` consults it before evaluating a
 * local decision and fills any counter the host left undefined; values the
 * host supplies always win.
 *
 * Scope: **per process**. The ledger is in-memory and bounded. Multiple
 * replicas each keep their own; for a fleet-wide limit put a shared counter
 * (Redis, your API layer) in front and populate the context yourself — the
 * host-supplied value takes precedence exactly as before.
 */

import type { EnforcementContext } from "./policy.js";

export interface SessionLedgerConfig {
  /** Maximum sessions tracked before the least-recently-touched are evicted. Default 10_000. */
  maxSessions?: number;
  /** Maximum action timestamps retained per session. Default 1_000. */
  maxTimestamps?: number;
  /** Sessions idle longer than this are dropped on the next write. Default 1 hour. */
  idleTtlMs?: number;
  /**
   * How a context maps to a session. Default: `metadata.sessionId`, then
   * `metadata.threadId`, then `agentId`.
   */
  keyBy?: (ctx: EnforcementContext) => string;
  /** Clock, injectable for tests. */
  now?: () => number;
}

export interface SessionSnapshot {
  key: string;
  actionTimestamps: number[];
  tokensUsed: number;
  cost: number;
  lastTouched: number;
}

export interface SessionLedger {
  keyFor(ctx: EnforcementContext): string;
  /** Record an allowed action (call after a non-blocking decision). */
  recordAction(key: string, at?: number): void;
  /** Add tokens and/or cost consumed by a completed action. */
  recordUsage(key: string, usage: { tokens?: number; cost?: number }): void;
  snapshot(key: string): SessionSnapshot | undefined;
  /**
   * Return a copy of `ctx` with `recentActionTimestamps`, `recentActionCount`,
   * `sessionTokensUsed` and `sessionCost` filled from the ledger wherever the
   * host left them undefined. Never overwrites a host-supplied value.
   */
  populate(ctx: EnforcementContext): EnforcementContext;
  /** Drop one session, or every session when no key is given. */
  reset(key?: string): void;
  readonly size: number;
}

const DEFAULTS = { maxSessions: 10_000, maxTimestamps: 1_000, idleTtlMs: 60 * 60 * 1000 };

function defaultKey(ctx: EnforcementContext): string {
  const meta = ctx.metadata;
  const sessionId = meta?.sessionId;
  if (typeof sessionId === "string" && sessionId.length > 0) return sessionId;
  const threadId = meta?.threadId;
  if (typeof threadId === "string" && threadId.length > 0) return threadId;
  return ctx.agentId;
}

export function createSessionLedger(config: SessionLedgerConfig = {}): SessionLedger {
  const maxSessions = config.maxSessions ?? DEFAULTS.maxSessions;
  const maxTimestamps = config.maxTimestamps ?? DEFAULTS.maxTimestamps;
  const idleTtlMs = config.idleTtlMs ?? DEFAULTS.idleTtlMs;
  const keyBy = config.keyBy ?? defaultKey;
  const now = config.now ?? (() => Date.now());

  // Map preserves insertion order; re-inserting on touch gives LRU ordering.
  const sessions = new Map<string, SessionSnapshot>();

  function touch(key: string): SessionSnapshot {
    const t = now();
    let s = sessions.get(key);
    if (s) {
      sessions.delete(key);
      s.lastTouched = t;
    } else {
      s = { key, actionTimestamps: [], tokensUsed: 0, cost: 0, lastTouched: t };
    }
    sessions.set(key, s);
    prune(t);
    return s;
  }

  function prune(t: number): void {
    if (sessions.size <= maxSessions) {
      // Cheap idle sweep from the LRU end only when over half full.
      if (sessions.size < maxSessions / 2) return;
      for (const [k, s] of sessions) {
        if (t - s.lastTouched <= idleTtlMs) break;
        sessions.delete(k);
      }
      return;
    }
    for (const k of sessions.keys()) {
      sessions.delete(k);
      if (sessions.size <= maxSessions) break;
    }
  }

  return {
    keyFor: keyBy,
    recordAction(key, at) {
      const s = touch(key);
      s.actionTimestamps.push(at ?? now());
      if (s.actionTimestamps.length > maxTimestamps) {
        s.actionTimestamps.splice(0, s.actionTimestamps.length - maxTimestamps);
      }
    },
    recordUsage(key, usage) {
      const s = touch(key);
      if (typeof usage.tokens === "number" && Number.isFinite(usage.tokens)) s.tokensUsed += usage.tokens;
      if (typeof usage.cost === "number" && Number.isFinite(usage.cost)) s.cost += usage.cost;
    },
    snapshot(key) {
      const s = sessions.get(key);
      return s ? { ...s, actionTimestamps: [...s.actionTimestamps] } : undefined;
    },
    populate(ctx) {
      const s = sessions.get(keyBy(ctx));
      if (!s) return ctx;
      return {
        ...ctx,
        ...(ctx.recentActionTimestamps === undefined ? { recentActionTimestamps: [...s.actionTimestamps] } : {}),
        ...(ctx.recentActionCount === undefined ? { recentActionCount: s.actionTimestamps.length } : {}),
        ...(ctx.sessionTokensUsed === undefined ? { sessionTokensUsed: s.tokensUsed } : {}),
        ...(ctx.sessionCost === undefined ? { sessionCost: s.cost } : {}),
      };
    },
    reset(key) {
      if (key === undefined) sessions.clear();
      else sessions.delete(key);
    },
    get size() {
      return sessions.size;
    },
  };
}
