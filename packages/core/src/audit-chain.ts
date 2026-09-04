/**
 * The tamper-evident audit chain, and the write path every audit event takes.
 *
 * Each event's HMAC covers the previous hash, the sequence number and the
 * canonicalised event, so an edit, an interior deletion or a renumbering
 * breaks verification. Chains are scoped per organisation: each org has its
 * own head, its own 1..N sequence and its own write lock, and the org is bound
 * into the hash so an event cannot be relabelled into another tenant's chain.
 *
 * Three write paths, in order of preference:
 *   1. `appendToAuditChain` — the adapter allocates the sequence and previous
 *      hash from the durable head under its own lock, so concurrent writers in
 *      separate processes cannot fork the chain. The signing key never leaves
 *      the SDK: the adapter calls back in to compute the HMAC.
 *   2. `createAuditEventWithIntegrity` — durable, but the sequence comes from
 *      process-local state, so it is correct under a single writer only.
 *   3. Neither — the event persists but its integrity lives only in this
 *      process, and is lost on restart. A downgrade, and it says so.
 *
 * What this cannot do, by construction: detect truncation of the tail, or
 * resist anyone holding the signing key. See docs/guarantees.md.
 */

import {
  canonicalize as canonicalizeAuditEvent,
  hmacSha256,
  GENESIS_HASH,
  type AuditIntegrity,
  type IntegrityAuditEvent,
} from "./audit-integrity.js";
import type { GovernanceStorage, AuditEvent, AuditQueryFilters } from "./storage.js";

/** What `createGovernance` settles `integrityAudit` into. */
export interface ResolvedIntegrityConfig {
  signingKey: string;
  onFailure: "allow" | "block";
}

export interface AuditChainDeps {
  storage: GovernanceStorage;
  /** Undefined when integrity audit is off — writes then take the plain path. */
  integrity: ResolvedIntegrityConfig | undefined;
  onAuditError: ((error: unknown) => void) | undefined;
  /** Fan a written event out to plugin sinks. Must never throw. */
  emitToSinks: (event: AuditEvent) => void;
}

export interface AuditChain {
  /** Write an audit event, chaining it when integrity audit is configured. */
  writeAudit(event: Omit<AuditEvent, "id" | "createdAt">): Promise<AuditEvent>;
  /** Chain export and stats — undefined when integrity audit is off. */
  integrityChain: {
    export(filters?: AuditQueryFilters): Promise<IntegrityAuditEvent[]>;
    stats(organizationId?: string): Promise<{ latestSequence: number; latestHash: string; algorithm: string }>;
  } | undefined;
}

/** Resolve the org id from an explicit field, falling back to metadata. */
export function resolveOrgId(
  explicit: string | undefined,
  metadata: Record<string, unknown> | undefined,
): string | undefined {
  if (explicit) return explicit;
  const fromMeta = metadata?.organizationId;
  return typeof fromMeta === "string" && fromMeta.length > 0 ? fromMeta : undefined;
}

export function createAuditChain(deps: AuditChainDeps): AuditChain {
  const { storage, integrity, onAuditError, emitToSinks } = deps;

  // ── Integrity audit chain (opt-in) ───────────────────────────
  //
  // When `integrityAudit` is configured, every write routed through
  // `writeAudit()` gets HMAC-SHA256 hash-chained. The chain state
  // (sequence, last hash, per-event integrity) is persisted to durable
  // storage through GovernanceStorage.createAuditEventWithIntegrity() so
  // the chain survives process restarts. Chain resume on boot is handled
  // by loadChainHead() below.
  //
  // Serialisation via `chainLock` prevents concurrent writes from forking
  // the chain within a single process. Cross-process safety is provided
  // by the UNIQUE index on integrity_sequence at the storage layer.
  // Per-org chain state. Each organization gets its OWN hash chain (own head,
  // own sequence 1..N, own write lock) so one org's audit trail is never
  // interleaved with another's — an org can export + verify its slice
  // standalone, and cross-org tampering breaks the chain. Events with no
  // organizationId share a single sentinel bucket (backward-compatible with
  // the original global chain).
  const GLOBAL_CHAIN_KEY = "global";
  interface OrgChainState {
    lastHash: string;
    sequence: number;
    loaded: boolean;
    loadPromise: Promise<void> | null;
    /** Serialises writes for THIS org so its sequence is race-free. */
    lock: Promise<unknown>;
  }
  const orgChains = new Map<string, OrgChainState>();
  function chainStateFor(organizationId: string | undefined): OrgChainState {
    // Namespaced so no real organization id can collide with the org-less bucket.
    const key = organizationId === undefined ? GLOBAL_CHAIN_KEY : `org:${organizationId}`;
    let state = orgChains.get(key);
    if (!state) {
      state = { lastHash: GENESIS_HASH, sequence: 0, loaded: false, loadPromise: null, lock: Promise.resolve() };
      orgChains.set(key, state);
    }
    return state;
  }
  // Fallback in-memory index for adapters that don't implement
  // createAuditEventWithIntegrity (e.g. third-party 0.11.x adapters).
  // When the storage adapter IS integrity-aware, we don't populate this
  // map — reads go back to storage.getAuditIntegrity().
  const integrityIndex = new Map<string, AuditIntegrity>();
  const storageHasIntegrity =
    typeof storage.createAuditEventWithIntegrity === "function" &&
    typeof storage.getAuditIntegrity === "function";
  // Durable integrity READS only need getAuditIntegrity — an adapter can
  // implement the newer appendToAuditChain write contract + getAuditIntegrity
  // without the legacy createAuditEventWithIntegrity. export()/verify() must
  // still read that durable integrity rather than the (empty) in-process index.
  const storageCanReadIntegrity = typeof storage.getAuditIntegrity === "function";
  // Multi-writer-safe path: the adapter allocates the sequence + previous-hash
  // from the durable head atomically (per-org lock), so concurrent processes
  // never fork the chain or collide on a sequence. Preferred when available.
  const storageHasAtomicAppend = typeof storage.appendToAuditChain === "function";
  // One-time advisory: an adapter with durable integrity but no atomic append
  // uses process-local sequence allocation, which is only safe under a single
  // writer. Signalled once so multi-process deployments aren't silently unsafe.
  let warnedNonAtomicAppend = false;

  async function loadChainHead(state: OrgChainState, organizationId: string | undefined): Promise<void> {
    if (state.loaded || !integrity) return;
    if (state.loadPromise) return state.loadPromise;
    state.loadPromise = (async () => {
      if (typeof storage.getChainHead === "function") {
        const head = await storage.getChainHead(organizationId);
        if (head) {
          state.lastHash = head.hash;
          state.sequence = head.sequence;
        }
      }
      state.loaded = true;
    })();
    return state.loadPromise;
  }

  async function writeAudit(
    event: Omit<AuditEvent, "id" | "createdAt">,
  ): Promise<AuditEvent> {
    const full: AuditEvent = {
      ...event,
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
    };

    if (!integrity) {
      // Plain path — as before.
      const stored = await storage.createAuditEvent(full);
      emitToSinks(stored);
      return stored;
    }

    // Chained path. Each org has its own head + lock, so its sequence is
    // contiguous within the org and independent across orgs. Serialise via
    // the org's lock so the sequence is race-free. On failure we preserve
    // the org's lastHash/sequence (don't bump) so the next write attempts
    // the same slot — avoids silent gaps.
    const state = chainStateFor(full.organizationId);
    const result = state.lock.then(async () => {
      // Preferred: the storage adapter allocates the sequence + previous-hash
      // from the CURRENT durable head atomically, so this is safe across pods.
      // The in-process `state.lock` above still serialises this pod's writes to
      // the org (cheap local ordering ahead of the DB lock); `state.*` is only
      // refreshed afterwards as a cache for stats(), never read to derive the
      // next slot.
      if (storageHasAtomicAppend) {
        const { event: stored, integrity: integrityMeta } = await storage.appendToAuditChain!(
          full,
          async (head) => {
            const previousHash = head?.hash ?? GENESIS_HASH;
            const nextSequence = (head?.sequence ?? 0) + 1;
            const canonical = canonicalizeAuditEvent(full, previousHash, nextSequence);
            const hash = await hmacSha256(integrity.signingKey, canonical);
            return { hash, previousHash, sequence: nextSequence, signedAt: new Date().toISOString() };
          },
        );
        state.lastHash = integrityMeta.hash;
        state.sequence = integrityMeta.sequence;
        state.loaded = true;
        return stored;
      }

      // Process-local sequence path (no appendToAuditChain). Correct under a
      // SINGLE writer only. Warn once so custom adapters in multi-process
      // deployments get the documented signal. (The pure-legacy branch below
      // additionally warns per-write about the non-durable session-local
      // downgrade — a strictly more severe, data-losing failure mode.)
      if (storageHasIntegrity && !warnedNonAtomicAppend) {
        warnedNonAtomicAppend = true;
        onAuditError?.(
          new Error(
            "integrity chain: storage adapter implements createAuditEventWithIntegrity but not appendToAuditChain; audit appends use process-local sequence allocation and are multi-process-safe only under a single writer — implement appendToAuditChain for atomic cross-process appends",
          ),
        );
      }

      // First call after boot: resume this org's chain from durable state.
      if (!state.loaded) await loadChainHead(state, full.organizationId);

      const previousHash = state.lastHash;
      const nextSequence = state.sequence + 1;
      const canonical = canonicalizeAuditEvent(full, previousHash, nextSequence);
      const hash = await hmacSha256(integrity.signingKey, canonical);
      const integrityMeta: AuditIntegrity = {
        hash,
        previousHash,
        sequence: nextSequence,
        signedAt: new Date().toISOString(),
      };

      let stored: AuditEvent;
      if (storageHasIntegrity) {
        // Durable path: integrity columns written in the same INSERT as
        // the event. Restart-safe — getChainHead() will find this row.
        stored = await storage.createAuditEventWithIntegrity!(full, integrityMeta);
      } else {
        // Legacy path: adapter predates 0.12. Event persists, integrity
        // lives only in this process's integrityIndex. A process restart
        // will leave earlier events unverifiable. This is a downgrade,
        // not the default; surfaced via onAuditError below.
        stored = await storage.createAuditEvent(full);
        integrityIndex.set(full.id, integrityMeta);
        onAuditError?.(
          new Error(
            "integrity chain: storage adapter does not implement createAuditEventWithIntegrity; chain is session-local only and will not survive process restart",
          ),
        );
      }
      state.lastHash = hash;
      state.sequence = nextSequence;
      return stored;
    });

    state.lock = result.catch(() => {
      /* lock must advance even on failure */
    });

    // Sinks see the event only once it is durably written and chained.
    result.then(emitToSinks).catch(() => { /* reported through the caller */ });

    return result; // throws on failure — callers decide policy
  }

  const integrityChain = integrity
    ? {
        async export(filters?: AuditQueryFilters): Promise<IntegrityAuditEvent[]> {
          // Ensure boot-time resume has run for the org being exported so
          // stats()/export() reflect durable state even if no writes have
          // happened yet this process. Export a single org at a time
          // (filters.organizationId) to get a contiguous, verifiable chain.
          const orgState = chainStateFor(filters?.organizationId);
          if (!orgState.loaded) await loadChainHead(orgState, filters?.organizationId);
          const events = await storage.queryAuditEvents({
            ...filters,
            limit: undefined,
            offset: undefined,
          });
          const result: IntegrityAuditEvent[] = [];
          // One round-trip for the whole export when the adapter supports it;
          // otherwise the per-event read (N+1) that older adapters require.
          const durableBatch =
            storageCanReadIntegrity && typeof storage.getAuditIntegrityBatch === "function"
              ? await storage.getAuditIntegrityBatch(events.map((e) => e.id))
              : null;
          for (const e of events) {
            // Prefer durable integrity record; fall back to in-memory
            // index for adapters that don't yet persist it.
            // An id the batch did not return is re-read individually — a
            // partial batch must never silently drop an event from the export.
            const durable = durableBatch
              ? durableBatch.get(e.id) ?? (storageCanReadIntegrity ? await storage.getAuditIntegrity!(e.id) : null)
              : storageCanReadIntegrity
                ? await storage.getAuditIntegrity!(e.id)
                : null;
            const meta = durable ?? integrityIndex.get(e.id);
            if (meta) result.push({ ...e, integrity: meta });
          }
          // Chain order is the lock-allocated sequence, not wall clock —
          // createdAt is stamped before the write lock and can invert under
          // concurrent writers. createdAt only tiebreaks legacy forked rows.
          return result.sort((a, b) => {
            if (a.integrity.sequence !== b.integrity.sequence) {
              return a.integrity.sequence - b.integrity.sequence;
            }
            return a.createdAt.localeCompare(b.createdAt);
          });
        },
        async stats(organizationId?: string) {
          // Durable head is the source of truth. Reading it FRESH per call
          // (not the process-local cache, which only reflects this process's
          // own appends) is what makes stats() correct under multiple writers
          // sharing one store — same durable-head machinery export() uses.
          // No mutation of chain state here: the write path owns
          // orgState.lastHash/sequence under the per-org lock.
          if (typeof storage.getChainHead === "function") {
            const head = await storage.getChainHead(organizationId);
            return {
              latestSequence: head?.sequence ?? 0,
              latestHash: head?.hash ?? GENESIS_HASH,
              algorithm: "hmac-sha256",
            };
          }
          // Adapter without a durable head (pre-0.12 / custom): fall back to
          // this process's cache, resuming once from boot state if needed.
          // Session-local by construction — correct single-process only.
          const orgState = chainStateFor(organizationId);
          if (!orgState.loaded) await loadChainHead(orgState, organizationId);
          return {
            latestSequence: orgState.sequence,
            latestHash: orgState.lastHash,
            algorithm: "hmac-sha256",
          };
        },
      }
    : undefined;

  return { writeAudit, integrityChain };
}
