/**
 * governance-sdk — High-level agent-identity token helpers
 *
 * Thin, opinionated wrappers around {@link createEd25519Identity} for callers
 * who just want "sign an agent identity" and "verify it." The token format
 * includes a nonce (`jti`), expiry (`exp`), optional audience (`aud`) and
 * issuer (`iss`) claims, and the agent's public key so any verifier can
 * re-check the signature. Split from `agent-identity-ed25519.ts` to keep each
 * file under 300 LOC; the replay store lives in `agent-identity-replay-store.ts`.
 */

import { deepSortKeys } from "./audit-integrity.js";
import {
  bufToHex,
  hexToBuf,
  importPublicKey,
  type Ed25519KeyPair,
} from "./agent-identity-ed25519.js";
import type { IdentityReplayStore } from "./agent-identity-replay-store.js";

export type {
  IdentityReplayStore,
  MemoryReplayStore,
  MemoryReplayStoreOptions,
} from "./agent-identity-replay-store.js";
export { createMemoryReplayStore } from "./agent-identity-replay-store.js";

export interface AgentIdentityToken {
  payload: {
    agentId: string;
    publicKeyHex: string;
    kid?: string;
    iat: number;
    exp: number;
    jti: string;
    /** Intended recipient(s). A verifier enforces it via `expectedAudience`. */
    aud?: string | string[];
    /** Minting authority. A verifier enforces it via `expectedIssuer`. */
    iss?: string;
    capabilities?: string[];
  };
  signature: string;
}

export interface SignAgentIdentityInput {
  agentId: string;
  keys: { publicKey: CryptoKey; privateKey: CryptoKey } | Ed25519KeyPair;
  /** Token lifetime in seconds. Default 3600. */
  ttlSeconds?: number;
  /** Opaque key identifier for rotation. */
  kid?: string;
  capabilities?: string[];
  /** Audience claim — the service(s) this token is for. */
  aud?: string | string[];
  /** Issuer claim — who minted this token. */
  iss?: string;
  /** Override the issued-at (UNIX seconds). Useful for reproducibility in tests. */
  now?: number;
}

/**
 * Sign an agent identity token.
 *
 * @example
 * ```ts
 * import { createEd25519Identity, signAgentIdentity, verifyAgentIdentity } from 'governance-sdk/agent-identity-ed25519';
 *
 * const identity = createEd25519Identity();
 * const keys = await identity.generateKeyPair();
 * const token = await signAgentIdentity({ agentId: 'sales-bot', keys, ttlSeconds: 3600, aud: 'orders-api' });
 * const result = await verifyAgentIdentity(token, { expectedAudience: 'orders-api' });
 * // => { valid: true, agentId: 'sales-bot' }
 * ```
 */
export async function signAgentIdentity(input: SignAgentIdentityInput): Promise<AgentIdentityToken> {
  const { agentId, keys, ttlSeconds = 3600, kid, capabilities, aud, iss, now } = input;
  const rawPublic = await crypto.subtle.exportKey("raw", keys.publicKey);
  const publicKeyHex = bufToHex(new Uint8Array(rawPublic));
  const iat = now ?? Math.floor(Date.now() / 1000);
  const payload: AgentIdentityToken["payload"] = {
    agentId,
    publicKeyHex,
    iat,
    exp: iat + ttlSeconds,
    jti: randomJti(),
    ...(kid !== undefined ? { kid } : {}),
    ...(aud !== undefined ? { aud: Array.isArray(aud) ? [...aud] : aud } : {}),
    ...(iss !== undefined ? { iss } : {}),
    ...(capabilities !== undefined ? { capabilities: [...capabilities].sort() } : {}),
  };
  const canonical = JSON.stringify(deepSortKeys(payload));
  const encoded = new TextEncoder().encode(canonical);
  const sig = await crypto.subtle.sign("Ed25519", keys.privateKey, encoded.buffer as ArrayBuffer);
  return { payload, signature: bufToHex(new Uint8Array(sig)) };
}

export interface VerifyAgentIdentityOptions {
  /** Clock skew tolerance in seconds. Default 60. */
  clockSkewSeconds?: number;
  now?: number;
  /**
   * Pinned public key (hex). If supplied, verification fails when the token's
   * embedded `publicKeyHex` doesn't match. Pin whenever you know which key
   * the agent is supposed to be using — a token self-describes its key, so
   * without pinning it only proves "someone signed this." Every pinning
   * option supplied must pass; they combine with AND.
   */
  pinnedPublicKeyHex?: string;
  /**
   * Accept any of these keys (hex) — list the outgoing and incoming keys
   * during a rotation window. Supplying an empty array rejects every token.
   */
  pinnedPublicKeysHex?: string[];
  /**
   * Resolve the expected key from the token's `kid`. Return `undefined` for
   * an unknown `kid` to reject the token.
   */
  resolvePublicKey?: (kid: string | undefined) => string | undefined | Promise<string | undefined>;
  /**
   * Audience this verifier identifies as. Required when tokens carry `aud`:
   * a token with an `aud` claim is rejected unless this matches (RFC 7519 §4.1.3).
   */
  expectedAudience?: string;
  /** Reject unless `payload.iss` equals this value. */
  expectedIssuer?: string;
  /**
   * Record accepted `jti`s and reject one seen before. Consulted after the
   * signature verifies, so forged tokens never reach the store.
   */
  replayStore?: IdentityReplayStore;
}

/** Every `reason` a failed verification can carry — match on these, not on prose. */
export type VerifyAgentIdentityFailureReason =
  | "Malformed token"
  | "Token expired"
  | "Token not yet valid"
  | "Public key does not match pinned key"
  | "No public key resolved for kid"
  | "Audience missing"
  | "Audience unexpected"
  | "Audience mismatch"
  | "Issuer missing"
  | "Issuer mismatch"
  | `Invalid key or signature encoding: ${string}`
  | "Invalid signature"
  | "Token replayed";

export interface VerifyAgentIdentityResult {
  valid: boolean;
  agentId?: string;
  reason?: VerifyAgentIdentityFailureReason;
}

/**
 * Verify an agent identity token produced by {@link signAgentIdentity}.
 * Checks shape, expiry and clock skew, key pinning / resolution, `aud` /
 * `iss`, the Ed25519 signature over the canonicalised payload, and finally
 * replay — in that order, so the cheapest checks run first and only an
 * authentic token is ever recorded in the replay store.
 */
export async function verifyAgentIdentity(
  token: AgentIdentityToken,
  options: VerifyAgentIdentityOptions = {},
): Promise<VerifyAgentIdentityResult> {
  const { clockSkewSeconds = 60, now, expectedAudience, expectedIssuer, replayStore } = options;
  const nowSec = now ?? Math.floor(Date.now() / 1000);

  if (!isTokenShaped(token)) return fail("Malformed token");
  const { payload, signature } = token;

  if (typeof payload.exp !== "number" || payload.exp + clockSkewSeconds < nowSec) return fail("Token expired");
  if (typeof payload.iat !== "number" || payload.iat - clockSkewSeconds > nowSec) return fail("Token not yet valid");

  const pinFailure = await checkPinnedKey(payload, options);
  if (pinFailure) return fail(pinFailure);

  const claimFailure = checkAudienceAndIssuer(payload, expectedAudience, expectedIssuer);
  if (claimFailure) return fail(claimFailure);

  let publicKey: CryptoKey;
  let sigBytes: Uint8Array;
  try {
    publicKey = await importPublicKey(payload.publicKeyHex);
    sigBytes = hexToBuf(signature);
  } catch (err) {
    return fail(`Invalid key or signature encoding: ${(err as Error).message}`);
  }

  const canonical = JSON.stringify(deepSortKeys(payload));
  const encoded = new TextEncoder().encode(canonical);
  const ok = await crypto.subtle.verify(
    "Ed25519",
    publicKey,
    sigBytes.buffer as ArrayBuffer,
    encoded.buffer as ArrayBuffer,
  );
  if (!ok) return fail("Invalid signature");

  if (replayStore) {
    // Only `await` when the store is async: a synchronous store's has→add
    // pair then runs with no interleaving window between check and record.
    const seen = replayStore.has(payload.jti);
    if (typeof seen === "boolean" ? seen : await seen) return fail("Token replayed");
    await replayStore.add(payload.jti, payload.exp + clockSkewSeconds);
  }

  return { valid: true, agentId: payload.agentId };
}

// ─── Internals ───────────────────────────────────────────────

function fail(reason: VerifyAgentIdentityFailureReason): VerifyAgentIdentityResult {
  return { valid: false, reason };
}

/** Structural check — tokens arrive over the wire as arbitrary JSON. */
function isTokenShaped(token: unknown): token is AgentIdentityToken {
  if (token === null || typeof token !== "object") return false;
  const t = token as Record<string, unknown>;
  if (typeof t.signature !== "string" || t.payload === null || typeof t.payload !== "object") return false;
  const p = t.payload as Record<string, unknown>;
  return (
    typeof p.agentId === "string" &&
    typeof p.publicKeyHex === "string" &&
    typeof p.jti === "string" &&
    p.jti.length > 0 &&
    (p.kid === undefined || typeof p.kid === "string")
  );
}

async function checkPinnedKey(
  payload: AgentIdentityToken["payload"],
  { pinnedPublicKeyHex, pinnedPublicKeysHex, resolvePublicKey }: VerifyAgentIdentityOptions,
): Promise<VerifyAgentIdentityFailureReason | undefined> {
  const presented = payload.publicKeyHex.toLowerCase();

  if (pinnedPublicKeyHex || pinnedPublicKeysHex !== undefined) {
    const pinned = [
      ...(pinnedPublicKeyHex ? [pinnedPublicKeyHex] : []),
      ...(pinnedPublicKeysHex ?? []),
    ].map((k) => k.toLowerCase());
    if (!pinned.includes(presented)) return "Public key does not match pinned key";
  }

  if (resolvePublicKey) {
    const resolved = await resolvePublicKey(payload.kid);
    if (resolved === undefined) return "No public key resolved for kid";
    if (resolved.toLowerCase() !== presented) return "Public key does not match pinned key";
  }

  return undefined;
}

function checkAudienceAndIssuer(
  payload: AgentIdentityToken["payload"],
  expectedAudience: string | undefined,
  expectedIssuer: string | undefined,
): VerifyAgentIdentityFailureReason | undefined {
  const { aud, iss } = payload;

  if (expectedAudience === undefined) {
    // A token addressed to someone must not verify at a party that never
    // said who it is — otherwise a token for service A works at service B.
    if (aud !== undefined) return "Audience unexpected";
  } else {
    if (aud === undefined) return "Audience missing";
    const matches = typeof aud === "string"
      ? aud === expectedAudience
      : Array.isArray(aud) && aud.some((a) => a === expectedAudience);
    if (!matches) return "Audience mismatch";
  }

  if (expectedIssuer !== undefined) {
    if (iss === undefined) return "Issuer missing";
    if (iss !== expectedIssuer) return "Issuer mismatch";
  }

  return undefined;
}

function randomJti(): string {
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return bufToHex(bytes);
}
