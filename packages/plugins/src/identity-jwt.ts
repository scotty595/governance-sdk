/**
 * governance-sdk — Verify an externally issued JWT as an agent identity
 *
 * The SDK's own identity story is self-issued Ed25519 tokens
 * (`agent-identity-ed25519-token.ts`). Enterprises do not have that problem:
 * their agents already carry a token from Microsoft Entra Agent ID, Okta,
 * Auth0 or a SPIFFE server. A governance layer that cannot verify the identity
 * its user's IdP already issues is asking them to run two identity systems, so
 * this module verifies theirs and maps it onto the same governance identity.
 *
 * Zero dependencies: `crypto.subtle` and `fetch`, nothing else — Node 20+,
 * Deno, Bun and Cloudflare Workers. Algorithms and JWK import live in
 * `identity-jwt-keys.ts`, JWKS fetching in `identity-jwks.ts`, claim mapping in
 * `identity-jwt-claims.ts`; SPIFFE sits on top in `identity-spiffe.ts`.
 *
 * Checks run cheapest-first — shape, algorithm, claims, then signature, then
 * replay — matching `verifyAgentIdentity`. Two consequences worth knowing: a
 * junk token never costs a JWKS fetch, and only a token whose signature
 * verified is ever recorded in the replay store.
 *
 * @example
 * ```ts
 * import { createJwksResolver, verifyJwt } from '@governance-sdk/plugins/identity-jwt.js';
 *
 * const resolveKey = createJwksResolver({ jwksUri: 'https://login.example.com/keys' });
 * const result = await verifyJwt(bearerToken, {
 *   resolveKey,
 *   expectedIssuer: 'https://login.example.com/',
 *   expectedAudience: 'orders-api',
 * });
 * if (result.valid) console.log(result.agentId, result.identity.capabilities);
 * else console.warn(result.reason);
 * ```
 */

import type { IdentityReplayStore } from "./agent-identity-replay-store.js";
import {
  JWT_ALGORITHMS,
  VERIFY_PARAMS,
  createStaticKeyResolver,
  isJwtAlgorithm,
  type JsonWebKeySet,
  type JwtAlgorithm,
  type JwtKeyResolver,
  type ResolvedVerificationKey,
} from "./identity-jwt-keys.js";
import {
  base64UrlToBytes,
  buildIdentity,
  checkAudience,
  checkIssuer,
  checkTimes,
  decodeJsonSegment,
  isRecord,
  numberClaim,
  stringClaim,
  toArrayBuffer,
  type VerifyJwtFailureReason,
  type VerifyJwtIdentity,
} from "./identity-jwt-claims.js";

export type {
  IdentityReplayStore,
  MemoryReplayStore,
  MemoryReplayStoreOptions,
} from "./agent-identity-replay-store.js";
export { createMemoryReplayStore } from "./agent-identity-replay-store.js";
export {
  JWT_ALGORITHMS,
  algorithmForJwk,
  createStaticKeyResolver,
  importJwk,
  isJwtAlgorithm,
  type JsonWebKeyLike,
  type JsonWebKeySet,
  type JwtAlgorithm,
  type JwtHeader,
  type JwtKeyResolver,
  type ResolvedVerificationKey,
} from "./identity-jwt-keys.js";
export {
  createJwksResolver,
  type JwksResolver,
  type JwksResolverOptions,
  type JwksResolverStats,
} from "./identity-jwks.js";
export {
  base64UrlToBytes,
  type JwtDelegation,
  type JwtDelegationActor,
  type VerifyJwtFailureReason,
  type VerifyJwtIdentity,
} from "./identity-jwt-claims.js";

// ─── Options and results ─────────────────────────────────────

export interface VerifyJwtOptions {
  /**
   * Resolve the verification key for a token's header — usually
   * {@link createJwksResolver}. Takes precedence over `jwks`.
   */
  resolveKey?: JwtKeyResolver;
  /** A JWKS document you already hold. Ignored when `resolveKey` is supplied. */
  jwks?: JsonWebKeySet;
  /**
   * Reject unless `iss` matches (or is one of several, during a migration).
   * Optional but strongly advised: the JWKS URI pins *a* key set, `iss` pins
   * who is speaking.
   */
  expectedIssuer?: string | string[];
  /**
   * Audience this verifier identifies as. Omit it and a token carrying `aud`
   * is rejected outright — otherwise a token minted for service A verifies at
   * service B, which is the whole reason `aud` exists (RFC 7519 §4.1.3).
   */
  expectedAudience?: string | string[];
  /** Narrow the accepted algorithms further. Default {@link JWT_ALGORITHMS}. */
  allowedAlgorithms?: readonly JwtAlgorithm[];
  /** Clock skew tolerance in seconds, applied to `exp`/`nbf`/`iat`. Default 60. */
  clockSkewSeconds?: number;
  /** Override "now" (UNIX seconds). Useful for reproducibility in tests. */
  now?: number;
  /** Reject a token with no `exp`. Default true. */
  requireExpiry?: boolean;
  /**
   * Record accepted `jti`s and reject one seen before. Consulted after the
   * signature verifies, so forged tokens never reach the store. A token with
   * no `jti` is rejected when a store is configured — there is nothing to
   * deduplicate on.
   */
  replayStore?: IdentityReplayStore;
  /** Claim carrying the agent id. Default `sub`. */
  agentIdClaim?: string;
  /**
   * Claim carrying capabilities. A string is split on whitespace, an array of
   * strings is taken as-is. Default: `scope`, then `scp` (Entra), then `roles`.
   */
  capabilitiesClaim?: string;
}

export type VerifyJwtResult =
  | { valid: true; agentId: string; identity: VerifyJwtIdentity }
  | { valid: false; reason: VerifyJwtFailureReason };

function fail(reason: VerifyJwtFailureReason): VerifyJwtResult {
  return { valid: false, reason };
}

// ─── Verification ────────────────────────────────────────────

/** Verify an externally issued JWT and map it onto a governance identity. */
export async function verifyJwt(token: string, options: VerifyJwtOptions = {}): Promise<VerifyJwtResult> {
  const parts = typeof token === "string" ? token.split(".") : [];
  const [rawHeader, rawPayload, rawSignature] = parts;
  if (parts.length !== 3 || rawHeader === undefined || rawPayload === undefined || rawSignature === undefined) {
    return fail("Malformed token");
  }

  const header = decodeJsonSegment(rawHeader);
  if (!isRecord(header) || typeof header.alg !== "string") return fail("Malformed token header");
  // `crit` names header parameters a verifier MUST understand (RFC 7515 §4.1.11).
  // We understand none of them, so its presence is a rejection, not a warning.
  if (header.crit !== undefined) return fail("Unsupported critical header");

  const allowed = options.allowedAlgorithms ?? JWT_ALGORITHMS;
  const alg = header.alg;
  // The header allowlist. `none` and every symmetric algorithm die here,
  // before any key is resolved — half the algorithm-confusion defence.
  if (!isJwtAlgorithm(alg) || !allowed.includes(alg)) return fail("Algorithm not allowed");

  const claims = decodeJsonSegment(rawPayload);
  if (!isRecord(claims)) return fail("Malformed token payload");

  const skew = options.clockSkewSeconds ?? 60;
  const nowSec = options.now ?? Math.floor(Date.now() / 1000);
  const claimFailure =
    checkTimes(claims, nowSec, skew, options.requireExpiry !== false) ??
    checkIssuer(claims, options.expectedIssuer) ??
    checkAudience(claims, options.expectedAudience);
  if (claimFailure) return fail(claimFailure);

  const resolveKey = options.resolveKey ?? (options.jwks ? createStaticKeyResolver(options.jwks) : undefined);
  if (!resolveKey) return fail("No verification key configured");
  let resolved: ResolvedVerificationKey | undefined;
  try {
    resolved = await resolveKey({ ...header, alg });
  } catch (err) {
    return fail(`Key resolution failed: ${(err as Error).message}`);
  }
  if (!resolved) return fail("No key resolved for kid");
  // The other half: a key verifies exactly one algorithm, derived from its own
  // key material, so a token claiming ES256 against an RSA key never reaches
  // `crypto.subtle.verify` — where a lenient implementation might oblige.
  if (resolved.alg !== alg) return fail("Algorithm mismatch between token and key");

  let signature: Uint8Array;
  try {
    signature = base64UrlToBytes(rawSignature);
  } catch {
    return fail("Malformed token");
  }
  const signingInput = new TextEncoder().encode(`${rawHeader}.${rawPayload}`);
  const ok = await crypto.subtle.verify(
    VERIFY_PARAMS[alg],
    resolved.key,
    toArrayBuffer(signature),
    toArrayBuffer(signingInput),
  );
  if (!ok) return fail("Invalid signature");

  const agentId = stringClaim(claims, options.agentIdClaim ?? "sub");
  if (agentId === undefined) return fail("Agent id claim missing");

  const jti = stringClaim(claims, "jti");
  if (options.replayStore) {
    if (jti === undefined) return fail("Token id missing");
    const exp = numberClaim(claims, "exp") ?? nowSec;
    // Only `await` when the store is async: a synchronous store's has→add
    // pair then runs with no interleaving window between check and record.
    const seen = options.replayStore.has(jti);
    if (typeof seen === "boolean" ? seen : await seen) return fail("Token replayed");
    await options.replayStore.add(jti, exp + skew);
  }

  return { valid: true, agentId, identity: buildIdentity(claims, agentId, alg, resolved.kid, options.capabilitiesClaim) };
}

