/**
 * governance-sdk — Claim mapping and claim checks for externally issued JWTs
 *
 * The half of `identity-jwt.ts` that reads a decoded payload: time, issuer and
 * audience checks, the claims→governance-identity map, and the on-behalf-of
 * chain. Split out to keep each file under 300 LOC.
 */

import type { JwtAlgorithm } from "./identity-jwt-keys.js";

// ─── Delegation ──────────────────────────────────────────────

/** One hop of an RFC 8693 `act` chain. Unknown members are carried verbatim. */
export interface JwtDelegationActor {
  /** Who is acting. */
  sub?: string;
  /** The next hop out, for a multi-party chain (RFC 8693 §4.1). */
  act?: JwtDelegationActor;
  [claim: string]: unknown;
}

/**
 * On-behalf-of claims, carried through so an audit event can record who
 * authorised what. This is the part enterprises are standardising on: an agent
 * acting for a user acting for a tenant is three principals, and "the agent
 * did it" is not an answer a regulator accepts.
 */
export interface JwtDelegation {
  /** RFC 8693 `act` — the immediate actor, possibly nesting further. */
  act?: JwtDelegationActor;
  /** OIDC `azp` — the authorised party the token was issued to. */
  azp?: string;
  /** A non-standard `actor` claim, carried verbatim when an IdP emits one. */
  actor?: unknown;
  /** The `act` chain flattened, nearest actor first. Depth-capped. */
  chain: string[];
}

/** How deep an `act` chain is walked before it is treated as hostile. */
const MAX_DELEGATION_DEPTH = 10;

/** The governance identity a verified token maps onto. */
export interface VerifyJwtIdentity {
  /** From `agentIdClaim` (default `sub`). */
  agentId: string;
  /** From `capabilitiesClaim`, normalised to a string array. */
  capabilities: string[];
  issuer?: string;
  audience?: string[];
  subject?: string;
  issuedAt?: number;
  expiresAt?: number;
  notBefore?: number;
  jti?: string;
  kid?: string;
  /** The algorithm the signature was actually verified with. */
  algorithm: JwtAlgorithm;
  /** Present only when the token carried `act`, `azp` or `actor`. */
  delegation?: JwtDelegation;
  /** Every claim, verbatim — for an audit event, or a claim this map missed. */
  claims: Readonly<Record<string, unknown>>;
}

/** Every `reason` a failed verification can carry — match on these, not prose. */
export type VerifyJwtFailureReason =
  | "Malformed token"
  | "Malformed token header"
  | "Malformed token payload"
  | "Unsupported critical header"
  | "Algorithm not allowed"
  | "Algorithm mismatch between token and key"
  | "No verification key configured"
  | "No key resolved for kid"
  | `Key resolution failed: ${string}`
  | "Invalid signature"
  | "Expiry missing"
  | "Token expired"
  | "Token not yet valid"
  | "Token issued in the future"
  | "Issuer missing"
  | "Issuer mismatch"
  | "Audience missing"
  | "Audience unexpected"
  | "Audience mismatch"
  | "Agent id claim missing"
  | "Token id missing"
  | "Token replayed";

// ─── Claim mapping ───────────────────────────────────────────

export function buildIdentity(
  claims: Record<string, unknown>,
  agentId: string,
  algorithm: JwtAlgorithm,
  kid: string | undefined,
  capabilitiesClaim: string | undefined,
): VerifyJwtIdentity {
  const issuer = stringClaim(claims, "iss");
  const subject = stringClaim(claims, "sub");
  const audience = audienceList(claims.aud);
  const issuedAt = numberClaim(claims, "iat");
  const expiresAt = numberClaim(claims, "exp");
  const notBefore = numberClaim(claims, "nbf");
  const jti = stringClaim(claims, "jti");
  const delegation = readDelegation(claims);
  return {
    agentId,
    capabilities: readCapabilities(claims, capabilitiesClaim),
    algorithm,
    claims: Object.freeze({ ...claims }),
    ...(issuer !== undefined ? { issuer } : {}),
    ...(subject !== undefined ? { subject } : {}),
    ...(audience !== undefined ? { audience } : {}),
    ...(issuedAt !== undefined ? { issuedAt } : {}),
    ...(expiresAt !== undefined ? { expiresAt } : {}),
    ...(notBefore !== undefined ? { notBefore } : {}),
    ...(jti !== undefined ? { jti } : {}),
    ...(kid !== undefined ? { kid } : {}),
    ...(delegation !== undefined ? { delegation } : {}),
  };
}

/** `scope` / `scp` are space-delimited strings; `roles` is an array. */
function readCapabilities(claims: Record<string, unknown>, claimName: string | undefined): string[] {
  const names = claimName !== undefined ? [claimName] : ["scope", "scp", "roles"];
  for (const name of names) {
    const raw = claims[name];
    if (typeof raw === "string") {
      const parts = raw.split(/\s+/).filter((s) => s.length > 0);
      if (parts.length > 0) return parts;
    }
    if (Array.isArray(raw)) {
      const parts = raw.filter((v): v is string => typeof v === "string" && v.length > 0);
      if (parts.length > 0) return parts;
    }
  }
  return [];
}

function readDelegation(claims: Record<string, unknown>): JwtDelegation | undefined {
  const act = isRecord(claims.act) ? (claims.act as JwtDelegationActor) : undefined;
  const azp = stringClaim(claims, "azp");
  const actor = claims.actor;
  if (act === undefined && azp === undefined && actor === undefined) return undefined;
  const chain: string[] = [];
  let hop: JwtDelegationActor | undefined = act;
  // Depth-capped: a token is attacker-supplied JSON, and an `act` nested a
  // thousand deep is a denial-of-service, not a delegation chain.
  for (let depth = 0; hop !== undefined && depth < MAX_DELEGATION_DEPTH; depth++) {
    if (typeof hop.sub === "string") chain.push(hop.sub);
    hop = isRecord(hop.act) ? (hop.act as JwtDelegationActor) : undefined;
  }
  return {
    chain,
    ...(act !== undefined ? { act } : {}),
    ...(azp !== undefined ? { azp } : {}),
    ...(actor !== undefined ? { actor } : {}),
  };
}

// ─── Claim checks ────────────────────────────────────────────

export function checkTimes(
  claims: Record<string, unknown>,
  nowSec: number,
  skew: number,
  requireExpiry: boolean,
): VerifyJwtFailureReason | undefined {
  // A non-numeric `exp` reads as absent, so a token carrying `exp: "soon"`
  // fails on "Expiry missing" rather than quietly never expiring.
  const exp = numberClaim(claims, "exp");
  if (exp === undefined) {
    if (requireExpiry) return "Expiry missing";
  } else if (exp + skew < nowSec) return "Token expired";

  const nbf = numberClaim(claims, "nbf");
  if (nbf !== undefined && nbf - skew > nowSec) return "Token not yet valid";
  const iat = numberClaim(claims, "iat");
  if (iat !== undefined && iat - skew > nowSec) return "Token issued in the future";
  return undefined;
}

export function checkIssuer(
  claims: Record<string, unknown>,
  expected: string | string[] | undefined,
): VerifyJwtFailureReason | undefined {
  if (expected === undefined) return undefined;
  const iss = stringClaim(claims, "iss");
  if (iss === undefined) return "Issuer missing";
  return toList(expected).includes(iss) ? undefined : "Issuer mismatch";
}

export function checkAudience(
  claims: Record<string, unknown>,
  expected: string | string[] | undefined,
): VerifyJwtFailureReason | undefined {
  const present = audienceList(claims.aud);
  if (expected === undefined) {
    // A token addressed to someone must not verify at a party that never said
    // who it is — otherwise a token for service A works at service B.
    return present === undefined ? undefined : "Audience unexpected";
  }
  if (present === undefined) return "Audience missing";
  const want = toList(expected);
  return present.some((a) => want.includes(a)) ? undefined : "Audience mismatch";
}

// ─── Internals ───────────────────────────────────────────────

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function stringClaim(claims: Record<string, unknown>, name: string): string | undefined {
  const v = claims[name];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

export function numberClaim(claims: Record<string, unknown>, name: string): number | undefined {
  const v = claims[name];
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function audienceList(aud: unknown): string[] | undefined {
  if (typeof aud === "string") return [aud];
  if (Array.isArray(aud)) {
    const list = aud.filter((v): v is string => typeof v === "string");
    return list.length > 0 ? list : undefined;
  }
  return undefined;
}

function toList(value: string | string[]): string[] {
  return typeof value === "string" ? [value] : value;
}

/** base64url segment → parsed JSON, or `undefined` when either step fails. */
export function decodeJsonSegment(segment: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment)));
  } catch {
    return undefined;
  }
}

/** base64url → bytes. Throws on anything that is not strict base64url. */
export function base64UrlToBytes(input: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(input)) throw new Error("not base64url");
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (input.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Web Crypto wants a BufferSource; copy so a view over a larger buffer is safe. */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
