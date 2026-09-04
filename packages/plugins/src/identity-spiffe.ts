/**
 * governance-sdk — SPIFFE identity
 *
 * SPIFFE is the workload-identity substrate underneath most of the agent
 * identity products enterprises are standing up, so a governance layer that
 * verifies Entra and Okta tokens but not SVIDs still leaves half the fleet
 * unverifiable. This module parses and validates SPIFFE IDs per the spec and
 * verifies **JWT-SVIDs** on top of `verifyJwt`.
 *
 * **X.509-SVIDs are not supported, and will not be.** Verifying one means
 * validating a certificate chain against a trust bundle — path building,
 * signature verification at each link, validity windows, basic constraints,
 * SAN URI extraction. Web Crypto provides none of that: it verifies a
 * signature over bytes and knows nothing about X.509. Implementing it here
 * would mean either a dependency (this package has none) or a hand-rolled
 * chain validator, which is exactly the code you do not want hand-rolled.
 * Terminate X.509-SVID mTLS at your proxy or SPIRE agent and pass the
 * validated SPIFFE ID in; {@link parseSpiffeId} will check its shape.
 *
 * Zero dependencies — `crypto.subtle` and `fetch` only. Node 20+, Deno, Bun,
 * Cloudflare Workers.
 *
 * @example
 * ```ts
 * import { verifyJwtSvid } from '@governance-sdk/plugins/identity-spiffe.js';
 *
 * const result = await verifyJwtSvid(svid, {
 *   resolveKey,                       // SPIRE's JWKS bundle endpoint
 *   audience: 'spiffe://example.org/orders-api',
 *   trustDomain: 'example.org',
 * });
 * if (result.valid) console.log(result.agentId); // example.org/ns/prod/sa/billing
 * ```
 */

import { verifyJwt, type VerifyJwtIdentity, type VerifyJwtOptions } from "./identity-jwt.js";
import type { VerifyJwtFailureReason } from "./identity-jwt-claims.js";

// ─── SPIFFE IDs ──────────────────────────────────────────────

/** A SPIFFE ID must fit in 2048 bytes (SPIFFE-ID §2). */
const MAX_ID_BYTES = 2048;
/** …of which the trust domain may use at most 255 (SPIFFE-ID §2.1). */
const MAX_TRUST_DOMAIN_BYTES = 255;
const SCHEME = "spiffe://";

/** Trust domains are lowercase: letters, digits, dots, dashes, underscores. */
const TRUST_DOMAIN_RE = /^[a-z0-9.\-_]+$/;
/** Path segments allow the same set, with uppercase (SPIFFE-ID §2.2). */
const PATH_SEGMENT_RE = /^[A-Za-z0-9.\-_]+$/;

export interface ParsedSpiffeId {
  /** The full `spiffe://…` URI as supplied. */
  uri: string;
  /** e.g. `example.org`. */
  trustDomain: string;
  /** Leading slash included, e.g. `/ns/prod/sa/billing`. Empty for a trust-domain ID. */
  path: string;
  /** Path segments with no leading slash. */
  segments: string[];
}

/** Every `reason` a SPIFFE ID can be rejected for — match on these, not prose. */
export type SpiffeIdFailureReason =
  | "SPIFFE ID is not a string"
  | "SPIFFE ID is too long"
  | "SPIFFE ID must use the spiffe:// scheme"
  | "SPIFFE ID must not contain a query"
  | "SPIFFE ID must not contain a fragment"
  | "SPIFFE ID must not contain userinfo"
  | "SPIFFE ID must not contain a port"
  | "SPIFFE ID trust domain is empty"
  | "SPIFFE ID trust domain is too long"
  | "SPIFFE ID trust domain has invalid characters"
  | "SPIFFE ID path is empty"
  | "SPIFFE ID path segment is empty"
  | "SPIFFE ID path segment is a relative modifier"
  | "SPIFFE ID path has invalid characters";

export type ParseSpiffeIdResult =
  | { valid: true; id: ParsedSpiffeId }
  | { valid: false; reason: SpiffeIdFailureReason };

export interface ParseSpiffeIdOptions {
  /**
   * Accept `spiffe://example.org` with no path. That names a *trust domain*,
   * not a workload, so it is rejected by default — an SVID must identify one.
   */
  allowTrustDomainOnly?: boolean;
}

/**
 * Parse and validate a SPIFFE ID per the SPIFFE-ID specification.
 *
 * Hand-rolled rather than delegated to `URL`, deliberately: `URL` normalises
 * (percent-decoding, case folding, `..` collapsing) and tolerates userinfo and
 * ports, so `spiffe://user@example.org:8443/a/../b` would parse and then not
 * mean what it says. An identity is compared as a string; anything that could
 * make two different strings compare equal is a vulnerability, not a nicety.
 */
export function parseSpiffeId(value: unknown, options: ParseSpiffeIdOptions = {}): ParseSpiffeIdResult {
  if (typeof value !== "string") return bad("SPIFFE ID is not a string");
  if (byteLength(value) > MAX_ID_BYTES) return bad("SPIFFE ID is too long");
  if (!value.startsWith(SCHEME)) return bad("SPIFFE ID must use the spiffe:// scheme");

  const rest = value.slice(SCHEME.length);
  if (rest.includes("?")) return bad("SPIFFE ID must not contain a query");
  if (rest.includes("#")) return bad("SPIFFE ID must not contain a fragment");

  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? "" : rest.slice(slash);

  if (authority.includes("@")) return bad("SPIFFE ID must not contain userinfo");
  if (authority.includes(":")) return bad("SPIFFE ID must not contain a port");
  if (authority.length === 0) return bad("SPIFFE ID trust domain is empty");
  if (byteLength(authority) > MAX_TRUST_DOMAIN_BYTES) return bad("SPIFFE ID trust domain is too long");
  if (!TRUST_DOMAIN_RE.test(authority)) return bad("SPIFFE ID trust domain has invalid characters");

  if (path.length === 0) {
    if (options.allowTrustDomainOnly !== true) return bad("SPIFFE ID path is empty");
    return { valid: true, id: { uri: value, trustDomain: authority, path: "", segments: [] } };
  }

  const segments = path.slice(1).split("/");
  for (const segment of segments) {
    // A trailing or doubled slash lands here, as does `%2e` — which is a path
    // that would be a dot-segment after decoding, so it never gets to decode.
    if (segment.length === 0) return bad("SPIFFE ID path segment is empty");
    if (segment === "." || segment === "..") return bad("SPIFFE ID path segment is a relative modifier");
    if (!PATH_SEGMENT_RE.test(segment)) return bad("SPIFFE ID path has invalid characters");
  }
  return { valid: true, id: { uri: value, trustDomain: authority, path, segments } };
}

/**
 * The SDK `agentId` for a SPIFFE ID: the URI with its scheme stripped, e.g.
 * `spiffe://example.org/ns/prod/sa/billing` → `example.org/ns/prod/sa/billing`.
 *
 * Trust domain first, so ids stay unique across domains and sort together per
 * domain in an audit query. Use `identity.subject` when you want the full URI.
 */
export function spiffeIdToAgentId(id: string | ParsedSpiffeId): string {
  const uri = typeof id === "string" ? id : id.uri;
  return uri.startsWith(SCHEME) ? uri.slice(SCHEME.length) : uri;
}

// ─── JWT-SVID ────────────────────────────────────────────────

export interface VerifyJwtSvidOptions extends Omit<VerifyJwtOptions, "expectedAudience" | "agentIdClaim"> {
  /**
   * Mandatory. A JWT-SVID's `aud` is what stops one workload replaying another
   * service's SVID at you, so unlike {@link verifyJwt} there is no way to skip it.
   */
  audience: string | string[];
  /** Trust domain(s) the subject must belong to — bare, no `spiffe://`. */
  trustDomain: string | string[];
}

export type VerifyJwtSvidFailureReason =
  | VerifyJwtFailureReason
  | SpiffeIdFailureReason
  | "Audience required for a JWT-SVID"
  | "Trust domain required for a JWT-SVID"
  | "Trust domain mismatch";

export type VerifyJwtSvidResult =
  | { valid: true; agentId: string; spiffeId: ParsedSpiffeId; identity: VerifyJwtIdentity }
  | { valid: false; reason: VerifyJwtSvidFailureReason };

/**
 * Verify a SPIFFE JWT-SVID.
 *
 * Everything {@link verifyJwt} does, plus the three things the JWT-SVID spec
 * adds: `aud` is mandatory, `sub` must be a valid workload SPIFFE ID, and its
 * trust domain must be one you expect. `exp` is required (the `verifyJwt`
 * default) because the spec requires it too.
 */
export async function verifyJwtSvid(
  token: string,
  options: VerifyJwtSvidOptions,
): Promise<VerifyJwtSvidResult> {
  const { audience, trustDomain, ...jwtOptions } = options;
  const audiences = toList(audience);
  if (audiences.length === 0) return { valid: false, reason: "Audience required for a JWT-SVID" };
  const domains = toList(trustDomain);
  if (domains.length === 0) return { valid: false, reason: "Trust domain required for a JWT-SVID" };

  const result = await verifyJwt(token, { ...jwtOptions, expectedAudience: audiences });
  if (!result.valid) return { valid: false, reason: result.reason };

  // `sub` specifically, not `agentId`: the SVID spec names the claim, and
  // `agentIdClaim` is deliberately not overridable on this path.
  const parsed = parseSpiffeId(result.identity.subject);
  if (!parsed.valid) return { valid: false, reason: parsed.reason };
  if (!domains.includes(parsed.id.trustDomain)) return { valid: false, reason: "Trust domain mismatch" };

  const agentId = spiffeIdToAgentId(parsed.id);
  return { valid: true, agentId, spiffeId: parsed.id, identity: { ...result.identity, agentId } };
}

// ─── Internals ───────────────────────────────────────────────

function bad(reason: SpiffeIdFailureReason): ParseSpiffeIdResult {
  return { valid: false, reason };
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

function toList(value: string | string[]): string[] {
  return typeof value === "string" ? [value] : [...value];
}
