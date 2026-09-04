/**
 * governance-sdk — Key material for externally issued JWTs
 *
 * Which algorithms this verifier accepts and how a JWK becomes a Web Crypto
 * key. The live JWKS resolver is in `identity-jwks.ts`, verification itself in
 * `identity-jwt.ts`; each file stays under 300 LOC.
 *
 * Zero dependencies — `crypto.subtle` and `fetch` only, so this runs on Node
 * 20+, Deno, Bun and Cloudflare Workers unchanged.
 *
 * Only asymmetric algorithms are here on purpose. HMAC (`HS256`) is absent
 * because a verifier that accepts both a JWKS *and* a shared secret is the
 * classic algorithm-confusion hole: the IdP's public key, which is public,
 * doubles as the HMAC secret. There is no option to turn it on.
 */

// ─── Algorithms ──────────────────────────────────────────────

/**
 * Algorithms this verifier implements, and the only ones it will ever accept.
 * Everything else — `none`, `HS*`, `PS*`, `RS384`/`RS512`, `ES384`/`ES512` —
 * is rejected before a key is even resolved.
 */
export const JWT_ALGORITHMS = ["RS256", "ES256", "EdDSA"] as const;

export type JwtAlgorithm = (typeof JWT_ALGORITHMS)[number];

export function isJwtAlgorithm(value: unknown): value is JwtAlgorithm {
  return typeof value === "string" && (JWT_ALGORITHMS as readonly string[]).includes(value);
}

/** Decoded JOSE header. `alg` stays `string` — validating it is the point. */
export interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
  crit?: unknown;
  [claim: string]: unknown;
}

/** A JWK as it arrives over the wire — every member optional and unvalidated. */
export interface JsonWebKeyLike {
  kty?: string;
  crv?: string;
  alg?: string;
  use?: string;
  kid?: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
  [member: string]: unknown;
}

/** A JWKS document (RFC 7517 §5). */
export interface JsonWebKeySet {
  keys: JsonWebKeyLike[];
}

/** An imported verification key plus the one algorithm it is allowed to verify. */
export interface ResolvedVerificationKey {
  key: CryptoKey;
  alg: JwtAlgorithm;
  kid?: string;
}

/**
 * Produce the key a token's header points at, or `undefined` when there is
 * none — which the verifier reports as `"No key resolved for kid"`. Throwing
 * is reserved for "I could not tell": a network failure surfaces separately as
 * `"Key resolution failed: …"` so an operator can distinguish an unknown key
 * from an unreachable IdP.
 */
export type JwtKeyResolver = (
  header: JwtHeader,
) => Promise<ResolvedVerificationKey | undefined> | ResolvedVerificationKey | undefined;

// ─── JWK → CryptoKey ─────────────────────────────────────────

const IMPORT_PARAMS: Record<JwtAlgorithm, RsaHashedImportParams | EcKeyImportParams | AlgorithmIdentifier> = {
  RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  ES256: { name: "ECDSA", namedCurve: "P-256" },
  EdDSA: { name: "Ed25519" },
};

/** Parameters for `crypto.subtle.verify`, keyed by JWS algorithm. */
export const VERIFY_PARAMS: Record<JwtAlgorithm, EcdsaParams | AlgorithmIdentifier> = {
  RS256: { name: "RSASSA-PKCS1-v1_5" },
  ES256: { name: "ECDSA", hash: "SHA-256" },
  EdDSA: { name: "Ed25519" },
};

/**
 * The single algorithm a JWK's key material can verify, or `undefined` when
 * this verifier does not support it.
 *
 * The algorithm is derived from `kty`/`crv` — never taken on trust from the
 * JWK's own `alg` — and a declared `alg` that disagrees with the key material
 * disqualifies the key outright. That is the second half of the
 * algorithm-confusion defence: the first half is the header allowlist, this
 * half means a key can only ever be used one way.
 */
export function algorithmForJwk(jwk: JsonWebKeyLike): JwtAlgorithm | undefined {
  const derived: JwtAlgorithm | undefined =
    jwk.kty === "RSA" ? "RS256"
    : jwk.kty === "EC" && jwk.crv === "P-256" ? "ES256"
    : jwk.kty === "OKP" && jwk.crv === "Ed25519" ? "EdDSA"
    : undefined;
  if (derived === undefined) return undefined;
  if (jwk.alg !== undefined) {
    // RFC 8037 spells the Ed25519 JWS algorithm "EdDSA"; Web Crypto exports
    // the curve name. Accept both spellings, reject everything else.
    const declared = jwk.alg === "Ed25519" ? "EdDSA" : jwk.alg;
    if (declared !== derived) return undefined;
  }
  return derived;
}

/**
 * Import a public JWK for verification. Returns `undefined` for a key this
 * verifier cannot use (unsupported type, an encryption key, a declared `alg`
 * that contradicts the key material); throws only if Web Crypto rejects
 * otherwise-plausible key material.
 */
export async function importJwk(jwk: JsonWebKeyLike): Promise<ResolvedVerificationKey | undefined> {
  if (jwk.use !== undefined && jwk.use !== "sig") return undefined;
  const alg = algorithmForJwk(jwk);
  if (alg === undefined) return undefined;
  // Rebuild the JWK from its public members only. Anything else a document
  // carries — `d`, `key_ops`, `use`, a contradictory `alg` — is dropped rather
  // than handed to Web Crypto, so a private key smuggled into a JWKS cannot
  // be imported and a stray member cannot fail an otherwise valid key.
  const material: JsonWebKey = {
    kty: jwk.kty,
    ...(jwk.crv !== undefined ? { crv: jwk.crv } : {}),
    ...(jwk.n !== undefined ? { n: jwk.n } : {}),
    ...(jwk.e !== undefined ? { e: jwk.e } : {}),
    ...(jwk.x !== undefined ? { x: jwk.x } : {}),
    ...(jwk.y !== undefined ? { y: jwk.y } : {}),
    ext: true,
  };
  const key = await crypto.subtle.importKey("jwk", material, IMPORT_PARAMS[alg], false, ["verify"]);
  return { key, alg, ...(typeof jwk.kid === "string" ? { kid: jwk.kid } : {}) };
}

/**
 * Resolve keys from a JWKS document you already hold — a bundled key set, a
 * key pinned in config, or a document you refresh yourself. No network.
 */
export function createStaticKeyResolver(jwks: JsonWebKeySet): JwtKeyResolver {
  const cache: KeyCache = new Map();
  let loaded = false;
  return async (header: JwtHeader): Promise<ResolvedVerificationKey | undefined> => {
    if (!loaded) {
      for (const jwk of jwks.keys ?? []) {
        const imported = await importJwk(jwk).catch(() => undefined);
        if (imported) cache.set(cacheKeyFor(jwk, imported), { key: imported, fetchedAt: 0 });
      }
      loaded = true;
    }
    return lookupIn(cache, header);
  };
}

// ─── Internals ───────────────────────────────────────────────

/**
 * Cache id for a key: its `kid`, or — for a kid-less JWK — a stable id from
 * the public key material itself. Two distinct kid-less keys must never share
 * an id (the later one would silently replace the earlier and a lookup would
 * verify against the wrong key), and the same key fetched twice must (or a
 * kid-less JWKS would accumulate duplicates and every lookup would fail as
 * ambiguous).
 */
export function cacheKeyFor(jwk: JsonWebKeyLike, key: ResolvedVerificationKey): string {
  if (key.kid !== undefined) return key.kid;
  return ["", key.alg, jwk.kty, jwk.crv, jwk.x, jwk.y, jwk.n, jwk.e].map((v) => v ?? "").join("|");
}

/** Shared by the static and JWKS-backed resolvers. */
export type KeyCache = Map<string, { key: ResolvedVerificationKey; fetchedAt: number }>;

export function lookupIn(cache: KeyCache, header: JwtHeader): ResolvedVerificationKey | undefined {
  if (typeof header.kid === "string") return cache.get(header.kid)?.key;
  // No `kid`: usable only when exactly one cached key could have signed this
  // token. With two candidates, picking one is a guess — reject instead.
  const matches = [...cache.values()].map((e) => e.key).filter((k) => k.alg === header.alg);
  return matches.length === 1 ? matches[0] : undefined;
}

