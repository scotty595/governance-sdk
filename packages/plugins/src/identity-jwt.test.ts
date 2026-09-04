/**
 * Security tests for the external-JWT verifier: happy path per algorithm,
 * then structure, algorithm-confusion, key and signature rejections. Claim
 * checks and mapping are in `identity-jwt-claims.test.ts`. Every key is
 * generated here with `crypto.subtle.generateKey`; every rejection is
 * asserted on its typed reason, never on `valid === false` alone.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { verifyJwt, type JsonWebKeyLike, type JwtAlgorithm, type VerifyJwtOptions } from "./identity-jwt.js";

// ─── Minting helpers (test-only; the SDK never signs external tokens) ──

interface Signer { alg: JwtAlgorithm; privateKey: CryptoKey; jwk: JsonWebKeyLike }

const SIGN_PARAMS: Record<JwtAlgorithm, EcdsaParams | AlgorithmIdentifier> = {
  RS256: { name: "RSASSA-PKCS1-v1_5" },
  ES256: { name: "ECDSA", hash: "SHA-256" },
  EdDSA: { name: "Ed25519" },
};

async function generateSigner(alg: JwtAlgorithm, kid: string): Promise<Signer> {
  const pair =
    alg === "RS256"
      ? await crypto.subtle.generateKey(
          { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
          true, ["sign", "verify"],
        )
      : alg === "ES256"
        ? await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
        : await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKeyLike;
  return { alg, privateKey: pair.privateKey, jwk: { ...jwk, kid } };
}

const enc = new TextEncoder();
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const segment = (obj: unknown): string => b64url(enc.encode(JSON.stringify(obj)));

async function mint(signer: Signer, payload: Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
  const h = segment({ alg: signer.alg, typ: "JWT", kid: signer.jwk.kid, ...header });
  const p = segment(payload);
  const sig = await crypto.subtle.sign(SIGN_PARAMS[signer.alg], signer.privateKey, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`;
}

const NOW = 1_800_000_000;
const ISS = "https://login.example.com/";
const AUD = "orders-api";
const claims = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  iss: ISS, sub: "agent-42", aud: AUD, iat: NOW, exp: NOW + 300, jti: "t-1", ...extra,
});

const rs = await generateSigner("RS256", "rs-1");
const es = await generateSigner("ES256", "es-1");
const ed = await generateSigner("EdDSA", "ed-1");
const jwks = { keys: [rs.jwk, es.jwk, ed.jwk] };
const base: VerifyJwtOptions = { jwks, expectedIssuer: ISS, expectedAudience: AUD, now: NOW };

async function reasonOf(token: string, opts: VerifyJwtOptions = base): Promise<string | undefined> {
  const r = await verifyJwt(token, opts);
  return r.valid ? undefined : r.reason;
}

// ─── Happy paths ─────────────────────────────────────────────

describe("verifyJwt — happy path per algorithm", () => {
  for (const signer of [rs, es, ed]) {
    it(`verifies a ${signer.alg} token and maps the identity`, async () => {
      const result = await verifyJwt(await mint(signer, claims({ scope: "read write" })), base);
      assert.equal(result.valid, true);
      if (!result.valid) return;
      assert.equal(result.agentId, "agent-42");
      assert.equal(result.identity.algorithm, signer.alg);
      assert.equal(result.identity.kid, signer.jwk.kid);
      assert.deepEqual(result.identity.capabilities, ["read", "write"]);
      assert.equal(result.identity.issuer, ISS);
      assert.deepEqual(result.identity.audience, [AUD]);
      assert.equal(result.identity.expiresAt, NOW + 300);
      assert.equal(result.identity.jti, "t-1");
    });
  }

  it("accepts Web Crypto's `alg: \"Ed25519\"` JWK spelling as well as RFC 8037's EdDSA", async () => {
    assert.equal(ed.jwk.alg, "Ed25519"); // what Node exports
    const rfc = { keys: [{ ...ed.jwk, alg: "EdDSA" }] };
    assert.equal(await reasonOf(await mint(ed, claims()), { ...base, jwks: rfc }), undefined);
  });

  it("accepts any one of several expected audiences / issuers", async () => {
    const token = await mint(ed, claims());
    const r = await verifyJwt(token, { ...base, expectedAudience: ["other", AUD], expectedIssuer: ["x", ISS] });
    assert.equal(r.valid, true);
  });

  it("matches an `aud` array against the expected audience", async () => {
    assert.equal(await reasonOf(await mint(ed, claims({ aud: ["billing", AUD] }))), undefined);
  });
});

// ─── Rejections: structure, algorithm, keys, signature ───────

describe("verifyJwt — structure and algorithm", () => {
  it("rejects a malformed token", async () => {
    assert.equal(await reasonOf("not-a-jwt"), "Malformed token");
    assert.equal(await reasonOf("a.b"), "Malformed token");
    assert.equal(await reasonOf("a.b.c.d"), "Malformed token");
    assert.equal(await reasonOf(""), "Malformed token");
  });

  it("rejects a header that is not JSON or has no `alg`", async () => {
    assert.equal(await reasonOf(`${b64url(enc.encode("{"))}.${segment(claims())}.x`), "Malformed token header");
    assert.equal(await reasonOf(`${segment({ kid: "rs-1" })}.${segment(claims())}.x`), "Malformed token header");
  });

  it("rejects a payload that is not a JSON object", async () => {
    const h = segment({ alg: "EdDSA", kid: "ed-1" });
    assert.equal(await reasonOf(`${h}.${segment([1, 2])}.x`), "Malformed token payload");
    assert.equal(await reasonOf(`${h}.${b64url(enc.encode("nope"))}.x`), "Malformed token payload");
  });

  it("rejects `alg: none` — with and without a signature segment", async () => {
    const h = segment({ alg: "none", kid: "ed-1" });
    assert.equal(await reasonOf(`${h}.${segment(claims())}.`), "Algorithm not allowed");
    assert.equal(await reasonOf(`${h}.${segment(claims())}.${b64url(new Uint8Array([1]))}`), "Algorithm not allowed");
  });

  it("rejects HS256 signed with the RSA public key — the classic algorithm confusion", async () => {
    const h = segment({ alg: "HS256", kid: "rs-1" });
    const p = segment(claims());
    const secret = await crypto.subtle.importKey(
      "raw", enc.encode(JSON.stringify(rs.jwk)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
    );
    const mac = await crypto.subtle.sign("HMAC", secret, enc.encode(`${h}.${p}`));
    assert.equal(await reasonOf(`${h}.${p}.${b64url(new Uint8Array(mac))}`), "Algorithm not allowed");
  });

  it("rejects an allowed algorithm whose key material is something else", async () => {
    // Header says ES256 and points at the RSA key. The signature is a real
    // ES256 signature, so only the key/alg binding stands in the way.
    const token = await mint(es, claims(), { kid: "rs-1" });
    assert.equal(await reasonOf(token), "Algorithm mismatch between token and key");
  });

  it("honours a narrowed `allowedAlgorithms`", async () => {
    const token = await mint(es, claims());
    assert.equal(await reasonOf(token, { ...base, allowedAlgorithms: ["RS256", "EdDSA"] }), "Algorithm not allowed");
  });

  it("rejects a `crit` header it does not understand", async () => {
    const token = await mint(ed, claims(), { crit: ["b64"], b64: false });
    assert.equal(await reasonOf(token), "Unsupported critical header");
  });
});

describe("verifyJwt — keys and signatures", () => {
  it("rejects when no key source is configured", async () => {
    const token = await mint(ed, claims());
    assert.equal(await reasonOf(token, { expectedIssuer: ISS, expectedAudience: AUD, now: NOW }), "No verification key configured");
  });

  it("rejects an unknown kid", async () => {
    const token = await mint(ed, claims(), { kid: "ed-rotated" });
    assert.equal(await reasonOf(token), "No key resolved for kid");
  });

  it("surfaces a throwing resolver as a resolution failure, not an unknown kid", async () => {
    const token = await mint(ed, claims());
    const reason = await reasonOf(token, { ...base, resolveKey: () => { throw new Error("IdP down"); } });
    assert.equal(reason, "Key resolution failed: IdP down");
  });

  it("rejects a JWKS key that does not match the signer (same kid, different key)", async () => {
    const impostor = await generateSigner("EdDSA", "ed-1");
    const token = await mint(impostor, claims());
    assert.equal(await reasonOf(token), "Invalid signature");
  });

  it("rejects a tampered signature and a tampered payload", async () => {
    const token = await mint(rs, claims());
    const [h, p, s] = token.split(".") as [string, string, string];
    const flipped = (s.startsWith("A") ? "B" : "A") + s.slice(1);
    assert.equal(await reasonOf(`${h}.${p}.${flipped}`), "Invalid signature");
    assert.equal(await reasonOf(`${h}.${segment(claims({ sub: "someone-else" }))}.${s}`), "Invalid signature");
  });

  it("rejects a signature segment that is not base64url", async () => {
    const [h, p] = (await mint(ed, claims())).split(".") as [string, string, string];
    assert.equal(await reasonOf(`${h}.${p}.not+base64/url=`), "Malformed token");
  });

  it("uses a kid-less JWKS only when exactly one key could have signed", async () => {
    const one = { keys: [{ ...ed.jwk, kid: undefined }] };
    const two = { keys: [{ ...ed.jwk, kid: undefined }, { ...(await generateSigner("EdDSA", "x")).jwk, kid: undefined }] };
    const token = await mint(ed, claims(), { kid: undefined });
    assert.equal(await reasonOf(token, { ...base, jwks: one }), undefined);
    assert.equal(await reasonOf(token, { ...base, jwks: two }), "No key resolved for kid");
  });

  it("skips JWKS keys that are for encryption or whose `alg` contradicts their type", async () => {
    const token = await mint(ed, claims());
    assert.equal(await reasonOf(token, { ...base, jwks: { keys: [{ ...ed.jwk, use: "enc" }] } }), "No key resolved for kid");
    assert.equal(await reasonOf(token, { ...base, jwks: { keys: [{ ...ed.jwk, alg: "RS256" }] } }), "No key resolved for kid");
  });
});
