/**
 * SPIFFE ID parsing is a string-equality identity check, so every form the
 * spec forbids is tested separately — each with its own reason — and the
 * JWT-SVID verifier is tested for the three things it adds over verifyJwt.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseSpiffeId, spiffeIdToAgentId, verifyJwtSvid, type SpiffeIdFailureReason } from "./identity-spiffe.js";
import type { JsonWebKeyLike } from "./identity-jwt.js";

const enc = new TextEncoder();
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const jwk = { ...((await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKeyLike), kid: "spire-1" };
async function mintSvid(payload: Record<string, unknown>): Promise<string> {
  const h = b64url(enc.encode(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: "spire-1" })));
  const p = b64url(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`;
}

const NOW = 1_800_000_000;
const SUB = "spiffe://example.org/ns/prod/sa/billing";
const svidClaims = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  sub: SUB, aud: "spiffe://example.org/orders-api", iat: NOW, exp: NOW + 300, ...extra,
});
const base = { jwks: { keys: [jwk] }, audience: "spiffe://example.org/orders-api", trustDomain: "example.org", now: NOW };

function reasonOf(value: unknown, allowTrustDomainOnly = false): SpiffeIdFailureReason | undefined {
  const r = parseSpiffeId(value, { allowTrustDomainOnly });
  return r.valid ? undefined : r.reason;
}

describe("parseSpiffeId — valid forms", () => {
  it("parses a workload id into trust domain, path and segments", () => {
    const r = parseSpiffeId(SUB);
    assert.equal(r.valid, true);
    if (!r.valid) return;
    assert.equal(r.id.uri, SUB);
    assert.equal(r.id.trustDomain, "example.org");
    assert.equal(r.id.path, "/ns/prod/sa/billing");
    assert.deepEqual(r.id.segments, ["ns", "prod", "sa", "billing"]);
  });

  it("accepts every character class the spec allows", () => {
    assert.equal(reasonOf("spiffe://a-b_c.d9/Path.With-Mixed_CASE9"), undefined);
    assert.equal(reasonOf("spiffe://example.org/.hidden/..dots/a..b"), undefined);
  });

  it("accepts a trust-domain-only id only when asked to", () => {
    assert.equal(reasonOf("spiffe://example.org"), "SPIFFE ID path is empty");
    const r = parseSpiffeId("spiffe://example.org", { allowTrustDomainOnly: true });
    assert.equal(r.valid, true);
    if (r.valid) assert.deepEqual([r.id.path, r.id.segments], ["", []]);
  });
});

describe("parseSpiffeId — every invalid form, each with its own reason", () => {
  it("not a string", () => {
    assert.equal(reasonOf(undefined), "SPIFFE ID is not a string");
    assert.equal(reasonOf({ toString: () => SUB }), "SPIFFE ID is not a string");
  });

  it("too long", () => {
    assert.equal(reasonOf(`spiffe://example.org/${"a".repeat(2048)}`), "SPIFFE ID is too long");
    assert.equal(reasonOf(`spiffe://example.org/${"a".repeat(2048 - "spiffe://example.org/".length)}`), undefined);
  });

  it("wrong scheme — including case variants and a missing authority marker", () => {
    for (const bad of ["https://example.org/x", "SPIFFE://example.org/x", "spiffe:/example.org/x", "spiffe:example.org/x", "example.org/x"]) {
      assert.equal(reasonOf(bad), "SPIFFE ID must use the spiffe:// scheme", bad);
    }
  });

  it("query and fragment", () => {
    assert.equal(reasonOf("spiffe://example.org/x?y=1"), "SPIFFE ID must not contain a query");
    assert.equal(reasonOf("spiffe://example.org?x"), "SPIFFE ID must not contain a query");
    assert.equal(reasonOf("spiffe://example.org/x#frag"), "SPIFFE ID must not contain a fragment");
  });

  it("userinfo and port", () => {
    assert.equal(reasonOf("spiffe://alice@example.org/x"), "SPIFFE ID must not contain userinfo");
    assert.equal(reasonOf("spiffe://example.org:8443/x"), "SPIFFE ID must not contain a port");
  });

  it("trust domain: empty, too long, invalid characters", () => {
    assert.equal(reasonOf("spiffe:///x"), "SPIFFE ID trust domain is empty");
    assert.equal(reasonOf("spiffe://"), "SPIFFE ID trust domain is empty");
    assert.equal(reasonOf(`spiffe://${"a".repeat(256)}/x`), "SPIFFE ID trust domain is too long");
    assert.equal(reasonOf(`spiffe://${"a".repeat(255)}/x`), undefined);
    for (const bad of ["Example.org", "exam ple.org", "ex%61mple.org", "exämple.org", "example.org\\x"]) {
      assert.equal(reasonOf(`spiffe://${bad}/x`), "SPIFFE ID trust domain has invalid characters", bad);
    }
  });

  it("path: empty segments from trailing or doubled slashes", () => {
    assert.equal(reasonOf("spiffe://example.org/"), "SPIFFE ID path segment is empty");
    assert.equal(reasonOf("spiffe://example.org/a/"), "SPIFFE ID path segment is empty");
    assert.equal(reasonOf("spiffe://example.org/a//b"), "SPIFFE ID path segment is empty");
  });

  it("path: relative modifiers are rejected, not resolved", () => {
    assert.equal(reasonOf("spiffe://example.org/a/../b"), "SPIFFE ID path segment is a relative modifier");
    assert.equal(reasonOf("spiffe://example.org/./a"), "SPIFFE ID path segment is a relative modifier");
    assert.equal(reasonOf("spiffe://example.org/.."), "SPIFFE ID path segment is a relative modifier");
  });

  it("path: invalid characters, including percent-encoding that would decode to a dot-segment", () => {
    for (const bad of ["a b", "a%2e%2e", "a:b", "a~b", "ünïcode", "a\\b", "a@b"]) {
      assert.equal(reasonOf(`spiffe://example.org/${bad}`), "SPIFFE ID path has invalid characters", bad);
    }
  });
});

describe("spiffeIdToAgentId", () => {
  it("strips the scheme, from a string or a parsed id", () => {
    assert.equal(spiffeIdToAgentId(SUB), "example.org/ns/prod/sa/billing");
    const parsed = parseSpiffeId(SUB);
    if (parsed.valid) assert.equal(spiffeIdToAgentId(parsed.id), "example.org/ns/prod/sa/billing");
  });
});

describe("verifyJwtSvid", () => {
  it("verifies a JWT-SVID and yields the normalised agent id", async () => {
    const r = await verifyJwtSvid(await mintSvid(svidClaims()), base);
    assert.equal(r.valid, true);
    if (!r.valid) return;
    assert.equal(r.agentId, "example.org/ns/prod/sa/billing");
    assert.equal(r.identity.agentId, r.agentId);
    assert.equal(r.identity.subject, SUB);
    assert.equal(r.spiffeId.trustDomain, "example.org");
    assert.deepEqual(r.spiffeId.segments, ["ns", "prod", "sa", "billing"]);
  });

  it("audience is mandatory — an empty list is refused before any crypto runs", async () => {
    const r = await verifyJwtSvid(await mintSvid(svidClaims()), { ...base, audience: [] });
    assert.equal(!r.valid && r.reason, "Audience required for a JWT-SVID");
    const t = await verifyJwtSvid(await mintSvid(svidClaims()), { ...base, trustDomain: [] });
    assert.equal(!t.valid && t.reason, "Trust domain required for a JWT-SVID");
  });

  it("an SVID for another service, or with no audience, is rejected", async () => {
    const other = await verifyJwtSvid(await mintSvid(svidClaims({ aud: "spiffe://example.org/hr-api" })), base);
    assert.equal(!other.valid && other.reason, "Audience mismatch");
    const none = await verifyJwtSvid(await mintSvid(svidClaims({ aud: undefined })), base);
    assert.equal(!none.valid && none.reason, "Audience missing");
  });

  it("the subject must be a valid workload SPIFFE ID", async () => {
    const plain = await verifyJwtSvid(await mintSvid(svidClaims({ sub: "billing-bot" })), base);
    assert.equal(!plain.valid && plain.reason, "SPIFFE ID must use the spiffe:// scheme");
    const domainOnly = await verifyJwtSvid(await mintSvid(svidClaims({ sub: "spiffe://example.org" })), base);
    assert.equal(!domainOnly.valid && domainOnly.reason, "SPIFFE ID path is empty");
    const traversal = await verifyJwtSvid(await mintSvid(svidClaims({ sub: "spiffe://example.org/ns/../admin" })), base);
    assert.equal(!traversal.valid && traversal.reason, "SPIFFE ID path segment is a relative modifier");
  });

  it("the trust domain must be one of the expected ones", async () => {
    const foreign = await verifyJwtSvid(await mintSvid(svidClaims({ sub: "spiffe://evil.example/ns/prod/sa/billing" })), base);
    assert.equal(!foreign.valid && foreign.reason, "Trust domain mismatch");
    const federated = await verifyJwtSvid(
      await mintSvid(svidClaims({ sub: "spiffe://partner.example/sa/x" })),
      { ...base, trustDomain: ["example.org", "partner.example"] },
    );
    assert.equal(federated.valid, true);
  });

  it("inherits verifyJwt's checks: expiry required, signature verified, issuer pinned", async () => {
    const noExp = await verifyJwtSvid(await mintSvid(svidClaims({ exp: undefined })), base);
    assert.equal(!noExp.valid && noExp.reason, "Expiry missing");
    const token = await mintSvid(svidClaims());
    const [h, p, s] = token.split(".") as [string, string, string];
    const tampered = await verifyJwtSvid(`${h}.${p}.${(s.startsWith("A") ? "B" : "A") + s.slice(1)}`, base);
    assert.equal(!tampered.valid && tampered.reason, "Invalid signature");
    const wrongIss = await verifyJwtSvid(await mintSvid(svidClaims({ iss: "other" })), { ...base, expectedIssuer: "spire" });
    assert.equal(!wrongIss.valid && wrongIss.reason, "Issuer mismatch");
  });
});
