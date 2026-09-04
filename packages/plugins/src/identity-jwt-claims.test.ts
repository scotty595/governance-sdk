/**
 * Claim-level tests for the external-JWT verifier: the claims→identity map,
 * the on-behalf-of chain, time claims with clock skew on both sides, issuer
 * and audience, and replay. Structure, algorithm and key tests are in
 * `identity-jwt.test.ts`. Keys are generated here; nothing is hardcoded.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createMemoryReplayStore, verifyJwt, type JsonWebKeyLike, type VerifyJwtOptions } from "./identity-jwt.js";

const enc = new TextEncoder();
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const segment = (obj: unknown): string => b64url(enc.encode(JSON.stringify(obj)));

const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const jwk = { ...((await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKeyLike), kid: "ed-1" };
async function mint(payload: Record<string, unknown>): Promise<string> {
  const h = segment({ alg: "EdDSA", typ: "JWT", kid: "ed-1" });
  const p = segment(payload);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`;
}
async function impostorMint(payload: Record<string, unknown>): Promise<string> {
  const other = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const h = segment({ alg: "EdDSA", typ: "JWT", kid: "ed-1" });
  const p = segment(payload);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, other.privateKey, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`;
}

const NOW = 1_800_000_000;
const ISS = "https://login.example.com/";
const AUD = "orders-api";
const claims = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  iss: ISS, sub: "agent-42", aud: AUD, iat: NOW, exp: NOW + 300, jti: "t-1", ...extra,
});
const base: VerifyJwtOptions = { jwks: { keys: [jwk] }, expectedIssuer: ISS, expectedAudience: AUD, now: NOW };

async function reasonOf(token: string, opts: VerifyJwtOptions = base): Promise<string | undefined> {
  const r = await verifyJwt(token, opts);
  return r.valid ? undefined : r.reason;
}

describe("verifyJwt — claim mapping", () => {
  it("reads capabilities from `scope`, then `scp` (Entra), then `roles`", async () => {
    const caps = async (extra: Record<string, unknown>) => {
      const r = await verifyJwt(await mint(claims(extra)), base);
      return r.valid ? r.identity.capabilities : r.reason;
    };
    assert.deepEqual(await caps({ scope: "a  b\tc" }), ["a", "b", "c"]);
    assert.deepEqual(await caps({ scp: "x y" }), ["x", "y"]);
    assert.deepEqual(await caps({ roles: ["admin", 7, "ops", ""] }), ["admin", "ops"]);
    assert.deepEqual(await caps({}), []);
  });

  it("honours a custom capabilities claim and a custom agent-id claim", async () => {
    const token = await mint(claims({ scope: "ignored", perms: ["p1"], appid: "app-9" }));
    const r = await verifyJwt(token, { ...base, capabilitiesClaim: "perms", agentIdClaim: "appid" });
    assert.equal(r.valid, true);
    if (!r.valid) return;
    assert.deepEqual(r.identity.capabilities, ["p1"]);
    assert.equal(r.agentId, "app-9");
    assert.equal(r.identity.subject, "agent-42");
  });

  it("carries the on-behalf-of chain: act (nested), azp and actor", async () => {
    const token = await mint(claims({
      azp: "client-app",
      actor: { id: "svc-gateway" },
      act: { sub: "alice@example.com", act: { sub: "tenant-admin" } },
    }));
    const r = await verifyJwt(token, base);
    assert.equal(r.valid, true);
    if (!r.valid) return;
    assert.deepEqual(r.identity.delegation?.chain, ["alice@example.com", "tenant-admin"]);
    assert.equal(r.identity.delegation?.azp, "client-app");
    assert.deepEqual(r.identity.delegation?.actor, { id: "svc-gateway" });
    assert.equal(r.identity.delegation?.act?.sub, "alice@example.com");
    assert.equal(r.identity.claims.azp, "client-app");
  });

  it("omits `delegation` when no delegation claim is present, and caps a hostile `act` chain", async () => {
    const plain = await verifyJwt(await mint(claims()), base);
    assert.equal(plain.valid && plain.identity.delegation, undefined);

    let act: Record<string, unknown> = { sub: "hop-999" };
    for (let i = 998; i >= 0; i--) act = { sub: `hop-${i}`, act };
    const deep = await verifyJwt(await mint(claims({ act })), base);
    assert.equal(deep.valid, true);
    if (!deep.valid) return;
    assert.equal(deep.identity.delegation?.chain.length, 10);
    assert.equal(deep.identity.delegation?.chain[0], "hop-0");
  });
});

describe("verifyJwt — time claims and clock skew", () => {
  it("requires `exp` by default, and only by default", async () => {
    const token = await mint(claims({ exp: undefined }));
    assert.equal(await reasonOf(token), "Expiry missing");
    assert.equal(await reasonOf(await mint(claims({ exp: "soon" }))), "Expiry missing");
    assert.equal(await reasonOf(token, { ...base, requireExpiry: false }), undefined);
  });

  it("rejects an expired token, an nbf in the future and an iat in the future", async () => {
    assert.equal(await reasonOf(await mint(claims({ exp: NOW - 3600 }))), "Token expired");
    assert.equal(await reasonOf(await mint(claims({ nbf: NOW + 3600 }))), "Token not yet valid");
    assert.equal(await reasonOf(await mint(claims({ iat: NOW + 3600 }))), "Token issued in the future");
  });

  it("applies the 60s default skew on both sides, to the second", async () => {
    assert.equal(await reasonOf(await mint(claims({ exp: NOW - 60 }))), undefined);
    assert.equal(await reasonOf(await mint(claims({ exp: NOW - 61 }))), "Token expired");
    assert.equal(await reasonOf(await mint(claims({ nbf: NOW + 60 }))), undefined);
    assert.equal(await reasonOf(await mint(claims({ nbf: NOW + 61 }))), "Token not yet valid");
    assert.equal(await reasonOf(await mint(claims({ iat: NOW + 60 }))), undefined);
    assert.equal(await reasonOf(await mint(claims({ iat: NOW + 61 }))), "Token issued in the future");
  });

  it("honours a configured skew, including zero", async () => {
    const strict = { ...base, clockSkewSeconds: 0 };
    assert.equal(await reasonOf(await mint(claims({ exp: NOW })), strict), undefined);
    assert.equal(await reasonOf(await mint(claims({ exp: NOW - 1 })), strict), "Token expired");
    assert.equal(await reasonOf(await mint(claims({ nbf: NOW + 1 })), strict), "Token not yet valid");
    const loose = { ...base, clockSkewSeconds: 600 };
    assert.equal(await reasonOf(await mint(claims({ exp: NOW - 600 })), loose), undefined);
    assert.equal(await reasonOf(await mint(claims({ exp: NOW - 601 })), loose), "Token expired");
  });
});

describe("verifyJwt — issuer, audience, subject", () => {
  it("rejects a wrong or missing issuer when one is expected", async () => {
    assert.equal(await reasonOf(await mint(claims({ iss: "https://evil.example/" }))), "Issuer mismatch");
    assert.equal(await reasonOf(await mint(claims({ iss: undefined }))), "Issuer missing");
  });

  it("rejects a wrong or missing audience when one is expected", async () => {
    assert.equal(await reasonOf(await mint(claims({ aud: "billing-api" }))), "Audience mismatch");
    assert.equal(await reasonOf(await mint(claims({ aud: ["billing", "hr"] }))), "Audience mismatch");
    assert.equal(await reasonOf(await mint(claims({ aud: undefined }))), "Audience missing");
  });

  it("rejects a token that names an audience when the verifier declared none", async () => {
    const opts = { ...base, expectedAudience: undefined };
    assert.equal(await reasonOf(await mint(claims()), opts), "Audience unexpected");
    assert.equal(await reasonOf(await mint(claims({ aud: undefined })), opts), undefined);
  });

  it("rejects a token with no agent-id claim", async () => {
    assert.equal(await reasonOf(await mint(claims({ sub: undefined }))), "Agent id claim missing");
    assert.equal(await reasonOf(await mint(claims({ sub: "" }))), "Agent id claim missing");
  });
});

describe("verifyJwt — replay", () => {
  it("accepts a jti once and rejects it thereafter", async () => {
    const replayStore = createMemoryReplayStore({ now: () => NOW });
    const token = await mint(claims({ jti: "once" }));
    assert.equal(await reasonOf(token, { ...base, replayStore }), undefined);
    assert.equal(await reasonOf(token, { ...base, replayStore }), "Token replayed");
    assert.equal(replayStore.size(), 1);
  });

  it("requires a jti when a store is configured", async () => {
    const replayStore = createMemoryReplayStore({ now: () => NOW });
    assert.equal(await reasonOf(await mint(claims({ jti: undefined })), { ...base, replayStore }), "Token id missing");
  });

  it("never records a token whose signature failed", async () => {
    const replayStore = createMemoryReplayStore({ now: () => NOW });
    assert.equal(await reasonOf(await impostorMint(claims({ jti: "forged" })), { ...base, replayStore }), "Invalid signature");
    assert.equal(replayStore.size(), 0);
  });
});
