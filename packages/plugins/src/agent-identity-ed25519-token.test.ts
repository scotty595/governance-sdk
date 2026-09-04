import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createEd25519Identity,
  createMemoryReplayStore,
  signAgentIdentity,
  verifyAgentIdentity,
  type AgentIdentityToken,
  type IdentityReplayStore,
} from "./agent-identity-ed25519.js";

const identity = createEd25519Identity();

/** Flip the first byte of a hex signature (stays hex-valid). */
function tamperSignature(token: AgentIdentityToken): AgentIdentityToken {
  const sig = token.signature;
  const flipped = sig.slice(0, 2) === "ff" ? "00" : "ff";
  return { ...token, signature: flipped + sig.slice(2) };
}

describe("signAgentIdentity + verifyAgentIdentity (high-level wrappers)", () => {
  it("signs and verifies a valid token round-trip", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "sales-bot", keys, ttlSeconds: 3600 });

    const result = await verifyAgentIdentity(token);
    assert.equal(result.valid, true);
    assert.equal(result.agentId, "sales-bot");
  });

  it("embeds agent public key for self-verification", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys });

    assert.equal(token.payload.publicKeyHex, keys.publicKeyHex);
    assert.match(token.signature, /^[0-9a-f]+$/);
  });

  it("includes kid + capabilities when provided, sorted deterministically", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({
      agentId: "x",
      keys,
      kid: "v2",
      capabilities: ["zeta", "alpha", "omicron"],
    });
    assert.equal(token.payload.kid, "v2");
    assert.deepEqual(token.payload.capabilities, ["alpha", "omicron", "zeta"]);
  });

  it("omits aud / iss from the payload when not supplied (older tokens still verify)", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys });
    assert.equal("aud" in token.payload, false);
    assert.equal("iss" in token.payload, false);
  });

  it("rejects a token whose signature has been tampered with", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys });

    const result = await verifyAgentIdentity(tamperSignature(token));
    assert.equal(result.valid, false);
    assert.equal(result.reason, "Invalid signature");
  });

  it("rejects a token whose payload has been modified", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "alice", keys });

    const tampered = { ...token, payload: { ...token.payload, agentId: "bob" } };
    const result = await verifyAgentIdentity(tampered);
    assert.equal(result.valid, false);
    assert.equal(result.reason, "Invalid signature");
  });

  it("rejects an expired token", async () => {
    const keys = await identity.generateKeyPair();
    const past = Math.floor(Date.now() / 1000) - 10_000;
    const token = await signAgentIdentity({ agentId: "x", keys, ttlSeconds: 60, now: past });
    const result = await verifyAgentIdentity(token);
    assert.equal(result.valid, false);
    assert.equal(result.reason, "Token expired");
  });

  it("keeps the 60s default clock-skew tolerance on both exp and iat", async () => {
    const keys = await identity.generateKeyPair();
    const nowSec = Math.floor(Date.now() / 1000);

    // Expired 30s ago — inside the 60s skew window, still accepted.
    const justExpired = await signAgentIdentity({ agentId: "x", keys, ttlSeconds: 10, now: nowSec - 40 });
    assert.equal((await verifyAgentIdentity(justExpired, { now: nowSec })).valid, true);
    // Expired 61s ago — outside the window.
    const tooOld = await signAgentIdentity({ agentId: "x", keys, ttlSeconds: 10, now: nowSec - 71 });
    assert.equal((await verifyAgentIdentity(tooOld, { now: nowSec })).reason, "Token expired");

    // Issued 30s in the future — accepted; 61s — rejected.
    const slightlyAhead = await signAgentIdentity({ agentId: "x", keys, now: nowSec + 30 });
    assert.equal((await verifyAgentIdentity(slightlyAhead, { now: nowSec })).valid, true);
    const farAhead = await signAgentIdentity({ agentId: "x", keys, now: nowSec + 61 });
    assert.equal((await verifyAgentIdentity(farAhead, { now: nowSec })).reason, "Token not yet valid");
  });

  it("rejects a token issued in the future beyond clock skew tolerance", async () => {
    const keys = await identity.generateKeyPair();
    const future = Math.floor(Date.now() / 1000) + 10_000;
    const token = await signAgentIdentity({ agentId: "x", keys, ttlSeconds: 60, now: future });
    const result = await verifyAgentIdentity(token, { clockSkewSeconds: 60 });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "Token not yet valid");
  });

  it("each signing produces a unique jti (prevents naive replay dedup collisions)", async () => {
    const keys = await identity.generateKeyPair();
    const t1 = await signAgentIdentity({ agentId: "x", keys });
    const t2 = await signAgentIdentity({ agentId: "x", keys });
    assert.notEqual(t1.payload.jti, t2.payload.jti);
    assert.match(t1.payload.jti, /^[0-9a-f]{32}$/);
  });

  it("rejects malformed input", async () => {
    // @ts-expect-error - deliberately malformed
    const r1 = await verifyAgentIdentity(null);
    assert.equal(r1.valid, false);
    assert.equal(r1.reason, "Malformed token");

    // @ts-expect-error - deliberately malformed
    const r2 = await verifyAgentIdentity({ payload: {}, signature: 123 });
    assert.equal(r2.valid, false);
    assert.equal(r2.reason, "Malformed token");
  });

  it("rejects a token with no jti or a non-string kid as malformed", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys });

    const { jti: _jti, ...noJti } = token.payload;
    const r1 = await verifyAgentIdentity({ ...token, payload: noJti as AgentIdentityToken["payload"] });
    assert.equal(r1.reason, "Malformed token");

    const badKid = { ...token, payload: { ...token.payload, kid: 7 as unknown as string } };
    const r2 = await verifyAgentIdentity(badKid);
    assert.equal(r2.reason, "Malformed token");
  });

  it("rejects tokens with invalid hex in publicKeyHex or signature", async () => {
    const r1 = await verifyAgentIdentity({
      payload: {
        agentId: "x",
        publicKeyHex: "not-hex",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
        jti: "abc",
      },
      signature: "also-not-hex",
    });
    assert.equal(r1.valid, false);
    assert.match(r1.reason ?? "", /^Invalid key or signature encoding: /);
  });
});

describe("verifyAgentIdentity — key pinning and rotation", () => {
  it("enforces pinned public key when supplied (single key, unchanged behaviour)", async () => {
    const keysA = await identity.generateKeyPair();
    const keysB = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys: keysA });

    const result = await verifyAgentIdentity(token, { pinnedPublicKeyHex: keysB.publicKeyHex });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "Public key does not match pinned key");

    const matched = await verifyAgentIdentity(token, { pinnedPublicKeyHex: keysA.publicKeyHex });
    assert.equal(matched.valid, true);
  });

  it("accepts either key during a rotation window via pinnedPublicKeysHex", async () => {
    const oldKeys = await identity.generateKeyPair();
    const newKeys = await identity.generateKeyPair();
    const strangerKeys = await identity.generateKeyPair();
    const pinned = { pinnedPublicKeysHex: [oldKeys.publicKeyHex, newKeys.publicKeyHex] };

    const fromOld = await signAgentIdentity({ agentId: "x", keys: oldKeys, kid: "2025-q4" });
    const fromNew = await signAgentIdentity({ agentId: "x", keys: newKeys, kid: "2026-q1" });
    const fromStranger = await signAgentIdentity({ agentId: "x", keys: strangerKeys });

    assert.equal((await verifyAgentIdentity(fromOld, pinned)).valid, true);
    assert.equal((await verifyAgentIdentity(fromNew, pinned)).valid, true);
    const rejected = await verifyAgentIdentity(fromStranger, pinned);
    assert.equal(rejected.valid, false);
    assert.equal(rejected.reason, "Public key does not match pinned key");
  });

  it("an empty pinnedPublicKeysHex list rejects every token (fail closed)", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys });
    const result = await verifyAgentIdentity(token, { pinnedPublicKeysHex: [] });
    assert.equal(result.reason, "Public key does not match pinned key");
  });

  it("compares pinned keys case-insensitively", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys });
    const result = await verifyAgentIdentity(token, { pinnedPublicKeysHex: [keys.publicKeyHex.toUpperCase()] });
    assert.equal(result.valid, true);
  });

  it("resolves the expected key by kid (sync and async resolvers)", async () => {
    const keysA = await identity.generateKeyPair();
    const keysB = await identity.generateKeyPair();
    const registry: Record<string, string> = { "key-a": keysA.publicKeyHex, "key-b": keysB.publicKeyHex };

    const tokenA = await signAgentIdentity({ agentId: "x", keys: keysA, kid: "key-a" });
    const tokenB = await signAgentIdentity({ agentId: "x", keys: keysB, kid: "key-b" });

    const sync = { resolvePublicKey: (kid: string | undefined) => (kid ? registry[kid] : undefined) };
    assert.equal((await verifyAgentIdentity(tokenA, sync)).valid, true);
    assert.equal((await verifyAgentIdentity(tokenB, sync)).valid, true);

    const asyncResolver = {
      resolvePublicKey: async (kid: string | undefined) => (kid ? registry[kid] : undefined),
    };
    assert.equal((await verifyAgentIdentity(tokenA, asyncResolver)).valid, true);
  });

  it("rejects an unknown kid and a kid whose registered key differs from the embedded one", async () => {
    const keysA = await identity.generateKeyPair();
    const keysB = await identity.generateKeyPair();
    const resolvePublicKey = (kid: string | undefined) => (kid === "key-a" ? keysA.publicKeyHex : undefined);

    const unknownKid = await signAgentIdentity({ agentId: "x", keys: keysA, kid: "retired" });
    const r1 = await verifyAgentIdentity(unknownKid, { resolvePublicKey });
    assert.equal(r1.reason, "No public key resolved for kid");

    const noKid = await signAgentIdentity({ agentId: "x", keys: keysA });
    const r2 = await verifyAgentIdentity(noKid, { resolvePublicKey });
    assert.equal(r2.reason, "No public key resolved for kid");

    // Attacker relabels their own key as "key-a"
    const relabelled = await signAgentIdentity({ agentId: "x", keys: keysB, kid: "key-a" });
    const r3 = await verifyAgentIdentity(relabelled, { resolvePublicKey });
    assert.equal(r3.reason, "Public key does not match pinned key");
  });

  it("pinning options combine with AND", async () => {
    const keysA = await identity.generateKeyPair();
    const keysB = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys: keysA, kid: "a" });

    const result = await verifyAgentIdentity(token, {
      pinnedPublicKeysHex: [keysB.publicKeyHex], // list disagrees
      resolvePublicKey: () => keysA.publicKeyHex, // resolver agrees
    });
    assert.equal(result.reason, "Public key does not match pinned key");
  });
});

describe("verifyAgentIdentity — audience and issuer", () => {
  it("accepts matching aud and iss", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys, aud: "orders-api", iss: "propolis" });
    assert.equal(token.payload.aud, "orders-api");
    assert.equal(token.payload.iss, "propolis");
    const result = await verifyAgentIdentity(token, { expectedAudience: "orders-api", expectedIssuer: "propolis" });
    assert.equal(result.valid, true);
  });

  it("accepts an audience list that includes the expected audience", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys, aud: ["billing", "orders-api"] });
    assert.equal((await verifyAgentIdentity(token, { expectedAudience: "orders-api" })).valid, true);
    assert.equal(
      (await verifyAgentIdentity(token, { expectedAudience: "search" })).reason,
      "Audience mismatch",
    );
  });

  it("rejects audience mismatch", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys, aud: "orders-api" });
    const result = await verifyAgentIdentity(token, { expectedAudience: "billing" });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "Audience mismatch");
  });

  it("rejects a token with no aud when the verifier expects one", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys });
    const result = await verifyAgentIdentity(token, { expectedAudience: "orders-api" });
    assert.equal(result.reason, "Audience missing");
  });

  it("rejects a token that carries aud at a verifier that declared no audience", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys, aud: "orders-api" });
    const result = await verifyAgentIdentity(token);
    assert.equal(result.reason, "Audience unexpected");
  });

  it("rejects issuer mismatch and missing issuer", async () => {
    const keys = await identity.generateKeyPair();
    const signed = await signAgentIdentity({ agentId: "x", keys, iss: "propolis" });
    assert.equal((await verifyAgentIdentity(signed, { expectedIssuer: "someone-else" })).reason, "Issuer mismatch");

    const unsigned = await signAgentIdentity({ agentId: "x", keys });
    assert.equal((await verifyAgentIdentity(unsigned, { expectedIssuer: "propolis" })).reason, "Issuer missing");
  });

  it("aud and iss are covered by the signature — rewriting them fails verification", async () => {
    const keys = await identity.generateKeyPair();
    const token = await signAgentIdentity({ agentId: "x", keys, aud: "billing", iss: "propolis" });

    const reAudienced = { ...token, payload: { ...token.payload, aud: "orders-api" } };
    const r1 = await verifyAgentIdentity(reAudienced, { expectedAudience: "orders-api", expectedIssuer: "propolis" });
    assert.equal(r1.reason, "Invalid signature");

    const reIssued = { ...token, payload: { ...token.payload, iss: "evil" } };
    const r2 = await verifyAgentIdentity(reIssued, { expectedAudience: "billing", expectedIssuer: "evil" });
    assert.equal(r2.reason, "Invalid signature");
  });
});

describe("verifyAgentIdentity — replay protection", () => {
  it("rejects a jti presented a second time", async () => {
    const keys = await identity.generateKeyPair();
    const replayStore = createMemoryReplayStore();
    const token = await signAgentIdentity({ agentId: "x", keys });

    const first = await verifyAgentIdentity(token, { replayStore });
    assert.equal(first.valid, true);

    const second = await verifyAgentIdentity(token, { replayStore });
    assert.equal(second.valid, false);
    assert.equal(second.reason, "Token replayed");
    assert.equal(replayStore.size(), 1);
  });

  it("distinct tokens from the same agent are each accepted once", async () => {
    const keys = await identity.generateKeyPair();
    const replayStore = createMemoryReplayStore();
    const t1 = await signAgentIdentity({ agentId: "x", keys });
    const t2 = await signAgentIdentity({ agentId: "x", keys });
    assert.equal((await verifyAgentIdentity(t1, { replayStore })).valid, true);
    assert.equal((await verifyAgentIdentity(t2, { replayStore })).valid, true);
    assert.equal((await verifyAgentIdentity(t1, { replayStore })).reason, "Token replayed");
  });

  it("does not record forged or otherwise rejected tokens", async () => {
    const keys = await identity.generateKeyPair();
    const replayStore = createMemoryReplayStore();
    const token = await signAgentIdentity({ agentId: "x", keys, aud: "a" });

    assert.equal((await verifyAgentIdentity(tamperSignature(token), { replayStore, expectedAudience: "a" })).valid, false);
    assert.equal((await verifyAgentIdentity(token, { replayStore, expectedAudience: "b" })).valid, false);
    assert.equal(replayStore.size(), 0);

    // The genuine token is still accepted afterwards, exactly once.
    assert.equal((await verifyAgentIdentity(token, { replayStore, expectedAudience: "a" })).valid, true);
    assert.equal((await verifyAgentIdentity(token, { replayStore, expectedAudience: "a" })).reason, "Token replayed");
  });

  it("records the jti with the expiry plus clock-skew allowance", async () => {
    const keys = await identity.generateKeyPair();
    const seen: Array<[string, number]> = [];
    const replayStore: IdentityReplayStore = {
      has: () => false,
      add: (jti, exp) => { seen.push([jti, exp]); },
    };
    const nowSec = 1_800_000_000;
    const token = await signAgentIdentity({ agentId: "x", keys, ttlSeconds: 100, now: nowSec });
    await verifyAgentIdentity(token, { replayStore, now: nowSec, clockSkewSeconds: 30 });
    assert.deepEqual(seen, [[token.payload.jti, nowSec + 100 + 30]]);
  });

  it("works with an async (e.g. network-backed) replay store", async () => {
    const keys = await identity.generateKeyPair();
    const backing = new Set<string>();
    const replayStore: IdentityReplayStore = {
      has: async (jti) => backing.has(jti),
      add: async (jti) => { backing.add(jti); },
    };
    const token = await signAgentIdentity({ agentId: "x", keys });
    assert.equal((await verifyAgentIdentity(token, { replayStore })).valid, true);
    assert.equal((await verifyAgentIdentity(token, { replayStore })).reason, "Token replayed");
  });
});
