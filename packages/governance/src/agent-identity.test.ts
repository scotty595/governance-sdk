import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createAgentIdentity,
  AGENT_IDENTITY_TOKEN_VERSION,
  MIN_SIGNING_KEY_BYTES,
  type AgentIdentityToken,
} from "./agent-identity";

describe("Agent Identity (HMAC, deprecated)", () => {
  const signingKey = "test-signing-key-2026";
  const agent = { id: "agent-1", name: "sales-bot", owner: "team-a", version: "1.2.0" };

  it("issues a v2 token with signature and fingerprint", async () => {
    const identity = createAgentIdentity(signingKey);
    const token = await identity.issueToken(agent);

    assert.equal(token.v, 2);
    assert.equal(token.v, AGENT_IDENTITY_TOKEN_VERSION);
    assert.ok(token.signature);
    assert.equal(token.signature.length, 64); // SHA-256 hex
    assert.equal(token.agentId, "agent-1");
    assert.ok(token.issuedAt);
    assert.equal(token.fingerprint, token.signature.slice(0, 16));
    assert.equal(token.expiresAt, undefined); // no TTL configured
  });

  it("verifies a valid token", async () => {
    const identity = createAgentIdentity(signingKey);
    const token = await identity.issueToken(agent);
    const result = await identity.verifyToken(token, agent);

    assert.equal(result.valid, true);
    assert.equal(result.reason, undefined);
  });

  it("verifies a valid token that carries an expiry", async () => {
    const identity = createAgentIdentity(signingKey, { tokenTtlMs: 60_000 });
    const token = await identity.issueToken(agent);
    assert.ok(token.expiresAt);
    const result = await identity.verifyToken(token, agent);
    assert.equal(result.valid, true);
  });

  it("rejects token with mismatched agent ID", async () => {
    const identity = createAgentIdentity(signingKey);
    const token = await identity.issueToken(agent);
    const result = await identity.verifyToken(token, { ...agent, id: "different-agent" });

    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("agent ID"));
  });

  it("rejects token when agent identity is tampered with", async () => {
    const identity = createAgentIdentity(signingKey);
    const token = await identity.issueToken(agent);
    const result = await identity.verifyToken(token, { ...agent, name: "tampered-name" });

    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("Signature mismatch"));
  });

  it("rejects expired token", async () => {
    const identity = createAgentIdentity(signingKey, { tokenTtlMs: 1 }); // 1ms TTL
    const token = await identity.issueToken(agent);

    // Wait for expiry
    await new Promise((resolve) => setTimeout(resolve, 5));

    const result = await identity.verifyToken(token, agent);
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("expired"));
  });

  it("rejects an expired token whose expiresAt was rewritten into the future (expiry is signed)", async () => {
    const identity = createAgentIdentity(signingKey, { tokenTtlMs: 1 });
    const token = await identity.issueToken(agent);
    await new Promise((resolve) => setTimeout(resolve, 5));

    const revived: AgentIdentityToken = { ...token, expiresAt: "2099-01-01T00:00:00.000Z" };
    const result = await identity.verifyToken(revived, agent);
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("Signature mismatch"), result.reason);
  });

  it("rejects an expired token whose expiresAt was deleted (absence is signed as null)", async () => {
    const identity = createAgentIdentity(signingKey, { tokenTtlMs: 1 });
    const token = await identity.issueToken(agent);
    await new Promise((resolve) => setTimeout(resolve, 5));

    const { expiresAt: _dropped, ...stripped } = token;
    const result = await identity.verifyToken(stripped as AgentIdentityToken, agent);
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("Signature mismatch"), result.reason);
  });

  it("rejects a token whose issuedAt was altered", async () => {
    const identity = createAgentIdentity(signingKey);
    const token = await identity.issueToken(agent);
    const result = await identity.verifyToken({ ...token, issuedAt: "2020-01-01T00:00:00.000Z" }, agent);
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("Signature mismatch"));
  });

  it("rejects a token whose signature was altered", async () => {
    const identity = createAgentIdentity(signingKey);
    const token = await identity.issueToken(agent);
    const flipped = (token.signature[0] === "0" ? "1" : "0") + token.signature.slice(1);
    const result = await identity.verifyToken({ ...token, signature: flipped }, agent);
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("Signature mismatch"));
  });

  it("rejects v1 tokens (no version field) with a clear error", async () => {
    const identity = createAgentIdentity(signingKey);
    const token = await identity.issueToken(agent);
    const { v: _v, ...v1Token } = token;
    const result = await identity.verifyToken(v1Token as unknown as AgentIdentityToken, agent);
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /Unsupported token version/);
    assert.match(result.reason ?? "", /re-issue/);
  });

  it("rejects tokens with an unknown version number", async () => {
    const identity = createAgentIdentity(signingKey);
    const token = await identity.issueToken(agent);
    const result = await identity.verifyToken({ ...token, v: 3 } as unknown as AgentIdentityToken, agent);
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /Unsupported token version/);
  });

  it("rejects malformed tokens without throwing", async () => {
    const identity = createAgentIdentity(signingKey);
    for (const bad of [null, undefined, "token", 42, {}, { v: 2, signature: 1 }, { v: 2, signature: "ab", agentId: "agent-1" }]) {
      const result = await identity.verifyToken(bad as unknown as AgentIdentityToken, agent);
      assert.equal(result.valid, false);
      assert.equal(result.reason, "Malformed token");
    }
  });

  it("includes expiresAt when TTL is configured", async () => {
    const identity = createAgentIdentity(signingKey, { tokenTtlMs: 3600_000 });
    const token = await identity.issueToken(agent);
    assert.ok(token.expiresAt);
  });

  it("generates deterministic fingerprints", async () => {
    const identity = createAgentIdentity(signingKey);
    const fp1 = await identity.getFingerprint(agent);
    const fp2 = await identity.getFingerprint(agent);

    assert.equal(fp1, fp2);
    assert.equal(fp1.length, 16);
  });

  it("generates different fingerprints for different agents", async () => {
    const identity = createAgentIdentity(signingKey);
    const fp1 = await identity.getFingerprint(agent);
    const fp2 = await identity.getFingerprint({ ...agent, id: "agent-2", name: "other-bot" });

    assert.notEqual(fp1, fp2);
  });

  it("generates different signatures with different signing keys", async () => {
    const id1 = createAgentIdentity("signing-key-a-0123456789");
    const id2 = createAgentIdentity("signing-key-b-0123456789");
    const fp1 = await id1.getFingerprint(agent);
    const fp2 = await id2.getFingerprint(agent);

    assert.notEqual(fp1, fp2);
  });

  it("does not verify a token issued under a different signing key", async () => {
    const issuer = createAgentIdentity("signing-key-a-0123456789");
    const verifier = createAgentIdentity("signing-key-b-0123456789");
    const token = await issuer.issueToken(agent);
    const result = await verifier.verifyToken(token, agent);
    assert.equal(result.valid, false);
  });

  it("throws on empty signing key", () => {
    assert.throws(() => createAgentIdentity(""), /Signing key is required/);
  });

  it("throws on a signing key shorter than 16 bytes", () => {
    assert.equal(MIN_SIGNING_KEY_BYTES, 16);
    assert.throws(() => createAgentIdentity("key-a"), /at least 16 bytes/);
    assert.throws(() => createAgentIdentity("123456789012345"), /at least 16 bytes \(got 15\)/);
  });

  it("accepts a signing key of exactly 16 bytes (measured in UTF-8 bytes)", async () => {
    const identity = createAgentIdentity("1234567890123456");
    const token = await identity.issueToken(agent);
    assert.equal((await identity.verifyToken(token, agent)).valid, true);

    // 8 two-byte characters = 16 bytes even though .length is 8
    assert.doesNotThrow(() => createAgentIdentity("éééééééé"));
  });

  it("handles agents with minimal fields", async () => {
    const identity = createAgentIdentity(signingKey);
    const minimal = { id: "min", name: "minimal" };
    const token = await identity.issueToken(minimal);
    const result = await identity.verifyToken(token, minimal);
    assert.equal(result.valid, true);
  });
});
