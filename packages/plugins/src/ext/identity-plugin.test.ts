/**
 * The identity plugin's job is the seam: the host verifies, spreads
 * `check.context` into `enforce()`, and `require_signed_identity` reads it.
 * These tests exercise that path end to end through the assembled SDK.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createGovernance, CORE_VERSION, satisfiesRange } from "governance-sdk";
import type { GovernanceInstance, PolicyRule } from "governance-sdk";
import { verifyJwt, type JsonWebKeyLike } from "../identity-jwt.js";
import { identityPlugin, type RegisteredIdentityVerifier } from "./identity-plugin.js";

const enc = new TextEncoder();
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const jwk = { ...((await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKeyLike), kid: "k1" };
async function mint(payload: Record<string, unknown>): Promise<string> {
  const h = b64url(enc.encode(JSON.stringify({ alg: "EdDSA", kid: "k1" })));
  const p = b64url(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`;
}

const NOW = 1_800_000_000;
const token = await mint({
  iss: "idp", sub: "sales-bot", aud: "orders", iat: NOW, exp: NOW + 300, scope: "search refund",
  azp: "crm-app", act: { sub: "alice@example.com" },
});

const REQUIRE_IDENTITY: PolicyRule = {
  id: "require-identity", name: "require identity", priority: 100, enabled: true,
  condition: { type: "require_signed_identity", params: {} },
  outcome: "block", reason: "unverified identity",
};

async function install(gov: GovernanceInstance, audit = true): Promise<RegisteredIdentityVerifier> {
  await gov.use!(identityPlugin({
    audit,
    verifier: (t) => verifyJwt(t, { jwks: { keys: [jwk] }, expectedIssuer: "idp", expectedAudience: "orders", now: NOW }),
  }));
  const verifier = gov.getVerifier!("identity") as RegisteredIdentityVerifier;
  assert.equal(verifier.kind, "identity");
  return verifier;
}

describe("identityPlugin — install", () => {
  it("declares the verifiers capability and a kernel range this one satisfies", () => {
    const plugin = identityPlugin({ verifier: async () => ({ valid: false, reason: "x" }) });
    assert.equal(plugin.id, "identity/external");
    assert.ok(satisfiesRange(CORE_VERSION, plugin.requires!.core));
    assert.deepEqual(plugin.requires!.capabilities, ["verifiers"]);
  });

  it("refuses a non-function verifier", () => {
    assert.throws(() => identityPlugin({ verifier: "nope" as unknown as () => never }), TypeError);
  });

  it("registers under gov.getVerifier('identity') and unuse() removes it", async () => {
    const gov = createGovernance();
    await install(gov);
    assert.equal(await gov.unuse!("identity/external"), true);
    assert.equal(gov.getVerifier!("identity"), undefined);
  });
});

describe("identityPlugin — verify()", () => {
  it("a good token yields the context fields ready to spread", async () => {
    const gov = createGovernance();
    const verifier = await install(gov);
    const check = await verifier.verify(token, { tool: "refund" });
    assert.equal(check.verified, true);
    if (!check.verified) return;
    assert.equal(check.agentId, "sales-bot");
    assert.deepEqual(check.context, { identityVerified: true, identityCapabilityMatch: true });
    assert.deepEqual(check.identity.delegation?.chain, ["alice@example.com"]);
  });

  it("capability binding: tool not in scope → match false; no tool → match true", async () => {
    const gov = createGovernance();
    const verifier = await install(gov);
    const escalated = await verifier.verify(token, { tool: "delete_everything" });
    assert.deepEqual(escalated.context, { identityVerified: true, identityCapabilityMatch: false });
    const untargeted = await verifier.verify(token);
    assert.deepEqual(untargeted.context, { identityVerified: true, identityCapabilityMatch: true });
  });

  it("matchCapability can map tools onto the IdP's scope vocabulary", async () => {
    const gov = createGovernance();
    await gov.use!(identityPlugin({
      verifier: (t) => verifyJwt(t, { jwks: { keys: [jwk] }, expectedIssuer: "idp", expectedAudience: "orders", now: NOW }),
      matchCapability: (tool, caps) => caps.includes(tool === "issue_refund" ? "refund" : tool),
    }));
    const verifier = gov.getVerifier!("identity") as RegisteredIdentityVerifier;
    assert.equal((await verifier.verify(token, { tool: "issue_refund" })).context.identityCapabilityMatch, true);
  });

  it("a bad token yields identityVerified false with the verifier's reason", async () => {
    const gov = createGovernance();
    const verifier = await install(gov);
    const check = await verifier.verify(token.slice(0, -4) + "AAAA");
    assert.equal(check.verified, false);
    if (check.verified) return;
    assert.equal(check.reason, "Invalid signature");
    assert.deepEqual(check.context, { identityVerified: false, identityFailureReason: "Invalid signature" });
  });

  it("a verifier that throws fails closed instead of throwing into the host", async () => {
    const gov = createGovernance();
    await gov.use!(identityPlugin({ verifier: async () => { throw new Error("JWKS unreachable"); } }));
    const verifier = gov.getVerifier!("identity") as RegisteredIdentityVerifier;
    const check = await verifier.verify(token);
    assert.equal(check.verified, false);
    assert.equal(check.context.identityFailureReason, "Verifier threw: JWKS unreachable");
  });
});

describe("identityPlugin — the seam into require_signed_identity", () => {
  it("verified + capability match → allowed; verified without capability → blocked; unverified → blocked", async () => {
    const gov = createGovernance();
    const verifier = await install(gov);
    gov.addRule(REQUIRE_IDENTITY);

    const enforceWith = async (bearer: string, tool: string) => {
      const check = await verifier.verify(bearer, { tool });
      return gov.enforce({ agentId: check.verified ? check.agentId : "unknown", action: "tool_call", tool, ...check.context });
    };

    assert.equal((await enforceWith(token, "refund")).blocked, false);
    const escalated = await enforceWith(token, "wire_funds");
    assert.equal(escalated.blocked, true);
    assert.equal(escalated.ruleId, "require-identity");
    const forged = await enforceWith(token.slice(0, -4) + "AAAA", "refund");
    assert.equal(forged.blocked, true);
    assert.equal(forged.ruleId, "require-identity");
  });

  it("a host that forgets to set the context fails closed", async () => {
    const gov = createGovernance();
    await install(gov);
    gov.addRule(REQUIRE_IDENTITY);
    const decision = await gov.enforce({ agentId: "sales-bot", action: "tool_call", tool: "refund" });
    assert.equal(decision.blocked, true);
  });
});

describe("identityPlugin — audit", () => {
  it("records who authorised what: the delegation chain and authorised party", async () => {
    const gov = createGovernance();
    const verifier = await install(gov);
    await verifier.verify(token, { tool: "refund" });
    await verifier.verify(token, { tool: "wire_funds" });
    await verifier.verify("garbage");

    // The memory store orders by createdAt, newest first, and three events
    // logged in the same millisecond tie — so find each by content, not index.
    const events = await gov.storage.queryAuditEvents({ eventType: "identity_verification" });
    assert.equal(events.length, 3);
    const byTool = (tool: string) => events.find((e) => e.detail?.tool === tool);
    const ok = byTool("refund");
    const miss = byTool("wire_funds");
    const bad = events.find((e) => e.detail?.reason !== undefined);
    assert.deepEqual([ok?.agentId, ok?.outcome, ok?.detail?.capabilityMatch], ["sales-bot", "success", true]);
    assert.deepEqual(ok?.detail?.delegationChain, ["alice@example.com"]);
    assert.equal(ok?.detail?.authorizedParty, "crm-app");
    assert.deepEqual([miss?.agentId, miss?.outcome, miss?.detail?.capabilityMatch], ["sales-bot", "failure", false]);
    assert.deepEqual([bad?.agentId, bad?.outcome, bad?.detail?.reason], ["unknown", "failure", "Malformed token"]);
  });

  it("audit: false writes nothing", async () => {
    const gov = createGovernance();
    const verifier = await install(gov, false);
    await verifier.verify(token);
    assert.equal((await gov.storage.queryAuditEvents({ eventType: "identity_verification" })).length, 0);
  });
});
