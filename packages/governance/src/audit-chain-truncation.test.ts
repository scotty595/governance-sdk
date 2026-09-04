/**
 * Asserts a documented LIMIT of the audit chain, not a desired property.
 *
 * Dropping the last k events leaves sequences 1..(N-k) contiguous with every
 * previousHash intact, so the remainder verifies exactly as a shorter chain
 * would. A hash chain proves its interior, never its exhaustiveness. This
 * test exists so the sentence in the verifier's header and in the README
 * ("interior deletion breaks verification; tail truncation does not") stops
 * depending on anyone remembering it — if a refactor ever starts detecting
 * truncation (or widens the gap), this fails and the docs get revisited.
 *
 * Suggested by an external reader in scotty595/governance-sdk#3.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createGovernance } from "./index.js";
import { verifyAuditIntegrity } from "@governance-sdk/core/audit-integrity-verify.js";

const KEY = "truncation-test-signing-key-32-bytes!!";

describe("audit chain tail truncation", () => {
  it("does NOT detect truncation of the chain tail — the documented limit, asserted", async () => {
    const gov = createGovernance({ integrityAudit: { signingKey: KEY } });
    for (let i = 0; i < 3; i++) {
      await gov.audit.log({ agentId: "agent-1", eventType: "tool_call", outcome: "success", severity: "info" });
    }

    const full = await gov.integrityChain!.export();
    assert.equal(full.length, 3);
    assert.equal((await verifyAuditIntegrity(full, KEY)).valid, true);

    // Drop the last entry. Nothing inside the remaining chain records that a
    // third event ever existed, so 1..2 verifies exactly as a two-event chain.
    const truncated = full.slice(0, 2);
    const result = await verifyAuditIntegrity(truncated, KEY);
    assert.equal(result.valid, true);
    assert.equal(result.eventsVerified, 2);
    assert.equal(result.brokenAt, null);
  });

  it("DOES detect an interior deletion", async () => {
    const gov = createGovernance({ integrityAudit: { signingKey: KEY } });
    for (let i = 0; i < 4; i++) {
      await gov.audit.log({ agentId: "agent-1", eventType: "tool_call", outcome: "success", severity: "info" });
    }
    const full = await gov.integrityChain!.export();
    const interiorDeleted = full.filter((_, i) => i !== 1);
    const result = await verifyAuditIntegrity(interiorDeleted, KEY);
    assert.equal(result.valid, false);
    assert.notEqual(result.brokenAt, null);
  });

  it("exposes the head that an external anchor would commit to", async () => {
    const gov = createGovernance({ integrityAudit: { signingKey: KEY } });
    await gov.audit.log({ agentId: "agent-1", eventType: "tool_call", outcome: "success", severity: "info" });
    await gov.audit.log({ agentId: "agent-1", eventType: "tool_call", outcome: "success", severity: "info" });
    const head = await gov.integrityChain!.stats();
    const chain = await gov.integrityChain!.export();
    assert.equal(head.latestSequence, 2);
    assert.equal(head.latestHash, chain[chain.length - 1].integrity.hash);
    // Anchoring `head` outside the writer's reach is what makes truncation
    // detectable: a verifier compares the anchored sequence to the exported
    // length. The SDK exposes the head; the anchor is deliberately not shipped.
  });
});
