/**
 * Session ledger — budgets and rate limits accumulate without host wiring.
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import { createGovernance, rateLimit, tokenBudget, costBudget, createSessionLedger } from "./index.js";

const call = (agentId = "a", metadata?: Record<string, unknown>) =>
  ({ agentId, action: "tool_call" as const, tool: "search", ...(metadata ? { metadata } : {}) });

describe("rateLimit through the ledger", () => {
  it("allows maxActions calls then blocks the next inside the window", async () => {
    const gov = createGovernance({ rules: [rateLimit(3, 60_000)] });
    const outcomes: string[] = [];
    for (let i = 0; i < 5; i++) outcomes.push((await gov.enforce(call())).outcome);
    assert.deepEqual(outcomes, ["allow", "allow", "allow", "block", "block"]);
  });

  it("only counts actions inside windowMs", async () => {
    const gov = createGovernance({ rules: [rateLimit(2, 1_000)] });
    // Two actions well outside the 1s window must not count…
    gov.ledger!.recordAction("a", Date.now() - 5_000);
    gov.ledger!.recordAction("a", Date.now() - 4_000);
    assert.equal((await gov.enforce(call())).outcome, "allow", "old actions must not count");
    // …but the ones just recorded inside it do.
    assert.equal((await gov.enforce(call())).outcome, "allow");
    assert.equal((await gov.enforce(call())).outcome, "block");
    assert.equal(gov.ledger!.snapshot("a")!.actionTimestamps.length, 4);
  });

  it("keys sessions by metadata.sessionId when present", async () => {
    const gov = createGovernance({ rules: [rateLimit(1, 60_000)] });
    assert.equal((await gov.enforce(call("a", { sessionId: "s1" }))).outcome, "allow");
    assert.equal((await gov.enforce(call("a", { sessionId: "s2" }))).outcome, "allow");
    assert.equal((await gov.enforce(call("a", { sessionId: "s1" }))).outcome, "block");
  });

  it("host-supplied recentActionCount takes precedence over the ledger", async () => {
    const gov = createGovernance({ rules: [rateLimit(1, 60_000)] });
    await gov.enforce(call());
    await gov.enforce(call());
    // ledger says 2 prior actions; host says 0 and supplies its own timestamps
    const d = await gov.enforce({ ...call(), recentActionCount: 0, recentActionTimestamps: [] });
    assert.equal(d.outcome, "allow");
  });

  it("does not count blocked actions or non-process stages", async () => {
    const gov = createGovernance({ rules: [rateLimit(1, 60_000)] });
    await gov.enforcePreprocess({ agentId: "a", action: "message_send", input: { message: "hi" } });
    await gov.enforcePostprocess({ agentId: "a", action: "message_send", outputText: "x" });
    assert.equal((await gov.enforce(call())).outcome, "allow");
    assert.equal((await gov.enforce(call())).outcome, "block");
    assert.equal((await gov.enforce(call())).outcome, "block", "blocked calls are not actions");
    assert.equal(gov.ledger!.snapshot("a")!.actionTimestamps.length, 1);
  });

  it("can be disabled", async () => {
    const gov = createGovernance({ rules: [rateLimit(1, 60_000)], ledger: false });
    assert.equal(gov.ledger, undefined);
    for (let i = 0; i < 3; i++) assert.equal((await gov.enforce(call())).outcome, "allow");
  });
});

describe("budgets through recordOutcome", () => {
  it("tokenBudget accumulates tokensUsed", async () => {
    const gov = createGovernance({ rules: [tokenBudget(100)] });
    assert.equal((await gov.enforce(call())).outcome, "allow");
    await gov.recordOutcome!({ agentId: "a", tool: "search", success: true, tokensUsed: 60 });
    assert.equal((await gov.enforce(call())).outcome, "allow");
    await gov.recordOutcome!({ agentId: "a", tool: "search", success: true, tokensUsed: 60 });
    assert.equal((await gov.enforce(call())).outcome, "block");
  });

  it("costBudget accumulates cost, attributed by metadata.sessionId", async () => {
    const gov = createGovernance({ rules: [costBudget(1.0)] });
    await gov.recordOutcome!({ agentId: "a", success: true, cost: 0.8, metadata: { sessionId: "s1" } });
    assert.equal((await gov.enforce(call("a", { sessionId: "s1" }))).outcome, "allow");
    await gov.recordOutcome!({ agentId: "a", success: true, cost: 0.5, metadata: { sessionId: "s1" } });
    assert.equal((await gov.enforce(call("a", { sessionId: "s1" }))).outcome, "block");
    assert.equal((await gov.enforce(call("a", { sessionId: "s2" }))).outcome, "allow");
  });
});

describe("createSessionLedger", () => {
  it("bounds sessions and timestamps", () => {
    const ledger = createSessionLedger({ maxSessions: 2, maxTimestamps: 3 });
    for (const k of ["a", "b", "c"]) ledger.recordAction(k);
    assert.equal(ledger.size, 2);
    assert.equal(ledger.snapshot("a"), undefined, "least recently touched evicted");
    for (let i = 0; i < 5; i++) ledger.recordAction("c");
    assert.equal(ledger.snapshot("c")!.actionTimestamps.length, 3);
  });

  it("populate never overwrites host values", () => {
    const ledger = createSessionLedger();
    ledger.recordUsage("a", { tokens: 10, cost: 2 });
    const ctx = ledger.populate({ agentId: "a", action: "tool_call", sessionTokensUsed: 999 });
    assert.equal(ctx.sessionTokensUsed, 999);
    assert.equal(ctx.sessionCost, 2);
  });
});
