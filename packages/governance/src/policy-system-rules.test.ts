/**
 * System rules — the kill switch's foundation.
 *
 * Asserts the two verified bypasses are closed:
 *   1. a user rule whose id starts with `__` no longer escapes the priority
 *      clamp (it used to be able to outrank the kill switch at 1000);
 *   2. a killed agent is blocked at EVERY stage, and in hosted mode the
 *      local kill wins over a remote allow.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert";
import { createGovernance, createPolicyEngine, MAX_USER_PRIORITY, blockTools } from "./index.js";
import { createKillSwitch } from "@governance-sdk/core/kill-switch.js";
import type { PolicyRule } from "@governance-sdk/core/policy.js";

const allowAll = (id: string, priority: number): PolicyRule => ({
  id,
  name: id,
  condition: { type: "custom", params: { evaluate: () => true } },
  outcome: "allow",
  reason: "escape attempt",
  priority,
  enabled: true,
});

describe("priority clamp", () => {
  it("clamps a `__`-prefixed user rule at 998 like any other", () => {
    const engine = createPolicyEngine({ rules: [allowAll("__sneaky", 1000)] });
    const stored = engine.getRules().find((r) => r.id === "__sneaky");
    assert.equal(stored?.priority, MAX_USER_PRIORITY);
    assert.equal(engine.isSystemRule("__sneaky"), false);
  });

  it("clamps via addRule too", () => {
    const engine = createPolicyEngine();
    engine.addRule(allowAll("__x", 5000));
    assert.equal(engine.getRules()[0].priority, MAX_USER_PRIORITY);
  });

  it("a `__`-prefixed allow rule at 1000 does NOT beat the kill switch", async () => {
    const gov = createGovernance({ rules: [allowAll("__x", 1000)] });
    const ks = createKillSwitch(gov);
    await ks.kill("agent-1", "test");
    const d = await gov.enforce({ agentId: "agent-1", action: "tool_call", tool: "anything" });
    assert.equal(d.outcome, "block");
    assert.equal(d.ruleId, "__kill_switch__agent-1");
  });
});

describe("system rule lifecycle", () => {
  it("addRule cannot replace a system rule; removeRule cannot remove it", async () => {
    const gov = createGovernance();
    const ks = createKillSwitch(gov);
    await ks.kill("agent-1", "test");
    assert.throws(() => gov.addRule(allowAll("__kill_switch__agent-1", 10)), /system rule/);
    assert.throws(() => gov.removeRule("__kill_switch__agent-1"), /system rule/);
    // still killed
    const d = await gov.enforce({ agentId: "agent-1", action: "tool_call", tool: "x" });
    assert.equal(d.blocked, true);
    // revive uses the system path
    await ks.revive("agent-1");
    const after = await gov.enforce({ agentId: "agent-1", action: "tool_call", tool: "x" });
    assert.equal(after.blocked, false);
  });

  it("evaluateSystemRules returns null when no system rule matches", () => {
    const engine = createPolicyEngine({ rules: [blockTools(["rm"])] });
    assert.equal(engine.evaluateSystemRules({ agentId: "a", action: "tool_call", tool: "rm" }), null);
  });
});

describe("kill switch covers every stage", () => {
  it("blocks preprocess, tool_result and postprocess after kill()", async () => {
    const gov = createGovernance();
    const ks = createKillSwitch(gov);
    await ks.kill("agent-1", "compromised");

    const pre = await gov.enforcePreprocess({ agentId: "agent-1", action: "message_send", input: { message: "hi" } });
    const tr = await gov.enforceToolResult({ agentId: "agent-1", action: "tool_call", tool: "search", outputText: "ok" });
    const post = await gov.enforcePostprocess({ agentId: "agent-1", action: "message_send", outputText: "bye" });
    for (const d of [pre, tr, post]) {
      assert.equal(d.outcome, "block", `expected block, got ${d.outcome} at stage ${d.stage}`);
      assert.equal(d.ruleId, "__kill_switch__agent-1");
    }

    // other agents unaffected
    const other = await gov.enforcePreprocess({ agentId: "agent-2", action: "message_send", input: { message: "hi" } });
    assert.equal(other.outcome, "allow");
  });

  it("fleet kill blocks every agent at every stage", async () => {
    const gov = createGovernance();
    const ks = createKillSwitch(gov);
    await ks.killAll("incident");
    const d = await gov.enforcePostprocess({ agentId: "anyone", action: "message_send", outputText: "x" });
    assert.equal(d.outcome, "block");
    assert.equal(d.ruleId, "__kill_switch__fleet__");
  });
});

describe("hosted mode honours a local kill", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns the local block without calling the remote API", async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      return new Response(
        JSON.stringify({ blocked: false, reason: "remote allow", ruleId: null, outcome: "allow", evaluatedAt: new Date().toISOString(), rulesEvaluated: 0 }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const gov = createGovernance({ serverUrl: "https://gov.example.test", apiKey: "ak_test" });
    const ks = createKillSwitch(gov);
    await ks.kill("agent-1", "hosted kill");

    const d = await gov.enforce({ agentId: "agent-1", action: "tool_call", tool: "x" });
    assert.equal(d.outcome, "block");
    assert.equal(d.ruleId, "__kill_switch__agent-1");
    const pre = await gov.enforcePreprocess({ agentId: "agent-1", action: "message_send", input: { message: "hi" } });
    assert.equal(pre.outcome, "block");
    assert.equal(calls, 0, "remote API must not be consulted for a killed agent");

    // an un-killed agent still goes remote
    const other = await gov.enforce({ agentId: "agent-2", action: "tool_call", tool: "x" });
    assert.equal(other.outcome, "allow");
    assert.equal(calls, 1);
  });
});
