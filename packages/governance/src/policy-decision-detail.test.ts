/**
 * Decisions that teach, and masks that fail closed.
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import { createGovernance, blockTools, maskSensitiveOutput, requireToolApproval } from "./index.js";
import type { PolicyRule } from "@governance-sdk/core/policy.js";

describe("decision detail", () => {
  it("carries stage, condition type and a remedy on block", async () => {
    const gov = createGovernance({ rules: [blockTools(["shell_exec"])] });
    const d = await gov.enforce({ agentId: "a", action: "tool_call", tool: "shell_exec" });
    assert.equal(d.outcome, "block");
    assert.equal(d.stage, "process");
    assert.deepEqual(d.condition, { type: "tool_blocked" });
    assert.match(d.remedy ?? "", /shell_exec/);
  });

  it("carries the requested stage on a no-match decision", async () => {
    const gov = createGovernance();
    const d = await gov.enforcePreprocess({ agentId: "a", action: "message_send", input: { message: "hi" } });
    assert.equal(d.outcome, "allow");
    assert.equal(d.stage, "preprocess");
    assert.equal(d.remedy, undefined);
  });

  it("approval decisions explain what to approve", async () => {
    const gov = createGovernance({ rules: [requireToolApproval(["send_email"])] });
    const d = await gov.enforce({ agentId: "a", action: "tool_call", tool: "send_email" });
    assert.equal(d.outcome, "require_approval");
    assert.match(d.remedy ?? "", /approval/);
  });
});

describe("mask fails closed", () => {
  it("masks preprocess text supplied as input.message", async () => {
    const gov = createGovernance({ rules: [{ ...maskSensitiveOutput(), stage: "preprocess" }] });
    const d = await gov.enforcePreprocess({
      agentId: "a",
      action: "message_send",
      input: { message: "my ssn is 123-45-6789" },
    });
    assert.equal(d.outcome, "mask");
    assert.ok(d.maskedText);
    assert.ok(!d.maskedText!.includes("123-45-6789"), "masked text still contains the SSN");
  });

  it("prefers inputText when present", async () => {
    const gov = createGovernance({ rules: [{ ...maskSensitiveOutput(), stage: "preprocess" }] });
    const d = await gov.enforcePreprocess({
      agentId: "a",
      action: "message_send",
      inputText: "card 4111 1111 1111 1111 please",
      input: { unrelated: true },
    });
    assert.equal(d.outcome, "mask");
    assert.ok(d.maskedText && !d.maskedText.includes("4111 1111 1111 1111"));
  });

  it("degrades to block when a mask rule matches a condition the masker cannot redact", async () => {
    const rule: PolicyRule = {
      id: "mask-tool",
      name: "mask tool",
      condition: { type: "tool_blocked", params: { tools: ["leaky"] } },
      outcome: "mask",
      reason: "redact leaky",
      priority: 10,
      enabled: true,
    };
    const gov = createGovernance({ rules: [rule] });
    const d = await gov.enforce({ agentId: "a", action: "tool_call", tool: "leaky", input: { message: "secret" } });
    assert.equal(d.outcome, "block");
    assert.equal(d.blocked, true);
    assert.equal(d.degradedFrom, "mask");
    assert.equal(d.maskedText, undefined);
    assert.match(d.reason, /failing closed/);
  });

  it("degrades to block when there is no text to mask", async () => {
    const rule: PolicyRule = {
      id: "mask-all",
      name: "mask all",
      condition: { type: "custom", params: { evaluate: () => true } },
      outcome: "mask",
      reason: "redact",
      priority: 10,
      enabled: true,
    };
    const gov = createGovernance({ rules: [rule] });
    const d = await gov.enforce({ agentId: "a", action: "tool_call", tool: "x" });
    assert.equal(d.outcome, "block");
    assert.equal(d.degradedFrom, "mask");
  });
});
