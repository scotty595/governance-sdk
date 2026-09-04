/**
 * Events, metrics, strict mode and fail-mode reporting on the instance.
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import { createGovernance, blockTools } from "./index.js";
import type { GovernanceEvent } from "./events.js";

describe("events and metrics", () => {
  it("emits enforcement, registration and policy events", async () => {
    const gov = createGovernance({ rules: [blockTools(["rm"])] });
    const seen: GovernanceEvent[] = [];
    gov.events!.onAny((e) => seen.push(e));

    const agent = await gov.register({ name: "bot", framework: "custom", owner: "t" });
    await gov.enforce({ agentId: agent.id, action: "tool_call", tool: "rm" });
    await gov.enforce({ agentId: agent.id, action: "tool_call", tool: "ls" });
    gov.addRule(blockTools(["curl"]));
    gov.removeRule(blockTools(["curl"]).id);

    const types = seen.map((e) => e.type);
    assert.deepEqual(types, ["registration", "enforcement", "enforcement", "policy_added", "policy_removed"]);
    const blocked = seen.find((e) => e.type === "enforcement" && e.detail.blocked === true);
    assert.equal(blocked?.agentId, agent.id);
    assert.equal(blocked?.detail.tool, "rm");

    const snap = gov.metrics!.snapshot();
    const counter = (name: string) => snap.counters.find((c) => c.name === name)?.value ?? 0;
    assert.equal(counter("enforcement.total"), 2);
    assert.equal(counter("enforcement.blocked"), 1);
    assert.equal(counter("enforcement.allowed"), 1);
    assert.equal(counter("registration.total"), 1);
    assert.equal(snap.timings.find((t) => t.name === "enforcement.duration_ms")?.count, 2);
  });
});

describe("fail modes", () => {
  it("reports defaults in local mode", () => {
    const gov = createGovernance();
    assert.deepEqual(gov.failModes!(), {
      mode: "local",
      strict: false,
      remoteFallback: "n/a",
      integrityAudit: "off",
      maskFailure: "block",
      unknownCondition: "reject",
      killSwitch: "all-stages",
      ledger: "on",
    });
  });

  it("strict flips remote fallback and integrity failure to block", () => {
    const gov = createGovernance({
      strict: true,
      serverUrl: "https://gov.example.test",
      apiKey: "ak",
      integrityAudit: { signingKey: "a-sufficiently-long-signing-key" },
      storage: undefined,
    });
    const fm = gov.failModes!();
    assert.equal(fm.mode, "hosted");
    assert.equal(fm.strict, true);
    assert.equal(fm.remoteFallback, "block");
    assert.equal(fm.integrityAudit, "block");
    assert.equal(fm.ledger, "off");
  });

  it("explicit settings win over strict", () => {
    const gov = createGovernance({ strict: true, integrityAudit: { signingKey: "a-sufficiently-long-signing-key", onFailure: "allow" } });
    assert.equal(gov.failModes!().integrityAudit, "allow");
  });

  it("logs one summary line when a logger is supplied", () => {
    const lines: string[] = [];
    createGovernance({ logger: { info: (m) => lines.push(m), warn: (m) => lines.push(`warn:${m}`) } });
    assert.equal(lines.length, 1);
    assert.match(lines[0], /mode=local strict=false .*killSwitch=all-stages ledger=on/);
  });
});

describe("signing key validation", () => {
  it("rejects an empty key", () => {
    assert.throws(() => createGovernance({ integrityAudit: { signingKey: "" } }), /non-empty/);
  });
  it("warns on a short key and rejects it under strict", () => {
    const warns: string[] = [];
    createGovernance({ integrityAudit: { signingKey: "short" }, logger: { info: () => {}, warn: (m) => warns.push(m) } });
    assert.equal(warns.length, 1);
    assert.match(warns[0], /at least 16/);
    assert.throws(() => createGovernance({ strict: true, integrityAudit: { signingKey: "short" } }), /at least 16/);
  });
});

describe("hosted-mode audit warning", () => {
  it("warns once that local audit writes do not reach the API", () => {
    const warns: string[] = [];
    const errors: unknown[] = [];
    createGovernance({
      serverUrl: "https://gov.example.test",
      apiKey: "ak",
      logger: { info: () => {}, warn: (m) => warns.push(m) },
      onAuditError: (e) => errors.push(e),
    });
    assert.equal(warns.length, 1);
    assert.equal(errors.length, 1);
    assert.match(warns[0], /hosted mode/);
  });
});
