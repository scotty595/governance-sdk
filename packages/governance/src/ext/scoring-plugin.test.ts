/**
 * The scoring plugin adds a route to the scorers, not a second scoring model:
 * the reports must equal the direct calls, and the behavioural report must
 * agree with `computeBehavioralAdjustments` over the instance's own audit.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createGovernance, blockTools, CORE_VERSION, satisfiesRange } from "../index";
import type { AgentRegistration, GovernanceAssessment } from "../types";
import { assessAgent, assessFleet } from "../scorer";
import { computeBehavioralAdjustments, type BehavioralAssessment } from "../behavioral-scorer";
import { scoringPlugin } from "./scoring-plugin";

const SALES: AgentRegistration = {
  name: "sales-agent", framework: "mastra", owner: "sales",
  tools: ["crm_update", "email_draft"], hasAuth: true, hasAuditLog: true, hasObservability: true,
};
const OPS: AgentRegistration = { name: "ops-agent", framework: "custom", owner: "ops", tools: [] };

/** Assessments carry a wall-clock `assessedAt`; everything else must match. */
function withoutTimestamp(a: GovernanceAssessment): Omit<GovernanceAssessment, "assessedAt"> {
  const { assessedAt, ...rest } = a;
  assert.ok(assessedAt, "assessment should still carry an assessedAt");
  return rest;
}

describe("scoringPlugin — install", () => {
  it("requires a kernel this one satisfies, and the events capability it actually uses", () => {
    const plugin = scoringPlugin();
    assert.equal(plugin.id, "scoring/posture");
    assert.ok(satisfiesRange(CORE_VERSION, plugin.requires!.core));
    assert.deepEqual(plugin.requires!.capabilities, ["reporters", "events"]);
  });

  it("installing twice is a no-op", async () => {
    const gov = createGovernance();
    await gov.use!(scoringPlugin());
    await gov.use!(scoringPlugin());
    assert.equal(gov.plugins!().length, 1);
    assert.equal(gov.plugins!()[0].version, "1.0.0");
  });

  it("unuse() drops the enforcement subscription", async () => {
    const gov = createGovernance();
    await gov.use!(scoringPlugin());
    assert.equal(gov.events.listenerCount("enforcement"), 1);
    await gov.unuse!("scoring/posture");
    assert.equal(gov.events.listenerCount("enforcement"), 0);
  });
});

describe("scoringPlugin — posture reports match the direct call", () => {
  it("scoring/agent === assessAgent", async () => {
    const gov = createGovernance();
    await gov.use!(scoringPlugin());
    const viaPlugin = await gov.report!<GovernanceAssessment>("scoring/agent", {
      agentId: "agent-1", registration: SALES,
    });
    assert.deepEqual(withoutTimestamp(viaPlugin), withoutTimestamp(assessAgent("agent-1", SALES)));
  });

  it("scoring/fleet === assessFleet", async () => {
    const gov = createGovernance();
    await gov.use!(scoringPlugin());
    const agents = [{ id: "agent-1", registration: SALES }, { id: "agent-2", registration: OPS }];

    const direct = assessFleet(agents);
    const viaPlugin = await gov.report!<ReturnType<typeof assessFleet>>("scoring/fleet", { agents });
    assert.deepEqual(
      viaPlugin.assessments.map(withoutTimestamp),
      direct.assessments.map(withoutTimestamp),
    );
    assert.deepEqual(viaPlugin.summary, direct.summary);
  });

  it("a reporter called without its config says so", async () => {
    const gov = createGovernance();
    await gov.use!(scoringPlugin());
    await assert.rejects(() => gov.report!("scoring/agent"), /Reporter "scoring\/agent" expects a config object/);
  });
});

describe("scoringPlugin — behavioural report from live enforcement", () => {
  it("agrees with computeBehavioralAdjustments over the instance's own audit events", async () => {
    const gov = createGovernance({ rules: [blockTools(["shell_exec"])] });
    await gov.use!(scoringPlugin());
    const agent = await gov.register(SALES);

    await gov.enforce({ agentId: agent.id, action: "tool_call", tool: "crm_update" });
    await gov.enforce({ agentId: agent.id, action: "tool_call", tool: "email_draft" });
    await gov.enforce({ agentId: agent.id, action: "tool_call", tool: "shell_exec" });
    // Audit writes are fire-and-forget off the hot path.
    await new Promise((r) => setTimeout(r, 10));

    const declaredTools = SALES.tools!;
    const viaPlugin = await gov.report!<BehavioralAssessment>("scoring/behavioral", {
      agentId: agent.id, declaredTools,
    });

    const stored = (await gov.audit.query({ agentId: agent.id }))
      .filter((e) => e.eventType.startsWith("policy_evaluation"));
    const expected = computeBehavioralAdjustments({ events: stored, declaredTools });

    assert.equal(viaPlugin.signals.totalEvents, 3);
    assert.equal(viaPlugin.signals.totalEvents, expected.signals.totalEvents);
    assert.equal(viaPlugin.signals.blockRate, expected.signals.blockRate);
    assert.ok(viaPlugin.signals.blockRate > 0, "one of the three calls was blocked");
    assert.deepEqual(
      [...viaPlugin.signals.uniqueToolsObserved].sort(),
      [...expected.signals.uniqueToolsObserved].sort(),
    );
    assert.deepEqual(viaPlugin.signals.undeclaredTools, ["shell_exec"]);
    // Adjustment values are timestamp-independent (both mirrors are "now"),
    // so they must match dimension for dimension.
    assert.deepEqual(
      viaPlugin.adjustments.map((a) => [a.dimension, a.adjustment]),
      expected.adjustments.map((a) => [a.dimension, a.adjustment]),
    );
  });

  it("scores an unseen agent as no-activity rather than throwing", async () => {
    const gov = createGovernance();
    await gov.use!(scoringPlugin());
    const report = await gov.report!<BehavioralAssessment>("scoring/behavioral", { agentId: "never-ran" });
    assert.equal(report.signals.totalEvents, 0);
    assert.equal(report.signals.lastActivityAt, null);
  });

  it("keeps the mirror bounded", async () => {
    const gov = createGovernance();
    await gov.use!(scoringPlugin({ maxEventsPerAgent: 5 }));
    const agent = await gov.register(OPS);
    for (let i = 0; i < 12; i++) {
      await gov.enforce({ agentId: agent.id, action: "tool_call", tool: `t${i}` });
    }
    const report = await gov.report!<BehavioralAssessment>("scoring/behavioral", { agentId: agent.id });
    assert.equal(report.signals.totalEvents, 5);
    assert.deepEqual(report.signals.uniqueToolsObserved, ["t7", "t8", "t9", "t10", "t11"]);
  });
});
