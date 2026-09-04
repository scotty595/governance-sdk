/**
 * standards/imda-agentic — the framework that asks for what this SDK does,
 * so most verdicts should move on a single policy or registration change.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createGovernance, blockTools, requireApproval, tokenBudget, networkAllowlist,
  CORE_VERSION, satisfiesRange,
} from "governance-sdk";
import type { GovernanceInstance, StoredAgent } from "governance-sdk";
import { createKillSwitch } from "@governance-sdk/core/kill-switch.js";
import { mapToImdaAgentic, IMDA_AGENTIC_PILLARS, getImdaRequirements, type ImdaAgenticReport } from "../imda-agentic.js";
import { imdaAgenticPlugin } from "./standards-plugin.js";

const ID = "standards/imda-agentic";

async function fixture(): Promise<{ governance: GovernanceInstance; agents: StoredAgent[]; agentId: string }> {
  const governance = createGovernance({
    rules: [blockTools(["shell_exec"]), requireApproval(["payment"]), tokenBudget(10_000)],
  });
  const agent = await governance.register({
    name: "ops-agent", framework: "vercel-ai", owner: "ops-lead", description: "Files expense reports",
    tools: ["expense_submit"], hasAuth: true, hasAuditLog: true, hasObservability: true,
    metadata: { hasAuth: true },
  });
  return { governance, agents: await governance.storage.listAgents(), agentId: agent.id };
}

function withoutTimestamp<T extends { generatedAt: string }>(report: T): Omit<T, "generatedAt"> {
  const { generatedAt, ...rest } = report;
  assert.ok(generatedAt);
  return rest;
}

function requirement(report: ImdaAgenticReport, id: string) {
  const found = report.pillars.flatMap((p) => p.requirements).find((r) => r.requirementId === id);
  assert.ok(found, `requirement ${id} missing from report`);
  return found;
}

describe("standards/imda-agentic — plugin contract", () => {
  it("carries v1.0's publication date as its version and requires only reporters", () => {
    const plugin = imdaAgenticPlugin();
    assert.equal(plugin.id, ID);
    assert.equal(plugin.version, "2026.1.22");
    assert.ok(satisfiesRange(CORE_VERSION, plugin.requires!.core));
    assert.deepEqual(plugin.requires!.capabilities, ["reporters"]);
  });

  it("the reporter returns what the direct call returns", async () => {
    const { governance, agents } = await fixture();
    await governance.use!(imdaAgenticPlugin());
    const config = { governance, agents, policiesTested: true };
    const direct = await mapToImdaAgentic(config);
    const viaPlugin = await governance.report!<ImdaAgenticReport>(ID, config);
    assert.deepEqual(withoutTimestamp(viaPlugin), withoutTimestamp(direct));
    assert.equal(viaPlugin.revision, "IMDA Model AI Governance Framework for Agentic AI, Version 1.0 (22 January 2026)");
    assert.match(viaPlugin.disclaimer, /Version 1\.5/);
    assert.ok(viaPlugin.sourceUrls.some((u) => u.startsWith("https://www.imda.gov.sg/")));
  });

  it("installing twice is a no-op", async () => {
    const gov = createGovernance();
    await gov.use!(imdaAgenticPlugin());
    await gov.use!(imdaAgenticPlugin());
    assert.equal(gov.plugins!().length, 1);
    const report = await gov.report!<ImdaAgenticReport>(ID, { governance: gov, agents: [] });
    assert.equal(report.pillars.length, 4);
  });

  it("unuse() frees the reporter id", async () => {
    const gov = createGovernance();
    await gov.use!(imdaAgenticPlugin());
    await gov.unuse!(ID);
    await assert.rejects(() => gov.report!(ID, { governance: gov, agents: [] }), /No reporter registered/);
    await gov.use!(imdaAgenticPlugin());
    assert.equal(gov.plugins!().length, 1);
  });
});

describe("standards/imda-agentic — verdicts follow governance state", () => {
  it("tables the four v1.0 pillars with seventeen sourced, section-numbered requirements", () => {
    assert.deepEqual(IMDA_AGENTIC_PILLARS.map((p) => p.id), ["2.1", "2.2", "2.3", "2.4"]);
    assert.deepEqual(IMDA_AGENTIC_PILLARS.map((p) => p.title), [
      "Assess and bound the risks upfront",
      "Make humans meaningfully accountable",
      "Implement technical controls and processes",
      "Enable end-user responsibility",
    ]);
    const reqs = getImdaRequirements();
    assert.equal(reqs.length, 17);
    for (const r of reqs) {
      assert.match(r.section, /^2\.[1-4]\.[1-3]$/, r.id);
      assert.ok(r.section.startsWith(IMDA_AGENTIC_PILLARS.find((p) => p.requirements.includes(r))!.id), r.id);
      assert.ok(r.sourceUrl.startsWith("https://www.imda.gov.sg/"), r.id);
    }
  });

  it("§2.2.2 approval checkpoints are non-compliant without a require_approval rule", async () => {
    const governance = createGovernance({ rules: [blockTools(["shell_exec"])] });
    await governance.register({ name: "a", framework: "mastra", owner: "x", tools: ["t"], hasAuth: true, metadata: { hasAuth: true } });
    const agents = await governance.storage.listAgents();
    const before = await mapToImdaAgentic({ governance, agents });
    assert.equal(requirement(before, "p2-approval-checkpoints").status, "non-compliant");

    governance.addRule(requireApproval(["payment"]));
    const after = await mapToImdaAgentic({ governance, agents });
    assert.equal(requirement(after, "p2-approval-checkpoints").status, "compliant");
    assert.ok(after.pillars.find((p) => p.article === "2.2")!.score > before.pillars.find((p) => p.article === "2.2")!.score);
  });

  it("§2.1.2 contained impact climbs fail → partial → compliant as boundary and kill switch arrive", async () => {
    const { governance, agents, agentId } = await fixture();
    assert.equal(requirement(await mapToImdaAgentic({ governance, agents }), "p1-contained-impact").status, "non-compliant");
    assert.equal(requirement(await mapToImdaAgentic({ governance, agents }), "p3-termination").status, "non-compliant");

    await createKillSwitch(governance).kill(agentId, "runaway");
    const mid = await mapToImdaAgentic({ governance, agents });
    assert.equal(requirement(mid, "p1-contained-impact").status, "partial");
    assert.equal(requirement(mid, "p3-termination").status, "compliant");

    governance.addRule(networkAllowlist(["api.internal"]));
    const after = await mapToImdaAgentic({ governance, agents });
    assert.equal(requirement(after, "p1-contained-impact").status, "compliant");
    assert.equal(requirement(after, "p3-trusted-servers").status, "compliant");
  });

  it("§2.1.2 agent identity needs both an authenticated identity and an owner", async () => {
    const governance = createGovernance();
    await governance.register({ name: "anon", framework: "mastra", owner: "team", tools: ["t"] });
    const unauthenticated = await governance.storage.listAgents();
    const before = await mapToImdaAgentic({ governance, agents: unauthenticated });
    assert.equal(requirement(before, "p1-agent-identity").status, "partial");

    await governance.register({ name: "signed", framework: "mastra", owner: "team", tools: ["t"], hasAuth: true, metadata: { hasAuth: true } });
    const mixed = await governance.storage.listAgents();
    assert.equal(requirement(await mapToImdaAgentic({ governance, agents: mixed }), "p1-agent-identity").status, "partial");

    const onlySigned = mixed.filter((a) => a.name === "signed");
    assert.equal(requirement(await mapToImdaAgentic({ governance, agents: onlySigned }), "p1-agent-identity").status, "compliant");
  });

  it("§2.4.2 user education is not-applicable until attested, and is excluded from the pillar score until then", async () => {
    const { governance, agents } = await fixture();
    const unattested = await mapToImdaAgentic({ governance, agents });
    assert.equal(requirement(unattested, "p4-user-education").status, "not-applicable");
    // Disclosure and escalation both pass on the fixture, so the pillar is 100 over two assessable requirements.
    assert.equal(unattested.pillars.find((p) => p.article === "2.4")!.score, 100);

    const attested = await mapToImdaAgentic({ governance, agents, usersTrained: true });
    assert.equal(requirement(attested, "p4-user-education").status, "compliant");
    assert.equal(attested.pillars.find((p) => p.article === "2.4")!.score, 100);
    assert.equal(attested.pillars.find((p) => p.article === "2.4")!.requirements.length, 3);
  });
});
