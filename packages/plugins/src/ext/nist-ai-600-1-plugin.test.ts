/**
 * standards/nist-ai-600-1 — the plugin is a second route to the same report,
 * and the report's verdicts move when the governance state moves.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createGovernance, blockTools, requireApproval, tokenBudget, sensitiveDataFilter,
  CORE_VERSION, satisfiesRange,
} from "governance-sdk";
import type { GovernanceInstance, StoredAgent } from "governance-sdk";
import { createKillSwitch } from "@governance-sdk/core/kill-switch.js";
import { mapToNistAi600, GAI_RISKS, getGenAiRequirements, type NistAi600Report } from "../nist-ai-600-1.js";
import { nistAi600Plugin } from "./standards-plugin.js";

const ID = "standards/nist-ai-600-1";

/** A governed instance with an owned, authenticated, tool-bearing agent. */
async function fixture(): Promise<{ governance: GovernanceInstance; agents: StoredAgent[]; agentId: string }> {
  const governance = createGovernance({
    rules: [blockTools(["shell_exec"]), requireApproval(["payment"]), tokenBudget(10_000)],
  });
  const agent = await governance.register({
    name: "genai-agent", framework: "mastra", owner: "platform", description: "Drafts replies",
    tools: ["crm_update"], hasAuth: true, hasAuditLog: true, hasObservability: true,
    metadata: { hasAuth: true },
  });
  return { governance, agents: await governance.storage.listAgents(), agentId: agent.id };
}

function withoutTimestamp<T extends { generatedAt: string }>(report: T): Omit<T, "generatedAt"> {
  const { generatedAt, ...rest } = report;
  assert.ok(generatedAt);
  return rest;
}

function requirement(report: NistAi600Report, id: string) {
  const found = report.functions.flatMap((f) => f.requirements).find((r) => r.requirementId === id);
  assert.ok(found, `requirement ${id} missing from report`);
  return found;
}

describe("standards/nist-ai-600-1 — plugin contract", () => {
  it("carries the profile's revision as its version and requires only reporters", () => {
    const plugin = nistAi600Plugin();
    assert.equal(plugin.id, ID);
    assert.equal(plugin.version, "2024.7.26");
    assert.ok(satisfiesRange(CORE_VERSION, plugin.requires!.core));
    assert.deepEqual(plugin.requires!.capabilities, ["reporters"]);
  });

  it("the reporter returns what the direct call returns", async () => {
    const { governance, agents } = await fixture();
    await governance.use!(nistAi600Plugin());
    const config = { governance, agents, auditIntegrity: true };
    const direct = await mapToNistAi600(config);
    const viaPlugin = await governance.report!<NistAi600Report>(ID, config);
    assert.deepEqual(withoutTimestamp(viaPlugin), withoutTimestamp(direct));
    assert.equal(viaPlugin.revision, "NIST AI 600-1 (Generative AI Profile, July 2024)");
    assert.ok(viaPlugin.sourceUrls.includes("https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf"));
    assert.match(viaPlugin.disclaimer, /Self-assessment only/);
  });

  it("installing twice is a no-op", async () => {
    const gov = createGovernance();
    await gov.use!(nistAi600Plugin());
    await gov.use!(nistAi600Plugin());
    assert.equal(gov.plugins!().length, 1);
    const report = await gov.report!<NistAi600Report>(ID, { governance: gov, agents: [] });
    assert.equal(typeof report.overallScore, "number");
  });

  it("unuse() frees the reporter id for a revised edition", async () => {
    const gov = createGovernance();
    await gov.use!(nistAi600Plugin());
    await gov.unuse!(ID);
    await assert.rejects(() => gov.report!(ID, { governance: gov, agents: [] }), /No reporter registered/);
    await gov.use!(nistAi600Plugin());
    assert.equal(gov.plugins!().length, 1);
  });
});

describe("standards/nist-ai-600-1 — verdicts follow governance state", () => {
  it("tables the twelve §2 risks in order and nineteen subcategories, each with a source", () => {
    assert.equal(GAI_RISKS.length, 12);
    assert.deepEqual(GAI_RISKS.map((r) => r.section), ["2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12"]);
    const reqs = getGenAiRequirements();
    assert.equal(reqs.length, 19);
    for (const r of reqs) {
      assert.match(r.subcategory, /^(GOVERN|MAP|MEASURE|MANAGE) \d+\.\d+$/, r.id);
      assert.ok(r.sourceUrl.startsWith("https://"), r.id);
      assert.ok(r.gaiRisks.length > 0, `${r.id} tags no GAI risk`);
    }
  });

  it("MANAGE 2.4 (deactivate) is non-compliant until a kill switch has actually been armed", async () => {
    const { governance, agents, agentId } = await fixture();
    const before = await mapToNistAi600({ governance, agents });
    assert.equal(requirement(before, "mg-2.4").status, "non-compliant");

    await createKillSwitch(governance).kill(agentId, "incident");
    const after = await mapToNistAi600({ governance, agents });
    assert.equal(requirement(after, "mg-2.4").status, "compliant");
    // MEASURE 2.6 (fail safe) moves with it: the token budget was already there.
    assert.equal(requirement(before, "ms-2.6").status, "partial");
    assert.equal(requirement(after, "ms-2.6").status, "compliant");
  });

  it("MEASURE 2.10 (privacy) flips on a sensitive-data filter, and the Data Privacy risk with it", async () => {
    const { governance, agents } = await fixture();
    const before = await mapToNistAi600({ governance, agents });
    assert.equal(requirement(before, "ms-2.10").status, "non-compliant");
    assert.equal(before.gaiRisks.find((r) => r.risk === "data-privacy")!.status, "partial");

    governance.addRule(sensitiveDataFilter());
    const after = await mapToNistAi600({ governance, agents });
    assert.equal(requirement(after, "ms-2.10").status, "compliant");
    // Data Privacy is tagged on ms-2.10 and mp-5.1; both compliant now.
    assert.equal(after.gaiRisks.find((r) => r.risk === "data-privacy")!.status, "compliant");
  });

  it("subcategories the SDK cannot see are not-applicable, excluded from the score, and attestable", async () => {
    const { governance, agents } = await fixture();
    const unattested = await mapToNistAi600({ governance, agents });
    assert.equal(requirement(unattested, "ms-2.11").status, "not-applicable");
    assert.equal(requirement(unattested, "ms-2.12").status, "not-applicable");
    assert.equal(unattested.gaiRisks.find((r) => r.risk === "environmental")!.status, "not-applicable");

    const attested = await mapToNistAi600({ governance, agents, biasEvaluated: true, environmentalImpactAssessed: true });
    assert.equal(requirement(attested, "ms-2.11").status, "compliant");
    assert.equal(requirement(attested, "ms-2.12").status, "compliant");
    assert.equal(attested.gaiRisks.find((r) => r.risk === "environmental")!.status, "compliant");

    // Two more compliant requirements in MEASURE raise its score, so the
    // unattested score was computed over four assessable requirements, not six.
    const measure = (r: NistAi600Report) => r.functions.find((f) => f.article === "MEASURE")!;
    assert.ok(attested.overallScore > unattested.overallScore);
    assert.ok(measure(attested).score > measure(unattested).score);
    assert.equal(measure(unattested).requirements.length, 6);
  });
});
