/**
 * standards/csa-aicm — a domain-level mapping that says so, whose scored
 * domains move with the governance state and whose unscored ones never
 * distort the number.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createGovernance, blockTools, requireApproval, tokenBudget, allowOnlyTools,
  CORE_VERSION, satisfiesRange,
} from "governance-sdk";
import type { GovernanceInstance, StoredAgent } from "governance-sdk";
import { createKillSwitch } from "@governance-sdk/core/kill-switch.js";
import { createSupplyChainPolicy } from "../supply-chain.js";
import {
  mapToCsaAicm, CSA_AICM_DOMAINS, AICM_ASSESSED_DOMAINS, AICM_OUT_OF_SCOPE_DOMAINS,
  type CsaAicmReport,
} from "../csa-aicm.js";
import { csaAicmPlugin } from "./standards-plugin.js";

const ID = "standards/csa-aicm";

/** The 18 AICM domain codes, in CSA's published order. */
const DOMAIN_ORDER = [
  "A&A", "AIS", "BCR", "CCC", "CEK", "DCS", "DSP", "GRC", "HRS",
  "IAM", "IPY", "I&S", "LOG", "MDS", "SEF", "STA", "TVM", "UEM",
];

async function fixture(): Promise<{ governance: GovernanceInstance; agents: StoredAgent[]; agentId: string }> {
  const governance = createGovernance({
    rules: [blockTools(["shell_exec"]), requireApproval(["payment"]), tokenBudget(10_000)],
  });
  const agent = await governance.register({
    name: "aicm-agent", framework: "langchain", owner: "security", description: "Triages tickets",
    tools: ["ticket_update"], hasAuth: true, hasAuditLog: true, hasObservability: true,
    metadata: { hasAuth: true },
  });
  return { governance, agents: await governance.storage.listAgents(), agentId: agent.id };
}

function withoutTimestamp<T extends { generatedAt: string }>(report: T): Omit<T, "generatedAt"> {
  const { generatedAt, ...rest } = report;
  assert.ok(generatedAt);
  return rest;
}

function requirement(report: CsaAicmReport, id: string) {
  const found = report.domains.flatMap((d) => d.requirements).find((r) => r.requirementId === id);
  assert.ok(found, `requirement ${id} missing from report`);
  return found;
}

describe("standards/csa-aicm — plugin contract", () => {
  it("carries AICM v1.1 as its version and requires only reporters", () => {
    const plugin = csaAicmPlugin();
    assert.equal(plugin.id, ID);
    assert.equal(plugin.version, "1.1.0");
    assert.ok(satisfiesRange(CORE_VERSION, plugin.requires!.core));
    assert.deepEqual(plugin.requires!.capabilities, ["reporters"]);
  });

  it("the reporter returns what the direct call returns", async () => {
    const { governance, agents } = await fixture();
    await governance.use!(csaAicmPlugin());
    const config = { governance, agents, auditIntegrity: true };
    const direct = await mapToCsaAicm(config);
    const viaPlugin = await governance.report!<CsaAicmReport>(ID, config);
    assert.deepEqual(withoutTimestamp(viaPlugin), withoutTimestamp(direct));
    assert.equal(viaPlugin.revision, "CSA AI Controls Matrix v1.1 (released 2026-06-22)");
    assert.equal(viaPlugin.totalControlObjectives, 247);
    assert.ok(viaPlugin.sourceUrls.includes("https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1"));
  });

  it("installing twice is a no-op", async () => {
    const gov = createGovernance();
    await gov.use!(csaAicmPlugin());
    await gov.use!(csaAicmPlugin());
    assert.equal(gov.plugins!().length, 1);
    const report = await gov.report!<CsaAicmReport>(ID, { governance: gov, agents: [] });
    assert.equal(report.domains.length, 18);
  });

  it("unuse() frees the reporter id", async () => {
    const gov = createGovernance();
    await gov.use!(csaAicmPlugin());
    await gov.unuse!(ID);
    await assert.rejects(() => gov.report!(ID, { governance: gov, agents: [] }), /No reporter registered/);
    await gov.use!(csaAicmPlugin());
    assert.equal(gov.plugins!().length, 1);
  });
});

describe("standards/csa-aicm — an honest half-mapping", () => {
  it("enumerates all 18 domains in CSA's order, with v1.0 control counts summing to 243", () => {
    assert.deepEqual(CSA_AICM_DOMAINS.map((d) => d.code), DOMAIN_ORDER);
    assert.equal(CSA_AICM_DOMAINS.reduce((n, d) => n + d.controlCount, 0), 243);
    assert.ok(CSA_AICM_DOMAINS.every((d) => d.asOfVersion === "1.0" && d.sourceUrl.startsWith("https://")));
    // The four codes CSA's guidance PDF does not print are flagged, not asserted.
    assert.deepEqual(CSA_AICM_DOMAINS.filter((d) => !d.codeVerified).map((d) => d.code), ["BCR", "CCC", "DCS", "LOG"]);
    assert.equal(AICM_ASSESSED_DOMAINS.length, 10);
    assert.equal(AICM_OUT_OF_SCOPE_DOMAINS.length, 8);
  });

  it("out-of-scope domains are not-applicable at 0, named in the disclaimer, and excluded from the score", async () => {
    const { governance, agents } = await fixture();
    const report = await mapToCsaAicm({ governance, agents });
    const outOfScope = report.domains.filter((d) => AICM_OUT_OF_SCOPE_DOMAINS.includes(d.article as never));
    assert.equal(outOfScope.length, 8);
    for (const d of outOfScope) {
      assert.equal(d.coverage, "not-applicable", d.article);
      assert.equal(d.score, 0, d.article);
      assert.equal(d.requirements.length, 0, d.article);
    }
    for (const code of [...AICM_OUT_OF_SCOPE_DOMAINS, ...AICM_ASSESSED_DOMAINS]) {
      assert.ok(report.disclaimer.includes(code), `disclaimer omits ${code}`);
    }
    assert.match(report.disclaimer, /none of AICM v1\.1's 247 control objectives are individually/);
    // The overall score is the mean of the ten scored domains — the eight zeros do not drag it.
    const scored = report.domains.filter((d) => d.coverage !== "not-applicable");
    assert.equal(scored.length, 10);
    const mean = Math.round(scored.reduce((n, d) => n + d.score, 0) / scored.length);
    assert.equal(report.overallScore, mean);
  });

  it("SEF containment is non-compliant until a kill switch is armed", async () => {
    const { governance, agents, agentId } = await fixture();
    const before = await mapToCsaAicm({ governance, agents });
    assert.equal(requirement(before, "sef-containment").status, "non-compliant");
    const sefBefore = before.domains.find((d) => d.article === "SEF")!;

    await createKillSwitch(governance).kill(agentId, "incident");
    const after = await mapToCsaAicm({ governance, agents, auditIntegrity: true });
    assert.equal(requirement(after, "sef-containment").status, "compliant");
    assert.ok(after.domains.find((d) => d.article === "SEF")!.score > sefBefore.score);
  });

  it("IAM least privilege and STA approved components flip on their respective policies", async () => {
    const governance = createGovernance({ rules: [requireApproval(["payment"])] });
    await governance.register({
      name: "open-agent", framework: "mastra", owner: "ops", tools: ["web_search"],
      hasAuth: true, metadata: { hasAuth: true },
    });
    const agents = await governance.storage.listAgents();

    const before = await mapToCsaAicm({ governance, agents });
    assert.equal(requirement(before, "iam-least-privilege").status, "non-compliant");
    assert.equal(requirement(before, "sta-approved-components").status, "non-compliant");

    governance.addRule(allowOnlyTools(["web_search"]));
    governance.addRule(createSupplyChainPolicy({ approvedTools: ["web_search"] }));
    const after = await mapToCsaAicm({ governance, agents });
    assert.equal(requirement(after, "iam-least-privilege").status, "compliant");
    assert.equal(requirement(after, "sta-approved-components").status, "compliant");
    assert.ok(after.overallScore > before.overallScore);
  });
});
