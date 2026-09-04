/**
 * The standards plugins are a second route to the same report, not a second
 * implementation. Every test here is a form of that claim.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createGovernance, blockTools, requireApproval, tokenBudget, CORE_VERSION, satisfiesRange } from "../index";
import type { GovernanceInstance, StoredAgent } from "../index";
import { mapToEuAiAct } from "../compliance";
import { coverageMatrix, mapToOwaspAgentic } from "../owasp-agentic";
import { mapToNistAiRmf } from "../nist-ai-rmf";
import { mapToIso42001 } from "../iso-42001";
import {
  allStandardsPlugins,
  euAiActPlugin,
  iso42001Plugin,
  nistAiRmfPlugin,
  owaspAgenticPlugin,
} from "./standards-plugin";

/** Fixed reference instant so the EU AI Act day counts are deterministic. */
const AS_OF = new Date("2026-09-04T00:00:00Z");

/** A governed instance with enough configured for the mappings to score above zero. */
async function fixture(): Promise<{ governance: GovernanceInstance; agents: StoredAgent[] }> {
  const governance = createGovernance({
    rules: [blockTools(["shell_exec"]), requireApproval(["payment"]), tokenBudget(10_000)],
  });
  await governance.register({
    name: "sales-agent", framework: "mastra", owner: "sales", tools: ["crm_update"],
    hasAuth: true, hasAuditLog: true, hasObservability: true,
  });
  return { governance, agents: await governance.storage.listAgents() };
}

/** Reports carry a wall-clock `generatedAt`; everything else must match. */
function withoutTimestamp<T extends { generatedAt: string }>(report: T): Omit<T, "generatedAt"> {
  const { generatedAt, ...rest } = report;
  assert.ok(generatedAt, "report should still carry a generatedAt");
  return rest;
}

describe("standards plugins — version gating", () => {
  it("every plugin's requires.core is satisfied by this kernel", () => {
    for (const plugin of allStandardsPlugins()) {
      assert.ok(plugin.requires, `${plugin.id} declares no requires`);
      assert.ok(
        satisfiesRange(CORE_VERSION, plugin.requires!.core),
        `${plugin.id} requires ${plugin.requires!.core}, kernel is ${CORE_VERSION}`,
      );
      assert.deepEqual(plugin.requires!.capabilities, ["reporters"]);
    }
  });

  it("each plugin's version is the revision it implements", () => {
    const versions = Object.fromEntries(allStandardsPlugins().map((p) => [p.id, p.version]));
    assert.deepEqual(versions, {
      // OJ publication date of Reg. (EU) 2026/1744.
      "standards/eu-ai-act": "2026.7.24",
      "standards/owasp-asi": "2026.0.0",
      "standards/nist-ai-rmf": "1.0.0",
      "standards/iso-42001": "2023.0.0",
    });
  });

  it("installs all four side by side", async () => {
    const gov = createGovernance();
    for (const plugin of allStandardsPlugins()) await gov.use!(plugin);
    assert.deepEqual(gov.plugins!().map((p) => p.id).sort(), [
      "standards/eu-ai-act", "standards/iso-42001", "standards/nist-ai-rmf", "standards/owasp-asi",
    ]);
  });

  it("installing twice is a no-op (a second install would re-register the reporter)", async () => {
    const gov = createGovernance();
    await gov.use!(euAiActPlugin());
    await gov.use!(euAiActPlugin());
    assert.equal(gov.plugins!().length, 1);
    const report = await gov.report!<{ overallScore: number }>("standards/eu-ai-act", {
      governance: gov, agents: [], asOf: AS_OF,
    });
    assert.equal(typeof report.overallScore, "number");
  });
});

describe("standards plugins — reports match the direct call", () => {
  it("standards/eu-ai-act === mapToEuAiAct", async () => {
    const { governance, agents } = await fixture();
    await governance.use!(euAiActPlugin());
    const config = { governance, agents, asOf: AS_OF, auditIntegrity: true };

    const direct = await mapToEuAiAct(config);
    const viaPlugin = await governance.report!<typeof direct>("standards/eu-ai-act", config);
    assert.deepEqual(withoutTimestamp(viaPlugin), withoutTimestamp(direct));
    assert.equal(viaPlugin.articles.length, 6);
  });

  it("standards/owasp-asi === mapToOwaspAgentic, and the coverage matrix rides along", async () => {
    const { governance, agents } = await fixture();
    await governance.use!(owaspAgenticPlugin());
    const config = { governance, agents, injectionDetection: true };

    const direct = await mapToOwaspAgentic(config);
    const viaPlugin = await governance.report!<typeof direct>("standards/owasp-asi", config);
    assert.deepEqual(withoutTimestamp(viaPlugin), withoutTimestamp(direct));

    const matrix = await governance.report!<Awaited<ReturnType<typeof coverageMatrix>>>(
      "standards/owasp-asi/coverage", config,
    );
    assert.deepEqual(matrix, await coverageMatrix(config));
    assert.equal(matrix.length, 10);
  });

  it("standards/nist-ai-rmf === mapToNistAiRmf", async () => {
    const { governance, agents } = await fixture();
    await governance.use!(nistAiRmfPlugin());
    const config = { governance, agents, auditIntegrity: true };

    const direct = await mapToNistAiRmf(config);
    const viaPlugin = await governance.report!<typeof direct>("standards/nist-ai-rmf", config);
    assert.deepEqual(withoutTimestamp(viaPlugin), withoutTimestamp(direct));
    assert.equal(viaPlugin.standardVersion, "NIST AI RMF 1.0");
  });

  it("standards/iso-42001 === mapToIso42001", async () => {
    const { governance, agents } = await fixture();
    await governance.use!(iso42001Plugin());
    const config = { governance, agents, policiesTested: true };

    const direct = await mapToIso42001(config);
    const viaPlugin = await governance.report!<typeof direct>("standards/iso-42001", config);
    assert.deepEqual(withoutTimestamp(viaPlugin), withoutTimestamp(direct));
    assert.equal(viaPlugin.standardVersion, "ISO/IEC 42001:2023");
  });

  it("a reporter called without its config says so instead of throwing deep inside a mapping", async () => {
    const gov = createGovernance();
    await gov.use!(nistAiRmfPlugin());
    await assert.rejects(
      () => gov.report!("standards/nist-ai-rmf"),
      /Reporter "standards\/nist-ai-rmf" expects its assessment config object, got undefined/,
    );
  });
});
