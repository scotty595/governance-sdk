/**
 * A report must not crash on one bad row. Found by `scripts/verify-pack.mjs`:
 * the 600-1, CSA and IMDA assessors read `agent.tools.length` and threw on an
 * agent without `tools`. `StoredAgent` types the field as required, but a
 * hand-edited store or an older row can lack it, and the NIST RMF mapping had
 * already learned to guard it.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createGovernance } from "governance-sdk";
import type { StoredAgent } from "@governance-sdk/core/storage.js";
import { allStandardsPlugins } from "./standards-plugin.js";

describe("standards plugins — malformed rows", () => {
  it("every mapping reports over an agent row that lacks `tools`", async () => {
    const gov = createGovernance();
    for (const plugin of allStandardsPlugins()) await gov.use(plugin);
    await gov.register({ name: "whole", owner: "team", framework: "custom", tools: ["search"], hasAuth: true });
    const [whole] = await gov.storage.listAgents();
    assert.ok(whole);
    // The type says `tools` is required; the store does not enforce it.
    const bare = { ...whole, id: "bare", name: "bare", tools: undefined } as unknown as StoredAgent;

    for (const plugin of allStandardsPlugins()) {
      // Not every mapping has a `disclaimer` field (OWASP does not); what
      // matters is that the report resolves rather than throwing on the row.
      const report = await gov.report<Record<string, unknown>>(plugin.id, { governance: gov, agents: [whole, bare] });
      assert.equal(typeof report, "object", `${plugin.id} produced a report`);
    }
  });
});
