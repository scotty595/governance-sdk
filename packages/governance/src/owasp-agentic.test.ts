import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createGovernance, blockTools, requireApproval, tokenBudget, rateLimit } from "./index";
import {
  assessOwaspAgentic,
  mapToOwaspAgentic,
  getOwaspRisks,
  getOwaspRisk,
  getOwaspRisksByLegacyId,
  buildCoverageMatrix,
  coverageMatrix,
  OWASP_LEGACY_ID_MAP,
  OWASP_AGENTIC_PUBLISHED,
  OWASP_AGENTIC_SOURCE_URL,
} from "./owasp-agentic";
import type { OwaspAsiId, OwaspLegacyId } from "./owasp-agentic";

/** Official ids and titles, verbatim — OWASP Top 10 for Agentic Applications 2026. */
const OFFICIAL: Record<OwaspAsiId, string> = {
  ASI01: "Agent Goal Hijack",
  ASI02: "Tool Misuse & Exploitation",
  ASI03: "Identity & Privilege Abuse",
  ASI04: "Agentic Supply Chain Vulnerabilities",
  ASI05: "Unexpected Code Execution (RCE)",
  ASI06: "Memory & Context Poisoning",
  ASI07: "Insecure Inter-Agent Communication",
  ASI08: "Cascading Failures",
  ASI09: "Human-Agent Trust Exploitation",
  ASI10: "Rogue Agents",
};
const LEGACY_IDS = Array.from({ length: 10 }, (_, i) => `OWASP-AA-${String(i + 1).padStart(2, "0")}`) as OwaspLegacyId[];

describe("OWASP Top 10 for Agentic Applications 2026 — schema", () => {
  it("exports the ten official items in order with verbatim titles", () => {
    const risks = getOwaspRisks();
    assert.equal(risks.length, 10);
    assert.deepEqual(risks.map((r) => r.id), Object.keys(OFFICIAL));
    for (const r of risks) assert.equal(r.title, OFFICIAL[r.id], r.id);
  });

  it("every item carries standard, revision, sourceUrl and a legacyId", () => {
    for (const r of getOwaspRisks()) {
      assert.equal(r.standard, "owasp-agentic-2026");
      assert.equal(r.revision, "2026");
      assert.equal(r.sourceUrl, OWASP_AGENTIC_SOURCE_URL);
      assert.match(r.legacyId, /^OWASP-AA-(0[1-9]|10)$/);
      assert.ok(r.requirements.length > 0, `${r.id} has no requirements`);
      for (const req of r.requirements) assert.ok(req.id.startsWith(r.id.toLowerCase() + "-"), req.id);
    }
    assert.equal(OWASP_AGENTIC_PUBLISHED, "2025-12-09");
  });

  it("each requirement has a unique ID", () => {
    const ids = getOwaspRisks().flatMap((r) => r.requirements.map((req) => req.id));
    assert.equal(ids.length, new Set(ids).size, "Duplicate requirement IDs found");
  });

  it("every legacy OWASP-AA id maps to at least one official item", () => {
    for (const legacy of LEGACY_IDS) {
      const targets = OWASP_LEGACY_ID_MAP[legacy];
      assert.ok(targets.length > 0, `${legacy} has no mapping`);
      for (const t of targets) assert.ok(getOwaspRisk(t), `${legacy} → ${t} does not exist`);
      // The primary target (first in the map) declares this legacyId — except
      // AA-08, whose two checks were absorbed by items with their own primary.
      if (legacy !== "OWASP-AA-08") {
        assert.ok(getOwaspRisksByLegacyId(legacy).some((r) => r.id === targets[0]), legacy);
      }
    }
    assert.deepEqual(getOwaspRisksByLegacyId("OWASP-AA-10").map((r) => r.id), ["ASI10"]);
    assert.deepEqual(getOwaspRisksByLegacyId("OWASP-AA-01").map((r) => r.id), ["ASI02", "ASI03"]);
  });

  it("exports mapToOwaspAgentic as an alias of assessOwaspAgentic", () => {
    assert.equal(mapToOwaspAgentic, assessOwaspAgentic);
  });
});

describe("OWASP Top 10 for Agentic Applications 2026 — assessment", () => {
  it("assesses a well-configured governance instance as mostly compliant", async () => {
    const gov = createGovernance({
      rules: [
        blockTools(["shell_exec", "eval"]),
        requireApproval(["payment"]),
        tokenBudget(100_000),
        rateLimit(100, 60_000),
      ],
    });

    const agent = await gov.register({
      name: "test-agent",
      framework: "mastra",
      owner: "team-a",
      tools: ["web_search", "crm_update"],
      hasAuth: true,
      hasGuardrails: true,
      hasObservability: true,
      hasAuditLog: true,
      metadata: { hasAuth: true },
    });

    // Trigger some enforcement
    await gov.enforce({ agentId: agent.id, agentName: "test-agent", agentLevel: agent.level, action: "tool_call", tool: "shell_exec" });

    const stored = await gov.storage.getAgent(agent.id);
    const report = await assessOwaspAgentic({
      governance: gov,
      agents: stored ? [stored] : [],
      auditIntegrity: true,
      injectionDetection: true,
    });

    assert.ok(report.overallScore > 50, `Expected score > 50, got ${report.overallScore}`);
    assert.equal(report.risksTotal, 10);
    assert.ok(report.risksCovered > 0);
    assert.ok(report.generatedAt);
    assert.equal(report.standard, "owasp-agentic-2026");
    assert.equal(report.revision, "2026");
    assert.equal(report.publishedOn, "2025-12-09");
    assert.match(report.scope!, /ASI01-ASI10/);
    assert.doesNotMatch(report.scope!, /internal/i);

    // Report rows are keyed by official id.
    assert.deepEqual(report.risks.map((r) => r.article), Object.keys(OFFICIAL));
    const asi08 = report.risks.find((r) => r.article === "ASI08")!;
    assert.equal(asi08.coverage, "compliant", "token budget + rate limit + audit → ASI08 covered");
  });

  it("assesses empty governance as non-compliant", async () => {
    const gov = createGovernance();
    const report = await assessOwaspAgentic({ governance: gov, agents: [] });

    assert.equal(report.status, "non-compliant");
    assert.ok(report.criticalGaps.length > 0);
    assert.ok(report.recommendations.length > 0);
  });

  it("ASI10 kill-switch requirement is non-compliant with no kill switch registered", async () => {
    const gov = createGovernance();
    const report = await assessOwaspAgentic({ governance: gov, agents: [] });
    const asi10 = report.risks.find((r) => r.article === "ASI10");
    const killReq = asi10!.requirements.find((r) => r.requirementId === "asi10-kill-switch");
    assert.ok(killReq);
    assert.equal(killReq!.status, "non-compliant", "stub used to pass here — now demands a real kill switch");
    assert.ok(killReq!.remediation);
  });

  it("ASI10 kill-switch requirement is compliant once createKillSwitch(gov) has run", async () => {
    const { createKillSwitch } = await import("./kill-switch");
    const gov = createGovernance();
    const agent = await gov.register({ name: "bot", framework: "mastra", owner: "t" });
    const ks = createKillSwitch(gov);
    await ks.kill(agent.id, "incident");
    const agents = await gov.storage.listAgents();
    const report = await assessOwaspAgentic({ governance: gov, agents });
    const killReq = report.risks
      .find((r) => r.article === "ASI10")!
      .requirements.find((r) => r.requirementId === "asi10-kill-switch");
    assert.equal(killReq!.status, "compliant");
  });

  it("ASI06 tool-result scan is covered when an injection rule runs at the tool_result stage", async () => {
    const { createInjectionGuard } = await import("./injection-detect");
    const gov = createGovernance({ rules: [{ ...createInjectionGuard(), stage: "tool_result" }] });
    const report = await assessOwaspAgentic({ governance: gov, agents: [] });
    const scan = report.risks.find((r) => r.article === "ASI06")!.requirements.find((r) => r.requirementId === "asi06-tool-result-scan");
    assert.equal(scan!.status, "compliant");
  });
});

describe("OWASP coverage matrix", () => {
  it("lists all ten official ids with covered / partial / missing", async () => {
    const gov = createGovernance();
    const report = await assessOwaspAgentic({ governance: gov, agents: [] });
    assert.equal(report.coverageMatrix.length, 10);
    assert.deepEqual(report.coverageMatrix.map((e) => e.id), Object.keys(OFFICIAL));
    for (const e of report.coverageMatrix) {
      assert.equal(e.title, OFFICIAL[e.id]);
      assert.ok(["covered", "partial", "missing"].includes(e.status), e.status);
      assert.ok(e.score >= 0 && e.score <= 100);
      const row = report.risks.find((r) => r.article === e.id)!;
      const expected = row.coverage === "compliant" ? "covered" : row.coverage === "partial" ? "partial" : "missing";
      assert.equal(e.status, expected, e.id);
    }
    assert.ok(report.coverageMatrix.some((e) => e.status === "missing"), "empty governance should leave gaps");
  });

  it("coverageMatrix(config) returns the same rows as the report", async () => {
    const gov = createGovernance({ rules: [tokenBudget(1000), rateLimit(5, 1000)] });
    const report = await assessOwaspAgentic({ governance: gov, agents: [] });
    const matrix = await coverageMatrix({ governance: gov, agents: [] });
    assert.deepEqual(matrix, report.coverageMatrix);
  });

  it("buildCoverageMatrix reports unassessed items as missing", () => {
    const matrix = buildCoverageMatrix([]);
    assert.equal(matrix.length, 10);
    for (const e of matrix) {
      assert.equal(e.status, "missing");
      assert.equal(e.score, 0);
      assert.match(e.legacyId, /^OWASP-AA-/);
    }
  });
});
