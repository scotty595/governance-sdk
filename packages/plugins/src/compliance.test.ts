import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createGovernance, blockTools, requireApproval, tokenBudget } from "governance-sdk";
import {
  assessCompliance,
  getArticles,
  getDaysUntilDeadline,
  EU_AI_ACT_SCHEDULE,
} from "./compliance.js";

// Fixed reference instant so day counts are deterministic (UTC midnight).
const AS_OF = new Date("2026-09-04T00:00:00Z");

describe("EU AI Act Compliance (Articles 9, 11, 12, 14, 15)", () => {
  it("returns low score when governance is unconfigured", async () => {
    const gov = createGovernance({});
    const report = await assessCompliance({
      governance: gov,
      agents: [],
    });

    assert.ok(report.overallScore < 50);
    assert.equal(report.status, "non-compliant");
    assert.ok(report.criticalGaps.length > 0);
    assert.ok(report.recommendations.length > 0);
    assert.equal(report.articles.length, 6);
    // `daysUntilDeadline` is computed from the soonest upcoming per-article
    // deadline. If *all* deadlines are past, the number is negative — that's
    // honest and informative, so don't assert > 0.
    assert.equal(typeof report.daysUntilDeadline, "number");
  });

  it("surfaces a legal disclaimer and the phased application schedule", async () => {
    const gov = createGovernance({});
    const report = await assessCompliance({ governance: gov, agents: [] });

    assert.ok(report.disclaimer, "disclaimer missing");
    assert.match(report.disclaimer!, /not legal advice/i);
    assert.match(report.disclaimer!, /Art 5-7|prohibited/i);
    assert.match(report.disclaimer!, /2026\/1744/, "disclaimer should name the Omnibus revision");
    assert.equal(report.regulationRevision, "Reg. (EU) 2024/1689 as amended by Reg. (EU) 2026/1744");
    assert.equal(report.annex, "III");

    const pd = report.phasedDeadlines;
    assert.equal(pd.prohibitedPractices, "2025-02-02");
    assert.equal(pd.gpaiModelObligations, "2025-08-02");
    // Legacy alias — must equal the GPAI-model date, NOT the Art 50 date.
    assert.equal(pd.gpaiTransparency, pd.gpaiModelObligations);
    assert.equal(pd.article50Transparency, "2026-08-02");
    assert.equal(pd.annexIIIHighRisk, "2027-12-02");
    assert.equal(pd.annexIHighRisk, "2028-08-02");
    // Legacy keys resolve for the default annex (III) / Art 113(c) milestone.
    assert.equal(pd.highRiskObligations, "2027-12-02");
    assert.equal(pd.postMarketAndDownstream, "2028-08-02");
  });

  it("each article keeps its own deadline (not a single hardcoded date)", async () => {
    const gov = createGovernance({});
    const report = await assessCompliance({ governance: gov, agents: [] });
    const art50 = report.articles.find((a) => a.article === "50");
    const art9 = report.articles.find((a) => a.article === "9");
    assert.ok(art50 && art9);
    assert.equal(art50!.deadline, "2026-08-02");
    assert.equal(art9!.deadline, "2027-12-02");
  });

  it("Art 50 transparency applies from 2026-08-02 — not the 2025-08-02 GPAI date — under either annex", async () => {
    const gov = createGovernance({});
    for (const annex of ["I", "III"] as const) {
      const report = await assessCompliance({ governance: gov, agents: [], annex });
      const art50 = report.articles.find((a) => a.article === "50")!;
      assert.equal(art50.deadline, EU_AI_ACT_SCHEDULE.milestones.article50Transparency.date);
      assert.equal(art50.deadline, "2026-08-02");
      assert.notEqual(art50.deadline, report.phasedDeadlines.gpaiModelObligations);
    }
  });

  it("annex: 'I' resolves the high-risk articles to 2028-08-02", async () => {
    const gov = createGovernance({});
    const report = await assessCompliance({ governance: gov, agents: [], annex: "I" });
    assert.equal(report.annex, "I");
    for (const art of ["9", "11", "12", "14", "15"]) {
      assert.equal(report.articles.find((a) => a.article === art)!.deadline, "2028-08-02", `Art ${art}`);
    }
    assert.equal(report.phasedDeadlines.highRiskObligations, "2028-08-02");
    assert.equal(report.phasedDeadlines.annexIIIHighRisk, "2027-12-02", "annex III milestone still reported");
  });

  it("daysUntilDeadline counts to the soonest upcoming deadline for the annex", async () => {
    const gov = createGovernance({});
    // As of 2026-09-04 Art 50 (2026-08-02) has passed, so the next milestone
    // is the high-risk date: 2027-12-02 (Annex III) or 2028-08-02 (Annex I).
    const iii = await assessCompliance({ governance: gov, agents: [], asOf: AS_OF });
    assert.equal(iii.daysUntilDeadline, 454);
    const i = await assessCompliance({ governance: gov, agents: [], annex: "I", asOf: AS_OF });
    assert.equal(i.daysUntilDeadline, 698);
    // Before Art 50 applied, it was the soonest deadline.
    const early = await assessCompliance({ governance: gov, agents: [], asOf: new Date("2026-01-15T00:00:00Z") });
    assert.equal(early.daysUntilDeadline, 199);
  });

  it("scores higher with policies and registered agents", async () => {
    const gov = createGovernance({
      rules: [
        blockTools(["shell_exec", "database_drop"]),
        requireApproval(["payment"]),
        tokenBudget(100000),
      ],
    });

    // Register an agent
    const agent = await gov.register({
      name: "sales-agent",
      framework: "mastra",
      owner: "sales-team",
      description: "Handles customer outreach",
      tools: ["email_draft", "crm_update"],
      hasAuth: true,
      hasGuardrails: true,
    });

    // Trigger some enforcement
    await gov.enforce({
      agentId: agent.id,
      agentName: "sales-agent",
      agentLevel: agent.level,
      action: "tool_call",
      tool: "shell_exec",
    });

    const agents = await gov.storage.listAgents();
    const report = await assessCompliance({
      governance: gov,
      agents,
      auditIntegrity: true,
      humanOversight: true,
      policiesTested: true,
      configVersionControlled: true,
      logRetention: true,
    });

    assert.ok(report.overallScore >= 80, `Expected >= 80, got ${report.overallScore}`);
    assert.equal(report.status, "compliant");
    assert.equal(report.agentsAssessed, 1);
  });

  it("identifies specific gaps for Article 12 (record-keeping)", async () => {
    const gov = createGovernance({
      rules: [blockTools(["shell_exec"])],
    });

    const agents = await gov.storage.listAgents();
    const report = await assessCompliance({
      governance: gov,
      agents,
      auditIntegrity: false, // Not using tamper-evident logs
    });

    const art12 = report.articles.find((a) => a.article === "12");
    assert.ok(art12);

    // Should flag missing audit integrity
    const integrityReq = art12.requirements.find((r) => r.requirementId === "art12-integrity");
    assert.ok(integrityReq);
    assert.equal(integrityReq.status, "non-compliant");
    assert.ok(integrityReq.remediation?.includes("createIntegrityAudit"));
  });

  it("identifies missing human oversight (Article 14)", async () => {
    const gov = createGovernance({
      rules: [blockTools(["shell_exec"])], // No requireApproval
    });

    const agents = await gov.storage.listAgents();
    const report = await assessCompliance({
      governance: gov,
      agents,
    });

    const art14 = report.articles.find((a) => a.article === "14");
    assert.ok(art14);

    const interventionReq = art14.requirements.find((r) => r.requirementId === "art14-intervention");
    assert.ok(interventionReq);
    assert.equal(interventionReq.status, "non-compliant");
  });

  it("recognizes requireApproval as human oversight", async () => {
    const gov = createGovernance({
      rules: [requireApproval(["payment", "data_access"])],
    });

    const agents = await gov.storage.listAgents();
    const report = await assessCompliance({
      governance: gov,
      agents,
    });

    const art14 = report.articles.find((a) => a.article === "14");
    assert.ok(art14);

    const interventionReq = art14.requirements.find((r) => r.requirementId === "art14-intervention");
    assert.ok(interventionReq);
    assert.equal(interventionReq.status, "compliant");
  });

  it("getArticles returns 6 EU AI Act articles", () => {
    const articles = getArticles();
    assert.equal(articles.length, 6);
    assert.deepEqual(
      articles.map((a) => a.article),
      ["9", "11", "12", "14", "15", "50"],
    );
  });

  it("getDaysUntilDeadline tracks the high-risk milestone for the annex", () => {
    assert.equal(getDaysUntilDeadline("III", AS_OF), 454);
    assert.equal(getDaysUntilDeadline("I", AS_OF), 698);
    // Default annex is III; default `now` is the wall clock.
    const days = getDaysUntilDeadline();
    const expected = getDaysUntilDeadline("III", new Date());
    assert.ok(Math.abs(days - expected) <= 1);
    assert.equal(EU_AI_ACT_SCHEDULE.milestones.annexIIIHighRisk.supersedes, "2026-08-02");
  });

  it("getArticles resolves deadlines per annex", () => {
    assert.equal(getArticles("I").find((a) => a.article === "9")!.deadline, "2028-08-02");
    assert.equal(getArticles("III").find((a) => a.article === "9")!.deadline, "2027-12-02");
    assert.equal(getArticles("I").find((a) => a.article === "50")!.deadline, "2026-08-02");
  });
});
