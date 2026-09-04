import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  EU_AI_ACT_ARTICLES,
  getArticles,
  getDaysUntilDeadline,
} from "./compliance-articles.js";
import type { EuAiActArticle, ArticleRequirement } from "./compliance-articles.js";
import {
  EU_AI_ACT_SCHEDULE,
  buildPhasedDeadlines,
  daysUntil,
  highRiskMilestone,
  resolveDeadline,
} from "./compliance-schedule.js";

const AS_OF = new Date("2026-09-04T00:00:00Z");

describe("EU_AI_ACT_ARTICLES structure", () => {
  test("has exactly 6 articles", () => {
    assert.equal(EU_AI_ACT_ARTICLES.length, 6);
  });

  test("covers all required article numbers", () => {
    const articleNums = EU_AI_ACT_ARTICLES.map((a) => a.article);
    assert.deepEqual(articleNums, ["9", "11", "12", "14", "15", "50"]);
  });

  test("all articles have required fields", () => {
    for (const art of EU_AI_ACT_ARTICLES) {
      assert.ok(art.article, "Missing article number");
      assert.ok(art.title, `Art. ${art.article} missing title`);
      assert.ok(art.description, `Art. ${art.article} missing description`);
      assert.ok(art.deadline, `Art. ${art.article} missing deadline`);
      assert.ok(art.maxFine, `Art. ${art.article} missing maxFine`);
      assert.ok(art.requirements.length > 0, `Art. ${art.article} has no requirements`);
    }
  });

  test("deadlines follow the EU AI Act phased application schedule (post-Omnibus)", () => {
    // Reg. (EU) 2024/1689 as amended by Reg. (EU) 2026/1744: Art 50 applies
    // from 2026-08-02; the Annex III high-risk obligations in Arts 9-15 were
    // deferred from 2026-08-02 to 2027-12-02. See compliance-schedule.ts.
    const expected: Record<string, string> = {
      "9": "2027-12-02",
      "11": "2027-12-02",
      "12": "2027-12-02",
      "14": "2027-12-02",
      "15": "2027-12-02",
      "50": "2026-08-02",
    };
    for (const art of EU_AI_ACT_ARTICLES) {
      assert.equal(
        art.deadline,
        expected[art.article],
        `Art. ${art.article}: expected deadline ${expected[art.article]}, got ${art.deadline}`,
      );
    }
  });

  test("every article carries the standard discriminator and a phase", () => {
    for (const art of EU_AI_ACT_ARTICLES) {
      assert.equal(art.standard, "eu-ai-act");
      assert.equal(art.phase, art.article === "50" ? "article50Transparency" : "highRisk");
    }
  });

  test("all articles have fine information", () => {
    for (const art of EU_AI_ACT_ARTICLES) {
      assert.ok(art.maxFine.includes("EUR") || art.maxFine.includes("turnover"),
        `Art. ${art.article} fine missing EUR or turnover reference`);
    }
  });
});

describe("ArticleRequirement structure", () => {
  const allRequirements = EU_AI_ACT_ARTICLES.flatMap((a) => a.requirements);

  test("has at least 18 total requirements", () => {
    assert.ok(allRequirements.length >= 18, `Only ${allRequirements.length} requirements`);
  });

  test("all requirement IDs are unique", () => {
    const ids = allRequirements.map((r) => r.id);
    assert.equal(ids.length, new Set(ids).size, "Duplicate requirement IDs found");
  });

  test("all requirements have required fields", () => {
    for (const req of allRequirements) {
      assert.ok(req.id, "Missing requirement id");
      assert.ok(req.requirement, `${req.id} missing requirement description`);
      assert.ok(req.sdkFeature, `${req.id} missing sdkFeature`);
      assert.ok(req.checkDescription, `${req.id} missing checkDescription`);
      assert.equal(typeof req.automatable, "boolean", `${req.id} automatable must be boolean`);
    }
  });

  test("requirement IDs follow naming convention (artN-*)", () => {
    for (const req of allRequirements) {
      assert.match(req.id, /^art\d+-.+$/, `${req.id} does not match artN-* pattern`);
    }
  });

  test("most requirements are automatable", () => {
    const automatable = allRequirements.filter((r) => r.automatable).length;
    assert.ok(automatable > allRequirements.length / 2,
      `Only ${automatable}/${allRequirements.length} requirements are automatable`);
  });
});

describe("Article 9 — Risk Management", () => {
  const art9 = EU_AI_ACT_ARTICLES.find((a) => a.article === "9")!;

  test("has 4 requirements", () => {
    assert.equal(art9.requirements.length, 4);
  });

  test("covers risk identification", () => {
    assert.ok(art9.requirements.some((r) => r.id.includes("risk-identification")));
  });

  test("covers risk mitigation", () => {
    assert.ok(art9.requirements.some((r) => r.id.includes("risk-mitigation")));
  });

  test("covers testing", () => {
    const testReq = art9.requirements.find((r) => r.id.includes("testing"));
    assert.ok(testReq);
    assert.equal(testReq!.automatable, false, "Testing requirement should not be automatable");
  });
});

describe("Article 12 — Record-Keeping", () => {
  const art12 = EU_AI_ACT_ARTICLES.find((a) => a.article === "12")!;

  test("has 4 requirements", () => {
    assert.equal(art12.requirements.length, 4);
  });

  test("covers automatic logging", () => {
    assert.ok(art12.requirements.some((r) => r.id.includes("automatic-logging")));
  });

  test("covers integrity (hash chaining)", () => {
    const integrityReq = art12.requirements.find((r) => r.id.includes("integrity"));
    assert.ok(integrityReq);
    assert.ok(integrityReq!.sdkFeature.includes("HMAC"), "Integrity should reference HMAC");
  });

  test("retention is not automatable", () => {
    const retentionReq = art12.requirements.find((r) => r.id.includes("retention"));
    assert.ok(retentionReq);
    assert.equal(retentionReq!.automatable, false);
  });
});

describe("Article 15 — Accuracy, Robustness, Cybersecurity", () => {
  const art15 = EU_AI_ACT_ARTICLES.find((a) => a.article === "15")!;

  test("has 2 requirements", () => {
    assert.equal(art15.requirements.length, 2);
  });

  test("covers resilience", () => {
    assert.ok(art15.requirements.some((r) => r.id.includes("resilience")));
  });

  test("covers security", () => {
    assert.ok(art15.requirements.some((r) => r.id.includes("security")));
  });
});

describe("Article 50 — Transparency", () => {
  const art50 = EU_AI_ACT_ARTICLES.find((a) => a.article === "50")!;

  test("covers AI disclosure", () => {
    assert.ok(art50.requirements.some((r) => r.id.includes("disclosure")));
  });

  test("covers content marking", () => {
    assert.ok(art50.requirements.some((r) => r.id.includes("content-marking")));
  });
});

describe("getArticles()", () => {
  test("returns same data as EU_AI_ACT_ARTICLES", () => {
    assert.deepEqual(getArticles(), EU_AI_ACT_ARTICLES);
  });
});

describe("getDaysUntilDeadline()", () => {
  test("counts to the Annex III high-risk date by default", () => {
    assert.equal(getDaysUntilDeadline("III", AS_OF), 454);
    assert.equal(getDaysUntilDeadline(undefined, AS_OF), 454);
    assert.equal(getDaysUntilDeadline("I", AS_OF), 698);
    assert.equal(typeof getDaysUntilDeadline(), "number");
  });

  test("goes negative once the milestone has passed", () => {
    assert.ok(getDaysUntilDeadline("III", new Date("2028-01-01T00:00:00Z")) < 0);
  });
});

describe("EU_AI_ACT_SCHEDULE", () => {
  const m = EU_AI_ACT_SCHEDULE.milestones;

  test("names the amended regulation and cites sources", () => {
    assert.equal(EU_AI_ACT_SCHEDULE.regulationRevision, "Reg. (EU) 2024/1689 as amended by Reg. (EU) 2026/1744");
    assert.equal(EU_AI_ACT_SCHEDULE.amendmentPublished, "2026-07-24");
    assert.equal(EU_AI_ACT_SCHEDULE.amendmentInForce, "2026-07-27");
    assert.ok(EU_AI_ACT_SCHEDULE.sourceUrls.length >= 2);
    for (const url of EU_AI_ACT_SCHEDULE.sourceUrls) assert.match(url, /^https:\/\//);
  });

  test("milestone dates are correct and chronological", () => {
    assert.equal(m.prohibitedPractices.date, "2025-02-02");
    assert.equal(m.gpaiModelObligations.date, "2025-08-02");
    assert.equal(m.article50Transparency.date, "2026-08-02");
    assert.equal(m.annexIIIHighRisk.date, "2027-12-02");
    assert.equal(m.annexIHighRisk.date, "2028-08-02");
    const dates = Object.values(m).map((x) => x.date);
    for (const d of dates) assert.match(d, /^\d{4}-\d{2}-\d{2}$/);
    assert.deepEqual(dates, [...dates].sort());
  });

  test("records the pre-Omnibus dates the high-risk milestones superseded", () => {
    assert.equal(m.annexIIIHighRisk.supersedes, "2026-08-02");
    assert.equal(m.annexIHighRisk.supersedes, "2027-08-02");
    assert.equal(m.article50Transparency.supersedes, undefined, "Art 50 was not deferred");
  });

  test("resolveDeadline / highRiskMilestone honour the annex", () => {
    assert.equal(resolveDeadline("highRisk"), "2027-12-02");
    assert.equal(resolveDeadline("highRisk", "III"), "2027-12-02");
    assert.equal(resolveDeadline("highRisk", "I"), "2028-08-02");
    assert.equal(resolveDeadline("article50Transparency", "I"), "2026-08-02");
    assert.equal(resolveDeadline("article50Transparency", "III"), "2026-08-02");
    assert.equal(highRiskMilestone().label, "Annex III high-risk");
    assert.equal(highRiskMilestone("I").label, "Annex I high-risk");
  });

  test("buildPhasedDeadlines populates legacy keys and new keys consistently", () => {
    const iii = buildPhasedDeadlines();
    assert.equal(iii.gpaiTransparency, iii.gpaiModelObligations);
    assert.equal(iii.highRiskObligations, iii.annexIIIHighRisk);
    assert.equal(iii.postMarketAndDownstream, iii.annexIHighRisk);
    assert.notEqual(iii.article50Transparency, iii.gpaiModelObligations);
    const i = buildPhasedDeadlines("I");
    assert.equal(i.highRiskObligations, i.annexIHighRisk);
    assert.equal(i.article50Transparency, "2026-08-02");
  });

  test("daysUntil is ceil-days and negative after the date", () => {
    assert.equal(daysUntil("2027-12-02", AS_OF), 454);
    assert.equal(daysUntil("2026-08-02", AS_OF), -33);
  });

  test("getArticles(annex) re-resolves only the high-risk deadlines", () => {
    const i = getArticles("I");
    assert.equal(i.length, 6);
    for (const art of i) {
      assert.equal(art.deadline, art.phase === "highRisk" ? "2028-08-02" : "2026-08-02", `Art ${art.article}`);
    }
    // The static table itself is never mutated.
    assert.equal(EU_AI_ACT_ARTICLES.find((a) => a.article === "9")!.deadline, "2027-12-02");
  });
});
