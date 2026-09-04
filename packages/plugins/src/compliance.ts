/**
 * governance-sdk — EU AI Act self-assessment (NOT legal advice)
 *
 * Assesses governance configuration against a **subset** of EU AI Act
 * (Regulation (EU) 2024/1689, as amended by Regulation (EU) 2026/1744 — the
 * "Digital Omnibus on AI", in force 2026-07-27) article requirements. Covers
 * Arts. 9, 11, 12, 14, 15, 50 — not the prohibited-use (Art 5-7),
 * data-governance (Art 10), or GPAI model obligations (Arts 51-56).
 *
 * Phased application schedule (data lives in compliance-schedule.ts):
 *   - 2025-02-02: Prohibited practices (Art 5) — NOT modelled here.
 *   - 2025-08-02: GPAI model obligations (Arts 51-56) — NOT modelled here.
 *   - 2026-08-02: Art 50 transparency (Art 50(2) marking grace to 2026-12-02
 *                 for generative systems already on the market).
 *   - 2027-12-02: Annex III stand-alone high-risk (Arts 9, 11, 12, 14, 15).
 *                 Was 2026-08-02 before the Omnibus.
 *   - 2028-08-02: Annex I product-embedded high-risk (Art 6(1)).
 *                 Was 2027-08-02 before the Omnibus.
 * Pass `annex: "I"` to resolve the high-risk articles against the Annex I
 * date; the default is Annex III.
 *
 * ⚠️  THIS IS NOT LEGAL ADVICE. ⚠️
 * The article texts here are paraphrased summaries, not the authoritative
 * regulation text. This module is a self-assessment helper for engineering
 * teams tracking SDK-level posture against a subset of AI Act obligations.
 * Do not substitute its output for qualified legal counsel. Consult your
 * compliance team before relying on it for regulatory filings or audits.
 */

import { EU_AI_ACT_ARTICLES } from "./compliance-articles.js";
import type {
  ComplianceAssessmentConfig,
  ComplianceStatus,
  RequirementAssessment,
  ArticleAssessment,
  ComplianceReport,
} from "./compliance-types.js";
import { assessEuAiActRequirement } from "./compliance-assessors.js";
import {
  EU_AI_ACT_SCHEDULE,
  buildPhasedDeadlines,
  daysUntil,
  resolveDeadline,
} from "./compliance-schedule.js";

// Public surface: types, the article table getters, and the schedule.
export type {
  EuAiActArticle,
  ArticleRequirement,
  ComplianceAssessmentConfig,
  ComplianceStatus,
  RequirementAssessment,
  ArticleAssessment,
  ComplianceReport,
  StandardId,
} from "./compliance-types.js";
export { getArticles, getDaysUntilDeadline } from "./compliance-articles.js";
export * from "./compliance-schedule.js";

// ─── Compliance Assessment ───────────────────────────────────

export async function assessCompliance(
  config: ComplianceAssessmentConfig,
): Promise<ComplianceReport> {
  const { agents, annex = "III" } = config;
  const asOf = config.asOf ?? new Date();
  const articleAssessments: ArticleAssessment[] = [];

  for (const article of EU_AI_ACT_ARTICLES) {
    const reqAssessments: RequirementAssessment[] = [];
    for (const req of article.requirements) {
      reqAssessments.push(await assessEuAiActRequirement(req, config));
    }

    const compliantCount = reqAssessments.filter((r) => r.status === "compliant").length;
    const partialCount = reqAssessments.filter((r) => r.status === "partial").length;
    const total = reqAssessments.length;
    const score = Math.round(((compliantCount + partialCount * 0.5) / total) * 100);

    const coverage: ComplianceStatus =
      score >= 80 ? "compliant" : score >= 40 ? "partial" : "non-compliant";

    articleAssessments.push({
      article: article.article,
      title: article.title,
      coverage,
      score,
      requirements: reqAssessments,
      deadline: resolveDeadline(article.phase, annex),
      maxFine: article.maxFine,
    });
  }

  const overallScore = Math.round(
    articleAssessments.reduce((sum, a) => sum + a.score, 0) / articleAssessments.length,
  );

  const status: ComplianceStatus =
    overallScore >= 80 ? "compliant" : overallScore >= 40 ? "partial" : "non-compliant";

  const criticalGaps = articleAssessments.flatMap((a) =>
    a.requirements
      .filter((r) => r.status === "non-compliant")
      .map((r) => `${a.title} (Art. ${a.article}): ${r.evidence}`),
  );

  const recommendations = articleAssessments
    .flatMap((a) => a.requirements.filter((r) => r.remediation).map((r) => r.remediation!))
    .filter((v, i, arr) => arr.indexOf(v) === i);

  // Soonest upcoming per-article deadline for the assessed annex (Art 50 on
  // 2026-08-02; high-risk articles on the Annex III or Annex I date). Falls
  // back to the latest deadline — a negative count — once all have passed.
  const now = asOf.getTime();
  const allDeadlines = articleAssessments
    .map((a) => new Date(a.deadline).getTime())
    .filter((t) => !Number.isNaN(t));
  const upcoming = allDeadlines.filter((t) => t > now);
  const referenceDeadline = upcoming.length > 0 ? Math.min(...upcoming) : Math.max(...allDeadlines);
  const daysUntilDeadline = daysUntil(new Date(referenceDeadline).toISOString(), asOf);

  return {
    overallScore,
    status,
    articles: articleAssessments,
    agentsAssessed: agents.length,
    criticalGaps,
    recommendations,
    generatedAt: new Date().toISOString(),
    daysUntilDeadline,
    // Surface the disclaimer in the report itself so anyone viewing the JSON
    // output sees it — not just readers of the source comment.
    disclaimer:
      "Not legal advice. This assessment covers a subset of EU AI Act obligations " +
      "(Arts 9, 11, 12, 14, 15, 50) under " + EU_AI_ACT_SCHEDULE.regulationRevision +
      " and uses paraphrased article summaries. It does NOT model prohibited " +
      "practices (Art 5-7), data governance (Art 10), or GPAI model obligations " +
      `(Arts 51-56). High-risk deadlines assume an Annex ${annex} system. ` +
      "Consult qualified legal counsel before relying on this output for regulatory filings.",
    regulationRevision: EU_AI_ACT_SCHEDULE.regulationRevision,
    annex,
    // Every milestone, so users can see what ACTUALLY applies when.
    phasedDeadlines: buildPhasedDeadlines(annex),
  };
}

// ─── Aliases ──────────────────────────────────────────────────────

/**
 * Preferred name for {@link assessCompliance}. Identical behavior; rename
 * for consistency with mapToIso42001 / mapToNistAiRmf / mapToOwaspAgentic.
 *
 * NOTE: This is policy-to-standard *self-assessment*. It is NOT a certified
 * audit and does NOT constitute legal advice.
 */
export const mapToEuAiAct = assessCompliance;

