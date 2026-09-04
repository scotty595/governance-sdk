/**
 * governance-sdk — OWASP Top 10 for Agentic Applications (2026) self-assessment
 *
 * Maps governance state onto the ten official items ASI01…ASI10 (published
 * 2025-12-09 by the OWASP GenAI Security Project). Each item is scored from
 * the SDK-checkable mitigations in owasp-agentic-articles.ts and the ten-row
 * `coverageMatrix` reports covered / partial / missing per official id.
 *
 * This is a governance-posture self-assessment against a subset of OWASP's
 * mitigations — not an OWASP-endorsed certification. Earlier releases used
 * an internal `OWASP-AA-01…AA-10` numbering; those ids survive as `legacyId`
 * on each item and in OWASP_LEGACY_ID_MAP (owasp-agentic-types.ts).
 */

import type { ComplianceStatus, RequirementAssessment, ArticleAssessment } from "./compliance-articles.js";
import { OWASP_AGENTIC_RISKS } from "./owasp-agentic-articles.js";
import {
  OWASP_AGENTIC_PUBLISHED,
  OWASP_AGENTIC_REVISION,
  OWASP_AGENTIC_SOURCE_URL,
  OWASP_AGENTIC_STANDARD,
  coverageStatusFor,
  type OwaspAgenticReport,
  type OwaspAssessmentConfig,
  type OwaspCoverageEntry,
} from "./owasp-agentic-types.js";
import { assessOwaspRequirement } from "./owasp-agentic-assessors.js";

export type {
  OwaspAgenticRisk,
  OwaspRequirement,
  OwaspAgenticReport,
  OwaspAssessmentConfig,
  OwaspAsiId,
  OwaspLegacyId,
  OwaspCoverageEntry,
  OwaspCoverageStatus,
} from "./owasp-agentic-types.js";
export {
  OWASP_AGENTIC_PUBLISHED,
  OWASP_AGENTIC_REVISION,
  OWASP_AGENTIC_SOURCE_URL,
  OWASP_AGENTIC_STANDARD,
  OWASP_LEGACY_ID_MAP,
} from "./owasp-agentic-types.js";
export { OWASP_AGENTIC_RISKS, getOwaspRisks, getOwaspRisk, getOwaspRisksByLegacyId } from "./owasp-agentic-articles.js";

// ─── Assessment ─────────────────────────────────────────────

export async function assessOwaspAgentic(
  config: OwaspAssessmentConfig,
): Promise<OwaspAgenticReport> {
  const riskAssessments: ArticleAssessment[] = [];

  for (const risk of OWASP_AGENTIC_RISKS) {
    const reqAssessments: RequirementAssessment[] = [];
    for (const req of risk.requirements) {
      reqAssessments.push(await assessOwaspRequirement(req.id, config));
    }

    const compliantCount = reqAssessments.filter((r) => r.status === "compliant").length;
    const partialCount = reqAssessments.filter((r) => r.status === "partial").length;
    const total = reqAssessments.length;
    const score = Math.round(((compliantCount + partialCount * 0.5) / total) * 100);
    const coverage: ComplianceStatus =
      score >= 80 ? "compliant" : score >= 40 ? "partial" : "non-compliant";

    riskAssessments.push({
      article: risk.id,
      title: risk.title,
      coverage,
      score,
      requirements: reqAssessments,
      deadline: "",
      maxFine: "",
    });
  }

  const overallScore = Math.round(
    riskAssessments.reduce((sum, a) => sum + a.score, 0) / riskAssessments.length,
  );
  const status: ComplianceStatus =
    overallScore >= 80 ? "compliant" : overallScore >= 40 ? "partial" : "non-compliant";

  const criticalGaps = riskAssessments.flatMap((a) =>
    a.requirements
      .filter((r) => r.status === "non-compliant")
      .map((r) => `${a.title} (${a.article}): ${r.evidence}`),
  );

  const recommendations = riskAssessments
    .flatMap((a) => a.requirements.filter((r) => r.remediation).map((r) => r.remediation!))
    .filter((v, i, arr) => arr.indexOf(v) === i);

  return {
    standard: OWASP_AGENTIC_STANDARD,
    revision: OWASP_AGENTIC_REVISION,
    publishedOn: OWASP_AGENTIC_PUBLISHED,
    sourceUrl: OWASP_AGENTIC_SOURCE_URL,
    overallScore,
    status,
    risks: riskAssessments,
    coverageMatrix: buildCoverageMatrix(riskAssessments),
    agentsAssessed: config.agents.length,
    criticalGaps,
    recommendations,
    generatedAt: new Date().toISOString(),
    risksCovered: riskAssessments.filter((r) => r.coverage !== "non-compliant").length,
    risksTotal: OWASP_AGENTIC_RISKS.length,
    scope:
      `OWASP Top 10 for Agentic Applications ${OWASP_AGENTIC_REVISION} (ASI01-ASI10, published ` +
      `${OWASP_AGENTIC_PUBLISHED}). Self-assessment of governance posture against the SDK-checkable ` +
      "mitigations for each item; it does not cover every mitigation OWASP lists and is not an " +
      "OWASP-endorsed certification. Pre-2026 OWASP-AA-* ids are preserved as legacyId.",
  };
}

// ─── Coverage matrix ─────────────────────────────────────────

/**
 * All ten official items with covered / partial / missing status, derived
 * from per-item assessments. Items absent from `risks` are reported missing.
 */
export function buildCoverageMatrix(risks: readonly ArticleAssessment[]): OwaspCoverageEntry[] {
  return OWASP_AGENTIC_RISKS.map((risk) => {
    const assessed = risks.find((r) => r.article === risk.id);
    return {
      id: risk.id,
      title: risk.title,
      legacyId: risk.legacyId,
      status: assessed ? coverageStatusFor(assessed.coverage) : "missing",
      score: assessed?.score ?? 0,
    };
  });
}

/** Run the assessment and return only the ten-row coverage matrix. */
export async function coverageMatrix(config: OwaspAssessmentConfig): Promise<OwaspCoverageEntry[]> {
  return (await assessOwaspAgentic(config)).coverageMatrix;
}

/**
 * Alias for {@link assessOwaspAgentic}. The README uses `mapToOwaspAgentic`
 * because the function maps governance state → OWASP items. Both names point
 * at the same implementation.
 */
export const mapToOwaspAgentic = assessOwaspAgentic;
