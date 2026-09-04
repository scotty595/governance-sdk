/**
 * governance-sdk — NIST AI 600-1 (Generative AI Profile) self-assessment.
 *
 * The AI RMF 1.0 mapping in nist-ai-rmf.ts says in its own header that it does
 * not cover NIST AI 600-1. This module is that coverage: nineteen AI RMF
 * subcategories that the GenAI Profile profiles, each tied to the governance
 * state the SDK can actually observe, and a roll-up of how the twelve §2 GAI
 * risk categories fare as a result.
 *
 * SCOPE — read this before quoting a score
 * NIST AI 600-1 §3 contains several hundred *suggested actions* across ~49
 * subcategories. Nineteen of those subcategories are assessed here; the rest
 * concern organizational process (workforce diversity, feedback channels,
 * incident disclosure to affected communities) that leaves no trace in a
 * policy engine. Two of the nineteen — MEASURE 2.11 (fairness and bias) and
 * MEASURE 2.12 (environmental impact) — have no SDK signal at all and stay
 * `not-applicable` unless the caller attests external evidence via
 * `biasEvaluated` / `environmentalImpactAssessed`. `not-applicable` is excluded
 * from the score rather than counted as a failure, so the number reports what
 * was assessed and `scope` says what was not.
 *
 * Table: nist-ai-600-1-articles.ts. Types and the twelve risks:
 * nist-ai-600-1-types.ts. Checks: nist-ai-600-1-assessors.ts.
 * Reference: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
 */

import type { ArticleAssessment, RequirementAssessment } from "./compliance-articles.js";
import {
  criticalGaps,
  foldStatuses,
  overallScore,
  recommendations,
  rollUpArticle,
  statusFor,
} from "./standards-rollup.js";
import {
  GAI_RISKS,
  NIST_AI_600_1_REVISION,
  NIST_AI_600_1_SOURCE_URLS,
  type GaiRiskCoverage,
  type GaiRiskId,
  type NistAi600Report,
} from "./nist-ai-600-1-types.js";
import { NIST_AI_600_1_FUNCTIONS } from "./nist-ai-600-1-articles.js";
import { assessGenAiRequirement, type NistAi600AssessmentConfig } from "./nist-ai-600-1-assessors.js";

export type {
  GaiRisk,
  GaiRiskId,
  GaiRiskCoverage,
  GenAiFunction,
  GenAiRequirement,
  NistAi600Report,
} from "./nist-ai-600-1-types.js";
export {
  getGaiRisks,
  GAI_RISKS,
  NIST_AI_600_1_REVISION,
  NIST_AI_600_1_SOURCE_URL,
  NIST_AI_600_1_SOURCE_URLS,
} from "./nist-ai-600-1-types.js";
export { getGenAiFunctions, getGenAiRequirements, NIST_AI_600_1_FUNCTIONS } from "./nist-ai-600-1-articles.js";
export type { NistAi600AssessmentConfig } from "./nist-ai-600-1-assessors.js";

/** This is a self-assessment helper, not a NIST conformity assessment. */
export const NIST_AI_600_1_DISCLAIMER =
  "Self-assessment only. NIST AI 600-1 is voluntary guidance and NIST does not " +
  "certify conformance to it; nobody does. This report describes what this " +
  "SDK can observe about a running governance configuration and is neither an " +
  "audit, an attestation, nor legal advice. Subcategories outside `scope` were " +
  "not assessed, and a subcategory reported `not-applicable` was not assessed " +
  "either — it was excluded from the score.";

// ─── Assessment ──────────────────────────────────────────────

export async function assessNistAi600(
  config: NistAi600AssessmentConfig,
): Promise<NistAi600Report> {
  const functions: ArticleAssessment[] = [];
  const byRequirement = new Map<string, RequirementAssessment>();

  for (const fn of NIST_AI_600_1_FUNCTIONS) {
    const assessed: RequirementAssessment[] = [];
    for (const req of fn.requirements) {
      const result = await assessGenAiRequirement(req.id, config);
      byRequirement.set(req.id, result);
      assessed.push(result);
    }
    functions.push(rollUpArticle(fn.id, fn.title, assessed));
  }

  const score = overallScore(functions);
  return {
    overallScore: score,
    status: statusFor(score),
    functions,
    gaiRisks: foldGaiRisks(byRequirement),
    agentsAssessed: config.agents.length,
    criticalGaps: criticalGaps(functions),
    recommendations: recommendations(functions),
    generatedAt: new Date().toISOString(),
    standardVersion: "NIST AI 600-1 (July 2024)",
    revision: NIST_AI_600_1_REVISION,
    sourceUrls: NIST_AI_600_1_SOURCE_URLS,
    scope:
      "19 of the ~49 AI RMF subcategories profiled by NIST AI 600-1 §3, chosen " +
      "because a policy engine can evidence them. NIST's per-action suggested " +
      "actions (GV-1.2-001 and the like) are not reproduced; this maps at " +
      "subcategory granularity. MEASURE 2.11 (fairness and bias) and MEASURE " +
      "2.12 (environmental impact) have no SDK signal and require external " +
      "evidence. Organizational-process subcategories are out of scope entirely.",
    disclaimer: NIST_AI_600_1_DISCLAIMER,
  };
}

/** Fold the twelve §2 risk categories out of the per-requirement results. */
function foldGaiRisks(results: Map<string, RequirementAssessment>): GaiRiskCoverage[] {
  const tagged = new Map<GaiRiskId, string[]>();
  for (const fn of NIST_AI_600_1_FUNCTIONS) {
    for (const req of fn.requirements) {
      for (const risk of req.gaiRisks) {
        const list = tagged.get(risk) ?? [];
        list.push(req.id);
        tagged.set(risk, list);
      }
    }
  }
  return GAI_RISKS.map((risk) => {
    const ids = tagged.get(risk.id) ?? [];
    return {
      risk: risk.id,
      title: risk.title,
      section: risk.section,
      status: foldStatuses(ids.map((id) => results.get(id)?.status ?? "not-applicable")),
      requirements: ids,
    };
  });
}

/**
 * Alias for {@link assessNistAi600}, matching `mapToNistAiRmf` /
 * `mapToOwaspAgentic`: the function maps governance state onto the profile.
 */
export const mapToNistAi600 = assessNistAi600;
