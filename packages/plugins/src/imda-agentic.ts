/**
 * governance-sdk — IMDA Model AI Governance Framework for Agentic AI (v1.0)
 * self-assessment.
 *
 * Singapore's IMDA framework (22 January 2026) is the most agent-specific
 * governance guidance published to date, and it asks for almost exactly what
 * this SDK does: an agent with its own identity tied to a supervising human,
 * minimum tools and data, approval before sensitive actions, continuous
 * logging, and a way to terminate. Seventeen requirements across the four
 * pillars are assessed here; three of them — oversight audits, pre-deployment
 * testing, user training — are people processes and rely on attestation.
 *
 * SCOPE
 * Mapped against Version 1.0. IMDA published Version 1.5 on 20 May 2026 and
 * that revision has not been diffed against this table; see the header of
 * imda-agentic-articles.ts. The framework is guidance with no control ids, so
 * every requirement id is this module's own and names the v1.0 section it is
 * drawn from.
 *
 * Reference: https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/mgf-for-agentic-ai.pdf
 */

import type { ArticleAssessment, RequirementAssessment } from "./compliance-articles.js";
import { criticalGaps, overallScore, recommendations, rollUpArticle, statusFor } from "./standards-rollup.js";
import {
  IMDA_AGENTIC_PILLARS,
  IMDA_AGENTIC_REVISION,
  IMDA_AGENTIC_SOURCE_URLS,
  type ImdaAgenticReport,
} from "./imda-agentic-articles.js";
import { assessImdaRequirement, type ImdaAgenticAssessmentConfig } from "./imda-agentic-assessors.js";

export type { ImdaAgenticReport, ImdaPillar, ImdaPillarId, ImdaRequirement } from "./imda-agentic-articles.js";
export {
  getImdaPillars,
  getImdaRequirements,
  IMDA_AGENTIC_PILLARS,
  IMDA_AGENTIC_REVISION,
  IMDA_AGENTIC_SOURCE_URL,
  IMDA_AGENTIC_SOURCE_URLS,
} from "./imda-agentic-articles.js";
export type { ImdaAgenticAssessmentConfig } from "./imda-agentic-assessors.js";

/** Self-assessment against voluntary guidance — nobody certifies against it. */
export const IMDA_AGENTIC_DISCLAIMER =
  "Self-assessment only. The IMDA Model AI Governance Framework for Agentic AI " +
  "is voluntary guidance; IMDA does not certify conformance and neither does " +
  "this report. It describes what this SDK can observe about a governance " +
  "configuration against Version 1.0 of the framework, is not an audit or " +
  "legal advice, and has not been updated for Version 1.5 (20 May 2026). " +
  "Requirements reported `not-applicable` were not assessed and are excluded " +
  "from the score.";

// ─── Assessment ──────────────────────────────────────────────

export async function assessImdaAgentic(
  config: ImdaAgenticAssessmentConfig,
): Promise<ImdaAgenticReport> {
  const pillars: ArticleAssessment[] = [];

  for (const pillar of IMDA_AGENTIC_PILLARS) {
    const assessed: RequirementAssessment[] = [];
    for (const req of pillar.requirements) {
      assessed.push(await assessImdaRequirement(req.id, config));
    }
    pillars.push(rollUpArticle(pillar.id, pillar.title, assessed));
  }

  const score = overallScore(pillars);
  return {
    overallScore: score,
    status: statusFor(score),
    pillars,
    agentsAssessed: config.agents.length,
    criticalGaps: criticalGaps(pillars),
    recommendations: recommendations(pillars),
    generatedAt: new Date().toISOString(),
    standardVersion: "IMDA MGF for Agentic AI v1.0",
    revision: IMDA_AGENTIC_REVISION,
    sourceUrls: IMDA_AGENTIC_SOURCE_URLS,
    scope:
      "17 requirements drawn from the four pillars of Version 1.0 (§2.1–§2.4). " +
      "The framework has no control ids; requirement ids are this module's own " +
      "and name the v1.0 section each is drawn from. Oversight auditing (§2.2.2), " +
      "pre-deployment testing (§2.3.2) and user training (§2.4.2) rely on caller " +
      "attestation. Version 1.5 (20 May 2026) has not been mapped.",
    disclaimer: IMDA_AGENTIC_DISCLAIMER,
  };
}

/** Alias for {@link assessImdaAgentic}, matching the other `mapToX` names. */
export const mapToImdaAgentic = assessImdaAgentic;
