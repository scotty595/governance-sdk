/**
 * governance-sdk — CSA AI Controls Matrix v1.1 self-assessment (domain level).
 *
 * WHAT THIS IS
 * A domain-level view of a governance configuration against the 18 AICM
 * domains: ten domains scored from policy-engine evidence, eight enumerated
 * and reported `not-applicable`. Every domain title, control count and code
 * is sourced — see the header of csa-aicm-types.ts for exactly which of them
 * were verified against CSA's own documents and which were not.
 *
 * WHAT THIS IS NOT
 * A control-level assessment. AICM v1.1's 247 control objectives ship as a
 * spreadsheet that is not openly retrievable; none of their ids or texts are
 * reproduced here and none are assessed. Do not present this report as
 * coverage of "N of 247 controls" — it is coverage of 10 of 18 domains, at
 * the granularity of this SDK's own checks.
 *
 * Reference: https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1
 */

import type { ArticleAssessment, RequirementAssessment } from "./compliance-articles.js";
import { criticalGaps, overallScore, recommendations, rollUpArticle, statusFor } from "./standards-rollup.js";
import {
  CSA_AICM_REVISION,
  CSA_AICM_SOURCE_URLS,
  CSA_AICM_TOTAL_CONTROLS,
  type CsaAicmReport,
} from "./csa-aicm-types.js";
import { AICM_ASSESSED_DOMAINS, AICM_OUT_OF_SCOPE_DOMAINS, CSA_AICM_DOMAINS } from "./csa-aicm-articles.js";
import { assessAicmRequirement, type CsaAicmAssessmentConfig } from "./csa-aicm-assessors.js";

export type { AicmDomain, AicmDomainCode, AicmRequirement, CsaAicmReport } from "./csa-aicm-types.js";
export {
  CSA_AICM_REVISION,
  CSA_AICM_SOURCE_URL,
  CSA_AICM_SOURCE_URLS,
  CSA_AICM_TOTAL_CONTROLS,
} from "./csa-aicm-types.js";
export {
  AICM_ASSESSED_DOMAINS,
  AICM_OUT_OF_SCOPE_DOMAINS,
  CSA_AICM_DOMAINS,
  getAicmDomain,
  getAicmDomains,
} from "./csa-aicm-articles.js";
export type { CsaAicmAssessmentConfig } from "./csa-aicm-assessors.js";

/** Self-assessment, not a CSA STAR for AI attestation. */
export const CSA_AICM_DISCLAIMER =
  "Self-assessment only, and domain-level only. This is not a CSA STAR for AI " +
  "attestation, not an AI-CAIQ response, and not a control-by-control " +
  "assessment: none of AICM v1.1's 247 control objectives are individually " +
  "reproduced or evaluated here, because the control text is not openly " +
  "retrievable. Ten domains (" + AICM_ASSESSED_DOMAINS.join(", ") + ") are " +
  "scored from what this SDK can observe; eight (" +
  AICM_OUT_OF_SCOPE_DOMAINS.join(", ") + ") are enumerated but not scored and " +
  "require infrastructure or process evidence outside the SDK. Neither the " +
  "score nor this report is an audit or legal advice.";

// ─── Assessment ──────────────────────────────────────────────

export async function assessCsaAicm(config: CsaAicmAssessmentConfig): Promise<CsaAicmReport> {
  const domains: ArticleAssessment[] = [];

  for (const domain of CSA_AICM_DOMAINS) {
    const assessed: RequirementAssessment[] = [];
    for (const req of domain.requirements) {
      assessed.push(await assessAicmRequirement(req.id, config));
    }
    // rollUpArticle reports an empty requirement list as `not-applicable`.
    domains.push(rollUpArticle(domain.code, domain.title, assessed));
  }

  const score = overallScore(domains);
  return {
    overallScore: score,
    status: statusFor(score),
    domains,
    domainsAssessed: [...AICM_ASSESSED_DOMAINS],
    domainsOutOfScope: [...AICM_OUT_OF_SCOPE_DOMAINS],
    totalControlObjectives: CSA_AICM_TOTAL_CONTROLS,
    agentsAssessed: config.agents.length,
    criticalGaps: criticalGaps(domains),
    recommendations: recommendations(domains),
    generatedAt: new Date().toISOString(),
    standardVersion: "CSA AICM v1.1",
    revision: CSA_AICM_REVISION,
    sourceUrls: CSA_AICM_SOURCE_URLS,
    scope:
      `Domain-level mapping of ${AICM_ASSESSED_DOMAINS.length} of 18 AICM v1.1 domains ` +
      `(${AICM_ASSESSED_DOMAINS.join(", ")}). The remaining ${AICM_OUT_OF_SCOPE_DOMAINS.length} ` +
      `(${AICM_OUT_OF_SCOPE_DOMAINS.join(", ")}) are enumerated but not scored. No individual ` +
      `control objective is assessed; per-domain control counts are v1.0's (243 total) ` +
      `because CSA has not published which domains gained v1.1's four additions.`,
    disclaimer: CSA_AICM_DISCLAIMER,
  };
}

/** Alias for {@link assessCsaAicm}, matching the other `mapToX` names. */
export const mapToCsaAicm = assessCsaAicm;
