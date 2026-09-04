/**
 * CSA AI Controls Matrix (AICM) v1.1 — shared vocabulary, sources, revision.
 *
 * ⚠️  THIS IS A DOMAIN-LEVEL MAPPING, NOT A CONTROL-LEVEL ONE. AICM v1.1
 * contains 247 control objectives across 18 domains. The full control text
 * ships as a spreadsheet from CSA and is not retrievable from an open URL, so
 * the individual control ids (`IAM-07`, `MDS-04`, …) and their wording are NOT
 * reproduced anywhere in this mapping and NOT assessed. What is assessed is a
 * set of governance checks attributed to ten of the eighteen domains — the
 * ten where a policy engine leaves evidence. The other eight are enumerated so
 * the report is honest about the shape of the framework, and are reported
 * `not-applicable`.
 *
 * VERIFIED ON 2026-09-04
 *   - v1.1 "Released: 06/22/2026", 247 control objectives, 18 domains, plus
 *     AI-CAIQ v1.1 (320 questions):
 *     https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1
 *   - The 18 domain titles and per-domain control counts are quoted from
 *     CSA's "The AI Controls Matrix (AICM)" introductory guidance (© 2025, AI
 *     Controls Framework Working Group), which describes v1.0. Those counts
 *     sum to 243 — v1.0's total. v1.1 adds four control objectives; CSA has
 *     not published, in any source reachable here, which domains gained them,
 *     so every `controlCount` is marked `asOfVersion: "1.0"` rather than
 *     guessed at for v1.1.
 *   - Domain codes for A&A, AIS, CEK, DSP, GRC, HRS, IAM, IPY, I&S, MDS, SEF,
 *     STA, TVM and UEM are printed in that guidance document. The codes for
 *     BCR, CCC, DCS and LOG are NOT printed there; they are inherited from CSA
 *     CCM v4, corroborated against the AICM control index at
 *     https://www.opensecurityarchitecture.org/frameworks/csa-aicm/controls/,
 *     and flagged `codeVerified: false` in csa-aicm-articles.ts.
 *
 * Domain table: csa-aicm-articles.ts. Checks: csa-aicm-assessors.ts.
 * Report: csa-aicm.ts.
 */

import type {
  ComplianceStatus,
  RequirementAssessment,
  ArticleAssessment,
} from "./compliance-articles.js";

export type { ComplianceStatus, RequirementAssessment, ArticleAssessment };

export const CSA_AICM_SOURCE_URL = "https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1";

export const CSA_AICM_SOURCE_URLS: readonly string[] = [
  CSA_AICM_SOURCE_URL,
  "https://cloudsecurityalliance.org/blog/2026/07/14/ai-controls-matrix-v1-1-strengthening-the-foundation-for-trustworthy-ai",
  "https://cloudsecurityalliance.org/research/working-groups/ai-controls",
  "https://www.opensecurityarchitecture.org/frameworks/csa-aicm/controls/",
];

/** Revision string carried in the report; the plugin's `version` is 1.1.0. */
export const CSA_AICM_REVISION = "CSA AI Controls Matrix v1.1 (released 2026-06-22)";

/** Control objectives in v1.1, per the CSA artifact page. */
export const CSA_AICM_TOTAL_CONTROLS = 247;

// ─── Types ───────────────────────────────────────────────────

export type AicmDomainCode =
  | "A&A" | "AIS" | "BCR" | "CCC" | "CEK" | "DCS" | "DSP" | "GRC" | "HRS"
  | "IAM" | "IPY" | "I&S" | "LOG" | "MDS" | "SEF" | "STA" | "TVM" | "UEM";

export interface AicmRequirement {
  /** `"iam-agent-identity"` — this module's id, NOT a CSA control id. */
  id: string;
  domain: AicmDomainCode;
  requirement: string;
  sdkFeature: string;
  checkDescription: string;
  automatable: boolean;
  sourceUrl: string;
}

export interface AicmDomain {
  code: AicmDomainCode;
  /** Domain title as printed in CSA's AICM guidance. */
  title: string;
  /** Control objectives in this domain as of AICM v1.0. */
  controlCount: number;
  /** The version `controlCount` was read from — always "1.0"; see header. */
  asOfVersion: "1.0";
  /** False where the code is inherited from CCM v4 rather than printed by CSA. */
  codeVerified: boolean;
  description: string;
  sourceUrl: string;
  /** Empty for the eight domains the SDK cannot evidence. */
  requirements: readonly AicmRequirement[];
}

export interface CsaAicmReport {
  overallScore: number;
  status: ComplianceStatus;
  /** All 18 domains; the eight out-of-scope ones carry `coverage: "not-applicable"`. */
  domains: ArticleAssessment[];
  /** Domain codes this report actually scored. */
  domainsAssessed: AicmDomainCode[];
  /** Domain codes enumerated but not scored. */
  domainsOutOfScope: AicmDomainCode[];
  /** Always 247 for v1.1 — none of them are individually assessed. */
  totalControlObjectives: number;
  agentsAssessed: number;
  criticalGaps: string[];
  recommendations: string[];
  generatedAt: string;
  standardVersion: string;
  revision: string;
  sourceUrls: readonly string[];
  scope: string;
  disclaimer: string;
}
