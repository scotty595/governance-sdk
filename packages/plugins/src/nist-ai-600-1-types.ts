/**
 * NIST AI 600-1 (Generative AI Profile) — shared vocabulary and the twelve
 * GAI risk categories from §2.
 *
 * Source: NIST AI 600-1, "Artificial Intelligence Risk Management Framework:
 * Generative Artificial Intelligence Profile", July 2024 (approved by the NIST
 * Editorial Review Board 2024-07-25),
 * https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf. The twelve titles and
 * definitions below were transcribed from §2 of that PDF on 2026-09-04.
 *
 * The subcategory table is in nist-ai-600-1-articles.ts, the per-requirement
 * checks in nist-ai-600-1-assessors.ts, and the report in nist-ai-600-1.ts.
 */

import type {
  ComplianceStatus,
  RequirementAssessment,
  ArticleAssessment,
} from "./compliance-articles.js";

export type { ComplianceStatus, RequirementAssessment, ArticleAssessment };

/** The publication this mapping transcribes. */
export const NIST_AI_600_1_SOURCE_URL = "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf";

/** Sources consulted on 2026-09-04. */
export const NIST_AI_600_1_SOURCE_URLS: readonly string[] = [
  NIST_AI_600_1_SOURCE_URL,
  "https://doi.org/10.6028/NIST.AI.600-1",
  "https://airc.nist.gov/Home",
];

/** Revision string carried in the report; the plugin's `version` matches it. */
export const NIST_AI_600_1_REVISION = "NIST AI 600-1 (Generative AI Profile, July 2024)";

// ─── The twelve GAI risks (§2) ───────────────────────────────

export type GaiRiskId =
  | "cbrn"
  | "confabulation"
  | "dangerous-violent-hateful"
  | "data-privacy"
  | "environmental"
  | "harmful-bias-homogenization"
  | "human-ai-configuration"
  | "information-integrity"
  | "information-security"
  | "intellectual-property"
  | "obscene-degrading-abusive"
  | "value-chain-integration";

export interface GaiRisk {
  id: GaiRiskId;
  /** Section of NIST AI 600-1 that defines it (§2.1 … §2.12). */
  section: string;
  /** Title exactly as printed in the §2 numbered list. */
  title: string;
  description: string;
  sourceUrl: string;
}

const S = NIST_AI_600_1_SOURCE_URL;

export const GAI_RISKS: readonly GaiRisk[] = [
  { id: "cbrn", section: "2.1", title: "CBRN Information or Capabilities", sourceUrl: S,
    description: "Eased access to or synthesis of materially nefarious information or design capabilities related to chemical, biological, radiological, or nuclear weapons or other dangerous materials or agents." },
  { id: "confabulation", section: "2.2", title: "Confabulation", sourceUrl: S,
    description: "The production of confidently stated but erroneous or false content by which users may be misled or deceived." },
  { id: "dangerous-violent-hateful", section: "2.3", title: "Dangerous, Violent, or Hateful Content", sourceUrl: S,
    description: "Eased production of and access to violent, inciting, radicalizing, or threatening content, and recommendations to carry out self-harm or conduct illegal activities." },
  { id: "data-privacy", section: "2.4", title: "Data Privacy", sourceUrl: S,
    description: "Impacts due to leakage and unauthorized use, disclosure, or de-anonymization of biometric, health, location, or other personally identifiable or sensitive data." },
  { id: "environmental", section: "2.5", title: "Environmental Impacts", sourceUrl: S,
    description: "Impacts due to high compute resource utilization in training or operating GAI models, and related outcomes that may adversely impact ecosystems." },
  { id: "harmful-bias-homogenization", section: "2.6", title: "Harmful Bias or Homogenization", sourceUrl: S,
    description: "Amplification and exacerbation of historical, societal, and systemic biases; performance disparities between sub-groups or languages; undesired homogeneity that skews system or model outputs." },
  { id: "human-ai-configuration", section: "2.7", title: "Human-AI Configuration", sourceUrl: S,
    description: "Arrangements of or interactions between a human and an AI system which can result in anthropomorphizing, algorithmic aversion, automation bias, over-reliance, or emotional entanglement." },
  { id: "information-integrity", section: "2.8", title: "Information Integrity", sourceUrl: S,
    description: "Lowered barrier to generating and exchanging content that may not distinguish fact from fiction or acknowledge uncertainty, or could be leveraged for large-scale dis- and mis-information campaigns." },
  { id: "information-security", section: "2.9", title: "Information Security", sourceUrl: S,
    description: "Lowered barriers for offensive cyber capabilities; increased attack surface for targeted cyberattacks that may compromise availability or the confidentiality or integrity of training data, code, or model weights." },
  { id: "intellectual-property", section: "2.10", title: "Intellectual Property", sourceUrl: S,
    description: "Eased production or replication of alleged copyrighted, trademarked, or licensed content without authorization; eased exposure of trade secrets; plagiarism or illegal replication." },
  { id: "obscene-degrading-abusive", section: "2.11", title: "Obscene, Degrading, and/or Abusive Content", sourceUrl: S,
    description: "Eased production of and access to obscene, degrading, and/or abusive imagery, including synthetic child sexual abuse material and nonconsensual intimate images of adults." },
  { id: "value-chain-integration", section: "2.12", title: "Value Chain and Component Integration", sourceUrl: S,
    description: "Non-transparent or untraceable integration of upstream third-party components; improper supplier vetting across the AI lifecycle; other issues that diminish transparency or accountability for downstream users." },
];

// ─── Requirements, keyed to AI RMF subcategories ─────────────

export interface GenAiRequirement {
  /** Lower-cased subcategory id — `"gv-1.6"`, `"ms-2.7"`. */
  id: string;
  /** The AI RMF subcategory as NIST prints it: `"GOVERN 1.6"`. */
  subcategory: string;
  /** §3 heading text, verbatim. */
  subcategoryTitle: string;
  /** What this module actually checks for. */
  requirement: string;
  sdkFeature: string;
  checkDescription: string;
  /**
   * Which of the twelve risks the check bears on. This is this SDK's own
   * attribution at subcategory granularity — NIST tags individual suggested
   * actions (`GV-1.2-001` and the like), and those tags are not reproduced
   * here. Do not cite this array as NIST's mapping.
   */
  gaiRisks: readonly GaiRiskId[];
  /** False where no governance state can evidence it; the caller must attest. */
  automatable: boolean;
  sourceUrl: string;
}

export interface GenAiFunction {
  id: "GOVERN" | "MAP" | "MEASURE" | "MANAGE";
  title: string;
  description: string;
  requirements: readonly GenAiRequirement[];
}

/** Per-risk roll-up: how the twelve fare given the requirement results. */
export interface GaiRiskCoverage {
  risk: GaiRiskId;
  title: string;
  section: string;
  status: ComplianceStatus;
  /** Requirement ids tagged with this risk. */
  requirements: string[];
}

export interface NistAi600Report {
  overallScore: number;
  status: ComplianceStatus;
  functions: ArticleAssessment[];
  /** The twelve §2 risk categories, folded from the requirement results. */
  gaiRisks: GaiRiskCoverage[];
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

/** The twelve GAI risk categories defined in §2. */
export function getGaiRisks(): readonly GaiRisk[] {
  return GAI_RISKS;
}
