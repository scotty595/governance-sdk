/**
 * OWASP Top 10 for Agentic Applications 2026 — schema, constants, legacy map.
 *
 * Official schema: ASI01…ASI10, published 2025-12-09 by the OWASP GenAI
 * Security Project. Titles are reproduced verbatim from the OWASP resource
 * page / announcement post (OWASP_AGENTIC_SOURCE_URL and
 * https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/),
 * with punctuation ("&", "(RCE)", "Human-Agent") cross-checked on 2026-09-04
 * against https://cycode.com/blog/owasp-top-10-agentic-applications/.
 *
 * Legacy mapping. Releases before this one used an internal
 * `OWASP-AA-01…AA-10` numbering. Each official item carries the `legacyId`
 * whose content it primarily absorbed; OWASP_LEGACY_ID_MAP gives the full
 * many-to-many mapping because the two schemas cut the space differently.
 *
 *   legacy                                    → official (requirements moved)
 *   AA-01 Excessive Agency                    → ASI02 (tool restriction), ASI03 (governance level)
 *   AA-02 Unrestricted Resource Consumption   → ASI08 (token budget, rate limiting)
 *   AA-03 Supply Chain Vulnerabilities        → ASI04 (tool inventory), ASI02 (tool I/O validation)
 *   AA-04 Data Leakage                        → ASI06 (output / prompt-leak filtering);
 *                                                audit-trail check merged into ASI08 (same check as AA-08)
 *   AA-05 Indirect Prompt Injection           → ASI01 (injection detection, cross-field scan)
 *   AA-06 Inadequate Sandboxing               → ASI05 (before-action enforcement, scope boundaries)
 *   AA-07 Over-Reliance on Agent Output       → ASI09 (human oversight, output validation)
 *   AA-08 Insufficient Logging & Monitoring   → ASI08 (audit observability), ASI10 (tamper-evident audit)
 *   AA-09 Insecure Inter-Agent Communication  → ASI07 (agent identity, communication policy)
 *   AA-10 Rogue Agents                        → ASI10 (kill switch, behavioral scoring)
 *
 * New checks with no legacy predecessor: asi03-agent-authentication,
 * asi04-approved-tool-registry, asi06-tool-result-scan.
 */

import type { GovernanceInstance } from "./governance.js";
import type { StoredAgent } from "./storage.js";
import type { ComplianceStatus, ArticleAssessment } from "./compliance-articles.js";

// ─── Constants ───────────────────────────────────────────────

export const OWASP_AGENTIC_STANDARD = "owasp-agentic-2026" as const;
export const OWASP_AGENTIC_REVISION = "2026" as const;
/** Publication date of the 2026 edition. */
export const OWASP_AGENTIC_PUBLISHED = "2025-12-09";
export const OWASP_AGENTIC_SOURCE_URL =
  "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/";

// ─── Identifiers ─────────────────────────────────────────────

export type OwaspAsiId =
  | "ASI01" | "ASI02" | "ASI03" | "ASI04" | "ASI05"
  | "ASI06" | "ASI07" | "ASI08" | "ASI09" | "ASI10";

/** Pre-2026 internal numbering, kept so existing consumers can re-key. */
export type OwaspLegacyId =
  | "OWASP-AA-01" | "OWASP-AA-02" | "OWASP-AA-03" | "OWASP-AA-04" | "OWASP-AA-05"
  | "OWASP-AA-06" | "OWASP-AA-07" | "OWASP-AA-08" | "OWASP-AA-09" | "OWASP-AA-10";

/** Full legacy → official mapping (see module comment). */
export const OWASP_LEGACY_ID_MAP: Readonly<Record<OwaspLegacyId, readonly OwaspAsiId[]>> = {
  "OWASP-AA-01": ["ASI02", "ASI03"],
  "OWASP-AA-02": ["ASI08"],
  "OWASP-AA-03": ["ASI04", "ASI02"],
  "OWASP-AA-04": ["ASI06", "ASI08"],
  "OWASP-AA-05": ["ASI01"],
  "OWASP-AA-06": ["ASI05"],
  "OWASP-AA-07": ["ASI09"],
  "OWASP-AA-08": ["ASI08", "ASI10"],
  "OWASP-AA-09": ["ASI07"],
  "OWASP-AA-10": ["ASI10"],
};

// ─── Table types ─────────────────────────────────────────────

/** One OWASP Top 10 for Agentic Applications item. */
export interface OwaspAgenticRisk {
  standard: typeof OWASP_AGENTIC_STANDARD;
  /** Official id, e.g. "ASI01". */
  id: OwaspAsiId;
  /** Official title, verbatim. */
  title: string;
  /** Primary pre-2026 internal id this item absorbed (see OWASP_LEGACY_ID_MAP). */
  legacyId: OwaspLegacyId;
  revision: typeof OWASP_AGENTIC_REVISION;
  sourceUrl: string;
  description: string;
  severity: "critical" | "high" | "medium";
  requirements: OwaspRequirement[];
}

/** A specific checkable requirement within a risk */
export interface OwaspRequirement {
  id: string;
  requirement: string;
  sdkFeature: string;
  checkDescription: string;
  automatable: boolean;
}

// ─── Assessment types ────────────────────────────────────────

export interface OwaspAssessmentConfig {
  governance: GovernanceInstance;
  agents: StoredAgent[];
  auditIntegrity?: boolean;
  injectionDetection?: boolean;
  outputFiltering?: boolean;
  a2aGovernance?: boolean;
}

export type OwaspCoverageStatus = "covered" | "partial" | "missing";

/** One row of the ten-item coverage matrix. */
export interface OwaspCoverageEntry {
  id: OwaspAsiId;
  title: string;
  legacyId: OwaspLegacyId;
  status: OwaspCoverageStatus;
  /** 0-100 article score; 0 when the item was not assessed. */
  score: number;
}

/** Full OWASP Agentic self-assessment report */
export interface OwaspAgenticReport {
  standard: typeof OWASP_AGENTIC_STANDARD;
  revision: typeof OWASP_AGENTIC_REVISION;
  publishedOn: string;
  sourceUrl: string;
  overallScore: number;
  status: ComplianceStatus;
  /** Per-item assessments; `article` holds the official id ("ASI01"…). */
  risks: ArticleAssessment[];
  /** All ten official items with covered / partial / missing status. */
  coverageMatrix: OwaspCoverageEntry[];
  agentsAssessed: number;
  criticalGaps: string[];
  recommendations: string[];
  generatedAt: string;
  risksCovered: number;
  risksTotal: number;
  /** Human-readable scope caveat surfaced in the JSON output. */
  scope?: string;
}

/** Map an article-level coverage status to the matrix vocabulary. */
export function coverageStatusFor(coverage: ComplianceStatus): OwaspCoverageStatus {
  if (coverage === "compliant") return "covered";
  if (coverage === "partial") return "partial";
  return "missing";
}
