/**
 * Shared standards-mapping types + EU AI Act report types.
 *
 * `ComplianceStatus`, `RequirementAssessment` and `ArticleAssessment` are the
 * common vocabulary reused by the OWASP, NIST and ISO modules (they import
 * them via compliance-articles.ts, which re-exports everything here).
 */

import type { StoredAgent, GovernanceInstance } from "./index.js";
import type { EuAiActAnnex, EuAiActPhase, EuAiActPhasedDeadlines } from "./compliance-schedule.js";

// ─── Shared across standards ─────────────────────────────────

/**
 * Discriminator for the standards tables. Extension point: add
 * `"owasp-mcp-top10"` / `"owasp-llm-top10-2026"` here when those tables land
 * so a single report consumer can switch on `standard`.
 */
export type StandardId = "eu-ai-act" | "owasp-agentic-2026";

/** Compliance status for a single requirement */
export type ComplianceStatus = "compliant" | "partial" | "non-compliant" | "not-applicable";

/** Assessment result for a single requirement */
export interface RequirementAssessment {
  requirementId: string;
  status: ComplianceStatus;
  evidence: string;
  remediation?: string;
}

/** Assessment result for a full article */
export interface ArticleAssessment {
  article: string;
  title: string;
  coverage: ComplianceStatus;
  score: number;
  requirements: RequirementAssessment[];
  deadline: string;
  maxFine: string;
}

// ─── EU AI Act ───────────────────────────────────────────────

/** EU AI Act article with requirements and SDK feature mapping */
export interface EuAiActArticle {
  standard: "eu-ai-act";
  /** Article number */
  article: string;
  /** Article title */
  title: string;
  /** Brief description of the requirement */
  description: string;
  /** Which application milestone gates this article. */
  phase: EuAiActPhase;
  /**
   * Application date resolved for Annex III (the default). Use
   * `getArticles(annex)` or `resolveDeadline()` for Annex I.
   */
  deadline: string;
  /** Maximum fine */
  maxFine: string;
  /** Specific requirements that can be checked */
  requirements: ArticleRequirement[];
}

/** A specific checkable requirement within an article */
export interface ArticleRequirement {
  /** Unique requirement ID (e.g., "art9-risk-classification") */
  id: string;
  /** What the law requires */
  requirement: string;
  /** How governance-sdk addresses this */
  sdkFeature: string;
  /** What to check for compliance */
  checkDescription: string;
  /** Whether this is automatically checkable by the SDK */
  automatable: boolean;
}

/** Configuration for compliance assessment */
export interface ComplianceAssessmentConfig {
  governance: GovernanceInstance;
  agents: StoredAgent[];
  auditIntegrity?: boolean;
  humanOversight?: boolean;
  logRetention?: boolean;
  configVersionControlled?: boolean;
  policiesTested?: boolean;
  /**
   * High-risk annex the system falls under. Drives the deadline on Arts 9,
   * 11, 12, 14, 15 and the `daysUntilDeadline` count. Default "III".
   */
  annex?: EuAiActAnnex;
  /** Reference instant for day counts; defaults to now. Useful for deterministic reports/tests. */
  asOf?: Date;
}

/** Full compliance report */
export interface ComplianceReport {
  overallScore: number;
  status: ComplianceStatus;
  articles: ArticleAssessment[];
  agentsAssessed: number;
  criticalGaps: string[];
  recommendations: string[];
  generatedAt: string;
  /** Days until the soonest upcoming per-article deadline. Phased — see `phasedDeadlines`. */
  daysUntilDeadline: number;
  /** Not-legal-advice notice surfaced in the report output. */
  disclaimer?: string;
  /** Regulation text the dates are drawn from. */
  regulationRevision: string;
  /** Annex the high-risk deadlines were resolved for. */
  annex: EuAiActAnnex;
  /** EU AI Act phased application milestones. */
  phasedDeadlines: EuAiActPhasedDeadlines;
}
