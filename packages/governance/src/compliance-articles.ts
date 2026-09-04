/**
 * EU AI Act Article Definitions
 *
 * Static article and requirement definitions for the 6 EU AI Act articles
 * tracked by governance-sdk. Dates come from compliance-schedule.ts (never
 * hard-coded here); assessment logic lives in compliance.ts.
 */

import {
  resolveDeadline,
  type EuAiActAnnex,
  highRiskMilestone,
  daysUntil,
} from "./compliance-schedule.js";
import type { EuAiActArticle } from "./compliance-types.js";

// Types live in compliance-types.ts; re-exported here because the OWASP,
// NIST and ISO modules import the shared vocabulary from this path.
export type {
  StandardId,
  ComplianceStatus,
  RequirementAssessment,
  ArticleAssessment,
  EuAiActArticle,
  ArticleRequirement,
  ComplianceReport,
} from "./compliance-types.js";

// ─── Article Definitions ────────────────────────────────────

const HIGH_RISK = resolveDeadline("highRisk", "III");
const ART50 = resolveDeadline("article50Transparency");
const HIGH_RISK_FINE = "Up to 15M EUR or 3% of global annual turnover";

export const EU_AI_ACT_ARTICLES: EuAiActArticle[] = [
  {
    standard: "eu-ai-act",
    article: "9",
    title: "Risk Management System",
    description: "Establish, implement, document, and maintain a risk management system throughout the AI system lifecycle.",
    phase: "highRisk",
    deadline: HIGH_RISK,
    maxFine: HIGH_RISK_FINE,
    requirements: [
      {
        id: "art9-risk-identification",
        requirement: "Identify and analyze known and reasonably foreseeable risks",
        sdkFeature: "Policy engine with blockTools(), allowOnlyTools() — identifies and blocks risky tool usage",
        checkDescription: "At least one policy rule configured to block or restrict dangerous operations",
        automatable: true,
      },
      {
        id: "art9-risk-mitigation",
        requirement: "Implement risk mitigation measures",
        sdkFeature: "Before-action enforcement via gov.enforce() — prevents risky actions before execution",
        checkDescription: "Enforcement is active and has blocked at least one action",
        automatable: true,
      },
      {
        id: "art9-residual-risk",
        requirement: "Evaluate and manage residual risks",
        sdkFeature: "7-dimension governance scoring — composite risk score per agent",
        checkDescription: "All agents have been scored and assessed",
        automatable: true,
      },
      {
        id: "art9-testing",
        requirement: "Test the AI system to identify appropriate risk management measures",
        sdkFeature: "Enforcement playground — interactive testing of policy rules",
        checkDescription: "Policy rules have been tested with representative scenarios",
        automatable: false,
      },
    ],
  },
  {
    standard: "eu-ai-act",
    article: "11",
    title: "Technical Documentation",
    description: "Technical documentation shall be drawn up before the AI system is placed on the market or put into service.",
    phase: "highRisk",
    deadline: HIGH_RISK,
    maxFine: HIGH_RISK_FINE,
    requirements: [
      {
        id: "art11-system-description",
        requirement: "General description of the AI system including intended purpose",
        sdkFeature: "Agent registration with name, description, owner, framework metadata",
        checkDescription: "All agents have description and owner fields populated",
        automatable: true,
      },
      {
        id: "art11-capabilities",
        requirement: "Document system capabilities and limitations",
        sdkFeature: "Agent tools list, permissions, governance level, and scoring dimensions",
        checkDescription: "All agents have tools and permissions documented",
        automatable: true,
      },
      {
        id: "art11-monitoring",
        requirement: "Description of monitoring, functioning, and control measures",
        sdkFeature: "Policy rules, enforcement decisions, audit trail configuration",
        checkDescription: "Governance configuration is documented and version-controlled",
        automatable: false,
      },
    ],
  },
  {
    standard: "eu-ai-act",
    article: "12",
    title: "Record-Keeping",
    description: "AI systems shall technically allow for automatic recording of events (logs) throughout the system lifecycle.",
    phase: "highRisk",
    deadline: HIGH_RISK,
    maxFine: HIGH_RISK_FINE,
    requirements: [
      {
        id: "art12-automatic-logging",
        requirement: "Automatic recording of events throughout the AI system lifecycle",
        sdkFeature: "Audit trail — gov.audit.log() records every action and decision automatically",
        checkDescription: "Audit logging is active and recording events",
        automatable: true,
      },
      {
        id: "art12-traceability",
        requirement: "Ensure traceability of the AI system operation",
        sdkFeature: "Audit events include agentId, eventType, outcome, severity, detail, timestamps",
        checkDescription: "Audit events contain sufficient context for traceability",
        automatable: true,
      },
      {
        id: "art12-integrity",
        requirement: "Logging system ensures integrity — logs cannot be tampered with",
        sdkFeature: "Tamper-evident audit via HMAC-SHA256 hash chaining (createIntegrityAudit)",
        checkDescription: "Integrity audit is enabled and chain is valid",
        automatable: true,
      },
      {
        id: "art12-retention",
        requirement: "Logs retained for appropriate period",
        sdkFeature: "Storage adapter pattern — implement retention policies in your backend",
        checkDescription: "Log retention policy is configured",
        automatable: false,
      },
    ],
  },
  {
    standard: "eu-ai-act",
    article: "14",
    title: "Human Oversight",
    description: "AI systems shall be designed to be effectively overseen by natural persons during the period of use.",
    phase: "highRisk",
    deadline: HIGH_RISK,
    maxFine: HIGH_RISK_FINE,
    requirements: [
      {
        id: "art14-intervention",
        requirement: "Ability to intervene or interrupt the AI system",
        sdkFeature: "requireApproval() policy — flags actions for human review before execution",
        checkDescription: "At least one requireApproval rule is configured for sensitive operations",
        automatable: true,
      },
      {
        id: "art14-understanding",
        requirement: "Enable human overseers to understand capabilities and limitations",
        sdkFeature: "Governance scoring with 7 explainable dimensions — each score has evidence",
        checkDescription: "Agent assessments include dimensional breakdowns with evidence",
        automatable: true,
      },
      {
        id: "art14-monitoring",
        requirement: "Enable monitoring of the AI system operation",
        sdkFeature: "Real-time audit trail queries, fleet scoring, processor session statistics",
        checkDescription: "Audit trail is queryable and fleet monitoring is active",
        automatable: true,
      },
    ],
  },
  {
    standard: "eu-ai-act",
    article: "15",
    title: "Accuracy, Robustness, Cybersecurity",
    description: "AI systems shall achieve appropriate levels of accuracy, robustness, and cybersecurity.",
    phase: "highRisk",
    deadline: HIGH_RISK,
    maxFine: HIGH_RISK_FINE,
    requirements: [
      {
        id: "art15-resilience",
        requirement: "Resilient against errors, faults, or inconsistencies",
        sdkFeature: "Policy engine with default-deny option, rate limiting, token budgets",
        checkDescription: "Defensive policies configured (rate limits, token budgets)",
        automatable: true,
      },
      {
        id: "art15-security",
        requirement: "Appropriate cybersecurity measures",
        sdkFeature: "HMAC-SHA256 signed audit trail, tool blocking, agent authentication support",
        checkDescription: "Agent has auth configured and audit integrity is enabled",
        automatable: true,
      },
    ],
  },
  {
    standard: "eu-ai-act",
    article: "50",
    title: "Transparency Obligations",
    description: "AI systems interacting with natural persons must disclose they are AI. AI-generated content must be machine-readable marked.",
    // Art 50 applies from 2026-08-02 under both the original Act and the
    // Omnibus — it is neither the 2025-08-02 GPAI-model date nor deferred
    // with the high-risk obligations. See compliance-schedule.ts.
    phase: "article50Transparency",
    deadline: ART50,
    maxFine: HIGH_RISK_FINE,
    requirements: [
      {
        id: "art50-disclosure",
        requirement: "Inform persons they are interacting with an AI system",
        sdkFeature: "Agent registration metadata + transparency markers in output",
        checkDescription: "Agents have disclosure configuration indicating AI interaction",
        automatable: true,
      },
      {
        id: "art50-content-marking",
        requirement: "AI-generated content must be marked in machine-readable format",
        sdkFeature: "Audit trail attaches agent ID, model version, and timestamp to all outputs",
        checkDescription: "Agent outputs include provenance metadata",
        automatable: true,
      },
    ],
  },
];

/** EU AI Act articles tracked by this module, with deadlines resolved for `annex`. */
export function getArticles(annex: EuAiActAnnex = "III"): EuAiActArticle[] {
  return EU_AI_ACT_ARTICLES.map((a) => ({ ...a, deadline: resolveDeadline(a.phase, annex) }));
}

/** Days until the high-risk application date for `annex` (negative once past). */
export function getDaysUntilDeadline(annex: EuAiActAnnex = "III", now: Date = new Date()): number {
  return daysUntil(highRiskMilestone(annex).date, now);
}
