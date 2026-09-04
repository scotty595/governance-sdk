/**
 * OWASP Top 10 for Agentic Applications 2026 — item definitions.
 *
 * Official ids/titles (ASI01…ASI10, published 2025-12-09). Requirement ids
 * are prefixed with the official id (`asi01-*`); the legacy `OWASP-AA-*`
 * origin of each item is recorded in `legacyId` and OWASP_LEGACY_ID_MAP
 * (owasp-agentic-types.ts). Assessment logic is in owasp-agentic-assessors.ts.
 *
 * Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
 */

import type { ComplianceStatus, RequirementAssessment, ArticleAssessment } from "./compliance-articles.js";
import {
  OWASP_AGENTIC_REVISION,
  OWASP_AGENTIC_SOURCE_URL,
  OWASP_AGENTIC_STANDARD,
  type OwaspAgenticRisk,
  type OwaspAsiId,
  type OwaspLegacyId,
} from "./owasp-agentic-types.js";

// Re-export shared types (kept for consumers importing from this module)
export type { ComplianceStatus, RequirementAssessment, ArticleAssessment };
export type { OwaspAgenticRisk, OwaspRequirement, OwaspAgenticReport } from "./owasp-agentic-types.js";

const BASE = {
  standard: OWASP_AGENTIC_STANDARD,
  revision: OWASP_AGENTIC_REVISION,
  sourceUrl: OWASP_AGENTIC_SOURCE_URL,
} as const;

// ─── Risk Definitions ───────────────────────────────────────

export const OWASP_AGENTIC_RISKS: OwaspAgenticRisk[] = [
  {
    ...BASE, id: "ASI01", legacyId: "OWASP-AA-05",
    title: "Agent Goal Hijack",
    description: "Attackers redirect an agent's objective through content it reads — injected instructions in prompts, tool outputs, documents, or data.",
    severity: "critical",
    requirements: [
      { id: "asi01-injection-detection", requirement: "Detect prompt-injection patterns in agent inputs before they steer the goal",
        sdkFeature: "createInjectionGuard() — 64+ patterns across 7 categories with base64 decoding",
        checkDescription: "Injection guard policy is configured", automatable: true },
      { id: "asi01-cross-field-scan", requirement: "Scan every input field, including tool outputs, for embedded instructions",
        sdkFeature: "Cross-field injection detection via extractStrings() recursive scanning",
        checkDescription: "Injection detection is configured with cross-field scanning", automatable: true },
    ],
  },
  {
    ...BASE, id: "ASI02", legacyId: "OWASP-AA-01",
    title: "Tool Misuse & Exploitation",
    description: "Agents invoke legitimate tools in unsafe ways — destructive actions, exfiltration, unsafe parameters — often from manipulated input.",
    severity: "critical",
    requirements: [
      { id: "asi02-tool-restriction", requirement: "Restrict agent tool access to the minimum necessary set",
        sdkFeature: "blockTools() and allowOnlyTools() — allowlist/blocklist tool access",
        checkDescription: "At least one tool restriction policy is configured", automatable: true },
      { id: "asi02-tool-io-validation", requirement: "Validate tool inputs and outputs to catch unsafe or compromised invocations",
        sdkFeature: "Injection detection on tool inputs, sensitive data filter on outputs",
        checkDescription: "Injection guard and output filtering policies are active", automatable: true },
    ],
  },
  {
    ...BASE, id: "ASI03", legacyId: "OWASP-AA-01",
    title: "Identity & Privilege Abuse",
    description: "Over-privileged agents, inherited or escalated permissions, and unauthenticated agent identities acting beyond their scope.",
    severity: "critical",
    requirements: [
      { id: "asi03-governance-level", requirement: "Gate privileged actions on an enforced governance trust level",
        sdkFeature: "requireLevel() — gate actions by governance trust level; 7-dimension scoring",
        checkDescription: "Agents are scored and governance levels enforced", automatable: true },
      { id: "asi03-agent-authentication", requirement: "Authenticate every agent identity that can act",
        sdkFeature: "Agent registration with hasAuth metadata; Ed25519 identity tokens (createEd25519Identity)",
        checkDescription: "All registered agents declare an authentication mechanism", automatable: true },
    ],
  },
  {
    ...BASE, id: "ASI04", legacyId: "OWASP-AA-03",
    title: "Agentic Supply Chain Vulnerabilities",
    description: "Compromised or unvetted tools, MCP servers, models, and dependencies loaded into the agent at runtime.",
    severity: "critical",
    requirements: [
      { id: "asi04-tool-inventory", requirement: "Maintain an inventory of agent tools and dependencies",
        sdkFeature: "Agent registration with tools list — documents agent capabilities",
        checkDescription: "All agents have tools documented in registration", automatable: true },
      { id: "asi04-approved-tool-registry", requirement: "Block tools that are not in an approved registry",
        sdkFeature: "createSupplyChainPolicy({ approvedTools }) — blocks unapproved tool calls",
        checkDescription: "A supply-chain approved-tool policy is registered", automatable: true },
    ],
  },
  {
    ...BASE, id: "ASI05", legacyId: "OWASP-AA-06",
    title: "Unexpected Code Execution (RCE)",
    description: "Agents execute attacker-influenced code, shell commands, or actions outside an isolated, policy-bounded environment.",
    severity: "critical",
    requirements: [
      { id: "asi05-action-enforcement", requirement: "Enforce before-action policies so unexpected operations never execute",
        sdkFeature: "gov.enforce() — before-action enforcement on every agent operation",
        checkDescription: "Enforcement is integrated into the agent pipeline", automatable: true },
      { id: "asi05-scope-boundaries", requirement: "Confine file and network access to declared boundaries",
        sdkFeature: "scopeBoundary() and networkAllowlist() — path and domain restrictions",
        checkDescription: "Scope boundary or network allowlist policies are configured", automatable: true },
    ],
  },
  {
    ...BASE, id: "ASI06", legacyId: "OWASP-AA-04",
    title: "Memory & Context Poisoning",
    description: "Untrusted content corrupts the agent's context or memory, altering behaviour or leaking sensitive data across turns and sessions.",
    severity: "high",
    requirements: [
      { id: "asi06-tool-result-scan", requirement: "Scan tool results before they enter the model context",
        sdkFeature: "tool_result-stage enforcement (scanToolResult / Mastra processToolResult) with injection and sensitive-data rules",
        checkDescription: "Injection or sensitive-data rules are active at the tool_result stage", automatable: true },
      { id: "asi06-output-filtering", requirement: "Filter credentials, PII, and prompt leaks crossing the context boundary",
        sdkFeature: "sensitiveDataFilter() — 26 patterns for credentials, PII, prompt leaks",
        checkDescription: "Output filtering policy is configured", automatable: true },
    ],
  },
  {
    ...BASE, id: "ASI07", legacyId: "OWASP-AA-09",
    title: "Insecure Inter-Agent Communication",
    description: "Agents exchange messages without authentication, authorization, or integrity — enabling spoofing and injection between agents.",
    severity: "high",
    requirements: [
      { id: "asi07-agent-identity", requirement: "Authenticate agent identity before inter-agent communication",
        sdkFeature: "Agent registration with identity scoring + A2A governance adapter",
        checkDescription: "Agents are registered with identity metadata and scored", automatable: true },
      { id: "asi07-communication-policy", requirement: "Enforce policies on inter-agent message exchange",
        sdkFeature: "A2A plugin governs both send and receive with policy enforcement",
        checkDescription: "Inter-agent communication is governed via A2A adapter or equivalent", automatable: false },
    ],
  },
  {
    ...BASE, id: "ASI08", legacyId: "OWASP-AA-02",
    title: "Cascading Failures",
    description: "One fault — a runaway loop, exhausted budget, or bad output — propagates across tools and agents without limits or observability.",
    severity: "high",
    requirements: [
      { id: "asi08-token-budget", requirement: "Cap token consumption per session",
        sdkFeature: "tokenBudget() — per-session token cap policy",
        checkDescription: "Token budget policy is configured", automatable: true },
      { id: "asi08-rate-limiting", requirement: "Rate-limit agent actions to contain runaway execution",
        sdkFeature: "rateLimit() — throttle agent requests within time windows",
        checkDescription: "Rate limiting policy is configured", automatable: true },
      { id: "asi08-audit-observability", requirement: "Record every action so failures can be detected and traced",
        sdkFeature: "Audit trail with agent ID, event type, outcome, severity, timestamps",
        checkDescription: "Audit trail is active with events recorded", automatable: true },
    ],
  },
  {
    ...BASE, id: "ASI09", legacyId: "OWASP-AA-07",
    title: "Human-Agent Trust Exploitation",
    description: "Humans over-trust agent output, or agents are steered into deceiving their operators — bypassing review of consequential actions.",
    severity: "medium",
    requirements: [
      { id: "asi09-human-oversight", requirement: "Require human approval for high-stakes agent actions",
        sdkFeature: "requireApproval() — gate sensitive operations behind human review",
        checkDescription: "At least one requireApproval policy is configured", automatable: true },
      { id: "asi09-output-validation", requirement: "Validate and scan agent outputs before they reach people",
        sdkFeature: "Postprocess stage enforcement — outputPattern() and outputLength() policies",
        checkDescription: "Postprocess output validation is configured", automatable: true },
    ],
  },
  {
    ...BASE, id: "ASI10", legacyId: "OWASP-AA-10",
    title: "Rogue Agents",
    description: "Agents operating outside their intended boundaries due to hijacking, misconfiguration, or drift — and no way to stop or prove it.",
    severity: "critical",
    requirements: [
      { id: "asi10-kill-switch", requirement: "Ability to immediately halt a rogue agent",
        sdkFeature: "Kill switch at priority 999 — overrides all policies, quarantines agent",
        checkDescription: "Kill switch is available and functional", automatable: true },
      { id: "asi10-behavioral-scoring", requirement: "Detect behavioural drift through ongoing monitoring",
        sdkFeature: "Behavioral scorer adjusts governance scores based on observed audit data",
        checkDescription: "Agents are scored and behavioural drift is tracked", automatable: true },
      { id: "asi10-tamper-evident-audit", requirement: "Keep a tamper-evident record for rogue-behaviour forensics",
        sdkFeature: "HMAC-SHA256 hash-chained audit via createIntegrityAudit()",
        checkDescription: "Tamper-evident audit logging is enabled", automatable: false },
    ],
  },
];

/** Get the list of OWASP Agentic risks tracked by this module */
export function getOwaspRisks(): OwaspAgenticRisk[] {
  return OWASP_AGENTIC_RISKS;
}

/** Official items that absorbed a pre-2026 `OWASP-AA-*` category. */
export function getOwaspRisksByLegacyId(legacyId: OwaspLegacyId): OwaspAgenticRisk[] {
  return OWASP_AGENTIC_RISKS.filter((r) => r.legacyId === legacyId);
}

/** Look up one official item by id. */
export function getOwaspRisk(id: OwaspAsiId): OwaspAgenticRisk | undefined {
  return OWASP_AGENTIC_RISKS.find((r) => r.id === id);
}
