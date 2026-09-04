/**
 * IMDA Model AI Governance Framework for Agentic AI — the four pillars.
 *
 * Source: Infocomm Media Development Authority (Singapore), "Model AI
 * Governance Framework for Agentic AI", Version 1.0, published 22 January
 * 2026. Every section number, pillar title and quoted phrase below was
 * transcribed from the v1.0 PDF on 2026-09-04 (mirror used for verification:
 * https://www.aigl.blog/content/files/2026/02/MODEL-AI-GOVERNANCE-FRAMEWORK-FOR-AGENTIC-AI.pdf;
 * official location:
 * https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/mgf-for-agentic-ai.pdf).
 *
 * REVISION NOTE — read before bumping
 * IMDA calls this "a living document" and published Version 1.5 on 20 May
 * 2026 (https://www.imda.gov.sg/resources/press-releases-factsheets-and-speeches/updated-model-ai-governance-framework-for-agentic-ai).
 * This mapping is against v1.0 — the revision named in the brief and the one
 * whose text was verified. The official URL above now serves v1.5 (which is
 * why the aigl.blog mirror is listed as the v1.0 verification copy). A spot
 * check of v1.5 on 2026-09-04 found the §2.1–§2.4 / §2.x.y section structure
 * unchanged and ten of eleven quoted phrases intact; the §2.1.2 identity
 * wording ("its own unique identity") was reworded. v1.5 has NOT been mapped
 * requirement-by-requirement. The plugin's `version` (2026.1.22) is v1.0's
 * publication date so that a v1.5 mapping is a visible bump, not silent drift.
 *
 * The framework is guidance, not a control catalogue: it has no control ids.
 * The requirement ids here (`p1-agent-identity`, …) are this module's own and
 * each one names the v1.0 section it is drawn from. Checks are in
 * imda-agentic-assessors.ts; the report in imda-agentic.ts.
 */

import type {
  ComplianceStatus,
  RequirementAssessment,
  ArticleAssessment,
} from "./compliance-articles.js";

export type { ComplianceStatus, RequirementAssessment, ArticleAssessment };

export const IMDA_AGENTIC_SOURCE_URL =
  "https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/mgf-for-agentic-ai.pdf";

/** Sources consulted on 2026-09-04. */
export const IMDA_AGENTIC_SOURCE_URLS: readonly string[] = [
  IMDA_AGENTIC_SOURCE_URL,
  "https://www.aigl.blog/content/files/2026/02/MODEL-AI-GOVERNANCE-FRAMEWORK-FOR-AGENTIC-AI.pdf",
  "https://www.imda.gov.sg/resources/press-releases-factsheets-and-speeches/press-releases/2026/new-model-ai-governance-framework-for-agentic-ai",
  "https://www.imda.gov.sg/resources/press-releases-factsheets-and-speeches/updated-model-ai-governance-framework-for-agentic-ai",
];

/** Revision string carried in the report; the plugin's `version` is 2026.1.22. */
export const IMDA_AGENTIC_REVISION = "IMDA Model AI Governance Framework for Agentic AI, Version 1.0 (22 January 2026)";

// ─── Types ───────────────────────────────────────────────────

export type ImdaPillarId = "2.1" | "2.2" | "2.3" | "2.4";

export interface ImdaRequirement {
  /** This module's id — `"p1-agent-identity"`. The framework has no control ids. */
  id: string;
  /** v1.0 section the requirement is drawn from — `"2.1.2"`. */
  section: string;
  /** Section heading, verbatim. */
  sectionTitle: string;
  /** What the framework asks for, close to its own wording. */
  requirement: string;
  sdkFeature: string;
  checkDescription: string;
  automatable: boolean;
  sourceUrl: string;
}

export interface ImdaPillar {
  id: ImdaPillarId;
  /** Pillar title, verbatim from v1.0 §2. */
  title: string;
  description: string;
  requirements: readonly ImdaRequirement[];
}

export interface ImdaAgenticReport {
  overallScore: number;
  status: ComplianceStatus;
  pillars: ArticleAssessment[];
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

const S = IMDA_AGENTIC_SOURCE_URL;

// ─── The four pillars (v1.0 §2) ──────────────────────────────

export const IMDA_AGENTIC_PILLARS: readonly ImdaPillar[] = [
  {
    id: "2.1", title: "Assess and bound the risks upfront",
    description: "Understand the risk of an agent's actions — scope, reversibility, autonomy — and bound it at design time through limits, permissions and identity.",
    requirements: [
      { id: "p1-risk-scoping", section: "2.1.1", sectionTitle: "Determine suitable use cases for agent deployment", sourceUrl: S, automatable: true,
        requirement: "Each agent's risk is assessed as a function of impact and likelihood before deployment",
        sdkFeature: "7-dimension composite scoring with governance levels 0-4, assigned at gov.register()",
        checkDescription: "Every registered agent carries a composite score and a governance level" },
      { id: "p1-minimum-tools", section: "2.1.2", sectionTitle: "Bound risks through design by defining agents limits and permissions", sourceUrl: S, automatable: true,
        requirement: "Policies give agents only the minimum tools and data access needed to complete the task",
        sdkFeature: "allowOnlyTools() / blockTools() — allowlist or blocklist the tool surface",
        checkDescription: "A tool allowlist or blocklist rule is configured" },
      { id: "p1-contained-impact", section: "2.1.2", sectionTitle: "Bound risks through design by defining agents limits and permissions", sourceUrl: S, automatable: true,
        requirement: "Agents run with limited network and data access and can be taken offline when they malfunction",
        sdkFeature: "scopeBoundary() / networkAllowlist() for the boundary; createKillSwitch(gov) to take an agent offline",
        checkDescription: "A scope or network boundary rule and a kill switch are both registered" },
      { id: "p1-agent-identity", section: "2.1.2", sectionTitle: "Bound risks through design by defining agents limits and permissions", sourceUrl: S, automatable: true,
        requirement: "An agent has its own unique identity, tied to a supervising human user or organisational department for accountability",
        sdkFeature: "Agent registration with hasAuth metadata and an owner; createEd25519Identity() for signed identity",
        checkDescription: "Every registered agent declares an authentication mechanism and an owner" },
      { id: "p1-delegation-recorded", section: "2.1.2", sectionTitle: "Bound risks through design by defining agents limits and permissions", sourceUrl: S, automatable: true,
        requirement: "An agent's permissions are pre-defined or set by its authorising user, and delegations of authority are clearly recorded",
        sdkFeature: "Agent registration `permissions` plus the audit trail recording every action under that agent id",
        checkDescription: "Every agent declares permissions and audit events are being recorded" },
    ],
  },
  {
    id: "2.2", title: "Make humans meaningfully accountable",
    description: "Organisations and the humans who oversee agents remain accountable; oversight is designed against automation bias.",
    requirements: [
      { id: "p2-accountable-owner", section: "2.2.1", sectionTitle: "Clear allocation of responsibilities within and outside the organisation", sourceUrl: S, automatable: true,
        requirement: "Responsibility for each agent's decisions and actions is allocated to a named party",
        sdkFeature: "Agent registration `owner`",
        checkDescription: "Every registered agent has an owner" },
      { id: "p2-approval-checkpoints", section: "2.2.2", sectionTitle: "Design for meaningful human oversight", sourceUrl: S, automatable: true,
        requirement: "Significant checkpoints or action boundaries require human approval before sensitive, high-stakes or irreversible actions execute",
        sdkFeature: "requireApproval() / requireToolApproval() — a require_approval outcome halts the action until a human decides",
        checkDescription: "At least one rule has the require_approval outcome" },
      { id: "p2-oversight-audited", section: "2.2.2", sectionTitle: "Design for meaningful human oversight", sourceUrl: S, automatable: false,
        requirement: "The effectiveness of human oversight is regularly audited, against alert fatigue and automation bias",
        sdkFeature: "Approval decisions land in the audit trail; whether they are reviewed for effectiveness is attested via config.oversightAudited",
        checkDescription: "Caller attests oversight audits; approval events in the audit trail count as partial evidence" },
      { id: "p2-automated-monitoring", section: "2.2.2", sectionTitle: "Design for meaningful human oversight", sourceUrl: S, automatable: true,
        requirement: "Human oversight is complemented with automated monitoring and predefined alert thresholds — e.g. attempted unauthorised access, repeated tool calls",
        sdkFeature: "rateLimit() for the repeated-call threshold; blocked-action audit events for unauthorised access",
        checkDescription: "A rate-limit rule is configured and enforcement outcomes are recorded" },
    ],
  },
  {
    id: "2.3", title: "Implement technical controls and processes",
    description: "Technical controls for the new agentic components during development, testing before deployment, and continuous monitoring after it.",
    requirements: [
      { id: "p3-least-privilege-enforced", section: "2.3.1", sectionTitle: "During design and development, use technical controls", sourceUrl: S, automatable: true,
        requirement: "Least privilege limits the tools available to each agent, enforced through robust authentication and authorisation",
        sdkFeature: "Tool allowlist/blocklist rules combined with authenticated agent identity",
        checkDescription: "A tool restriction rule exists and every agent authenticates" },
      { id: "p3-trusted-servers", section: "2.3.1", sectionTitle: "During design and development, use technical controls", sourceUrl: S, automatable: true,
        requirement: "Agents interact only with whitelisted trusted servers, and code execution is sandboxed",
        sdkFeature: "createSupplyChainPolicy({ approvedTools }) for the whitelist; networkAllowlist() for the reachable hosts",
        checkDescription: "A supply-chain approved-tool policy or a network allowlist is registered" },
      { id: "p3-pre-deployment-testing", section: "2.3.2", sectionTitle: "Before deploying, test agents", sourceUrl: S, automatable: false,
        requirement: "Agents are tested for policy compliance and tool calling — right tools, right permissions — before deployment",
        sdkFeature: "fleetDryRun() replays scenarios through the policy set without enforcing",
        checkDescription: "Caller attests pre-deployment policy testing via config.policiesTested" },
      { id: "p3-continuous-monitoring", section: "2.3.3", sectionTitle: "When deploying, continuously monitor and test", sourceUrl: S, automatable: true,
        requirement: "Agent behaviour is continuously monitored and logged post-deployment, with each step traceable for debugging and audit",
        sdkFeature: "Audit trail on every enforce() decision; behavioral scorer re-scores agents from observed events",
        checkDescription: "Audit events are being recorded and agents carry live scores" },
      { id: "p3-termination", section: "2.3.3", sectionTitle: "When deploying, continuously monitor and test", sourceUrl: S, automatable: true,
        requirement: "Failsafe mechanisms exist to stop an agent workflow in real time and, on catastrophic malfunction or compromise, terminate it",
        sdkFeature: "createKillSwitch(gov) — a reserved priority-999 rule that blocks every subsequent action",
        checkDescription: "A kill-switch rule is registered" },
    ],
  },
  {
    id: "2.4", title: "Enable end-user responsibility",
    description: "Users are told what an agent can do and access, whom to escalate to, and are trained to oversee it.",
    requirements: [
      { id: "p4-capability-disclosure", section: "2.4.2", sectionTitle: "Users who interact with agents", sourceUrl: S, automatable: true,
        requirement: "Users are informed of the agent's capabilities — the scope of its access to their data and the actions it can take",
        sdkFeature: "Agent registration `description` and `tools` — the disclosed capability set is the registered one",
        checkDescription: "Every registered agent has a description and a declared tools list" },
      { id: "p4-escalation-contact", section: "2.4.2", sectionTitle: "Users who interact with agents", sourceUrl: S, automatable: true,
        requirement: "Users know the contact point to escalate to if the agent malfunctions",
        sdkFeature: "Agent registration `owner`",
        checkDescription: "Every registered agent has an owner" },
      { id: "p4-user-education", section: "2.4.2", sectionTitle: "Users who interact with agents", sourceUrl: S, automatable: false,
        requirement: "Users are educated on proper use and oversight of agents — range of actions, common failure modes, data usage policies",
        sdkFeature: "None. Training is a people process the SDK cannot observe.",
        checkDescription: "Caller attests user training via config.usersTrained" },
    ],
  },
];

/** The four pillars. */
export function getImdaPillars(): readonly ImdaPillar[] {
  return IMDA_AGENTIC_PILLARS;
}

/** Every requirement across the four pillars, flattened. */
export function getImdaRequirements(): ImdaRequirement[] {
  return IMDA_AGENTIC_PILLARS.flatMap((p) => [...p.requirements]);
}
