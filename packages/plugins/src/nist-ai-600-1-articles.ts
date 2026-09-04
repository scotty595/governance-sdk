/**
 * NIST AI 600-1 — Generative AI Profile: the AI RMF subcategories this SDK
 * can evidence, grouped by function.
 *
 * Source of every `subcategory` / `subcategoryTitle` below: NIST AI 600-1,
 * July 2024, https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf. Each title
 * is a §3 heading quoted verbatim, verified against the PDF on 2026-09-04.
 *
 * WHAT IS AND IS NOT REPRODUCED HERE
 * NIST's §3 tables key *suggested actions* — `GV-1.1-001`, `MS-2.7-009` and
 * so on — to subcategories, and tag each action with the GAI risks it
 * addresses. Those action-level texts and tags are NOT reproduced: this maps
 * at subcategory granularity, and `gaiRisks` on each requirement is this SDK's
 * own attribution of which risks the SDK-observable check bears on. Nineteen
 * of the ~49 subcategories NIST profiles are here; the rest concern
 * organizational process the SDK cannot see.
 *
 * Types and the twelve §2 risks: nist-ai-600-1-types.ts.
 * Per-requirement checks: nist-ai-600-1-assessors.ts.
 */

import { NIST_AI_600_1_SOURCE_URL, type GenAiFunction, type GenAiRequirement } from "./nist-ai-600-1-types.js";

const S = NIST_AI_600_1_SOURCE_URL;

export const NIST_AI_600_1_FUNCTIONS: readonly GenAiFunction[] = [
  {
    id: "GOVERN", title: "Govern",
    description: "Cultivate and implement a culture of risk management for generative AI.",
    requirements: [
      { id: "gv-1.2", subcategory: "GOVERN 1.2", sourceUrl: S, automatable: true,
        subcategoryTitle: "The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.",
        requirement: "Trustworthy-AI policy is expressed as enforceable, documented rules rather than prose",
        sdkFeature: "Policy engine — every rule carries a name and a reason and is evaluated on every action",
        checkDescription: "Every policy rule has a name and a reason",
        gaiRisks: ["human-ai-configuration", "information-security"] },
      { id: "gv-1.3", subcategory: "GOVERN 1.3", sourceUrl: S, automatable: true,
        subcategoryTitle: "Processes, procedures, and practices are in place to determine the needed level of risk management activities based on the organization's risk tolerance.",
        requirement: "Risk-management effort is graduated, not uniform, across agents and actions",
        sdkFeature: "Governance levels 0-4 from 7-dimension scoring, plus graduated policy outcomes (allow / warn / require_approval / block)",
        checkDescription: "Agents are scored and at least two distinct policy outcomes are in use",
        gaiRisks: ["confabulation", "dangerous-violent-hateful", "information-security"] },
      { id: "gv-1.6", subcategory: "GOVERN 1.6", sourceUrl: S, automatable: true,
        subcategoryTitle: "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.",
        requirement: "Every GAI-backed agent in production is inventoried with an owner",
        sdkFeature: "gov.register() — the agent registry is the inventory; owner, framework, tools and channels are stored per agent",
        checkDescription: "At least one agent is registered and every agent has an owner",
        gaiRisks: ["value-chain-integration"] },
      { id: "gv-4.1", subcategory: "GOVERN 4.1", sourceUrl: S, automatable: true,
        subcategoryTitle: "Organizational policies and practices are in place to foster a critical thinking and safety-first mindset in the design, development, deployment, and uses of AI systems to minimize potential negative impacts.",
        requirement: "Unsafe generations and actions are refused before they take effect, not reviewed afterwards",
        sdkFeature: "gov.enforce() before-action enforcement; blocked actions are recorded in the audit trail",
        checkDescription: "Policies are configured and enforcement has actually blocked an action",
        gaiRisks: ["cbrn", "dangerous-violent-hateful", "obscene-degrading-abusive"] },
      { id: "gv-6.1", subcategory: "GOVERN 6.1", sourceUrl: S, automatable: true,
        subcategoryTitle: "Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third-party's intellectual property or other rights.",
        requirement: "Third-party tools and components an agent can reach are governed by policy",
        sdkFeature: "createSupplyChainPolicy({ approvedTools }) — blocks calls to tools outside the approved registry",
        checkDescription: "A supply-chain approved-tool policy is registered",
        gaiRisks: ["intellectual-property", "value-chain-integration"] },
    ],
  },
  {
    id: "MAP", title: "Map",
    description: "Establish the context and categorize the generative AI risks in it.",
    requirements: [
      { id: "mp-1.1", subcategory: "MAP 1.1", sourceUrl: S, automatable: true,
        subcategoryTitle: "Intended purposes, potentially beneficial uses, context specific laws, norms and expectations, and prospective settings in which the AI system will be deployed are understood and documented.",
        requirement: "Each agent's intended purpose and deploying owner are recorded",
        sdkFeature: "Agent registration carries description, owner, framework and channels",
        checkDescription: "Every registered agent has both a description and an owner",
        gaiRisks: ["human-ai-configuration"] },
      { id: "mp-2.3", subcategory: "MAP 2.3", sourceUrl: S, automatable: false,
        subcategoryTitle: "Scientific integrity and TEVV considerations are identified and documented, including those related to experimental design, data collection and selection, system trustworthiness, and construct validation.",
        requirement: "Policies are exercised against representative scenarios before they are relied on",
        sdkFeature: "fleetDryRun() — replay scenarios through the policy set without enforcing",
        checkDescription: "Caller attests policy testing via config.policiesTested",
        gaiRisks: ["confabulation", "information-integrity"] },
      { id: "mp-4.1", subcategory: "MAP 4.1", sourceUrl: S, automatable: true,
        subcategoryTitle: "Approaches for mapping AI technology and legal risks of its components – including the use of third-party data or software – are in place, followed, and documented, as are risks of infringement of a third-party's intellectual property or other rights.",
        requirement: "The third-party components each agent can invoke are enumerated",
        sdkFeature: "Agent registration `tools` list, plus the CycloneDX supply-chain inventory",
        checkDescription: "Every registered agent declares its tools",
        gaiRisks: ["intellectual-property", "value-chain-integration"] },
      { id: "mp-5.1", subcategory: "MAP 5.1", sourceUrl: S, automatable: true,
        subcategoryTitle: "Likelihood and magnitude of each identified impact (both potentially beneficial and harmful) based on expected use, past uses of AI systems in similar contexts, public incident reports, feedback from those external to the team that developed or deployed the AI system, or other data are identified and documented.",
        requirement: "Each agent carries a quantified impact estimate that can be compared across the fleet",
        sdkFeature: "7-dimension composite scoring (identity, permissions, observability, guardrails, auditability, compliance, lifecycle)",
        checkDescription: "Every registered agent has a composite score above zero",
        gaiRisks: ["harmful-bias-homogenization", "data-privacy"] },
    ],
  },
  {
    id: "MEASURE", title: "Measure",
    description: "Analyze, benchmark and monitor the generative AI risks that were mapped.",
    requirements: [
      { id: "ms-2.6", subcategory: "MEASURE 2.6", sourceUrl: S, automatable: true,
        subcategoryTitle: "The AI system is evaluated regularly for safety risks – as identified in the MAP function. The AI system to be deployed is demonstrated to be safe, its residual negative risk does not exceed the risk tolerance, and it can fail safely, particularly if made to operate beyond its knowledge limits.",
        requirement: "The system can fail safe: runaway generation is capped and a rogue agent can be stopped",
        sdkFeature: "tokenBudget() and rateLimit() bound consumption; createKillSwitch(gov) halts an agent at priority 999",
        checkDescription: "A consumption bound (token budget or rate limit) and a kill switch are both registered",
        gaiRisks: ["cbrn", "dangerous-violent-hateful", "obscene-degrading-abusive"] },
      { id: "ms-2.7", subcategory: "MEASURE 2.7", sourceUrl: S, automatable: true,
        subcategoryTitle: "AI system security and resilience – as identified in the MAP function – are evaluated and documented.",
        requirement: "Adversarial input to the model is detected, and the outcome is documented",
        sdkFeature: "createInjectionGuard() / ml_injection_guard, with every decision written to the audit trail",
        checkDescription: "An injection-detection rule is active and enforcement outcomes are recorded",
        gaiRisks: ["information-security"] },
      { id: "ms-2.10", subcategory: "MEASURE 2.10", sourceUrl: S, automatable: true,
        subcategoryTitle: "Privacy risk of the AI system – as identified in the MAP function – is examined and documented.",
        requirement: "Personal and sensitive data crossing the model boundary is detected",
        sdkFeature: "sensitiveDataFilter() — credential, PII and prompt-leak patterns, with masking",
        checkDescription: "A sensitive-data filter rule is configured",
        gaiRisks: ["data-privacy"] },
      { id: "ms-2.11", subcategory: "MEASURE 2.11", sourceUrl: S, automatable: false,
        subcategoryTitle: "Fairness and bias – as identified in the MAP function – are evaluated and results are documented.",
        requirement: "Fairness and bias evaluations are run and their results documented",
        sdkFeature: "None. The SDK observes policy decisions, not model outputs across demographic slices.",
        checkDescription: "Caller attests an external bias evaluation via config.biasEvaluated",
        gaiRisks: ["harmful-bias-homogenization"] },
      { id: "ms-2.12", subcategory: "MEASURE 2.12", sourceUrl: S, automatable: false,
        subcategoryTitle: "Environmental impact and sustainability of AI model training and management activities – as identified in the MAP function – are assessed and documented.",
        requirement: "Compute and energy impact of training and serving is assessed and documented",
        sdkFeature: "None. The SDK has no visibility into training or inference compute.",
        checkDescription: "Caller attests an external assessment via config.environmentalImpactAssessed",
        gaiRisks: ["environmental"] },
      { id: "ms-4.2", subcategory: "MEASURE 4.2", sourceUrl: S, automatable: true,
        subcategoryTitle: "Measurement results regarding AI system trustworthiness in deployment context(s) and across the AI lifecycle are informed by input from domain experts and relevant AI Actors to validate whether the system is performing consistently as intended. Results are documented.",
        requirement: "Measurement results are durably recorded and queryable",
        sdkFeature: "Audit trail — queryable events with agent id, outcome, severity and timestamp; HMAC-SHA256 chaining when integrity audit is on",
        checkDescription: "Audit events exist and, ideally, the log is tamper-evident",
        gaiRisks: ["confabulation", "information-integrity"] },
    ],
  },
  {
    id: "MANAGE", title: "Manage",
    description: "Act on the measured generative AI risks, and keep acting after deployment.",
    requirements: [
      { id: "mg-2.2", subcategory: "MANAGE 2.2", sourceUrl: S, automatable: true,
        subcategoryTitle: "Mechanisms are in place and applied to sustain the value of deployed AI systems.",
        requirement: "Deployed agents are watched continuously rather than assessed once",
        sdkFeature: "Audit trail plus the behavioral scorer, which re-scores an agent from observed events",
        checkDescription: "Audit events exist and agents carry live scores",
        gaiRisks: ["confabulation", "information-integrity"] },
      { id: "mg-2.4", subcategory: "MANAGE 2.4", sourceUrl: S, automatable: true,
        subcategoryTitle: "Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.",
        requirement: "A deployed agent can be deactivated immediately, by someone identifiable",
        sdkFeature: "createKillSwitch(gov) — a reserved priority-999 rule that overrides every other rule; user rules clamp to 998",
        checkDescription: "A kill-switch rule is registered and agents have owners",
        gaiRisks: ["cbrn", "dangerous-violent-hateful", "information-security", "obscene-degrading-abusive"] },
      { id: "mg-3.1", subcategory: "MANAGE 3.1", sourceUrl: S, automatable: true,
        subcategoryTitle: "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented.",
        requirement: "Third-party tools are both inventoried and controlled at call time",
        sdkFeature: "Supply-chain approved-tool policy alongside the per-agent tools inventory",
        checkDescription: "A supply-chain policy is registered and agents declare their tools",
        gaiRisks: ["value-chain-integration", "intellectual-property"] },
      { id: "mg-4.1", subcategory: "MANAGE 4.1", sourceUrl: S, automatable: true,
        subcategoryTitle: "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI Actors, appeal and override, decommissioning, incident response, recovery, and change management.",
        requirement: "There is a human override path and an incident record after deployment",
        sdkFeature: "requireApproval() for the override path; the audit trail for the incident record; kill switch for decommissioning",
        checkDescription: "An approval-gated rule exists and audit events are being recorded",
        gaiRisks: ["human-ai-configuration", "information-integrity"] },
    ],
  },
];

/** Every requirement across the four functions, flattened. */
export function getGenAiRequirements(): GenAiRequirement[] {
  return NIST_AI_600_1_FUNCTIONS.flatMap((fn) => [...fn.requirements]);
}

/** The four AI RMF functions as profiled by NIST AI 600-1. */
export function getGenAiFunctions(): readonly GenAiFunction[] {
  return NIST_AI_600_1_FUNCTIONS;
}
