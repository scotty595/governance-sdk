/**
 * CSA AI Controls Matrix (AICM) v1.1 — the 18 domains.
 *
 * Domain-level only: no CSA control ids or control text are reproduced here.
 * The requirement ids (`iam-agent-identity`, …) are this module's own. Ten
 * domains carry requirements the SDK can evidence; the other eight are listed
 * with an empty `requirements` array and report `not-applicable`. Read the
 * header of csa-aicm-types.ts for exactly what was and was not verified.
 *
 * Titles and control counts: CSA, "The AI Controls Matrix (AICM)" (v1.0
 * guidance, © 2025). Totals and release date:
 * https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1
 */

import { CSA_AICM_SOURCE_URL, type AicmDomain, type AicmDomainCode } from "./csa-aicm-types.js";

const S = CSA_AICM_SOURCE_URL;
const V = "1.0" as const;

export const CSA_AICM_DOMAINS: readonly AicmDomain[] = [
  {
    code: "A&A", title: "Audit and Assurance", controlCount: 6, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Audit and assurance policies, regular AI security assessments, and independent evidence that controls operate as described.",
    requirements: [
      { id: "aa-audit-trail", domain: "A&A", sourceUrl: S, automatable: true,
        requirement: "Agent activity produces an assurance record an assessor can review",
        sdkFeature: "Audit trail — queryable events with agent id, event type, outcome, severity and timestamp",
        checkDescription: "Audit events are being recorded" },
      { id: "aa-tamper-evidence", domain: "A&A", sourceUrl: S, automatable: true,
        requirement: "The assurance record cannot be silently rewritten between assessments",
        sdkFeature: "createIntegrityAudit() — HMAC-SHA256 hash-chained audit log with verification",
        checkDescription: "Tamper-evident audit logging is enabled" },
    ],
  },
  {
    code: "AIS", title: "Application and Interface Security", controlCount: 15, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Secure application and API services around AI workloads, including input validation and interface hardening.",
    requirements: [
      { id: "ais-input-validation", domain: "AIS", sourceUrl: S, automatable: true,
        requirement: "Untrusted input reaching the AI interface is validated before it is acted on",
        sdkFeature: "createInjectionGuard() at the preprocess stage; input_pattern and blocklist conditions",
        checkDescription: "An input-validation or injection-detection rule is active" },
      { id: "ais-output-validation", domain: "AIS", sourceUrl: S, automatable: true,
        requirement: "Interface responses are validated before they leave the system",
        sdkFeature: "Postprocess-stage rules — output_pattern, output_length, sensitive_data_filter",
        checkDescription: "A postprocess-stage rule is configured" },
    ],
  },
  {
    code: "BCR", title: "Business Continuity Management and Operational Resilience", controlCount: 11, asOfVersion: V, codeVerified: false, sourceUrl: S,
    description: "Availability, redundancy and recovery for AI services and the infrastructure under them.",
    requirements: [],
  },
  {
    code: "CCC", title: "Change Control and Configuration Management", controlCount: 9, asOfVersion: V, codeVerified: false, sourceUrl: S,
    description: "Changes to models, data and infrastructure do not introduce vulnerabilities or cause model drift.",
    requirements: [],
  },
  {
    code: "CEK", title: "Cryptography, Encryption and Key Management", controlCount: 21, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Cryptographic protection of data, model weights and serving infrastructure, and the key lifecycle behind it.",
    requirements: [],
  },
  {
    code: "DCS", title: "Datacenter Security", controlCount: 15, asOfVersion: V, codeVerified: false, sourceUrl: S,
    description: "Physical security of the facilities that host model training and inference.",
    requirements: [],
  },
  {
    code: "DSP", title: "Data Security and Privacy Lifecycle Management", controlCount: 24, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Classification, protection and privacy handling of data across the AI lifecycle.",
    requirements: [
      { id: "dsp-sensitive-data", domain: "DSP", sourceUrl: S, automatable: true,
        requirement: "Credentials and personal data are detected before they cross a boundary",
        sdkFeature: "sensitiveDataFilter() — credential, PII and prompt-leak patterns, with a mask strategy",
        checkDescription: "A sensitive-data filter rule is configured" },
      { id: "dsp-classification", domain: "DSP", sourceUrl: S, automatable: true,
        requirement: "Data an agent touches is handled according to its classification",
        sdkFeature: "data_classification condition — gate actions on the classification of the data in scope",
        checkDescription: "A data-classification rule is configured" },
    ],
  },
  {
    code: "GRC", title: "Governance, Risk Management and Compliance", controlCount: 15, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "An information-governance programme for AI systems, sponsored by leadership, with documented policy and risk treatment.",
    requirements: [
      { id: "grc-documented-policy", domain: "GRC", sourceUrl: S, automatable: true,
        requirement: "Policy exists as documented, enforceable rules rather than intent",
        sdkFeature: "Policy engine — rules carry a name, a reason and a priority and are evaluated on every action",
        checkDescription: "Every policy rule has a name and a reason" },
      { id: "grc-risk-treatment", domain: "GRC", sourceUrl: S, automatable: true,
        requirement: "Risk treatment is graduated to the risk, not uniform",
        sdkFeature: "Four outcomes (allow, warn, require_approval, block) plus governance levels 0-4",
        checkDescription: "More than one policy outcome is in use and agents are scored" },
    ],
  },
  {
    code: "HRS", title: "Human Resources", controlCount: 15, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Personnel security, training and acceptable-use obligations for the people around AI systems.",
    requirements: [],
  },
  {
    code: "IAM", title: "Identity and Access Management", controlCount: 19, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Identity, authentication, authorization and least privilege for the actors — human and non-human — that reach AI systems.",
    requirements: [
      { id: "iam-agent-identity", domain: "IAM", sourceUrl: S, automatable: true,
        requirement: "Every non-human actor authenticates rather than acting anonymously",
        sdkFeature: "Agent registration with hasAuth metadata; createEd25519Identity() for signed agent identity tokens",
        checkDescription: "Every registered agent declares an authentication mechanism" },
      { id: "iam-least-privilege", domain: "IAM", sourceUrl: S, automatable: true,
        requirement: "Each actor reaches only the tools its task requires",
        sdkFeature: "allowOnlyTools() / blockTools() — allowlist or blocklist the tool surface per policy",
        checkDescription: "A tool allowlist or blocklist rule is configured" },
      { id: "iam-privilege-gate", domain: "IAM", sourceUrl: S, automatable: true,
        requirement: "Privileged operations are gated on an assessed trust level",
        sdkFeature: "requireLevel() — gate an action on the agent's governance level",
        checkDescription: "An agent_level rule is configured and agents are scored" },
    ],
  },
  {
    code: "IPY", title: "Interoperability and Portability", controlCount: 4, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Portability of data and models between providers, and interoperability of the interfaces around them.",
    requirements: [],
  },
  {
    code: "I&S", title: "Infrastructure Security", controlCount: 9, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Network and compute security for the infrastructure that trains and serves models.",
    requirements: [],
  },
  {
    code: "LOG", title: "Logging and Monitoring", controlCount: 15, asOfVersion: V, codeVerified: false, sourceUrl: S,
    description: "Logging, monitoring and detection across the AI stack, sufficient to reconstruct what happened.",
    requirements: [
      { id: "log-event-capture", domain: "LOG", sourceUrl: S, automatable: true,
        requirement: "Security-relevant AI events are captured as they happen",
        sdkFeature: "Audit trail written on every enforce() decision, plus addSink() for OTel or a webhook",
        checkDescription: "Audit events are being recorded" },
      { id: "log-behavioural-monitoring", domain: "LOG", sourceUrl: S, automatable: true,
        requirement: "Captured events are analysed for drift rather than only stored",
        sdkFeature: "Behavioral scorer — re-scores an agent from its observed audit history",
        checkDescription: "Agents carry live scores derived from observed behaviour" },
    ],
  },
  {
    code: "MDS", title: "Model Security", controlCount: 13, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "The AI-specific domain: model poisoning and manipulation, prompt-injection attacks, and unauthorized model access.",
    requirements: [
      { id: "mds-prompt-injection", domain: "MDS", sourceUrl: S, automatable: true,
        requirement: "Prompt-injection attempts against the model are detected",
        sdkFeature: "createInjectionGuard() — regex corpus across seven categories, with base64 decoding; ml_injection_guard for the classifier",
        checkDescription: "An injection-detection rule is active" },
      { id: "mds-context-poisoning", domain: "MDS", sourceUrl: S, automatable: true,
        requirement: "Content returned by tools is screened before it re-enters the model context",
        sdkFeature: "tool_result-stage enforcement (scanToolResult / the Mastra processToolResult hook)",
        checkDescription: "A rule runs at the tool_result stage" },
      { id: "mds-model-access", domain: "MDS", sourceUrl: S, automatable: true,
        requirement: "Access to the model is bounded and attributable",
        sdkFeature: "Agent registration with authentication metadata plus token and rate budgets per agent",
        checkDescription: "Agents authenticate and consumption is bounded" },
    ],
  },
  {
    code: "SEF", title: "Security Incident Management, E-Discovery, and Cloud Forensics", controlCount: 9, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Detecting, responding to and investigating incidents involving AI systems, across the shared responsibility boundary.",
    requirements: [
      { id: "sef-containment", domain: "SEF", sourceUrl: S, automatable: true,
        requirement: "A compromised AI actor can be contained immediately",
        sdkFeature: "createKillSwitch(gov) — reserved priority-999 rule that overrides every other rule",
        checkDescription: "A kill-switch rule is registered" },
      { id: "sef-forensic-record", domain: "SEF", sourceUrl: S, automatable: true,
        requirement: "There is a forensically usable record of what the actor did",
        sdkFeature: "Audit trail, hash-chained under createIntegrityAudit(), queryable by agent and outcome",
        checkDescription: "Audit events exist and the log is tamper-evident" },
    ],
  },
  {
    code: "STA", title: "Supply Chain Management, Transparency, and Accountability", controlCount: 16, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Transparency and accountability across the AI supply chain, and control over the third-party components in it.",
    requirements: [
      { id: "sta-component-inventory", domain: "STA", sourceUrl: S, automatable: true,
        requirement: "The third-party components each AI actor depends on are inventoried",
        sdkFeature: "Agent registration `tools` list plus the CycloneDX supply-chain export",
        checkDescription: "Every registered agent declares its tools" },
      { id: "sta-approved-components", domain: "STA", sourceUrl: S, automatable: true,
        requirement: "Components outside the approved set are refused at call time",
        sdkFeature: "createSupplyChainPolicy({ approvedTools }) — blocks unapproved tool calls",
        checkDescription: "A supply-chain approved-tool policy is registered" },
    ],
  },
  {
    code: "TVM", title: "Threat and Vulnerability Management", controlCount: 13, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Identifying, assessing and remediating threats and vulnerabilities across AI systems and their dependencies.",
    requirements: [
      { id: "tvm-threat-detection", domain: "TVM", sourceUrl: S, automatable: true,
        requirement: "Known attack patterns against the AI system are detected in traffic",
        sdkFeature: "Injection detection corpus plus the blocklist condition",
        checkDescription: "An injection-detection or blocklist rule is active" },
      { id: "tvm-abuse-throttling", domain: "TVM", sourceUrl: S, automatable: true,
        requirement: "Exploitation attempts are bounded rather than merely observed",
        sdkFeature: "rateLimit() and tokenBudget() — throttle actions and cap consumption",
        checkDescription: "A rate-limit or token-budget rule is configured" },
    ],
  },
  {
    code: "UEM", title: "Universal Endpoint Management", controlCount: 14, asOfVersion: V, codeVerified: true, sourceUrl: S,
    description: "Management and hardening of the endpoints from which AI systems are accessed.",
    requirements: [],
  },
];

/** The ten domains this module scores. */
export const AICM_ASSESSED_DOMAINS: readonly AicmDomainCode[] = CSA_AICM_DOMAINS
  .filter((d) => d.requirements.length > 0)
  .map((d) => d.code);

/** The eight domains enumerated but not scored — no policy-engine evidence. */
export const AICM_OUT_OF_SCOPE_DOMAINS: readonly AicmDomainCode[] = CSA_AICM_DOMAINS
  .filter((d) => d.requirements.length === 0)
  .map((d) => d.code);

/** All 18 domains. */
export function getAicmDomains(): readonly AicmDomain[] {
  return CSA_AICM_DOMAINS;
}

/** One domain by its code. */
export function getAicmDomain(code: AicmDomainCode): AicmDomain | undefined {
  return CSA_AICM_DOMAINS.find((d) => d.code === code);
}
