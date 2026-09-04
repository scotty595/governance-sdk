/**
 * CSA AI Controls Matrix v1.1 — per-requirement assessors.
 *
 * Each case maps one of this module's requirement ids (csa-aicm-articles.ts)
 * to the governance state it can be checked against. The ids are this
 * module's own — no CSA control id is reproduced or assessed. Called from
 * csa-aicm.ts.
 */

import type { GovernanceInstance } from "@governance-sdk/core/governance.js";
import type { StoredAgent } from "@governance-sdk/core/storage.js";
import type { RequirementAssessment } from "./compliance-articles.js";
import { external, fail, ok, partial } from "./standards-rollup.js";

// ─── Assessment Config ───────────────────────────────────────

export interface CsaAicmAssessmentConfig {
  governance: GovernanceInstance;
  agents: StoredAgent[];
  /** Hash-chained audit is enabled (createIntegrityAudit). */
  auditIntegrity?: boolean;
}

/** Condition types that scan content for prompt injection. */
const INJECTION_CONDITIONS: ReadonlySet<string> = new Set(["injection_guard", "ml_injection_guard"]);
/** Condition types that validate input at the interface. */
const INPUT_CONDITIONS: ReadonlySet<string> = new Set(["injection_guard", "ml_injection_guard", "input_pattern", "blocklist"]);
/** Condition types that bound consumption. */
const BOUND_CONDITIONS: ReadonlySet<string> = new Set(["token_limit", "rate_limit"]);
/** Condition types that restrict the tool surface. */
const TOOL_CONDITIONS: ReadonlySet<string> = new Set(["tool_blocked", "tool_allowed"]);

// ─── Assessors ───────────────────────────────────────────────

export async function assessAicmRequirement(
  id: string,
  config: CsaAicmAssessmentConfig,
): Promise<RequirementAssessment> {
  const { governance, agents } = config;
  const rules = governance.policies.getRules();
  const has = (pred: (type: string) => boolean): boolean => rules.some((r) => pred(r.condition.type));
  const scored = agents.filter((a) => a.compositeScore > 0);
  const authed = agents.filter((a) => a.metadata?.["hasAuth"] === true);
  const allAuthed = agents.length > 0 && authed.length === agents.length;

  switch (id) {
    // ─── A&A ───
    case "aa-audit-trail": {
      const events = await governance.audit.count();
      if (events > 0) return ok(id, `${events} audit event(s) available for assurance review`);
      return fail(id, "No audit events recorded", "Enable audit logging via gov.enforce() or gov.audit.log()");
    }
    case "aa-tamper-evidence":
      return config.auditIntegrity
        ? ok(id, "Audit log is HMAC-SHA256 hash-chained and verifiable")
        : partial(id, "Audit log is not tamper-evident", "Enable createIntegrityAudit() so the assurance record cannot be rewritten");

    // ─── AIS ───
    case "ais-input-validation":
      return has((t) => INPUT_CONDITIONS.has(t))
        ? ok(id, "Input validation active at the AI interface")
        : fail(id, "Untrusted input reaches the interface unvalidated", "Add createInjectionGuard() or an input_pattern / blocklist rule");
    case "ais-output-validation":
      return rules.some((r) => r.stage === "postprocess")
        ? ok(id, "Postprocess-stage output validation configured")
        : fail(id, "Responses leave the interface unvalidated", "Add outputPattern(), outputLength() or sensitiveDataFilter() at the postprocess stage");

    // ─── DSP ───
    case "dsp-sensitive-data":
      return has((t) => t === "sensitive_data_filter")
        ? ok(id, "Sensitive-data filtering configured")
        : fail(id, "Nothing detects credentials or personal data crossing a boundary", "Add sensitiveDataFilter()");
    case "dsp-classification":
      return has((t) => t === "data_classification")
        ? ok(id, "Data-classification rule configured")
        : partial(id, "No data-classification rule", "Add a data_classification rule so handling follows the data's classification");

    // ─── GRC ───
    case "grc-documented-policy": {
      if (rules.length === 0) return fail(id, "No policy rules configured", "Express governance policy as named rules with reasons");
      const documented = rules.filter((r) => r.name && r.reason);
      if (documented.length === rules.length) return ok(id, `${rules.length} documented policy rule(s)`);
      return partial(id, `${documented.length}/${rules.length} rules carry both a name and a reason`, "Give every policy rule a name and a reason");
    }
    case "grc-risk-treatment": {
      const outcomes = new Set(rules.map((r) => r.outcome));
      const allScored = agents.length > 0 && scored.length === agents.length;
      if (outcomes.size >= 2 && allScored) return ok(id, `Graduated treatment: outcomes ${[...outcomes].sort().join(", ")}, ${agents.length} scored agent(s)`);
      if (outcomes.size >= 2 || allScored) return partial(id, "Risk treatment partially graduated", "Score every agent and use more than one policy outcome");
      return fail(id, "Risk treatment is uniform", "Score agents and mix block / warn / require_approval outcomes");
    }

    // ─── IAM ───
    case "iam-agent-identity": {
      if (agents.length === 0) return fail(id, "No agents registered", "Register agents with metadata.hasAuth or Ed25519 identity tokens");
      if (allAuthed) return ok(id, `${agents.length} agent(s) declare an authentication mechanism`);
      if (authed.length > 0) return partial(id, `${authed.length}/${agents.length} agents declare authentication`, "Set metadata.hasAuth on every agent registration");
      return fail(id, "No agent declares an authentication mechanism", "Set metadata.hasAuth: true or use createEd25519Identity()");
    }
    case "iam-least-privilege":
      return has((t) => TOOL_CONDITIONS.has(t))
        ? ok(id, "Tool surface restricted by allowlist or blocklist")
        : fail(id, "No tool restriction — every agent can reach every tool", "Add allowOnlyTools() or blockTools()");
    case "iam-privilege-gate": {
      const levelGate = has((t) => t === "agent_level");
      if (levelGate && scored.length === agents.length && agents.length > 0) return ok(id, "Privileged actions gated on governance level, all agents scored");
      if (levelGate || scored.length > 0) return partial(id, levelGate ? "Level gate configured but not every agent is scored" : "Agents scored but no level gate exists", "Add requireLevel() and score every agent");
      return fail(id, "No trust-level gate on privileged operations", "Add requireLevel() and score agents via gov.register()");
    }

    // ─── LOG ───
    case "log-event-capture": {
      const events = await governance.audit.count();
      if (events > 0) return ok(id, `${events} security-relevant event(s) captured`);
      return fail(id, "No events captured", "Enable audit logging; add a sink with addSink() to export");
    }
    case "log-behavioural-monitoring": {
      if (agents.length === 0) return fail(id, "No agents to monitor", "Register agents so behavioural scoring can run");
      if (scored.length === agents.length) return ok(id, `${agents.length} agent(s) carry behaviour-derived scores`);
      return partial(id, `${scored.length}/${agents.length} agents scored`, "Score every agent so drift is detectable");
    }

    // ─── MDS ───
    case "mds-prompt-injection":
      return has((t) => INJECTION_CONDITIONS.has(t))
        ? ok(id, "Prompt-injection detection active")
        : fail(id, "No prompt-injection detection", "Add createInjectionGuard()");
    case "mds-context-poisoning":
      return rules.some((r) => r.stage === "tool_result")
        ? ok(id, "Tool results screened at the tool_result stage")
        : partial(id, "Tool results re-enter the model context unscreened", "Run scanToolResult() or the equivalent adapter hook at the tool_result stage");
    case "mds-model-access": {
      const bounded = has((t) => BOUND_CONDITIONS.has(t));
      if (allAuthed && bounded) return ok(id, "Model access is authenticated and consumption-bounded");
      if (allAuthed || bounded) return partial(id, allAuthed ? "Agents authenticate but consumption is unbounded" : "Consumption bounded but not every agent authenticates", "Require hasAuth on every agent and add tokenBudget() or rateLimit()");
      return fail(id, "Model access is neither authenticated nor bounded", "Set metadata.hasAuth on agents and add tokenBudget() or rateLimit()");
    }

    // ─── SEF ───
    case "sef-containment":
      return rules.some((r) => r.id.startsWith("__kill_switch__"))
        ? ok(id, "Kill switch registered (priority 999) — a compromised agent can be contained")
        : fail(id, "No kill-switch rule registered — nothing can contain a compromised agent via enforce()", "Register createKillSwitch(gov)");
    case "sef-forensic-record": {
      const events = await governance.audit.count();
      if (events > 0 && config.auditIntegrity) return ok(id, `${events} event(s) in a hash-chained forensic record`);
      if (events > 0) return partial(id, `${events} event(s) recorded but the record is not tamper-evident`, "Enable createIntegrityAudit()");
      return fail(id, "No forensic record", "Enable audit logging and createIntegrityAudit()");
    }

    // ─── STA ───
    case "sta-component-inventory": {
      if (agents.length === 0) return fail(id, "No agents registered — no component inventory", "Register agents with their tools list");
      const withTools = agents.filter((a) => a.tools && a.tools.length > 0);
      if (withTools.length === agents.length) return ok(id, `${agents.length} agent(s) inventory their components`);
      return partial(id, `${withTools.length}/${agents.length} agents inventory their tools`, "Declare tools on every agent registration");
    }
    case "sta-approved-components":
      return rules.some((r) => r.id.startsWith("supply-chain"))
        ? ok(id, "Supply-chain approved-component policy registered")
        : fail(id, "Unapproved components are not refused at call time", "Add createSupplyChainPolicy({ approvedTools })");

    // ─── TVM ───
    case "tvm-threat-detection":
      return has((t) => INJECTION_CONDITIONS.has(t) || t === "blocklist")
        ? ok(id, "Known attack patterns are detected in traffic")
        : fail(id, "No threat-pattern detection", "Add createInjectionGuard() or a blocklist rule");
    case "tvm-abuse-throttling":
      return has((t) => BOUND_CONDITIONS.has(t))
        ? ok(id, "Exploitation attempts are throttled")
        : fail(id, "Nothing bounds an exploitation attempt", "Add rateLimit() or tokenBudget()");

    default:
      return external(id, "Unknown requirement");
  }
}
