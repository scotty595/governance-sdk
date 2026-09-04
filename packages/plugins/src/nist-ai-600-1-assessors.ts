/**
 * NIST AI 600-1 (Generative AI Profile) — per-subcategory assessors.
 *
 * Each case maps one requirement from nist-ai-600-1-articles.ts to the
 * governance state it can be checked against: policy rules, audit counts,
 * registered agents, and the explicit attestation flags on the config. Called
 * from nist-ai-600-1.ts.
 *
 * Two cases — `ms-2.11` (fairness and bias) and `ms-2.12` (environmental
 * impact) — return `not-applicable` unless the caller attests external
 * evidence, because nothing in a policy engine can evidence them.
 */

import type { GovernanceInstance } from "@governance-sdk/core/governance.js";
import type { StoredAgent } from "@governance-sdk/core/storage.js";
import type { RequirementAssessment } from "./compliance-articles.js";
import { external, fail, ok, partial } from "./standards-rollup.js";

// ─── Assessment Config ───────────────────────────────────────

export interface NistAi600AssessmentConfig {
  governance: GovernanceInstance;
  agents: StoredAgent[];
  /** Hash-chained audit is enabled (createIntegrityAudit). */
  auditIntegrity?: boolean;
  /** Policies have been exercised against representative scenarios (MAP 2.3). */
  policiesTested?: boolean;
  /** An external fairness/bias evaluation has been run and documented (MEASURE 2.11). */
  biasEvaluated?: boolean;
  /** An external compute/energy impact assessment exists (MEASURE 2.12). */
  environmentalImpactAssessed?: boolean;
}

/** Condition types that scan content for prompt injection. */
const INJECTION_CONDITIONS: ReadonlySet<string> = new Set(["injection_guard", "ml_injection_guard"]);

// ─── Assessors ───────────────────────────────────────────────

export async function assessGenAiRequirement(
  id: string,
  config: NistAi600AssessmentConfig,
): Promise<RequirementAssessment> {
  const { governance, agents } = config;
  const rules = governance.policies.getRules();
  const scored = agents.filter((a) => a.compositeScore > 0);
  const owned = agents.filter((a) => a.owner);
  const hasKillSwitch = rules.some((r) => r.id.startsWith("__kill_switch__"));
  const hasSupplyChain = rules.some((r) => r.id.startsWith("supply-chain"));

  switch (id) {
    // ─── GOVERN ───
    case "gv-1.2": {
      if (rules.length === 0) return fail(id, "No policy rules configured", "Express your trustworthy-AI policy as named rules with reasons");
      const documented = rules.filter((r) => r.name && r.reason);
      if (documented.length === rules.length) return ok(id, `${rules.length} policy rule(s), all with a name and a reason`);
      return partial(id, `${documented.length}/${rules.length} rules carry both a name and a reason`, "Give every policy rule a name and a reason");
    }
    case "gv-1.3": {
      const outcomes = new Set(rules.map((r) => r.outcome));
      const allScored = agents.length > 0 && scored.length === agents.length;
      if (allScored && outcomes.size >= 2) return ok(id, `Risk effort is graduated: ${agents.length} scored agent(s), outcomes ${[...outcomes].sort().join(", ")}`);
      if (allScored || outcomes.size >= 2) return partial(id, `Partially graduated (${scored.length}/${agents.length} agents scored, ${outcomes.size} distinct outcome(s))`, "Score every agent and use more than one policy outcome so effort tracks risk");
      return fail(id, "Risk management is uniform — no scoring and a single outcome level", "Score agents via gov.register() and mix block / warn / require_approval outcomes");
    }
    case "gv-1.6": {
      if (agents.length === 0) return fail(id, "No agents registered — there is no inventory", "Register every GAI-backed agent via gov.register()");
      if (owned.length === agents.length) return ok(id, `${agents.length} agent(s) inventoried, each with an owner`);
      return partial(id, `${owned.length}/${agents.length} inventoried agents have an owner`, "Set an owner on every agent registration");
    }
    case "gv-4.1": {
      const blocked = await governance.audit.count({ outcome: "block" });
      if (rules.length > 0 && blocked > 0) return ok(id, `Before-action enforcement is live — ${blocked} action(s) refused under ${rules.length} rule(s)`);
      if (rules.length > 0) return partial(id, "Policies configured but nothing has been refused yet", "Route agent actions through gov.enforce() so policies actually gate execution");
      return fail(id, "Nothing gates unsafe generations before they take effect", "Configure policy rules and call gov.enforce() before each action");
    }
    case "gv-6.1":
      return hasSupplyChain
        ? ok(id, "Third-party tool access is governed by a supply-chain approved-tool policy")
        : fail(id, "No policy governs which third-party tools an agent may reach", "Add createSupplyChainPolicy({ approvedTools }) to gate third-party components");

    // ─── MAP ───
    case "mp-1.1": {
      if (agents.length === 0) return fail(id, "No agents registered", "Register agents with a description and an owner");
      const documented = agents.filter((a) => a.description && a.owner);
      if (documented.length === agents.length) return ok(id, `${agents.length} agent(s) document intended purpose and owner`);
      return partial(id, `${documented.length}/${agents.length} agents document purpose and owner`, "Add a description and an owner to every agent registration");
    }
    case "mp-2.3":
      return config.policiesTested
        ? ok(id, "Policies have been exercised against representative scenarios")
        : partial(id, "Policy testing not attested", "Exercise the policy set with fleetDryRun() and set policiesTested");

    case "mp-4.1": {
      if (agents.length === 0) return fail(id, "No agents registered — no component inventory", "Register agents with their tools list");
      const withTools = agents.filter((a) => a.tools.length > 0);
      if (withTools.length === agents.length) return ok(id, `${agents.length} agent(s) enumerate the third-party tools they invoke`);
      return partial(id, `${withTools.length}/${agents.length} agents enumerate their tools`, "Declare the tools list on every agent registration");
    }
    case "mp-5.1": {
      if (agents.length === 0) return fail(id, "No agents scored — impact is unquantified", "Register agents so the 7-dimension scorer can run");
      if (scored.length === agents.length) return ok(id, `${agents.length} agent(s) carry a composite impact score`);
      return partial(id, `${scored.length}/${agents.length} agents carry a composite score`, "Score every agent via gov.register() or gov.score()");
    }

    // ─── MEASURE ───
    case "ms-2.6": {
      const bounded = rules.some((r) => r.condition.type === "token_limit" || r.condition.type === "rate_limit");
      if (bounded && hasKillSwitch) return ok(id, "Fails safe: consumption is bounded and a kill switch can halt the agent");
      if (bounded || hasKillSwitch) return partial(id, bounded ? "Consumption is bounded but no kill switch is registered" : "Kill switch registered but consumption is unbounded", "Register both a consumption bound (tokenBudget() / rateLimit()) and createKillSwitch(gov)");
      return fail(id, "Nothing caps runaway generation and nothing can halt the agent", "Add tokenBudget() or rateLimit(), and register createKillSwitch(gov)");
    }
    case "ms-2.7": {
      const guarded = rules.some((r) => INJECTION_CONDITIONS.has(r.condition.type));
      const events = await governance.audit.count();
      if (guarded && events > 0) return ok(id, `Injection detection active and ${events} enforcement outcome(s) documented`);
      if (guarded) return partial(id, "Injection detection active but no outcomes recorded yet", "Enable audit logging so security evaluations are documented");
      return fail(id, "No adversarial-input detection configured", "Add createInjectionGuard() so adversarial input is detected and recorded");
    }
    case "ms-2.10":
      return rules.some((r) => r.condition.type === "sensitive_data_filter")
        ? ok(id, "Sensitive-data filtering is configured on the model boundary")
        : fail(id, "Nothing detects personal or sensitive data crossing the model boundary", "Add sensitiveDataFilter() to scan inputs and outputs for PII and credentials");

    case "ms-2.11":
      return config.biasEvaluated
        ? ok(id, "External fairness and bias evaluation attested by the caller")
        : external(id, "Not assessed — the SDK observes policy decisions, not model outputs across demographic slices", "Run a fairness/bias evaluation outside the SDK and set biasEvaluated");

    case "ms-2.12":
      return config.environmentalImpactAssessed
        ? ok(id, "External compute and energy impact assessment attested by the caller")
        : external(id, "Not assessed — the SDK has no visibility into training or inference compute", "Assess compute and energy impact outside the SDK and set environmentalImpactAssessed");

    case "ms-4.2": {
      const events = await governance.audit.count();
      if (events > 0 && config.auditIntegrity) return ok(id, `${events} audit event(s) recorded in a hash-chained, tamper-evident log`);
      if (events > 0) return partial(id, `${events} audit event(s) recorded, but the log is not tamper-evident`, "Enable createIntegrityAudit() so recorded results cannot be silently rewritten");
      return fail(id, "No measurement results are recorded", "Enable audit logging so results are durable and queryable");
    }

    // ─── MANAGE ───
    case "mg-2.2": {
      const events = await governance.audit.count();
      if (events > 0 && scored.length > 0) return ok(id, `Continuous monitoring: ${events} audit event(s) and ${scored.length} live agent score(s)`);
      if (events > 0) return partial(id, "Audit trail active but no agent carries a live score", "Score agents so drift is visible alongside the audit trail");
      return fail(id, "Deployed agents are not being monitored", "Enable audit logging and score agents so deployment is watched, not assumed");
    }
    case "mg-2.4": {
      if (!hasKillSwitch) return fail(id, "No kill-switch rule registered — a misbehaving agent cannot be deactivated via enforce()", "Register createKillSwitch(gov) so an agent can be halted immediately");
      if (agents.length > 0 && owned.length === agents.length) return ok(id, "Kill switch registered (priority 999) and every agent has an accountable owner");
      return partial(id, "Kill switch registered but not every agent has an owner", "Set an owner on every agent so deactivation responsibility is assigned");
    }
    case "mg-3.1": {
      const withTools = agents.filter((a) => a.tools.length > 0);
      const inventoried = agents.length > 0 && withTools.length === agents.length;
      if (hasSupplyChain && inventoried) return ok(id, "Third-party tools are inventoried per agent and gated by a supply-chain policy");
      if (hasSupplyChain || inventoried) return partial(id, hasSupplyChain ? "Supply-chain policy registered but tool inventories are incomplete" : "Tools inventoried but no supply-chain policy controls them at call time", "Register createSupplyChainPolicy({ approvedTools }) and declare tools on every agent");
      return fail(id, "Third-party resources are neither inventoried nor controlled", "Declare each agent's tools and add createSupplyChainPolicy({ approvedTools })");
    }
    case "mg-4.1": {
      const override = rules.some((r) => r.outcome === "require_approval");
      const events = await governance.audit.count();
      if (override && events > 0) return ok(id, `Human override path configured and ${events} post-deployment event(s) recorded`);
      if (override || events > 0) return partial(id, override ? "Override path configured but nothing is being recorded" : "Events recorded but no human override path exists", "Add requireApproval() for the override path and keep audit logging on");
      return fail(id, "No post-deployment monitoring and no human override path", "Add requireApproval() and enable audit logging");
    }

    default:
      return external(id, "Unknown requirement");
  }
}
