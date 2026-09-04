/**
 * IMDA Model AI Governance Framework for Agentic AI v1.0 — per-requirement
 * assessors.
 *
 * Each case maps one requirement id from imda-agentic-articles.ts to the
 * governance state it can be checked against. The framework maps unusually
 * directly onto what this SDK does — unique identity tied to an owner,
 * bounded tools and data, approval before execution, retained records, a way
 * to terminate — so most cases are a straight read of policy rules and the
 * agent registry. Three are people processes and rely on attestation flags.
 * Called from imda-agentic.ts.
 */

import type { GovernanceInstance } from "@governance-sdk/core/governance.js";
import type { StoredAgent } from "@governance-sdk/core/storage.js";
import type { RequirementAssessment } from "./compliance-articles.js";
import { external, fail, ok, partial } from "./standards-rollup.js";

// ─── Assessment Config ───────────────────────────────────────

export interface ImdaAgenticAssessmentConfig {
  governance: GovernanceInstance;
  agents: StoredAgent[];
  /** Hash-chained audit is enabled (createIntegrityAudit). */
  auditIntegrity?: boolean;
  /** Agents were tested for policy compliance and tool calling before deployment (§2.3.2). */
  policiesTested?: boolean;
  /** The effectiveness of human oversight is regularly audited (§2.2.2). */
  oversightAudited?: boolean;
  /** Users have been trained on proper use and oversight of agents (§2.4.2). */
  usersTrained?: boolean;
}

/** Condition types that restrict the tool surface. */
const TOOL_CONDITIONS: ReadonlySet<string> = new Set(["tool_blocked", "tool_allowed"]);
/** Condition types that confine where an agent may reach. */
const BOUNDARY_CONDITIONS: ReadonlySet<string> = new Set(["scope_boundary", "network_allowlist"]);

// ─── Assessors ───────────────────────────────────────────────

export async function assessImdaRequirement(
  id: string,
  config: ImdaAgenticAssessmentConfig,
): Promise<RequirementAssessment> {
  const { governance, agents } = config;
  const rules = governance.policies.getRules();
  const has = (pred: (type: string) => boolean): boolean => rules.some((r) => pred(r.condition.type));
  const hasKillSwitch = rules.some((r) => r.id.startsWith("__kill_switch__"));
  const hasToolRule = has((t) => TOOL_CONDITIONS.has(t));
  const scored = agents.filter((a) => a.compositeScore > 0);
  const owned = agents.filter((a) => a.owner);
  const authed = agents.filter((a) => a.metadata?.["hasAuth"] === true);
  const allOwned = agents.length > 0 && owned.length === agents.length;
  const allAuthed = agents.length > 0 && authed.length === agents.length;

  switch (id) {
    // ─── 2.1 Assess and bound the risks upfront ───
    case "p1-risk-scoping": {
      if (agents.length === 0) return fail(id, "No agents registered — no risk has been scoped", "Register agents via gov.register() so each is scored and levelled");
      if (scored.length === agents.length) return ok(id, `${agents.length} agent(s) scored and assigned a governance level`);
      return partial(id, `${scored.length}/${agents.length} agents scored`, "Score every agent via gov.register() or gov.score()");
    }
    case "p1-minimum-tools":
      return hasToolRule
        ? ok(id, "Tool access is limited by an allowlist or blocklist policy")
        : fail(id, "No policy limits which tools an agent may use", "Add allowOnlyTools() with the minimum set, or blockTools() for the dangerous ones");
    case "p1-contained-impact": {
      const bounded = has((t) => BOUNDARY_CONDITIONS.has(t));
      if (bounded && hasKillSwitch) return ok(id, "Scope of impact is bounded and the agent can be taken offline");
      if (bounded || hasKillSwitch) return partial(id, bounded ? "Boundary configured but no kill switch to take the agent offline" : "Kill switch registered but no scope or network boundary", "Add scopeBoundary() / networkAllowlist() and register createKillSwitch(gov)");
      return fail(id, "No boundary on the agent's reach and no way to take it offline", "Add scopeBoundary() or networkAllowlist(), and register createKillSwitch(gov)");
    }
    case "p1-agent-identity": {
      if (agents.length === 0) return fail(id, "No agents registered — no agent has an identity", "Register agents with metadata.hasAuth and an owner");
      if (allAuthed && allOwned) return ok(id, `${agents.length} agent(s) each carry an authenticated identity tied to an owner`);
      if (authed.length > 0 || owned.length > 0) return partial(id, `${authed.length}/${agents.length} authenticate, ${owned.length}/${agents.length} have an owner`, "Set metadata.hasAuth and an owner on every agent registration");
      return fail(id, "No agent authenticates or is tied to an owner", "Set metadata.hasAuth: true and an owner on every agent, or use createEd25519Identity()");
    }
    case "p1-delegation-recorded": {
      const withPerms = agents.filter((a) => a.permissions && Object.keys(a.permissions).length > 0);
      const events = await governance.audit.count();
      if (agents.length === 0) return fail(id, "No agents registered — no delegations to record", "Register agents with their permissions");
      if (withPerms.length === agents.length && events > 0) return ok(id, `${agents.length} agent(s) declare permissions and ${events} action(s) are recorded against them`);
      if (withPerms.length > 0 || events > 0) return partial(id, `${withPerms.length}/${agents.length} agents declare permissions; ${events} audit event(s)`, "Declare permissions on every agent and keep audit logging on");
      return fail(id, "Delegated authority is neither declared nor recorded", "Declare permissions at registration and enable audit logging");
    }

    // ─── 2.2 Make humans meaningfully accountable ───
    case "p2-accountable-owner": {
      if (agents.length === 0) return fail(id, "No agents registered", "Register agents with a named owner");
      if (allOwned) return ok(id, `${agents.length} agent(s) have an accountable owner`);
      return partial(id, `${owned.length}/${agents.length} agents have an owner`, "Set an owner on every agent registration");
    }
    case "p2-approval-checkpoints":
      return rules.some((r) => r.outcome === "require_approval")
        ? ok(id, "Human approval is required at defined checkpoints")
        : fail(id, "No action requires human approval before it executes", "Add requireApproval() for high-stakes or irreversible actions");
    case "p2-oversight-audited": {
      if (config.oversightAudited) return ok(id, "Effectiveness of human oversight is audited (attested)");
      const approvals = await governance.audit.count({ outcome: "require_approval" });
      if (approvals > 0) return partial(id, `${approvals} approval decision(s) recorded but their effectiveness is not attested as audited`, "Review approval outcomes regularly and set oversightAudited");
      return external(id, "Not assessed — no approval decisions recorded and no oversight audit attested", "Route sensitive actions through requireApproval() and audit the resulting decisions");
    }
    case "p2-automated-monitoring": {
      const throttled = has((t) => t === "rate_limit");
      const blocked = await governance.audit.count({ outcome: "block" });
      if (throttled && blocked > 0) return ok(id, `Threshold alerting active: rate limit configured, ${blocked} unauthorised action(s) blocked and recorded`);
      if (throttled || blocked > 0) return partial(id, throttled ? "Rate limit configured but no enforcement outcomes recorded yet" : "Blocked actions recorded but no repeated-call threshold is set", "Add rateLimit() and keep enforcement outcomes in the audit trail");
      return fail(id, "No automated monitoring thresholds", "Add rateLimit() and route actions through gov.enforce()");
    }

    // ─── 2.3 Implement technical controls and processes ───
    case "p3-least-privilege-enforced": {
      if (hasToolRule && allAuthed) return ok(id, "Tool least-privilege is enforced against authenticated agent identities");
      if (hasToolRule || allAuthed) return partial(id, hasToolRule ? "Tool restriction exists but not every agent authenticates" : "Agents authenticate but no tool restriction exists", "Add allowOnlyTools() and set metadata.hasAuth on every agent");
      return fail(id, "No tool restriction and no authenticated agent identity", "Add allowOnlyTools() and require hasAuth on every agent");
    }
    case "p3-trusted-servers": {
      const whitelisted = rules.some((r) => r.id.startsWith("supply-chain")) || has((t) => t === "network_allowlist");
      return whitelisted
        ? ok(id, "Agents are confined to whitelisted tools or hosts")
        : fail(id, "Agents may reach any server or tool", "Add createSupplyChainPolicy({ approvedTools }) or networkAllowlist()");
    }
    case "p3-pre-deployment-testing":
      return config.policiesTested
        ? ok(id, "Pre-deployment policy-compliance and tool-calling tests attested")
        : partial(id, "Pre-deployment testing not attested", "Run fleetDryRun() against representative scenarios and set policiesTested");
    case "p3-continuous-monitoring": {
      const events = await governance.audit.count();
      if (events > 0 && scored.length > 0) return ok(id, `${events} audit event(s) recorded and ${scored.length} agent(s) carry live scores`);
      if (events > 0) return partial(id, "Audit trail active but no agent carries a live score", "Score agents so behavioural drift is visible");
      return fail(id, "Agent behaviour is not being logged post-deployment", "Route actions through gov.enforce() so every step is recorded");
    }
    case "p3-termination":
      return hasKillSwitch
        ? ok(id, "Kill switch registered (priority 999) — an agent can be terminated in real time")
        : fail(id, "No kill-switch rule registered — a compromised agent cannot be terminated via enforce()", "Register createKillSwitch(gov)");

    // ─── 2.4 Enable end-user responsibility ───
    case "p4-capability-disclosure": {
      if (agents.length === 0) return fail(id, "No agents registered — no capabilities to disclose", "Register agents with a description and tools list");
      const disclosed = agents.filter((a) => a.description && a.tools && a.tools.length > 0);
      if (disclosed.length === agents.length) return ok(id, `${agents.length} agent(s) have a documented description and tool set to disclose`);
      return partial(id, `${disclosed.length}/${agents.length} agents document both description and tools`, "Add a description and tools list to every agent registration");
    }
    case "p4-escalation-contact": {
      if (agents.length === 0) return fail(id, "No agents registered", "Register agents with an owner as the escalation contact");
      if (allOwned) return ok(id, `${agents.length} agent(s) have an owner to escalate to`);
      return partial(id, `${owned.length}/${agents.length} agents have an owner`, "Set an owner on every agent registration");
    }
    case "p4-user-education":
      return config.usersTrained
        ? ok(id, "User training on agent use and oversight attested")
        : external(id, "Not assessed — training is a people process the SDK cannot observe", "Train users on the agent's range of actions and failure modes, then set usersTrained");

    default:
      return external(id, "Unknown requirement");
  }
}
