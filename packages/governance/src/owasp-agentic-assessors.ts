/**
 * OWASP Top 10 for Agentic Applications 2026 — per-requirement assessors.
 *
 * Each case maps one `asiNN-*` requirement (owasp-agentic-articles.ts) to the
 * governance state it can be checked against: policy rules, audit counts,
 * registered agents, and the explicit config flags. Called from
 * owasp-agentic.ts.
 */

import type { RequirementAssessment } from "./compliance-articles.js";
import type { OwaspAssessmentConfig } from "./owasp-agentic-types.js";

/** Condition types that scan content for prompt injection. */
const INJECTION_CONDITIONS: ReadonlySet<string> = new Set(["injection_guard", "ml_injection_guard"]);
/** Condition types that filter sensitive data / output patterns. */
const OUTPUT_CONDITIONS: ReadonlySet<string> = new Set(["sensitive_data_filter", "output_pattern"]);

export async function assessOwaspRequirement(
  id: string,
  config: OwaspAssessmentConfig,
): Promise<RequirementAssessment> {
  const { governance, agents } = config;
  const rules = governance.policies.getRules();
  const hasInjectionRule = rules.some((r) => INJECTION_CONDITIONS.has(r.condition.type));
  const hasOutputRule = rules.some((r) => OUTPUT_CONDITIONS.has(r.condition.type));
  const scored = agents.filter((a) => a.compositeScore > 0);

  switch (id) {
    // ASI01: Agent Goal Hijack (legacy AA-05)
    case "asi01-injection-detection": {
      if (hasInjectionRule) return ok(id, "Injection guard policy configured (64+ patterns, 7 categories)");
      if (config.injectionDetection) return ok(id, "Injection detection confirmed");
      return fail(id, "No injection detection configured", "Add createInjectionGuard() to scan inputs for prompt injection");
    }
    case "asi01-cross-field-scan": {
      if (hasInjectionRule) return ok(id, "Injection guard includes cross-field recursive scanning");
      return partial(id, "Cross-field scanning not active without injection guard", "Enable createInjectionGuard() for automatic cross-field scanning");
    }

    // ASI02: Tool Misuse & Exploitation (legacy AA-01 tool surface, AA-03 tool I/O)
    case "asi02-tool-restriction": {
      const hasToolPolicy = rules.some((r) => r.condition.type === "tool_blocked" || r.condition.type === "tool_allowed");
      if (hasToolPolicy) return ok(id, "Tool restriction policies configured");
      return fail(id, "No tool restriction policies", "Add blockTools() or allowOnlyTools() to restrict agent tool access");
    }
    case "asi02-tool-io-validation": {
      if (hasInjectionRule && hasOutputRule) return ok(id, "Input injection detection and output filtering active");
      if (hasInjectionRule || hasOutputRule) return partial(id, "Partial input/output validation", "Add both injection_guard and sensitiveDataFilter() policies");
      return fail(id, "No tool input/output validation", "Add createInjectionGuard() and sensitiveDataFilter() policies");
    }

    // ASI03: Identity & Privilege Abuse (legacy AA-01 governance level)
    case "asi03-governance-level": {
      const hasLevelPolicy = rules.some((r) => r.condition.type === "agent_level");
      if (hasLevelPolicy && agents.every((a) => a.compositeScore > 0)) return ok(id, "Governance levels enforced with scored agents");
      if (scored.length > 0) return partial(id, "Agents scored but no level enforcement policy");
      return fail(id, "No governance level enforcement", "Add requireLevel() and score agents via gov.register()");
    }
    case "asi03-agent-authentication": {
      if (agents.length === 0) return fail(id, "No agents registered", "Register agents with metadata.hasAuth or issue Ed25519 identity tokens");
      const authed = agents.filter((a) => a.metadata?.["hasAuth"] === true);
      if (authed.length === agents.length) return ok(id, `${agents.length} agent(s) declare an authentication mechanism`);
      if (authed.length > 0) return partial(id, `${authed.length}/${agents.length} agents declare authentication`, "Set metadata.hasAuth on every agent registration");
      return fail(id, "No agent declares an authentication mechanism", "Set metadata.hasAuth: true or use createEd25519Identity() for signed agent identity");
    }

    // ASI04: Agentic Supply Chain Vulnerabilities (legacy AA-03)
    case "asi04-tool-inventory": {
      if (agents.length === 0) return fail(id, "No agents registered", "Register agents with tools list via gov.register()");
      const withTools = agents.filter((a) => a.tools && a.tools.length > 0);
      if (withTools.length === agents.length) return ok(id, `${agents.length} agent(s) have documented tool inventory`);
      return partial(id, `${withTools.length}/${agents.length} agents have tools documented`);
    }
    case "asi04-approved-tool-registry": {
      if (rules.some((r) => r.id.startsWith("supply-chain"))) return ok(id, "Supply-chain approved-tool policy registered");
      return partial(id, "No approved-tool registry policy", "Add createSupplyChainPolicy({ approvedTools }) to block unapproved tools");
    }

    // ASI05: Unexpected Code Execution (RCE) (legacy AA-06)
    case "asi05-action-enforcement": {
      const enforced = await governance.audit.count({ outcome: "block" });
      if (enforced > 0) return ok(id, `Before-action enforcement active — ${enforced} action(s) blocked`);
      if (rules.length > 0) return partial(id, "Policies configured but no actions blocked yet");
      return fail(id, "No before-action enforcement", "Integrate gov.enforce() into your agent pipeline");
    }
    case "asi05-scope-boundaries": {
      const hasScope = rules.some((r) => r.condition.type === "scope_boundary" || r.condition.type === "network_allowlist");
      if (hasScope) return ok(id, "Scope boundary or network allowlist configured");
      return partial(id, "No explicit scope boundaries", "Add scopeBoundary() or networkAllowlist() for path/domain restrictions");
    }

    // ASI06: Memory & Context Poisoning (legacy AA-04)
    case "asi06-tool-result-scan": {
      const atToolResult = rules.some(
        (r) => r.stage === "tool_result" && (INJECTION_CONDITIONS.has(r.condition.type) || OUTPUT_CONDITIONS.has(r.condition.type)),
      );
      if (atToolResult) return ok(id, "Tool results are scanned at the tool_result stage before entering context");
      if (hasInjectionRule || config.injectionDetection) return partial(id, "Injection scanning active but not at the tool_result stage", "Run scanToolResult() / the Mastra processToolResult hook so tool outputs are scanned before they reach the model");
      return fail(id, "Tool results enter the model context unscanned", "Add createInjectionGuard() and wire scanToolResult() into your tool adapter");
    }
    case "asi06-output-filtering": {
      if (rules.some((r) => r.condition.type === "sensitive_data_filter")) return ok(id, "Sensitive data output filtering configured");
      if (config.outputFiltering) return ok(id, "Output filtering confirmed");
      return fail(id, "No output filtering for sensitive data", "Add sensitiveDataFilter() to scan outputs for credentials and PII");
    }

    // ASI07: Insecure Inter-Agent Communication (legacy AA-09)
    case "asi07-agent-identity": {
      if (agents.length === 0) return fail(id, "No agents registered", "Register agents with identity metadata");
      if (scored.length === agents.length) return ok(id, `${agents.length} agent(s) registered with identity scoring`);
      return partial(id, `${scored.length}/${agents.length} agents have identity scores`);
    }
    case "asi07-communication-policy":
      return config.a2aGovernance
        ? ok(id, "Inter-agent communication governed via A2A adapter")
        : partial(id, "No inter-agent governance configured", "Use the A2A governance adapter for agent-to-agent communication");

    // ASI08: Cascading Failures (legacy AA-02, AA-08 observability)
    case "asi08-token-budget": {
      if (rules.some((r) => r.condition.type === "token_limit")) return ok(id, "Token budget policy configured");
      return fail(id, "No token budget configured", "Add tokenBudget() to limit per-session token consumption");
    }
    case "asi08-rate-limiting": {
      if (rules.some((r) => r.condition.type === "rate_limit")) return ok(id, "Rate limiting policy configured");
      return fail(id, "No rate limiting configured", "Add rateLimit() to throttle agent actions");
    }
    case "asi08-audit-observability": {
      const count = await governance.audit.count();
      if (count > 0) return ok(id, `Comprehensive audit trail with ${count} event(s)`);
      return fail(id, "No audit events recorded", "Enable audit logging via gov.enforce() or gov.audit.log()");
    }

    // ASI09: Human-Agent Trust Exploitation (legacy AA-07)
    case "asi09-human-oversight": {
      if (rules.some((r) => r.outcome === "require_approval")) return ok(id, "Human approval required for sensitive operations");
      return fail(id, "No human-in-the-loop policy", "Add requireApproval() for high-stakes agent actions");
    }
    case "asi09-output-validation": {
      if (rules.some((r) => r.stage === "postprocess")) return ok(id, "Postprocess output validation configured");
      return partial(id, "No postprocess output validation", "Add outputPattern() or outputLength() policies for output scanning");
    }

    // ASI10: Rogue Agents (legacy AA-10, AA-08 tamper evidence)
    case "asi10-kill-switch": {
      // Only a registered kill-switch rule actually blocks enforce() calls;
      // a storage-only quarantine (status update) is not sufficient.
      if (rules.some((r) => r.id.startsWith("__kill_switch__")))
        return ok(id, "Kill switch active (priority 999 reserved rule); user rules are clamped to 998");
      return fail(id, "No kill-switch rule registered — agents cannot be halted via enforce()", "Create a kill switch with createKillSwitch(gov) so rogue agents can be instantly blocked");
    }
    case "asi10-behavioral-scoring": {
      if (agents.length === 0) return fail(id, "No agents registered for behavioral monitoring", "Register agents to enable behavioral scoring");
      if (scored.length === agents.length) return ok(id, `${agents.length} agent(s) scored with behavioral drift tracking`);
      return partial(id, `${scored.length}/${agents.length} agents scored`, "Score all agents via gov.register() or gov.score()");
    }
    case "asi10-tamper-evident-audit":
      return config.auditIntegrity
        ? ok(id, "HMAC-SHA256 tamper-evident audit logging enabled")
        : partial(id, "Audit logs not tamper-evident", "Enable createIntegrityAudit() for hash-chained logging");

    default:
      return { requirementId: id, status: "not-applicable", evidence: "Unknown requirement" };
  }
}

// ─── Helpers ─────────────────────────────────────────────────

function ok(id: string, evidence: string): RequirementAssessment {
  return { requirementId: id, status: "compliant", evidence };
}
function partial(id: string, evidence: string, remediation?: string): RequirementAssessment {
  return { requirementId: id, status: "partial", evidence, remediation };
}
function fail(id: string, evidence: string, remediation?: string): RequirementAssessment {
  return { requirementId: id, status: "non-compliant", evidence, remediation };
}
