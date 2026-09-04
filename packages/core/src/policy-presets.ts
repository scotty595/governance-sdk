/**
 * Policy Preset Builders
 *
 * Convenience functions that create common PolicyRule configurations.
 * Separated from the policy engine to keep files under 300 LOC.
 */

import type { ActionTier, PolicyRule, PolicyAction, PolicyOutcome, PolicyStage } from "./policy.js";
import type { TaintSource } from "./taint.js";

/**
 * Block specific tools from being called by any agent.
 *
 * @param tools - Array of tool names to block
 * @param reason - Optional custom reason message
 * @returns A PolicyRule with priority 100 that blocks matching tool_call actions
 *
 * @example
 * ```ts
 * const rule = blockTools(['shell_exec', 'rm_rf', 'database_drop']);
 * ```
 */
export function blockTools(tools: string[], reason?: string): PolicyRule {
  return {
    id: `block-tools-${tools.join("-")}`,
    name: `Block tools: ${tools.join(", ")}`,
    condition: { type: "tool_blocked", params: { tools } },
    outcome: "block",
    reason: reason ?? `Tool is on the blocked list: ${tools.join(", ")}`,
    priority: 100,
    enabled: true,
    stage: "process",
  };
}

/**
 * Only allow specific tools — block everything not on the list.
 *
 * @param tools - Array of tool names to allow (all others blocked)
 * @param reason - Optional custom reason message
 * @returns A PolicyRule with priority 90 that blocks unlisted tools
 *
 * @example
 * ```ts
 * const rule = allowOnlyTools(['web_search', 'email_read']);
 * ```
 */
export function allowOnlyTools(tools: string[], reason?: string): PolicyRule {
  return {
    id: `allow-only-tools`,
    name: `Allow only: ${tools.join(", ")}`,
    condition: { type: "tool_allowed", params: { tools } },
    outcome: "block",
    reason: reason ?? `Tool is not on the approved list`,
    priority: 90,
    enabled: true,
    stage: "process",
  };
}

/**
 * Require human approval for specific action types.
 * Uses the action_type condition with a require_approval outcome.
 *
 * @param actions - Action types that need human review (e.g., "payment", "external_request")
 * @param reason - Optional custom reason message
 * @returns A PolicyRule with outcome "require_approval"
 *
 * @example
 * ```ts
 * const rule = requireApproval(['payment', 'database_mutation']);
 * ```
 */
export function requireApproval(actions: PolicyAction[], reason?: string): PolicyRule {
  return {
    id: `require-approval-${actions.join("-")}`,
    name: `Require approval: ${actions.join(", ")}`,
    condition: { type: "action_type", params: { actions } },
    outcome: "require_approval",
    reason: reason ?? `Action requires human approval: ${actions.join(", ")}`,
    priority: 80,
    enabled: true,
    stage: "process",
  };
}

/**
 * Require human approval for specific tools, matched by name against the
 * runtime `ctx.tool` field. Use this — not `requireApproval` — when the
 * approval list is a set of tool names: `requireApproval` gates action
 * *categories* (`ctx.action`, e.g. "payment"), and runtime tool calls
 * always evaluate as `action: "tool_call"` with the tool name in `ctx.tool`.
 *
 * @param tools - Tool names that need human review before execution
 * @param reason - Optional custom reason message
 * @returns A PolicyRule with outcome "require_approval"
 *
 * @example
 * ```ts
 * const rule = requireToolApproval(['linear_create_task_task', 'send_email']);
 * ```
 */
export function requireToolApproval(tools: string[], reason?: string): PolicyRule {
  return {
    id: `require-tool-approval-${tools.join("-")}`,
    name: `Require approval for tools: ${tools.join(", ")}`,
    condition: { type: "tool_match", params: { tools } },
    outcome: "require_approval",
    reason: reason ?? `Tool requires human approval: ${tools.join(", ")}`,
    priority: 80,
    enabled: true,
    stage: "process",
  };
}

/**
 * Enforce a per-session token budget. Blocks when sessionTokensUsed exceeds maxTokens.
 *
 * @param maxTokens - Maximum tokens allowed per session
 * @returns A PolicyRule with priority 70 that blocks over-budget actions
 */
export function tokenBudget(maxTokens: number): PolicyRule {
  return {
    id: `token-budget-${maxTokens}`,
    name: `Token budget: ${maxTokens.toLocaleString()}`,
    condition: { type: "token_limit", params: { maxTokens } },
    outcome: "block",
    reason: `Session token budget exceeded (${maxTokens.toLocaleString()} max)`,
    priority: 70,
    enabled: true,
    stage: "process",
  };
}

/**
 * Rate-limit agent actions within a time window.
 *
 * In local mode `createGovernance()` keeps a per-process session ledger of
 * allowed actions and fills `ctx.recentActionTimestamps` before evaluation,
 * so this rule counts the actions in the last `windowMs` and blocks the
 * (maxActions+1)-th. No host wiring required for single-process
 * correctness.
 *
 * For a fleet-wide limit across replicas, keep a shared counter in your API
 * layer (Redis INCR, a rate-limit service) and set `ctx.recentActionCount`
 * (or `recentActionTimestamps`) yourself — host-supplied values always take
 * precedence over the ledger. Hosted mode never consults the ledger; the
 * remote API owns the count.
 *
 * @param maxActions - Maximum actions allowed in the window
 * @param windowMs - Window duration in milliseconds
 * @returns A PolicyRule with priority 60
 */
export function rateLimit(maxActions: number, windowMs: number): PolicyRule {
  return {
    id: `rate-limit-${maxActions}-${windowMs}`,
    name: `Rate limit: ${maxActions} per ${windowMs}ms`,
    condition: { type: "rate_limit", params: { maxActions, windowMs } },
    outcome: "block",
    reason: `Rate limit exceeded (${maxActions} actions per ${windowMs / 1000}s window)`,
    priority: 60,
    enabled: true,
    stage: "process",
  };
}

/**
 * Require a minimum governance level (0-4) for the agent to operate.
 *
 * @param minLevel - Minimum governance level (0=Unregistered, 4=Certified)
 * @returns A PolicyRule with priority 95 that blocks under-level agents
 */
export function requireLevel(minLevel: number): PolicyRule {
  return {
    id: `require-level-${minLevel}`,
    name: `Require governance level ${minLevel}+`,
    condition: { type: "agent_level", params: { minLevel } },
    outcome: "block",
    reason: `Agent governance level below required minimum (L${minLevel})`,
    priority: 95,
    enabled: true,
    stage: "process",
  };
}

/**
 * Require a cryptographically signed Ed25519 identity on every matching
 * action. The host (API layer) must verify the signature against its cert
 * vault BEFORE calling enforce() and set `ctx.identityVerified` and
 * `ctx.identityCapabilityMatch` accordingly.
 *
 * This is the one-click "agents must prove who they are" policy. Pairs with
 * governance-sdk/agent-identity-ed25519 for keygen + cert signing and with
 * a host cert vault for authoritative lookups.
 *
 * @param opts.enforceCapabilityBinding — default true. When on, also blocks
 *   tool calls where the tool is not listed in the verified cert's
 *   capabilities. Set to false for identity-only enforcement.
 */
export function requireSignedIdentity(
  opts: { enforceCapabilityBinding?: boolean; reason?: string } = {},
): PolicyRule {
  const enforceCapabilityBinding = opts.enforceCapabilityBinding !== false;
  return {
    id: "require-signed-identity",
    name: enforceCapabilityBinding
      ? "Require signed identity + capability binding"
      : "Require signed identity",
    condition: {
      type: "require_signed_identity",
      params: { enforceCapabilityBinding },
    },
    outcome: "block",
    reason:
      opts.reason ??
      "Agent did not present a valid signed identity for this action",
    // Priority 950 — just below kill_switch (999) so identity is verified
    // before almost everything else. Unsigned calls fail fast, before
    // wasting cycles on injection detection or resource checks.
    priority: 950,
    enabled: true,
    stage: "process",
  };
}

/**
 * Require a tool to be preceded by other tools in the session.
 * Example: requireSequence("delete_record", ["backup_record"])
 */
export function requireSequence(
  tool: string,
  requiredPrior: string[],
  reason?: string,
): PolicyRule {
  return {
    id: `sequence-${tool}-requires-${requiredPrior.join("-")}`,
    name: `${tool} requires: ${requiredPrior.join(", ")}`,
    condition: { type: "tool_sequence", params: { tool, requiredPrior } },
    outcome: "block",
    reason: reason ?? `${tool} requires prior call to: ${requiredPrior.join(", ")}`,
    priority: 85,
    enabled: true,
    stage: "process",
  };
}

/** Restrict actions to specific hours (24h format, local time) */
export function timeWindow(
  startHour: number,
  endHour: number,
  reason?: string,
): PolicyRule {
  return {
    id: `time-window-${startHour}-${endHour}`,
    name: `Allow ${startHour}:00-${endHour}:00 only`,
    condition: { type: "time_window", params: { allowedHours: { start: startHour, end: endHour } } },
    outcome: "block",
    reason: reason ?? `Action blocked outside allowed hours (${startHour}:00-${endHour}:00)`,
    priority: 50,
    enabled: true,
    stage: "process",
  };
}

/**
 * Block when a caller-supplied ML injection score exceeds the threshold.
 *
 * The policy engine is synchronous by design (zero-dep, no hidden I/O), so
 * async ML classifiers cannot run inside `enforce()` directly. Pattern:
 *
 *   1. Your host wrapper runs an ML classifier (e.g. `hybridDetect()` from
 *      `governance-sdk/injection-classifier`, or a Groq/Prompt-Guard-2 call).
 *   2. Host sets `ctx.mlInjectionScore` and optionally `ctx.mlInjectionCategories`.
 *   3. Host calls `gov.enforce(ctx)` — this preset reads the score and
 *      blocks when it meets or exceeds `threshold`.
 *
 * Pair with `createInjectionGuard()` (the built-in regex detector) for
 * defence in depth. Regex catches known syntactic attacks with low FPR;
 * ML catches the rest.
 *
 * Stage defaults to `preprocess` (the user prompt). For tool returns use
 * `toolResultInjectionGuard()` — or pass `stage: "tool_result"` here.
 */
export function mlInjectionGuard(opts: {
  threshold?: number;
  requireCategory?: string;
  reason?: string;
  id?: string;
  stage?: PolicyStage;
} = {}): PolicyRule {
  const threshold = opts.threshold ?? 0.5;
  return {
    id: opts.id ?? "ml-injection-guard",
    name: `ML injection guard (threshold ${threshold})`,
    condition: {
      type: "ml_injection_guard",
      params: {
        threshold,
        ...(opts.requireCategory !== undefined ? { requireCategory: opts.requireCategory } : {}),
      },
    },
    outcome: "block",
    reason:
      opts.reason ??
      "Classifier flagged input as injection (ctx.injectionScore over threshold)",
    priority: 130, // between tool allowlist (90) and requireSignedIdentity (950)
    enabled: true,
    stage: opts.stage ?? "preprocess",
  };
}

/**
 * Block tool RETURNS that score as prompt injection, at the `tool_result`
 * stage. `scanToolResult()` (used by every adapter that sees tool returns)
 * runs the built-in detector on the returned content and sets
 * `ctx.injectionScore`; this rule turns that signal into a decision.
 *
 * Until this preset existed, "tool results are scanned by default" was true
 * and "and enforced against something" was not — no shipped preset produced
 * a `tool_result`-stage rule. Add this one and blocked returns are replaced
 * with `{ blocked, reason, ruleId }` before the LLM sees them.
 *
 * @param opts.threshold - Score (0–1) at or above which to block. Default 0.5.
 * @param opts.outcome - `block` (default) or `require_approval`.
 */
export function toolResultInjectionGuard(opts: {
  threshold?: number;
  outcome?: Extract<PolicyOutcome, "block" | "require_approval">;
  reason?: string;
  id?: string;
} = {}): PolicyRule {
  const threshold = opts.threshold ?? 0.5;
  return {
    id: opts.id ?? "tool-result-injection-guard",
    name: `Tool-result injection guard (threshold ${threshold})`,
    condition: { type: "ml_injection_guard", params: { threshold } },
    outcome: opts.outcome ?? "block",
    reason: opts.reason ?? "Tool returned content that scored as prompt injection",
    priority: 130,
    enabled: true,
    stage: "tool_result",
  };
}

/**
 * Require human approval for actions in the given consequence tiers.
 * Adapters set `ctx.actionTier` from their tool → tier map (for example the
 * Mastra processor's `toolTiers` option); unmapped tools never match.
 *
 * The tiering itself follows what regulators now ask for: read-only actions
 * run, reversible ones run and are logged, external-facing ones may need a
 * person, irreversible ones always do.
 *
 * @example
 * ```ts
 * requireTierApproval(['external', 'irreversible'])
 * ```
 */
export function requireTierApproval(tiers: ActionTier[], reason?: string): PolicyRule {
  return {
    id: `require-tier-approval-${tiers.join("-")}`,
    name: `Require approval for ${tiers.join(", ")} actions`,
    condition: { type: "action_tier", params: { tiers } },
    outcome: "require_approval",
    reason: reason ?? `Action tier requires human approval: ${tiers.join(", ")}`,
    priority: 82,
    enabled: true,
    stage: "process",
  };
}

/**
 * Gate consequential tools once the session has ingested untrusted content.
 *
 * This is the architectural control the prompt-injection literature asks
 * for: after an agent reads a web page, a file, an MCP tool description or
 * another agent's message, arguments it passes to `send_email` or
 * `shell_exec` may be attacker-derived. Detection alone cannot prove they
 * are not. This rule matches when any taint mark (optionally filtered by
 * source, or to detector-flagged content only) is present on the context
 * and the tool is in `tools`.
 *
 * Default outcome is `require_approval` — the human sees what the agent
 * wants to do with external content before it happens. Use `block` for
 * tools that must never run on tainted input.
 *
 * @example
 * ```ts
 * blockTaintedTools(['send_email', 'shell_exec', 'transfer_funds'])
 * blockTaintedTools(['shell_exec'], { outcome: 'block', suspiciousOnly: true })
 * ```
 */
export function blockTaintedTools(
  tools: string[],
  opts: {
    sources?: TaintSource[];
    suspiciousOnly?: boolean;
    outcome?: Extract<PolicyOutcome, "block" | "require_approval">;
    reason?: string;
  } = {},
): PolicyRule {
  return {
    id: `tainted-tools-${tools.join("-")}`,
    name: `Guard ${tools.join(", ")} against tainted input`,
    condition: {
      type: "tainted_input",
      params: {
        tools,
        ...(opts.sources ? { sources: opts.sources } : {}),
        ...(opts.suspiciousOnly ? { suspiciousOnly: true } : {}),
      },
    },
    outcome: opts.outcome ?? "require_approval",
    reason:
      opts.reason ??
      `Tool received arguments after the session ingested untrusted content: ${tools.join(", ")}`,
    priority: 88,
    enabled: true,
    stage: "process",
  };
}
