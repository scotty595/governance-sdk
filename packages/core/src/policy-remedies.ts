/**
 * Remedy hints — one line telling a developer how to make a blocked call
 * pass, attached to every non-allow decision as `decision.remedy`.
 *
 * Developers turn off guardrails they cannot debug. A decision that names
 * the stage, the condition that matched, and the change that would allow
 * the call is the difference between "governance got in my way" and
 * "governance told me exactly what to do." Hints are deliberately short and
 * never include user content.
 */

import type { EnforcementContext, PolicyRule } from "./policy.js";

function list(v: unknown, max = 4): string {
  if (!Array.isArray(v)) return "";
  const items = v.filter((x): x is string => typeof x === "string");
  const head = items.slice(0, max).join(", ");
  return items.length > max ? `${head}, …` : head;
}

/**
 * Describe how to satisfy `rule` for the call described by `ctx`. Returns
 * `undefined` for outcomes that need no remedy (`allow`) or when the
 * condition type is unknown to this table (custom conditions).
 */
export function describeRemedy(rule: PolicyRule, ctx: EnforcementContext): string | undefined {
  if (rule.outcome === "allow") return undefined;
  const { type, params } = rule.condition;
  const p = (params ?? {}) as Record<string, unknown>;
  const tool = ctx.tool ?? "this tool";
  const disable = `or disable rule "${rule.id}"`;

  switch (type) {
    case "tool_blocked":
      return `Remove "${tool}" from the blocked list (${list(p.tools)}) ${disable}.`;
    case "tool_allowed":
      return `Add "${tool}" to the allow-list (${list(p.tools)}) ${disable}.`;
    case "tool_match":
      return rule.outcome === "require_approval"
        ? `"${tool}" requires human approval — approve the request, or remove it from the approval list (${list(p.tools)}).`
        : `Remove "${tool}" from the match list (${list(p.tools)}) ${disable}.`;
    case "action_type":
      return `Action "${ctx.action}" is gated (${list(p.actions)}) — approve it, or remove the action type from the rule.`;
    case "action_tier":
      return `Action tier "${ctx.actionTier ?? "unset"}" is gated (${list(p.tiers)}) — approve it, or map "${tool}" to a lower tier.`;
    case "tainted_input":
      return `"${tool}" received arguments derived from untrusted content (${list(ctx.taint?.map((t) => t.source))}) — approve, or run it before ingesting external content.`;
    case "agent_level":
      return `Agent level ${ctx.agentLevel ?? 0} is below the required L${String(p.minLevel)} — raise the agent's governance score (auth, guardrails, observability, audit) or lower the requirement.`;
    case "require_signed_identity":
      return ctx.identityVerified === true
        ? `"${tool}" is not in the agent's signed capability set — add it to the certificate or set enforceCapabilityBinding: false.`
        : `Present a verified Ed25519 identity: the host must call verifyAgentIdentity() and set ctx.identityVerified before enforce().`;
    case "tool_sequence":
      return `Call ${list(p.requiredPrior)} before "${tool}" in this session.`;
    case "token_limit":
      return `Session tokens exceed ${String(p.maxTokens)} — start a new session or raise the budget.`;
    case "rate_limit":
      return `More than ${String(p.maxActions)} actions in the window — wait, or raise the limit.`;
    case "cost_budget":
      return `Session cost exceeds ${String(p.maxCost)} — start a new session or raise the budget.`;
    case "concurrent_limit":
      return `More than ${String(p.maxConcurrent)} concurrent tool executions — wait for one to finish.`;
    case "time_window":
      return `Outside the allowed hours — retry within the window or widen it.`;
    case "network_allowlist":
      return `Target domain is not allow-listed (${list(p.allowedDomains)}) — add it to the rule.`;
    case "scope_boundary":
      return `Target path is outside the allowed scope — move the resource or extend allowedPaths.`;
    case "injection_guard":
    case "ml_injection_guard":
      return `Content scored as prompt injection — inspect the input; if benign, raise the threshold or add the phrase to a benign corpus test before lowering sensitivity.`;
    case "blocklist":
      return `Content contains a blocked term (${list(p.terms)}) — rephrase, or remove the term from the rule.`;
    case "input_length":
    case "output_length":
      return `Content exceeds the configured length — shorten it or raise the limit.`;
    case "input_pattern":
    case "output_pattern":
      return `Content matches the pattern /${String(p.pattern)}/ — change the content or the pattern.`;
    case "sensitive_data_filter":
      return rule.outcome === "mask"
        ? `Sensitive data was redacted — no action needed unless a false positive; then narrow params.patterns.`
        : `Content contains sensitive data — redact it, or switch the rule outcome to "mask".`;
    case "data_classification":
      return `Input references classified data (${list(p.blocked)}) — remove it or update the classification list.`;
    case "require_signed_action":
      return `Include a signature in metadata.signature.`;
    default:
      return undefined;
  }
}
