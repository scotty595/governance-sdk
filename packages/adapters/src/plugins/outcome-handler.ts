/**
 * Shared outcome handler for all framework adapters.
 *
 * Handles all 5 enforcement outcomes (allow, block, warn, require_approval, mask)
 * so individual adapters don't need to duplicate this logic.
 */

import type { EnforcementDecision } from "@governance-sdk/core/policy.js";

// ─── Error Types ──────────────────────────────────────────────

/** Thrown when a tool call is blocked by governance policy. */
export class GovernanceBlockedError extends Error {
  public readonly decision: EnforcementDecision;
  public readonly toolName: string;

  constructor(decision: EnforcementDecision, toolName: string) {
    super(`Governance blocked ${toolName}: ${decision.reason}`);
    this.name = "GovernanceBlockedError";
    this.decision = decision;
    this.toolName = toolName;
  }
}

/** Thrown when a tool call requires human approval before proceeding. */
export class GovernanceApprovalRequiredError extends Error {
  public readonly decision: EnforcementDecision;
  public readonly toolName: string;
  public readonly approvalId: string;
  public readonly pollUrl: string;

  constructor(decision: EnforcementDecision, toolName: string) {
    super(`Governance requires approval for ${toolName}: ${decision.reason}`);
    this.name = "GovernanceApprovalRequiredError";
    this.decision = decision;
    this.toolName = toolName;
    this.approvalId = decision.approvalId ?? "";
    this.pollUrl = decision.approval?.pollUrl ?? "";
  }
}

// ─── Outcome Callbacks ────────────────────────────────────────

export interface OutcomeCallbacks {
  onDecision?: (decision: EnforcementDecision, toolName: string) => void;
  onBlocked?: (decision: EnforcementDecision, toolName: string) => void;
  onWarn?: (decision: EnforcementDecision, toolName: string) => void;
  onMask?: (decision: EnforcementDecision, toolName: string, maskedText: string) => void;
  onApprovalRequired?: (decision: EnforcementDecision, toolName: string) => void;
}

// ─── Outcome Handler ──────────────────────────────────────────

/**
 * Handle an enforcement decision with proper outcome-specific behavior.
 *
 * - `allow`: No action, returns decision.
 * - `warn`: Calls onWarn callback, returns decision (does NOT block).
 * - `mask`: Calls onMask callback with maskedText, returns decision.
 * - `require_approval`: Throws GovernanceApprovalRequiredError.
 * - `block`: Throws GovernanceBlockedError.
 *
 * Always calls onDecision for every outcome.
 */
/**
 * Fire the callback each outcome owns and say which refusal, if any, the
 * decision is. `handleOutcome` turns the refusal into a throw;
 * `notifyOutcome` hands it back as a decision. One place decides which
 * callback fires for which outcome.
 */
function dispatch(
  decision: EnforcementDecision,
  toolName: string,
  callbacks: OutcomeCallbacks,
): "block" | "require_approval" | undefined {
  callbacks.onDecision?.(decision, toolName);

  switch (decision.outcome) {
    case "warn":
      callbacks.onWarn?.(decision, toolName);
      return undefined;

    case "mask":
      if (decision.maskedText) {
        callbacks.onMask?.(decision, toolName, decision.maskedText);
      }
      return undefined;

    case "require_approval":
      callbacks.onApprovalRequired?.(decision, toolName);
      return "require_approval";

    case "block":
      callbacks.onBlocked?.(decision, toolName);
      return "block";

    default:
      // "allow" or unknown — pass through
      if (decision.blocked) {
        callbacks.onBlocked?.(decision, toolName);
        return "block";
      }
      return undefined;
  }
}

export function handleOutcome(
  decision: EnforcementDecision,
  toolName: string,
  callbacks: OutcomeCallbacks,
): EnforcementDecision {
  const refusal = dispatch(decision, toolName, callbacks);
  if (refusal === "require_approval") throw new GovernanceApprovalRequiredError(decision, toolName);
  if (refusal === "block") throw new GovernanceBlockedError(decision, toolName);
  return decision;
}

/**
 * The same callbacks `handleOutcome` fires, with the decision returned
 * instead of thrown on block and require_approval — for frameworks that want
 * a verdict handed back rather than an exception raised (Claude's
 * `canUseTool`, the Agent Hooks contract).
 */
export function notifyOutcome(
  decision: EnforcementDecision,
  toolName: string,
  callbacks: OutcomeCallbacks,
): EnforcementDecision {
  dispatch(decision, toolName, callbacks);
  return decision;
}
