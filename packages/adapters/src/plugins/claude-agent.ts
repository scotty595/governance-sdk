/**
 * governance-sdk — Claude Agent SDK adapter
 *
 * Governs an `@anthropic-ai/claude-agent-sdk` run through the two seams the
 * SDK gives a host: the `canUseTool` permission callback and the `PreToolUse`
 * / `PostToolUse` hooks. Both answer with a verdict rather than by throwing,
 * which is the one thing that makes this adapter shaped differently from the
 * tool-wrapping ones — the decision itself comes from the same adapter kernel,
 * over the same assembled context, so a policy that blocks a tool here blocks
 * it identically on Mastra, Vercel or MCP.
 *
 * Stage mapping:
 *
 *   | SDK seam            | Stage         | Kernel call                     |
 *   |---------------------|---------------|---------------------------------|
 *   | `canUseTool`        | `process`     | `core.decide()`                  |
 *   | `PreToolUse` hook   | `process`     | `core.decide()`                  |
 *   | `PostToolUse` hook  | `tool_result` | `core.scanResult()`              |
 *   | `preprocess(text)`  | `preprocess`  | `core.preprocess()`              |
 *   | `postprocess(text)` | `postprocess` | `core.postprocess()`             |
 *
 * The SDK has no prompt or final-output hook this adapter is confident enough
 * to wire (see `claude-agent-types.ts` on what is and is not verified), so the
 * two text stages are exposed as plain functions for the host to call where it
 * owns the prompt and the final answer.
 *
 * `canUseTool` and `PreToolUse` are two routes to the same `process`-stage
 * decision, and the SDK consults them independently — `canUseTool` for tools
 * that need permission, the hook for every tool call. A host that wires both
 * therefore gets two evaluations, and so two `policy_evaluation` audit events,
 * for one call. That is the SDK's shape, not a defect here; wire whichever
 * single seam covers the tools you care about if the duplication matters.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { createClaudeAgentGovernance } from 'governance-sdk/plugins/claude-agent';
 * import { query } from '@anthropic-ai/claude-agent-sdk';
 *
 * const gov = createGovernance({ rules: [blockTools(['Bash'])] });
 * const governed = await createClaudeAgentGovernance(gov, {
 *   agentName: 'research-agent',
 *   owner: 'research-team',
 * });
 *
 * for await (const message of query({
 *   prompt: 'summarise the repo',
 *   options: { canUseTool: governed.canUseTool, hooks: governed.hooks },
 * })) { ... }
 * ```
 */

import type { AuditEvent, GovernanceInstance } from "@governance-sdk/core";
import type { EnforcementDecision } from "@governance-sdk/core/policy.js";
import { createAdapterCore } from "./adapter-core.js";
import type {
  ClaudeAgentGovernanceConfig,
  ClaudeAgentGovernanceResult,
  ClaudeAgentHookOutput,
  ClaudeAgentPostToolUseInput,
  ClaudeAgentPreToolUseInput,
  ClaudeAgentToolInput,
  GovernedPermissionResult,
} from "./claude-agent-types.js";

export type {
  ClaudeAgentCallbackOptions,
  ClaudeAgentCanUseTool,
  ClaudeAgentGovernanceConfig,
  ClaudeAgentGovernanceResult,
  ClaudeAgentHookCallback,
  ClaudeAgentHookInputBase,
  ClaudeAgentHookMatcher,
  ClaudeAgentHookOutput,
  ClaudeAgentHooks,
  ClaudeAgentPermissionAllow,
  ClaudeAgentPermissionDeny,
  ClaudeAgentPermissionResult,
  ClaudeAgentPostToolUseInput,
  ClaudeAgentPreToolUseInput,
  ClaudeAgentToolInput,
  GovernedPermissionResult,
} from "./claude-agent-types.js";

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

/**
 * Keys a tool's arguments conventionally use for governable text, most
 * specific first. The winner becomes `ctx.inputText`, which is what content
 * rules scan and what a `mask` outcome rewrites.
 */
const DEFAULT_TEXT_FIELDS: readonly string[] = [
  "message", "prompt", "text", "content", "command", "query",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** First configured key holding a non-empty string, with its value. */
function findText(
  input: ClaudeAgentToolInput,
  fields: readonly string[],
): { key: string; value: string } | undefined {
  for (const key of fields) {
    const value = input[key];
    if (typeof value === "string" && value.length > 0) return { key, value };
  }
  return undefined;
}

/** The engine refused outright, or wants a human before the call proceeds. */
function refused(decision: EnforcementDecision): boolean {
  return decision.blocked || decision.outcome === "block" || decision.outcome === "require_approval";
}

/**
 * Register the agent and return the governance surface for a Claude Agent SDK
 * run: a `canUseTool` callback, the `PreToolUse` / `PostToolUse` hooks, and
 * the shared adapter kernel behind them.
 */
export async function createClaudeAgentGovernance(
  governance: GovernanceInstance,
  config: ClaudeAgentGovernanceConfig,
): Promise<ClaudeAgentGovernanceResult> {
  const core = await createAdapterCore(governance, config, {
    ...(config.tools ? { tools: config.tools } : {}),
    // The SDK is Anthropic's; `framework` in the config still wins.
    framework: "anthropic",
    callbacks: config,
  });
  const textFields = config.inputTextFields ?? DEFAULT_TEXT_FIELDS;
  const denyMessage = config.denyMessage
    ?? ((decision: EnforcementDecision) =>
      decision.remedy ? `${decision.reason} — ${decision.remedy}` : decision.reason);

  /** One `process`-stage decision, with the callbacks fired but not thrown. */
  async function decide(
    toolName: string,
    input: ClaudeAgentToolInput,
  ): Promise<{ decision: EnforcementDecision; textKey?: string }> {
    const found = findText(input, textFields);
    const decision = await core.decide(toolName, input, found ? { inputText: found.value } : {});
    return { decision, ...(found ? { textKey: found.key } : {}) };
  }

  /**
   * A refusal happens before the tool ever runs, so nothing else audits it —
   * the engine's own `policy_evaluation` event records the decision, this
   * records the attempted call.
   */
  function auditRefusal(toolName: string, decision: EnforcementDecision): Promise<AuditEvent> {
    return core.audit(toolName, "failure", {
      reason: decision.reason,
      ruleId: decision.ruleId,
      outcome: decision.outcome,
      ...(decision.approvalId ? { approvalId: decision.approvalId } : {}),
    });
  }

  async function canUseTool(
    toolName: string,
    input: ClaudeAgentToolInput,
  ): Promise<GovernedPermissionResult> {
    const { decision, textKey } = await decide(toolName, input);
    if (refused(decision)) {
      await auditRefusal(toolName, decision);
      // `require_approval` denies too: the SDK has no "ask a human" verdict,
      // so the host reads `decision.approvalId` / `decision.approval.pollUrl`
      // off the result to run its own approval flow and retry.
      return { behavior: "deny", message: denyMessage(decision, toolName), decision };
    }
    if (decision.outcome === "mask" && decision.maskedText !== undefined && textKey !== undefined) {
      return {
        behavior: "allow",
        updatedInput: { ...input, [textKey]: decision.maskedText },
        decision,
      };
    }
    // A mask with no text field to rewrite cannot be applied here; the engine
    // has already failed a mask it could not compute closed to a block, so
    // what reaches this line is an allow, a warn, or a mask of an argument
    // shape `inputTextFields` does not name.
    return { behavior: "allow", updatedInput: input, decision };
  }

  async function preToolUse(
    input: ClaudeAgentPreToolUseInput,
  ): Promise<ClaudeAgentHookOutput> {
    const args = isRecord(input.tool_input) ? input.tool_input : {};
    const { decision } = await decide(input.tool_name, args);
    if (!refused(decision)) return { continue: true };
    await auditRefusal(input.tool_name, decision);
    const message = denyMessage(decision, input.tool_name);
    // A hook has no verified way to rewrite a tool's arguments, so a `mask`
    // reaching this seam is allowed through unredacted — wire `canUseTool`
    // if your policy masks tool inputs.
    return {
      continue: false,
      decision: "block",
      stopReason: message,
      systemMessage: `[governance] ${input.tool_name}: ${message}`,
    };
  }

  async function postToolUse(
    input: ClaudeAgentPostToolUseInput,
  ): Promise<ClaudeAgentHookOutput> {
    if (config.scanToolResults === false) return { continue: true };
    const args = isRecord(input.tool_input) ? input.tool_input : undefined;
    const scan = await core.scanResult({
      tool: input.tool_name,
      result: input.tool_response,
      ...(args ? { args } : {}),
      ...(config.toolResultInjectionThreshold !== undefined
        ? { injectionThreshold: config.toolResultInjectionThreshold }
        : {}),
    });
    core.notify(scan.decision, input.tool_name);
    if (scan.blocked) {
      await auditRefusal(input.tool_name, scan.decision);
      const message = denyMessage(scan.decision, input.tool_name);
      return {
        continue: false,
        decision: "block",
        stopReason: message,
        systemMessage: `[governance] ${input.tool_name} result withheld: ${message}`,
      };
    }
    await core.audit(input.tool_name, "success", { toolResultOutcome: scan.decision.outcome });
    if (scan.decision.outcome === "mask") {
      // Same limitation as `preToolUse`: the hook cannot replace the payload
      // the model already has, so the redaction is surfaced as a note rather
      // than silently dropped.
      return {
        continue: true,
        systemMessage: `[governance] ${input.tool_name} result matched a mask rule: ${scan.decision.reason}`,
      };
    }
    return { continue: true };
  }

  return {
    canUseTool,
    hooks: {
      PreToolUse: [{ hooks: [preToolUse] }],
      PostToolUse: [{ hooks: [postToolUse] }],
    },
    preToolUse,
    postToolUse,
    preprocess: (text: string) => core.preprocess(text),
    postprocess: (text: string) => core.postprocess(text),
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    core,
    enforce: (toolName: string, input?: Record<string, unknown>) => core.enforce(toolName, input),
    audit: core.audit,
  };
}
