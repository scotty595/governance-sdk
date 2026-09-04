/**
 * governance-sdk AWS Bedrock Agents Plugin
 *
 * Integrates governance enforcement into AWS Bedrock agent invocations.
 * Wraps invokeAgent calls and action group execution with policy checks.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { createGovernedBedrock } from 'governance-sdk/plugins/bedrock';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['delete_records', 'send_email'])],
 * });
 *
 * const { invokeAgent, guardActionGroup } = await createGovernedBedrock(
 *   gov, originalInvokeAgent, {
 *     agentName: 'bedrock-assistant',
 *     owner: 'cloud-team',
 *   },
 * );
 *
 * // Use governed invokeAgent instead of direct SDK call
 * const response = await invokeAgent({ agentId: '...', ... });
 * ```
 */

import type { GovernanceInstance } from "../index";
import type { EnforcementDecision } from "../policy";
import type {
  BedrockInvokeAgentInput, BedrockActionGroupInvocation, BedrockToolUseBlock,
  GovernBedrockConfig, GovernedBedrockResult, BedrockInvokeHandler,
} from "./bedrock-types.js";

// Re-export all types
export type {
  BedrockInvokeAgentInput, BedrockActionGroupInvocation, BedrockActionParameter,
  BedrockResponseChunk, BedrockTrace,
  BedrockToolUseBlock, BedrockToolResultBlock, BedrockToolResultContent,
  BedrockContentBlock, BedrockToolSpec, BedrockTool, BedrockToolChoice,
  BedrockToolConfiguration,
  GovernBedrockConfig, GovernedBedrockResult, BedrockInvokeHandler,
} from "./bedrock-types.js";

import { GovernanceBlockedError } from "./outcome-handler.js";
import type { OutcomeCallbacks } from "./outcome-handler.js";
import { enforcePreprocess, enforcePostprocess } from "./pre-post-enforce.js";
import { createAdapterCore } from "./adapter-core.js";

// ─── Blocked Error ──────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Create Governed Bedrock ────────────────────────────────

/**
 * Create a governed AWS Bedrock agent wrapper.
 *
 * Wraps an existing invokeAgent handler with governance enforcement.
 * Also provides a guardActionGroup method for action-level governance.
 */
export async function createGovernedBedrock(
  governance: GovernanceInstance,
  invokeHandler: BedrockInvokeHandler,
  config: GovernBedrockConfig,
): Promise<GovernedBedrockResult> {
  // Bedrock uses IAM auth by default, so `hasAuth` defaults to true here.
  const core = await createAdapterCore(
    governance,
    { ...config, hasAuth: config.hasAuth ?? true },
    { tools: config.tools ?? [], framework: "bedrock", callbacks: config },
  );
  const enforce = (toolName: string, input?: Record<string, unknown>) => core.enforce(toolName, input);
  const audit = core.audit;

  async function invokeAgent(input: BedrockInvokeAgentInput): Promise<unknown> {
    const toolName = `bedrock:${input.agentId}:${input.agentAliasId}`;

    // Pre-scan on the user's inputText BEFORE Bedrock receives it. This is
    // entry-gate only — Bedrock Agents execute their internal tool calls
    // inside AWS, so we don't see them individually. What we CAN gate is
    // the prompt coming in and the final text coming out.
    if ((config.preprocess ?? true) && input.inputText) {
      await enforcePreprocess(governance, input.inputText, {
        agentId: core.agentId,
        agentName: config.agentName,
        agentLevel: core.agentLevel,
        metadata: config.metadata,
        sessionTokensUsed: config.sessionTokenTracker?.(),
        callbacks: config as OutcomeCallbacks,
        toolName: "bedrock.invokeAgent:pre",
      });
    }

    await enforce(toolName, {
      agentId: input.agentId,
      agentAliasId: input.agentAliasId,
      sessionId: input.sessionId,
      inputText: input.inputText,
    });

    try {
      const response = await invokeHandler(input);
      await audit(toolName, "success", { sessionId: input.sessionId });
      return response;
    } catch (error) {
      await audit(toolName, "failure", {
        sessionId: input.sessionId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Post-scan helper for callers who've already assembled the Bedrock
   * response text. Bedrock's invokeAgent returns a streamed completion,
   * and deserialization is caller-specific (they decode the chunk bytes);
   * we expose this so callers can post-scan after their own assembly:
   *
   *   const response = await invokeAgent({...});
   *   const text = await assembleBedrockResponse(response);
   *   const safeText = await scanOutput(text);
   *
   * Returns the (possibly masked) text. Throws on block.
   */
  async function scanOutput(outputText: string): Promise<string> {
    if (!(config.postprocess ?? true)) return outputText;
    const post = await enforcePostprocess(governance, outputText, {
      agentId: core.agentId,
      agentName: config.agentName,
      agentLevel: core.agentLevel,
      metadata: config.metadata,
      sessionTokensUsed: config.sessionTokenTracker?.(),
      callbacks: config as OutcomeCallbacks,
      toolName: "bedrock.invokeAgent:post",
    });
    return post.text;
  }

  async function guardActionGroup(invocation: BedrockActionGroupInvocation): Promise<EnforcementDecision> {
    const toolName = invocation.actionGroupName;
    const input: Record<string, unknown> = {
      apiPath: invocation.apiPath,
      verb: invocation.verb,
    };

    if (invocation.parameters) {
      input.parameters = invocation.parameters.map((p) => ({ name: p.name, value: p.value }));
    }

    try {
      const decision = await enforce(toolName, input);
      await audit(toolName, "success", { type: "action_group_allowed" });
      return decision;
    } catch (error) {
      if (error instanceof GovernanceBlockedError) {
        await audit(toolName, "failure", { reason: error.decision.reason, type: "action_group_blocked" });
      }
      throw error;
    }
  }

  async function guardToolUse(block: BedrockToolUseBlock): Promise<EnforcementDecision> {
    const toolName = block.name;
    const input = (block.input ?? {}) as Record<string, unknown>;
    try {
      const decision = await enforce(toolName, { toolUseId: block.toolUseId, ...input });
      await audit(toolName, "success", { type: "tool_use_allowed", toolUseId: block.toolUseId });
      return decision;
    } catch (error) {
      if (error instanceof GovernanceBlockedError) {
        await audit(toolName, "failure", { reason: error.decision.reason, type: "tool_use_blocked", toolUseId: block.toolUseId });
      }
      throw error;
    }
  }

  return {
    invokeAgent,
    guardActionGroup,
    guardToolUse,
    scanOutput,
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    enforce,
    audit,
  };
}
