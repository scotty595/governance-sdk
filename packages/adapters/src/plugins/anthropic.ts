/**
 * governance-sdk Anthropic Claude SDK Plugin
 *
 * Integrates governance enforcement into Anthropic Claude tool execution.
 * Wraps tool executors with before-action policy checks and audit logging.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { governAnthropicTools } from 'governance-sdk/plugins/anthropic';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['file_write'])],
 * });
 *
 * const { tools, handleToolUse } = await governAnthropicTools(gov, myTools, {
 *   agentName: 'claude-assistant',
 *   owner: 'ai-team',
 * });
 * ```
 */

import type { GovernanceInstance } from "@governance-sdk/core";
import type {
  AnthropicToolExecutor, AnthropicToolUseBlock, AnthropicToolResultBlock,
  GovernAnthropicConfig, GovernedAnthropicResult,
} from "./anthropic-types.js";

// Re-export all types
export type {
  AnthropicToolDefinition, AnthropicToolUseBlock, AnthropicToolResultBlock,
  AnthropicContentBlock, AnthropicContentBlockParam, AnthropicToolExecutor,
  AnthropicCacheControl, AnthropicInputSchema, AnthropicToolCaller,
  GovernAnthropicConfig, GovernedAnthropicResult,
} from "./anthropic-types.js";

import { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";
import { createAdapterCore } from "./adapter-core.js";

// ─── Blocked Error ──────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Pre/post messages wrapper ──────────────────────────────
// See ./anthropic-messages.ts for docs + examples.
export type {
  AnthropicMessagesClient,
  AnthropicMessagesCreateParams,
  AnthropicMessage,
  AnthropicMessagesConfig,
} from "./anthropic-messages.js";
export { createGovernedMessages } from "./anthropic-messages.js";

// ─── Streaming messages wrapper ─────────────────────────────
// See ./anthropic-stream.ts for docs + examples.
export type {
  AnthropicStreamEvent,
  AnthropicStreamParams,
  AnthropicStreamConfig,
} from "./anthropic-stream.js";
export { createGovernedMessageStream } from "./anthropic-stream.js";

// ─── Main Export ────────────────────────────────────────────

export async function governAnthropicTools(
  governance: GovernanceInstance,
  tools: AnthropicToolExecutor[],
  config: GovernAnthropicConfig,
): Promise<GovernedAnthropicResult> {
  const toolNames = tools.map((t) => t.name);
  const core = await createAdapterCore(governance, config, { tools: toolNames, framework: "anthropic", callbacks: config });
  const enforce = (toolName: string, input?: Record<string, unknown>) => core.enforce(toolName, input);
  const audit = core.audit;

  const toolMap = new Map(tools.map((t) => [t.name, t]));

  const governedTools: AnthropicToolExecutor[] = tools.map((tool) => ({
    ...tool,
    execute: (input: Record<string, unknown>) => core.run(tool.name, input, () => tool.execute(input)),
  }));

  async function handleToolUse(block: AnthropicToolUseBlock): Promise<AnthropicToolResultBlock> {
    const executor = toolMap.get(block.name);
    if (!executor) {
      return { type: "tool_result", tool_use_id: block.id, content: `Unknown tool: ${block.name}`, is_error: true };
    }
    const input = (block.input ?? {}) as Record<string, unknown>;
    try {
      const output = await core.run(block.name, input, () => executor.execute(input));
      const content = typeof output === "string" ? output : JSON.stringify(output);
      return { type: "tool_result", tool_use_id: block.id, content };
    } catch (error) {
      if (error instanceof GovernanceBlockedError || error instanceof GovernanceApprovalRequiredError) {
        // core.run() audits its own failures; a governance refusal is
        // audited here because it happens before the tool ever runs.
        await audit(block.name, "failure", { reason: (error as GovernanceBlockedError).decision.reason });
        return { type: "tool_result", tool_use_id: block.id, content: `Blocked: ${(error as GovernanceBlockedError).decision.reason}`, is_error: true };
      }
      const msg = error instanceof Error ? error.message : String(error);
      return { type: "tool_result", tool_use_id: block.id, content: msg, is_error: true };
    }
  }

  return {
    tools: governedTools,
    handleToolUse,
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    enforce,
    audit,
  };
}
