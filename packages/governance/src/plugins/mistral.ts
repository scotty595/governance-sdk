/**
 * governance-sdk Mistral AI Plugin
 *
 * Integrates governance enforcement into Mistral AI tool execution.
 * Wraps tool executors with before-action policy checks and audit logging.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { governMistralTools } from 'governance-sdk/plugins/mistral';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['shell_exec'])],
 * });
 *
 * const { tools, handleToolCall } = await governMistralTools(gov, myTools, {
 *   agentName: 'mistral-agent',
 *   owner: 'ai-team',
 * });
 * ```
 */

import type { GovernanceInstance } from "../index";
import type {
  MistralToolExecutor, MistralToolCall,
  GovernMistralConfig, GovernedMistralResult,
} from "./mistral-types.js";

// Re-export all types
export type {
  MistralToolDefinition, MistralToolCall, MistralToolExecutor,
  GovernMistralConfig, GovernedMistralResult,
} from "./mistral-types.js";

import { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";
import { createAdapterCore } from "./adapter-core.js";

// ─── Blocked Error ──────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Pre/post chat wrappers ─────────────────────────────────
// See ./mistral-messages.ts for docs + examples.
export type {
  MistralChatClient,
  MistralChatParams,
  MistralChatResponse,
  MistralStreamEvent,
  MistralMessagesConfig,
} from "./mistral-messages.js";
export {
  createGovernedChat,
  createGovernedChatStream,
} from "./mistral-messages.js";

// ─── Main Export ────────────────────────────────────────────

export async function governMistralTools(
  governance: GovernanceInstance,
  tools: MistralToolExecutor[],
  config: GovernMistralConfig,
): Promise<GovernedMistralResult> {
  const core = await createAdapterCore(governance, config, {
    tools: tools.map((t) => t.name), framework: "mistral", callbacks: config,
  });
  const enforce = (toolName: string, input?: Record<string, unknown>) => core.enforce(toolName, input);
  const audit = core.audit;

  const toolMap = new Map(tools.map((t) => [t.name, t]));

  const governedTools: MistralToolExecutor[] = tools.map((tool) => ({
    ...tool,
    execute: (args: Record<string, unknown>) => core.run(tool.name, args, () => tool.execute(args)),
  }));

  async function handleToolCall(toolCall: MistralToolCall): Promise<{ toolCallId: string; content: string }> {
    const toolCallId = toolCall.id && toolCall.id !== "null" ? toolCall.id : `call_${toolCall.function.name}_${Date.now()}`;
    const executor = toolMap.get(toolCall.function.name);
    if (!executor) {
      return { toolCallId, content: `Unknown tool: ${toolCall.function.name}` };
    }
    const args = (typeof toolCall.function.arguments === "string"
      ? JSON.parse(toolCall.function.arguments)
      : toolCall.function.arguments) as Record<string, unknown>;
    const name = toolCall.function.name;
    try {
      const output = await core.run(name, args, () => executor.execute(args));
      return { toolCallId, content: typeof output === "string" ? output : JSON.stringify(output) };
    } catch (error) {
      if (error instanceof GovernanceBlockedError || error instanceof GovernanceApprovalRequiredError) {
        // core.run() audits its own failures; a governance refusal is
        // audited here because it happens before the tool ever runs.
        await audit(name, "failure", { reason: (error as GovernanceBlockedError).decision.reason });
        return { toolCallId, content: `Blocked: ${(error as GovernanceBlockedError).decision.reason}` };
      }
      return { toolCallId, content: error instanceof Error ? error.message : String(error) };
    }
  }

  return {
    tools: governedTools,
    handleToolCall,
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    enforce,
    audit,
  };
}
