/**
 * governance-sdk Ollama Plugin
 *
 * Integrates governance enforcement into Ollama tool execution.
 * Wraps tool executors with before-action policy checks and audit logging.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { governOllamaTools } from 'governance-sdk/plugins/ollama';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['shell_exec'])],
 * });
 *
 * const { tools, handleToolCall } = await governOllamaTools(gov, myTools, {
 *   agentName: 'ollama-agent',
 *   owner: 'local-team',
 * });
 * ```
 */

import type { GovernanceInstance } from "../index";
import type {
  OllamaToolExecutor, OllamaToolCall,
  GovernOllamaConfig, GovernedOllamaResult,
} from "./ollama-types.js";

// Re-export all types
export type {
  OllamaToolDefinition, OllamaToolCall, OllamaToolExecutor,
  GovernOllamaConfig, GovernedOllamaResult,
} from "./ollama-types.js";

import { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";
import { createAdapterCore } from "./adapter-core.js";

// ─── Blocked Error ──────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Pre/post chat wrappers ─────────────────────────────────
// See ./ollama-chat.ts for docs + examples.
export type {
  OllamaChatParams,
  OllamaChatResponse,
  OllamaChatChunk,
  OllamaChatConfig,
} from "./ollama-chat.js";
export {
  createGovernedOllamaChat,
  createGovernedOllamaChatStream,
} from "./ollama-chat.js";

// ─── Main Export ────────────────────────────────────────────

export async function governOllamaTools(
  governance: GovernanceInstance,
  tools: OllamaToolExecutor[],
  config: GovernOllamaConfig,
): Promise<GovernedOllamaResult> {
  const core = await createAdapterCore(governance, config, {
    tools: tools.map((t) => t.name), framework: "ollama", callbacks: config,
  });
  const enforce = (toolName: string, input?: Record<string, unknown>) => core.enforce(toolName, input);
  const audit = core.audit;

  const toolMap = new Map(tools.map((t) => [t.name, t]));

  const governedTools: OllamaToolExecutor[] = tools.map((tool) => ({
    ...tool,
    execute: (args: Record<string, unknown>) => core.run(tool.name, args, () => tool.execute(args)),
  }));

  async function handleToolCall(toolCall: OllamaToolCall): Promise<string> {
    const executor = toolMap.get(toolCall.function.name);
    if (!executor) {
      return `Unknown tool: ${toolCall.function.name}`;
    }
    const args = toolCall.function.arguments;
    const name = toolCall.function.name;
    try {
      const output = await core.run(name, args, () => executor.execute(args));
      return typeof output === "string" ? output : JSON.stringify(output);
    } catch (error) {
      if (error instanceof GovernanceBlockedError || error instanceof GovernanceApprovalRequiredError) {
        // core.run() audits its own failures; a governance refusal is
        // audited here because it happens before the tool ever runs.
        await audit(name, "failure", { reason: (error as GovernanceBlockedError).decision.reason });
        return `Blocked: ${(error as GovernanceBlockedError).decision.reason}`;
      }
      return error instanceof Error ? error.message : String(error);
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
