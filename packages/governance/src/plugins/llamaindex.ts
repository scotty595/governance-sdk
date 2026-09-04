/**
 * governance-sdk LlamaIndex Plugin
 *
 * Integrates governance enforcement into LlamaIndex tool execution.
 * Wraps tools with before-action policy checks and audit logging.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { governLlamaIndexTools } from 'governance-sdk/plugins/llamaindex';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['file_delete', 'shell_exec'])],
 * });
 *
 * const { tools } = await governLlamaIndexTools(gov, [searchTool, writeTool], {
 *   agentName: 'llamaindex-agent',
 *   owner: 'ai-team',
 * });
 *
 * // Use governed tools in your LlamaIndex agent
 * const agent = new OpenAIAgent({ tools });
 * ```
 */

import type { GovernanceInstance } from "../index";
import type {
  LlamaIndexTool, LlamaIndexAgent, LlamaIndexJSONValue,
  GovernLlamaIndexConfig, GovernedLlamaIndexToolsResult, GovernedLlamaIndexAgentResult,
} from "./llamaindex-types.js";

// Re-export all types
export type {
  LlamaIndexTool, LlamaIndexToolMetadata, LlamaIndexToolOutput, LlamaIndexJSONValue,
  LlamaIndexQueryEngineTool, LlamaIndexAgent,
  GovernLlamaIndexConfig, GovernedLlamaIndexToolsResult, GovernedLlamaIndexAgentResult,
} from "./llamaindex-types.js";

import { createAdapterCore } from "./adapter-core.js";
import type { AdapterCore } from "./adapter-core.js";

// ─── Pre/post LLM wrapper ───────────────────────────────────
// See ./llamaindex-llm.ts for docs + examples.
export type {
  LlamaChatMessage,
  LlamaChatRequest,
  LlamaChatResponse,
  LlamaChatResponseChunk,
  LlamaLLM,
  LlamaLLMConfig,
} from "./llamaindex-llm.js";
export { wrapLlamaLLM } from "./llamaindex-llm.js";

// ─── Blocked Error ──────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

/**
 * Register once, with the runtime marker LlamaIndex agents carry in their
 * registration metadata.
 */
function attach(
  governance: GovernanceInstance,
  config: GovernLlamaIndexConfig,
  toolNames: string[],
): Promise<AdapterCore> {
  return createAdapterCore(
    governance,
    { ...config, metadata: { ...config.metadata, runtime: "llamaindex" } },
    { tools: toolNames, framework: "custom", callbacks: config },
  );
}

/**
 * Run the tool's raw output through the policy engine at stage `tool_result`
 * and return either the original (allow) or a redacted detail object (block).
 * No-op when `config.scanToolResults === false`. Default-on.
 */
async function scanOutput(
  core: AdapterCore,
  config: GovernLlamaIndexConfig,
  toolName: string,
  args: Record<string, unknown> | undefined,
  output: LlamaIndexJSONValue,
): Promise<LlamaIndexJSONValue> {
  if (config.scanToolResults === false) return output;
  const scanned = await core.scanResult({
    tool: toolName, args, result: output,
    injectionThreshold: config.toolResultInjectionThreshold,
  });
  // BlockedToolResult.ruleId is `string | null`, but LlamaIndexJSONValue
  // explicitly excludes `null` per the SDK contract. Coerce on block so
  // downstream LlamaIndex JSON walkers don't trip on the null property.
  if (scanned.blocked) {
    const blocked = scanned.result as { blocked: true; reason: string; ruleId: string | null };
    return { blocked: true, reason: blocked.reason, ruleId: blocked.ruleId ?? "unknown" };
  }
  return scanned.result as LlamaIndexJSONValue;
}

function wrapTool(tool: LlamaIndexTool, core: AdapterCore, config: GovernLlamaIndexConfig): LlamaIndexTool {
  if (!tool.call) return tool;
  const toolName = tool.metadata.name;
  return {
    ...tool,
    call: async (input: Record<string, unknown>): Promise<LlamaIndexJSONValue> => {
      await core.enforce(toolName, input);
      try {
        const output = await tool.call!(input);
        const finalOutput = await scanOutput(core, config, toolName, input, output);
        await core.audit(toolName, "success");
        return finalOutput;
      } catch (error) {
        await core.audit(toolName, "failure", { error: error instanceof Error ? error.message : String(error) });
        throw error;
      }
    },
  };
}

// ─── Govern LlamaIndex Tools ────────────────────────────────

export async function governLlamaIndexTools(
  governance: GovernanceInstance,
  tools: LlamaIndexTool[],
  config: GovernLlamaIndexConfig,
): Promise<GovernedLlamaIndexToolsResult> {
  const core = await attach(governance, config, tools.map((t) => t.metadata.name));

  return {
    tools: tools.map((tool) => wrapTool(tool, core, config)),
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    enforce: (toolName, input) => core.enforce(toolName, input),
    audit: core.audit,
  };
}

// ─── Govern LlamaIndex Agent ────────────────────────────────

export async function governLlamaIndexAgent(
  governance: GovernanceInstance,
  agent: LlamaIndexAgent,
  config: GovernLlamaIndexConfig,
): Promise<GovernedLlamaIndexAgentResult> {
  const core = await attach(governance, config, agent.tools.map((t) => t.metadata.name));

  return {
    agent: { ...agent, tools: agent.tools.map((tool) => wrapTool(tool, core, config)) },
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    enforce: (toolName, input) => core.enforce(toolName, input),
    audit: core.audit,
  };
}
