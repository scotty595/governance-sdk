/**
 * governance-sdk OpenAI Agents SDK Plugin
 *
 * Integrates governance enforcement into OpenAI Agents SDK tool execution.
 * Wraps tools with before-action policy checks and audit logging.
 * Types are in openai-agents-types.ts.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { governAgent } from 'governance-sdk/plugins/openai-agents';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['shell_exec', 'database_drop'])],
 * });
 *
 * const governed = await governAgent(gov, {
 *   name: 'research-agent',
 *   tools: [webSearchTool, fileWriteTool],
 * }, {
 *   agentName: 'research-agent',
 *   owner: 'research-team',
 * });
 * ```
 */

import type { GovernanceInstance } from "../index";
import type {
  OpenAIFunctionTool,
  OpenAIAgent,
  GovernAgentConfig,
  GovernedAgentResult,
  GovernedToolsResult,
} from "./openai-agents-types.js";

// Re-export all types for consumers
export type {
  OpenAIFunctionTool, OpenAIAgent, OpenAIRunContext, OpenAIToolCallDetails,
  GovernAgentConfig, GovernedAgentResult, GovernedToolsResult,
} from "./openai-agents-types.js";

import { createAdapterCore } from "./adapter-core.js";
import type { AdapterCore } from "./adapter-core.js";

// ─── Blocked Error ──────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Pre/post guardrails ────────────────────────────────────
// See ./openai-agents-guardrails.ts for docs + examples.
export type {
  OpenAIInputGuardrail,
  OpenAIOutputGuardrail,
  OpenAIGuardrailConfig,
  GuardrailOutputInfo,
} from "./openai-agents-guardrails.js";
export {
  createInputGuardrail,
  createOutputGuardrail,
} from "./openai-agents-guardrails.js";

/**
 * Run the tool's raw output through the policy engine at stage `tool_result`
 * and return either the original (allow) or a redacted detail object (block).
 * No-op when `config.scanToolResults === false`.
 */
function scanOutput(
  core: AdapterCore,
  config: GovernAgentConfig,
  toolName: string,
  args: Record<string, unknown> | undefined,
  output: unknown,
): Promise<unknown> {
  if (config.scanToolResults === false) return Promise.resolve(output);
  return core
    .scanResult({
      tool: toolName, args, result: output,
      injectionThreshold: config.toolResultInjectionThreshold,
    })
    .then((scanned) => scanned.result);
}

function wrapTool(
  tool: OpenAIFunctionTool,
  core: AdapterCore,
  config: GovernAgentConfig,
): OpenAIFunctionTool {
  const hasHandler = tool.invoke ?? tool.execute;
  if (!hasHandler) return tool;

  const wrapped: OpenAIFunctionTool = { ...tool };

  // Wrap invoke (SDK canonical method — args is JSON string, optional details)
  if (tool.invoke) {
    wrapped.invoke = async (ctx, args, details) => {
      const parsed = JSON.parse(args) as Record<string, unknown>;
      await core.enforce(tool.name, parsed);
      try {
        const output = await tool.invoke!(ctx, args, details);
        const finalOutput = await scanOutput(core, config, tool.name, parsed, output);
        await core.audit(tool.name, "success");
        // The SDK types `invoke` as Promise<string> (the value flows into
        // the Responses API's function_call_output, which requires a
        // string). When the original tool returned a string and we passed
        // through (allow), keep it as-is. When scanToolResult substituted
        // a BlockedToolResult object on block / require_approval,
        // serialise it so the LLM sees a parseable JSON string instead
        // of [object Object] when the SDK builds the API payload.
        return typeof finalOutput === "string" ? finalOutput : JSON.stringify(finalOutput);
      } catch (error) {
        await core.audit(tool.name, "failure", { error: error instanceof Error ? error.message : String(error) });
        throw error;
      }
    };
  }

  // Wrap legacy execute (governance wrapper convenience — does not exist in SDK)
  if (tool.execute) {
    wrapped.execute = async (args: Record<string, unknown>) => {
      await core.enforce(tool.name, args);
      try {
        const output = await tool.execute!(args);
        const finalOutput = await scanOutput(core, config, tool.name, args, output);
        await core.audit(tool.name, "success");
        return finalOutput;
      } catch (error) {
        await core.audit(tool.name, "failure", { error: error instanceof Error ? error.message : String(error) });
        throw error;
      }
    };
  }

  return wrapped;
}

// ─── Govern Agent ───────────────────────────────────────────

export async function governAgent<T extends OpenAIAgent>(
  governance: GovernanceInstance,
  agent: T,
  config: GovernAgentConfig,
): Promise<GovernedAgentResult<T>> {
  const toolNames = (agent.tools ?? []).filter((t): t is OpenAIFunctionTool => t.type === "function").map((t) => t.name);
  const desc = typeof agent.instructions === "string" ? agent.instructions : undefined;
  const core = await createAdapterCore(
    governance,
    { ...config, description: config.description ?? desc },
    { tools: toolNames, framework: "openai", callbacks: config },
  );
  const wrappedTools = (agent.tools ?? []).map((tool) => tool.type === "function" ? wrapTool(tool, core, config) : tool);

  return {
    agent: { ...agent, tools: wrappedTools } as T,
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    enforce: (toolName, input) => core.enforce(toolName, input),
    audit: core.audit,
  };
}

// ─── Govern Tools Only ──────────────────────────────────────

export async function governTools(
  governance: GovernanceInstance,
  tools: OpenAIFunctionTool[],
  config: GovernAgentConfig,
): Promise<GovernedToolsResult> {
  const toolNames = tools.map((t) => t.name);
  const core = await createAdapterCore(governance, config, {
    tools: toolNames, framework: "openai", callbacks: config,
  });

  return {
    tools: tools.map((tool) => wrapTool(tool, core, config)),
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
  };
}
