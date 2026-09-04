/**
 * governance-sdk Google Genkit Plugin
 *
 * Integrates governance enforcement into Genkit tool execution and flows.
 * Wraps tools with before-action policy checks and audit logging.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { governGenkitTools } from 'governance-sdk/plugins/genkit';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['file_delete', 'send_email'])],
 * });
 *
 * const { tools } = await governGenkitTools(gov, [searchTool, writeTool], {
 *   agentName: 'genkit-agent',
 *   owner: 'ai-team',
 * });
 *
 * // Use governed tools in your Genkit flow
 * ```
 */

import type { GovernanceInstance } from "@governance-sdk/core";
import type {
  GenkitTool, GenkitFlow,
  GovernGenkitConfig, GovernedGenkitToolsResult, GovernedGenkitFlowResult,
} from "./genkit-types.js";

// Re-export all types
export type {
  GenkitTool, GenkitFlow, GenkitMiddleware,
  GovernGenkitConfig, GovernedGenkitToolsResult, GovernedGenkitFlowResult,
} from "./genkit-types.js";

import { createAdapterCore } from "./adapter-core.js";
import type { AdapterCore } from "./adapter-core.js";

// ─── Blocked Error ──────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Pre/post generate wrappers ─────────────────────────────
// See ./genkit-generate.ts for docs + examples.
export type {
  GenkitGenerateOptions,
  GenkitGenerateResponse,
  GenkitStreamChunk,
  GenkitGenerateStreamResponse,
  GenkitGenerateConfig,
} from "./genkit-generate.js";
export {
  createGovernedGenerate,
  createGovernedGenerateStream,
} from "./genkit-generate.js";

/**
 * Run the tool's raw output through the policy engine at stage `tool_result`,
 * returning either the original (allow) or a redacted detail object (block /
 * require_approval). No-op when `config.scanToolResults === false` — the
 * default is on, so any Genkit user gets injection scanning of tool returns
 * automatically, the same default as the Mastra processor.
 */
async function scanOutput(
  core: AdapterCore,
  config: GovernGenkitConfig,
  toolName: string,
  args: Record<string, unknown> | undefined,
  output: unknown,
): Promise<unknown> {
  if (config.scanToolResults === false) return output;
  const scanned = await core.scanResult({
    tool: toolName, args, result: output,
    injectionThreshold: config.toolResultInjectionThreshold,
  });
  return scanned.result;
}

function wrapTool(tool: GenkitTool, core: AdapterCore, config: GovernGenkitConfig): GenkitTool {
  return {
    ...tool,
    call: async (input: unknown, options?: Record<string, unknown>): Promise<unknown> => {
      const inputRecord = typeof input === "object" && input !== null ? input as Record<string, unknown> : { input };
      await core.enforce(tool.name, inputRecord);
      try {
        const output = await tool.call(input, options);
        // Scan tool result before returning to the agent loop. On block
        // the LLM gets a redacted detail object in place of the original.
        const finalOutput = await scanOutput(core, config, tool.name, inputRecord, output);
        await core.audit(tool.name, "success");
        return finalOutput;
      } catch (error) {
        await core.audit(tool.name, "failure", { error: error instanceof Error ? error.message : String(error) });
        throw error;
      }
    },
  };
}

// ─── Govern Genkit Tools ────────────────────────────────────

export async function governGenkitTools(
  governance: GovernanceInstance,
  tools: GenkitTool[],
  config: GovernGenkitConfig,
): Promise<GovernedGenkitToolsResult> {
  const core = await createAdapterCore(governance, config, {
    tools: tools.map((t) => t.name), framework: "genkit", callbacks: config,
  });

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

// ─── Govern Genkit Flow ─────────────────────────────────────

export async function governGenkitFlow(
  governance: GovernanceInstance,
  flow: GenkitFlow,
  config: GovernGenkitConfig,
): Promise<GovernedGenkitFlowResult> {
  const core = await createAdapterCore(governance, config, {
    tools: [flow.name], framework: "genkit", callbacks: config,
  });

  const governedFlow: GenkitFlow = {
    ...flow,
    call: (input: unknown): Promise<unknown> => {
      const inputRecord = typeof input === "object" && input !== null ? input as Record<string, unknown> : { input };
      return core.run(flow.name, inputRecord, () => flow.call(input));
    },
  };

  return {
    flow: governedFlow,
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
  };
}
