/**
 * governance-sdk LangChain Plugin
 *
 * Integrates governance enforcement into LangChain/LangGraph tool execution.
 * Wraps tools with before-action policy checks and audit logging.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { governTool, governTools } from 'governance-sdk/plugins/langchain';
 * import { DynamicStructuredTool } from 'langchain/tools';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['shell_exec', 'database_drop'])],
 * });
 *
 * const searchTool = new DynamicStructuredTool({
 *   name: 'web_search',
 *   description: 'Search the web',
 *   schema: z.object({ query: z.string() }),
 *   func: async ({ query }) => '...',
 * });
 *
 * // Wrap a single tool
 * const governed = await governTool(gov, searchTool, {
 *   agentName: 'research-agent',
 *   owner: 'research-team',
 * });
 *
 * // Or wrap all tools at once
 * const governedTools = await governTools(gov, [searchTool, crmTool], {
 *   agentName: 'research-agent',
 *   owner: 'research-team',
 * });
 * ```
 */

import type { GovernanceInstance } from "../index";
import { createAdapterCore } from "./adapter-core.js";
import type { AdapterConfig, AdapterCore } from "./adapter-core.js";

// ─── Types ──────────────────────────────────────────────────────

/** LangChain runnable config (RunnableConfig / ToolRunnableConfig) */
export interface LangChainRunnableConfig {
  tags?: string[];
  metadata?: Record<string, unknown>;
  callbacks?: unknown[];
  /** Configurable fields for the runnable */
  configurable?: Record<string, unknown>;
  /** Custom run name for tracing */
  runName?: string;
  /** Run ID for tracing */
  runId?: string;
  /** Max concurrent calls */
  maxConcurrency?: number;
  /** Recursion limit (default 25 in SDK) */
  recursionLimit?: number;
  /** Abort signal */
  signal?: AbortSignal;
  /** Timeout in milliseconds */
  timeout?: number;
  /** Tool call context (ToolRunnableConfig extension) */
  toolCall?: Record<string, unknown>;
  /** Tool runtime context (ToolRunnableConfig extension) */
  context?: unknown;
  [key: string]: unknown;
}

/** Generic LangChain tool shape (no direct dependency) */
export interface LangChainTool {
  name: string;
  description: string;
  /** Input schema (Zod or JSON Schema) */
  schema?: unknown;
  /** Whether to return result directly to user */
  returnDirect?: boolean;
  /** Response format — SDK accepts arbitrary strings beyond the two known values */
  responseFormat?: "content" | "content_and_artifact" | string;
  /** Whether to show verbose parsing errors */
  verboseParsingErrors?: boolean;
  /** Default runnable config for this tool */
  defaultConfig?: LangChainRunnableConfig;
  /** Extra tool metadata */
  extras?: Record<string, unknown>;
  /** Tool metadata */
  metadata?: Record<string, unknown>;
  invoke: (input: unknown, config?: LangChainRunnableConfig) => Promise<unknown>;
}

/**
 * Extends the shared `AdapterConfig`, so beyond the tool-result options below
 * it accepts every cross-adapter field: `agentId`, `agentName`, `owner`,
 * `framework`, `metadata`, `actionMapper`, `sessionTokenTracker`, the
 * `onBlocked` / `onDecision` / `onWarn` / `onMask` / `onApprovalRequired`
 * callbacks, plus `toolTiers` (consequence tiers for
 * `requireTierApproval()`), `trackTaint` (provenance from scanned tool
 * output carried onto later calls, for `blockTaintedTools()`) and
 * `toolFieldExtraction` (map tool arguments onto `ctx.targetPath` /
 * `ctx.targetUrl`).
 */
export interface GovernToolConfig extends AdapterConfig {
  /**
   * Master switch for tool-result scanning (governance-sdk 0.15+).
   * Default: `true`. Wrapped tools run their return values through the
   * policy engine at stage `tool_result` before returning to the agent
   * loop. On block, the redacted detail object replaces the original.
   */
  scanToolResults?: boolean;
  /** Detection threshold for the local injection signal (0-1). Default 0.5. */
  toolResultInjectionThreshold?: number;
}

export interface GovernedResult {
  agentId: string;
  score: number;
  level: number;
  governance: GovernanceInstance;
}

// ─── Blocked Error ──────────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Helpers ────────────────────────────────────────────────────

/**
 * LangChain DynamicTool inputs are commonly plain strings. An unchecked cast
 * would set `ctx.input` to a string (typed as `Record<string, unknown>`), and
 * condition evaluators reading properties off it would silently get undefined
 * and never match — so anything that is not an object becomes `undefined`.
 */
function toArgRecord(input: unknown): Record<string, unknown> | undefined {
  return typeof input === "object" && input !== null
    ? input as Record<string, unknown>
    : undefined;
}

/**
 * Build the governed `invoke` for one tool: enforce, run, scan the result at
 * stage `tool_result`, audit. Shared by `governTool` and `governTools` so the
 * single-tool and multi-tool paths can never drift.
 */
function governedInvoke(
  tool: LangChainTool,
  core: AdapterCore,
  config: GovernToolConfig,
): (input: unknown, runConfig?: LangChainRunnableConfig) => Promise<unknown> {
  return async (input, runConfig) => {
    const args = toArgRecord(input);
    await core.enforce(tool.name, args);

    try {
      const output = await tool.invoke(input, runConfig);
      const finalOutput = config.scanToolResults === false
        ? output
        : (await core.scanResult({
            tool: tool.name, args, result: output,
            injectionThreshold: config.toolResultInjectionThreshold,
          })).result;
      await core.audit(tool.name, "success");
      return finalOutput;
    } catch (error) {
      await core.audit(tool.name, "failure", {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  };
}

function attach(
  governance: GovernanceInstance,
  config: GovernToolConfig,
  toolNames: string[],
): Promise<AdapterCore> {
  return createAdapterCore(governance, config, {
    tools: toolNames, framework: "langchain", callbacks: config,
  });
}

// ─── Govern a Single Tool ───────────────────────────────────────

/**
 * Wrap a single LangChain tool with governance enforcement.
 *
 * Returns a new tool-like object with the same interface but governed invoke.
 */
export async function governTool<T extends LangChainTool>(
  governance: GovernanceInstance,
  tool: T,
  config: GovernToolConfig,
): Promise<T & GovernedResult> {
  const core = await attach(governance, config, [tool.name]);

  const governed = {
    ...tool,
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    invoke: governedInvoke(tool, core, config),
  };

  return governed as T & GovernedResult;
}

// ─── Govern Multiple Tools ──────────────────────────────────────

/**
 * Wrap multiple LangChain tools with governance enforcement.
 *
 * Registers a single agent with all tool names, then wraps each tool's invoke.
 */
export async function governTools<T extends LangChainTool>(
  governance: GovernanceInstance,
  tools: T[],
  config: GovernToolConfig,
): Promise<{ tools: T[]; agentId: string; score: number; level: number }> {
  const core = await attach(governance, config, tools.map((t) => t.name));

  const governed = tools.map((tool) => ({
    ...tool,
    invoke: governedInvoke(tool, core, config),
  }));

  return {
    tools: governed as T[],
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
  };
}

// ─── Pre/post model wrapper ─────────────────────────────────────
// See ./langchain-model.ts for docs + examples.
export type {
  LangChainMessage,
  LangChainChatModel,
  LangChainModelConfig,
} from "./langchain-model.js";
export { wrapChatModel } from "./langchain-model.js";
