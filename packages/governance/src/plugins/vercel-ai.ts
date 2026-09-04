/**
 * governance-sdk Vercel AI SDK Plugin
 *
 * Integrates governance enforcement into the Vercel AI SDK tool system.
 * Wraps tool execution with before-action policy checks and audit logging.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { createGovernedTools } from 'governance-sdk/plugins/vercel-ai';
 * import { generateText, tool } from 'ai';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['shell_exec', 'database_drop'])],
 * });
 *
 * const myTools = {
 *   webSearch: tool({ description: 'Search', inputSchema: z.object({ query: z.string() }), execute: async ({ query }) => ... }),
 *   crmUpdate: tool({ description: 'Update CRM', inputSchema: z.object({ id: z.string() }), execute: async ({ id }) => ... }),
 * };
 *
 * // Wrap all tools with governance
 * const { tools, middleware } = await createGovernedTools(gov, myTools, {
 *   agentName: 'sales-agent',
 *   owner: 'sales-team',
 *   framework: 'vercel-ai',
 * });
 *
 * // Use governed tools with generateText/streamText
 * const result = await generateText({ model, tools, prompt: '...' });
 * ```
 *
 * ## Version compatibility (checked against the published `ai` typings)
 *
 * `VercelTool` / `VercelToolExecutionOptions` mirror the `ai` 6 tool shape:
 * `inputSchema` (ai ≥ 5.0, replaced `parameters`) plus `needsApproval`,
 * `inputExamples`, `strict`, `title` and `toModelOutput({ output })`
 * (ai ≥ 6.0). Every field is optional and `createGovernedTools` only replaces
 * `execute`, so the wrapper also works structurally with `ai` 5.x tools and,
 * via the deprecated `parameters` field, with 3.x / 4.x tools. Type-level
 * floor: `ai` 6.0.0. `createGovernanceMiddleware` (vercel-ai-middleware.ts)
 * has a separate, lower floor of `ai` 3.4.0 — see that file's header.
 */

import type {
  GovernanceInstance,
  AuditEvent,
} from "../index";
import type { EnforcementDecision } from "../policy";
import { createAdapterCore } from "./adapter-core.js";
import type { AdapterConfig } from "./adapter-core.js";

// ─── Types ──────────────────────────────────────────────────────

/** Vercel AI SDK tool execution options (SDK 6+) */
export interface VercelToolExecutionOptions {
  toolCallId: string;
  messages: unknown[];
  abortSignal?: AbortSignal;
  /** Arbitrary context passthrough from generateText/streamText */
  experimental_context?: unknown;
}

/** Vercel AI SDK tool shape (SDK 6+ — uses inputSchema, not parameters) */
export interface VercelTool {
  description?: string;
  /** Human-readable display name (AI SDK 6+) */
  title?: string;
  /** @deprecated Use inputSchema (AI SDK 6 renamed parameters to inputSchema) */
  parameters?: unknown;
  /** Input schema — Zod or JSON Schema (required in SDK 6, optional here for wrapper flexibility) */
  inputSchema?: unknown;
  /** Output schema — Zod or JSON Schema (AI SDK 6+) */
  outputSchema?: unknown;
  /** Tool execution handler — options is required in SDK 6 */
  execute?: (input: unknown, options: VercelToolExecutionOptions) => Promise<unknown> | AsyncIterable<unknown> | unknown;
  /** Whether this tool requires human approval before execution */
  needsApproval?: boolean | ((input: unknown, options: { toolCallId: string; messages: unknown[]; experimental_context?: unknown }) => boolean | PromiseLike<boolean>);
  /** Enable strict schema validation (AI SDK 6+) */
  strict?: boolean;
  /** Tool type (AI SDK 6+) */
  type?: "function" | "dynamic" | "provider";
  /** Convert tool output to model-consumable content (replaces experimental_toToolResultContent) */
  toModelOutput?: (options: { toolCallId: string; input: unknown; output: unknown }) => unknown;
  /** Callback when argument streaming begins */
  onInputStart?: (options: VercelToolExecutionOptions) => void | Promise<void>;
  /** Callback for argument streaming deltas */
  onInputDelta?: (options: { inputTextDelta: string } & VercelToolExecutionOptions) => void | Promise<void>;
  /** Callback when full input becomes available */
  onInputAvailable?: (options: { input: unknown } & VercelToolExecutionOptions) => void | Promise<void>;
  /** Example inputs for the tool */
  inputExamples?: Array<{ input: unknown }>;
  /** Provider-specific options */
  providerOptions?: Record<string, unknown>;
  /** Tool ID — for provider tools (format: `provider.toolName`) */
  id?: `${string}.${string}`;
  /** Tool name — for provider-defined tools */
  name?: string;
  /** Pre-set args — for provider-defined tools */
  args?: Record<string, unknown>;
}

/**
 * Everything the shared `AdapterConfig` accepts: `agentId`, `agentName`,
 * `owner`, `framework`, `metadata`, `actionMapper`, `sessionTokenTracker`,
 * the `onBlocked` / `onDecision` / `onWarn` / `onMask` /
 * `onApprovalRequired` callbacks, plus `toolTiers` (consequence tiers for
 * `requireTierApproval()`), `trackTaint` (provenance carried from scanned
 * tool output onto later calls, for `blockTaintedTools()`) and
 * `toolFieldExtraction` (map tool arguments onto `ctx.targetPath` /
 * `ctx.targetUrl` so `scope_boundary` and `network_allowlist` match).
 */
/* An interface rather than an alias so consumer declaration merging still works. */
export interface GovernedToolsConfig extends AdapterConfig {}

export interface GovernedToolsResult<T> {
  tools: T;
  agentId: string;
  score: number;
  level: number;
  governance: GovernanceInstance;
  enforce: (toolName: string, input?: Record<string, unknown>) => Promise<EnforcementDecision>;
  audit: (toolName: string, outcome: "success" | "failure", detail?: Record<string, unknown>) => Promise<AuditEvent>;
}

// ─── Blocked Error ──────────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Create Governed Tools ──────────────────────────────────────

/**
 * Wrap Vercel AI SDK tools with governance enforcement.
 *
 * Returns new tool objects with the same shape but governed execute functions.
 * Each tool call is checked against policies before execution and logged to audit trail.
 */
export async function createGovernedTools<
  T extends Record<string, VercelTool>,
>(
  governance: GovernanceInstance,
  tools: T,
  config: GovernedToolsConfig,
): Promise<GovernedToolsResult<T>> {
  const core = await createAdapterCore(governance, config, {
    tools: Object.keys(tools),
    framework: "vercel-ai",
    callbacks: config,
  });
  const enforce = (toolName: string, input?: Record<string, unknown>) => core.enforce(toolName, input);
  const audit = core.audit;

  // Wrap each tool's execute function
  const governed = {} as Record<string, VercelTool>;
  for (const [name, tool] of Object.entries(tools)) {
    governed[name] = {
      ...tool,
      execute: tool.execute
        ? (input: unknown, options: VercelToolExecutionOptions) =>
            core.run(name, (input ?? {}) as Record<string, unknown>, async () =>
              tool.execute!(input, options),
            )
        : undefined,
    };
  }

  return {
    tools: governed as T,
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    enforce,
    audit,
  };
}

// Pre/post middleware lives in `vercel-ai-middleware.ts` — see README.
export type {
  VercelLanguageModelMiddleware,
  VercelLanguageModelParams,
  VercelGenerateResult,
  VercelMiddlewareConfig,
} from "./vercel-ai-middleware.js";
export { createGovernanceMiddleware } from "./vercel-ai-middleware.js";
