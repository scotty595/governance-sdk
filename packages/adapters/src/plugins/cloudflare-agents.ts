/**
 * governance-sdk — Cloudflare Agents adapter
 *
 * Governs the tools of an agent built on Cloudflare's `agents` package. Tools
 * there are AI-SDK-shaped: an optional `execute`, an optional `needsApproval`
 * that the runtime consults before pausing for a human, and a schema. This
 * adapter wraps `execute` with the shared adapter kernel and offers a
 * `needsApproval` predicate backed by the same policy set, so the tool a
 * Worker runs is judged exactly as the same tool on any other framework.
 *
 * Stage mapping:
 *
 *   | Seam                       | Stage         | Kernel call            |
 *   |----------------------------|---------------|------------------------|
 *   | wrapped `execute`, entry   | `process`     | `core.enforce()`        |
 *   | wrapped `execute`, return  | `tool_result` | `core.scanResult()`     |
 *   | `preprocess(text)`         | `preprocess`  | `core.preprocess()`     |
 *   | `postprocess(text)`        | `postprocess` | `core.postprocess()`    |
 *
 * ## Workers
 *
 * Everything on this path is Web-standard: no `node:` import, no Node global,
 * no filesystem, no timers beyond what the kernel already uses. The adapter,
 * the adapter kernel, `@governance-sdk/core` and the detector all run inside a
 * Worker isolate unmodified. Keep it that way — a `node:` import here is what
 * would make the whole package unusable on Workers.
 *
 * ## `needsApproval` and the approval record
 *
 * `needsApproval` is deliberately NOT attached to your tools for you. The two
 * approvals are different things and conflating them strands the call:
 * Cloudflare's `needsApproval` pauses for a confirmation in the chat, while a
 * `require_approval` outcome opens a governance approval record that only
 * `gov.waitForApproval()` resolves — and in local mode nothing resolves it at
 * all. Attach the predicate when you want the human prompt raised early, and
 * expect the governed `execute` to refuse the call afterwards until the
 * governance approval itself is granted. That refusal is the point: the chat
 * confirmation is not the policy's approval.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { governCloudflareTools } from 'governance-sdk/plugins/cloudflare-agents';
 *
 * const gov = createGovernance({ rules: [blockTools(['deleteAccount'])] });
 * const { tools, needsApproval } = await governCloudflareTools(gov, myTools, {
 *   agentName: 'support-agent',
 *   owner: 'platform-team',
 * });
 *
 * // inside the Agent's onChatMessage:
 * const result = streamText({ model, tools, messages });
 * ```
 */

import type { AuditEvent, GovernanceInstance } from "@governance-sdk/core";
import type { EnforcementDecision } from "@governance-sdk/core/policy.js";
import { createAdapterCore, type AdapterConfig, type AdapterCore } from "./adapter-core.js";
import type { PrePostResult } from "./pre-post-enforce.js";

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Cloudflare Agents shapes ───────────────────────────────

/**
 * The execution options a tool's `execute` receives. Mirrored structurally —
 * the `agents` package is not a dependency — and every field is optional
 * because the adapter only ever passes this value straight through.
 */
export interface CloudflareToolExecutionOptions {
  toolCallId?: string;
  messages?: unknown[];
  abortSignal?: AbortSignal;
  /** Arbitrary context the host threads through the call. */
  experimental_context?: unknown;
}

/**
 * A tool as Cloudflare Agents accepts it.
 *
 * `execute` is optional on purpose: the human-in-the-loop pattern registers a
 * tool with no `execute` and runs it from a separate confirmation map once the
 * user agrees. Such a tool is left untouched here (there is nothing to wrap);
 * govern its deferred execution through the returned `enforce()`.
 */
export interface CloudflareAgentTool {
  description?: string;
  /** Zod or JSON Schema, per AI SDK 5+. */
  inputSchema?: unknown;
  /** @deprecated Pre-AI-SDK-5 name for `inputSchema`. */
  parameters?: unknown;
  outputSchema?: unknown;
  execute?: (input: unknown, options: CloudflareToolExecutionOptions) => Promise<unknown> | unknown;
  /** Consulted by the runtime before pausing the turn for a human. */
  needsApproval?:
    | boolean
    | ((input: unknown, options: CloudflareToolExecutionOptions) => boolean | PromiseLike<boolean>);
  type?: "function" | "dynamic" | "provider";
  toModelOutput?: (options: { toolCallId: string; input: unknown; output: unknown }) => unknown;
}

/** A predicate in the shape `CloudflareAgentTool.needsApproval` expects. */
export type NeedsApprovalPredicate = (
  input: unknown,
  options: CloudflareToolExecutionOptions,
) => Promise<boolean>;

// ─── Configuration ──────────────────────────────────────────

/**
 * Extends the shared `AdapterConfig`, so beyond the two fields below it takes
 * every cross-adapter option: `agentId`, `agentName`, `owner`, `framework`,
 * `metadata`, `actionMapper`, `sessionTokenTracker`, the `onBlocked` /
 * `onDecision` / `onWarn` / `onMask` / `onApprovalRequired` callbacks, plus
 * `toolTiers`, `trackTaint` and `toolFieldExtraction`.
 */
export interface GovernCloudflareConfig extends AdapterConfig {
  /**
   * Run each tool's return value through the policy engine at stage
   * `tool_result` before the model ingests it. Default `true` — the same
   * default the Mastra processor, Genkit and OpenAI Agents adapters use, and
   * what makes `blockTaintedTools()` work on this adapter.
   */
  scanToolResults?: boolean;
  /** Threshold for the local injection signal on tool results. Default 0.5. */
  toolResultInjectionThreshold?: number;
}

export interface GovernedCloudflareToolsResult<T> {
  /** The same tools, with governed `execute` functions. */
  tools: T;
  /**
   * Does policy want a human before this call? A pure predicate: it evaluates
   * the `process` stage and reports whether the outcome is `require_approval`,
   * firing no outcome callbacks and throwing nothing, because a predicate the
   * runtime polls is not an enforcement point.
   */
  needsApproval: (toolName: string, input?: Record<string, unknown>) => Promise<boolean>;
  /** The same check bound to one tool, shaped for `tool.needsApproval`. */
  needsApprovalFor: (toolName: string) => NeedsApprovalPredicate;
  /** Prompt text through the `preprocess` stage. Throws on block/approval. */
  preprocess: (text: string) => Promise<PrePostResult>;
  /** Final output text through the `postprocess` stage. Same contract. */
  postprocess: (text: string) => Promise<PrePostResult>;
  agentId: string;
  score: number;
  level: number;
  governance: GovernanceInstance;
  /** The shared adapter kernel, for deferred or non-tool actions. */
  core: AdapterCore;
  enforce: (toolName: string, input?: Record<string, unknown>) => Promise<EnforcementDecision>;
  audit: (toolName: string, outcome: "success" | "failure", detail?: Record<string, unknown>) => Promise<AuditEvent>;
}

// ─── Implementation ─────────────────────────────────────────

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * Wrap Cloudflare Agents tools with governance.
 *
 * Registers once, then replaces every `execute` with: enforce at the `process`
 * stage (throwing `GovernanceBlockedError` on block and
 * `GovernanceApprovalRequiredError` on require_approval, as every adapter
 * does), run the tool, scan the return value at the `tool_result` stage, audit
 * the outcome. Tools without an `execute` are returned unchanged.
 */
export async function governCloudflareTools<T extends Record<string, CloudflareAgentTool>>(
  governance: GovernanceInstance,
  tools: T,
  config: GovernCloudflareConfig,
): Promise<GovernedCloudflareToolsResult<T>> {
  const core = await createAdapterCore(governance, config, {
    tools: Object.keys(tools),
    // `config.framework` wins.
    framework: "cloudflare",
    callbacks: config,
  });

  async function scanOutput(
    toolName: string,
    args: Record<string, unknown> | undefined,
    output: unknown,
  ): Promise<unknown> {
    if (config.scanToolResults === false) return output;
    const scanned = await core.scanResult({
      tool: toolName,
      result: output,
      ...(args ? { args } : {}),
      ...(config.toolResultInjectionThreshold !== undefined
        ? { injectionThreshold: config.toolResultInjectionThreshold }
        : {}),
    });
    return scanned.result;
  }

  function wrap(name: string, tool: CloudflareAgentTool): CloudflareAgentTool {
    const execute = tool.execute;
    if (!execute) return tool;
    return {
      ...tool,
      execute: async (input: unknown, options: CloudflareToolExecutionOptions): Promise<unknown> => {
        const args = asRecord(input);
        // Outside the try, like every other adapter: a governance refusal is
        // not a tool failure, and the engine has already audited the decision.
        await core.enforce(name, args);
        try {
          const output = await execute(input, options);
          const scanned = await scanOutput(name, args, output);
          await core.audit(name, "success");
          return scanned;
        } catch (error) {
          await core.audit(name, "failure", {
            error: error instanceof Error ? error.message : String(error),
          });
          throw error;
        }
      },
    };
  }

  const governed: Record<string, CloudflareAgentTool> = {};
  for (const [name, tool] of Object.entries(tools)) governed[name] = wrap(name, tool);

  async function needsApproval(
    toolName: string,
    input?: Record<string, unknown>,
  ): Promise<boolean> {
    const decision = await core.enforceStage("process", {
      tool: toolName,
      ...(input ? { input } : {}),
    });
    return decision.outcome === "require_approval";
  }

  return {
    tools: governed as T,
    needsApproval,
    needsApprovalFor: (toolName: string) => (input: unknown) => {
      const args = asRecord(input);
      return needsApproval(toolName, args);
    },
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
