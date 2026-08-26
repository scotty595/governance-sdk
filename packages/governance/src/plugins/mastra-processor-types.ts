/**
 * Types for the Mastra Processor governance integration.
 *
 * Mirrors Mastra's Processor interface without requiring @mastra/core
 * as a dependency. Structurally compatible at runtime.
 *
 * Updated for Mastra v1.10+ (March 2026): ProcessOutputStepArgs
 * inherits from ProcessorMessageContext → ProcessorContext.
 *
 * Updated for governance-sdk 0.8.0: adds ProcessInputArgs and
 * ProcessOutputResultArgs mirrors so the processor can implement
 * processInput() (preprocess on user messages) and processOutputResult()
 * (postprocess on the agent's final output) in addition to the existing
 * processOutputStep() (tool-call enforcement).
 *
 * Updated for governance-sdk 0.21.0: adds the ProcessToolResultArgs mirror
 * for Mastra's `processToolResult` lifecycle hook (@mastra/core >= 1.57,
 * mastra-ai/mastra#16012) so tool returns are scanned at the `tool_result`
 * stage automatically — no `wrapTool` needed on those versions.
 */

import type { EnforcementDecision, PolicyAction } from "../policy";
import type { AgentFramework } from "../types";
import type { ToolFieldExtractionRegistry } from "./mastra-processor-tool-wrap.js";

// ─── Mastra Processor Types ────────────────────────────────────

export interface MastraToolCallInfo {
  toolName: string;
  args: unknown;
  toolCallId: string;
}

export interface MastraAbortOptions<TMetadata = unknown> {
  retry?: boolean;
  metadata?: TMetadata;
}

export interface GovernanceViolation {
  toolName: string;
  ruleId: string;
  reason: string;
  decision: EnforcementDecision;
}

export type MastraAbortFn = (
  reason?: string,
  options?: MastraAbortOptions<{ violations: GovernanceViolation[] }>,
) => never;

/** Mastra message shape (simplified — MastraDBMessage) */
export interface MastraMessage {
  role: string;
  content: unknown;
  id?: string;
}

/** Mastra stream writer for custom data chunks (ProcessorStreamWriter in SDK) */
export interface MastraStreamWriter {
  /** Emit a custom data chunk to the stream. Chunk type must start with 'data-' prefix. */
  custom<T extends { type: string }>(data: T): Promise<void>;
}

/**
 * Stage label passed to GovernanceProcessorConfig.metadataProvider.
 * Lets a single metadata-building function distinguish where it was called from.
 */
export type GovernanceStage = "preprocess" | "tool_call" | "tool_result" | "postprocess";

/**
 * Resolved generation result passed to processOutputResult.
 * Mirror of Mastra's OutputResult.
 */
export interface MastraOutputResult {
  /** The accumulated text from all steps */
  text: string;
  /** Token usage (cumulative across all steps) */
  usage?: {
    inputTokens?: number;
    outputTokens?: number;
    totalTokens?: number;
    [key: string]: unknown;
  };
  /** Why the generation finished (e.g. 'stop', 'tool-calls', 'length') */
  finishReason?: string;
  /** All LLM step results */
  steps?: unknown[];
}

/**
 * Mastra ProcessOutputStepArgs — extends ProcessorMessageContext.
 *
 * Required fields come from the Mastra ProcessorContext and
 * ProcessorMessageContext base interfaces.
 */
export interface ProcessOutputStepArgs {
  /** Tool calls made in this step (optional — absent on non-tool steps) */
  toolCalls?: MastraToolCallInfo[];
  /** Text output from the model (optional — absent on tool-only steps) */
  text?: string;
  /** Step number (0-indexed) */
  stepNumber: number;
  /** Why the model stopped generating (optional) */
  finishReason?: string;
  /** Retry count — from ProcessorContext */
  retryCount: number;
  /** Abort function — from ProcessorContext */
  abort: MastraAbortFn;
  /** All messages including latest LLM response — from ProcessorMessageContext */
  messages: MastraMessage[];
  /** Message list instance for message management */
  messageList: unknown;
  /** System messages (instructions, memory, etc.) */
  systemMessages: MastraMessage[];
  /** Step results accumulated so far */
  steps: unknown[];
  /** Cross-step processor state */
  state: Record<string, unknown>;
  /** Per-request execution metadata — from ProcessorContext (optional) */
  requestContext?: unknown;
  /** Stream writer for emitting custom data-* chunks (optional, from ProcessorContext) */
  writer?: MastraStreamWriter;
  /** Abort signal from parent agent execution (optional, from ProcessorContext) */
  abortSignal?: AbortSignal;
}

/**
 * Mastra ProcessInputArgs — runs once BEFORE the LLM is called for the
 * first time. This is where preprocess governance fires (injection scanning,
 * input blocklists, input length, prompt-injection ML detection).
 *
 * Mirror of Mastra's ProcessInputArgs from @mastra/core/processors.
 */
export interface ProcessInputArgs {
  /** All messages being processed (including the latest user input) */
  messages: MastraMessage[];
  /** Message list instance for message management */
  messageList: unknown;
  /** All system messages (instructions, memory) — read/modify access */
  systemMessages: MastraMessage[];
  /** Per-processor state that persists across all method calls within this request */
  state: Record<string, unknown>;
  /** Retry count — from ProcessorContext */
  retryCount: number;
  /** Abort function — from ProcessorContext */
  abort: MastraAbortFn;
  /** Per-request execution metadata — from ProcessorContext (optional) */
  requestContext?: unknown;
  /** Stream writer for emitting custom data-* chunks (optional, from ProcessorContext) */
  writer?: MastraStreamWriter;
  /** Abort signal from parent agent execution (optional, from ProcessorContext) */
  abortSignal?: AbortSignal;
}

/**
 * Mastra ProcessOutputResultArgs — runs once AFTER the agent has finished
 * generating, with the resolved output result. This is where postprocess
 * governance fires (output filtering, PII redaction, sensitive-data masking).
 *
 * Mirror of Mastra's ProcessOutputResultArgs from @mastra/core/processors.
 */
export interface ProcessOutputResultArgs {
  /** All messages including the final assistant response */
  messages: MastraMessage[];
  /** Message list instance for message management */
  messageList: unknown;
  /** Per-processor state that persists across all method calls within this request */
  state: Record<string, unknown>;
  /** Retry count — from ProcessorContext */
  retryCount: number;
  /** Abort function — from ProcessorContext */
  abort: MastraAbortFn;
  /** Resolved generation result (final text, usage, finishReason, steps) */
  result: MastraOutputResult;
  /** Per-request execution metadata — from ProcessorContext (optional) */
  requestContext?: unknown;
  /** Stream writer for emitting custom data-* chunks (optional, from ProcessorContext) */
  writer?: MastraStreamWriter;
  /** Abort signal from parent agent execution (optional, from ProcessorContext) */
  abortSignal?: AbortSignal;
}

/**
 * A `tool-invocation` message part in result state — the payload
 * `MessageList.updateToolInvocation()` takes to replace a tool's result.
 * Mirror of the relevant member of Mastra's `MastraMessagePart` union.
 */
export interface MastraToolInvocationPart {
  type: "tool-invocation";
  toolInvocation: {
    state: "result";
    toolCallId: string;
    toolName: string;
    args: unknown;
    result: unknown;
  };
}

/**
 * The slice of Mastra's `MessageList` the tool-result hook relies on.
 * Structurally satisfied by the real `MessageList` (@mastra/core >= 1.57).
 */
export interface MastraMessageListLike {
  /**
   * Replace the result of the tool invocation with the given `toolCallId`.
   * The runtime re-reads the message list after `processToolResult` and
   * syncs the new value into the streamed `tool-result` chunk, so both the
   * next LLM turn and streaming clients see the replacement.
   * @returns true if the tool call was found and updated.
   */
  updateToolInvocation(part: MastraToolInvocationPart, metadata?: Record<string, unknown>): boolean;
}

/**
 * Mastra ProcessToolResultArgs — runs after a tool's `execute()` returns
 * successfully (or a provider-executed result arrives) and BEFORE the result
 * is appended to the message list / fed to the next LLM call. This is where
 * `tool_result`-stage governance fires (injection in returned content,
 * leaked secrets, scope/network rules keyed on the tool's args).
 *
 * Mirror of Mastra's ProcessToolResultArgs from @mastra/core/processors
 * (added in @mastra/core 1.57.0 by mastra-ai/mastra#16012). Does not fire
 * when `tool.execute()` throws.
 */
export interface ProcessToolResultArgs {
  /** All messages including the assistant message carrying the tool call */
  messages: MastraMessage[];
  /** Message list — call `updateToolInvocation` to replace the result */
  messageList: MastraMessageListLike;
  /** Step number (0-indexed) */
  stepNumber: number;
  /** Name of the tool that was executed (the key in the agent's tools record) */
  toolName: string;
  /** Unique identifier for this specific tool call */
  toolCallId: string;
  /** Arguments the LLM passed to the tool */
  args: unknown;
  /** Value the tool returned (client tools: post-`ensureSerializable`; provider tools: raw) */
  result: unknown;
  /** True when a provider executed the tool (e.g. Anthropic `web_search`) */
  providerExecuted?: boolean;
  /** System messages (instructions, memory, etc.) */
  systemMessages: MastraMessage[];
  /** Step results accumulated so far */
  steps: unknown[];
  /** Per-processor state that persists across all method calls within this request */
  state: Record<string, unknown>;
  /** Retry count — from ProcessorContext */
  retryCount: number;
  /** Abort function — from ProcessorContext (Mastra tripwire) */
  abort: MastraAbortFn;
  /** Per-request execution metadata — from ProcessorContext (optional) */
  requestContext?: unknown;
  /** Stream writer for emitting custom data-* chunks (optional, from ProcessorContext) */
  writer?: MastraStreamWriter;
  /** Abort signal from parent agent execution (optional, from ProcessorContext) */
  abortSignal?: AbortSignal;
}

/** What the tool-result callbacks receive alongside the decision. */
export interface MastraToolResultInfo {
  toolName: string;
  toolCallId: string;
  args: unknown;
  /** The tool's ORIGINAL return value (before any substitution or masking). */
  result: unknown;
  providerExecuted?: boolean;
}

/**
 * Union of all argument shapes a `metadataProvider` callback may receive.
 * The `stage` parameter tells the callback which lifecycle method called it.
 */
export type GovernanceLifecycleArgs =
  | ProcessInputArgs
  | ProcessOutputStepArgs
  | ProcessToolResultArgs
  | ProcessOutputResultArgs;

/**
 * Mastra Processor interface — simplified for governance use.
 *
 * As of governance-sdk 0.21.0, the GovernanceProcessor implements five
 * Mastra lifecycle methods: processInput, processOutputStep,
 * processToolResult (@mastra/core >= 1.57; ignored by older versions),
 * processOutputResult, and processOutputStream (per-chunk streaming).
 * processInputStep is not implemented (agentic-loop step, not per-chunk input).
 *
 * Also supports __registerMastra (not mirrored here).
 */
export interface MastraProcessorInterface {
  readonly id: string;
  readonly name?: string;
  readonly description?: string;
  processorIndex?: number;
  /** Preprocess: runs once before the LLM is called */
  processInput?(args: ProcessInputArgs): Promise<unknown> | unknown;
  /** Per-step: runs after each LLM response, before tool execution */
  processOutputStep(args: ProcessOutputStepArgs): Promise<unknown> | unknown;
  /**
   * Tool-result: runs after each tool's execute() returns, before the LLM
   * ingests the result (@mastra/core >= 1.57). Replace the result via
   * args.messageList.updateToolInvocation(), or call args.abort() to tripwire.
   */
  processToolResult?(args: ProcessToolResultArgs): Promise<unknown> | unknown;
  /** Postprocess: runs once at the end, with the resolved output */
  processOutputResult?(args: ProcessOutputResultArgs): Promise<unknown> | unknown;
  /**
   * Per-chunk streaming: runs for each chunk during agent.stream(). Return
   * the part (optionally modified), return null/undefined to drop the chunk,
   * or call args.abort(...) to tripwire.
   */
  processOutputStream?(
    args: ProcessOutputStreamArgs,
  ): Promise<MastraStreamChunk | null | undefined> | MastraStreamChunk | null | undefined;
}

/** Minimal shape of a Mastra stream chunk we care about. */
export interface MastraStreamChunk {
  type: string;
  /** Text-delta chunks carry a `payload.text` string. */
  payload?: { text?: string; [k: string]: unknown };
  [k: string]: unknown;
}

/** Args for processOutputStream (per-chunk streaming hook). */
export interface ProcessOutputStreamArgs {
  part: MastraStreamChunk;
  streamParts?: MastraStreamChunk[];
  state?: Record<string, unknown>;
  messageList?: unknown;
  abort: (reason?: string, options?: { retry?: boolean; metadata?: unknown }) => never;
  requestContext?: unknown;
  retryCount?: number;
  writer?: unknown;
  abortSignal?: AbortSignal;
}

// ─── Processor Configuration ──────────────────────────────────

export interface GovernanceProcessorConfig {
  /**
   * Optional caller-supplied agent id. When set, the processor will
   * register with this exact id so the runtime record matches a
   * pre-existing dashboard-scanned record (e.g. Lua's `agent.agentId`
   * from `lua.skill.yaml`). When omitted, the SDK generates a UUID.
   */
  agentId?: string;
  agentName: string;
  owner: string;
  framework?: AgentFramework;
  description?: string;
  version?: string;
  channels?: string[];
  hasAuth?: boolean;
  hasGuardrails?: boolean;
  hasObservability?: boolean;
  hasAuditLog?: boolean;
  permissions?: Record<string, unknown>;
  /**
   * Static metadata merged into every enforce call's `EnforcementContext.metadata`.
   * Per-call values from `metadataProvider` take precedence on key conflicts.
   */
  metadata?: Record<string, unknown>;

  // ─── Tool-call (processOutputStep) — existing ────────────────
  onBlocked?: (decision: EnforcementDecision, toolCall: MastraToolCallInfo) => void;
  onDecision?: (decision: EnforcementDecision, toolCall: MastraToolCallInfo) => void;
  actionMapper?: (toolName: string) => PolicyAction;
  sessionTokenTracker?: () => number;
  abortOnBlock?: boolean;
  abortMessage?: (decision: EnforcementDecision, toolCall: MastraToolCallInfo) => string;
  retryOnBlock?: boolean;
  maxRetries?: number;

  // ─── Per-call metadata enrichment — 0.8.0 ────────────────────
  /**
   * Per-call metadata enrichment. Called once per enforce invocation
   * (preprocess, tool call, postprocess) and the returned object is
   * merged into the `EnforcementContext.metadata` field that the SDK
   * sends to the policy engine and the cloud audit log.
   *
   * For Mastra integrators, the `args.requestContext` field is the
   * canonical place to read per-request data (userId, channel, threadId,
   * etc.) — Mastra's RequestContext is plumbed through every processor
   * lifecycle method.
   *
   * The promise return is supported because some integrators may need
   * to look up routing data from a service. Avoid anything slow here —
   * this runs synchronously inside the agent execution path.
   */
  metadataProvider?: (
    stage: GovernanceStage,
    args: GovernanceLifecycleArgs,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>;

  // ─── Preprocess (processInput) — 0.8.0 ───────────────────────
  /**
   * Skip preprocess enforcement entirely. Default: false.
   * Useful for legacy migration paths or for replay flows where
   * governance has already approved the call out-of-band.
   */
  skipPreprocess?: boolean;
  /**
   * Fired when a preprocess rule blocks an inbound user message.
   * The second arg is the user message text that was scanned.
   */
  onPreprocessBlocked?: (decision: EnforcementDecision, message: string) => void;

  // ─── Postprocess (processOutputResult) — 0.8.0 ───────────────
  /**
   * Skip postprocess enforcement entirely. Default: false.
   */
  skipPostprocess?: boolean;
  /**
   * Fired when a postprocess rule blocks the agent's output.
   * The second arg is the agent's response text that was scanned.
   */
  onPostprocessBlocked?: (decision: EnforcementDecision, output: string) => void;

  // ─── Streaming postprocess (processOutputStream) — 0.9.0 ─────
  /**
   * Skip per-chunk streaming postprocess entirely. When true, streamed
   * chunks pass through untouched and governance only fires via
   * processOutputResult at the end of the stream. Default: false.
   */
  skipStreamPostprocess?: boolean;
  /**
   * Streaming post-scan mode. Default: "per-chunk" (Mastra's native shape).
   *   - "per-chunk": scan each chunk in isolation, mask if needed
   *   - "sliding": hold back chunks (via state) to catch cross-chunk patterns
   *   - "buffered": suppress per-chunk scanning; rely on processOutputResult instead
   */
  streamMode?: "per-chunk" | "sliding" | "buffered";
  /** Sliding mode: chunks to hold back (default 2). */
  streamLookbackChunks?: number;
  /** Sliding mode: chars to hold back (overrides chunk count when exceeded). */
  streamLookbackChars?: number;
  /** Fired when a stream chunk is blocked by a rule. */
  onStreamBlocked?: (decision: EnforcementDecision, chunkText: string) => void;

  // ─── Tool-result scanning — 0.14.0 (wrapTool) / 0.21.0 (hook) ─
  /**
   * Master switch for tool-result governance — both the automatic
   * `processToolResult` hook (@mastra/core >= 1.57) and the `wrapTool` /
   * `wrapTools` helpers. Default: `true`. Set to `false` to skip the
   * `tool_result` stage entirely (the hook returns without enforcing and
   * the wrap helpers return the tool unchanged) — useful for test
   * environments that mock tool returns and don't want the scan to run.
   *
   * Note: pre-call governance via `processOutputStep` is unaffected and
   * always runs.
   */
  scanToolResults?: boolean;
  /**
   * Per-tool override for `scanToolResults`. Keys are tool names — the
   * name Mastra reports for the call (the key in the agent's tools record)
   * for the hook, or `tool.id` for `wrapTool`. Use `"never"` to skip
   * scanning a specific tool even when `scanToolResults: true` globally.
   */
  toolResultScans?: Record<string, "always" | "never">;
  /**
   * What the `processToolResult` hook does when a `tool_result`-stage rule
   * blocks (or requires approval). Default: `"substitute"`.
   *
   *   - `"substitute"` — replace the tool's result in the message list with
   *     `{ blocked: true, reason, ruleId }` via `messageList.updateToolInvocation`.
   *     The LLM (and streaming clients) see the substitute, never the
   *     original content, and the run continues so the model can adapt.
   *     Same semantics as `wrapTool`.
   *   - `"abort"` — call `args.abort()` (Mastra tripwire). Honors
   *     `retryOnBlock` / `maxRetries`: while retries remain the abort
   *     carries `retry: true` so Mastra re-runs the step with the reason as
   *     feedback; otherwise the run halts.
   *
   * Only affects the hook. `wrapTool` always substitutes.
   */
  toolResultBlockMode?: "substitute" | "abort";
  /**
   * Fired when a `tool_result`-stage rule blocks (or requires approval on)
   * a tool's return value in the `processToolResult` hook. `info.result` is
   * the original value the tool returned.
   */
  onToolResultBlocked?: (decision: EnforcementDecision, info: MastraToolResultInfo) => void;
  /**
   * Fired after every tool-result scan in the `processToolResult` hook,
   * whatever the outcome. Use it for audit/metrics; branch on
   * `decision.outcome`.
   */
  onToolResult?: (decision: EnforcementDecision, info: MastraToolResultInfo) => void;
  /**
   * Per-tool registry mapping input arg names to EnforcementContext fields.
   * Without this, rules like `scope_boundary: { allowedPaths }` and
   * `network_allowlist: { allowedDomains }` silently never fire — the
   * engine reads `ctx.targetPath` / `ctx.targetUrl`, not raw `args.path`.
   *
   * Generic defaults cover the common conventions (`path` → `targetPath`,
   * `url` → `targetUrl`, etc.) so most tools work without an explicit
   * entry. Add a per-tool entry when args use non-standard names or to
   * map multiple args.
   */
  toolFieldExtraction?: ToolFieldExtractionRegistry;
  /**
   * Detection threshold for the local injection signal (0-1) computed by
   * `detectInjection()` and passed to the engine via `ctx.mlInjectionScore`.
   * Default 0.5. Lower = more aggressive flagging; higher = more permissive.
   */
  toolResultInjectionThreshold?: number;

  // ─── Cross-stage callbacks — 0.8.0 ───────────────────────────
  /**
   * Fired when an enforcement decision returns `outcome: require_approval`
   * at any stage. The integrator typically uses this to surface the approval
   * payload (`decision.approval`, `decision.approvalId`) to its caller.
   */
  onApprovalRequired?: (decision: EnforcementDecision, stage: GovernanceStage) => void;
  /**
   * Fired when a postprocess rule returns `outcome: mask` and the SDK
   * computed a redacted version of the output. The processor mutates the
   * latest assistant message in place AFTER this callback fires.
   */
  onMask?: (decision: EnforcementDecision, original: string, masked: string) => void;
}

// ─── Processor Stats ──────────────────────────────────────────

export interface ProcessorStats {
  totalProcessed: number;
  totalBlocked: number;
  totalAllowed: number;
  byTool: Record<string, { allowed: number; blocked: number }>;
  /** Counters for the `processToolResult` hook (tool_result stage). */
  toolResults: { scanned: number; blocked: number; masked: number };
  initializedAt: string;
}
