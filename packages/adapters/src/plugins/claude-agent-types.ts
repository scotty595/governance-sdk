/**
 * Structural types for the Claude Agent SDK (`@anthropic-ai/claude-agent-sdk`).
 *
 * Mirrored, never imported: this package has zero runtime dependencies, so the
 * adapter describes the SDK's shapes structurally and the real SDK's objects
 * satisfy them by construction. `createClaudeAgentGovernance()`'s return value
 * is assignable straight into the `options` bag of `query()`.
 *
 * ## What is and is not verified
 *
 * Nothing here was checked against an installed copy: the SDK is not a
 * dependency of this repository and no copy is vendored. These types describe
 * the SDK's documented surface, narrowed to the fields the adapter actually
 * reads or writes. Where the exact shape could not be pinned down, the type is
 * the widest thing that is certainly true (`unknown`) rather than a guess, and
 * says so at the field.
 *
 * The consequence of getting one of these wrong is a compile error in the
 * host's `query({ options })` call, not a governance bypass — every decision
 * is made by the kernel from a context the adapter core assembled, and the
 * types below only describe how that decision is handed back to the SDK.
 */

import type { GovernanceInstance, AuditEvent } from "@governance-sdk/core";
import type { EnforcementDecision } from "@governance-sdk/core/policy.js";
import type { AdapterConfig, AdapterCore } from "./adapter-core.js";
import type { PrePostResult } from "./pre-post-enforce.js";

// ─── SDK shapes ─────────────────────────────────────────────

/** A tool's arguments as the SDK hands them to a permission callback. */
export type ClaudeAgentToolInput = Record<string, unknown>;

/**
 * The trailing options argument the SDK passes to `canUseTool` and to every
 * hook callback. Only `signal` is relied on (and only by hosts — the adapter
 * itself never aborts); anything else the SDK adds arrives structurally.
 */
export interface ClaudeAgentCallbackOptions {
  signal: AbortSignal;
  /**
   * Permission suggestions the SDK may pass alongside the request. Left
   * `unknown`: the element shape is not verified, and the adapter never reads
   * it, so narrowing it would only risk rejecting a valid caller.
   */
  suggestions?: unknown;
}

/** `canUseTool` allowing the call, optionally with rewritten arguments. */
export interface ClaudeAgentPermissionAllow {
  behavior: "allow";
  updatedInput: ClaudeAgentToolInput;
  /** Permission-rule updates. `unknown[]`: shape not verified, never written. */
  updatedPermissions?: unknown[];
}

/** `canUseTool` refusing the call. `message` is what the model is told. */
export interface ClaudeAgentPermissionDeny {
  behavior: "deny";
  message: string;
  /** Ask the SDK to interrupt the turn rather than let the model retry. */
  interrupt?: boolean;
}

export type ClaudeAgentPermissionResult =
  | ClaudeAgentPermissionAllow
  | ClaudeAgentPermissionDeny;

/**
 * What this adapter returns: the SDK's own result plus the decision behind it,
 * so a host can read `approvalId`, `ruleId` or `remedy` without parsing the
 * message. The extra key is inert for the SDK, which reads `behavior` and the
 * fields its own union declares.
 */
export type GovernedPermissionResult = ClaudeAgentPermissionResult & {
  decision: EnforcementDecision;
};

export type ClaudeAgentCanUseTool = (
  toolName: string,
  input: ClaudeAgentToolInput,
  options: ClaudeAgentCallbackOptions,
) => Promise<ClaudeAgentPermissionResult>;

/** Fields every hook input carries. Only `hook_event_name` is depended on. */
export interface ClaudeAgentHookInputBase {
  hook_event_name: string;
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  permission_mode?: string;
}

export interface ClaudeAgentPreToolUseInput extends ClaudeAgentHookInputBase {
  hook_event_name: "PreToolUse";
  tool_name: string;
  /** `unknown` because a tool's input is only a record by convention. */
  tool_input: unknown;
}

export interface ClaudeAgentPostToolUseInput extends ClaudeAgentHookInputBase {
  hook_event_name: "PostToolUse";
  tool_name: string;
  tool_input: unknown;
  /** Whatever the tool returned. Any shape — `scanResult()` extracts text. */
  tool_response: unknown;
}

/**
 * A hook's return value. Every field is optional, so the adapter's outputs are
 * valid whichever subset a given SDK version reads. `decision: "block"` and
 * `continue: false` are both set on a refusal for the same reason.
 */
export interface ClaudeAgentHookOutput {
  continue?: boolean;
  decision?: "approve" | "block";
  stopReason?: string;
  systemMessage?: string;
  suppressOutput?: boolean;
  /**
   * Per-event extras (`hookEventName` plus event-specific keys). Left as a
   * loose record: the union is versioned and the adapter never writes it.
   */
  hookSpecificOutput?: Record<string, unknown>;
}

export type ClaudeAgentHookCallback<TInput> = (
  input: TInput,
  toolUseId: string | undefined,
  options: ClaudeAgentCallbackOptions,
) => Promise<ClaudeAgentHookOutput>;

/**
 * The SDK groups hook callbacks under an optional tool-name matcher. This is
 * the shape the adapter is least sure of — some hosts wire a bare callback per
 * event instead. `createClaudeAgentGovernance()` therefore returns the raw
 * callbacks (`preToolUse`, `postToolUse`) as well as this grouped `hooks`
 * object, so either wiring is a one-liner and neither needs a cast.
 */
export interface ClaudeAgentHookMatcher<TInput> {
  /** Tool-name matcher (regex source in the SDK). Omitted means "every tool". */
  matcher?: string;
  hooks: Array<ClaudeAgentHookCallback<TInput>>;
}

export interface ClaudeAgentHooks {
  PreToolUse: Array<ClaudeAgentHookMatcher<ClaudeAgentPreToolUseInput>>;
  PostToolUse: Array<ClaudeAgentHookMatcher<ClaudeAgentPostToolUseInput>>;
}

// ─── Configuration ──────────────────────────────────────────

/**
 * Extends the shared `AdapterConfig`, so beyond the fields below it accepts
 * every cross-adapter option: `agentId`, `agentName`, `owner`, `framework`,
 * `metadata`, `actionMapper`, `sessionTokenTracker`, the `onBlocked` /
 * `onDecision` / `onWarn` / `onMask` / `onApprovalRequired` callbacks, plus
 * `toolTiers` (consequence tiers for `requireTierApproval()`), `trackTaint`
 * (provenance carried from a scanned tool result onto later calls, for
 * `blockTaintedTools()`) and `toolFieldExtraction` (map tool arguments onto
 * `ctx.targetPath` / `ctx.targetUrl` so `scope_boundary` and
 * `network_allowlist` match).
 */
export interface ClaudeAgentGovernanceConfig extends AdapterConfig {
  /** Tool names to declare at registration. The SDK's tool set is dynamic. */
  tools?: string[];
  /**
   * Run every `PostToolUse` result through the policy engine at stage
   * `tool_result`. Default `true` — the same default the Mastra processor,
   * Genkit and OpenAI Agents adapters use.
   */
  scanToolResults?: boolean;
  /** Threshold for the local injection signal on tool results. Default 0.5. */
  toolResultInjectionThreshold?: number;
  /**
   * Which keys of a tool's input hold governable text, most specific first.
   * The first key present with a non-empty string value becomes
   * `ctx.inputText` — which is what content rules scan and what a `mask`
   * outcome rewrites. Default:
   * `["message", "prompt", "text", "content", "command", "query"]`.
   */
  inputTextFields?: string[];
  /**
   * Build the message the model sees on a deny. Default: the decision's
   * reason, plus its remedy after an em dash when the engine supplied one.
   */
  denyMessage?: (decision: EnforcementDecision, toolName: string) => string;
}

// ─── Result ─────────────────────────────────────────────────

export interface ClaudeAgentGovernanceResult {
  /**
   * Drop into `query({ options: { canUseTool } })`. Denies on `block` and on
   * `require_approval`; allows otherwise, rewriting the text field on `mask`.
   */
  canUseTool: (
    toolName: string,
    input: ClaudeAgentToolInput,
    options?: ClaudeAgentCallbackOptions,
  ) => Promise<GovernedPermissionResult>;
  /** Drop into `query({ options: { hooks } })`. */
  hooks: ClaudeAgentHooks;
  /** The same callbacks ungrouped, for hosts that wire hooks differently. */
  preToolUse: (
    input: ClaudeAgentPreToolUseInput,
    toolUseId?: string,
    options?: ClaudeAgentCallbackOptions,
  ) => Promise<ClaudeAgentHookOutput>;
  postToolUse: (
    input: ClaudeAgentPostToolUseInput,
    toolUseId?: string,
    options?: ClaudeAgentCallbackOptions,
  ) => Promise<ClaudeAgentHookOutput>;
  /** Prompt text through the `preprocess` stage. Throws on block/approval. */
  preprocess: (text: string) => Promise<PrePostResult>;
  /** Final output text through the `postprocess` stage. Same contract. */
  postprocess: (text: string) => Promise<PrePostResult>;
  agentId: string;
  score: number;
  level: number;
  governance: GovernanceInstance;
  /** The shared adapter kernel, for hosts that need a stage the SDK lacks. */
  core: AdapterCore;
  /** Imperative escape hatch — throws on block, like every other adapter. */
  enforce: (toolName: string, input?: Record<string, unknown>) => Promise<EnforcementDecision>;
  audit: (toolName: string, outcome: "success" | "failure", detail?: Record<string, unknown>) => Promise<AuditEvent>;
}
