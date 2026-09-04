/**
 * governance-sdk Vercel AI — LanguageModelMiddleware (pre/post)
 *
 * `createGovernanceMiddleware` returns a language-model middleware object for
 * the Vercel AI SDK's `wrapLanguageModel`. It intercepts:
 *
 *   - transformParams → pre-scan last user message (injection, blocklists, ...)
 *   - wrapGenerate    → post-scan the resulting model text (masking, PII, ...)
 *   - wrapStream      → post-scan streamed text incrementally (vercel-ai-stream.ts)
 *
 * ## Version compatibility (checked against the published `ai` typings)
 *
 *   - `ai` ≥ 3.4.0 is the floor: 3.4 introduced language-model middleware as
 *     `experimental_wrapLanguageModel` (LanguageModelV1).
 *   - `ai` ≥ 4.2.0 exports the stable `wrapLanguageModel`; the `experimental_`
 *     alias remains through 4.x and is removed in 5.0.
 *   - `ai` 5.x / 6.x / 7.x (LanguageModelV2 / V3 / V4) — `wrapLanguageModel`.
 *
 * Stream text parts are recognised in both the V1 shape
 * (`{ type: 'text-delta', textDelta }`) and the V2+ shape
 * (`{ type: 'text-delta', id, delta }`). Structural typing keeps this
 * SDK-version-agnostic and zero-runtime-deps. The tool wrapper in
 * `vercel-ai.ts` types its interfaces against the `ai` 6 tool shape — see that
 * file's header; the two floors are independent.
 *
 * @example
 * ```ts
 * import { wrapLanguageModel, generateText } from 'ai'; // ai ≥ 4.2
 * // ai 3.4 – 4.1: import { experimental_wrapLanguageModel as wrapLanguageModel } from 'ai';
 * import { createGovernance } from 'governance-sdk';
 * import { createGovernanceMiddleware } from 'governance-sdk/plugins/vercel-ai';
 *
 * const gov = createGovernance({ rules: [] });
 * const { id: agentId } = await gov.register({
 *   name: 'sales', framework: 'vercel-ai', owner: 'team',
 * });
 *
 * const model = wrapLanguageModel({
 *   model: openai('gpt-4o'),
 *   middleware: createGovernanceMiddleware(gov, { agentId }),
 * });
 * ```
 */

import type { GovernanceInstance } from "../index";
import type { OutcomeCallbacks } from "./outcome-handler.js";
import { enforcePreprocess, enforcePostprocess } from "./pre-post-enforce.js";
import { buildWrapStream } from "./vercel-ai-stream.js";
import type {
  VercelStreamResult,
} from "./vercel-ai-stream.js";
import type { StreamMode } from "./pre-post-stream.js";
import { extractLastText, partsToText, replaceContentText, replaceLastText } from "./text-extract.js";

// ─── Types ──────────────────────────────────────────────────────

/** Minimal shape of a Vercel AI LanguageModelMiddleware. */
export interface VercelLanguageModelMiddleware {
  transformParams?: (options: {
    type: "generate" | "stream";
    params: VercelLanguageModelParams;
  }) => Promise<VercelLanguageModelParams>;
  wrapGenerate?: (options: {
    doGenerate: () => Promise<VercelGenerateResult>;
    params: VercelLanguageModelParams;
  }) => Promise<VercelGenerateResult>;
  wrapStream?: (options: {
    doStream: () => Promise<VercelStreamResult>;
    params: VercelLanguageModelParams;
  }) => Promise<VercelStreamResult>;
}

/** Subset of Vercel's LanguageModelV2 params we touch. */
export interface VercelLanguageModelParams {
  prompt?: Array<{ role: string; content: unknown }>;
  [key: string]: unknown;
}

/** Subset of Vercel's generate result we touch. */
export interface VercelGenerateResult {
  text?: string;
  content?: Array<{ type: string; text?: string; [k: string]: unknown }>;
  usage?: { inputTokens?: number; outputTokens?: number; [k: string]: unknown };
  [key: string]: unknown;
}

export interface VercelMiddlewareConfig extends OutcomeCallbacks {
  /**
   * Bring-your-own agent id. This wrapper never calls `gov.register()`;
   * pass the `id` returned by your own registration (or a tool adapter's
   * `agentId`) so enforcement and audit bind to that agent row.
   */
  agentId: string;
  agentName?: string;
  /**
   * Governance level for `agent_level` rules such as `requireLevel()`. Pass
   * the `level` returned by `gov.register()`; when omitted the engine
   * treats the agent as level 0 and `requireLevel(1+)` blocks every call.
   */
  agentLevel?: number;
  /** Disable pre-scan of user input (default: enabled). */
  preprocess?: boolean;
  /** Disable post-scan of model output (default: enabled). */
  postprocess?: boolean;
  /** Optional static metadata merged into every EnforcementContext. */
  metadata?: Record<string, unknown>;
  sessionTokenTracker?: () => number;
  /**
   * Streaming post-scan mode (only applies to `streamText` / wrapStream):
   *   - "buffered" (default, safest): scan full output at end, flush all at once
   *   - "sliding": hold back N chunks so patterns spanning chunk boundaries are caught
   *   - "per-chunk": scan each chunk in isolation (fastest, weakest)
   */
  streamMode?: StreamMode;
  /** Sliding mode: chunks to hold back (default 2). */
  streamLookbackChunks?: number;
  /** Sliding mode: chars to hold back (overrides chunk count when exceeded). */
  streamLookbackChars?: number;
}

// ─── Middleware ─────────────────────────────────────────────────

export function createGovernanceMiddleware(
  governance: GovernanceInstance,
  config: VercelMiddlewareConfig,
): VercelLanguageModelMiddleware {
  const callbacks: OutcomeCallbacks = config;
  const runPre = config.preprocess ?? true;
  const runPost = config.postprocess ?? true;

  return {
    transformParams: runPre
      ? async ({ params }) => {
          const text = extractLastUserText(params);
          if (!text) return params;

          const result = await enforcePreprocess(governance, text, {
            agentId: config.agentId,
            agentName: config.agentName,
            agentLevel: config.agentLevel,
            metadata: config.metadata,
            sessionTokensUsed: config.sessionTokenTracker?.(),
            callbacks,
            toolName: "vercel.transformParams",
          });

          if (result.text === text) return params;
          return replaceLastUserText(params, result.text);
        }
      : undefined,

    wrapGenerate: runPost
      ? async ({ doGenerate }) => {
          const result = await doGenerate();
          const text = extractGenerateText(result);
          if (!text) return result;

          const post = await enforcePostprocess(governance, text, {
            agentId: config.agentId,
            agentName: config.agentName,
            agentLevel: config.agentLevel,
            metadata: config.metadata,
            outputTokenCount: result.usage?.outputTokens,
            sessionTokensUsed: config.sessionTokenTracker?.(),
            callbacks,
            toolName: "vercel.wrapGenerate",
          });

          if (post.text === text) return result;
          return replaceGenerateText(result, post.text);
        }
      : undefined,

    // Streaming post-scan — lives in vercel-ai-stream.ts to respect the
    // <300 LOC per file cap.
    wrapStream: runPost ? buildWrapStream(governance, config) : undefined,
  };
}

// Re-export stream types so consumers can import via the main plugin path.
export type { VercelStreamPart, VercelStreamResult } from "./vercel-ai-stream.js";
export type { StreamMode } from "./pre-post-stream.js";

// ─── Prompt helpers ─────────────────────────────────────────────
// Message extraction and shape-preserving replacement live in
// text-extract.ts; only the Vercel params/result envelopes are handled here.

function extractLastUserText(params: VercelLanguageModelParams): string {
  return Array.isArray(params.prompt) ? extractLastText(params.prompt) : "";
}

function replaceLastUserText(
  params: VercelLanguageModelParams,
  newText: string,
): VercelLanguageModelParams {
  if (!Array.isArray(params.prompt)) return params;
  return { ...params, prompt: replaceLastText(params.prompt, newText) };
}

function extractGenerateText(result: VercelGenerateResult): string {
  if (typeof result.text === "string" && result.text) return result.text;
  return Array.isArray(result.content) ? partsToText(result.content) : "";
}

function replaceGenerateText(
  result: VercelGenerateResult,
  newText: string,
): VercelGenerateResult {
  const next: VercelGenerateResult = { ...result };
  if (typeof result.text === "string") next.text = newText;
  if (Array.isArray(result.content)) {
    next.content = replaceContentText(result.content, newText) as VercelGenerateResult["content"];
  }
  return next;
}
