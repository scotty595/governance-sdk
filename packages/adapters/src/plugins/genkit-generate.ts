/**
 * governance-sdk Google Genkit — ai.generate / ai.generateStream wrappers (pre/post)
 *
 * Companion to `governGenkitTools` / `governGenkitFlow` in `genkit.ts`.
 * Wraps Genkit's `generate` call shapes:
 *
 *   - `generate(opts)` → Promise<GenerateResponse>  (non-streaming)
 *   - `generateStream(opts)` → { stream, response }  (streaming)
 *
 * Preprocess runs on the last user message / prompt; postprocess runs on
 * the assembled response text (or streamed chunks via enforcePostprocessStream).
 *
 * @example
 * ```ts
 * import { genkit } from 'genkit';
 * import { createGovernance } from 'governance-sdk';
 * import { createGovernedGenerate } from 'governance-sdk/plugins/genkit';
 *
 * const ai = genkit({ plugins: [...] });
 * const { id: agentId } = await gov.register({
 *   name: 'genkit', framework: 'genkit', owner: 'team',
 * });
 * const generate = createGovernedGenerate(ai.generate.bind(ai), gov, { agentId });
 * const res = await generate({ model: geminiPro, prompt: 'hi' });
 * ```
 */

import type { GovernanceInstance } from "@governance-sdk/core";
import type { OutcomeCallbacks } from "./outcome-handler.js";
import { enforcePreprocess, enforcePostprocess } from "./pre-post-enforce.js";
import { enforcePostprocessStream } from "./pre-post-stream.js";
import type { StreamMode } from "./pre-post-stream.js";
import {
  contentToText as flattenContent,
  extractLastText,
  replaceLastText,
  type TextMessage,
} from "./text-extract.js";

// ─── Types ──────────────────────────────────────────────────────

/** Minimal Genkit GenerateOptions shape. */
export interface GenkitGenerateOptions {
  model?: unknown;
  prompt?: unknown;
  messages?: Array<{ role: string; content: unknown }>;
  [key: string]: unknown;
}

/** Minimal Genkit GenerateResponse shape. */
export interface GenkitGenerateResponse {
  text?: string;
  message?: { role?: string; content?: unknown };
  usage?: {
    inputTokens?: number;
    outputTokens?: number;
    totalTokens?: number;
    [k: string]: unknown;
  };
  [key: string]: unknown;
}

/** Minimal Genkit streaming chunk shape. */
export interface GenkitStreamChunk {
  text?: string;
  content?: Array<{ text?: string; [k: string]: unknown }>;
  [key: string]: unknown;
}

/** Minimal Genkit streaming response shape. */
export interface GenkitGenerateStreamResponse {
  stream: AsyncIterable<GenkitStreamChunk>;
  response: Promise<GenkitGenerateResponse>;
  [key: string]: unknown;
}

export interface GenkitGenerateConfig extends OutcomeCallbacks {
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
  preprocess?: boolean;
  postprocess?: boolean;
  metadata?: Record<string, unknown>;
  sessionTokenTracker?: () => number;
  streamMode?: StreamMode;
  streamLookbackChunks?: number;
  streamLookbackChars?: number;
}

// ─── Non-streaming wrapper ─────────────────────────────────────

export function createGovernedGenerate(
  generate: (opts: GenkitGenerateOptions) => Promise<GenkitGenerateResponse>,
  governance: GovernanceInstance,
  config: GenkitGenerateConfig,
): (opts: GenkitGenerateOptions) => Promise<GenkitGenerateResponse> {
  const callbacks: OutcomeCallbacks = config;
  const runPre = config.preprocess ?? true;
  const runPost = config.postprocess ?? true;

  return async (opts) => {
    let working = opts;

    if (runPre) {
      const text = extractUserText(opts);
      if (text) {
        const pre = await enforcePreprocess(governance, text, {
          agentId: config.agentId,
          agentName: config.agentName,
          agentLevel: config.agentLevel,
          metadata: config.metadata,
          sessionTokensUsed: config.sessionTokenTracker?.(),
          callbacks,
          toolName: "genkit.generate:pre",
        });
        if (pre.text !== text) working = replaceUserText(opts, pre.text);
      }
    }

    const response = await generate(working);
    if (!runPost) return response;

    const outText = extractResponseText(response);
    if (!outText) return response;

    const post = await enforcePostprocess(governance, outText, {
      agentId: config.agentId,
      agentName: config.agentName,
      agentLevel: config.agentLevel,
      metadata: config.metadata,
      outputTokenCount: response.usage?.outputTokens,
      sessionTokensUsed: config.sessionTokenTracker?.(),
      callbacks,
      toolName: "genkit.generate:post",
    });

    if (post.text === outText) return response;
    return replaceResponseText(response, post.text);
  };
}

// ─── Streaming wrapper ─────────────────────────────────────────

export function createGovernedGenerateStream(
  generateStream: (
    opts: GenkitGenerateOptions,
  ) => GenkitGenerateStreamResponse | Promise<GenkitGenerateStreamResponse>,
  governance: GovernanceInstance,
  config: GenkitGenerateConfig,
): (opts: GenkitGenerateOptions) => Promise<GenkitGenerateStreamResponse> {
  const callbacks: OutcomeCallbacks = config;
  const runPre = config.preprocess ?? true;
  const runPost = config.postprocess ?? true;

  return async (opts) => {
    let working = opts;

    if (runPre) {
      const text = extractUserText(opts);
      if (text) {
        const pre = await enforcePreprocess(governance, text, {
          agentId: config.agentId,
          agentName: config.agentName,
          agentLevel: config.agentLevel,
          metadata: config.metadata,
          sessionTokensUsed: config.sessionTokenTracker?.(),
          callbacks,
          toolName: "genkit.generateStream:pre",
        });
        if (pre.text !== text) working = replaceUserText(opts, pre.text);
      }
    }

    const upstream = await generateStream(working);

    if (!runPost) return upstream;

    const guarded = enforcePostprocessStream(governance, upstream.stream, {
      agentId: config.agentId,
      agentName: config.agentName,
      agentLevel: config.agentLevel,
      metadata: config.metadata,
      sessionTokensUsed: config.sessionTokenTracker?.(),
      callbacks,
      toolName: "genkit.generateStream",
      streamMode: config.streamMode,
      streamLookbackChunks: config.streamLookbackChunks,
      streamLookbackChars: config.streamLookbackChars,
      extractText: (c) => extractChunkText(c),
      buildMaskedChunk: (orig, masked) => setChunkText(orig, masked),
    });

    return { ...upstream, stream: guarded };
  };
}

// ─── Helpers ────────────────────────────────────────────────────

/**
 * Genkit content parts carry `{ text }` with no `type` discriminator, so tag
 * them before handing the value to the shared extractor (which keys off
 * `type: "text"`, the shape every other framework uses).
 */
function asTextParts(content: unknown): unknown {
  if (!Array.isArray(content)) return content;
  return content.map((p) =>
    p && typeof p === "object" && typeof (p as { text?: unknown }).text === "string"
      ? { type: "text", ...(p as object) }
      : p,
  );
}

function contentToText(content: unknown): string {
  return flattenContent(asTextParts(content));
}

function toTextMessages(messages: Array<{ role: string; content: unknown }>): TextMessage[] {
  return messages.map((m) => ({ role: m.role, content: asTextParts(m.content) }));
}

function extractUserText(opts: GenkitGenerateOptions): string {
  if (typeof opts.prompt === "string") return opts.prompt;
  if (Array.isArray(opts.messages) && opts.messages.some((m) => m.role === "user")) {
    return extractLastText(toTextMessages(opts.messages));
  }
  if (opts.prompt && typeof opts.prompt === "object") {
    return contentToText(opts.prompt);
  }
  return "";
}

function replaceUserText(
  opts: GenkitGenerateOptions,
  newText: string,
): GenkitGenerateOptions {
  if (typeof opts.prompt === "string") return { ...opts, prompt: newText };
  if (Array.isArray(opts.messages)) {
    return { ...opts, messages: replaceLastText(opts.messages, newText) };
  }
  return { ...opts, prompt: newText };
}

function extractResponseText(response: GenkitGenerateResponse): string {
  if (typeof response.text === "string" && response.text) return response.text;
  if (response.message?.content) return contentToText(response.message.content);
  return "";
}

function replaceResponseText(
  response: GenkitGenerateResponse,
  newText: string,
): GenkitGenerateResponse {
  const next: GenkitGenerateResponse = { ...response };
  if (typeof response.text === "string") next.text = newText;
  if (response.message) {
    next.message = { ...response.message, content: newText };
  }
  return next;
}

function extractChunkText(chunk: GenkitStreamChunk): string {
  if (typeof chunk.text === "string") return chunk.text;
  if (Array.isArray(chunk.content)) {
    return chunk.content
      .map((p) => (typeof p.text === "string" ? p.text : ""))
      .filter(Boolean)
      .join("");
  }
  return "";
}

function setChunkText(
  chunk: GenkitStreamChunk,
  newText: string,
): GenkitStreamChunk {
  const next: GenkitStreamChunk = { ...chunk };
  if (typeof chunk.text === "string") next.text = newText;
  if (Array.isArray(chunk.content)) {
    next.content = chunk.content.map((p, i) =>
      i === 0 && typeof p.text === "string" ? { ...p, text: newText } : p,
    );
  }
  if (typeof chunk.text !== "string" && !Array.isArray(chunk.content)) {
    next.text = newText;
  }
  return next;
}
