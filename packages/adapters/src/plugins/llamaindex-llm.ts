/**
 * governance-sdk LlamaIndex — LLM wrapper (pre/post + streaming)
 *
 * Companion to `governLlamaTools` in `llamaindex.ts`. LlamaIndex's LLM
 * interface is `llm.chat({ messages, stream? })`:
 *
 *   - stream omitted/false → Promise<ChatResponse>
 *   - stream: true        → AsyncIterable<ChatResponseChunk>
 *
 * `wrapLlamaLLM` returns a new object with the same `chat` shape but
 * governance pre/post enforcement applied. Prototype is preserved so
 * downstream LlamaIndex code that uses `instanceof` or depends on the
 * original class keeps working.
 */

import type { GovernanceInstance } from "@governance-sdk/core";
import type { OutcomeCallbacks } from "./outcome-handler.js";
import { enforcePreprocess, enforcePostprocess } from "./pre-post-enforce.js";
import { enforcePostprocessStream } from "./pre-post-stream.js";
import type { StreamMode } from "./pre-post-stream.js";
import {
  contentToText,
  extractLastText,
  replaceLastText,
  type TextMessage,
} from "./text-extract.js";

// ─── Types ──────────────────────────────────────────────────────

/** Minimal LlamaIndex ChatMessage shape. */
export interface LlamaChatMessage {
  role: string;
  content: unknown;
  [key: string]: unknown;
}

export interface LlamaChatRequest {
  messages: LlamaChatMessage[];
  stream?: boolean;
  [key: string]: unknown;
}

export interface LlamaChatResponse {
  message?: LlamaChatMessage;
  raw?: unknown;
  [key: string]: unknown;
}

export interface LlamaChatResponseChunk {
  delta?: string;
  raw?: unknown;
  [key: string]: unknown;
}

/**
 * Minimal LlamaIndex LLM shape. `chat` returns one of:
 *   - Promise<LlamaChatResponse>          (stream omitted or false)
 *   - AsyncIterable<LlamaChatResponseChunk> (stream: true)
 */
export interface LlamaLLM {
  chat: (
    request: LlamaChatRequest,
  ) => Promise<LlamaChatResponse> | AsyncIterable<LlamaChatResponseChunk>;
  [key: string]: unknown;
}

export interface LlamaLLMConfig extends OutcomeCallbacks {
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

// ─── Main Export ────────────────────────────────────────────────

export function wrapLlamaLLM<T extends LlamaLLM>(
  llm: T,
  governance: GovernanceInstance,
  config: LlamaLLMConfig,
): T {
  const callbacks: OutcomeCallbacks = config;
  const runPre = config.preprocess ?? true;
  const runPost = config.postprocess ?? true;

  // Preserve prototype so LlamaIndex's instanceof / tagging stays intact.
  const wrapped: LlamaLLM = Object.create(Object.getPrototypeOf(llm) as object);
  Object.assign(wrapped, llm);

  wrapped.chat = function (
    request: LlamaChatRequest,
  ): Promise<LlamaChatResponse> | AsyncIterable<LlamaChatResponseChunk> {
    if (request.stream) {
      return wrapStreamChat(llm, request, governance, config, callbacks, runPre, runPost);
    }
    return wrapChat(llm, request, governance, config, callbacks, runPre, runPost);
  };

  return wrapped as T;
}

// ─── Non-streaming ─────────────────────────────────────────────

async function wrapChat(
  llm: LlamaLLM,
  request: LlamaChatRequest,
  governance: GovernanceInstance,
  config: LlamaLLMConfig,
  callbacks: OutcomeCallbacks,
  runPre: boolean,
  runPost: boolean,
): Promise<LlamaChatResponse> {
  let working = request;

  if (runPre) {
    const text = extractLastText(toTextMessages(request.messages));
    if (text) {
      const pre = await enforcePreprocess(governance, text, {
        agentId: config.agentId,
        agentName: config.agentName,
        agentLevel: config.agentLevel,
        metadata: config.metadata,
        sessionTokensUsed: config.sessionTokenTracker?.(),
        callbacks,
        toolName: "llamaindex.chat:pre",
      });
      if (pre.text !== text) {
        working = { ...request, messages: replaceLastText(request.messages, pre.text) };
      }
    }
  }

  const response = (await llm.chat(working)) as LlamaChatResponse;
  if (!runPost) return response;

  const outText = messageContentToText(response.message?.content);
  if (!outText) return response;

  const post = await enforcePostprocess(governance, outText, {
    agentId: config.agentId,
    agentName: config.agentName,
    agentLevel: config.agentLevel,
    metadata: config.metadata,
    sessionTokensUsed: config.sessionTokenTracker?.(),
    callbacks,
    toolName: "llamaindex.chat:post",
  });

  if (post.text === outText) return response;
  return {
    ...response,
    message: { ...(response.message ?? { role: "assistant", content: "" }), content: post.text },
  };
}

// ─── Streaming ─────────────────────────────────────────────────

async function* wrapStreamChat(
  llm: LlamaLLM,
  request: LlamaChatRequest,
  governance: GovernanceInstance,
  config: LlamaLLMConfig,
  callbacks: OutcomeCallbacks,
  runPre: boolean,
  runPost: boolean,
): AsyncIterable<LlamaChatResponseChunk> {
  let working = request;

  if (runPre) {
    const text = extractLastText(toTextMessages(request.messages));
    if (text) {
      const pre = await enforcePreprocess(governance, text, {
        agentId: config.agentId,
        agentName: config.agentName,
        agentLevel: config.agentLevel,
        metadata: config.metadata,
        sessionTokensUsed: config.sessionTokenTracker?.(),
        callbacks,
        toolName: "llamaindex.chat.stream:pre",
      });
      if (pre.text !== text) {
        working = { ...request, messages: replaceLastText(request.messages, pre.text) };
      }
    }
  }

  const upstream = llm.chat(working) as AsyncIterable<LlamaChatResponseChunk>;
  if (!runPost) {
    yield* upstream;
    return;
  }

  yield* enforcePostprocessStream(governance, upstream, {
    agentId: config.agentId,
    agentName: config.agentName,
    agentLevel: config.agentLevel,
    metadata: config.metadata,
    sessionTokensUsed: config.sessionTokenTracker?.(),
    callbacks,
    toolName: "llamaindex.chat.stream",
    streamMode: config.streamMode,
    streamLookbackChunks: config.streamLookbackChunks,
    streamLookbackChars: config.streamLookbackChars,
    extractText: (c) => c.delta ?? "",
    buildMaskedChunk: (orig, masked) => ({ ...orig, delta: masked }),
  });
}

// ─── Helpers ───────────────────────────────────────────────────
// Message extraction and shape-preserving replacement live in
// text-extract.ts. LlamaIndex content parts carry `{ text }` with no `type`
// discriminator, so tag them before handing the value to the shared
// extractor, which keys off `type: "text"` — the shape every other
// framework uses.

function asTextParts(content: unknown): unknown {
  if (!Array.isArray(content)) return content;
  return content.map((p) =>
    p && typeof p === "object" && typeof (p as { text?: unknown }).text === "string"
      ? { type: "text", ...(p as object) }
      : p,
  );
}

function toTextMessages(messages: LlamaChatMessage[]): TextMessage[] {
  return messages.map((m) => ({ role: m.role, content: asTextParts(m.content) }));
}

function messageContentToText(content: unknown): string {
  return contentToText(asTextParts(content));
}
