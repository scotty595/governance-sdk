/**
 * governance-sdk Mistral — chat.complete + chat.stream wrappers (pre/post)
 *
 * Companion to `governMistralTools` in `mistral.ts`. Provides two wrappers:
 *
 *   - `createGovernedChat(client.chat, gov, config)` wraps `chat.complete`
 *     with preprocess on the last user message and postprocess on the
 *     assembled response. Signature-compatible with the underlying SDK.
 *
 *   - `createGovernedChatStream(client.chat.stream.bind(client.chat), gov, config)`
 *     wraps the streaming variant. Text deltas route through
 *     enforcePostprocessStream with configurable mode (buffered/sliding/per-chunk).
 *
 * Structural typing keeps this SDK-version-agnostic and zero-runtime-deps.
 */

import type { GovernanceInstance } from "../index";
import type { OutcomeCallbacks } from "./outcome-handler.js";
import { enforcePreprocess, enforcePostprocess } from "./pre-post-enforce.js";
import { enforcePostprocessStream } from "./pre-post-stream.js";
import type { StreamMode } from "./pre-post-stream.js";
import { contentToText, extractLastText, replaceLastText } from "./text-extract.js";

// ─── Types ──────────────────────────────────────────────────────

export interface MistralChatClient {
  complete: (params: MistralChatParams) => Promise<MistralChatResponse>;
  stream?: (params: MistralChatParams) => AsyncIterable<MistralStreamEvent>;
}

export interface MistralChatParams {
  model: string;
  messages: Array<{ role: string; content: unknown }>;
  [key: string]: unknown;
}

export interface MistralChatResponse {
  id?: string;
  choices?: Array<{
    message?: { role?: string; content?: unknown };
    [k: string]: unknown;
  }>;
  usage?: { prompt_tokens?: number; completion_tokens?: number; [k: string]: unknown };
  [key: string]: unknown;
}

export interface MistralStreamEvent {
  data?: {
    id?: string;
    choices?: Array<{
      delta?: { content?: string; role?: string; [k: string]: unknown };
      [k: string]: unknown;
    }>;
    [k: string]: unknown;
  };
  [key: string]: unknown;
}

export interface MistralMessagesConfig extends OutcomeCallbacks {
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

// ─── createGovernedChat (non-streaming) ────────────────────────

export function createGovernedChat(
  chat: Pick<MistralChatClient, "complete">,
  governance: GovernanceInstance,
  config: MistralMessagesConfig,
): Pick<MistralChatClient, "complete"> {
  const callbacks: OutcomeCallbacks = config;
  const runPre = config.preprocess ?? true;
  const runPost = config.postprocess ?? true;

  return {
    complete: async (params) => {
      let workingParams = params;

      if (runPre) {
        const text = extractLastText(params.messages);
        if (text) {
          const pre = await enforcePreprocess(governance, text, {
            agentId: config.agentId,
            agentName: config.agentName,
            agentLevel: config.agentLevel,
            metadata: config.metadata,
            sessionTokensUsed: config.sessionTokenTracker?.(),
            callbacks,
            toolName: "mistral.chat.complete:pre",
          });
          if (pre.text !== text) {
            workingParams = {
              ...params,
              messages: replaceLastText(params.messages, pre.text),
            };
          }
        }
      }

      const response = await chat.complete(workingParams);

      if (!runPost) return response;
      const outText = extractResponseText(response);
      if (!outText) return response;

      const post = await enforcePostprocess(governance, outText, {
        agentId: config.agentId,
        agentName: config.agentName,
        agentLevel: config.agentLevel,
        metadata: config.metadata,
        outputTokenCount: response.usage?.completion_tokens,
        sessionTokensUsed: config.sessionTokenTracker?.(),
        callbacks,
        toolName: "mistral.chat.complete:post",
      });

      if (post.text === outText) return response;
      return replaceResponseText(response, post.text);
    },
  };
}

// ─── createGovernedChatStream (streaming) ─────────────────────

export function createGovernedChatStream(
  streamFn: (params: MistralChatParams) => AsyncIterable<MistralStreamEvent>,
  governance: GovernanceInstance,
  config: MistralMessagesConfig,
): (params: MistralChatParams) => AsyncIterable<MistralStreamEvent> {
  return (params) => wrapGovernedMistralStream(streamFn, governance, config, params);
}

async function* wrapGovernedMistralStream(
  streamFn: (params: MistralChatParams) => AsyncIterable<MistralStreamEvent>,
  governance: GovernanceInstance,
  config: MistralMessagesConfig,
  params: MistralChatParams,
): AsyncIterable<MistralStreamEvent> {
  const callbacks: OutcomeCallbacks = config;
  const runPre = config.preprocess ?? true;
  const runPost = config.postprocess ?? true;

  let workingParams = params;
  if (runPre) {
    const text = extractLastText(params.messages);
    if (text) {
      const pre = await enforcePreprocess(governance, text, {
        agentId: config.agentId,
        agentName: config.agentName,
        agentLevel: config.agentLevel,
        metadata: config.metadata,
        sessionTokensUsed: config.sessionTokenTracker?.(),
        callbacks,
        toolName: "mistral.chat.stream:pre",
      });
      if (pre.text !== text) {
        workingParams = {
          ...params,
          messages: replaceLastText(params.messages, pre.text),
        };
      }
    }
  }

  const source = streamFn(workingParams);
  if (!runPost) {
    yield* source;
    return;
  }

  // Route through the shared streaming enforcer. Mistral's delta text is on
  // event.data.choices[0].delta.content — we extract that and rebuild on mask.
  yield* enforcePostprocessStream(governance, source, {
    agentId: config.agentId,
    agentName: config.agentName,
    agentLevel: config.agentLevel,
    metadata: config.metadata,
    sessionTokensUsed: config.sessionTokenTracker?.(),
    callbacks,
    toolName: "mistral.chat.stream",
    streamMode: config.streamMode,
    streamLookbackChunks: config.streamLookbackChunks,
    streamLookbackChars: config.streamLookbackChars,
    extractText: (ev) => ev.data?.choices?.[0]?.delta?.content ?? "",
    buildMaskedChunk: (orig, masked) => {
      const nextData = { ...(orig.data ?? {}) };
      const choices = (orig.data?.choices ?? []).map((c, i) =>
        i === 0
          ? { ...c, delta: { ...(c.delta ?? {}), content: masked } }
          : c,
      );
      nextData.choices = choices;
      return { ...orig, data: nextData };
    },
  });
}

// ─── Helpers ────────────────────────────────────────────────────
// Request-message extraction and shape-preserving replacement live in
// text-extract.ts; only the Mistral response envelope is handled here.

function extractResponseText(response: MistralChatResponse): string {
  return contentToText(response.choices?.[0]?.message?.content);
}

function replaceResponseText(
  response: MistralChatResponse,
  newText: string,
): MistralChatResponse {
  const choices = (response.choices ?? []).map((c, i) => {
    if (i !== 0) return c;
    const msg = c.message ?? {};
    if (msg.content == null) return { ...c, message: { ...msg, content: newText } };
    const [replaced] = replaceLastText([{ role: "assistant", content: msg.content }], newText, "assistant");
    return { ...c, message: { ...msg, content: replaced.content } };
  });
  return { ...response, choices };
}
