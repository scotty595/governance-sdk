/**
 * governance-sdk Anthropic — messages.stream wrapper (postprocess streaming)
 *
 * Companion to `createGovernedMessages` in `anthropic-messages.ts`. The
 * Anthropic SDK exposes streaming two ways:
 *
 *   - `client.messages.stream(params)` → returns a MessageStream (async iterable
 *     of typed events). Highest level API.
 *   - `client.messages.create({ ..., stream: true })` → returns an async iterable
 *     of RawMessageStreamEvent.
 *
 * Both surface the same underlying event shape for text tokens:
 *
 *   { type: 'content_block_delta',
 *     index: number,
 *     delta: { type: 'text_delta', text: string } }
 *
 * `wrapGovernedMessageStream` wraps either iterable, runs preprocess on the
 * last user message once up-front, then routes `text_delta` events through
 * `enforcePostprocessStream`. Non-text events pass through untouched.
 */

import type { GovernanceInstance } from "../index";
import type { OutcomeCallbacks } from "./outcome-handler.js";
import { enforcePreprocess } from "./pre-post-enforce.js";
import { extractLastText, replaceLastText } from "./text-extract.js";
import { enforcePostprocessStream } from "./pre-post-stream.js";
import type { StreamMode } from "./pre-post-stream.js";

// ─── Types ──────────────────────────────────────────────────────

/** Minimal shape of an Anthropic stream event we care about. */
export interface AnthropicStreamEvent {
  type: string;
  index?: number;
  delta?: { type?: string; text?: string; [k: string]: unknown };
  [k: string]: unknown;
}

export interface AnthropicStreamParams {
  messages: Array<{ role: "user" | "assistant"; content: unknown }>;
  model: string;
  max_tokens: number;
  system?: unknown;
  [key: string]: unknown;
}

export interface AnthropicStreamConfig extends OutcomeCallbacks {
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

// ─── wrapGovernedMessageStream ──────────────────────────────────

/**
 * Wrap a stream-producing function (e.g. `client.messages.stream` or a
 * `client.messages.create({stream:true})` caller) with governance.
 *
 * Returns a function with the same signature; the returned stream applies
 * preprocess once, then wraps the event stream through postprocess scanning.
 */
export function createGovernedMessageStream(
  streamFn: (params: AnthropicStreamParams) => AsyncIterable<AnthropicStreamEvent>,
  governance: GovernanceInstance,
  config: AnthropicStreamConfig,
): (params: AnthropicStreamParams) => AsyncIterable<AnthropicStreamEvent> {
  return (params) => wrapGovernedAnthropicStream(streamFn, governance, config, params);
}

async function* wrapGovernedAnthropicStream(
  streamFn: (params: AnthropicStreamParams) => AsyncIterable<AnthropicStreamEvent>,
  governance: GovernanceInstance,
  config: AnthropicStreamConfig,
  params: AnthropicStreamParams,
): AsyncIterable<AnthropicStreamEvent> {
  const callbacks: OutcomeCallbacks = config;
  const runPre = config.preprocess ?? true;
  const runPost = config.postprocess ?? true;

  let workingParams = params;
  if (runPre) {
    const userText = extractLastText(params.messages);
    if (userText) {
      const pre = await enforcePreprocess(governance, userText, {
        agentId: config.agentId,
        agentName: config.agentName,
        agentLevel: config.agentLevel,
        metadata: config.metadata,
        sessionTokensUsed: config.sessionTokenTracker?.(),
        callbacks,
        toolName: "anthropic.messages.stream:pre",
      });
      if (pre.text !== userText) {
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

  // Split the event stream into text-delta and passthrough. Collect in order,
  // scan the text-deltas through enforcePostprocessStream, then re-interleave.
  yield* scanAndInterleave(source, governance, config, callbacks);
}

async function* scanAndInterleave(
  source: AsyncIterable<AnthropicStreamEvent>,
  governance: GovernanceInstance,
  config: AnthropicStreamConfig,
  callbacks: OutcomeCallbacks,
): AsyncIterable<AnthropicStreamEvent> {
  const schedule: Array<
    | { kind: "text"; index: number }
    | { kind: "passthrough"; event: AnthropicStreamEvent }
  > = [];
  const textEvents: AnthropicStreamEvent[] = [];

  for await (const event of source) {
    if (isTextDelta(event)) {
      schedule.push({ kind: "text", index: textEvents.length });
      textEvents.push(event);
    } else {
      schedule.push({ kind: "passthrough", event });
    }
  }

  if (textEvents.length === 0) {
    for (const step of schedule) {
      if (step.kind === "passthrough") yield step.event;
    }
    return;
  }

  const scanned: AnthropicStreamEvent[] = [];
  for await (const ev of enforcePostprocessStream(
    governance,
    iterateArray(textEvents),
    {
      agentId: config.agentId,
      agentName: config.agentName,
      agentLevel: config.agentLevel,
      metadata: config.metadata,
      sessionTokensUsed: config.sessionTokenTracker?.(),
      callbacks,
      toolName: "anthropic.messages.stream",
      streamMode: config.streamMode,
      streamLookbackChunks: config.streamLookbackChunks,
      streamLookbackChars: config.streamLookbackChars,
      extractText: (e) => e.delta?.text ?? "",
      buildMaskedChunk: (orig, maskedText) => ({
        ...orig,
        delta: { ...(orig.delta ?? {}), type: "text_delta", text: maskedText },
      }),
    },
  )) {
    scanned.push(ev);
  }

  let scannedCursor = 0;
  for (const step of schedule) {
    if (step.kind === "passthrough") {
      yield step.event;
      continue;
    }
    if (scannedCursor < scanned.length) {
      yield scanned[scannedCursor++];
    }
  }
  while (scannedCursor < scanned.length) {
    yield scanned[scannedCursor++];
  }
}

function isTextDelta(ev: AnthropicStreamEvent): boolean {
  return (
    ev.type === "content_block_delta" &&
    ev.delta?.type === "text_delta" &&
    typeof ev.delta?.text === "string"
  );
}

async function* iterateArray<T>(arr: T[]): AsyncIterable<T> {
  for (const x of arr) yield x;
}
