/**
 * governance-sdk Vercel AI — wrapStream (postprocess streaming)
 *
 * Companion to `createGovernanceMiddleware` (vercel-ai-middleware.ts), which
 * handles transformParams (pre) and wrapGenerate (non-streaming post). The
 * middleware contract is `wrapStream({ doStream, params }) → { stream, ... }`
 * where `stream` is a `ReadableStream` of language-model stream parts.
 *
 * Text parts are `{ type: 'text-delta', id, delta }` on LanguageModelV2+
 * (`ai` ≥ 5) and `{ type: 'text-delta', textDelta }` on V1 (`ai` 3.4 – 4.x);
 * both are scanned. Every other part (text-start/end, reasoning, tool-call,
 * finish, ...) passes through unscanned.
 *
 * ## Incremental by design
 *
 * The governed stream is pull-based: a source part is read only when the
 * shared scanner (`enforcePostprocessStream`) asks for its next chunk, and the
 * scanner only advances when the consumer pulls. So `per-chunk` emits each
 * text-delta before the next source part is read (TTFT ≈ one chunk),
 * `sliding` emits as its lookback window slides (TTFT ≈ lookback + 1 chunks),
 * and only `buffered` drains the source before emitting. Source read-ahead is
 * bounded by the scanner window plus this stream's one-part queue, so a
 * stalled consumer stalls the upstream model instead of buffering unbounded.
 *
 * Non-text parts are never reordered relative to text: one that arrives while
 * text is held in the window is released right after the text preceding it.
 *
 * On block / require_approval the governed stream errors with the scanner's
 * `GovernanceBlockedError` / `GovernanceApprovalRequiredError` and the source
 * is cancelled so the model stops generating. Text already emitted in
 * `sliding` / `per-chunk` mode has reached the consumer — use `buffered` when
 * that is unacceptable.
 */

import type { GovernanceInstance } from "../index";
import type { OutcomeCallbacks } from "./outcome-handler.js";
import { enforcePostprocessStream } from "./pre-post-stream.js";
import type { StreamMode } from "./pre-post-stream.js";

// ─── Types ──────────────────────────────────────────────────────

/** Minimal shape of a language-model stream part we care about. */
export interface VercelStreamPart {
  type: string;
  /** text-delta payload on LanguageModelV2+ (`ai` ≥ 5). */
  delta?: string;
  /** text-delta payload on LanguageModelV1 (`ai` 3.4 – 4.x). */
  textDelta?: string;
  [k: string]: unknown;
}

export interface VercelStreamResult {
  stream: ReadableStream<VercelStreamPart>;
  [key: string]: unknown;
}

export interface VercelStreamConfig extends OutcomeCallbacks {
  agentId: string;
  agentName?: string;
  agentLevel?: number;
  /** Disable post-scan of streamed output (default: enabled). */
  postprocess?: boolean;
  metadata?: Record<string, unknown>;
  sessionTokenTracker?: () => number;
  /** Streaming mode: "buffered" | "sliding" | "per-chunk". Default "buffered". */
  streamMode?: StreamMode;
  /** Sliding mode: chunks to hold back (default 2). */
  streamLookbackChunks?: number;
  /** Sliding mode: chars to hold back (overrides chunk count if exceeded). */
  streamLookbackChars?: number;
}

// ─── wrapStream ────────────────────────────────────────────────

export function buildWrapStream(
  governance: GovernanceInstance,
  config: VercelStreamConfig,
): (options: {
  doStream: () => Promise<VercelStreamResult>;
  params: unknown;
}) => Promise<VercelStreamResult> {
  const callbacks: OutcomeCallbacks = config;

  return async ({ doStream }) => {
    const result = await doStream();
    const stream = wrapStreamWithGovernance(result.stream, governance, config, callbacks);
    return { ...result, stream };
  };
}

type PumpEvent =
  | { kind: "request" }
  | { kind: "output"; result: IteratorResult<VercelStreamPart> }
  | { kind: "error"; error: unknown };

function wrapStreamWithGovernance(
  source: ReadableStream<VercelStreamPart>,
  governance: GovernanceInstance,
  config: VercelStreamConfig,
  callbacks: OutcomeCallbacks,
): ReadableStream<VercelStreamPart> {
  if (!(config.postprocess ?? true)) return source;

  const reader = source.getReader();
  const input = new InputChannel<VercelStreamPart>();
  // Parts produced by buildMaskedChunk. The scanner emits one masked part in
  // place of *everything* it holds, so seeing one means all text fed so far is consumed.
  const maskedParts = new WeakSet<VercelStreamPart>();

  const scanned: AsyncIterator<VercelStreamPart> = enforcePostprocessStream(
    governance,
    input,
    {
      agentId: config.agentId,
      agentName: config.agentName,
      agentLevel: config.agentLevel,
      metadata: config.metadata,
      sessionTokensUsed: config.sessionTokenTracker?.(),
      callbacks,
      toolName: "vercel.wrapStream",
      streamMode: config.streamMode,
      streamLookbackChunks: config.streamLookbackChunks,
      streamLookbackChars: config.streamLookbackChars,
      extractText: textOf,
      buildMaskedChunk: (orig, masked) => {
        const part = withText(orig, masked);
        maskedParts.add(part);
        return part;
      },
    },
  )[Symbol.asyncIterator]();

  const ready: VercelStreamPart[] = []; // cleared for emission, in order
  const held: Array<{ afterText: number; part: VercelStreamPart }> = []; // non-text parts behind held text
  let fed = 0; // text parts handed to the scanner
  let consumed = 0; // text parts the scanner has emitted (or collapsed)
  let scannerDone = false;
  let cancelled = false;
  let pendingOutput: Promise<IteratorResult<VercelStreamPart>> | null = null;

  const releaseHeld = (): void => {
    for (let next = held[0]; next !== undefined && next.afterText <= consumed; next = held[0]) {
      held.shift();
      ready.push(next.part);
    }
  };

  const fail = async (
    controller: ReadableStreamDefaultController<VercelStreamPart>,
    error: unknown,
  ): Promise<void> => {
    await reader.cancel(error).catch(() => undefined); // source may already be closed
    if (!cancelled) controller.error(error);
  };

  return new ReadableStream<VercelStreamPart>({
    async pull(controller) {
      // Each pull emits exactly one part (or closes/errors). Source parts are read
      // one at a time, only when the scanner asks, so a stalled consumer stalls the source.
      while (!cancelled) {
        if (ready.length > 0) {
          controller.enqueue(ready.shift()!);
          return;
        }
        if (scannerDone) {
          controller.close();
          return;
        }

        if (input.waiting) {
          let next: ReadableStreamReadResult<VercelStreamPart>;
          try {
            next = await reader.read();
          } catch (error) {
            await fail(controller, error);
            return;
          }
          if (cancelled) return;
          if (next.done) {
            input.end();
          } else if (isTextPart(next.value)) {
            fed++;
            input.feed(next.value);
          } else if (consumed >= fed) {
            ready.push(next.value);
          } else {
            held.push({ afterText: fed, part: next.value });
          }
          continue;
        }

        // Advance the scanner until it either emits a part or asks for input.
        pendingOutput ??= scanned.next();
        const event: PumpEvent = await Promise.race([
          pendingOutput.then(
            (result): PumpEvent => ({ kind: "output", result }),
            (error: unknown): PumpEvent => ({ kind: "error", error }),
          ),
          input.requested().then((): PumpEvent => ({ kind: "request" })),
        ]);
        if (event.kind === "request") continue;
        pendingOutput = null;
        if (event.kind === "error") {
          await fail(controller, event.error);
          return;
        }
        if (event.result.done) {
          scannerDone = true;
          consumed = fed;
        } else {
          const part = event.result.value;
          consumed = maskedParts.has(part) ? fed : consumed + 1;
          ready.push(part);
        }
        releaseHeld();
      }
    },
    async cancel(reason: unknown) {
      cancelled = true;
      pendingOutput?.catch(() => undefined);
      await reader.cancel(reason);
    },
  });
}

// ─── Helpers ───────────────────────────────────────────────────

/**
 * Pull-driven async iterable handed to the scanner as its source. The scanner calls
 * `next()` when it wants a chunk; the pump sees that via `waiting` / `requested()` and
 * answers with `feed()` or `end()`. Nothing is buffered here — reads stay on demand.
 */
class InputChannel<T> implements AsyncIterableIterator<T> {
  private pendingRequest: ((result: IteratorResult<T>) => void) | null = null;
  private signal: { promise: Promise<void>; resolve: () => void } | null = null;
  private closed = false;

  /** True while the scanner is blocked waiting for the next chunk. */
  get waiting(): boolean {
    return this.pendingRequest !== null;
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<T> {
    return this;
  }

  next(): Promise<IteratorResult<T>> {
    if (this.closed) return Promise.resolve({ done: true, value: undefined });
    return new Promise((resolve) => {
      this.pendingRequest = resolve;
      this.signal?.resolve();
      this.signal = null;
    });
  }

  return(): Promise<IteratorResult<T>> {
    this.end();
    return Promise.resolve({ done: true, value: undefined });
  }

  /** Resolves once the scanner asks for a chunk (immediately if it already has). */
  requested(): Promise<void> {
    if (this.pendingRequest) return Promise.resolve();
    if (!this.signal) {
      let resolve: () => void = () => undefined;
      const promise = new Promise<void>((r) => { resolve = r; });
      this.signal = { promise, resolve };
    }
    return this.signal.promise;
  }

  feed(value: T): void {
    const resolve = this.pendingRequest;
    this.pendingRequest = null;
    resolve?.({ done: false, value });
  }

  end(): void {
    this.closed = true;
    const resolve = this.pendingRequest;
    this.pendingRequest = null;
    resolve?.({ done: true, value: undefined });
  }
}

function isTextPart(part: VercelStreamPart): boolean {
  return part.type === "text-delta" && (typeof part.delta === "string" || typeof part.textDelta === "string");
}

function textOf(part: VercelStreamPart): string {
  if (typeof part.delta === "string") return part.delta;
  return typeof part.textDelta === "string" ? part.textDelta : "";
}

/** Copy a text part with replacement text, keeping the source's field name (V1 vs V2+). */
function withText(part: VercelStreamPart, text: string): VercelStreamPart {
  const isV1 = typeof part.delta !== "string" && typeof part.textDelta === "string";
  return isV1 ? { ...part, textDelta: text } : { ...part, delta: text };
}
