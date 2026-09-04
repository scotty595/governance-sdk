/**
 * Retry and fallback policy for the remote enforcer: status classification,
 * Retry-After parsing, a bounded retry loop that reports how many attempts
 * it made, and the synthetic decision returned when no valid remote decision
 * could be obtained.
 *
 * Split out of remote-enforce.ts so the policy can be unit-tested without a
 * fetch mock. Zero runtime dependencies. The wire semantics this implements
 * are documented in docs/remote-contract.md at the repo root.
 */

import type { EnforcementDecision } from "./policy.js";
import { RemoteContractError } from "./remote-enforce-validate.js";

// ─── Constants ──────────────────────────────────────────────────

/**
 * Backoff between attempts when the server sent no Retry-After hint (ms).
 * Index = number of retries already made; the last value repeats.
 */
export const RETRY_DELAYS_MS: readonly number[] = [100, 500, 2000];

/** Absolute cap on a single wait between attempts, whatever Retry-After says. */
export const MAX_RETRY_WAIT_MS = 30_000;

// ─── Status classification ──────────────────────────────────────

/**
 * Whether an HTTP status is worth retrying: 408 Request Timeout, 425 Too
 * Early, 429 Too Many Requests and every 5xx. Status 0 stands for "no HTTP
 * response at all" (network error / timeout) and is retryable too.
 */
export function isRetryableStatus(status: number): boolean {
  return status === 0 || status === 408 || status === 425 || status === 429 || status >= 500;
}

// ─── Error type ─────────────────────────────────────────────────

/** Error thrown when the remote API returns a non-2xx response. */
export class RemoteEnforcementError extends Error {
  /** True for 408/425/429/5xx — see isRetryableStatus(). */
  public readonly retryable: boolean;
  /** Parsed `Retry-After` hint in ms when the server sent a usable one. Uncapped. */
  public readonly retryAfterMs: number | undefined;

  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly responseBody: string,
    retryAfterMs?: number,
  ) {
    super(message);
    this.name = "RemoteEnforcementError";
    this.retryable = isRetryableStatus(statusCode);
    this.retryAfterMs = retryAfterMs;
  }
}

// ─── Retry-After ────────────────────────────────────────────────

/**
 * Parse a `Retry-After` header into a wait in milliseconds.
 *
 * Accepts delay-seconds (a non-negative integer) or an HTTP-date (RFC 9110
 * §10.2.3). Returns undefined for a missing or unparseable value; a date in
 * the past yields 0. The result is uncapped — see retryDelayMs().
 */
export function parseRetryAfter(
  value: string | null | undefined,
  nowMs: number = Date.now(),
): number | undefined {
  if (value === null || value === undefined) return undefined;
  const v = value.trim();
  if (v === "") return undefined;
  if (/^\d+$/.test(v)) return Number(v) * 1000;
  // Every HTTP-date form contains a month name. Without this gate Date.parse()
  // would read bare numerics such as "-1" or "1.5" as years.
  if (!/[A-Za-z]/.test(v)) return undefined;
  const at = Date.parse(v);
  if (Number.isNaN(at)) return undefined;
  return Math.max(0, at - nowMs);
}

/**
 * Wait before the next attempt. `retriesMade` is how many retries have
 * already happened (0 before the first retry). A Retry-After hint on the
 * error wins over the backoff schedule; either is capped at maxWaitMs.
 */
export function retryDelayMs(retriesMade: number, error: unknown, maxWaitMs: number): number {
  const index = Math.min(Math.max(0, retriesMade), RETRY_DELAYS_MS.length - 1);
  const backoff = RETRY_DELAYS_MS[index];
  const hinted = error instanceof RemoteEnforcementError ? error.retryAfterMs : undefined;
  return Math.max(0, Math.min(hinted ?? backoff, maxWaitMs));
}

// ─── Retry loop ─────────────────────────────────────────────────

export type RetryOutcome<T> =
  | { ok: true; value: T; attempts: number }
  | { ok: false; error: unknown; attempts: number };

export interface RetryOptions {
  /**
   * Retries after the first attempt, so total attempts = maxRetries + 1.
   * Must be a finite number; it is floored and clamped to >= 0.
   */
  maxRetries: number;
  /** Cap on any single wait between attempts (ms). */
  maxWaitMs: number;
  /**
   * Decide whether an error is worth retrying. Default: a
   * RemoteEnforcementError is retried iff `.retryable`; any other error
   * (network failure, timeout) is retried.
   */
  isRetryable?: (error: unknown) => boolean;
  /** Injectable sleep, for tests. */
  sleep?: (ms: number) => Promise<void>;
}

const defaultIsRetryable = (error: unknown): boolean =>
  error instanceof RemoteEnforcementError ? error.retryable : true;

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Run `fn` up to `1 + maxRetries` times. Never throws: the outcome carries
 * either the value or the final error, plus the number of attempts made, so
 * the caller can choose between falling back and re-throwing.
 */
export async function withRetry<T>(fn: () => Promise<T>, opts: RetryOptions): Promise<RetryOutcome<T>> {
  const maxRetries = Number.isFinite(opts.maxRetries) ? Math.max(0, Math.floor(opts.maxRetries)) : 0;
  const isRetryable = opts.isRetryable ?? defaultIsRetryable;
  const sleep = opts.sleep ?? defaultSleep;
  let attempts = 0;
  for (;;) {
    attempts += 1;
    try {
      return { ok: true, value: await fn(), attempts };
    } catch (error) {
      const retriesMade = attempts - 1;
      if (!isRetryable(error) || retriesMade >= maxRetries) return { ok: false, error, attempts };
      await sleep(retryDelayMs(retriesMade, error, opts.maxWaitMs));
    }
  }
}

// ─── Fallback decision ──────────────────────────────────────────

export type FallbackMode = "allow" | "block";

/** One line saying why the remote decision could not be used. */
export function describeFallbackCause(error: unknown, attempts: number): string {
  const tries = `${attempts} attempt${attempts === 1 ? "" : "s"}`;
  if (error instanceof RemoteContractError) {
    return `Governance API returned an invalid response (HTTP ${error.statusCode}: ${error.message})`;
  }
  if (error instanceof RemoteEnforcementError && error.statusCode > 0) {
    const verb = error.statusCode === 429
      ? "rate-limited the request"
      : error.statusCode >= 500 ? "is unavailable" : "rejected the request";
    return `Governance API ${verb} (HTTP ${error.statusCode}) after ${tries}`;
  }
  const detail = error instanceof Error ? error.message : String(error);
  return `Governance API unreachable after ${tries} (${detail})`;
}

/** Synthetic decision for `mode`, explaining itself with `cause`. */
export function fallbackFor(mode: FallbackMode, cause: string): EnforcementDecision {
  return {
    blocked: mode === "block",
    reason: `${cause} — ${mode === "block" ? "blocking" : "allowing"} by fallback policy.`,
    ruleId: null,
    outcome: mode === "block" ? "block" : "allow",
    evaluatedAt: new Date().toISOString(),
    rulesEvaluated: 0,
  };
}

/**
 * Decision used when no valid remote decision could be obtained. `error` is
 * the final failure (network error, RemoteEnforcementError or
 * RemoteContractError); `attempts` is how many HTTP requests were made.
 */
export function fallbackDecision(mode: FallbackMode, error: unknown, attempts = 1): EnforcementDecision {
  return fallbackFor(mode, describeFallbackCause(error, attempts));
}
