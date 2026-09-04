/**
 * Remote Enforcement — forward enforce() and register() to a hosted
 * governance API (any server implementing the remote-enforcer contract; see
 * docs/remote-contract.md at the repo root).
 *
 * When serverUrl is configured, these functions POST to the remote API
 * instead of evaluating locally. Responses are validated against the wire
 * contract before they are honoured; transient failures are retried with
 * exponential backoff (honouring Retry-After); everything else degrades to
 * the configured fallback decision, except auth failures which throw.
 * Retry and fallback policy lives in remote-enforce-retry.ts; request
 * minimisation and response validation in remote-enforce-validate.ts.
 */

import type { EnforcementContext, EnforcementDecision, PolicyStage } from "./policy.js";
import type { AgentRegistration, GovernanceAssessment } from "./types.js";
import type { FallbackMode } from "./remote-enforce-retry.js";
import {
  MAX_RETRY_WAIT_MS, RemoteEnforcementError, describeFallbackCause, fallbackFor, parseRetryAfter, withRetry,
} from "./remote-enforce-retry.js";
import { RemoteContractError, parseEnforceResponse, redactContext } from "./remote-enforce-validate.js";

export type { FallbackMode } from "./remote-enforce-retry.js";
export {
  MAX_RETRY_WAIT_MS, RETRY_DELAYS_MS, RemoteEnforcementError, fallbackDecision, isRetryableStatus, parseRetryAfter,
} from "./remote-enforce-retry.js";
export type { EnforcementDecisionEnvelope, ParsedEnforceResponse } from "./remote-enforce-validate.js";
export {
  REDACTED_CONTEXT_FIELDS, RemoteContractError, describeDecisionViolation, isEnforcementDecision,
  parseEnforceResponse, redactContext,
} from "./remote-enforce-validate.js";

// ─── Types ──────────────────────────────────────────────────────

/** Passed to RemoteConfig.onFallback whenever enforce() returns a fallback decision. */
export interface RemoteFallbackInfo {
  /** Why the remote decision could not be used (network error, HTTP status or contract violation). */
  reason: string;
  /** HTTP status of the final response, when the server answered at all. */
  status?: number;
  /** HTTP requests made by this enforce() call (1 + retries). */
  attempts: number;
}

export interface RemoteConfig {
  serverUrl: string;
  apiKey: string;
  /** Timeout per HTTP attempt in milliseconds (default: 30000). Also caps any Retry-After wait. */
  timeout?: number;
  /**
   * Retries after the first attempt for retryable failures — network errors,
   * timeouts, 408/425/429 and 5xx. Default 3, i.e. up to 4 requests per
   * enforce() call. 0 disables retries. register() is never retried.
   */
  maxRetries?: number;
  /**
   * Decision returned when no valid remote decision could be obtained: after
   * retries are exhausted, on a non-auth 4xx (400, 404, 422, …) and when a
   * 2xx body does not match the contract. Default "allow" (fail-open).
   * 401 and 403 never fall back — they throw RemoteEnforcementError.
   */
  fallbackMode?: FallbackMode;
  /**
   * Called every time enforce() returns a fallback decision — wire it to
   * alerting. Exceptions thrown by the hook are swallowed so they cannot
   * change the enforcement result.
   */
  onFallback?: (info: RemoteFallbackInfo) => void;
  /**
   * Context minimisation. Default false: the whole EnforcementContext is
   * sent as the request body, including `input`, `inputText`, `outputText`,
   * `metadata` and `textByModality`. `true` strips those five fields before
   * sending (the server then cannot evaluate content-scanning rules). A
   * function receives the context and returns exactly what is sent.
   */
  redactInput?: boolean | ((ctx: EnforcementContext) => EnforcementContext);
}

export interface RemoteRegisterResult {
  id: string;
  score: number;
  level: number;
  status: string;
  assessment: GovernanceAssessment;
}

export interface RemoteStatus {
  /**
   * True when the API answered the most recent call decisively (2xx or any
   * 4xx). False after network failures, timeouts and exhausted 5xx retries.
   */
  connected: boolean;
  /**
   * "remote" when the most recent enforce() (or connect()) was served by the
   * API; "fallback" when it returned a fallback decision or the API is down.
   */
  mode: "remote" | "fallback";
  latencyMs: number;
  plan?: string;
  features?: string[];
  agentQuota?: { used: number; limit: number | "unlimited" };
  /** HTTP requests made by the most recent enforce() call (1 = first attempt succeeded). Unset before the first call. */
  lastAttempts?: number;
}

// ─── Remote Enforcer ────────────────────────────────────────────

/**
 * Create a remote enforcer that forwards calls to a hosted governance API
 * (any server implementing the remote-enforcer contract).
 *
 * @param config - Remote server URL, API key, and resilience options
 * @returns Object with remote enforce, register, connect, status, and waitForApproval
 */
export function createRemoteEnforcer(config: RemoteConfig) {
  const { serverUrl, apiKey, onFallback, redactInput } = config;
  const timeout = config.timeout ?? 30_000;
  const maxRetries = config.maxRetries ?? 3;
  const fallbackMode = config.fallbackMode ?? "allow";
  const maxWaitMs = Math.min(MAX_RETRY_WAIT_MS, timeout);
  const baseUrl = serverUrl.replace(/\/$/, "");
  const jsonHeaders = {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${apiKey}`,
  };

  let lastConnected = false;
  let lastMode: RemoteStatus["mode"] = "fallback";
  let lastLatencyMs = 0;
  let lastAttempts: number | undefined;

  function projectContext(ctx: EnforcementContext): EnforcementContext {
    if (typeof redactInput === "function") return redactInput(ctx);
    return redactInput === true ? redactContext(ctx) : ctx;
  }

  /** One HTTP attempt. Resolves with the raw 2xx body; throws RemoteEnforcementError on non-2xx. */
  async function requestOnce(endpoint: string, body: string): Promise<{ status: number; text: string }> {
    const start = performance.now();
    const response = await fetch(endpoint, {
      method: "POST",
      headers: jsonHeaders,
      body,
      signal: AbortSignal.timeout(timeout),
    });
    lastLatencyMs = Math.round(performance.now() - start);
    const text = await response.text();
    if (!response.ok) {
      throw new RemoteEnforcementError(
        `Remote enforce failed: ${response.status} ${response.statusText}`,
        response.status,
        text,
        parseRetryAfter(response.headers.get("retry-after")),
      );
    }
    return { status: response.status, text };
  }

  /** Build the fallback decision, record it for status() and notify the host. */
  function fallBack(error: unknown, attempts: number): EnforcementDecision {
    lastMode = "fallback";
    const reason = describeFallbackCause(error, attempts);
    if (onFallback) {
      const status = error instanceof RemoteEnforcementError || error instanceof RemoteContractError
        ? error.statusCode
        : undefined;
      try {
        onFallback({ reason, status, attempts });
      } catch {
        // A failing alert hook must not change the enforcement result.
      }
    }
    return fallbackFor(fallbackMode, reason);
  }

  async function remoteEnforce(
    ctx: EnforcementContext,
    stage?: PolicyStage,
  ): Promise<EnforcementDecision> {
    const endpoint = stage
      ? `${baseUrl}/api/v1/enforce/${stage}`
      : `${baseUrl}/api/v1/enforce`;
    const body = JSON.stringify(projectContext(ctx));

    const outcome = await withRetry(() => requestOnce(endpoint, body), { maxRetries, maxWaitMs });
    lastAttempts = outcome.attempts;

    if (outcome.ok) {
      // The server answered 2xx. It still has to say something we can act on.
      lastConnected = true;
      const { status, text } = outcome.value;
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        return fallBack(new RemoteContractError("response body is not valid JSON", status, text), outcome.attempts);
      }
      const parsed = parseEnforceResponse(json);
      if (parsed.ok) {
        lastMode = "remote";
        return parsed.decision;
      }
      return fallBack(new RemoteContractError(parsed.violation, status, text), outcome.attempts);
    }

    const { error, attempts } = outcome;
    if (error instanceof RemoteEnforcementError) {
      // The API answered, so the connection is live — unless it is failing outright (5xx).
      lastConnected = error.statusCode > 0 && error.statusCode < 500;
      if (error.statusCode === 401 || error.statusCode === 403) {
        // Misconfiguration must be loud. A rejected key is not an outage, so
        // neither fail-open nor fail-closed is the right answer.
        lastMode = "remote";
        throw error;
      }
    } else {
      // Network error / timeout, retries exhausted.
      lastConnected = false;
    }
    return fallBack(error, attempts);
  }

  /**
   * Register (or look up) an agent against the governance API.
   *
   * POSTs to `/api/v1/agents` with the registration payload. The API
   * auto-dedupes by id/name, so calling this on a pre-existing agent
   * is idempotent — it returns the existing record's authoritative
   * score + level. This fixes the previous placeholder behaviour where
   * remoteRegister returned `level: 0` unconditionally, which caused
   * agent_level-conditioned rules to fire incorrectly for higher-level
   * agents on every enforce().
   *
   * If the call fails for any reason (network, auth, 5xx), we still
   * return a synthetic "registered" receipt so the caller isn't blocked
   * on a non-essential register step. The next enforce() will carry
   * authoritative data regardless. This call is not retried.
   */
  async function remoteRegister(input: AgentRegistration): Promise<RemoteRegisterResult> {
    try {
      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({
          id: input.id,
          name: input.name,
          framework: input.framework,
          owner: input.owner,
          description: input.description,
          tools: input.tools,
          channels: input.channels,
          hasAuth: input.hasAuth,
          hasGuardrails: input.hasGuardrails,
          hasObservability: input.hasObservability,
          hasAuditLog: input.hasAuditLog,
        }),
        signal: AbortSignal.timeout(timeout),
      });
      if (response.ok) {
        const data = await response.json() as {
          id?: string;
          name?: string;
          compositeScore?: number;
          governanceLevel?: number;
          status?: string;
        };
        const id = data.id ?? input.name;
        const score = typeof data.compositeScore === "number" ? data.compositeScore : 0;
        // Clamp to the valid GovernanceLevel range (0-4). The API is the
        // source of truth here, but we validate defensively.
        const rawLevel = typeof data.governanceLevel === "number" ? data.governanceLevel : 0;
        const level = (rawLevel >= 0 && rawLevel <= 4
          ? Math.round(rawLevel)
          : 0) as 0 | 1 | 2 | 3 | 4;
        const status: "registered" | "assessed" | "approved" | "flagged" | "deprecated" | "quarantined" =
          data.status === "assessed" || data.status === "approved" ||
          data.status === "flagged" || data.status === "deprecated" ||
          data.status === "quarantined"
            ? data.status
            : "registered";
        return {
          id,
          score,
          level,
          status,
          assessment: {
            agentId: id,
            agentName: data.name ?? input.name,
            compositeScore: score,
            level: { level, label: "live", autonomy: "governed", minScore: 0, maxScore: 100 },
            status,
            dimensions: [],
            recommendations: [],
            assessedAt: new Date().toISOString(),
          },
        };
      }
      // 409 / 4xx — fall through to the synthetic receipt. The next
      // enforce() is still authoritative.
    } catch {
      // Network/timeout — same fall-through.
    }
    return {
      id: input.name,
      score: 0,
      level: 0,
      status: "registered",
      assessment: {
        agentId: input.name,
        agentName: input.name,
        compositeScore: 0,
        level: { level: 0, label: "pending", autonomy: "none", minScore: 0, maxScore: 0 },
        status: "registered",
        dimensions: [],
        recommendations: [],
        assessedAt: new Date().toISOString(),
      },
    };
  }

  /**
   * Test connectivity to the governance API. Returns status without throwing.
   * Call at startup to verify the connection before first enforce().
   */
  async function connect(): Promise<RemoteStatus> {
    try {
      const start = performance.now();
      const res = await fetch(`${baseUrl}/api/v1/connect`, {
        headers: { "Authorization": `Bearer ${apiKey}` },
        signal: AbortSignal.timeout(5000),
      });
      lastLatencyMs = Math.round(performance.now() - start);
      lastConnected = res.ok;
      lastMode = res.ok ? "remote" : "fallback";

      if (res.ok) {
        const data = await res.json() as {
          plan?: string;
          features?: string[];
          agentQuota?: { used: number; limit: number | "unlimited" };
        };
        return {
          connected: true, mode: "remote", latencyMs: lastLatencyMs, lastAttempts,
          plan: data.plan, features: data.features, agentQuota: data.agentQuota,
        };
      }
    } catch {
      lastConnected = false;
      lastMode = "fallback";
      lastLatencyMs = 0;
    }
    return { connected: lastConnected, mode: lastMode, latencyMs: lastLatencyMs, lastAttempts };
  }

  /** Current connection status (cached from the last enforce/connect call). */
  function status(): RemoteStatus {
    return { connected: lastConnected, mode: lastMode, latencyMs: lastLatencyMs, lastAttempts };
  }

  /**
   * Poll an approval until it resolves. Returns the final status.
   * Useful for agents that want to pause and wait for human approval.
   */
  async function waitForApproval(
    approvalId: string,
    opts?: { timeoutMs?: number; pollIntervalMs?: number },
  ): Promise<"approved" | "denied" | "expired" | "timeout"> {
    const timeoutMs = opts?.timeoutMs ?? 30 * 60 * 1000; // 30 minutes
    const pollInterval = opts?.pollIntervalMs ?? 5000;
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      try {
        const res = await fetch(`${baseUrl}/api/v1/approvals/${approvalId}`, {
          headers: { "Authorization": `Bearer ${apiKey}` },
          signal: AbortSignal.timeout(5000),
        });
        if (res.ok) {
          const data = await res.json() as { request?: { status?: string } };
          const s = data.request?.status;
          if (s === "approved") return "approved";
          if (s === "denied" || s === "cancelled") return "denied";
          if (s === "expired") return "expired";
        }
      } catch {
        // transient failure — continue polling
      }
      await new Promise((r) => setTimeout(r, pollInterval));
    }
    return "timeout";
  }

  return { enforce: remoteEnforce, register: remoteRegister, connect, status, waitForApproval };
}

/**
 * Validate remote config — throws if serverUrl is set but apiKey is missing,
 * or if serverUrl is not a valid http/https URL.
 */
export function validateRemoteConfig(serverUrl?: string, apiKey?: string): void {
  if (!serverUrl) return;
  if (!apiKey) {
    throw new Error("apiKey is required when serverUrl is configured");
  }
  let parsed: URL;
  try {
    parsed = new URL(serverUrl);
  } catch {
    throw new Error(`Invalid serverUrl: "${serverUrl}" is not a valid URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Invalid serverUrl protocol "${parsed.protocol}" — only http: and https: are allowed`);
  }
}
