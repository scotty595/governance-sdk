import { test, describe, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import type { EnforcementContext } from "./policy.js";
import { createGovernance } from "governance-sdk";
import {
  createRemoteEnforcer,
  validateRemoteConfig,
  fallbackDecision,
  redactContext,
  REDACTED_CONTEXT_FIELDS,
  RemoteEnforcementError,
  RemoteContractError,
  isEnforcementDecision,
  describeDecisionViolation,
  parseEnforceResponse,
  isRetryableStatus,
  parseRetryAfter,
  type RemoteFallbackInfo,
} from "./remote-enforce.js";
import { retryDelayMs, withRetry, RETRY_DELAYS_MS } from "./remote-enforce-retry.js";

// ─── Mock fetch ─────────────────────────────────────────────────

interface MockResponseSpec {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
  /** Reject the fetch with this error instead of resolving a response. */
  reject?: Error;
}

const STATUS_TEXT: Record<number, string> = {
  200: "OK", 201: "Created", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
  404: "Not Found", 422: "Unprocessable Entity", 429: "Too Many Requests",
  500: "Internal Server Error", 503: "Service Unavailable",
};

let mockFetch: ReturnType<typeof mock.fn>;
const realFetch = globalThis.fetch;

function mockResponse(spec: MockResponseSpec) {
  const body = spec.body;
  const text = typeof body === "string" ? body : body === undefined ? "" : JSON.stringify(body);
  return {
    ok: spec.status >= 200 && spec.status < 300,
    status: spec.status,
    statusText: STATUS_TEXT[spec.status] ?? "Error",
    headers: new Headers(spec.headers ?? {}),
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(text),
  };
}

/** Serve responses in order; the last spec repeats for any further calls. */
function setupFetchSequence(...specs: MockResponseSpec[]) {
  let i = 0;
  mockFetch = mock.fn(() => {
    const spec = specs[Math.min(i, specs.length - 1)];
    i += 1;
    if (spec.reject) return Promise.reject(spec.reject);
    return Promise.resolve(mockResponse(spec));
  });
  (globalThis as Record<string, unknown>).fetch = mockFetch;
}

function setupFetchMock(status: number, body: unknown, headers?: Record<string, string>) {
  setupFetchSequence({ status, body, headers });
}

function requestBody(callIndex = 0): Record<string, unknown> {
  const options = mockFetch.mock.calls[callIndex].arguments[1] as { body: string };
  return JSON.parse(options.body);
}

afterEach(() => {
  (globalThis as Record<string, unknown>).fetch = realFetch;
});

const config = { serverUrl: "https://api.example.com", apiKey: "test-key" };
const ctx: EnforcementContext = { agentId: "agent-1", action: "tool_call", tool: "web_search" };

const allowDecision = {
  blocked: false, reason: "Allowed by remote", ruleId: null, outcome: "allow",
  evaluatedAt: "2026-03-10T00:00:00Z", rulesEvaluated: 3,
};
const blockDecision = {
  blocked: true, reason: "Tool blocked by policy", ruleId: "block-tools", outcome: "block",
  evaluatedAt: "2026-03-10T00:00:00Z", rulesEvaluated: 5,
};

// ─── validateRemoteConfig ───────────────────────────────────────

describe("validateRemoteConfig", () => {
  test("throws when serverUrl set but apiKey missing", () => {
    assert.throws(
      () => validateRemoteConfig("https://api.example.com", undefined),
      { message: "apiKey is required when serverUrl is configured" },
    );
  });

  test("throws when serverUrl set but apiKey is empty string", () => {
    assert.throws(
      () => validateRemoteConfig("https://api.example.com", ""),
      { message: "apiKey is required when serverUrl is configured" },
    );
  });

  test("does not throw when both serverUrl and apiKey are set", () => {
    assert.doesNotThrow(() => validateRemoteConfig("https://api.example.com", "key-123"));
  });

  test("does not throw when neither is set", () => {
    assert.doesNotThrow(() => validateRemoteConfig(undefined, undefined));
  });

  test("does not throw when only apiKey is set (no serverUrl)", () => {
    assert.doesNotThrow(() => validateRemoteConfig(undefined, "key-123"));
  });

  test("throws on invalid URL format", () => {
    assert.throws(() => validateRemoteConfig("not-a-url", "key-123"), /Invalid serverUrl/);
  });

  test("throws on non-http protocol (file://)", () => {
    assert.throws(
      () => validateRemoteConfig("file:///etc/passwd", "key-123"),
      /only http: and https: are allowed/,
    );
  });

  test("throws on non-http protocol (ftp://)", () => {
    assert.throws(
      () => validateRemoteConfig("ftp://example.com", "key-123"),
      /only http: and https: are allowed/,
    );
  });

  test("allows http:// URLs (for localhost dev)", () => {
    assert.doesNotThrow(() => validateRemoteConfig("http://localhost:4000", "key-123"));
  });

  test("allows https:// URLs", () => {
    assert.doesNotThrow(() => validateRemoteConfig("https://api.example.com", "key-123"));
  });
});

// ─── createGovernance with serverUrl ────────────────────────────

describe("createGovernance with serverUrl", () => {
  test("throws if serverUrl without apiKey", () => {
    assert.throws(
      () => createGovernance({ serverUrl: "https://api.example.com" }),
      { message: "apiKey is required when serverUrl is configured" },
    );
  });

  test("creates instance when both serverUrl and apiKey provided", () => {
    setupFetchMock(200, {});
    const gov = createGovernance({ serverUrl: "https://api.example.com", apiKey: "test-key" });
    assert.ok(gov.enforce);
    assert.ok(gov.register);
  });
});

// ─── Remote enforce: happy path ─────────────────────────────────

describe("remote enforce", () => {
  test("POSTs to /api/v1/enforce with correct headers", async () => {
    setupFetchMock(200, allowDecision);

    const remote = createRemoteEnforcer(config);
    const result = await remote.enforce(ctx);

    assert.equal(result.blocked, false);
    assert.equal(result.reason, "Allowed by remote");
    assert.equal(mockFetch.mock.calls.length, 1);

    const call = mockFetch.mock.calls[0];
    assert.equal(call.arguments[0], "https://api.example.com/api/v1/enforce");
    const options = call.arguments[1] as Record<string, unknown>;
    assert.equal(options.method, "POST");
    const headers = options.headers as Record<string, string>;
    assert.equal(headers["Authorization"], "Bearer test-key");
    assert.equal(headers["Content-Type"], "application/json");
  });

  test("POSTs to /api/v1/enforce/{stage} when a stage is given", async () => {
    setupFetchMock(200, allowDecision);
    const remote = createRemoteEnforcer(config);
    await remote.enforce(ctx, "postprocess");
    assert.equal(mockFetch.mock.calls[0].arguments[0], "https://api.example.com/api/v1/enforce/postprocess");
  });

  test("sends enforcement context in request body", async () => {
    setupFetchMock(200, blockDecision);

    const remote = createRemoteEnforcer(config);
    await remote.enforce({
      agentId: "agent-1", agentName: "my-agent", agentLevel: 2, action: "tool_call", tool: "shell_exec",
    });

    const body = requestBody();
    assert.equal(body.agentId, "agent-1");
    assert.equal(body.agentName, "my-agent");
    assert.equal(body.agentLevel, 2);
    assert.equal(body.tool, "shell_exec");
  });

  test("returns blocked decision from remote", async () => {
    setupFetchMock(200, blockDecision);

    const remote = createRemoteEnforcer(config);
    const result = await remote.enforce({ agentId: "agent-1", action: "tool_call", tool: "shell_exec" });

    assert.equal(result.blocked, true);
    assert.equal(result.ruleId, "block-tools");
    assert.equal(result.outcome, "block");
    assert.equal(remote.status().mode, "remote");
    assert.equal(remote.status().lastAttempts, 1);
  });

  test("unwraps the { decision, approvalId, approval } envelope", async () => {
    const approval = { id: "apr-1", status: "pending", pollUrl: "/api/v1/approvals/apr-1", message: "Waiting" };
    setupFetchMock(200, {
      decision: { ...blockDecision, outcome: "require_approval" },
      approvalId: "apr-1",
      approval,
    });

    const remote = createRemoteEnforcer(config);
    const result = await remote.enforce(ctx);
    assert.equal(result.outcome, "require_approval");
    assert.equal(result.approvalId, "apr-1");
    assert.deepEqual(result.approval, approval);
  });

  test("strips trailing slash from serverUrl", async () => {
    setupFetchMock(200, allowDecision);

    const remote = createRemoteEnforcer({ serverUrl: "https://api.example.com/", apiKey: "key" });
    await remote.enforce({ agentId: "a1", action: "tool_call" });

    assert.equal(mockFetch.mock.calls[0].arguments[0], "https://api.example.com/api/v1/enforce");
  });

  test("status() has no lastAttempts before the first call", () => {
    const remote = createRemoteEnforcer(config);
    assert.equal(remote.status().lastAttempts, undefined);
    assert.equal(remote.status().connected, false);
  });
});

// ─── Contract validation ────────────────────────────────────────

describe("remote enforce: response validation", () => {
  test("empty object body falls back (fail-open) instead of reading blocked: undefined", async () => {
    setupFetchMock(200, {});

    const remote = createRemoteEnforcer(config);
    const decision = await remote.enforce(ctx);

    assert.equal(decision.blocked, false);
    assert.equal(decision.outcome, "allow");
    assert.equal(decision.rulesEvaluated, 0);
    assert.match(decision.reason, /invalid response/);
    assert.match(decision.reason, /decision\.blocked must be a boolean/);
    assert.equal(mockFetch.mock.calls.length, 1, "contract violations are not retried");
    assert.equal(remote.status().connected, true, "the server answered; the connection is live");
    assert.equal(remote.status().mode, "fallback");
  });

  test("invalid body with fallbackMode block yields a blocked decision", async () => {
    setupFetchMock(200, { blocked: "yes", outcome: "allow" });

    const remote = createRemoteEnforcer({ ...config, fallbackMode: "block" });
    const decision = await remote.enforce(ctx);
    assert.equal(decision.blocked, true);
    assert.equal(decision.outcome, "block");
    assert.match(decision.reason, /blocking by fallback policy/);
  });

  test("invalid decision inside the envelope falls back", async () => {
    setupFetchMock(200, { decision: { blocked: false }, approvalId: "apr-1" });

    const remote = createRemoteEnforcer(config);
    const decision = await remote.enforce(ctx);
    assert.match(decision.reason, /decision\.outcome must be one of/);
    assert.equal(decision.approvalId, undefined);
  });

  test("envelope with malformed approval falls back", async () => {
    setupFetchMock(200, { decision: allowDecision, approval: { id: 42 } });

    const remote = createRemoteEnforcer(config);
    const decision = await remote.enforce(ctx);
    assert.match(decision.reason, /approval must be/);
  });

  test("null optional fields are treated as absent", async () => {
    setupFetchMock(200, {
      decision: { ...allowDecision, maskedText: null, approval: null },
      approvalId: null,
      approval: null,
    });

    const remote = createRemoteEnforcer(config);
    const decision = await remote.enforce(ctx);
    assert.equal(decision.reason, "Allowed by remote");
    assert.equal("approvalId" in decision, false);
    assert.equal("maskedText" in decision, false);
  });

  test("non-JSON body falls back", async () => {
    setupFetchMock(200, "<html>maintenance</html>");

    const remote = createRemoteEnforcer(config);
    const decision = await remote.enforce(ctx);
    assert.match(decision.reason, /not valid JSON/);
    assert.equal(mockFetch.mock.calls.length, 1);
  });

  test("incoherent blocked/outcome pair falls back", async () => {
    setupFetchMock(200, { ...blockDecision, blocked: false });

    const remote = createRemoteEnforcer(config);
    const decision = await remote.enforce(ctx);
    assert.match(decision.reason, /requires blocked: true/);
  });
});

describe("isEnforcementDecision / parseEnforceResponse", () => {
  test("accepts a minimal valid decision and one with every optional field", () => {
    assert.equal(isEnforcementDecision(allowDecision), true);
    assert.equal(isEnforcementDecision({
      ...blockDecision,
      stage: "process",
      condition: { type: "tool_blocklist" },
      remedy: "Remove shell_exec from the tool list",
      degradedFrom: "mask",
      maskedText: "***",
      approvalId: "apr-1",
      approval: { id: "apr-1", status: "pending", pollUrl: "/x", message: "m" },
      someFutureField: 1,
    }), true);
  });

  test("rejects each required-field violation with a named reason", () => {
    const cases: Array<[unknown, RegExp]> = [
      [null, /must be a JSON object/],
      [[], /must be a JSON object/],
      [{ ...allowDecision, blocked: "false" }, /blocked must be a boolean/],
      [{ ...allowDecision, outcome: "deny" }, /outcome must be one of/],
      [{ ...allowDecision, reason: 1 }, /reason must be a string/],
      [{ ...allowDecision, ruleId: undefined }, /ruleId must be a string or null/],
      [{ ...allowDecision, evaluatedAt: Date.now() }, /evaluatedAt must be a string/],
      [{ ...allowDecision, rulesEvaluated: "3" }, /rulesEvaluated must be a finite number/],
      [{ ...allowDecision, rulesEvaluated: Infinity }, /rulesEvaluated must be a finite number/],
      [{ ...allowDecision, blocked: true }, /"allow" requires blocked: false/],
      [{ ...blockDecision, blocked: false }, /"block" requires blocked: true/],
    ];
    for (const [value, pattern] of cases) {
      assert.equal(isEnforcementDecision(value), false);
      assert.match(describeDecisionViolation(value) ?? "", pattern);
    }
  });

  test("rejects ill-typed optional fields", () => {
    const cases: Array<[unknown, RegExp]> = [
      [{ ...allowDecision, stage: "prefetch" }, /stage must be one of/],
      [{ ...allowDecision, condition: "tool" }, /condition must be/],
      [{ ...allowDecision, remedy: 1 }, /remedy must be a string/],
      [{ ...allowDecision, degradedFrom: "block" }, /degradedFrom must be "mask"/],
      [{ ...allowDecision, maskedText: 1 }, /maskedText must be a string/],
      [{ ...allowDecision, approvalId: 1 }, /approvalId must be a string/],
      [{ ...allowDecision, approval: { id: "x" } }, /approval must be/],
    ];
    for (const [value, pattern] of cases) {
      assert.match(describeDecisionViolation(value) ?? "", pattern);
    }
  });

  test("parseEnforceResponse accepts both wire forms and never throws", () => {
    assert.deepEqual(parseEnforceResponse(allowDecision), { ok: true, decision: allowDecision });
    const enveloped = parseEnforceResponse({ decision: allowDecision, approvalId: "apr-1" });
    assert.equal(enveloped.ok, true);
    if (enveloped.ok) assert.equal(enveloped.decision.approvalId, "apr-1");
    assert.equal(parseEnforceResponse(undefined).ok, false);
    assert.equal(parseEnforceResponse("allow").ok, false);
    assert.equal(parseEnforceResponse({ decision: null }).ok, false);
  });
});

// ─── Retry semantics ────────────────────────────────────────────

describe("remote enforce: retries", () => {
  test("429 with Retry-After is retried and the second response is honoured", async () => {
    setupFetchSequence(
      { status: 429, body: "slow down", headers: { "Retry-After": "0" } },
      { status: 200, body: blockDecision },
    );

    const remote = createRemoteEnforcer(config);
    const decision = await remote.enforce(ctx);

    assert.equal(decision.blocked, true);
    assert.equal(decision.ruleId, "block-tools");
    assert.equal(mockFetch.mock.calls.length, 2);
    assert.equal(remote.status().lastAttempts, 2);
    assert.equal(remote.status().connected, true);
    assert.equal(remote.status().mode, "remote");
  });

  test("429 exhausted falls back instead of throwing", async () => {
    setupFetchMock(429, "Too Many Requests", { "Retry-After": "0" });

    const remote = createRemoteEnforcer({ ...config, maxRetries: 1 });
    const decision = await remote.enforce(ctx);

    assert.equal(decision.blocked, false);
    assert.match(decision.reason, /rate-limited the request \(HTTP 429\) after 2 attempts/);
    assert.equal(mockFetch.mock.calls.length, 2);
    assert.equal(remote.status().connected, true, "a 429 is an answer; the API is up");
    assert.equal(remote.status().mode, "fallback");
    assert.equal(remote.status().lastAttempts, 2);
  });

  test("default maxRetries (3) means 4 requests", async () => {
    setupFetchMock(429, "Too Many Requests", { "Retry-After": "0" });

    const remote = createRemoteEnforcer(config);
    await remote.enforce(ctx);
    assert.equal(mockFetch.mock.calls.length, 4);
    assert.equal(remote.status().lastAttempts, 4);
  });

  test("maxRetries: 0 makes exactly one request", async () => {
    setupFetchMock(503, "unavailable", { "Retry-After": "0" });

    const remote = createRemoteEnforcer({ ...config, maxRetries: 0 });
    await remote.enforce(ctx);
    assert.equal(mockFetch.mock.calls.length, 1);
  });

  test("503 with an HTTP-date Retry-After in the past is retried immediately", async () => {
    setupFetchSequence(
      { status: 503, body: "", headers: { "Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT" } },
      { status: 200, body: allowDecision },
    );

    const remote = createRemoteEnforcer(config);
    const decision = await remote.enforce(ctx);
    assert.equal(decision.reason, "Allowed by remote");
    assert.equal(mockFetch.mock.calls.length, 2);
  });

  test("falls back on 500 after retries (fail-open) and reports disconnected", async () => {
    setupFetchMock(500, "Internal Server Error");

    const remote = createRemoteEnforcer({ ...config, maxRetries: 0 });
    const decision = await remote.enforce(ctx);
    assert.equal(decision.blocked, false);
    assert.match(decision.reason, /is unavailable \(HTTP 500\) after 1 attempt —/);
    assert.equal(remote.status().connected, false);
  });

  test("blocks on 500 with fallbackMode block", async () => {
    setupFetchMock(500, "Internal Server Error");

    const remote = createRemoteEnforcer({ ...config, maxRetries: 0, fallbackMode: "block" });
    const decision = await remote.enforce(ctx);
    assert.equal(decision.blocked, true);
    assert.match(decision.reason, /blocking/);
  });

  test("falls back on network failure (fail-open)", async () => {
    setupFetchSequence({ status: 0, reject: new TypeError("fetch failed") });

    const remote = createRemoteEnforcer({ ...config, maxRetries: 0 });
    const decision = await remote.enforce(ctx);
    assert.equal(decision.blocked, false);
    assert.match(decision.reason, /unreachable after 1 attempt \(fetch failed\)/);
    assert.equal(remote.status().connected, false);
  });
});

// ─── Status-code semantics ──────────────────────────────────────

describe("remote enforce: 4xx handling", () => {
  test("401 throws RemoteEnforcementError (misconfiguration must be loud)", async () => {
    setupFetchMock(401, "Unauthorized");

    const remote = createRemoteEnforcer(config);
    await assert.rejects(
      () => remote.enforce({ agentId: "a1", action: "tool_call" }),
      (err: RemoteEnforcementError) => {
        assert.equal(err.name, "RemoteEnforcementError");
        assert.equal(err.statusCode, 401);
        assert.equal(err.retryable, false);
        assert.ok(err.message.includes("401"));
        return true;
      },
    );
    assert.equal(mockFetch.mock.calls.length, 1);
  });

  test("403 throws RemoteEnforcementError", async () => {
    setupFetchMock(403, "Forbidden");

    const remote = createRemoteEnforcer(config);
    await assert.rejects(
      () => remote.enforce({ agentId: "a1", action: "tool_call" }),
      (err: RemoteEnforcementError) => {
        assert.equal(err.statusCode, 403);
        return true;
      },
    );
  });

  for (const status of [400, 404, 422]) {
    test(`${status} falls back without retrying and names the status`, async () => {
      setupFetchMock(status, "nope");

      const remote = createRemoteEnforcer(config);
      const decision = await remote.enforce(ctx);
      assert.equal(decision.blocked, false);
      assert.match(decision.reason, new RegExp(`rejected the request \\(HTTP ${status}\\)`));
      assert.equal(mockFetch.mock.calls.length, 1);
      assert.equal(remote.status().connected, true);
      assert.equal(remote.status().mode, "fallback");
    });
  }

  test("400 with fallbackMode block returns a blocked decision", async () => {
    setupFetchMock(400, "bad");
    const remote = createRemoteEnforcer({ ...config, fallbackMode: "block" });
    const decision = await remote.enforce(ctx);
    assert.equal(decision.blocked, true);
  });
});

// ─── onFallback hook ────────────────────────────────────────────

describe("onFallback", () => {
  test("fires with status and attempts on a non-retryable 4xx", async () => {
    setupFetchMock(400, "bad");
    const calls: RemoteFallbackInfo[] = [];

    const remote = createRemoteEnforcer({ ...config, onFallback: (info) => calls.push(info) });
    await remote.enforce(ctx);

    assert.equal(calls.length, 1);
    assert.equal(calls[0].status, 400);
    assert.equal(calls[0].attempts, 1);
    assert.match(calls[0].reason, /HTTP 400/);
  });

  test("fires without a status on network failure, with attempts = 1 + maxRetries", async () => {
    setupFetchSequence({ status: 0, reject: new Error("ECONNREFUSED") });
    const calls: RemoteFallbackInfo[] = [];

    const remote = createRemoteEnforcer({ ...config, maxRetries: 1, onFallback: (info) => calls.push(info) });
    await remote.enforce(ctx);

    assert.equal(calls.length, 1);
    assert.equal(calls[0].status, undefined);
    assert.equal(calls[0].attempts, 2);
    assert.match(calls[0].reason, /ECONNREFUSED/);
  });

  test("fires with the 2xx status on a contract violation", async () => {
    setupFetchMock(200, {});
    const calls: RemoteFallbackInfo[] = [];

    const remote = createRemoteEnforcer({ ...config, onFallback: (info) => calls.push(info) });
    await remote.enforce(ctx);

    assert.equal(calls.length, 1);
    assert.equal(calls[0].status, 200);
    assert.match(calls[0].reason, /decision\.blocked/);
  });

  test("does not fire on success or when auth failures throw", async () => {
    const calls: RemoteFallbackInfo[] = [];
    const remote = createRemoteEnforcer({ ...config, onFallback: (info) => calls.push(info) });

    setupFetchMock(200, allowDecision);
    await remote.enforce(ctx);
    setupFetchMock(401, "Unauthorized");
    await assert.rejects(() => remote.enforce(ctx), RemoteEnforcementError);

    assert.equal(calls.length, 0);
  });

  test("a throwing hook does not change the enforcement result", async () => {
    setupFetchMock(400, "bad");
    const remote = createRemoteEnforcer({
      ...config,
      fallbackMode: "block",
      onFallback: () => { throw new Error("pager is down"); },
    });
    const decision = await remote.enforce(ctx);
    assert.equal(decision.blocked, true);
  });
});

// ─── redactInput ────────────────────────────────────────────────

describe("redactInput", () => {
  const richCtx: EnforcementContext = {
    agentId: "agent-1",
    action: "tool_call",
    tool: "shell_exec",
    input: { cmd: "rm -rf /" },
    inputText: "please run rm -rf /",
    outputText: "done",
    metadata: { userId: "u-1" },
    textByModality: { text: "please run rm -rf /" },
    agentLevel: 2,
    recentActionCount: 4,
  };

  test("default sends the whole context, raw content included", async () => {
    setupFetchMock(200, allowDecision);
    const remote = createRemoteEnforcer(config);
    await remote.enforce(richCtx);

    const body = requestBody();
    assert.deepEqual(body.input, { cmd: "rm -rf /" });
    assert.equal(body.inputText, "please run rm -rf /");
    assert.equal(body.outputText, "done");
    assert.deepEqual(body.metadata, { userId: "u-1" });
    assert.deepEqual(body.textByModality, { text: "please run rm -rf /" });
  });

  test("redactInput: true strips content fields and keeps everything else", async () => {
    setupFetchMock(200, allowDecision);
    const remote = createRemoteEnforcer({ ...config, redactInput: true });
    await remote.enforce(richCtx);

    const body = requestBody();
    for (const field of REDACTED_CONTEXT_FIELDS) {
      assert.equal(field in body, false, `${field} must not be sent`);
    }
    assert.equal(body.agentId, "agent-1");
    assert.equal(body.tool, "shell_exec");
    assert.equal(body.agentLevel, 2);
    assert.equal(body.recentActionCount, 4);
  });

  test("redactInput function controls exactly what is sent", async () => {
    setupFetchMock(200, allowDecision);
    const remote = createRemoteEnforcer({
      ...config,
      redactInput: (c) => ({ agentId: c.agentId, action: c.action, tool: c.tool, metadata: { tenant: "t-1" } }),
    });
    await remote.enforce(richCtx);

    assert.deepEqual(requestBody(), { agentId: "agent-1", action: "tool_call", tool: "shell_exec", metadata: { tenant: "t-1" } });
  });

  test("redactContext does not mutate its argument", () => {
    const copy = redactContext(richCtx);
    assert.equal(richCtx.input?.cmd, "rm -rf /");
    assert.equal("input" in copy, false);
    assert.equal(copy.agentId, "agent-1");
  });
});

// ─── Retry helpers (pure) ───────────────────────────────────────

describe("retry helpers", () => {
  test("isRetryableStatus", () => {
    for (const s of [0, 408, 425, 429, 500, 502, 503, 504]) assert.equal(isRetryableStatus(s), true, `${s}`);
    for (const s of [200, 400, 401, 403, 404, 409, 422]) assert.equal(isRetryableStatus(s), false, `${s}`);
  });

  test("parseRetryAfter handles delay-seconds, HTTP-dates and garbage", () => {
    const now = Date.parse("2026-09-04T00:00:00Z");
    assert.equal(parseRetryAfter("3"), 3000);
    assert.equal(parseRetryAfter(" 0 "), 0);
    assert.equal(parseRetryAfter("Fri, 04 Sep 2026 00:00:05 GMT", now), 5000);
    assert.equal(parseRetryAfter("Wed, 21 Oct 2015 07:28:00 GMT", now), 0);
    assert.equal(parseRetryAfter("-1", now), undefined);
    assert.equal(parseRetryAfter("1.5", now), undefined);
    assert.equal(parseRetryAfter("garbage", now), undefined);
    assert.equal(parseRetryAfter("", now), undefined);
    assert.equal(parseRetryAfter(null), undefined);
    assert.equal(parseRetryAfter(undefined), undefined);
  });

  test("retryDelayMs follows the backoff schedule, prefers Retry-After, and caps both", () => {
    const plain = new RemoteEnforcementError("x", 500, "");
    assert.equal(retryDelayMs(0, plain, 30_000), RETRY_DELAYS_MS[0]);
    assert.equal(retryDelayMs(1, plain, 30_000), RETRY_DELAYS_MS[1]);
    assert.equal(retryDelayMs(2, plain, 30_000), RETRY_DELAYS_MS[2]);
    assert.equal(retryDelayMs(9, plain, 30_000), RETRY_DELAYS_MS[2], "last value repeats");
    assert.equal(retryDelayMs(0, new TypeError("fetch failed"), 30_000), RETRY_DELAYS_MS[0]);

    const hinted = new RemoteEnforcementError("x", 429, "", 7000);
    assert.equal(retryDelayMs(0, hinted, 30_000), 7000);
    assert.equal(retryDelayMs(0, new RemoteEnforcementError("x", 429, "", 120_000), 30_000), 30_000, "30s cap");
    assert.equal(retryDelayMs(0, hinted, 2000), 2000, "request timeout cap");
    assert.equal(retryDelayMs(2, plain, 500), 500, "cap applies to backoff too");
  });

  test("withRetry reports attempts, sleeps between tries and stops on non-retryable errors", async () => {
    const sleeps: number[] = [];
    const sleep = (ms: number) => { sleeps.push(ms); return Promise.resolve(); };

    let n = 0;
    const flaky = await withRetry(() => {
      n += 1;
      return n < 3 ? Promise.reject(new RemoteEnforcementError("x", 503, "", 1000)) : Promise.resolve("ok");
    }, { maxRetries: 3, maxWaitMs: 30_000, sleep });
    assert.deepEqual(flaky, { ok: true, value: "ok", attempts: 3 });
    assert.deepEqual(sleeps, [1000, 1000]);

    const exhausted = await withRetry(() => Promise.reject(new Error("down")), { maxRetries: 2, maxWaitMs: 30_000, sleep });
    assert.equal(exhausted.ok, false);
    assert.equal(exhausted.attempts, 3);

    let calls = 0;
    const auth = await withRetry(() => { calls += 1; return Promise.reject(new RemoteEnforcementError("x", 401, "")); }, { maxRetries: 3, maxWaitMs: 30_000, sleep });
    assert.equal(auth.ok, false);
    assert.equal(auth.attempts, 1);
    assert.equal(calls, 1);

    const nan = await withRetry(() => Promise.reject(new Error("down")), { maxRetries: Number.NaN, maxWaitMs: 30_000, sleep });
    assert.equal(nan.attempts, 1, "non-finite maxRetries means no retries, not infinite retries");
  });

  test("fallbackDecision names the cause", () => {
    assert.match(fallbackDecision("allow", new TypeError("fetch failed"), 4).reason, /unreachable after 4 attempts \(fetch failed\)/);
    assert.match(fallbackDecision("block", new RemoteEnforcementError("x", 429, ""), 4).reason, /rate-limited the request \(HTTP 429\) after 4 attempts — blocking/);
    assert.match(fallbackDecision("allow", new RemoteContractError("decision.blocked must be a boolean", 200, "{}")).reason, /invalid response \(HTTP 200: decision\.blocked must be a boolean\)/);
  });
});

// ─── Remote register ────────────────────────────────────────────

describe("remote register (POST /api/v1/agents)", () => {
  test("POSTs to /api/v1/agents and returns authoritative score + level", async () => {
    setupFetchMock(201, { id: "agent-abc", name: "my-agent", compositeScore: 72, governanceLevel: 3, status: "approved" });
    const remote = createRemoteEnforcer(config);
    const result = await remote.register({ name: "my-agent", framework: "mastra", owner: "team-a" });

    assert.equal(mockFetch.mock.calls.length, 1);
    assert.equal(mockFetch.mock.calls[0].arguments[0], "https://api.example.com/api/v1/agents");
    assert.equal(result.id, "agent-abc");
    assert.equal(result.score, 72);
    assert.equal(result.level, 3);
    assert.equal(result.status, "approved");
    assert.equal(result.assessment.agentName, "my-agent");
  });

  test("falls back to synthetic receipt when the API is unreachable", async () => {
    setupFetchMock(500, {});
    const remote = createRemoteEnforcer(config);
    const result = await remote.register({ name: "my-agent", framework: "mastra", owner: "team-a" });

    // Non-200 — we fall through so register never throws on the caller.
    assert.equal(result.id, "my-agent");
    assert.equal(result.status, "registered");
    assert.equal(result.level, 0);
  });
});

// ─── Integration: createGovernance with remote ──────────────────

describe("createGovernance remote integration", () => {
  test("enforce delegates to remote when serverUrl is set", async () => {
    setupFetchMock(200, { ...blockDecision, reason: "Remote block", ruleId: "remote-rule", rulesEvaluated: 1 });

    const gov = createGovernance({
      serverUrl: "https://api.example.com",
      apiKey: "key-123",
      rules: [], // local rules should be ignored for enforce
    });

    const decision = await gov.enforce({ agentId: "a1", action: "tool_call", tool: "shell_exec" });

    assert.equal(decision.blocked, true);
    assert.equal(decision.reason, "Remote block");
    assert.equal(mockFetch.mock.calls.length, 1);
  });

  test("register POSTs to /api/v1/agents when serverUrl is set", async () => {
    setupFetchMock(201, { id: "agent-xyz", name: "test", compositeScore: 55, governanceLevel: 2, status: "approved" });

    const gov = createGovernance({ serverUrl: "https://api.example.com", apiKey: "key-123" });
    const result = await gov.register({ name: "test", framework: "mastra", owner: "team" });

    // Register fetches authoritative score/level from the API rather than
    // returning a synthetic level: 0 placeholder.
    assert.equal(result.id, "agent-xyz");
    assert.equal(result.level, 2);
    assert.equal(mockFetch.mock.calls.length, 1);
    assert.equal(mockFetch.mock.calls[0].arguments[0], "https://api.example.com/api/v1/agents");
  });

  test("local methods still work when serverUrl is set", async () => {
    setupFetchMock(200, {});
    const gov = createGovernance({ serverUrl: "https://api.example.com", apiKey: "key-123" });

    // These should NOT go through remote
    assert.ok(gov.policies);
    assert.ok(gov.storage);
    assert.ok(gov.audit);
    assert.ok(gov.score);
    assert.ok(gov.scoreFleet);
  });
});

// ─── Status tracking ────────────────────────────────────────────

describe("remote status tracking", () => {
  test("auth failure leaves connected=true because the API answered us", async () => {
    setupFetchMock(200, { decision: allowDecision });
    const enforcer = createRemoteEnforcer({ serverUrl: "https://api.example.com", apiKey: "key-123" });
    await enforcer.enforce({ agentId: "a", agentName: "a", agentLevel: 1, action: "tool_call" });
    assert.equal(enforcer.status().connected, true);

    // A 401 must throw but must NOT flip connected to false — the API
    // answered; only transport-level failure counts as disconnection.
    setupFetchMock(401, "Unauthorized");
    await assert.rejects(
      () => enforcer.enforce({ agentId: "a", agentName: "a", agentLevel: 1, action: "tool_call" }),
      RemoteEnforcementError,
    );
    assert.equal(enforcer.status().connected, true, "4xx is an API-layer error; the connection is still healthy");
    assert.equal(enforcer.status().mode, "remote");
  });

  test("network failure flips connected to false then back to true on recovery", async () => {
    const enforcer = createRemoteEnforcer({ serverUrl: "https://api.example.com", apiKey: "key-123", maxRetries: 0 });

    // Offline.
    setupFetchSequence({ status: 0, reject: new Error("ECONNREFUSED") });
    await enforcer.enforce({ agentId: "a", agentName: "a", agentLevel: 1, action: "tool_call" });
    assert.equal(enforcer.status().connected, false);
    assert.equal(enforcer.status().mode, "fallback");

    // Recovery.
    setupFetchMock(200, { decision: allowDecision });
    await enforcer.enforce({ agentId: "a", agentName: "a", agentLevel: 1, action: "tool_call" });
    assert.equal(enforcer.status().connected, true);
    assert.equal(enforcer.status().mode, "remote");
  });

  test("connect() reports plan/features and resets mode to remote", async () => {
    setupFetchMock(200, { plan: "pro", features: ["approvals"], agentQuota: { used: 3, limit: 25 } });
    const enforcer = createRemoteEnforcer(config);
    const status = await enforcer.connect();
    assert.equal(status.connected, true);
    assert.equal(status.mode, "remote");
    assert.equal(status.plan, "pro");
    assert.deepEqual(status.features, ["approvals"]);
    assert.equal(mockFetch.mock.calls[0].arguments[0], "https://api.example.com/api/v1/connect");

    setupFetchSequence({ status: 0, reject: new Error("ECONNREFUSED") });
    const offline = await enforcer.connect();
    assert.equal(offline.connected, false);
    assert.equal(offline.mode, "fallback");
  });
});
