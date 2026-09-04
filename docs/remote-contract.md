# Remote enforcer wire contract

This document is the exact HTTP contract the `governance-sdk` client speaks
when `createGovernance({ serverUrl, apiKey })` is configured (hosted mode).
Any server that implements it works; the SDK is vendor-neutral. It describes
what the client sends, what it accepts back, and how it behaves on every
failure path. Source of truth is the implementation:

- Client: [`packages/governance/src/remote-enforce.ts`](../packages/governance/src/remote-enforce.ts)
- Retry and fallback policy: [`packages/governance/src/remote-enforce-retry.ts`](../packages/governance/src/remote-enforce-retry.ts)
- Request minimisation and response validation: [`packages/governance/src/remote-enforce-validate.ts`](../packages/governance/src/remote-enforce-validate.ts)
- Request/response types: [`EnforcementContext`, `EnforcementDecision`](../packages/governance/src/policy.ts), [`AgentRegistration`](../packages/governance/src/types.ts)
- Client options: [`RemoteConfig`, `RemoteStatus`, `RemoteFallbackInfo`](../packages/governance/src/remote-enforce.ts)

If this page and the code disagree, the code is right and this page has a bug.

## Base URL and authentication

- `serverUrl` must be an absolute `http:` or `https:` URL. A trailing slash is
  stripped; every path below is appended to it verbatim. No other path prefix
  is configurable.
- Every request carries `Authorization: Bearer <apiKey>`. The key is never
  placed in a query string or body.
- Requests with a body carry `Content-Type: application/json`.
- No other headers are sent (no user-agent override, no request id, no
  telemetry). The client does not check the response `Content-Type`; bodies
  are read as text and parsed as JSON.

## Endpoints

| Method | Path | Used by | Timeout per attempt | Retried |
|---|---|---|---|---|
| `POST` | `/api/v1/enforce` | `enforce(ctx)` | `timeout` (default 30 000 ms) | yes |
| `POST` | `/api/v1/enforce/{stage}` | `enforcePreprocess` / `enforceProcess` / `enforceToolResult` / `enforcePostprocess` | `timeout` | yes |
| `POST` | `/api/v1/agents` | `register(input)` | `timeout` | no |
| `GET` | `/api/v1/connect` | `connect()`, `npx governance-sdk connect` | 5 000 ms (CLI: 10 000 ms) | no |
| `GET` | `/api/v1/approvals/{id}` | `waitForApproval(id)` | 5 000 ms per poll | polled |

`{stage}` is one of `preprocess`, `process`, `tool_result`, `postprocess`
(`PolicyStage` in `policy.ts`).

## `POST /api/v1/enforce` and `POST /api/v1/enforce/{stage}`

### Request body

The JSON serialisation of an [`EnforcementContext`](../packages/governance/src/policy.ts).
Every field the host populated is sent — by default this includes the raw
tool input (`input`), prompt text (`inputText`), model output (`outputText`),
free-form `metadata`, and per-modality extracted text (`textByModality`).
Required fields are `agentId` and `action`; everything else is optional and
absent keys are simply omitted from the JSON.

#### Context minimisation (`redactInput`)

`RemoteConfig.redactInput` controls what leaves the process:

| Value | Body sent |
|---|---|
| `false` / unset (default) | The whole context. |
| `true` | The context minus `input`, `inputText`, `outputText`, `metadata`, `textByModality` (`REDACTED_CONTEXT_FIELDS`). Provenance (`taint`), scores, counters, identity flags and the tool name are still sent. A server receiving a redacted context cannot evaluate content-scanning rules (injection guard, sensitive-data filter, blocklists, `mask`). |
| `(ctx) => EnforcementContext` | Exactly the object the function returns. The function runs once per `enforce()` call; if it throws, `enforce()` throws. |

The projection is computed once per call, so every retry sends an identical body.

### Response body

Status `2xx` with a JSON body in either of two forms:

**Bare decision**

```json
{
  "blocked": false,
  "outcome": "allow",
  "reason": "No rule matched",
  "ruleId": null,
  "evaluatedAt": "2026-09-04T10:15:00.000Z",
  "rulesEvaluated": 4
}
```

**Envelope** (detected by the presence of a `decision` key)

```json
{
  "decision": { "...": "an EnforcementDecision as above" },
  "approvalId": "apr_123",
  "approval": { "id": "apr_123", "status": "pending", "pollUrl": "/api/v1/approvals/apr_123", "message": "Awaiting reviewer" }
}
```

Envelope `approvalId` / `approval` are copied onto the decision; a value on
the decision itself is overwritten by the envelope value when both are present.

#### Decision fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `blocked` | `boolean` | yes | The only field that gates the action downstream. |
| `outcome` | `"allow" \| "block" \| "warn" \| "require_approval" \| "mask"` | yes | `"block"` requires `blocked: true`; `"allow"` requires `blocked: false`. Other outcomes may pair with either. |
| `reason` | `string` | yes | Human-readable; surfaced to the agent/host and the audit log. |
| `ruleId` | `string \| null` | yes | `null` when no rule matched. The key must be present. |
| `evaluatedAt` | `string` | yes | ISO-8601 recommended; only the type is checked. |
| `rulesEvaluated` | `number` (finite) | yes | |
| `stage` | `PolicyStage` | no | |
| `condition` | `{ type: string }` | no | Matched condition type. |
| `remedy` | `string` | no | One-line hint on how to make the call pass. |
| `degradedFrom` | `"mask"` | no | Mask rule matched but no redaction could be produced. |
| `maskedText` | `string` | no | Redacted text when `outcome` is `"mask"`. |
| `approvalId` | `string` | no | |
| `approval` | `{ id, status, pollUrl, message }` all `string` | no | |

Validation rules (`isEnforcementDecision` / `parseEnforceResponse`):

- Required fields must be present with the exact type above. `{}` is invalid.
- Optional fields must be absent or well-typed. A `null` optional field is
  treated as absent (JSON APIs commonly emit `null`); `undefined` is not JSON.
- Unknown extra fields are ignored and passed through untouched.
- Arrays, strings, numbers and `null` at the top level are invalid.
- A body that is not valid JSON (including an empty body / `204`) is invalid.

An invalid or missing decision is a **contract violation**: `enforce()` does
not throw and does not retry — it returns the fallback decision (below) with a
reason naming the first violated field, e.g. `Governance API returned an
invalid response (HTTP 200: decision.blocked must be a boolean) — allowing by
fallback policy.`, and calls `onFallback` with `status` set to the 2xx status.

### Status-code semantics

| Response | Client behaviour | `status().connected` |
|---|---|---|
| `2xx`, valid body | Decision honoured. `mode: "remote"`. | `true` |
| `2xx`, invalid body / not JSON | Fallback decision, no retry. | `true` |
| `401`, `403` | **Throws `RemoteEnforcementError`** (`statusCode`, `responseBody`, `retryable: false`). Not retried. Never falls back: a rejected key is misconfiguration, not an outage. | `true` |
| other `4xx` (`400`, `404`, `409`, `422`, …) except below | Fallback decision, no retry. Reason: `Governance API rejected the request (HTTP 4xx) after 1 attempt — …`. | `true` |
| `408`, `425`, `429` | Retried (see below). If retries are exhausted: fallback decision. Reason for 429: `Governance API rate-limited the request (HTTP 429) after N attempts — …`. | `true` |
| `5xx` | Retried. If exhausted: fallback decision, reason `Governance API is unavailable (HTTP 5xx) after N attempts — …`. | `false` |
| No HTTP response (DNS/TCP/TLS failure, abort, per-attempt timeout) | Retried. If exhausted: fallback decision, reason `Governance API unreachable after N attempts (<error message>) — …`. | `false` |

`3xx` responses are followed by `fetch` transparently (default redirect mode);
the SDK never sees them.

### Retry, backoff and `Retry-After`

- `maxRetries` (default `3`) is the number of **retries after the first
  attempt**. Total HTTP requests per `enforce()` call = `1 + maxRetries`, so
  the default makes up to **4 requests**. `0` disables retries. Non-finite
  values are treated as `0`.
- Only retryable failures are retried: `408`, `425`, `429`, any `5xx`, and
  requests that produced no HTTP response (network error, timeout). `4xx`
  other than those, `401`/`403`, and contract violations are never retried.
- Wait before retry *n* (n = 1, 2, 3, …): `100 ms`, `500 ms`, `2 000 ms`,
  then `2 000 ms` for every further retry (`RETRY_DELAYS_MS`).
- If the failing response carries a `Retry-After` header the client waits
  **that** long instead of the backoff value. Both forms are accepted:
  delay-seconds (`Retry-After: 7`) and HTTP-date (`Retry-After: Fri, 04 Sep
  2026 10:15:07 GMT`); a date in the past means retry immediately.
  Unparseable values are ignored (backoff is used).
- Every wait — hinted or backoff — is capped at `min(30 000 ms, timeout)`.
  A `Retry-After: 120` therefore waits 30 s (or less if `timeout` is
  shorter) and retries; a server that wants the client to back off for
  longer than that should expect a second `429` and the client to fall back.
- Each attempt has its own `timeout` (`AbortSignal.timeout`); the total wall
  time for one `enforce()` call is bounded by `(1 + maxRetries) × timeout`
  plus the waits.
- `register()`, `connect()` and each `waitForApproval()` poll make exactly
  one request; they are not retried by this policy.

### Fallback behaviour and defaults

When no valid decision can be obtained (retries exhausted, non-auth `4xx`,
contract violation), `enforce()` resolves — it does not reject — with a
synthetic decision:

```json
{
  "blocked": false,
  "outcome": "allow",
  "reason": "Governance API unreachable after 4 attempts (fetch failed) — allowing by fallback policy.",
  "ruleId": null,
  "evaluatedAt": "<now>",
  "rulesEvaluated": 0
}
```

- `fallbackMode: "allow"` (default) → `blocked: false, outcome: "allow"`
  (fail-open). `fallbackMode: "block"` → `blocked: true, outcome: "block"`
  (fail-closed).
- `RemoteConfig.onFallback(info)` is invoked once per fallback with
  `{ reason, status?, attempts }` — `status` is the final HTTP status when the
  server answered (including the `2xx` of a contract violation) and
  `undefined` for transport failures; `attempts` is the number of HTTP
  requests made. Exceptions thrown by the hook are swallowed.
- `status()` returns `{ connected, mode, latencyMs, lastAttempts }`:
  `connected` per the table above; `mode` is `"remote"` when the most recent
  `enforce()`/`connect()` was served by the API and `"fallback"` when it
  returned a fallback decision or the API is down; `lastAttempts` is the
  request count of the most recent `enforce()` call (`undefined` before the
  first). `latencyMs` is the duration of the last HTTP attempt.
- The only exception that escapes `enforce()` in hosted mode is
  `RemoteEnforcementError` for `401`/`403` (plus any error thrown by a
  caller-supplied `redactInput` function).

## `POST /api/v1/agents`

### Request body

A fixed projection of [`AgentRegistration`](../packages/governance/src/types.ts) —
**only** these keys, each omitted from the JSON when undefined:

```
id, name, framework, owner, description, tools, channels,
hasAuth, hasGuardrails, hasObservability, hasAuditLog
```

`organizationId`, `version`, `permissions` and `metadata` are **not** sent.

### Response body

Any `2xx` with a JSON object. Fields read (all optional, defensively typed):

| Field | Type | Fallback when missing/ill-typed |
|---|---|---|
| `id` | `string` | `input.name` |
| `name` | `string` | `input.name` |
| `compositeScore` | `number` | `0` |
| `governanceLevel` | `number` 0–4 | `0` (out-of-range values are also clamped to 0; in-range values are rounded) |
| `status` | `"registered" \| "assessed" \| "approved" \| "flagged" \| "deprecated" \| "quarantined"` | `"registered"` |

The server should be idempotent on `id`/`name` — the client calls this on
every start-up and expects the existing record's authoritative score and
level back (`409` is treated like any other non-2xx).

### Failure

Any non-`2xx`, network error or timeout makes `register()` resolve with a
synthetic receipt `{ id: input.name, score: 0, level: 0, status: "registered" }`.
It never throws and is never retried; the next `enforce()` carries the
authoritative data anyway.

## `GET /api/v1/connect`

Health/identity check. Response: `2xx` with a JSON object.

Read by `connect()` (all optional): `plan: string`, `features: string[]`,
`agentQuota: { used: number, limit: number | "unlimited" }`.

Read by `npx governance-sdk connect` (printed as-is, so a server should
provide them): `ok: boolean`, `orgId: string`, `plan: string`,
`features: string[]`, `agentQuota: { used, limit }`, `version: string`.

Any non-`2xx` or network error → `connect()` resolves `{ connected: false,
mode: "fallback", latencyMs: 0 }` (non-2xx keeps the measured latency). The
CLI exits `1` and prints a key hint on `401`.

## `GET /api/v1/approvals/{id}`

Polled by `waitForApproval(approvalId, { timeoutMs = 1 800 000, pollIntervalMs = 5 000 })`.
Response: `2xx` with

```json
{ "request": { "status": "pending" } }
```

| `request.status` | `waitForApproval` returns |
|---|---|
| `"approved"` | `"approved"` |
| `"denied"`, `"cancelled"` | `"denied"` |
| `"expired"` | `"expired"` |
| anything else, non-`2xx`, network error | keep polling |

The deadline yields `"timeout"`. `{id}` is interpolated into the path without
encoding; servers should issue URL-safe approval ids.

## What is and is not sent

| Data | Sent? | Where |
|---|---|---|
| API key | yes | `Authorization` header only |
| Full `EnforcementContext` incl. raw `input`, `inputText`, `outputText`, `metadata`, `textByModality` | **yes by default** | `POST /api/v1/enforce*` body — opt out with `redactInput` |
| `taint` provenance marks, scores, counters, identity flags | yes | `POST /api/v1/enforce*` body (kept even with `redactInput: true`) |
| Agent registration (11 listed fields) | yes | `POST /api/v1/agents` body |
| `AgentRegistration.organizationId`, `version`, `permissions`, `metadata` | no | — |
| Local policy rules, audit entries, storage contents | no | Hosted mode replaces evaluation; it does not sync local state |
| SDK version, hostname, telemetry | no | — |
| Anything on `4xx`/`5xx` retries beyond the identical body | no | Retries resend the same body |

## Implementing a compatible server — checklist

1. Accept `Authorization: Bearer <key>`; answer `401` for a missing/invalid
   key and `403` for a valid key without access. Both make the client throw,
   so use them only for genuine auth problems.
2. Implement `POST /api/v1/enforce` and `POST /api/v1/enforce/{stage}` for the
   four stages. Parse the body as an `EnforcementContext`; tolerate missing
   optional fields (the client may redact `input`, `inputText`, `outputText`,
   `metadata`, `textByModality`).
3. Respond `200` with either wire form. Always include all six required
   decision fields with the exact types; keep `blocked` and `outcome`
   coherent (`block` ⇔ `blocked: true`, `allow` ⇔ `blocked: false`). Omit or
   `null` optional fields you do not use — never send them ill-typed.
4. Never send `204`, an empty body, HTML or a non-object JSON value on `2xx`:
   the client treats it as a contract violation and falls back (fail-open by
   default), which silently disables governance.
5. For validation errors return a `4xx` other than `401`/`403`/`408`/`425`/`429`
   (e.g. `400`, `422`); the client falls back and reports the status. Do not
   use `4xx` for policy outcomes — a blocked action is a `200` with
   `blocked: true`.
6. For overload, send `429` or `503` with `Retry-After` (seconds or
   HTTP-date). Values above 30 s are capped client-side; expect a retry then.
   Budget for up to `1 + maxRetries` (default 4) identical requests per call.
7. Implement `POST /api/v1/agents` idempotently on `id`/`name` and return
   `{ id, name, compositeScore, governanceLevel (0–4), status }`.
8. Implement `GET /api/v1/connect` returning `{ ok, orgId, plan, features,
   agentQuota: { used, limit }, version }`; respond within 5 s.
9. If you issue `require_approval` decisions, include `approvalId` (and
   `approval`) and implement `GET /api/v1/approvals/{id}` returning
   `{ request: { status } }` with the statuses above.
10. Treat the context as sensitive: unless the client redacts, you receive
    raw prompts, tool arguments and outputs.
