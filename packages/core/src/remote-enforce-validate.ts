/**
 * Wire shapes for the remote enforcer: what is sent (request minimisation via
 * redactContext) and what is accepted back (response validation).
 *
 * A hosted governance API is untrusted input as far as type safety goes: a
 * server returning `{}` must not be read as `blocked: undefined` and treated
 * as allow. These guards check the shape documented in
 * docs/remote-contract.md before a decision is honoured. Zero dependencies.
 */

import type { EnforcementContext, EnforcementDecision, PolicyOutcome, PolicyStage } from "./policy.js";

// ─── Types ──────────────────────────────────────────────────────

/** Envelope response form: `{ decision, approvalId?, approval? }`. */
export interface EnforcementDecisionEnvelope {
  decision: EnforcementDecision;
  approvalId?: string;
  approval?: EnforcementDecision["approval"];
}

/** Result of parsing a 2xx enforce response body. */
export type ParsedEnforceResponse =
  | { ok: true; decision: EnforcementDecision }
  | { ok: false; violation: string };

/**
 * A 2xx response whose body does not match the contract. Never retried —
 * treated like a transport failure and routed to the fallback decision.
 */
export class RemoteContractError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly responseBody: string,
  ) {
    super(message);
    this.name = "RemoteContractError";
  }
}

// ─── Primitive guards ───────────────────────────────────────────

type Approval = NonNullable<EnforcementDecision["approval"]>;
type UnknownRecord = Record<string, unknown>;

const POLICY_OUTCOMES: ReadonlySet<string> = new Set<PolicyOutcome>([
  "allow", "block", "warn", "require_approval", "mask",
]);
const POLICY_STAGES: ReadonlySet<string> = new Set<PolicyStage>([
  "preprocess", "process", "tool_result", "postprocess",
]);

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const isString = (value: unknown): value is string => typeof value === "string";

const isOptionalString = (value: unknown): value is string | undefined =>
  value === undefined || isString(value);

function isApproval(value: unknown): value is Approval {
  return isRecord(value)
    && isString(value.id)
    && isString(value.status)
    && isString(value.pollUrl)
    && isString(value.message);
}

const isOptionalApproval = (value: unknown): value is Approval | undefined =>
  value === undefined || isApproval(value);

// ─── Decision guard ─────────────────────────────────────────────

/**
 * Return the first contract violation of `value` as an EnforcementDecision,
 * or null when it is valid.
 *
 * Required: blocked (boolean), outcome (allow | block | warn |
 * require_approval | mask), reason (string), ruleId (string | null),
 * evaluatedAt (string), rulesEvaluated (finite number). `outcome: "block"`
 * requires `blocked: true` and `outcome: "allow"` requires `blocked: false`.
 * Optional fields must be absent (undefined) or well-typed. Unknown extra
 * fields are ignored.
 */
export function describeDecisionViolation(value: unknown): string | null {
  if (!isRecord(value)) return "decision must be a JSON object";
  if (typeof value.blocked !== "boolean") return "decision.blocked must be a boolean";
  if (!isString(value.outcome) || !POLICY_OUTCOMES.has(value.outcome)) {
    return "decision.outcome must be one of allow, block, warn, require_approval, mask";
  }
  if (value.outcome === "block" && value.blocked !== true) return 'decision.outcome "block" requires blocked: true';
  if (value.outcome === "allow" && value.blocked !== false) return 'decision.outcome "allow" requires blocked: false';
  if (!isString(value.reason)) return "decision.reason must be a string";
  if (value.ruleId !== null && !isString(value.ruleId)) return "decision.ruleId must be a string or null";
  if (!isString(value.evaluatedAt)) return "decision.evaluatedAt must be a string";
  if (typeof value.rulesEvaluated !== "number" || !Number.isFinite(value.rulesEvaluated)) {
    return "decision.rulesEvaluated must be a finite number";
  }
  if (value.stage !== undefined && !(isString(value.stage) && POLICY_STAGES.has(value.stage))) {
    return "decision.stage must be one of preprocess, process, tool_result, postprocess when present";
  }
  if (value.condition !== undefined && !(isRecord(value.condition) && isString(value.condition.type))) {
    return "decision.condition must be { type: string } when present";
  }
  if (!isOptionalString(value.remedy)) return "decision.remedy must be a string when present";
  if (value.degradedFrom !== undefined && value.degradedFrom !== "mask") {
    return 'decision.degradedFrom must be "mask" when present';
  }
  if (!isOptionalString(value.maskedText)) return "decision.maskedText must be a string when present";
  if (!isOptionalString(value.approvalId)) return "decision.approvalId must be a string when present";
  if (!isOptionalApproval(value.approval)) {
    return "decision.approval must be { id, status, pollUrl, message } (all strings) when present";
  }
  return null;
}

/** Type guard for the wire form of an EnforcementDecision. See describeDecisionViolation(). */
export function isEnforcementDecision(value: unknown): value is EnforcementDecision {
  return describeDecisionViolation(value) === null;
}

// ─── Response parsing ───────────────────────────────────────────

const NULLABLE_OPTIONAL_FIELDS = [
  "stage", "condition", "remedy", "degradedFrom", "maskedText", "approvalId", "approval",
] as const;

/**
 * Shallow copy with optional decision fields sent as `null` removed. JSON
 * APIs commonly emit null for "absent"; the TypeScript type says undefined.
 */
function withoutNullOptionals(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const copy: UnknownRecord = { ...value };
  for (const key of NULLABLE_OPTIONAL_FIELDS) {
    if (copy[key] === null) delete copy[key];
  }
  return copy;
}

function parseDecision(value: unknown): ParsedEnforceResponse {
  const candidate = withoutNullOptionals(value);
  if (!isEnforcementDecision(candidate)) {
    return { ok: false, violation: describeDecisionViolation(candidate) ?? "decision is invalid" };
  }
  return { ok: true, decision: candidate };
}

/**
 * Parse a JSON-decoded 2xx body into a decision. Accepts either a bare
 * EnforcementDecision or the envelope `{ decision, approvalId?, approval? }`
 * (detected by the presence of a `decision` key); envelope approval fields
 * are copied onto the decision. Optional fields sent as null are treated as
 * absent. Never throws.
 */
export function parseEnforceResponse(body: unknown): ParsedEnforceResponse {
  if (!isRecord(body) || !("decision" in body)) return parseDecision(body);

  const parsed = parseDecision(body.decision);
  if (!parsed.ok) return parsed;

  const approvalId = body.approvalId ?? undefined;
  if (!isOptionalString(approvalId)) return { ok: false, violation: "approvalId must be a string when present" };
  const approval = body.approval ?? undefined;
  if (!isOptionalApproval(approval)) {
    return { ok: false, violation: "approval must be { id, status, pollUrl, message } (all strings) when present" };
  }

  const decision: EnforcementDecision = { ...parsed.decision };
  if (approvalId !== undefined) decision.approvalId = approvalId;
  if (approval !== undefined) decision.approval = approval;
  return { ok: true, decision };
}

// ─── Request minimisation ───────────────────────────────────────

/**
 * Fields removed by `redactInput: true` — everywhere raw prompt, tool-input
 * or output content travels on the context. Provenance (`taint`), scores and
 * counters are kept: they are what content-free remote rules need.
 */
export const REDACTED_CONTEXT_FIELDS = [
  "input", "inputText", "outputText", "metadata", "textByModality",
] as const satisfies readonly (keyof EnforcementContext)[];

/** Copy of `ctx` without REDACTED_CONTEXT_FIELDS. Does not mutate `ctx`. */
export function redactContext(ctx: EnforcementContext): EnforcementContext {
  const copy: EnforcementContext = { ...ctx };
  for (const key of REDACTED_CONTEXT_FIELDS) delete copy[key];
  return copy;
}
