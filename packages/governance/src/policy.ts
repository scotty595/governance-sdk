/**
 * Policy Engine — before-action enforcement for AI agents.
 *
 * Evaluates rules in priority order against enforcement contexts.
 * Preset builders are in policy-presets.ts.
 */

import { getBuiltinConditions } from "./conditions/builtins.js";
import { getDefaultStage } from "./policy-stage-defaults.js";
import { maskSensitiveData, maskPattern, maskBlocklistTerms } from "./mask.js";
import { conditionSupportsModalities, type Modality } from "./scan/multi-modal.js";
import { validateRule, assertValidRule } from "./policy-validate.js";
import { describeRemedy } from "./policy-remedies.js";
import type { MaskStrategy } from "./plugin.js";
import type { TaintMark } from "./taint.js";

// ─── Types ──────────────────────────────────────────────────────

export type PolicyAction =
  | "tool_call"
  | "message_send"
  | "data_access"
  | "external_request"
  | "file_write"
  | "database_mutation"
  | "payment"
  | "custom";

export type PolicyOutcome = "allow" | "block" | "warn" | "require_approval" | "mask";

/**
 * Pipeline stages, in execution order:
 *
 *   preprocess  — user input before LLM (injection scanning, blocklists, length)
 *   process     — tool calls after LLM, before tool execution (block-tools, approval, budgets)
 *   tool_result — tool returns AFTER execution, before LLM ingests on next turn
 *                 (injection scanning of tool returns, scope re-checks, output redaction
 *                 of external content)
 *   postprocess — agent's final output before user (PII redaction, output filtering)
 *
 * `tool_result` exists separately from `postprocess` because the threat model
 * is different: tool_result protects the LLM context from external-content
 * injection; postprocess protects the user from agent leaks. Different default
 * conditions, different audit semantics.
 */
export type PolicyStage = "preprocess" | "process" | "tool_result" | "postprocess";

/**
 * How consequential an action is. Regulators (MAS SAFR, China's three-tier
 * agent rules, EU AI Act Art 14) and buyer RFPs converge on tiered human
 * oversight: read-only actions run freely, irreversible ones need a person.
 * Adapters map tools to tiers via config; `requireTierApproval()` gates them.
 */
export type ActionTier = "read" | "reversible" | "external" | "irreversible";

export interface PolicyRule {
  id: string;
  name: string;
  condition: PolicyCondition;
  outcome: PolicyOutcome;
  reason: string;
  priority: number;
  enabled: boolean;
  /** Pipeline stage — defaults to "process" when omitted */
  stage?: PolicyStage;
  /**
   * Which content modalities this rule scans. Only meaningful for
   * content-scanning conditions (`injection_guard`, `sensitive_data_filter`,
   * `blocklist`, `input_pattern`, `output_pattern`, `ml_injection_guard`).
   * Ignored for everything else. Use `conditionSupportsModalities()` from
   * `governance-sdk/scan/multi-modal` to validate before persisting.
   *
   * The host pre-extracts text per modality into `ctx.textByModality`
   * (typically by calling `scanMultiModal()` once for the union of
   * modalities across active rules). When `scanModalities` is unset or
   * empty, the evaluator falls back to its existing input-walk behaviour
   * — strict-improvement-only, no break risk for legacy rules.
   */
  scanModalities?: Modality[];
}

/**
 * A policy condition — built-in or plugin-provided.
 * `type` identifies the evaluator (looked up in the condition registry).
 * `params` holds the configuration for that evaluator.
 */
export interface PolicyCondition {
  type: string;
  params: Record<string, unknown>;
}

export interface EnforcementContext {
  agentId: string;
  agentName?: string;
  agentLevel?: number;
  /**
   * Organization that owns this agent/request. Used to scope the tamper-evident
   * audit chain per-org (each org gets an independent HMAC chain) and for
   * multi-tenant audit queries. Populated by the host; falls back to
   * `metadata.organizationId` when omitted. Does not affect policy evaluation.
   */
  organizationId?: string;
  action: PolicyAction;
  tool?: string;
  input?: Record<string, unknown>;
  /**
   * Canonical text for content rules at the preprocess stage (the user
   * prompt) and the single source the engine masks when a preprocess-stage
   * `mask` rule fires. Adapters set this; when absent the engine falls back
   * to `input.message`, then `input.prompt`, then `input.text`.
   */
  inputText?: string;
  metadata?: Record<string, unknown>;
  sessionTokensUsed?: number;
  recentActionCount?: number;
  /**
   * Epoch-ms timestamps of recent allowed actions in this session, newest
   * last. Populated by the session ledger in `createGovernance()` (local
   * mode) unless the host supplies it. The `rate_limit` condition counts
   * entries inside its own `windowMs` — so windows finally mean something.
   */
  recentActionTimestamps?: number[];
  toolHistory?: string[];
  /** Output text for postprocess evaluation */
  outputText?: string;
  /** Output token count for postprocess evaluation */
  outputTokenCount?: number;
  /** Execution duration in ms for postprocess evaluation */
  executionDurationMs?: number;
  /** Target URL/domain for network_allowlist evaluation */
  targetUrl?: string;
  /** Target file/resource path for scope_boundary evaluation */
  targetPath?: string;
  /** Session cost so far for cost_budget evaluation */
  sessionCost?: number;
  /** Current concurrent tool count for concurrent_limit evaluation */
  concurrentCount?: number;
  /**
   * Consequence tier of this action, set by the adapter from its tool → tier
   * map. Read by the `action_tier` condition. Unset means "unknown", which
   * never matches a tier rule — map your tools explicitly.
   */
  actionTier?: ActionTier;
  /**
   * Provenance marks for untrusted content ingested earlier in this session
   * (tool results, retrieved documents, MCP metadata, other agents'
   * messages). Adapters carry the session's marks forward on every tool
   * call; the `tainted_input` condition reads them. See `taint.ts`.
   */
  taint?: TaintMark[];
  /**
   * Whether the host successfully verified the caller's Ed25519 identity
   * against the authoritative cert vault.
   *
   * This field is populated by the HOST (API layer) before the policy engine
   * runs — the SDK is zero-dep and synchronous, so it cannot do the vault
   * lookup or crypto verify itself. The host resolves the agent's active cert,
   * checks signature + expiry, then sets this flag accordingly. The
   * `require_signed_identity` condition reads it.
   *
   * `true`  — valid signature, non-expired cert, cert exists in this org's vault
   * `false` — verification explicitly failed (see identityFailureReason)
   * `undefined` — host did not perform identity verification on this request
   */
  identityVerified?: boolean;
  /**
   * Whether `ctx.tool` is listed in the verified certificate's capability set.
   * Computed by the host at the same time as `identityVerified` so the policy
   * engine can do the capability-narrowing check with a single boolean read.
   *
   * `true`  — tool is in the cert's capabilities (or no tool on the request)
   * `false` — tool is NOT in the cert's capabilities (capability escalation)
   * `undefined` — host did not evaluate capability binding
   */
  identityCapabilityMatch?: boolean;
  /**
   * Human-readable reason when identityVerified === false.
   * One of: "no_cert" | "expired_cert" | "missing_signature" | "invalid_signature"
   * | "capability_not_in_cert" (or any string the host provides).
   */
  identityFailureReason?: string;
  /**
   * Injection score (0–1) computed BEFORE calling `enforce()` — by the
   * built-in regex detector (`scanToolResult` does this for tool returns) or
   * by an ML classifier the host ran. The policy engine is synchronous and
   * cannot run a detector itself. Read by `ml_injection_guard`. Preferred
   * over the older `mlInjectionScore`, which it aliases.
   */
  injectionScore?: number;
  /**
   * Legacy name for `injectionScore`. Still honoured; new code should set
   * `injectionScore`. The name was misleading — in local mode the value
   * comes from the regex detector, not an ML model.
   */
  mlInjectionScore?: number;
  /**
   * Categories tagged by the detector alongside the score.
   * Optional — enables the `ml_injection_guard` to narrow on category too.
   */
  mlInjectionCategories?: string[];
  /**
   * Pre-extracted text per modality, populated by the host before calling
   * `enforce()`. Typically the host calls `scanMultiModal()` once per
   * request for the union of modalities across active rules and stuffs
   * the result here. Content-scanning condition evaluators consult this
   * via `getScanText(ctx, rule)` when the rule has `scanModalities` set.
   *
   * `textByModality.text` is the user's prompt; `textByModality.image` is
   * the OCR'd / vision-LLM extraction of image blocks; etc. Empty or
   * undefined entries are equivalent to "no contribution from that
   * modality." The SDK never populates this itself — host responsibility.
   */
  textByModality?: Partial<Record<Modality, string>>;
}

export interface EnforcementDecision {
  blocked: boolean;
  reason: string;
  ruleId: string | null;
  outcome: PolicyOutcome;
  evaluatedAt: string;
  rulesEvaluated: number;
  /** Stage the decision was evaluated at (the matched rule's stage, or the requested stage). */
  stage?: PolicyStage;
  /** The condition type that matched, so callers can branch without parsing `reason`. */
  condition?: { type: string };
  /** One-line hint on how to make the call pass. Absent on `allow` and for custom conditions. */
  remedy?: string;
  /**
   * Set when a `mask` rule matched but no redacted text could be produced
   * (no text on the context, or a condition the masker does not understand).
   * The engine fails closed: the outcome is `block`, never a silent pass-through.
   */
  degradedFrom?: "mask";
  /** Redacted text when outcome is "mask" — the transformed version with sensitive data replaced */
  maskedText?: string;
  /** Approval request ID when outcome is "require_approval" */
  approvalId?: string;
  /** Approval details with polling endpoint for async approval flows */
  approval?: {
    id: string;
    status: string;
    pollUrl: string;
    message: string;
  };
}

// ─── Condition Registry ─────────────────────────────────────────

/**
 * Evaluator function for a registered condition type.
 *
 * The optional `rule` argument is the parent PolicyRule that the engine is
 * currently evaluating. Most evaluators ignore it; content-scanning
 * evaluators (`injection_guard`, `sensitive_data_filter`, `blocklist`,
 * `input_pattern`, `output_pattern`, `ml_injection_guard`) read
 * `rule.scanModalities` via `getScanText()` to know which slices of
 * `ctx.textByModality` to scan.
 *
 * Adding `rule?` is structurally backward compatible — existing
 * `(ctx, params) => boolean` implementations satisfy the wider signature
 * unchanged.
 */
export type ConditionEvaluator = (
  ctx: EnforcementContext,
  params: Record<string, unknown>,
  rule?: PolicyRule,
) => boolean;

/**
 * Pull scannable text from `ctx.textByModality` for a content-scanning rule.
 *
 * Returns an array of strings (typically the per-modality texts plus a
 * joined-all version, mirroring `extractStrings`'s shape) when:
 *   - a rule was passed,
 *   - the rule's condition type supports modalities, and
 *   - the rule has `scanModalities` set.
 *
 * Returns `null` to signal "use the existing extractStrings(ctx.input)
 * fallback" — for legacy rules that don't opt in. This is the
 * backward-compat seam: rules without `scanModalities` see exactly the
 * same content they did before this feature shipped.
 */
export function getScanText(
  ctx: EnforcementContext,
  rule?: PolicyRule,
): string[] | null {
  if (!rule) return null;
  if (!conditionSupportsModalities(rule.condition.type)) return null;
  const modalities = rule.scanModalities;
  if (!modalities || modalities.length === 0) return null;

  const out: string[] = [];
  for (const m of modalities) {
    const t = ctx.textByModality?.[m];
    if (typeof t === "string" && t.length > 0) out.push(t);
  }
  if (out.length > 1) out.push(out.join(" "));
  return out;
}

/** Metadata for a registered condition type */
export interface RegisteredConditionType {
  name: string;
  description: string;
  evaluator: ConditionEvaluator;
  /** JSON Schema for params — enables visual builders to render config UIs */
  paramSchema?: Record<string, unknown>;
}

// ─── Policy Engine ──────────────────────────────────────────────

/**
 * Highest priority a user rule may hold. 999 is reserved for system rules
 * (the kill switch). Enforced by clamping — there is no id-prefix or other
 * opt-out; system rules enter through `addSystemRule()` only.
 */
export const MAX_USER_PRIORITY = 998;
export const SYSTEM_RULE_PRIORITY = 999;

export interface PolicyEngine {
  evaluate: (ctx: EnforcementContext) => EnforcementDecision;
  /** Evaluate only rules matching the given stage (system rules apply at every stage) */
  evaluateStage: (ctx: EnforcementContext, stage: PolicyStage) => EnforcementDecision;
  /**
   * Evaluate ONLY system rules (kill switch). Returns the matching decision,
   * or `null` when no system rule fires. Used by hosted mode to honour a
   * local kill before deferring to the remote API.
   */
  evaluateSystemRules: (ctx: EnforcementContext, stage?: PolicyStage) => EnforcementDecision | null;
  /** Add a user rule. Validated; priority clamped to `MAX_USER_PRIORITY`. Throws `PolicyValidationError`. */
  addRule: (rule: PolicyRule) => void;
  /** Remove a user rule by ID. Throws when the id names a system rule. */
  removeRule: (ruleId: string) => void;
  /**
   * Add a system rule — evaluated at every stage, exempt from the priority
   * clamp, and not removable through `removeRule()`. Reserved for the kill
   * switch and other SDK-internal safety rules.
   * @internal
   */
  addSystemRule: (rule: PolicyRule) => void;
  /** Remove a system rule by ID. @internal */
  removeSystemRule: (ruleId: string) => void;
  /** Whether `ruleId` names a system rule. */
  isSystemRule: (ruleId: string) => boolean;
  /** Validate a rule against this engine's registry without adding it. Returns issues (empty = valid). */
  validateRule: (rule: PolicyRule) => ReturnType<typeof validateRule>;
  /**
   * Teach the engine how to produce redacted text for a condition type when a
   * `mask` rule on it matches. Without a strategy the engine fails closed and
   * turns the decision into a `block`. Built-in content conditions
   * (`sensitive_data_filter`, `input_pattern`, `output_pattern`, `blocklist`)
   * are registered at construction; plugins add their own through
   * `KernelHandle.registerMaskStrategy`.
   */
  registerMaskStrategy: (conditionType: string, mask: MaskStrategy) => void;
  /** Whether a mask strategy is registered for `conditionType`. */
  hasMaskStrategy: (conditionType: string) => boolean;
  getRules: (stage?: PolicyStage) => PolicyRule[];
  ruleCount: number;
  /** Register a custom condition type on this engine instance */
  registerCondition: (entry: RegisteredConditionType, opts?: { override?: boolean }) => void;
  /** Unregister a condition type by name */
  unregisterCondition: (name: string) => boolean;
  /** Get a registered condition type by name */
  getRegisteredCondition: (name: string) => RegisteredConditionType | undefined;
  /** List all registered condition types */
  getRegisteredConditions: () => RegisteredConditionType[];
  /** Clear all registered conditions. Set `keepBuiltins: true` to re-register built-ins after clearing. */
  clearConditionRegistry: (opts?: { keepBuiltins?: boolean }) => void;
}

export interface PolicyEngineConfig {
  rules?: PolicyRule[];
  defaultOutcome?: PolicyOutcome;
  /** Custom condition types to register on this engine instance */
  conditions?: RegisteredConditionType[];
}

/**
 * Create a standalone policy engine for before-action enforcement.
 *
 * Each engine has its own isolated condition registry — built-in conditions
 * are registered automatically, and custom conditions can be added via
 * `config.conditions` or `engine.registerCondition()`.
 *
 * Rules are validated when added (shape, outcome and stage enums, finite
 * priority, registered condition type, compilable regex) and rejected with
 * `PolicyValidationError` — a typo can no longer become a rule that never
 * matches or that throws on the first request.
 *
 * @param config - Rules, default outcome, and custom conditions
 * @returns A PolicyEngine with evaluate, addRule, removeRule, getRules, and condition management
 *
 * @example
 * ```ts
 * const engine = createPolicyEngine({
 *   rules: [blockTools(['shell_exec'])],
 *   conditions: [{ name: 'geo_fence', description: 'Block by region', evaluator: myEval }],
 * });
 * const decision = engine.evaluate({ agentId: 'a1', action: 'tool_call', tool: 'shell_exec' });
 * ```
 */
export function createPolicyEngine(config: PolicyEngineConfig = {}): PolicyEngine {
  // Instance-scoped condition registry — fully isolated per engine
  const registry = new Map<string, RegisteredConditionType>();

  function evaluateCondition(
    condition: PolicyCondition,
    ctx: EnforcementContext,
    rule?: PolicyRule,
  ): boolean {
    // Inline custom evaluators (params.evaluate is a function)
    const evalFn = condition.params?.evaluate;
    if (typeof evalFn === "function") {
      const r = (evalFn as (ctx: EnforcementContext) => boolean)(ctx);
      if (r && typeof r === "object" && typeof (r as Promise<boolean>).then === "function") {
        throw new Error("Custom policy evaluator returned a Promise — evaluators must be synchronous.");
      }
      return r;
    }

    const entry = registry.get(condition.type);
    if (!entry) {
      throw new Error(`Unknown condition type "${condition.type}" — register it via engine.registerCondition()`);
    }
    return entry.evaluator(ctx, condition.params, rule);
  }

  // Register built-in conditions
  for (const def of getBuiltinConditions(evaluateCondition)) {
    registry.set(def.name, def);
  }

  // Register any custom conditions from config
  for (const entry of config.conditions ?? []) {
    registry.set(entry.name, entry);
  }

  const isRegistered = (type: string) => registry.has(type);

  // User rules and system rules share one array; `systemIds` is the only
  // thing that distinguishes them. There is deliberately no id convention
  // (the old `__` prefix let any YAML file mint a rule that outranked the
  // kill switch).
  const rules: PolicyRule[] = [];
  const systemIds = new Set<string>();
  // Cache of enabled rules sorted by priority, rebuilt lazily after mutation.
  let sortedActive: PolicyRule[] | null = null;
  const invalidate = () => { sortedActive = null; };

  function clampPriority(rule: PolicyRule): PolicyRule {
    return rule.priority > MAX_USER_PRIORITY ? { ...rule, priority: MAX_USER_PRIORITY } : rule;
  }

  function upsert(rule: PolicyRule): void {
    const idx = rules.findIndex((r) => r.id === rule.id);
    if (idx >= 0) rules[idx] = rule;
    else rules.push(rule);
    invalidate();
  }

  for (const r of config.rules ?? []) {
    assertValidRule(r, validateRule(r, isRegistered));
    upsert(clampPriority(r));
  }
  const defaultOutcome = config.defaultOutcome ?? "allow";

  function activeRules(): PolicyRule[] {
    if (!sortedActive) {
      sortedActive = rules.filter((r) => r.enabled).sort((a, b) => b.priority - a.priority);
    }
    return sortedActive;
  }

  function stageOf(rule: PolicyRule): PolicyStage {
    return rule.stage ?? getDefaultStage(rule.condition.type);
  }

  /** Resolve the text a preprocess/postprocess mask rule operates on. */
  function textFor(ctx: EnforcementContext): string {
    if (typeof ctx.outputText === "string" && ctx.outputText.length > 0) return ctx.outputText;
    if (typeof ctx.inputText === "string" && ctx.inputText.length > 0) return ctx.inputText;
    for (const key of ["message", "prompt", "text"]) {
      const v = ctx.input?.[key];
      if (typeof v === "string" && v.length > 0) return v;
    }
    return "";
  }

  // How to redact, per condition type. Built-ins cover the content conditions
  // the kernel ships; plugins add theirs through registerMaskStrategy(). A
  // condition with no strategy cannot be masked, and the engine says so by
  // failing closed rather than passing the original text through.
  const maskStrategies = new Map<string, MaskStrategy>([
    ["sensitive_data_filter", (text, params) => maskSensitiveData(text, params.patterns as string[] | undefined)],
    ["output_pattern", (text, params) => maskPattern(text, params.pattern as string, params.flags as string | undefined)],
    ["input_pattern", (text, params) => maskPattern(text, params.pattern as string, params.flags as string | undefined)],
    ["blocklist", (text, params) => maskBlocklistTerms(text, params.terms as string[])],
  ]);

  /**
   * Compute masked text when outcome is "mask". Returns `undefined` when no
   * redaction can be produced — the caller then fails closed rather than
   * returning the original text under a "mask" label.
   */
  function computeMaskedText(rule: PolicyRule, ctx: EnforcementContext): string | undefined {
    const text = textFor(ctx);
    if (!text) return undefined;
    const strategy = maskStrategies.get(rule.condition.type);
    if (!strategy) return undefined;
    return strategy(text, rule.condition.params ?? {}, ctx);
  }

  function buildDecision(
    rule: PolicyRule,
    ctx: EnforcementContext,
    rulesEvaluated: number,
    stage: PolicyStage,
  ): EnforcementDecision {
    const base = {
      ruleId: rule.id,
      evaluatedAt: new Date().toISOString(),
      rulesEvaluated,
      stage,
      condition: { type: rule.condition.type },
    };
    const remedy = describeRemedy(rule, ctx);

    if (rule.outcome === "mask") {
      const maskedText = computeMaskedText(rule, ctx);
      if (maskedText === undefined) {
        return {
          ...base,
          blocked: true,
          outcome: "block",
          reason: `${rule.reason} (mask could not be applied to this content — failing closed)`,
          degradedFrom: "mask",
          ...(remedy ? { remedy } : {}),
        };
      }
      return { ...base, blocked: false, outcome: "mask", reason: rule.reason, maskedText, ...(remedy ? { remedy } : {}) };
    }

    return {
      ...base,
      blocked: rule.outcome === "block" || rule.outcome === "require_approval",
      reason: rule.reason,
      outcome: rule.outcome,
      ...(remedy ? { remedy } : {}),
    };
  }

  function noMatch(rulesEvaluated: number, stage?: PolicyStage): EnforcementDecision {
    return {
      blocked: defaultOutcome === "block",
      reason: "No policy rules matched",
      ruleId: null,
      outcome: defaultOutcome,
      evaluatedAt: new Date().toISOString(),
      rulesEvaluated,
      ...(stage ? { stage } : {}),
    };
  }

  function evaluate(ctx: EnforcementContext): EnforcementDecision {
    const active = activeRules();
    for (const rule of active) {
      if (evaluateCondition(rule.condition, ctx, rule)) {
        return buildDecision(rule, ctx, active.length, stageOf(rule));
      }
    }
    return noMatch(active.length);
  }

  function evaluateStage(ctx: EnforcementContext, stage: PolicyStage): EnforcementDecision {
    // System rules are stage-agnostic: a killed agent is killed at the
    // prompt, the tool call, the tool result and the output alike.
    const active = activeRules().filter((r) => systemIds.has(r.id) || stageOf(r) === stage);
    for (const rule of active) {
      if (evaluateCondition(rule.condition, ctx, rule)) {
        return buildDecision(rule, ctx, active.length, stage);
      }
    }
    return noMatch(active.length, stage);
  }

  function evaluateSystemRules(ctx: EnforcementContext, stage?: PolicyStage): EnforcementDecision | null {
    if (systemIds.size === 0) return null;
    const system = activeRules().filter((r) => systemIds.has(r.id));
    for (const rule of system) {
      if (evaluateCondition(rule.condition, ctx, rule)) {
        return buildDecision(rule, ctx, system.length, stage ?? stageOf(rule));
      }
    }
    return null;
  }

  function addRule(rule: PolicyRule): void {
    assertValidRule(rule, validateRule(rule, isRegistered));
    if (systemIds.has(rule.id)) {
      throw new Error(`Rule id "${rule.id}" belongs to a system rule and cannot be replaced via addRule()`);
    }
    // Priorities above MAX_USER_PRIORITY are reserved for system rules (kill
    // switch et al.). User rules are clamped so the kill switch remains the
    // unconditional top priority. There is no opt-out.
    upsert(clampPriority(rule));
  }

  function removeRule(ruleId: string): void {
    if (systemIds.has(ruleId)) {
      throw new Error(`Rule id "${ruleId}" is a system rule — it can only be removed by the component that installed it`);
    }
    const idx = rules.findIndex((r) => r.id === ruleId);
    if (idx >= 0) {
      rules.splice(idx, 1);
      invalidate();
    }
  }

  function addSystemRule(rule: PolicyRule): void {
    assertValidRule(rule, validateRule(rule, isRegistered));
    systemIds.add(rule.id);
    upsert({ ...rule, priority: Math.max(rule.priority, SYSTEM_RULE_PRIORITY) });
  }

  function removeSystemRule(ruleId: string): void {
    systemIds.delete(ruleId);
    const idx = rules.findIndex((r) => r.id === ruleId);
    if (idx >= 0) {
      rules.splice(idx, 1);
      invalidate();
    }
  }

  function getRules(stage?: PolicyStage): PolicyRule[] {
    if (stage) return rules.filter((r) => systemIds.has(r.id) || stageOf(r) === stage);
    return [...rules];
  }

  function registerCondition(entry: RegisteredConditionType, opts?: { override?: boolean }): void {
    if (registry.has(entry.name) && !opts?.override) {
      throw new Error(`Condition type "${entry.name}" is already registered. Use { override: true } to replace.`);
    }
    registry.set(entry.name, entry);
  }

  function unregisterCondition(name: string): boolean {
    return registry.delete(name);
  }

  function getRegisteredCondition(name: string): RegisteredConditionType | undefined {
    return registry.get(name);
  }

  function getRegisteredConditions(): RegisteredConditionType[] {
    return [...registry.values()];
  }

  function clearConditionRegistry(opts?: { keepBuiltins?: boolean }): void {
    registry.clear();
    if (opts?.keepBuiltins) {
      for (const def of getBuiltinConditions(evaluateCondition)) {
        registry.set(def.name, def);
      }
    }
  }

  return {
    evaluate,
    evaluateStage,
    evaluateSystemRules,
    addRule,
    removeRule,
    addSystemRule,
    removeSystemRule,
    isSystemRule: (id) => systemIds.has(id),
    validateRule: (rule) => validateRule(rule, isRegistered),
    registerMaskStrategy: (conditionType, mask) => { maskStrategies.set(conditionType, mask); },
    hasMaskStrategy: (conditionType) => maskStrategies.has(conditionType),
    getRules,
    get ruleCount() { return rules.filter((r) => r.enabled).length; },
    registerCondition,
    unregisterCondition,
    getRegisteredCondition,
    getRegisteredConditions,
    clearConditionRegistry,
  };
}

// ─── Re-exports ─────────────────────────────────────────────────

export { PolicyValidationError, validateRuleShape, POLICY_OUTCOMES, POLICY_STAGES } from "./policy-validate.js";
export type { PolicyValidationIssue } from "./policy-validate.js";
export type { TaintMark, TaintSource, TaintFilter } from "./taint.js";
export { markTaint, hasTaint, appendTaint } from "./taint.js";

export {
  blockTools,
  allowOnlyTools,
  requireApproval,
  requireToolApproval,
  requireTierApproval,
  blockTaintedTools,
  tokenBudget,
  rateLimit,
  requireLevel,
  requireSignedIdentity,
  requireSequence,
  timeWindow,
  toolResultInjectionGuard,
} from "./policy-presets.js";
