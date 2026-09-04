/**
 * Policy rule validation — reject malformed rules at the door.
 *
 * Before this module, a rule with `outcome: "blcok"`, `priority: NaN`, an
 * unknown condition type, or an uncompilable regex was accepted by
 * `addRule()` / `createPolicyEngine()` and only surfaced at the first
 * `enforce()` — as an exception (one bad rule took down every request) or,
 * worse, as a silently non-matching rule that failed open. Every entry point
 * that accepts a rule now runs `validateRule()` and throws
 * `PolicyValidationError` on the first problem set.
 *
 * Two levels:
 *   - `validateRuleShape()` — structural checks only (no engine needed).
 *     Used by the YAML loader and policy composer, which have no registry.
 *   - `validateRule()` — shape + condition-type registration + regex
 *     compilation. Used by the engine's constructor and `addRule()`.
 */

import type { PolicyCondition, PolicyOutcome, PolicyRule, PolicyStage } from "./policy.js";

export const POLICY_OUTCOMES: readonly PolicyOutcome[] = [
  "allow",
  "block",
  "warn",
  "require_approval",
  "mask",
];

export const POLICY_STAGES: readonly PolicyStage[] = [
  "preprocess",
  "process",
  "tool_result",
  "postprocess",
];

export interface PolicyValidationIssue {
  /** Dotted path into the rule, e.g. `outcome`, `condition.params.pattern`. */
  path: string;
  message: string;
}

export class PolicyValidationError extends Error {
  public readonly issues: readonly PolicyValidationIssue[];
  public readonly ruleId: string | undefined;

  constructor(ruleId: string | undefined, issues: PolicyValidationIssue[]) {
    const summary = issues.map((i) => `${i.path}: ${i.message}`).join("; ");
    super(`Invalid policy rule${ruleId ? ` "${ruleId}"` : ""}: ${summary}`);
    this.name = "PolicyValidationError";
    this.ruleId = ruleId;
    this.issues = issues;
  }
}

/** Condition types whose `params.pattern` must compile as a RegExp. */
const REGEX_PARAM_CONDITIONS = new Set(["input_pattern", "output_pattern"]);
/** Combinators whose params carry nested conditions. */
const NESTED_LIST_CONDITIONS = new Set(["any_of", "all_of"]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Structural validation: field presence and enum membership. Does not know
 * which condition types exist — see `validateRule()` for that.
 */
export function validateRuleShape(rule: unknown): PolicyValidationIssue[] {
  const issues: PolicyValidationIssue[] = [];
  if (!isRecord(rule)) return [{ path: "", message: "rule must be an object" }];

  if (typeof rule.id !== "string" || rule.id.length === 0) {
    issues.push({ path: "id", message: "must be a non-empty string" });
  }
  if (typeof rule.name !== "string") {
    issues.push({ path: "name", message: "must be a string" });
  }
  if (!POLICY_OUTCOMES.includes(rule.outcome as PolicyOutcome)) {
    issues.push({
      path: "outcome",
      message: `must be one of ${POLICY_OUTCOMES.join(", ")} (got ${JSON.stringify(rule.outcome)})`,
    });
  }
  if (typeof rule.reason !== "string") {
    issues.push({ path: "reason", message: "must be a string" });
  }
  if (typeof rule.priority !== "number" || !Number.isFinite(rule.priority)) {
    issues.push({ path: "priority", message: `must be a finite number (got ${JSON.stringify(rule.priority)})` });
  }
  if (typeof rule.enabled !== "boolean") {
    issues.push({ path: "enabled", message: "must be a boolean" });
  }
  if (rule.stage !== undefined && !POLICY_STAGES.includes(rule.stage as PolicyStage)) {
    issues.push({
      path: "stage",
      message: `must be one of ${POLICY_STAGES.join(", ")} (got ${JSON.stringify(rule.stage)})`,
    });
  }
  if (!isRecord(rule.condition)) {
    issues.push({ path: "condition", message: "must be an object" });
  } else {
    if (typeof rule.condition.type !== "string" || rule.condition.type.length === 0) {
      issues.push({ path: "condition.type", message: "must be a non-empty string" });
    }
    if (rule.condition.params !== undefined && !isRecord(rule.condition.params)) {
      issues.push({ path: "condition.params", message: "must be an object" });
    }
  }
  return issues;
}

/**
 * Full validation against an engine's condition registry. `isRegistered`
 * answers whether a condition type has an evaluator. Conditions carrying an
 * inline `params.evaluate` function are accepted without a registry lookup
 * (that is how the kill switch and ad-hoc custom rules are expressed).
 */
export function validateRule(
  rule: unknown,
  isRegistered: (type: string) => boolean,
): PolicyValidationIssue[] {
  const issues = validateRuleShape(rule);
  if (issues.length > 0) return issues;
  const r = rule as PolicyRule;
  validateCondition(r.condition, "condition", isRegistered, issues);
  return issues;
}

function validateCondition(
  condition: PolicyCondition,
  path: string,
  isRegistered: (type: string) => boolean,
  issues: PolicyValidationIssue[],
): void {
  const params = (condition.params ?? {}) as Record<string, unknown>;
  const inline = typeof params.evaluate === "function";
  if (!inline && !isRegistered(condition.type)) {
    issues.push({
      path: `${path}.type`,
      message: `unknown condition type "${condition.type}" — register it via registerCondition() before adding rules that use it`,
    });
    return;
  }
  if (REGEX_PARAM_CONDITIONS.has(condition.type)) {
    const pattern = params.pattern;
    const flags = params.flags;
    if (typeof pattern !== "string") {
      issues.push({ path: `${path}.params.pattern`, message: "must be a string" });
    } else {
      try {
        new RegExp(pattern, typeof flags === "string" ? flags : undefined);
      } catch (err) {
        issues.push({
          path: `${path}.params.pattern`,
          message: `does not compile: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }
  }
  if (NESTED_LIST_CONDITIONS.has(condition.type)) {
    const nested = params.conditions;
    if (!Array.isArray(nested) || nested.length === 0) {
      issues.push({ path: `${path}.params.conditions`, message: "must be a non-empty array of conditions" });
    } else {
      nested.forEach((c, i) => {
        if (!isRecord(c) || typeof c.type !== "string") {
          issues.push({ path: `${path}.params.conditions[${i}]`, message: "must be a condition object" });
        } else {
          validateCondition(c as unknown as PolicyCondition, `${path}.params.conditions[${i}]`, isRegistered, issues);
        }
      });
    }
  }
  if (condition.type === "not") {
    const inner = params.condition;
    if (!isRecord(inner) || typeof inner.type !== "string") {
      issues.push({ path: `${path}.params.condition`, message: "must be a condition object" });
    } else {
      validateCondition(inner as unknown as PolicyCondition, `${path}.params.condition`, isRegistered, issues);
    }
  }
}

/** Throw `PolicyValidationError` if `issues` is non-empty. */
export function assertValidRule(rule: unknown, issues: PolicyValidationIssue[]): void {
  if (issues.length === 0) return;
  const id = isRecord(rule) && typeof rule.id === "string" ? rule.id : undefined;
  throw new PolicyValidationError(id, issues);
}
