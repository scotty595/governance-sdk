/**
 * The sensitive-data evaluator.
 *
 * Reads the shared corpus, so it is a detection concern and cannot sit in the
 * kernel. `ext/defaults.ts` registers it as the `sensitive_data_filter`
 * condition, which is how the published behaviour stays identical.
 */

import type { EnforcementContext } from "@governance-sdk/core/policy.js";
import { getSensitivePatterns, matchesSensitivePattern } from "../conditions/sensitive-patterns.js";

/**
 * Scan for sensitive data using built-in or custom patterns.
 *
 * Reads `outputText` (postprocess / tool_result) and falls back to the
 * preprocess text sources (`inputText`, then `input.message` / `prompt` /
 * `text`) so the same rule can redact an SSN in the user's prompt before
 * the LLM sees it. The text chosen here is the text the engine masks.
 */
export function evaluateSensitiveDataFilter(
  ctx: EnforcementContext,
  patternIds?: string[],
): boolean {
  const text = sensitiveScanText(ctx);
  if (!text) return false;

  const patterns = getSensitivePatterns(patternIds);
  return patterns.some((p) => matchesSensitivePattern(p, text));
}

function sensitiveScanText(ctx: EnforcementContext): string {
  if (typeof ctx.outputText === "string" && ctx.outputText.length > 0) return ctx.outputText;
  if (typeof ctx.inputText === "string" && ctx.inputText.length > 0) return ctx.inputText;
  for (const key of ["message", "prompt", "text"]) {
    const v = ctx.input?.[key];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return "";
}
