/**
 * Postprocess condition evaluators — run after agent execution.
 * Output length, output pattern, and sensitive data filtering.
 */

import type { EnforcementContext } from "../policy.js";
import { getSensitivePatterns, matchesSensitivePattern } from "./sensitive-patterns.js";

/** Check if output exceeds length limits */
export function evaluateOutputLength(
  ctx: EnforcementContext,
  maxChars?: number,
  maxTokens?: number,
): boolean {
  if (!ctx.outputText) return false;

  if (maxChars !== undefined && ctx.outputText.length > maxChars) return true;
  if (maxTokens !== undefined) {
    const count = ctx.outputTokenCount ?? Math.ceil(ctx.outputText.length / 4);
    if (count > maxTokens) return true;
  }
  return false;
}

/** Check if output matches a regex pattern (e.g., secrets, API keys) */
export function evaluateOutputPattern(
  ctx: EnforcementContext,
  pattern: string,
  flags?: string,
): boolean {
  if (!ctx.outputText) return false;

  const regex = new RegExp(pattern, flags);
  return regex.test(ctx.outputText);
}

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
