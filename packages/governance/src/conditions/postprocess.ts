/**
 * Postprocess condition evaluators — run after agent execution.
 * Output length and output pattern. Sensitive-data filtering needs the
 * detection corpus, so it lives in `ext/sensitive-filter.ts` and reaches the
 * engine as a kernel extension.
 */

import type { EnforcementContext } from "../policy.js";

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
