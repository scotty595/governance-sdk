/**
 * Masking helpers — redact sensitive data instead of blocking.
 *
 * Used by the policy engine when a rule's outcome is "mask".
 * Applies the same detection patterns as the condition evaluators
 * but replaces matched content with [REDACTED].
 */

import { getSensitivePatterns } from "./conditions/sensitive-patterns.js";

import { REDACTED } from "@governance-sdk/core/mask-primitives.js";

// Re-exported so `governance-sdk` keeps one masking entry point.
export { maskPattern, maskBlocklistTerms, REDACTED } from "@governance-sdk/core/mask-primitives.js";

/**
 * System prompt leak patterns only match trigger phrases. For masking,
 * we redact from the trigger to the end of the sentence/line.
 */
const PROMPT_LEAK_IDS = new Set(["system_prompt_leak", "hidden_instructions", "never_reveal"]);

/**
 * Mask sensitive data detected by the built-in sensitive_data_filter patterns.
 * Returns the text with all matches replaced by [REDACTED].
 *
 * Every pattern is matched against the ORIGINAL text and the resulting spans
 * are merged before anything is replaced. Replacing pattern-by-pattern would
 * let an earlier pattern destroy the context a later one needs (aws_secret's
 * AKIA… pairing, once aws_key has already redacted the key id) and could
 * leave the tail of a token visible when two patterns overlap it. Merged
 * spans make the result independent of pattern order.
 */
export function maskSensitiveData(text: string, patternIds?: string[]): string {
  const spans: Array<[number, number]> = [];
  for (const p of getSensitivePatterns(patternIds)) {
    const source = PROMPT_LEAK_IDS.has(p.id) ? p.pattern.source + "[^.\\n]*" : p.pattern.source;
    const flags = p.pattern.flags.includes("g") ? p.pattern.flags : p.pattern.flags + "g";
    for (const m of text.matchAll(new RegExp(source, flags))) {
      if (m[0].length === 0 || (p.validate && !p.validate(m[0]))) continue;
      spans.push([m.index, m.index + m[0].length]);
    }
  }
  return redactSpans(text, spans);
}

/** Replace each span with [REDACTED], merging spans that overlap or touch. */
function redactSpans(text: string, spans: Array<[number, number]>): string {
  spans.sort((a, b) => a[0] - b[0]);
  const first = spans[0];
  if (first === undefined) return text; // no spans — nothing to redact
  let out = "";
  let cursor = 0;
  let [start, end] = first;
  for (const [s, e] of spans.slice(1)) {
    if (s <= end) {
      end = Math.max(end, e);
      continue;
    }
    out += text.slice(cursor, start) + REDACTED;
    cursor = end;
    [start, end] = [s, e];
  }
  return out + text.slice(cursor, start) + REDACTED + text.slice(end);
}

/**
 * Mask text matching a custom regex pattern.
 * Used for output_pattern / input_pattern conditions with mask outcome.
 */
