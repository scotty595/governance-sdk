/**
 * Masking primitives — redaction that needs no pattern corpus.
 *
 * A `mask` outcome on `input_pattern`, `output_pattern` or `blocklist` is a
 * pure string operation over what the rule itself declares, so it is kernel.
 * `maskSensitiveData` is not: it reads the shared sensitive-data corpus, which
 * is a detection concern and lives in `mask.ts` alongside it.
 */

export const REDACTED = "[REDACTED]";

export function maskPattern(text: string, pattern: string, flags?: string): string {
  const f = flags ?? "";
  const global = new RegExp(pattern, f.includes("g") ? f : f + "g");
  return text.replace(global, REDACTED);
}

/**
 * Mask blocklisted terms in text.
 * Used for blocklist condition with mask outcome.
 */
export function maskBlocklistTerms(text: string, terms: string[]): string {
  let result = text;
  for (const term of terms) {
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(escaped, "gi");
    result = result.replace(regex, REDACTED);
  }
  return result;
}
