/**
 * Which condition types can scan per-modality text, and the modality names.
 *
 * This is a lookup the policy engine consults on every content rule, so it is
 * kernel. The orchestration that actually extracts text from an image, a PDF
 * or an audio block — the scanners, the timeouts, the fail-closed options —
 * is `scan/multi-modal.ts`, which is a plugin concern and stays there.
 */

/** Content kinds a rule can be scoped to. */
export type Modality = "text" | "image" | "pdf" | "audio" | "video";

export const MODALITIES: readonly Modality[] = ["text", "image", "pdf", "audio", "video"];

/**
 * Condition types whose `scanModalities` is meaningful. Everything else
 * ignores it — a tool-name or budget rule has no text to scope.
 */
const CONDITIONS_SUPPORTING_MODALITIES = new Set([
  "injection_guard",
  "ml_injection_guard",
  "blocklist",
  "input_pattern",
  "output_pattern",
  "sensitive_data_filter",
]);

/** Whether `scanModalities` means anything for this condition type. */
export function conditionSupportsModalities(conditionType: string): boolean {
  return CONDITIONS_SUPPORTING_MODALITIES.has(conditionType);
}
