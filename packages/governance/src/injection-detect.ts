/**
 * Prompt Injection Detection — zero-dependency, pattern-based.
 *
 * Detects common prompt injection patterns in agent inputs.
 * Pattern definitions are in injection-patterns.ts.
 *
 * @example
 * ```ts
 * import { detectInjection, createInjectionGuard } from 'governance-sdk/injection-detect';
 *
 * const result = detectInjection('Ignore previous instructions...');
 * // { detected: true, score: 0.85, patterns: ['instruction_override'], ... }
 *
 * const guard = createInjectionGuard({ threshold: 0.5 });
 * gov.addRule(guard);
 * ```
 */

import { BUILTIN_PATTERNS } from "./injection-patterns.js";

// ─── Types ──────────────────────────────────────────────────────

export interface InjectionPattern {
  id: string;
  category: InjectionCategory;
  pattern: RegExp;
  weight: number;
  description: string;
}

export type InjectionCategory =
  | "instruction_override"
  | "role_manipulation"
  | "context_escape"
  | "data_exfiltration"
  | "encoding_attack"
  | "social_engineering"
  | "obfuscation";

export interface InjectionResult {
  detected: boolean;
  score: number;
  patterns: string[];
  categories: InjectionCategory[];
  summary: string;
  inputLength: number;
}

/** Default max input length: 100KB */
const DEFAULT_MAX_INPUT_LENGTH = 100_000;

export interface InjectionDetectorConfig {
  threshold?: number;
  customPatterns?: InjectionPattern[];
  skipCategories?: InjectionCategory[];
  /** Maximum input length in characters. Inputs exceeding this are flagged as detected. Default: 100000 */
  maxInputLength?: number;
}

// ─── Detection Engine ───────────────────────────────────────────

/**
 * Strip zero-width characters, normalize Unicode to NFKC (compatibility +
 * canonical), and fold Cyrillic/Greek confusables to Latin so fullwidth,
 * circled, superscript, and homoglyph evasions collapse to their ASCII form
 * before pattern matching.
 */
function normalizeInput(input: string): string {
  // Remove zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+00AD, U+2060, U+180E)
  const stripped = input.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g, "");
  // NFKC folds compatibility variants (fullwidth `Ｉ` → `I`, superscripts → digits, etc.)
  const nfkc = stripped.normalize("NFKC");
  // Fold confusables that NFKC leaves alone (Cyrillic/Greek lookalikes).
  return nfkc.replace(CONFUSABLE_RE, (ch) => CONFUSABLES[ch] ?? ch);
}

/**
 * Confusable (homoglyph) folding map: Unicode lookalikes → their Latin form.
 * NFKC does NOT fold these (Cyrillic `а`, Greek `ο` are distinct codepoints,
 * not compatibility variants), so an attack like `systеm prоmpt` (Cyrillic
 * е/о) survives NFKC untouched. We map the common Cyrillic/Greek confusables
 * back to Latin so they match the same patterns as their ASCII form. Targets
 * are lowercase — all injection patterns are case-insensitive, so the case of
 * the folded form is irrelevant.
 */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic → Latin
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
  "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
  "к": "k", "м": "m", "н": "h", "в": "b", "т": "t",
  "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m",
  "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t",
  "У": "y", "Х": "x", "І": "i", "Ј": "j",
  // Greek → Latin
  "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k",
  "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
  "Α": "a", "Β": "b", "Ε": "e", "Η": "h", "Ι": "i",
  "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p",
  "Τ": "t", "Υ": "y", "Χ": "x",
};

const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join("")}]`, "g");

/**
 * Collapse runs of single characters separated by a single space or separator
 * (`. _ -`) back into a word, so spaced-out evasions like `i g n o r e` or
 * `i.g.n.o.r.e` match the same patterns as the contiguous form. Only runs of
 * 4+ single chars are collapsed (a first char plus 3+ separated chars), so
 * benign initials/acronyms ("U S A", "I am a") are left intact. Multi-space
 * gaps between words are preserved as word boundaries.
 */
export function collapseSpacedChars(input: string): string {
  return input.replace(
    /[A-Za-z0-9](?:[ \t._-][A-Za-z0-9]){3,}/g,
    (run) => run.replace(/[ \t._-]/g, ""),
  );
}

/**
 * Remove markdown emphasis/code markers that attackers insert mid-word to
 * break keyword matching (e.g. `ig**no**re`). Only the markers are stripped,
 * so `ig**no**re previous` folds back to `ignore previous`.
 */
export function stripMarkdownEmphasis(input: string): string {
  return input.replace(/[*_~`]/g, "");
}

/**
 * Map common leetspeak substitutions back to letters so attacks like
 * `1gn0r3 pr3v10us 1nstruct10ns` match the same patterns as `ignore
 * previous instructions`. We apply this as a **second pass** alongside
 * (not replacing) the normalised input, so a rule only needs to match
 * either form to fire. Conservative mapping — we keep common false-positive
 * digits (0=0, 1=1 in numeric context) intact if the surrounding token has
 * no alpha characters.
 */
const LEET_MAP: Record<string, string> = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  "$": "s",
  "!": "i",
  "|": "i",
};

export function deleetInput(input: string): string {
  // Walk token-by-token. A token is a run of non-whitespace. We only apply
  // leet mapping to tokens that already contain at least one alpha — that
  // way "payment of $99" stays as "$99" (not "say99") while "1gn0r3" gets
  // normalised to "ignore".
  return input
    .split(/(\s+)/)
    .map((tok) => {
      if (!/[a-zA-Z]/.test(tok)) return tok;
      let out = "";
      for (const ch of tok) out += LEET_MAP[ch] ?? ch;
      return out;
    })
    .join("");
}

/** Base64 regex: 16+ base64 chars with optional padding, not a common word */
const BASE64_RE = /[A-Za-z0-9+/]{16,}={0,2}/g;

/** Try to decode base64 strings in input; returns decoded text or null */
function tryDecodeBase64(encoded: string): string | null {
  try {
    const decoded = atob(encoded);
    // Only accept if result is printable ASCII/UTF-8
    if (/^[\x20-\x7E\t\n\r]+$/.test(decoded) && decoded.length >= 4) {
      return decoded;
    }
  } catch { /* not valid base64 */ }
  return null;
}

/**
 * Detect prompt injection patterns in text input.
 * Returns a score from 0 (no injection) to 1 (certain injection).
 *
 * Note: This is a heuristic pattern matcher, not an LLM classifier.
 * It catches known syntactic patterns but cannot detect novel semantic attacks.
 * For high-security deployments, layer this with an LLM-based classifier.
 */
export function detectInjection(
  input: string,
  config: InjectionDetectorConfig = {},
): InjectionResult {
  const maxLen = config.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
  if (input.length > maxLen) {
    return {
      detected: true,
      score: 1,
      patterns: ["input_too_large"],
      categories: ["system_prompt" as InjectionCategory],
      summary: `Input exceeds maximum length (${input.length} > ${maxLen})`,
      inputLength: input.length,
    };
  }

  const threshold = config.threshold ?? 0.5;
  const skipCategories = new Set(config.skipCategories ?? []);

  const allPatterns = [
    ...BUILTIN_PATTERNS,
    ...(config.customPatterns ?? []),
  ].filter((p) => !skipCategories.has(p.category));

  const normalized = normalizeInput(input);

  const matchedPatterns: string[] = [];
  const matchedIds = new Set<string>();
  const matchedCategories = new Set<InjectionCategory>();
  let maxWeight = 0;

  // Scan the normalised input first (clean ids), then fall back to obfuscation
  // variants so an attack only has to match in ONE form. Each variant rewrites
  // a known evasion back to its plain form:
  //   :leet       — "1gn0r3 pr3v10us"  → leetspeak folded to letters
  //   :despaced   — "i g n o r e"      → spaced-out chars collapsed
  //   :demarkdown — "ig**no**re"       → markdown emphasis stripped
  const variants: Array<{ suffix: string; text: string }> = [];
  const deleeted = deleetInput(normalized);
  if (deleeted !== normalized) variants.push({ suffix: ":leet", text: deleeted });
  const despaced = collapseSpacedChars(normalized);
  if (despaced !== normalized) variants.push({ suffix: ":despaced", text: despaced });
  const demarkdown = stripMarkdownEmphasis(normalized);
  if (demarkdown !== normalized) variants.push({ suffix: ":demarkdown", text: demarkdown });

  for (const pattern of allPatterns) {
    if (pattern.pattern.test(normalized)) {
      matchedPatterns.push(pattern.id);
      matchedIds.add(pattern.id);
      matchedCategories.add(pattern.category);
      if (pattern.weight > maxWeight) maxWeight = pattern.weight;
    }
  }

  // Obfuscation variants get the same +0.1 nudge as encoded attacks — they are
  // deliberate evasion, so they rank slightly above a plain keyword hit. A
  // pattern already matched in a cleaner form is not re-counted.
  for (const { suffix, text } of variants) {
    for (const pattern of allPatterns) {
      if (matchedIds.has(pattern.id)) continue;
      if (pattern.pattern.test(text)) {
        matchedPatterns.push(pattern.id + suffix);
        matchedIds.add(pattern.id);
        matchedCategories.add(pattern.category);
        const weight = Math.min(1, pattern.weight + 0.1);
        if (weight > maxWeight) maxWeight = weight;
      }
    }
  }

  // Decode any base64 strings and scan the decoded content too
  const b64Matches = normalized.match(BASE64_RE) ?? [];
  for (const b64 of b64Matches) {
    const decoded = tryDecodeBase64(b64);
    if (!decoded) continue;
    for (const pattern of allPatterns) {
      if (pattern.pattern.test(decoded) && !matchedPatterns.includes(pattern.id + ":decoded")) {
        matchedPatterns.push(pattern.id + ":decoded");
        matchedCategories.add(pattern.category);
        // Boost weight for encoded attacks — deliberate obfuscation
        const boosted = Math.min(1, pattern.weight + 0.1);
        if (boosted > maxWeight) maxWeight = boosted;
      }
    }
  }

  // Score = highest weight + boosts for multiple matches/categories
  const additionalBoost = matchedPatterns.length > 1
    ? Math.min(0.1, (matchedPatterns.length - 1) * 0.02)
    : 0;
  const categoryBoost = matchedCategories.size > 1
    ? Math.min(0.1, (matchedCategories.size - 1) * 0.03)
    : 0;

  const score = Math.min(1, maxWeight + additionalBoost + categoryBoost);
  const detected = score >= threshold;
  const categories = Array.from(matchedCategories);

  let summary: string;
  if (!detected) summary = "No injection detected";
  else if (score >= 0.8) summary = `High-confidence injection attempt: ${categories.join(", ")}`;
  else if (score >= 0.5) summary = `Possible injection attempt: ${categories.join(", ")}`;
  else summary = `Low-confidence injection signals: ${categories.join(", ")}`;

  return {
    detected,
    score: Math.round(score * 100) / 100,
    patterns: matchedPatterns,
    categories,
    summary,
    inputLength: input.length,
  };
}

// ─── Policy Integration ─────────────────────────────────────────

/**
 * Create a policy rule that blocks actions containing prompt injection.
 * Examines `ctx.input` for injection patterns.
 */
export function createInjectionGuard(config?: InjectionDetectorConfig & {
  priority?: number;
}): import("./policy").PolicyRule {
  const threshold = config?.threshold ?? 0.5;
  const priority = config?.priority ?? 110;

  return {
    id: "injection-guard",
    name: "Prompt Injection Guard",
    condition: {
      type: "injection_guard",
      params: {
        threshold,
        skipCategories: config?.skipCategories ?? [],
      },
    },
    outcome: "block",
    reason: `Prompt injection detected (threshold: ${threshold})`,
    priority,
    enabled: true,
    stage: "preprocess" as const,
  };
}

/** Extract all string values from a nested object. */
function extractStrings(obj: Record<string, unknown>): string[] {
  const strings: string[] = [];
  function walk(value: unknown): void {
    if (typeof value === "string") strings.push(value);
    else if (Array.isArray(value)) value.forEach(walk);
    else if (value !== null && typeof value === "object") {
      Object.values(value as Record<string, unknown>).forEach(walk);
    }
  }
  walk(obj);
  // Also test concatenation of all fields to catch cross-field injection splitting
  if (strings.length > 1) {
    strings.push(strings.join(" "));
  }
  return strings;
}

/** Get all built-in injection patterns. */
export function getBuiltinPatterns(): InjectionPattern[] {
  return [...BUILTIN_PATTERNS];
}
