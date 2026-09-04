/**
 * Extended injection patterns — obfuscation and advanced attacks.
 * Separated to keep each file under 300 LOC.
 *
 * Obfuscation-category patterns are also matched against the RAW input by
 * detectInjection(): normalisation strips the very characters most of them
 * look for (zero-width/format chars, bidi controls, combining marks) and
 * NFKC folds fullwidth letters and exotic spaces to ASCII, so on normalised
 * text alone they would never fire.
 */

import type { InjectionPattern } from "./injection-detect.js";

export const EXTENDED_PATTERNS: InjectionPattern[] = [
  // ─── Obfuscation ───────────────────────────────────────────────

  {
    id: "zero_width_chars",
    category: "obfuscation",
    pattern: /[\u200B\u200C\u200D\uFEFF]{2,}/,
    weight: 0.7,
    description: "Multiple zero-width characters (likely obfuscation)",
  },
  {
    id: "rtl_override",
    category: "obfuscation",
    pattern: /[\u202E\u202D]/,
    weight: 0.85,
    description: "Right-to-left override markers (text direction attack)",
  },
  {
    id: "bidi_control",
    category: "obfuscation",
    pattern: /[\u202A-\u202E\u2066-\u2069]+/,
    weight: 0.7,
    description: "Bidirectional control characters",
  },
  {
    id: "char_insertion",
    category: "obfuscation",
    pattern: /\bi[\s._-]g[\s._-]n[\s._-]o[\s._-]r[\s._-]e\b/i,
    weight: 0.85,
    description: "Character insertion obfuscation (i_g_n_o_r_e)",
  },
  {
    id: "homoglyph_ignore",
    category: "obfuscation",
    pattern: /[ΙІі]gn[oοо]re?|ign[οо]re/i,
    weight: 0.85,
    description: "Homoglyph attack on 'ignore' (Greek/Cyrillic substitution)",
  },
  {
    id: "excessive_spacing",
    category: "obfuscation",
    // Two runs of 4+ whitespace between word characters, within 500 chars on
    // one line. A single `\w` on each side of a gap and a bounded window keep
    // this linear; the previous `\w+\s{4,}\w+.*\w+\s{4,}\w+` was quartic on
    // `aaa…    bbb…` (35s for a 1KB input) and quadratic on any long token.
    // Truthiness is unchanged: `\w+` around a gap always reduces to one `\w`.
    pattern: /\w\s{4,}\w[^\n]{0,500}?\w\s{4,}\w/,
    weight: 0.5,
    description: "Excessive spacing between words (obfuscation attempt)",
  },
  {
    id: "fullwidth_latin",
    category: "obfuscation",
    pattern: /[\uFF21-\uFF3A\uFF41-\uFF5A]{3,}/,
    weight: 0.7,
    description: "Full-width Unicode Latin characters (visual obfuscation)",
  },
  {
    id: "uncommon_spaces",
    category: "obfuscation",
    pattern: /[\u2000-\u200A\u202F\u205F]{2,}/,
    weight: 0.6,
    description: "Uncommon Unicode space characters",
  },
  {
    id: "zalgo_text",
    category: "obfuscation",
    pattern: /[\u0300-\u036F]{3,}/,
    weight: 0.7,
    description: "Zalgo text (excessive combining diacriticals)",
  },
];
