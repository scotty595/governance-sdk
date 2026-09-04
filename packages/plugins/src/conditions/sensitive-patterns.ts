/**
 * Built-in regex patterns for detecting sensitive data in outputs.
 * Used by the sensitive_data_filter condition and maskSensitiveData().
 *
 * Every regex here is linear-time on adversarial input (bounded quantifiers,
 * no overlapping repeats) — timed in injection-redos.test.ts. Shape-only
 * regexes over-match (any 40-char token "is" an AWS secret, any 16 digits
 * "are" a card), so patterns add context lookarounds and/or a `validate` step.
 */

export interface SensitivePattern {
  id: string;
  name: string;
  pattern: RegExp;
  /**
   * Second-stage check on the matched text. The regex describes the shape;
   * `validate` rejects shape-only false positives (Luhn for card numbers,
   * octet range for IPs). A match is only reported or masked when it returns
   * true. Omit for patterns whose shape is specific enough on its own.
   */
  validate?: (match: string) => boolean;
}

/** Luhn checksum over the digits of `s` (separators are ignored). */
export function luhnValid(s: string): boolean {
  const digits = s.replace(/\D/g, "");
  if (digits.length < 12) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Every dotted-quad octet is in 0–255. */
function validOctets(ip: string): boolean {
  return ip.split(".").every((octet) => Number(octet) <= 255);
}

export const SENSITIVE_PATTERNS: SensitivePattern[] = [
  // ── Credentials & Secrets ──
  { id: "aws_key", name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/ },
  // A 40-char base64-alphabet token is the shape of an AWS secret key — and of
  // every git SHA-1. Require context: a secret / secret-key label within 40
  // chars on the same line, or an AKIA… key id within 120 chars before it.
  // The cheap token lookahead runs before the context lookbehind so the
  // 160-char backward scan only happens at genuine 40-char token starts.
  {
    id: "aws_secret",
    name: "AWS Secret Key",
    pattern: /(?<![0-9a-zA-Z/+])(?=[0-9a-zA-Z/+]{40}(?![0-9a-zA-Z/+]))(?<=(?:(?:aws[_ -]?)?secret(?:[_ -]?access)?[_ -]?key|aws[_ -]?secret|secret\s{0,3}[:=])[^\n]{0,40}|AKIA[0-9A-Z]{16}[\s\S]{0,120})[0-9a-zA-Z/+]{40}/i,
  },
  { id: "github_pat", name: "GitHub PAT", pattern: /ghp_[0-9a-zA-Z]{36}/ },
  { id: "github_oauth", name: "GitHub OAuth", pattern: /gho_[0-9a-zA-Z]{36}/ },
  { id: "github_app", name: "GitHub App Token", pattern: /ghs_[0-9a-zA-Z]{36}/ },
  { id: "generic_sk", name: "Secret Key (sk-)", pattern: /sk-[0-9a-zA-Z-]{20,}/ },
  { id: "generic_pk", name: "Public Key (pk-)", pattern: /pk-[0-9a-zA-Z-]{20,}/ },
  { id: "jwt", name: "JWT", pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { id: "private_key", name: "Private Key", pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/ },
  { id: "postgres_uri", name: "PostgreSQL URI", pattern: /postgres(?:ql)?:\/\/[^\s]+/ },
  { id: "mysql_uri", name: "MySQL URI", pattern: /mysql:\/\/[^\s]+/ },
  { id: "mongodb_uri", name: "MongoDB URI", pattern: /mongodb(?:\+srv)?:\/\/[^\s]+/ },
  { id: "redis_uri", name: "Redis URI", pattern: /redis(?:s)?:\/\/[^\s]+/ },
  { id: "slack_token", name: "Slack Token", pattern: /xox[bpras]-[0-9a-zA-Z-]+/ },
  { id: "stripe_key", name: "Stripe Key", pattern: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/ },
  { id: "sendgrid_key", name: "SendGrid Key", pattern: /SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}/ },
  { id: "anthropic_key", name: "Anthropic Key", pattern: /sk-ant-[0-9a-zA-Z_-]{20,}/ },
  { id: "google_api_key", name: "Google API Key", pattern: /AIza[0-9A-Za-z_-]{35}/ },
  // ── PII ──
  { id: "ssn", name: "US SSN", pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  // Visa / Mastercard / Amex-prefix / Discover shape in four groups of four;
  // `validate` applies the Luhn check so ids that merely look like a card
  // are not redacted.
  {
    id: "credit_card",
    name: "Credit Card Number",
    pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/,
    validate: luhnValid,
  },
  // Local part, domain and TLD are bounded (RFC 5321 limits) so `a.a.a.…` and
  // `a@a.a@a.…` cannot backtrack quadratically.
  { id: "email_address", name: "Email Address", pattern: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/ },
  // Ten bare digits are more often an id than a phone number. Require the +1
  // country code, a parenthesised area code, or separators between all three
  // groups, and reject digits glued to a longer identifier (`ORD-123-456-7890`).
  {
    id: "phone_us",
    name: "US Phone Number",
    pattern: /(?<![\w+-])(?:\+1[-. ]?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}|(?:1[-. ])?\(\d{3}\)[-. ]?\d{3}[-. ]?\d{4}|(?:1[-. ])?\d{3}[-. ]\d{3}[-. ]\d{4})(?![\w-])/,
  },
  // Dotted quad with every octet ≤ 255 (`validate`); not part of a longer
  // dotted number, not preceded by a version label (`v1.2.3.4`,
  // `version 1.2.3.4`, `release-1.2.3.4`) and not carrying a semver suffix
  // (`1.2.3.4-beta`, `1.2.3.4+build`).
  {
    id: "ip_address",
    name: "IP Address",
    pattern: /(?<![\w.])(?<!\b(?:v|ver|version|build|release)[\s.:=-]{0,3})(?:\d{1,3}\.){3}\d{1,3}(?![\w.+]|-[A-Za-z])/i,
    validate: validOctets,
  },
  // ── System Prompt Leak ──
  { id: "system_prompt_leak", name: "System Prompt Leak", pattern: /\b(?:my|the|your|our)\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:is|are|says?|reads?|states?)\s*:/i },
  { id: "hidden_instructions", name: "Hidden Instructions Leak", pattern: /\b(?:hidden|secret|internal|original|initial|confidential)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b/i },
  { id: "never_reveal", name: "Leaking 'Never Reveal' Content", pattern: /\b(?:you\s+must\s+never|never\s+reveal|do\s+not\s+(?:share|reveal|disclose)|must\s+not\s+(?:share|reveal|disclose))\s+(?:these|this|the|your)\s+(?:instructions?|prompt|rules?|guidelines?)\b/i },
];

/** Get patterns by ID list, or all if empty/undefined */
export function getSensitivePatterns(ids?: string[]): SensitivePattern[] {
  if (!ids || ids.length === 0) return SENSITIVE_PATTERNS;
  return SENSITIVE_PATTERNS.filter((p) => ids.includes(p.id));
}

/**
 * True when `text` contains at least one match of `p` that passes its
 * `validate` hook. Patterns are declared without the `g` flag, so a global
 * clone is built to iterate candidates when validation is needed.
 */
export function matchesSensitivePattern(p: SensitivePattern, text: string): boolean {
  if (!p.validate) return p.pattern.test(text);
  const flags = p.pattern.flags.includes("g") ? p.pattern.flags : p.pattern.flags + "g";
  for (const m of text.matchAll(new RegExp(p.pattern.source, flags))) {
    if (p.validate(m[0])) return true;
  }
  return false;
}
