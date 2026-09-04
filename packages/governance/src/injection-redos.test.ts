/**
 * ReDoS guard — every built-in injection pattern and every sensitive-data
 * pattern must stay linear on adversarial input.
 *
 * Each regex is timed alone against hostile 50KB shapes: the generic set
 * below, plus "literal word + filler" shapes derived from the regex itself so
 * a quadratic tail after e.g. `override` or `forward` is exercised even though
 * no generic input contains the trigger word. detectInjection() and
 * maskSensitiveData() are then timed end to end. Local runs land well under
 * 25ms per input; the assertion bound is loose so CI machines do not flake.
 * Before the fix the worst shapes took 4–35 seconds (minutes at 6KB+).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { BUILTIN_PATTERNS } from "./injection-patterns";
import { SENSITIVE_PATTERNS } from "./conditions/sensitive-patterns";
import { detectInjection } from "./injection-detect";
import { maskSensitiveData } from "./mask";

const KB = 1024;
const BUDGET_MS = 150;

/** Invisible code points are spelled out so the input shape stays readable. */
const cp = (...codes: number[]): string => String.fromCodePoint(...codes);

/** Repeat `unit` to exactly `length` characters. */
function fill(unit: string, length: number): string {
  return unit.repeat(Math.ceil(length / unit.length)).slice(0, length);
}

const GENERIC: Record<string, string> = {
  "50KB alphanumeric token": "a".repeat(50 * KB),
  "50KB spaces": " ".repeat(50 * KB),
  "6KB a…    b…": "a".repeat(3 * KB) + "    " + "b".repeat(3 * KB),
  "50KB a…    b…": "a".repeat(25 * KB) + "    " + "b".repeat(25 * KB),
  "50KB unmapped Cyrillic": fill("жд", 50 * KB),
  "50KB base64-ish": fill("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MTIz", 50 * KB),
  "50KB markdown openers": fill("[", 25 * KB) + fill("](", 25 * KB),
  "50KB image openers": fill("![](https://", 50 * KB),
  "50KB 'ignore '": fill("ignore ", 50 * KB),
  "50KB mixed unicode": fill("aЖ中é🙂ｉ" + cp(0x200b), 50 * KB),
  "50KB dotted letters": fill("a.", 50 * KB),
  "50KB 'a@a.'": fill("a@a.", 50 * KB),
  "50KB near-miss secrets": fill("secret: " + "a".repeat(39) + " ", 50 * KB),
  "50KB entity prefix": "&#" + "a".repeat(50 * KB),
};

const BENIGN_PROSE = fill(
  "The quarterly report shows steady growth across all regions, with notable gains in the enterprise segment. ",
  50 * KB,
);

/** Lower-cased literal words of a regex — its trigger vocabulary. */
function literalWords(re: RegExp): string[] {
  return [...new Set((re.source.match(/[A-Za-z]{3,}/g) ?? []).map((w) => w.toLowerCase()))];
}

/** A trigger word followed by the fillers that expose a backtracking tail. */
function triggerShapes(word: string): Record<string, string> {
  return {
    [`'${word}' + 50KB spaces`]: word + " ".repeat(50 * KB) + "x",
    [`'${word}' + 50KB alnum`]: word + "a".repeat(50 * KB),
    [`'${word} ' repeated`]: fill(word + " ", 50 * KB),
    [`'${word}:' + 50KB spaces`]: word + ":" + " ".repeat(50 * KB) + "x",
  };
}

function timeMs(fn: () => void): number {
  const start = performance.now();
  fn();
  return performance.now() - start;
}

function assertFast(label: string, fn: () => void): void {
  const ms = timeMs(fn);
  assert.ok(ms < BUDGET_MS, `${label} took ${ms.toFixed(1)}ms (budget ${BUDGET_MS}ms)`);
}

function assertRegexLinear(id: string, re: RegExp): void {
  for (const [name, input] of Object.entries(GENERIC)) {
    assertFast(`${id} × ${name}`, () => re.test(input));
  }
  for (const word of literalWords(re)) {
    for (const [name, input] of Object.entries(triggerShapes(word))) {
      assertFast(`${id} × ${name}`, () => re.test(input));
    }
  }
}

describe("ReDoS guard — built-in injection patterns", () => {
  for (const p of BUILTIN_PATTERNS) {
    it(`${p.id} stays linear on hostile input`, () => assertRegexLinear(p.id, p.pattern));
  }
});

describe("ReDoS guard — sensitive-data patterns", () => {
  for (const p of SENSITIVE_PATTERNS) {
    it(`${p.id} stays linear on hostile input`, () => assertRegexLinear(p.id, p.pattern));
  }
});

/** Trigger phrases whose patterns had quadratic or cubic tails before the fix. */
const KNOWN_TRIGGERS = [
  "override", "permanently", "forward", "inject", "run", "decode",
  "your new role is", "i am the admin", "tool_choice", "when", "keep this always",
];

describe("ReDoS guard — detectInjection() end to end", () => {
  for (const [name, input] of Object.entries(GENERIC)) {
    it(name, () => assertFast(`detectInjection × ${name}`, () => detectInjection(input)));
  }
  for (const word of KNOWN_TRIGGERS) {
    it(`trigger shapes for '${word}'`, () => {
      for (const [name, input] of Object.entries(triggerShapes(word))) {
        assertFast(`detectInjection × ${name}`, () => detectInjection(input));
      }
    });
  }
  it("50KB benign prose stays fast", () => {
    detectInjection(BENIGN_PROSE); // warm up
    const ms = timeMs(() => detectInjection(BENIGN_PROSE));
    console.log(`benign 50KB prose: detectInjection ${ms.toFixed(2)}ms`);
    assert.ok(ms < BUDGET_MS, `benign prose took ${ms.toFixed(1)}ms`);
  });
});

describe("ReDoS guard — maskSensitiveData() end to end", () => {
  for (const [name, input] of Object.entries(GENERIC)) {
    it(name, () => assertFast(`maskSensitiveData × ${name}`, () => maskSensitiveData(input)));
  }
  for (const word of ["secret", "AKIAIOSFODNN7EXAMPLE", "postgres://", "-----BEGIN"]) {
    it(`trigger shapes for '${word}'`, () => {
      for (const [name, input] of Object.entries(triggerShapes(word))) {
        assertFast(`maskSensitiveData × ${name}`, () => maskSensitiveData(input));
      }
    });
  }
});
