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
/**
 * A hang backstop, not a performance target. The shapes here took 4–120+
 * seconds before the patterns were bounded, so anything under a second means
 * "not blowing up"; the real guard is the scaling assertion below, which does
 * not depend on this constant at all.
 */
const BUDGET_MS = 750;

/**
 * How much the cost may grow when the input grows 4x. A linear scan is ~4x; a
 * quadratic one is ~16x. 8x sits between them with room for measurement noise.
 */
const MAX_GROWTH_FOR_4X_INPUT = 8;

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

/**
 * Best of N. The whole suite runs in parallel, so a single sample measures
 * scheduler contention as much as it measures the code; the minimum is the
 * closest thing to an uncontended reading we can get cheaply.
 */
function bestOf(fn: () => void, runs = 3): number {
  let best = Infinity;
  for (let i = 0; i < runs; i++) best = Math.min(best, timeMs(fn));
  return best;
}

function assertFast(label: string, fn: () => void): void {
  const ms = bestOf(fn);
  assert.ok(ms < BUDGET_MS, `${label} took ${ms.toFixed(1)}ms (backstop ${BUDGET_MS}ms) — a blowup, not slow hardware`);
}

/**
 * The assertion that actually guards against catastrophic backtracking:
 * quadruple the input and the cost must not grow more than `MAX_GROWTH_FOR_4X_INPUT`.
 *
 * This is immune to machine load in a way a wall-clock budget is not — both
 * measurements suffer the same contention, so the ratio survives it — and it
 * fails on a quadratic pattern even on hardware fast enough to stay inside any
 * absolute budget.
 */
function assertLinearInInputSize(label: string, build: (chars: number) => string, run: (input: string) => void): void {
  const small = build(8 * KB);
  const large = build(32 * KB);
  run(small); // warm up, so JIT compilation is not charged to the first sample
  const smallMs = Math.max(bestOf(() => run(small)), 0.05);
  const largeMs = bestOf(() => run(large));
  const growth = largeMs / smallMs;
  assert.ok(
    growth < MAX_GROWTH_FOR_4X_INPUT,
    `${label}: 4x the input cost ${growth.toFixed(1)}x the time (${smallMs.toFixed(2)}ms to ${largeMs.toFixed(2)}ms) — that is super-linear`,
  );
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
  it("cost stays linear in input size for the shapes that used to blow up", () => {
    // The four shapes that were quartic, quadratic and cubic before bounding.
    assertLinearInInputSize("alnum run", (n) => "a".repeat(n), (i) => { detectInjection(i); });
    assertLinearInInputSize("gap shape", (n) => "a".repeat(n / 2) + "    " + "b".repeat(n / 2), (i) => { detectInjection(i); });
    assertLinearInInputSize("trigger + spaces", (n) => "override" + " ".repeat(n) + "x", (i) => { detectInjection(i); });
    assertLinearInInputSize("markdown openers", (n) => "[](".repeat(n / 3), (i) => { detectInjection(i); });
  });

  it("50KB benign prose stays fast", () => {
    detectInjection(BENIGN_PROSE); // warm up
    const ms = bestOf(() => detectInjection(BENIGN_PROSE));
    console.log(`benign 50KB prose: detectInjection ${ms.toFixed(2)}ms`);
    assert.ok(ms < BUDGET_MS, `benign prose took ${ms.toFixed(1)}ms (backstop ${BUDGET_MS}ms)`);
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
