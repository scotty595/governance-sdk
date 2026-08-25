import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runDemo } from "./demo.js";

describe("CLI demo", () => {
  it("runs end-to-end in-process and returns the advertised outcomes", async () => {
    const lines: string[] = [];
    const result = await runDemo((l) => lines.push(l));

    // Step 1 — registration produced a scored agent.
    assert.ok(result.agent.id.length > 0);
    assert.ok(result.agent.score >= 0 && result.agent.score <= 100);

    // Step 2 — tool-call enforcement.
    assert.equal(result.decisions.webSearch.outcome, "allow");
    assert.equal(result.decisions.shellExec.outcome, "block");
    assert.equal(result.decisions.sendEmail.outcome, "require_approval");

    // Step 3 — preprocess injection guard fired.
    assert.equal(result.decisions.injection.outcome, "block");
    assert.equal(result.decisions.injection.ruleId, "injection-guard");

    // Step 4 — postprocess masking redacted the secret and the SSN.
    assert.equal(result.decisions.leak.outcome, "mask");
    assert.ok(result.decisions.leak.maskedText, "maskedText should be populated");
    assert.ok(!result.decisions.leak.maskedText.includes("123-45-6789"));
    assert.ok(!result.decisions.leak.maskedText.includes("hunter2"));

    // Step 5 — the chain covers every step and tampering is detected.
    assert.ok(result.chain.events >= 5, `expected ≥5 chained events, got ${result.chain.events}`);
    assert.equal(result.chain.intact.valid, true);
    assert.equal(result.chain.intact.eventsVerified, result.chain.events);
    assert.equal(result.chain.edited.valid, false);
    assert.match(result.chain.edited.breakDetail ?? "", /Hash mismatch at sequence 2/);
    assert.equal(result.chain.deleted.valid, false);
    assert.match(result.chain.deleted.breakDetail ?? "", /Sequence gap/);
  });

  it("prints a plain-text transcript with no ANSI codes by default", async () => {
    const lines: string[] = [];
    await runDemo((l) => lines.push(l));
    const text = lines.join("\n");
    assert.ok(!text.includes("\x1b["), "no ANSI escapes when color is off");
    assert.ok(text.includes("governance-sdk demo"));
    assert.ok(text.includes("✗ block"));
    assert.ok(text.includes("⏸ require_approval"));
    assert.ok(text.includes("◐ mask"));
    assert.ok(text.includes("intact export"));
    assert.ok(text.includes("Everything above ran in-process"));
    assert.ok(!text.includes("123-45-6789\""), "the redacted output line must not echo the SSN");
  });

  it("emits ANSI codes when color is requested", async () => {
    const lines: string[] = [];
    await runDemo((l) => lines.push(l), { color: true });
    assert.ok(lines.join("\n").includes("\x1b["));
  });
});
