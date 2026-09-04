/**
 * Rule validation at every entry point: a typo becomes an error at
 * addRule() / createGovernance() / fromYAML(), never a rule that silently
 * fails open or throws on the first request.
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import { createGovernance, createPolicyEngine, PolicyValidationError, blockTools } from "./index.js";
import { fromYAML } from "./policy-yaml.js";
import type { PolicyRule } from "./policy.js";

const base: PolicyRule = {
  id: "r",
  name: "r",
  condition: { type: "tool_blocked", params: { tools: ["rm"] } },
  outcome: "block",
  reason: "no",
  priority: 10,
  enabled: true,
};

describe("validateRule via engine", () => {
  it("rejects a misspelled outcome", () => {
    const engine = createPolicyEngine();
    assert.throws(
      () => engine.addRule({ ...base, outcome: "blcok" as PolicyRule["outcome"] }),
      (e: unknown) => e instanceof PolicyValidationError && e.issues.some((i) => i.path === "outcome"),
    );
  });

  it("rejects an unknown condition type at construction", () => {
    assert.throws(
      () => createGovernance({ rules: [{ ...base, condition: { type: "geo_fence", params: {} } }] }),
      /unknown condition type "geo_fence"/,
    );
  });

  it("accepts an unknown type once the condition is registered", () => {
    const gov = createGovernance({
      conditions: [{ name: "geo_fence", description: "", evaluator: () => true }],
      rules: [{ ...base, condition: { type: "geo_fence", params: {} } }],
    });
    assert.equal(gov.policies.ruleCount, 1);
  });

  it("rejects NaN / non-finite priority and a non-boolean enabled", () => {
    const engine = createPolicyEngine();
    assert.throws(() => engine.addRule({ ...base, priority: Number.NaN }), PolicyValidationError);
    assert.throws(() => engine.addRule({ ...base, enabled: "yes" as unknown as boolean }), PolicyValidationError);
  });

  it("rejects an uncompilable regex in input_pattern", () => {
    const engine = createPolicyEngine();
    assert.throws(
      () => engine.addRule({ ...base, condition: { type: "input_pattern", params: { pattern: "([" } } }),
      /does not compile/,
    );
  });

  it("validates nested conditions inside any_of / not", () => {
    const engine = createPolicyEngine();
    assert.throws(
      () =>
        engine.addRule({
          ...base,
          condition: { type: "any_of", params: { conditions: [{ type: "nope", params: {} }] } },
        }),
      /conditions\[0\]\.type/,
    );
    assert.throws(
      () => engine.addRule({ ...base, condition: { type: "not", params: { condition: { type: "nope", params: {} } } } }),
      /params\.condition\.type/,
    );
  });

  it("accepts inline evaluators without a registry entry", () => {
    const engine = createPolicyEngine();
    engine.addRule({ ...base, condition: { type: "custom", params: { evaluate: () => false } } });
    assert.equal(engine.ruleCount, 1);
  });

  it("engine.validateRule reports without throwing", () => {
    const engine = createPolicyEngine();
    const issues = engine.validateRule({ ...base, stage: "later" as PolicyRule["stage"] });
    assert.equal(issues.length, 1);
    assert.equal(issues[0].path, "stage");
    assert.deepEqual(engine.validateRule(blockTools(["x"])), []);
  });
});

describe("fromYAML", () => {
  it("throws on a misspelled outcome instead of producing a fail-open rule", () => {
    const yaml = `rules:
  - id: r1
    name: R1
    outcome: blcok
    reason: no
    priority: 10
    enabled: true
    condition:
      type: tool_blocked
      params:
        tools:
          - rm
`;
    assert.throws(() => fromYAML(yaml), (e: unknown) => e instanceof PolicyValidationError && /outcome/.test(e.message));
  });

  it("throws on a non-numeric priority", () => {
    const yaml = `rules:
  - id: r1
    name: R1
    outcome: block
    reason: no
    priority: high
    enabled: true
    condition:
      type: tool_blocked
`;
    assert.throws(() => fromYAML(yaml), /priority/);
  });

  it("keeps quoted URLs in arrays as strings", () => {
    const yaml = `rules:
  - id: r1
    name: R1
    outcome: block
    reason: no
    priority: 10
    enabled: true
    condition:
      type: network_allowlist
      params:
        allowedDomains:
          - "http://good.example"
          - "https://also.example:8443"
`;
    const [rule] = fromYAML(yaml);
    assert.deepEqual(rule.condition.params.allowedDomains, ["http://good.example", "https://also.example:8443"]);
  });

  it("still parses inline-key array items as objects", () => {
    const yaml = `rules:
  - id: r1
    name: R1
    outcome: block
    reason: no
    priority: 10
    enabled: true
    condition:
      type: any_of
      params:
        conditions:
          - type: tool_blocked
            params:
              tools:
                - rm
`;
    const [rule] = fromYAML(yaml);
    const conditions = rule.condition.params.conditions as Array<Record<string, unknown>>;
    assert.equal(conditions[0].type, "tool_blocked");
  });

  it("rejects __proto__ keys", () => {
    const yaml = `rules:
  - id: r1
    name: R1
    outcome: block
    reason: no
    priority: 10
    enabled: true
    condition:
      type: tool_blocked
      params:
        __proto__:
          polluted: true
`;
    assert.throws(() => fromYAML(yaml), /not allowed/);
  });
});
