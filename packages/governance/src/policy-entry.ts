/**
 * `governance-sdk/policy` — the policy surface as callers import it.
 *
 * `policy.ts` is the kernel engine: it knows the structural conditions and
 * nothing about detection. This entry point is the published subpath, so it
 * behaves the way it always has — `createPolicyEngine()` here comes with
 * `injection_guard` and `sensitive_data_filter` registered, because that is
 * what the documented condition vocabulary includes.
 *
 * Import `./policy.js` directly for a bare kernel engine.
 */

import { createPolicyEngine as createKernelPolicyEngine, type PolicyEngine, type PolicyEngineConfig } from "./policy.js";
import { defaultExtensions } from "./ext/defaults.js";

export * from "./policy.js";

/**
 * Create a policy engine with the SDK's full built-in condition vocabulary.
 *
 * Pass `conditions` to add your own, as before. To run without the detection
 * conditions, construct the kernel engine directly from `./policy.js`.
 */
export function createPolicyEngine(config: PolicyEngineConfig = {}): PolicyEngine {
  const defaults = defaultExtensions();
  const engine = createKernelPolicyEngine({
    ...config,
    // Defaults first so a caller's own entry of the same name still wins.
    conditions: [...(defaults.conditions ?? []), ...(config.conditions ?? [])],
  });
  for (const [conditionType, mask] of Object.entries(defaults.maskStrategies ?? {})) {
    engine.registerMaskStrategy(conditionType, mask);
  }
  return engine;
}
