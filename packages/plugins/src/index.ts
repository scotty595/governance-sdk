/**
 * `@governance-sdk/plugins` — extensions to the governance kernel.
 *
 * Detection, standards mappings, scoring, identity, supply chain, policy
 * authoring and storage adapters. Everything here revises on someone else's
 * schedule — OWASP annually, a regulator by moving a date, a detector corpus
 * whenever the attacks change — which is exactly why it is not in the kernel.
 */

export * from "./ext/defaults.js";
export * from "./ext/standards-plugin.js";
export * from "./ext/scoring-plugin.js";
export * from "./ext/detect-plugin.js";
export * from "./ext/scoring-hooks.js";
