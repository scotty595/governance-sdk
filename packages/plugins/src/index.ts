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
// The three Phase C standards mappings. The four older ones (EU AI Act, OWASP
// ASI, NIST AI RMF, ISO 42001) are reached by subpath only; these are exported
// from the barrel as well because they carry `revision` and `sourceUrls` that
// a caller assembling a compliance pack wants without a second import.
export * from "./nist-ai-600-1.js";
export * from "./csa-aicm.js";
export * from "./imda-agentic.js";
export * from "./ext/scoring-plugin.js";
export * from "./ext/detect-plugin.js";
export * from "./ext/scoring-hooks.js";
export * from "./ext/identity-plugin.js";
