/**
 * Compatibility re-export: `governance-sdk/plugins/genkit`.
 *
 * The implementation moved to @governance-sdk/adapters in the kernel/plugin split. This
 * file keeps the published subpath working unchanged; import it from the
 * package above if you want the dependency to be explicit.
 */

export * from "@governance-sdk/adapters/plugins/genkit.js";
