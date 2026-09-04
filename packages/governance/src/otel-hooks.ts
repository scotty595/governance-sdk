/**
 * Compatibility re-export: `governance-sdk/otel-hooks`.
 *
 * The implementation moved to @governance-sdk/plugins in the kernel/plugin split. This
 * file keeps the published subpath working unchanged; import it from the
 * package above if you want the dependency to be explicit.
 */

export * from "@governance-sdk/plugins/otel-hooks.js";
