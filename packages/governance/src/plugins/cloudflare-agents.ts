/**
 * Compatibility re-export: `governance-sdk/plugins/cloudflare-agents`.
 *
 * The implementation lives in @governance-sdk/adapters. This file exposes it
 * under the meta-package's subpath convention, so the Cloudflare Agents adapter
 * resolves the way every other `governance-sdk/plugins/*` adapter does; import
 * it from the package above if you want the dependency to be explicit.
 */

export * from "@governance-sdk/adapters/plugins/cloudflare-agents.js";
