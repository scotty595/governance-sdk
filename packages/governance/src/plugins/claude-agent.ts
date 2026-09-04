/**
 * Compatibility re-export: `governance-sdk/plugins/claude-agent`.
 *
 * The implementation lives in @governance-sdk/adapters. This file exposes it
 * under the meta-package's subpath convention, so the Claude Agent SDK adapter
 * resolves the way every other `governance-sdk/plugins/*` adapter does; import
 * it from the package above if you want the dependency to be explicit.
 */

export * from "@governance-sdk/adapters/plugins/claude-agent.js";
