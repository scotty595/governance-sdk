/**
 * `@governance-sdk/adapters` — framework adapters and the adapter kernel.
 *
 * One shared core (registration, context assembly, enforcement, audit,
 * provenance) and a thin mapping per framework, so one policy gives one answer
 * everywhere. Also the Agent Hooks conformance surface.
 *
 * Import the framework you use from its subpath, e.g.
 * `@governance-sdk/adapters/plugins/mastra-processor.js`.
 */

export * from "./plugins/adapter-core.js";
export * from "./plugins/text-extract.js";
export * from "./plugins/outcome-handler.js";
export * from "./plugins/tool-result-scan.js";
export * from "./conformance/agent-hooks.js";
