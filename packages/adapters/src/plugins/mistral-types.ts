/**
 * Types for the Mistral AI governance integration.
 *
 * Mirrors @mistralai/mistralai (client-ts) shapes without requiring the SDK
 * as a dependency. Structurally compatible at runtime.
 */

import type { GovernanceInstance, AuditEvent } from "@governance-sdk/core";
import type { EnforcementDecision } from "@governance-sdk/core/policy.js";
import type { AdapterConfig } from "./adapter-core.js";

// ─── Mistral AI Shapes ──────────────────────────────────────

/** Mistral tool definition */
export interface MistralToolDefinition {
  type: "function";
  function: {
    name: string;
    description?: string;
    parameters: Record<string, unknown>;
    /** Enforce strict JSON schema for parameters */
    strict?: boolean;
  };
}

/** Mistral tool call from assistant response */
export interface MistralToolCall {
  /** Tool call ID (SDK defaults to "null" if absent) */
  id?: string;
  type?: "function";
  function: {
    name: string;
    /** Arguments — JSON string in API responses, may be pre-parsed in SDK */
    arguments: string | Record<string, unknown>;
  };
  /** Position in parallel tool calls (SDK defaults to 0) */
  index?: number;
}

/** Mistral tool executor */
export interface MistralToolExecutor {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

// ─── Configuration ──────────────────────────────────────────

/**
 * Extends the shared `AdapterConfig`: `agentId`, `agentName`, `owner`,
 * `framework`, `metadata`, `actionMapper`, `sessionTokenTracker`, the
 * `onBlocked` / `onDecision` / `onWarn` / `onMask` / `onApprovalRequired`
 * callbacks, plus `toolTiers` (consequence tiers for
 * `requireTierApproval()`), `trackTaint` (provenance from scanned tool
 * output carried onto later calls, for `blockTaintedTools()`) and
 * `toolFieldExtraction` (map tool arguments onto `ctx.targetPath` /
 * `ctx.targetUrl`).
 */
/* An interface rather than an alias so consumer declaration merging still works. */
export interface GovernMistralConfig extends AdapterConfig {}

// ─── Results ────────────────────────────────────────────────

export interface GovernedMistralResult {
  tools: MistralToolExecutor[];
  /** Process a Mistral tool call: enforce policy, execute, return result */
  handleToolCall: (toolCall: MistralToolCall) => Promise<{ toolCallId: string; content: string }>;
  agentId: string;
  score: number;
  level: number;
  governance: GovernanceInstance;
  enforce: (toolName: string, input?: Record<string, unknown>) => Promise<EnforcementDecision>;
  audit: (toolName: string, outcome: "success" | "failure", detail?: Record<string, unknown>) => Promise<AuditEvent>;
}
