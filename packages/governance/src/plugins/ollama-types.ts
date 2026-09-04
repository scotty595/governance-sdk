/**
 * Types for the Ollama governance integration.
 *
 * Mirrors ollama-js shapes without requiring the SDK
 * as a dependency. Structurally compatible at runtime.
 */

import type { GovernanceInstance, AuditEvent } from "../index";
import type { EnforcementDecision } from "../policy";
import type { AdapterConfig } from "./adapter-core.js";

// ─── Ollama Shapes ──────────────────────────────────────────

/** Ollama tool definition (matches ollama-js Tool type) */
export interface OllamaToolDefinition {
  type: "function";
  function: {
    name?: string;
    description?: string;
    /** JSON Schema-like type for the function */
    type?: string;
    parameters?: {
      type?: string;
      /** JSON Schema $defs for complex type references */
      $defs?: Record<string, unknown>;
      /** JSON Schema items for array types */
      items?: Record<string, unknown>;
      required?: string[];
      properties?: Record<string, {
        type?: string | string[];
        items?: Record<string, unknown>;
        description?: string;
        enum?: unknown[];
      }>;
    };
  };
}

/** Ollama tool call from model response */
export interface OllamaToolCall {
  function: {
    name: string;
    arguments: Record<string, unknown>;
  };
}

/** Ollama tool executor */
export interface OllamaToolExecutor {
  name: string;
  description: string;
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
export type GovernOllamaConfig = AdapterConfig;

// ─── Results ────────────────────────────────────────────────

export interface GovernedOllamaResult {
  tools: OllamaToolExecutor[];
  /** Process an Ollama tool call: enforce, execute, return result */
  handleToolCall: (toolCall: OllamaToolCall) => Promise<string>;
  agentId: string;
  score: number;
  level: number;
  governance: GovernanceInstance;
  enforce: (toolName: string, input?: Record<string, unknown>) => Promise<EnforcementDecision>;
  audit: (toolName: string, outcome: "success" | "failure", detail?: Record<string, unknown>) => Promise<AuditEvent>;
}
