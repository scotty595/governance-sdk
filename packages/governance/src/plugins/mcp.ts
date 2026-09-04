/**
 * governance-sdk MCP (Model Context Protocol) Plugin
 *
 * Integrates governance enforcement into MCP servers.
 * Governs tool calls and resource reads with before-action policy checks.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools } from 'governance-sdk';
 * import { createGovernedMCP } from 'governance-sdk/plugins/mcp';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['shell_exec', 'file_delete'])],
 * });
 *
 * const { handleToolCall } = await createGovernedMCP(gov, originalHandler, {
 *   agentName: 'my-mcp-server',
 *   owner: 'platform-team',
 * });
 *
 * // Use handleToolCall as your server's tools/call handler
 * server.setRequestHandler('tools/call', handleToolCall);
 * ```
 */

import type { GovernanceInstance } from "../index";
import type { PolicyAction } from "../policy";
import { detectInjection } from "../injection-detect.js";
import { createAdapterCore } from "./adapter-core.js";
import type {
  MCPCallToolRequest,
  MCPCallToolResult,
  MCPReadResourceRequest,
  MCPContent,
  GovernMCPConfig,
  GovernedMCPResult,
  MCPToolCallHandler,
  MCPResourceReadHandler,
} from "./mcp-types.js";

// Re-export all types
export type {
  MCPCallToolRequest, MCPCallToolResult, MCPContent,
  MCPReadResourceRequest, MCPToolDefinition,
  GovernMCPConfig, GovernedMCPResult,
  MCPToolCallHandler, MCPResourceReadHandler,
} from "./mcp-types.js";

import { GovernanceBlockedError } from "./outcome-handler.js";

// ─── Blocked Error ──────────────────────────────────────────

export { GovernanceBlockedError, GovernanceApprovalRequiredError } from "./outcome-handler.js";

// ─── Create Governed MCP ────────────────────────────────────

/**
 * Create a governed MCP server handler.
 *
 * Wraps an existing tool call handler with governance enforcement.
 * Each tool call is checked against policies before execution.
 */
export async function createGovernedMCP(
  governance: GovernanceInstance,
  toolCallHandler: MCPToolCallHandler,
  config: GovernMCPConfig,
  resourceReadHandler?: MCPResourceReadHandler,
): Promise<GovernedMCPResult> {
  const core = await createAdapterCore(governance, config, {
    tools: config.tools ?? [],
    framework: "mcp",
    callbacks: config,
  });
  const enforce = (toolName: string, input?: Record<string, unknown>) => core.enforce(toolName, input);
  const audit = core.audit;

  const governResources = config.governResources !== false;

  async function handleToolCall(request: MCPCallToolRequest): Promise<MCPCallToolResult> {
    const toolName = request.params.name;
    const args = request.params.arguments;

    // Input pre-scan — symmetric to the output injection scan below.
    // Walks the incoming tool arguments for textual fields and scans each
    // for injection patterns BEFORE we call the tool handler. On detection
    // we block with a GovernanceBlockedError so the caller sees a structured
    // failure (audit event + policy violation) rather than silent pass-through.
    if (config.scanToolInputs !== false) {
      const textInputs = collectTextInputs(args);
      for (const text of textInputs) {
        const scan = detectInjection(text, {
          threshold: config.inputInjectionThreshold ?? 0.6,
        });
        if (scan.detected) {
          await audit(toolName, "failure", {
            injectionInInput: true, score: scan.score, patterns: scan.patterns,
          });
          throw new GovernanceBlockedError(
            {
              blocked: true,
              reason: `Injection detected in tool input (score: ${scan.score})`,
              ruleId: null,
              outcome: "block",
              evaluatedAt: new Date().toISOString(),
              rulesEvaluated: 0,
            },
            toolName,
          );
        }
      }
    }

    await enforce(toolName, args);

    try {
      const output = await toolCallHandler(request);

      // Scan tool output through the policy engine at stage="tool_result".
      // Replaces the legacy inline detectInjection() throw with a uniform
      // signal-then-enforce pattern shared with the Mastra wrapTool helper:
      // detectInjection populates ctx.mlInjectionScore as a signal; the
      // engine evaluates every applicable rule (ml_injection_guard,
      // sensitive_data_filter, output_pattern, scope_boundary, composites,
      // kill switch); first matching rule's outcome wins.
      if (config.scanToolOutputs !== false) {
        const scanned = await core.scanResult({
          tool: toolName,
          args: args as Record<string, unknown> | undefined,
          result: output.content,
          injectionThreshold: config.outputInjectionThreshold ?? 0.6,
          metadata: { source: "mcp", contentTypes: output.content.map((c) => c.type) },
        });
        if (scanned.blocked) {
          await audit(toolName, "failure", {
            injectionInOutput: true,
            reason: scanned.decision.reason,
            ruleId: scanned.decision.ruleId,
            outcome: scanned.decision.outcome,
          });
          throw new GovernanceBlockedError(scanned.decision, toolName);
        }
      }

      await audit(toolName, output.isError ? "failure" : "success", {
        contentTypes: output.content.map((c) => c.type),
      });
      return output;
    } catch (error) {
      await audit(toolName, "failure", {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  async function handleResourceRead(request: MCPReadResourceRequest): Promise<MCPContent[]> {
    if (governResources && resourceReadHandler) {
      const uri = request.params.uri;
      const resourceAction = config.resourceActionMapper?.(uri) ?? ("data_access" as PolicyAction);
      await core.enforce(uri, undefined, { action: resourceAction, metadata: { resourceUri: uri } });
    }

    if (!resourceReadHandler) {
      return [{ type: "text", text: "No resource handler configured" }];
    }

    try {
      const content = await resourceReadHandler(request);
      await audit(request.params.uri, "success", { type: "resource_read" });
      return content;
    } catch (error) {
      await audit(request.params.uri, "failure", {
        type: "resource_read",
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  return {
    handleToolCall,
    handleResourceRead,
    agentId: core.agentId,
    score: core.score,
    level: core.agentLevel,
    governance,
    enforce,
    audit,
  };
}

// ─── Utilities ─────────────────────────────────────────────────

/**
 * Walk an arbitrary tool-call arguments object and collect every string leaf
 * for injection scanning. Handles nested objects and arrays. Skips short
 * strings that are unlikely to contain meaningful payloads.
 */
function collectTextInputs(args: unknown, depth = 0): string[] {
  if (depth > 10) return []; // guard against pathological nesting
  const out: string[] = [];
  const visit = (v: unknown): void => {
    if (typeof v === "string") {
      if (v.length >= 8) out.push(v);
      return;
    }
    if (Array.isArray(v)) {
      for (const item of v) visit(item);
      return;
    }
    if (v && typeof v === "object") {
      for (const val of Object.values(v as Record<string, unknown>)) visit(val);
    }
  };
  visit(args);
  return out;
}
