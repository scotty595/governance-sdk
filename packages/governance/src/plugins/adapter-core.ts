/**
 * The adapter kernel — registration, context building, enforcement, audit and
 * provenance, once, for every framework adapter.
 *
 * Nine adapters carried their own copy of `buildRegistration`, `createEnforcer`
 * and `createAuditor`. The copies drifted: all nine hard-coded `agentLevel: 0`,
 * so `requireLevel(1)` blocked every call through them while the two adapters
 * that passed the real level allowed it. Same policy, different answer per
 * framework — the one thing a cross-framework governance layer must never do.
 *
 * An adapter's job is now only to map its framework's hook shape onto these
 * calls. Everything a decision depends on — the agent's level, the consequence
 * tier, the taint marks, the extracted target path and URL, the session token
 * count — is assembled here, so every adapter sees the same context for the
 * same call.
 */

import type { GovernanceInstance } from "../governance.js";
import type { AuditEvent } from "../storage.js";
import type {
  ActionTier,
  EnforcementContext,
  EnforcementDecision,
  PolicyAction,
  PolicyStage,
} from "../policy.js";
import type { AgentRegistration, AgentFramework } from "../types.js";
import { appendTaint, type TaintMark } from "../taint.js";
import { scanToolResult, type ScanToolResultInput, type ScanToolResultOutput } from "./tool-result-scan.js";
import { handleOutcome, type OutcomeCallbacks } from "./outcome-handler.js";
import {
  enforcePreprocess as runPreprocess,
  enforcePostprocess as runPostprocess,
  type PrePostResult,
} from "./pre-post-enforce.js";
import { extractFields, type ToolFieldExtractionRegistry } from "./mastra-processor-tool-wrap.js";

/**
 * The configuration every adapter accepts. Individual adapters extend this
 * with their own framework-specific options; the fields here mean the same
 * thing everywhere.
 */
export interface AdapterCoreConfig {
  /**
   * Stable agent id, forwarded to `gov.register({ id })`. Pass the same value
   * on every process start so registration re-binds to the existing agent row
   * in durable storage instead of creating a new one each restart.
   */
  agentId?: string;
  agentName: string;
  owner: string;
  framework?: AgentFramework;
  description?: string;
  version?: string;
  channels?: string[];
  hasAuth?: boolean;
  hasGuardrails?: boolean;
  hasObservability?: boolean;
  /** Defaults to true: an adapter is an audit log. */
  hasAuditLog?: boolean;
  permissions?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  /** Map a tool name to a policy action. Defaults to `"tool_call"`. */
  actionMapper?: (toolName: string) => PolicyAction;
  /** Supplies `ctx.sessionTokensUsed` when the host tracks it itself. */
  sessionTokenTracker?: () => number;
  /**
   * Map tool names to consequence tiers so `requireTierApproval()` can gate
   * them. Unmapped tools carry no tier and never match a tier rule.
   */
  toolTiers?: Record<string, ActionTier>;
  /**
   * Carry provenance across this adapter's session: every tool result scanned
   * through `scanResult()` leaves a taint mark, and later tool calls carry the
   * marks on `ctx.taint` so `blockTaintedTools()` can fire. Default true.
   */
  trackTaint?: boolean;
  /**
   * Map tool argument names onto `ctx.targetPath` / `ctx.targetUrl` so
   * `scope_boundary` and `network_allowlist` rules actually match. Generic
   * conventions (`path`, `url`, …) are applied without configuration.
   */
  toolFieldExtraction?: ToolFieldExtractionRegistry;
}

/**
 * The common case: a config that is also the outcome-callback bag, which is
 * how most adapters are shaped. Adapters whose callbacks take a richer object
 * than a tool name (the Mastra processor hands back a tool-call record) use
 * `AdapterCoreConfig` and handle outcomes themselves.
 */
export interface AdapterConfig extends AdapterCoreConfig, OutcomeCallbacks {}

/** Extra per-call inputs an adapter can supply when building a context. */
export interface CallContext {
  tool?: string;
  input?: Record<string, unknown>;
  action?: PolicyAction;
  inputText?: string;
  outputText?: string;
  metadata?: Record<string, unknown>;
  organizationId?: string;
  /** Output token count, for output-budget rules at the postprocess stage. */
  outputTokenCount?: number;
  /** Wall-clock duration, for latency rules at the postprocess stage. */
  executionDurationMs?: number;
  /**
   * Provenance marks for this call, when the adapter tracks them at a finer
   * scope than the core's per-session list. The Mastra processor does: it
   * keeps marks in Mastra's per-request processor state, which is exactly the
   * scope provenance should have. Supplying this replaces the session marks
   * for this context rather than merging with them.
   */
  taint?: TaintMark[];
}

export interface AdapterCore {
  /** Agent id assigned (or reused) at registration. */
  readonly agentId: string;
  /** Governance level from registration — what `requireLevel()` compares against. */
  readonly agentLevel: number;
  /** Composite score from registration. */
  readonly score: number;
  readonly governance: GovernanceInstance;
  /** Build a full enforcement context for a call. */
  context(call: CallContext): EnforcementContext;
  /**
   * Enforce a tool call at the `process` stage and apply the configured
   * outcome callbacks — throwing `GovernanceBlockedError` on block and
   * `GovernanceApprovalRequiredError` on require_approval, as adapters have
   * always done.
   */
  enforce(toolName: string, input?: Record<string, unknown>, call?: CallContext): Promise<EnforcementDecision>;
  /** Enforce at a specific stage without throwing; the caller decides. */
  enforceStage(stage: PolicyStage, call: CallContext): Promise<EnforcementDecision>;
  /** Write a tool-call audit event. */
  audit(toolName: string, outcome: "success" | "failure", detail?: Record<string, unknown>): Promise<AuditEvent>;
  /** Scan a tool's return value at the `tool_result` stage, recording provenance. */
  scanResult(input: Omit<ScanToolResultInput, "governance" | "agentId" | "agentName" | "agentLevel" | "taint">): Promise<ScanToolResultOutput>;
  /**
   * Enforce, run, and record the outcome — the shape every adapter's governed
   * `execute` wrapper had: enforce first, run the tool, audit success, audit
   * and rethrow on failure.
   */
  run<T>(toolName: string, input: Record<string, unknown> | undefined, fn: () => Promise<T>): Promise<T>;
  /**
   * Scan a user prompt at the `preprocess` stage. Throws on block and
   * require_approval, returns the text to use downstream (masked when a mask
   * rule fired) — the same contract the pre/post wrappers have always had,
   * but over a context the core assembled, so a prompt and a tool call on the
   * same agent are judged against the same facts.
   */
  preprocess(text: string, call?: CallContext): Promise<PrePostResult>;
  /** The same, at the `postprocess` stage, for a model's output. */
  postprocess(text: string, call?: CallContext): Promise<PrePostResult>;
  /** Provenance marks accumulated in this adapter's session. */
  readonly taint: {
    marks(): TaintMark[];
    record(mark: TaintMark): void;
    reset(): void;
  };
}

/** Drop undefined keys so a default underneath is not overwritten by absence. */
function stripUndefined(reg: AgentRegistration): AgentRegistration {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(reg)) if (v !== undefined) out[k] = v;
  return out as unknown as AgentRegistration;
}

/** Build the registration payload an adapter sends to `gov.register()`. */
export function buildRegistration(config: AdapterCoreConfig, tools: string[], framework: AgentFramework): AgentRegistration {
  return {
    id: config.agentId,
    name: config.agentName,
    framework: config.framework ?? framework,
    owner: config.owner,
    description: config.description,
    version: config.version,
    channels: config.channels,
    tools,
    hasAuth: config.hasAuth,
    hasGuardrails: config.hasGuardrails,
    hasObservability: config.hasObservability,
    hasAuditLog: config.hasAuditLog ?? true,
    permissions: config.permissions,
    metadata: config.metadata,
  };
}

export interface CreateAdapterCoreOptions {
  /** Tool names to declare at registration. */
  tools?: string[];
  /** Framework to record when the config does not name one. */
  framework: AgentFramework;
  /**
   * Per-adapter registration defaults, applied under the caller's config —
   * Bedrock treats an agent as authenticated unless told otherwise, LlamaIndex
   * tags its runtime, OpenAI Agents falls back to the agent's instructions for
   * a description. Anything the caller set wins.
   */
  registrationDefaults?: Partial<AgentRegistration>;
  /**
   * Applied by `core.enforce()` — throwing on block and require_approval, as
   * adapters have always done. Adapters whose config is itself the callback
   * bag pass `callbacks: config`; adapters that handle outcomes themselves
   * (the Mastra processor aborts the run instead of throwing) pass nothing.
   */
  callbacks?: OutcomeCallbacks;
}

/**
 * Register the agent and return the shared machinery every adapter needs.
 *
 * Registration happens once, here, and the level it returns is carried on
 * every context this core builds.
 */
export async function createAdapterCore(
  governance: GovernanceInstance,
  config: AdapterCoreConfig,
  opts: CreateAdapterCoreOptions,
): Promise<AdapterCore> {
  const registration: AgentRegistration = {
    ...opts.registrationDefaults,
    ...stripUndefined(buildRegistration(config, opts.tools ?? [], opts.framework)),
  };
  const registered = await governance.register(registration);
  return attachAdapterCore(governance, config, {
    agentId: registered.id,
    agentLevel: registered.level,
    score: registered.score,
    ...(opts.callbacks ? { callbacks: opts.callbacks } : {}),
  });
}

/**
 * The same core for an adapter that already has an agent id — the
 * bring-your-own-id wrappers that deliberately do not register.
 */
export function attachAdapterCore(
  governance: GovernanceInstance,
  config: AdapterCoreConfig,
  identity: { agentId: string; agentLevel?: number; score?: number; callbacks?: OutcomeCallbacks },
): AdapterCore {
  const agentId = identity.agentId;
  const agentLevel = identity.agentLevel ?? 0;
  const score = identity.score ?? 0;
  const trackTaint = config.trackTaint !== false;
  let marks: TaintMark[] = [];

  /** Caller-supplied marks win over the session list; see CallContext.taint. */
  function taintFor(call: CallContext): TaintMark[] {
    if (call.taint) return [...call.taint];
    return trackTaint && marks.length > 0 ? [...marks] : [];
  }

  function context(call: CallContext): EnforcementContext {
    const tool = call.tool;
    const fields = extractFields(call.input, config.toolFieldExtraction, tool ?? "");
    const tier = tool ? config.toolTiers?.[tool] : undefined;
    const metadata = call.metadata ?? config.metadata;
    return {
      agentId,
      agentName: config.agentName,
      agentLevel,
      action: call.action ?? (tool ? config.actionMapper?.(tool) ?? "tool_call" : "tool_call"),
      ...(tool !== undefined ? { tool } : {}),
      ...(call.input !== undefined ? { input: call.input } : {}),
      ...(call.inputText !== undefined ? { inputText: call.inputText } : {}),
      ...(call.outputText !== undefined ? { outputText: call.outputText } : {}),
      ...(call.outputTokenCount !== undefined ? { outputTokenCount: call.outputTokenCount } : {}),
      ...(call.executionDurationMs !== undefined ? { executionDurationMs: call.executionDurationMs } : {}),
      ...(fields.targetPath !== undefined ? { targetPath: fields.targetPath } : {}),
      ...(fields.targetUrl !== undefined ? { targetUrl: fields.targetUrl } : {}),
      ...(tier !== undefined ? { actionTier: tier } : {}),
      ...(taintFor(call).length > 0 ? { taint: taintFor(call) } : {}),
      ...(call.organizationId !== undefined ? { organizationId: call.organizationId } : {}),
      ...(metadata !== undefined ? { metadata } : {}),
      sessionTokensUsed: config.sessionTokenTracker?.(),
    };
  }

  async function enforce(
    toolName: string,
    input?: Record<string, unknown>,
    call: CallContext = {},
  ): Promise<EnforcementDecision> {
    const decision = await governance.enforce(context({ ...call, tool: toolName, input }));
    if (identity.callbacks) handleOutcome(decision, toolName, identity.callbacks);
    return decision;
  }

  async function enforceStage(stage: PolicyStage, call: CallContext): Promise<EnforcementDecision> {
    const ctx = context(call);
    switch (stage) {
      case "preprocess": return governance.enforcePreprocess(ctx);
      case "tool_result": return governance.enforceToolResult(ctx);
      case "postprocess": return governance.enforcePostprocess(ctx);
      default: return governance.enforce(ctx);
    }
  }

  function audit(
    toolName: string,
    outcome: "success" | "failure",
    detail?: Record<string, unknown>,
  ): Promise<AuditEvent> {
    return governance.audit.log({
      agentId,
      eventType: "tool_call",
      outcome,
      severity: outcome === "failure" ? "warning" : "info",
      detail: { tool: toolName, ...detail },
    });
  }

  async function scanResult(
    input: Omit<ScanToolResultInput, "governance" | "agentId" | "agentName" | "agentLevel" | "taint">,
  ): Promise<ScanToolResultOutput> {
    const scan = await scanToolResult({
      ...input,
      governance,
      agentId,
      agentName: config.agentName,
      agentLevel,
      ...(trackTaint && marks.length > 0 ? { taint: [...marks] } : {}),
    });
    if (trackTaint) marks = appendTaint(marks, scan.taint);
    return scan;
  }

  function prePostOptions(call: CallContext) {
    return {
      agentId,
      agentName: config.agentName,
      agentLevel,
      context: context(call),
      ...(identity.callbacks ? { callbacks: identity.callbacks } : {}),
      ...(call.action !== undefined ? { action: call.action } : {}),
      ...(call.metadata !== undefined ? { metadata: call.metadata } : {}),
    };
  }

  async function preprocess(text: string, call: CallContext = {}): Promise<PrePostResult> {
    return runPreprocess(governance, text, prePostOptions(call));
  }

  async function postprocess(text: string, call: CallContext = {}): Promise<PrePostResult> {
    return runPostprocess(governance, text, {
      ...prePostOptions(call),
      ...(call.outputTokenCount !== undefined ? { outputTokenCount: call.outputTokenCount } : {}),
      ...(call.executionDurationMs !== undefined ? { executionDurationMs: call.executionDurationMs } : {}),
    });
  }

  async function run<T>(
    toolName: string,
    input: Record<string, unknown> | undefined,
    fn: () => Promise<T>,
  ): Promise<T> {
    await enforce(toolName, input);
    try {
      const output = await fn();
      await audit(toolName, "success");
      return output;
    } catch (error) {
      await audit(toolName, "failure", {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  return {
    agentId,
    agentLevel,
    score,
    governance,
    context,
    enforce,
    enforceStage,
    audit,
    scanResult,
    run,
    preprocess,
    postprocess,
    taint: {
      marks: () => [...marks],
      record: (mark) => { if (trackTaint) marks = appendTaint(marks, mark); },
      reset: () => { marks = []; },
    },
  };
}
