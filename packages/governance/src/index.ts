/**
 * governance-sdk — Runtime governance for TypeScript AI agents.
 *
 * @example
 * ```ts
 * import { createGovernance, blockTools, requireLevel } from 'governance-sdk';
 *
 * const gov = createGovernance({
 *   rules: [blockTools(['shell_exec']), requireLevel(2)],
 * });
 *
 * const agent = await gov.register({
 *   name: 'sales-agent', framework: 'mastra', owner: 'sales-team',
 *   tools: ['email_draft', 'crm_update'], hasAuth: true,
 * });
 *
 * const decision = await gov.enforce({
 *   agentId: agent.id, agentName: 'sales-agent',
 *   agentLevel: agent.level, action: 'tool_call', tool: 'shell_exec',
 * });
 * // decision.blocked === true
 * ```
 *
 * @packageDocumentation
 */

import { assessAgent } from "./scorer.js";
import { createPolicyEngine } from "./policy.js";
import { createMemoryStorage } from "./storage.js";
import { createRemoteEnforcer, validateRemoteConfig, type RemoteConfig } from "./remote-enforce.js";
import { createGovernanceEmitter, type GovernanceEmitter } from "./events.js";
import { createGovernanceMetrics, type GovernanceMetrics } from "./metrics.js";
import { createSessionLedger, type SessionLedger, type SessionLedgerConfig } from "./session-ledger.js";
import {
  createPluginRegistry,
  type AuditSink,
  type GovernancePlugin,
  type InstalledPlugin,
  type KernelHandle,
  type MaskStrategy,
  type Reporter,
  type VerifierKind,
} from "./plugin.js";
import { createAuditChain, resolveOrgId } from "./audit-chain.js";
import { createScoringHooks } from "./scoring-hooks.js";
import { computeFailModes, describeFailModes, type FailModes } from "./fail-modes.js";
export type { FailModes };
import type { IntegrityAuditEvent } from "./audit-integrity.js";
import type { AgentRegistration, GovernanceAssessment, FleetSummary } from "./types.js";
import type {
  PolicyRule,
  PolicyOutcome,
  PolicyStage,
  EnforcementContext,
  EnforcementDecision,
  RegisteredConditionType,
} from "./policy.js";
import type { GovernanceStorage, StoredAgent, AuditEvent, AuditQueryFilters } from "./storage.js";

/**
 * The kernel's version, checked against a plugin's `requires.core` range.
 * Kept in step with `packages/governance/package.json` by
 * `src/core-version.test.ts`.
 */
export const CORE_VERSION = "0.22.0";

/**
 * Post-execution outcome payload for `gov.recordOutcome()`. Framework
 * adapters build this after a tool / LLM / governed-action returns and
 * pass it back so the audit chain covers "decision → outcome."
 */
export interface ActionOutcome {
  agentId: string;
  /** Organization that owns this agent — scopes the audit event to its per-org chain. */
  organizationId?: string;
  /** The tool / action that ran — matches what was on the EnforcementContext. */
  tool?: string;
  action?: string;
  /** Whether the action succeeded without throwing. */
  success: boolean;
  /** Wall-clock duration in ms. */
  durationMs?: number;
  /** Output summary — callers should redact sensitive content before passing. */
  output?: unknown;
  /** Error message if `success === false`. */
  error?: string;
  /** Tokens consumed by the action (LLM calls). */
  tokensUsed?: number;
  /** Monetary cost of the action, in whatever unit your `costBudget()` rules use. */
  cost?: number;
  /**
   * Mirrors `EnforcementContext.metadata` for the same call, so the session
   * ledger can attribute `tokensUsed` / `cost` to the right session
   * (`metadata.sessionId` / `metadata.threadId`, falling back to `agentId`).
   */
  metadata?: Record<string, unknown>;
  /** Optional ruleId that the preceding enforce() matched, to link the outcome back to the decision. */
  policyRuleId?: string;
  /** Optional extra fields. */
  detail?: Record<string, unknown>;
}

// Re-export storage types (other modules import from ./index)
export type { GovernanceStorage, StoredAgent, AuditEvent, AuditOutcome, AuditQueryFilters } from "./storage.js";
export { createMemoryStorage } from "./storage.js";

// ─── Governance Instance ────────────────────────────────────────

/** Configuration for createGovernance() */
export interface GovernanceConfig {
  storage?: GovernanceStorage;
  rules?: PolicyRule[];
  /**
   * Default outcome when no rules match. Accepts the full `PolicyOutcome`
   * union to mirror `PolicyEngineConfig.defaultOutcome` — the common case
   * is `"allow"` or `"block"`, but `"warn"` / `"require_approval"` /
   * `"mask"` are valid too.
   */
  defaultOutcome?: PolicyOutcome;
  /**
   * Custom condition types to register on the underlying policy engine.
   * Mirrors `PolicyEngineConfig.conditions` so callers using
   * `createGovernance()` don't have to drop down to `createPolicyEngine()`
   * just to register a custom evaluator.
   */
  conditions?: RegisteredConditionType[];
  /** When set, enforce() and register() POST to this URL instead of running locally */
  serverUrl?: string;
  /** Bearer token for remote calls — required when serverUrl is set */
  apiKey?: string;
  /** Request timeout in ms for remote calls (default: 30000) */
  timeout?: number;
  /** Max retry attempts for transient remote failures (default: 3) */
  maxRetries?: number;
  /** What to do when the API is unreachable after retries: "allow" (fail-open) or "block" (fail-closed). Default: "allow", or "block" under `strict`. */
  fallbackMode?: "allow" | "block";
  /** Hosted mode: called whenever a decision is produced by fallback rather than by the API (unreachable, retries exhausted, non-auth 4xx, invalid decision shape). */
  onFallback?: RemoteConfig["onFallback"];
  /**
   * Hosted mode: strip `input`, `inputText`, `outputText`, `metadata` and
   * `textByModality` from the context before it is sent (`true`), or apply
   * your own projection. Default `false` — the whole context is sent.
   */
  redactInput?: RemoteConfig["redactInput"];
  /**
   * Fail closed everywhere at once. Sets `fallbackMode: "block"` and
   * `integrityAudit.onFailure: "block"` unless each is set explicitly, and
   * rejects integrity signing keys shorter than 16 characters. Mask failure,
   * unknown condition types and kill-switch coverage already fail closed
   * regardless of this flag — see `failModes()`.
   */
  strict?: boolean;
  /**
   * Optional logger. When provided, one line summarising the instance's fail
   * modes is emitted at construction and warnings (weak signing key, hosted
   * mode writing audit locally) go here as well as to `onAuditError`.
   */
  logger?: { info: (message: string) => void; warn: (message: string) => void };
  /**
   * Per-process session ledger that fills `recentActionTimestamps`,
   * `recentActionCount`, `sessionTokensUsed` and `sessionCost` on the
   * context before local evaluation, so `rateLimit()`, `tokenBudget()` and
   * `costBudget()` accumulate without host wiring. Host-supplied values on
   * the context always win. Pass `false` to disable; pass a config to tune
   * bounds or the session key. Ignored in hosted mode.
   */
  ledger?: false | SessionLedgerConfig;
  /** Called when a fire-and-forget audit write fails. Audit errors never block enforcement. */
  onAuditError?: (error: unknown) => void;
  /**
   * Wire tamper-evident (HMAC-SHA256 hash-chained) audit into EVERY event
   * the SDK writes — registrations, enforce decisions, `audit.log()` calls,
   * `recordOutcome()` calls, kill-switch events. When set, every write is
   * intercepted and appended to a signed chain that `verifyAuditIntegrity`
   * can re-check offline.
   *
   * Honesty notes:
   *  - Only events routed through THIS governance instance get chained.
   *    Host-level logging your app does independently is not covered.
   *  - Plain HMAC is tamper-evident to holders of the signing secret;
   *    if the secret leaks, history is rewritable. Rotate + pair with an
   *    external anchor for defence-in-depth.
   */
  integrityAudit?: {
    /** HMAC secret. Rotate regularly. */
    signingKey: string;
    /**
     * What to do when a chain write fails (storage down, async contention):
     *  - `"allow"` (default) — log via `onAuditError`, proceed anyway. Chain
     *    may have a gap; `verifyAuditIntegrity` will detect it.
     *  - `"block"` — throw from `enforce()` so the decision is NOT applied.
     *    Guarantees no gaps at the cost of availability.
     */
    onFailure?: "allow" | "block";
  };
}

/** Read-only view of the policy engine — addRule/removeRule are not exposed */
export interface ReadonlyPolicyEngine {
  evaluate: (ctx: EnforcementContext) => EnforcementDecision;
  evaluateStage: (ctx: EnforcementContext, stage: PolicyStage) => EnforcementDecision;
  getRules: (stage?: PolicyStage) => PolicyRule[];
  readonly ruleCount: number;
}

/** The main governance instance returned by createGovernance() */
export interface GovernanceInstance {
  register: (input: AgentRegistration) => Promise<{
    id: string; score: number; level: number; status: string;
    assessment: GovernanceAssessment;
  }>;
  enforce: (ctx: EnforcementContext) => Promise<EnforcementDecision>;
  /** Evaluate only preprocess-stage rules */
  enforcePreprocess: (ctx: EnforcementContext) => Promise<EnforcementDecision>;
  /**
   * Evaluate only tool_result-stage rules.
   *
   * The `tool_result` stage runs after a tool returns and before the LLM
   * ingests the result on the next turn. Use this when you've intercepted
   * a tool's output (e.g. via wrapTool() or the MCP adapter) and want
   * stage-scoped enforcement on the returned content.
   *
   * For most callers, prefer `scanToolResult()` from `tool-result-scan.ts`
   * — it does the signal generation (detectInjection → mlInjectionScore)
   * and field extraction in addition to calling this method.
   */
  enforceToolResult: (ctx: EnforcementContext) => Promise<EnforcementDecision>;
  /** Evaluate only postprocess-stage rules */
  enforcePostprocess: (ctx: EnforcementContext) => Promise<EnforcementDecision>;
  /**
   * Record what actually happened AFTER an enforce()-approved action ran.
   * Framework adapters call this after the tool/LLM invocation returns so
   * the audit chain covers "decision → outcome," not just the decision.
   *
   * Safe to call even when `integrityAudit` isn't configured — the event
   * is written to plain storage. When integrity IS on, it's HMAC-chained
   * alongside everything else.
   *
   * Marked optional on the type for backwards compatibility with 0.10.x
   * consumers who implemented `GovernanceInstance` by hand (e.g. in test
   * mocks). Always populated by `createGovernance()` at runtime.
   */
  recordOutcome?: (outcome: ActionOutcome) => Promise<AuditEvent>;
  /**
   * Integrity-audit helpers. Only populated when `integrityAudit` is
   * configured on createGovernance(). Exports the signed chain for
   * offline verification via `verifyAuditIntegrity`.
   */
  integrityChain?: {
    /**
     * Export the chain as IntegrityAuditEvent[]. Pass `{ organizationId }` in
     * the filters to export a single org's contiguous, independently-verifiable
     * chain (chains are scoped per-org).
     */
    export: (filters?: AuditQueryFilters) => Promise<IntegrityAuditEvent[]>;
    /**
     * Chain stats for one org (or the org-less chain when omitted):
     * latest sequence, latest hash, algorithm.
     *
     * Reads the **durable** chain head from storage (`getChainHead`) whenever
     * the adapter provides it — the memory and Postgres adapters do — so under
     * a multi-process deployment the stats reflect the true head, including
     * writes made by other processes sharing the store, not just this
     * process's last append. Adapters with no `getChainHead` fall back to this
     * process's boot-resumed local cache (correct single-process only).
     *
     * Async since 0.19.0 (was sync ≤0.18.x): the durable head read is a
     * storage round-trip. `await` the call.
     */
    stats: (organizationId?: string) => Promise<{ latestSequence: number; latestHash: string; algorithm: string }>;
  };
  audit: {
    log: (event: Omit<AuditEvent, "id" | "createdAt">) => Promise<AuditEvent>;
    query: (filters: AuditQueryFilters) => Promise<AuditEvent[]>;
    count: (filters?: AuditQueryFilters) => Promise<number>;
  };
  score: (agentId: string) => Promise<GovernanceAssessment | null>;
  scoreFleet: () => Promise<{ assessments: GovernanceAssessment[]; summary: FleetSummary }>;
  /** Read-only view — use addRule()/removeRule() on the instance for mutations */
  policies: ReadonlyPolicyEngine;
  /** Direct storage access for queries — mutations should go through instance methods */
  storage: GovernanceStorage;
  /** Add a policy rule (instrumented — prefer this over direct policies.addRule) */
  addRule: (rule: PolicyRule) => void;
  /** Remove a policy rule by ID */
  removeRule: (ruleId: string) => void;
  /** Register a custom condition type on the underlying policy engine */
  registerCondition: (entry: RegisteredConditionType, opts?: { override?: boolean }) => void;
  /** Unregister a condition type by name */
  unregisterCondition: (name: string) => boolean;
  /** Get a registered condition type by name */
  getRegisteredCondition: (name: string) => RegisteredConditionType | undefined;
  /** List all registered condition types (custom + built-ins) */
  getRegisteredConditions: () => RegisteredConditionType[];
  /** Clear all registered conditions. Set `keepBuiltins: true` to re-register built-ins. */
  clearConditionRegistry: (opts?: { keepBuiltins?: boolean }) => void;
  /** Test API connectivity. Returns status without throwing. */
  connect: () => Promise<{ connected: boolean; mode: string; latencyMs: number }>;
  /** Current connection status (cached from last enforce/connect call). */
  status: () => { connected: boolean; mode: string; latencyMs: number };
  /** Poll an approval until resolved. Returns final status. */
  waitForApproval: (approvalId: string, opts?: { timeoutMs?: number; pollIntervalMs?: number }) => Promise<"approved" | "denied" | "expired" | "timeout">;
  /**
   * Install a system rule: evaluated at every stage, exempt from the
   * user-priority clamp, immune to `removeRule()`, and checked locally even
   * in hosted mode. Reserved for the kill switch and SDK-internal safety
   * rules. Optional on the type so hand-rolled mocks keep compiling; always
   * present on instances from `createGovernance()`.
   * @internal
   */
  addSystemRule?: (rule: PolicyRule) => void;
  /** Remove a system rule by ID. @internal */
  removeSystemRule?: (ruleId: string) => void;
  /**
   * Typed event stream: `enforcement`, `registration`, `policy_added`,
   * `policy_removed`, `kill`, `revive`. Subscribe with `gov.events.on(...)`
   * or `gov.events.onAny(...)` to feed dashboards, alerting or OTel.
   */
  events?: GovernanceEmitter;
  /** In-memory counters and timings for enforcement, registration and audit. */
  metrics?: GovernanceMetrics;
  /** The per-process session ledger (absent when disabled or in hosted mode). */
  ledger?: SessionLedger;
  /** How this instance behaves under failure — see `FailModes`. */
  failModes?: () => FailModes;
  /**
   * Install a plugin: a detector, a standards mapping, a scoring model, an
   * identity verifier, an audit sink. Idempotent per plugin id; refuses a
   * plugin whose `requires.core` range this kernel does not satisfy. See
   * `plugin.ts` for the contract and docs/restructure-plan.md for why the
   * seam exists.
   */
  use?: (plugin: GovernancePlugin) => Promise<void>;
  /** Remove a plugin by id, running its `uninstall()`. Returns false if absent. */
  unuse?: (id: string) => Promise<boolean>;
  /** Plugins installed on this instance. */
  plugins?: () => InstalledPlugin[];
  /**
   * Run a report a plugin registered (`standards/eu-ai-act`,
   * `standards/owasp-asi`, …). Throws when no reporter is registered under
   * that id, naming the ids that are.
   */
  report?: <Report = unknown>(id: string, config?: unknown) => Promise<Report>;
  /** Verifiers plugins registered, consulted by the kernel where it has a hook. */
  getVerifier?: (kind: VerifierKind) => unknown;
}

/** Reconstruct an AgentRegistration from a StoredAgent, including capability booleans from metadata. */
function storedToRegistration(agent: StoredAgent): AgentRegistration {
  const meta = (agent.metadata ?? {}) as Record<string, unknown>;
  return {
    name: agent.name,
    framework: agent.framework as AgentRegistration["framework"],
    owner: agent.owner, description: agent.description, version: agent.version,
    channels: agent.channels, tools: agent.tools, permissions: agent.permissions, metadata: agent.metadata,
    hasAuth: meta.hasAuth === true,
    hasGuardrails: meta.hasGuardrails === true,
    hasObservability: meta.hasObservability === true,
    hasAuditLog: meta.hasAuditLog === true,
  };
}

/**
 * Create a governance instance — the main entry point for governance-sdk.
 *
 * @param config - Optional configuration: storage adapter, policy rules, default outcome, remote server
 * @returns A fully-wired governance instance with register, enforce, audit, score, and scoreFleet
 *
 * @example
 * ```ts
 * const gov = createGovernance({
 *   rules: [blockTools(['shell_exec']), requireLevel(2)],
 * });
 * ```
 */
export function createGovernance(config: GovernanceConfig = {}): GovernanceInstance {
  validateRemoteConfig(config.serverUrl, config.apiKey);

  const onAuditError = config.onAuditError;
  const logger = config.logger;
  const strict = config.strict === true;
  const fallbackMode: "allow" | "block" = config.fallbackMode ?? (strict ? "block" : "allow");
  // Integrity config with strict-mode default applied. Validated up front:
  // an empty key silently produced a "signed" chain anyone could recompute.
  const integrity = config.integrityAudit
    ? { ...config.integrityAudit, onFailure: config.integrityAudit.onFailure ?? (strict ? "block" as const : "allow" as const) }
    : undefined;
  if (integrity) {
    if (typeof integrity.signingKey !== "string" || integrity.signingKey.length === 0) {
      throw new Error("integrityAudit.signingKey must be a non-empty string");
    }
    if (integrity.signingKey.length < 16) {
      const msg = `integrityAudit.signingKey is ${integrity.signingKey.length} characters; use at least 16 (32+ recommended) — short HMAC keys are brute-forceable offline`;
      if (strict) throw new Error(msg);
      logger?.warn(msg);
    }
  }
  const events = createGovernanceEmitter();
  const metrics = createGovernanceMetrics();
  const storage = config.storage ?? createMemoryStorage();
  const policies = createPolicyEngine({
    rules: config.rules,
    defaultOutcome: config.defaultOutcome,
    conditions: config.conditions,
  });

  // ── Plugin surface ───────────────────────────────────────────
  // Sinks receive every audit event after it is written (and chained, when
  // integrity audit is on). Reporters are named reports over governance state.
  // Verifiers are consulted by the kernel where it has a hook for them.
  const sinks: AuditSink[] = [];
  const reporters = new Map<string, Reporter>();
  const verifiers = new Map<VerifierKind, unknown>();

  /** Fan a written event out to sinks. Never throws into the write path. */
  function emitToSinks(event: AuditEvent): void {
    for (const sink of sinks) {
      try {
        const r = sink(event);
        if (r && typeof (r as Promise<void>).catch === "function") {
          (r as Promise<void>).catch((err: unknown) => { onAuditError?.(err); });
        }
      } catch (err) {
        onAuditError?.(err);
      }
    }
  }

  // The chain owns the write path and the per-org heads; see audit-chain.ts.
  const chain = createAuditChain({ storage, integrity, onAuditError, emitToSinks });
  const writeAudit = chain.writeAudit;

  const remote = config.serverUrl
    ? createRemoteEnforcer({
        serverUrl: config.serverUrl,
        apiKey: config.apiKey!,
        timeout: config.timeout,
        maxRetries: config.maxRetries,
        fallbackMode,
        ...(config.onFallback ? { onFallback: config.onFallback } : {}),
        ...(config.redactInput !== undefined ? { redactInput: config.redactInput } : {}),
      })
    : null;

  // Session ledger (local mode only — the remote API owns counts in hosted mode).
  const ledger: SessionLedger | null =
    remote || config.ledger === false ? null : createSessionLedger(config.ledger ?? {});

  if (remote && !config.storage) {
    const msg =
      "hosted mode: audit.log(), recordOutcome() and kill-switch events are written to local in-memory storage, not sent to the remote API — pass `storage` (e.g. Postgres) to persist them, or rely on the hosted API's own audit trail";
    logger?.warn(msg);
    onAuditError?.(new Error(msg));
  }

  function failModes(): FailModes {
    return computeFailModes({
      remote: remote !== null,
      strict,
      fallbackMode,
      integrityOnFailure: integrity?.onFailure,
      ledger: ledger !== null,
    });
  }
  /** Bookkeeping shared by enforce() and enforceStage(): ledger, metrics, events. */
  function finishDecision(
    ctx: EnforcementContext,
    decision: EnforcementDecision,
    stage: PolicyStage | undefined,
    startedAt: number,
  ): void {
    // Only tool-call–shaped stages count as "actions" for rate limiting.
    if (ledger && !decision.blocked && (stage === undefined || stage === "process")) {
      ledger.recordAction(ledger.keyFor(ctx));
    }
    metrics.increment("enforcement.total");
    if (decision.outcome === "require_approval") metrics.increment("enforcement.require_approval");
    else if (decision.blocked) metrics.increment("enforcement.blocked");
    else metrics.increment("enforcement.allowed");
    metrics.timing("enforcement.duration_ms", performance.now() - startedAt);
    if (events.listenerCount("enforcement") > 0) {
      events.emit({
        type: "enforcement",
        timestamp: decision.evaluatedAt,
        agentId: ctx.agentId,
        detail: {
          outcome: decision.outcome,
          blocked: decision.blocked,
          ruleId: decision.ruleId,
          reason: decision.reason,
          action: ctx.action,
          tool: ctx.tool,
          stage: stage ?? decision.stage,
        },
      });
    }
  }

  async function register(input: AgentRegistration) {
    if (remote) {
      const result = await remote.register(input);
      metrics.increment("registration.total");
      events.emit({ type: "registration", timestamp: new Date().toISOString(), agentId: result.id, detail: { name: input.name, framework: input.framework, score: result.score, level: result.level, mode: "hosted" } });
      return result;
    }

    // Honor a caller-supplied id when present (e.g. binding to a Lua
    // agent's canonical agentId from lua.skill.yaml so the dashboard
    // record uses the same id the runtime will send to enforce()).
    const id = input.id ?? crypto.randomUUID();
    const organizationId = resolveOrgId(input.organizationId, input.metadata);
    const assessment = assessAgent(id, input);

    // Persist capability booleans in metadata so re-scoring can reconstruct them
    const capabilities = {
      hasAuth: input.hasAuth ?? false,
      hasGuardrails: input.hasGuardrails ?? false,
      hasObservability: input.hasObservability ?? false,
      hasAuditLog: input.hasAuditLog ?? false,
    };
    const metadata = { ...input.metadata, ...capabilities };

    const stored = await storage.createAgent({
      id,
      name: input.name,
      framework: input.framework,
      owner: input.owner,
      description: input.description,
      organizationId,
      version: input.version ?? "1.0.0",
      channels: input.channels ?? [],
      tools: input.tools ?? [],
      permissions: input.permissions,
      metadata,
      compositeScore: assessment.compositeScore,
      governanceLevel: assessment.level.level,
      status: assessment.status,
      registeredAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // With integrity on, await the chain write so sequence ordering is
    // deterministic (and fail-closed mode can reject). Without integrity,
    // fire-and-forget for the legacy behaviour.
    const regWrite = writeAudit({
      agentId: id,
      ...(organizationId ? { organizationId } : {}),
      eventType: "agent_registered",
      outcome: "success",
      severity: "info",
      detail: { score: assessment.compositeScore, level: assessment.level.level, status: assessment.status },
    });
    if (integrity) {
      try { await regWrite; } catch (err) { onAuditError?.(err); if (integrity.onFailure === "block") throw err; }
    } else {
      regWrite.catch((err: unknown) => { onAuditError?.(err); });
    }

    metrics.increment("registration.total");
    events.emit({ type: "registration", timestamp: new Date().toISOString(), agentId: stored.id, detail: { name: input.name, framework: input.framework, score: assessment.compositeScore, level: assessment.level.level, mode: "local" } });
    return { id: stored.id, score: assessment.compositeScore, level: assessment.level.level, status: assessment.status, assessment };
  }

  async function enforce(ctx: EnforcementContext): Promise<EnforcementDecision> {
    const startedAt = performance.now();
    if (remote) {
      // System rules (kill switch) are authoritative for this process even
      // when decisions come from the API — a local kill must not be undone
      // by a remote allow.
      const local = policies.evaluateSystemRules(ctx);
      const decision = local ?? (await remote.enforce(ctx));
      finishDecision(ctx, decision, undefined, startedAt);
      return decision;
    }

    const evalCtx = ledger ? ledger.populate(ctx) : ctx;
    const decision = policies.evaluate(evalCtx);
    const organizationId = resolveOrgId(ctx.organizationId, ctx.metadata);

    // When integrityAudit is configured, we AWAIT the chain write so
    // sequencing is deterministic (and onFailure:"block" can veto the
    // decision). Without integrity, keep the legacy fire-and-forget path
    // to stay off the hot path.
    const writePromise = writeAudit({
      agentId: ctx.agentId,
      ...(organizationId ? { organizationId } : {}),
      eventType: "policy_evaluation",
      outcome: decision.outcome,
      severity: decision.blocked ? "warning" : "info",
      detail: { action: ctx.action, tool: ctx.tool, ruleId: decision.ruleId, reason: decision.reason, rulesEvaluated: decision.rulesEvaluated },
      policyRuleId: decision.ruleId ?? undefined,
    });
    if (integrity) {
      try {
        await writePromise;
      } catch (err) {
        onAuditError?.(err);
        if (integrity.onFailure === "block") throw err;
      }
    } else {
      writePromise.catch((err: unknown) => { onAuditError?.(err); });
    }

    finishDecision(evalCtx, decision, undefined, startedAt);
    return decision;
  }

  const audit = {
    async log(event: Omit<AuditEvent, "id" | "createdAt">): Promise<AuditEvent> {
      return writeAudit(event);
    },
    async query(filters: AuditQueryFilters): Promise<AuditEvent[]> {
      return storage.queryAuditEvents(filters);
    },
    async count(filters?: AuditQueryFilters): Promise<number> {
      return storage.countAuditEvents(filters);
    },
  };

  const scoring = createScoringHooks(storage, storedToRegistration);

  async function enforceStage(ctx: EnforcementContext, stage: PolicyStage): Promise<EnforcementDecision> {
    const startedAt = performance.now();
    if (remote) {
      const local = policies.evaluateSystemRules(ctx, stage);
      const decision = local ?? (await remote.enforce(ctx, stage));
      finishDecision(ctx, decision, stage, startedAt);
      return decision;
    }

    const evalCtx = ledger ? ledger.populate(ctx) : ctx;
    const decision = policies.evaluateStage(evalCtx, stage);
    const organizationId = resolveOrgId(ctx.organizationId, ctx.metadata);

    const writePromise = writeAudit({
      agentId: ctx.agentId,
      ...(organizationId ? { organizationId } : {}),
      eventType: `policy_evaluation_${stage}`,
      outcome: decision.outcome,
      severity: decision.blocked ? "warning" : "info",
      detail: { action: ctx.action, tool: ctx.tool, ruleId: decision.ruleId, reason: decision.reason, stage },
      policyRuleId: decision.ruleId ?? undefined,
    });
    if (integrity) {
      try {
        await writePromise;
      } catch (err) {
        onAuditError?.(err);
        if (integrity.onFailure === "block") throw err;
      }
    } else {
      writePromise.catch((err: unknown) => { onAuditError?.(err); });
    }

    finishDecision(evalCtx, decision, stage, startedAt);
    return decision;
  }

  const enforcePreprocess = (ctx: EnforcementContext) => enforceStage(ctx, "preprocess");
  const enforceToolResult = (ctx: EnforcementContext) => enforceStage(ctx, "tool_result");
  const enforcePostprocess = (ctx: EnforcementContext) => enforceStage(ctx, "postprocess");

  // Expose read-only policy view — mutations go through addRule/removeRule
  const readonlyPolicies: ReadonlyPolicyEngine = {
    evaluate: (ctx) => policies.evaluate(ctx),
    evaluateStage: (ctx, stage) => policies.evaluateStage(ctx, stage),
    getRules: (stage?) => policies.getRules(stage),
    get ruleCount() { return policies.ruleCount; },
  };

  function addRule(rule: PolicyRule): void {
    policies.addRule(rule);
    events.emit({ type: "policy_added", timestamp: new Date().toISOString(), detail: { ruleId: rule.id, outcome: rule.outcome, priority: rule.priority, stage: rule.stage } });
  }

  function removeRule(ruleId: string): void {
    policies.removeRule(ruleId);
    events.emit({ type: "policy_removed", timestamp: new Date().toISOString(), detail: { ruleId } });
  }

  function addSystemRule(rule: PolicyRule): void {
    policies.addSystemRule(rule);
    events.emit({ type: "policy_added", timestamp: new Date().toISOString(), detail: { ruleId: rule.id, outcome: rule.outcome, priority: rule.priority, system: true } });
  }

  function removeSystemRule(ruleId: string): void {
    policies.removeSystemRule(ruleId);
    events.emit({ type: "policy_removed", timestamp: new Date().toISOString(), detail: { ruleId, system: true } });
  }

  function registerCondition(entry: RegisteredConditionType, opts?: { override?: boolean }): void {
    policies.registerCondition(entry, opts);
  }

  function unregisterCondition(name: string): boolean {
    return policies.unregisterCondition(name);
  }

  function getRegisteredCondition(name: string): RegisteredConditionType | undefined {
    return policies.getRegisteredCondition(name);
  }

  function getRegisteredConditions(): RegisteredConditionType[] {
    return policies.getRegisteredConditions();
  }

  function clearConditionRegistry(opts?: { keepBuiltins?: boolean }): void {
    policies.clearConditionRegistry(opts);
  }

  const noopStatus = () => ({ connected: true, mode: "local" as const, latencyMs: 0 });

  const integrityChain = chain.integrityChain;

  async function recordOutcome(outcome: ActionOutcome): Promise<AuditEvent> {
    if (ledger && (outcome.tokensUsed !== undefined || outcome.cost !== undefined)) {
      const key = ledger.keyFor({ agentId: outcome.agentId, action: "custom", metadata: outcome.metadata });
      ledger.recordUsage(key, { tokens: outcome.tokensUsed, cost: outcome.cost });
    }
    return writeAudit({
      agentId: outcome.agentId,
      ...(outcome.organizationId ? { organizationId: outcome.organizationId } : {}),
      eventType: "action_outcome",
      outcome: outcome.success ? "success" : "failure",
      severity: outcome.success ? "info" : "warning",
      detail: {
        tool: outcome.tool,
        action: outcome.action,
        durationMs: outcome.durationMs,
        tokensUsed: outcome.tokensUsed,
        ...(outcome.cost !== undefined ? { cost: outcome.cost } : {}),
        error: outcome.error,
        output: outcome.output,
        ...(outcome.detail ?? {}),
      },
      policyRuleId: outcome.policyRuleId,
    });
  }

  // The handle a plugin is given at install time: registration verbs, the
  // event stream, an audit writer and the fail modes — never the instance
  // itself, its storage or its rules.
  const kernelHandle: KernelHandle = {
    core: CORE_VERSION,
    registerCondition: (entry, opts) => policies.registerCondition(entry, opts),
    registerMaskStrategy: (conditionType: string, mask: MaskStrategy) =>
      policies.registerMaskStrategy(conditionType, mask),
    registerVerifier: (kind, verifier) => { verifiers.set(kind, verifier); },
    registerReporter: (id, reporter) => {
      if (reporters.has(id)) {
        throw new Error(`Reporter "${id}" is already registered on this instance`);
      }
      reporters.set(id, reporter);
    },
    events,
    audit: { log: (event) => writeAudit(event) },
    addSink: (sink) => { sinks.push(sink); },
    failModes,
  };
  const pluginRegistry = createPluginRegistry(kernelHandle, CORE_VERSION);

  async function report<Report = unknown>(id: string, reportConfig?: unknown): Promise<Report> {
    const reporter = reporters.get(id);
    if (!reporter) {
      const known = [...reporters.keys()].sort();
      throw new Error(
        `No reporter registered under "${id}". ${known.length > 0 ? `Registered: ${known.join(", ")}.` : "Install a plugin that registers one, e.g. gov.use(euAiActPlugin())."}`,
      );
    }
    return (await reporter(reportConfig)) as Report;
  }

  const instance: GovernanceInstance = {
    register, enforce, enforcePreprocess, enforceToolResult, enforcePostprocess, audit,
    recordOutcome,
    score: scoring.scoreAgent, scoreFleet: scoring.scoreFleet,
    policies: readonlyPolicies, storage, addRule, removeRule,
    addSystemRule,
    removeSystemRule,
    registerCondition,
    unregisterCondition,
    getRegisteredCondition,
    getRegisteredConditions,
    clearConditionRegistry,
    connect: remote ? remote.connect : async () => noopStatus(),
    status: remote ? remote.status : noopStatus,
    waitForApproval: remote
      ? remote.waitForApproval
      : async () => "timeout" as const,
    events,
    metrics,
    ...(ledger ? { ledger } : {}),
    failModes,
    use: (plugin) => pluginRegistry.use(plugin),
    unuse: (id) => pluginRegistry.unuse(id),
    plugins: () => pluginRegistry.list(),
    report,
    getVerifier: (kind) => verifiers.get(kind),
    ...(integrityChain ? { integrityChain } : {}),
  };

  if (logger) {
    const fm = failModes();
    logger.info(describeFailModes(fm));
  }

  return instance;
}

// ─── Re-exports ─────────────────────────────────────────────────

export { storedToRegistration };
export { assessAgent, assessFleet, getGovernanceLevel } from "./scorer.js";
export { createPolicyEngine, blockTools, allowOnlyTools, requireApproval, requireToolApproval, requireTierApproval, blockTaintedTools, toolResultInjectionGuard, tokenBudget, rateLimit, requireLevel, requireSignedIdentity, requireSequence, timeWindow, MAX_USER_PRIORITY, SYSTEM_RULE_PRIORITY, PolicyValidationError, validateRuleShape, POLICY_OUTCOMES, POLICY_STAGES, markTaint, hasTaint, appendTaint } from "./policy.js";
export type { PolicyRule, PolicyEngine, PolicyAction, PolicyCondition, PolicyOutcome, PolicyStage, ActionTier, EnforcementContext, EnforcementDecision, PolicyEngineConfig, ConditionEvaluator, RegisteredConditionType, PolicyValidationIssue, TaintMark, TaintSource, TaintFilter } from "./policy.js";
export { createAuditChain, resolveOrgId } from "./audit-chain.js";
export type { AuditChain, AuditChainDeps, ResolvedIntegrityConfig } from "./audit-chain.js";
export { createScoringHooks } from "./scoring-hooks.js";
export type { ScoringHooks } from "./scoring-hooks.js";
export { createSessionLedger } from "./session-ledger.js";
export { createPluginRegistry, satisfiesRange, PluginError } from "./plugin.js";
export type {
  GovernancePlugin,
  KernelHandle,
  KernelCapability,
  InstalledPlugin,
  MaskStrategy,
  AuditSink,
  Reporter,
  VerifierKind,
  PluginRegistry,
} from "./plugin.js";
export type { SessionLedger, SessionLedgerConfig, SessionSnapshot } from "./session-ledger.js";
export type { AgentRegistration, AgentFramework, AgentStatus, GovernanceAssessment, GovernanceLevel, DimensionResult, ScoreDimension, FleetSummary } from "./types.js";
export { detectInjection, createInjectionGuard, getBuiltinPatterns } from "./injection-detect.js";
export type { InjectionPattern, InjectionCategory, InjectionResult, InjectionDetectorConfig } from "./injection-detect.js";
export { createGovernanceEmitter } from "./events.js";
export { dryRun, fleetDryRun } from "./dry-run.js";
export type { DryRunScenario, DryRunAction, DryRunResult, DryRunDecision, DryRunSummary, DryRunConfig, FleetDryRunResult } from "./dry-run.js";
export { createGovernanceMetrics } from "./metrics.js";
export type { GovernanceMetrics, MetricName, TimingName, MetricLabels, MetricsSnapshot } from "./metrics.js";
export type { GovernanceEmitter, GovernanceEvent, GovernanceEventType, GovernanceEventHandler } from "./events.js";
export { computeSignals, computeBehavioralAdjustments, applyBehavioralAdjustments } from "./behavioral-scorer.js";
export type { BehavioralInput, BehavioralAdjustment, BehavioralAssessment, BehavioralSignals } from "./behavioral-scorer.js";
export { scanRepoContents, scanRepoContentsWithPlugins, SCAN_GLOBS, SCAN_IGNORE } from "./repo-patterns.js";
export type { CapabilityDetection, RepoScanResult, ScanWithPluginsOptions } from "./repo-patterns.js";
export type {
  ScannerPlugin,
  ScannerImport,
  FileResolver,
  ResolvedSource,
  ExpandToolsContext,
} from "./scanner-plugins/types.js";
export { findPackageJsonPaths, detectAgentRoots } from "./monorepo-detect.js";
export type { AgentRoot } from "./monorepo-detect.js";
export { RemoteEnforcementError, RemoteContractError, isEnforcementDecision } from "./remote-enforce.js";
export type { FallbackMode, RemoteStatus, RemoteConfig, RemoteFallbackInfo } from "./remote-enforce.js";
export { composePolicies, securityBaseline, complianceOverlay, platformDefaults } from "./policy-compose.js";
export type { PolicySet, ConflictStrategy, ComposeConfig, ComposeResult, PolicyConflict } from "./policy-compose.js";
export { getDefaultStage } from "./policy-stage-defaults.js";
export { inputBlocklist, inputLength, inputPattern, networkAllowlist, scopeBoundary, costBudget, concurrentLimit, outputLength, outputPattern, sensitiveDataFilter, maskSensitiveOutput, maskOutputPattern } from "./policy-presets-extended.js";
export { mlInjectionGuard } from "./policy-presets.js";
export { runWithOutcome } from "./action-recorder.js";
export type { RunWithOutcomeOptions } from "./action-recorder.js";
export { scanToolResult, extractScannableText } from "./tool-result-scan.js";
export type { ScanToolResultInput, ScanToolResultOutput, BlockedToolResult } from "./tool-result-scan.js";
export { SENSITIVE_PATTERNS, getSensitivePatterns } from "./conditions/sensitive-patterns.js";
export type { SensitivePattern } from "./conditions/sensitive-patterns.js";
export { maskSensitiveData, maskPattern, maskBlocklistTerms } from "./mask.js";
