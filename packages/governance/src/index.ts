/**
 * governance-sdk — the package barrel.
 *
 * This is the meta-package: it re-exports the kernel, the adapters and the
 * extensions under one name, and it is the only place that wires the default
 * extension set onto the kernel. Everything a caller imported before the
 * kernel/plugin split still resolves from here, unchanged.
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

import { createGovernanceKernel } from "./governance.js";
import type { GovernanceConfig, GovernanceInstance } from "./governance.js";
import { defaultExtensions } from "./ext/defaults.js";

/**
 * Create a governance instance.
 *
 * The kernel plus the default extension set — injection detection and
 * sensitive-data masking — so every built-in condition behaves as documented
 * without the caller knowing the plugin contract exists.
 *
 * Pass `extensions` to replace the defaults, or `extensions: {}` to run a bare
 * kernel. Both are honest: asking for a kernel without the piece that
 * implements a condition gets you a rule that is rejected when added, and a
 * mask with no strategy that fails closed to `block`.
 */
export function createGovernance(config: GovernanceConfig = {}): GovernanceInstance {
  return createGovernanceKernel({ ...config, extensions: config.extensions ?? defaultExtensions() });
}

export { createGovernanceKernel, storedToRegistration, CORE_VERSION } from "./governance.js";
export type {
  GovernanceConfig,
  GovernanceInstance,
  ReadonlyPolicyEngine,
  ActionOutcome,
  KernelExtensions,
} from "./governance.js";
export { defaultExtensions } from "./ext/defaults.js";
export { createPolicyEngine } from "./policy-entry.js";

// Storage types and the memory adapter — other modules import these from the
// barrel, so it stays the one place they resolve from.
export type { GovernanceStorage, StoredAgent, AuditEvent, AuditOutcome, AuditQueryFilters } from "./storage.js";
export { createMemoryStorage } from "./storage.js";

// ─── Re-exports ─────────────────────────────────────────────────

export { assessAgent, assessFleet, getGovernanceLevel } from "./scorer.js";
export { blockTools, allowOnlyTools, requireApproval, requireToolApproval, requireTierApproval, blockTaintedTools, toolResultInjectionGuard, tokenBudget, rateLimit, requireLevel, requireSignedIdentity, requireSequence, timeWindow, MAX_USER_PRIORITY, SYSTEM_RULE_PRIORITY, PolicyValidationError, validateRuleShape, POLICY_OUTCOMES, POLICY_STAGES, markTaint, hasTaint, appendTaint } from "./policy.js";
export type { PolicyRule, PolicyEngine, PolicyAction, PolicyCondition, PolicyOutcome, PolicyStage, ActionTier, EnforcementContext, EnforcementDecision, PolicyEngineConfig, ConditionEvaluator, RegisteredConditionType, PolicyValidationIssue, TaintMark, TaintSource, TaintFilter } from "./policy.js";
export { createAuditChain, resolveOrgId } from "./audit-chain.js";
export type { AuditChain, AuditChainDeps, ResolvedIntegrityConfig } from "./audit-chain.js";
export { createScoringHooks } from "./scoring-hooks.js";
export type { ScoringHooks } from "./scoring-hooks.js";
export { createSessionLedger } from "./session-ledger.js";

// ─── Plugins (ext) ──────────────────────────────────────────────
// Standards, scoring and detection reached through gov.use(). Additive: the
// direct exports (mapToEuAiAct, assessAgent, detectInjection) are unchanged.
export {
  euAiActPlugin,
  owaspAgenticPlugin,
  nistAiRmfPlugin,
  iso42001Plugin,
  allStandardsPlugins,
} from "./ext/standards-plugin.js";
export { scoringPlugin } from "./ext/scoring-plugin.js";
export type {
  AgentScoreConfig,
  FleetScoreConfig,
  BehavioralScoreConfig,
  ScoringPluginOptions,
} from "./ext/scoring-plugin.js";
export { detectPlugin } from "./ext/detect-plugin.js";
export type { DetectPluginOptions, BenchmarkReportConfig } from "./ext/detect-plugin.js";
export { createPluginRegistry, satisfiesRange, PluginError } from "./plugin.js";
export type {
  GovernancePlugin,
  KernelHandle,
  Disposer,
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
