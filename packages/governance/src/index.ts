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

import { createGovernanceKernel } from "@governance-sdk/core/governance.js";
import type { GovernanceConfig, GovernanceInstance } from "@governance-sdk/core/governance.js";
import { defaultExtensions } from "@governance-sdk/plugins/ext/defaults.js";

/**
 * Create a governance instance.
 *
 * The kernel plus the default extension set — injection detection,
 * sensitive-data masking and the 7-dimension posture scorer — so every
 * built-in condition, and `register()`'s score, behave as documented without
 * the caller knowing the plugin contract exists.
 *
 * Pass `extensions` to replace the defaults, or `extensions: {}` to run a bare
 * kernel. Both are honest: asking for a kernel without the piece that
 * implements a condition gets you a rule that is rejected when added, a mask
 * with no strategy that fails closed to `block`, and — with no scorer — a
 * `register()` that returns a level-0 assessment marked unscored while
 * `score()` and `scoreFleet()` throw rather than invent a number.
 */
export function createGovernance(config: GovernanceConfig = {}): GovernanceInstance {
  return createGovernanceKernel({ ...config, extensions: config.extensions ?? defaultExtensions() });
}

export { createGovernanceKernel, storedToRegistration, CORE_VERSION } from "@governance-sdk/core/governance.js";
export type {
  GovernanceConfig,
  GovernanceInstance,
  ReadonlyPolicyEngine,
  ActionOutcome,
  KernelExtensions,
  KernelScoring,
  KernelScoringDeps,
} from "@governance-sdk/core/governance.js";
export { NoScorerError, unscoredAssessment, NO_SCORER_LEVEL } from "@governance-sdk/core/governance.js";
export { defaultExtensions } from "@governance-sdk/plugins/ext/defaults.js";
export { createPolicyEngine } from "./policy-entry.js";

// Storage types and the memory adapter — other modules import these from the
// barrel, so it stays the one place they resolve from.
export type { GovernanceStorage, StoredAgent, AuditEvent, AuditOutcome, AuditQueryFilters } from "@governance-sdk/core/storage.js";
export { createMemoryStorage } from "@governance-sdk/core/storage.js";

// ─── Re-exports ─────────────────────────────────────────────────

export { assessAgent, assessFleet, getGovernanceLevel } from "@governance-sdk/plugins/scorer.js";
export { blockTools, allowOnlyTools, requireApproval, requireToolApproval, requireTierApproval, blockTaintedTools, toolResultInjectionGuard, tokenBudget, rateLimit, requireLevel, requireSignedIdentity, requireSequence, timeWindow, MAX_USER_PRIORITY, SYSTEM_RULE_PRIORITY, PolicyValidationError, validateRuleShape, POLICY_OUTCOMES, POLICY_STAGES, markTaint, hasTaint, appendTaint } from "@governance-sdk/core/policy.js";
export type { PolicyRule, PolicyEngine, PolicyAction, PolicyCondition, PolicyOutcome, PolicyStage, ActionTier, EnforcementContext, EnforcementDecision, PolicyEngineConfig, ConditionEvaluator, RegisteredConditionType, PolicyValidationIssue, TaintMark, TaintSource, TaintFilter } from "@governance-sdk/core/policy.js";
export { createAuditChain, resolveOrgId } from "@governance-sdk/core/audit-chain.js";
export type { AuditChain, AuditChainDeps, ResolvedIntegrityConfig } from "@governance-sdk/core/audit-chain.js";
export { createScoringHooks, scoringExtension } from "@governance-sdk/plugins/ext/scoring-hooks.js";
export type { ScoringHooks } from "@governance-sdk/plugins/ext/scoring-hooks.js";
export { createSessionLedger } from "@governance-sdk/core/session-ledger.js";

// ─── Plugins (ext) ──────────────────────────────────────────────
// Standards, scoring and detection reached through gov.use(). Additive: the
// direct exports (mapToEuAiAct, assessAgent, detectInjection) are unchanged.
export {
  euAiActPlugin,
  owaspAgenticPlugin,
  nistAiRmfPlugin,
  iso42001Plugin,
  allStandardsPlugins,
} from "@governance-sdk/plugins/ext/standards-plugin.js";
export { scoringPlugin } from "@governance-sdk/plugins/ext/scoring-plugin.js";
export type {
  AgentScoreConfig,
  FleetScoreConfig,
  BehavioralScoreConfig,
  ScoringPluginOptions,
} from "@governance-sdk/plugins/ext/scoring-plugin.js";
export { detectPlugin } from "@governance-sdk/plugins/ext/detect-plugin.js";
export type { DetectPluginOptions, BenchmarkReportConfig } from "@governance-sdk/plugins/ext/detect-plugin.js";
export { createPluginRegistry, satisfiesRange, PluginError } from "@governance-sdk/core/plugin.js";
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
  VerifierRegistry,
  VerifierOf,
  PluginRegistry,
} from "@governance-sdk/core/plugin.js";
export type { SessionLedger, SessionLedgerConfig, SessionSnapshot } from "@governance-sdk/core/session-ledger.js";
export type { AgentRegistration, AgentFramework, AgentStatus, GovernanceAssessment, GovernanceLevel, DimensionResult, ScoreDimension, FleetSummary } from "@governance-sdk/core/types.js";
export { detectInjection, createInjectionGuard, getBuiltinPatterns } from "@governance-sdk/plugins/injection-detect.js";
export type { InjectionPattern, InjectionCategory, InjectionResult, InjectionDetectorConfig } from "@governance-sdk/plugins/injection-detect.js";
export { createGovernanceEmitter } from "@governance-sdk/core/events.js";
export { dryRun, fleetDryRun } from "@governance-sdk/plugins/dry-run.js";
export type { DryRunScenario, DryRunAction, DryRunResult, DryRunDecision, DryRunSummary, DryRunConfig, FleetDryRunResult } from "@governance-sdk/plugins/dry-run.js";
export { createGovernanceMetrics } from "@governance-sdk/core/metrics.js";
export type { GovernanceMetrics, MetricName, TimingName, MetricLabels, MetricsSnapshot } from "@governance-sdk/core/metrics.js";
export type { GovernanceEmitter, GovernanceEvent, GovernanceEventType, GovernanceEventHandler } from "@governance-sdk/core/events.js";
export { computeSignals, computeBehavioralAdjustments, applyBehavioralAdjustments } from "@governance-sdk/plugins/behavioral-scorer.js";
export type { BehavioralInput, BehavioralAdjustment, BehavioralAssessment, BehavioralSignals } from "@governance-sdk/plugins/behavioral-scorer.js";
export { scanRepoContents, scanRepoContentsWithPlugins, SCAN_GLOBS, SCAN_IGNORE } from "@governance-sdk/plugins/repo-patterns.js";
export type { CapabilityDetection, RepoScanResult, ScanWithPluginsOptions } from "@governance-sdk/plugins/repo-patterns.js";
export type {
  ScannerPlugin,
  ScannerImport,
  FileResolver,
  ResolvedSource,
  ExpandToolsContext,
} from "@governance-sdk/plugins/scanner-plugins/types.js";
export { findPackageJsonPaths, detectAgentRoots } from "@governance-sdk/plugins/monorepo-detect.js";
export type { AgentRoot } from "@governance-sdk/plugins/monorepo-detect.js";
export { RemoteEnforcementError, RemoteContractError, isEnforcementDecision } from "@governance-sdk/core/remote-enforce.js";
export type { FallbackMode, RemoteStatus, RemoteConfig, RemoteFallbackInfo } from "@governance-sdk/core/remote-enforce.js";
export { composePolicies, securityBaseline, complianceOverlay, platformDefaults } from "@governance-sdk/plugins/policy-compose.js";
export type { PolicySet, ConflictStrategy, ComposeConfig, ComposeResult, PolicyConflict } from "@governance-sdk/plugins/policy-compose.js";
export { getDefaultStage } from "@governance-sdk/core/policy-stage-defaults.js";
export { inputBlocklist, inputLength, inputPattern, networkAllowlist, scopeBoundary, costBudget, concurrentLimit, outputLength, outputPattern, sensitiveDataFilter, maskSensitiveOutput, maskOutputPattern } from "@governance-sdk/core/policy-presets-extended.js";
export { mlInjectionGuard } from "@governance-sdk/core/policy-presets.js";
export { runWithOutcome } from "@governance-sdk/core/action-recorder.js";
export type { RunWithOutcomeOptions } from "@governance-sdk/core/action-recorder.js";
export { scanToolResult, extractScannableText } from "@governance-sdk/adapters/plugins/tool-result-scan.js";
export type { ScanToolResultInput, ScanToolResultOutput, BlockedToolResult } from "@governance-sdk/adapters/plugins/tool-result-scan.js";
export { SENSITIVE_PATTERNS, getSensitivePatterns } from "@governance-sdk/plugins/conditions/sensitive-patterns.js";
export type { SensitivePattern } from "@governance-sdk/plugins/conditions/sensitive-patterns.js";
export { maskSensitiveData, maskPattern, maskBlocklistTerms } from "@governance-sdk/plugins/mask.js";

// Type of `gov.failModes()`; was a root export in 0.22.0.
export type { FailModes } from "@governance-sdk/core/governance.js";
