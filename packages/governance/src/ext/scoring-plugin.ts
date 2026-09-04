/**
 * Posture and behavioural scoring, as a plugin.
 *
 * A score is only comparable across runs that used the same weights, which is
 * why the weight set gets its own version rather than riding the kernel's.
 * The plugin adds nothing to the scoring model: `assessAgent`, `assessFleet`,
 * `computeSignals` and `computeBehavioralAdjustments` keep working exactly as
 * they do today, and the reporters here call straight into them.
 *
 * The behavioural reporter is the reason this plugin wants `events`. It
 * subscribes to `enforcement` and keeps a bounded, in-memory mirror of the
 * decisions it sees, so `gov.report("scoring/behavioral", …)` can answer from
 * live traffic without the plugin ever reaching into storage — which the
 * `KernelHandle` deliberately does not expose.
 */

import type { GovernancePlugin, KernelHandle } from "../plugin.js";
import type { GovernanceEvent } from "../events.js";
import type { AgentRegistration } from "../types.js";
import type { AuditEvent, AuditOutcome } from "../storage.js";
import { POLICY_OUTCOMES } from "../policy.js";
import { assessAgent, assessFleet } from "../scorer.js";
import {
  computeBehavioralAdjustments,
  type BehavioralAssessment,
  type BehavioralConfig,
} from "../behavioral-scorer.js";

/**
 * Weight-set revision: the dimension weights in `scorer-dimensions.ts` plus
 * the level thresholds in `scorer.ts`. Bump it when either moves, so a
 * deployment cannot silently start comparing scores from two weightings.
 */
const WEIGHT_SET_REVISION = "1.0.0";

/** Enforcement decisions kept per agent when `maxEventsPerAgent` is unset. */
const DEFAULT_EVENT_CAP = 500;

const AUDIT_OUTCOMES = new Set<string>([...POLICY_OUTCOMES, "success", "failure", "kill_switch"]);

// ─── Reporter configs ───────────────────────────────────────────

/** Config for the `"scoring/agent"` reporter — the args `assessAgent` takes. */
export interface AgentScoreConfig {
  agentId: string;
  registration: AgentRegistration;
}

/** Config for the `"scoring/fleet"` reporter — the arg `assessFleet` takes. */
export interface FleetScoreConfig {
  agents: { id: string; registration: AgentRegistration }[];
}

/** Config for the `"scoring/behavioral"` reporter. */
export interface BehavioralScoreConfig {
  /** Which agent's observed enforcement decisions to score. */
  agentId: string;
  /** Tools the agent declared at registration; drives the drift signal. */
  declaredTools?: string[];
  /** Per-call tuning, overriding the plugin's own `behavioral` defaults. */
  config?: BehavioralConfig;
}

export interface ScoringPluginOptions {
  /** Default tuning for the behavioural reporter. */
  behavioral?: BehavioralConfig;
  /** Cap on the per-agent decision mirror. Default 500. */
  maxEventsPerAgent?: number;
}

// ─── Event mirror ───────────────────────────────────────────────

function isAuditOutcome(value: unknown): value is AuditOutcome {
  return typeof value === "string" && AUDIT_OUTCOMES.has(value);
}

/**
 * Mirror an `enforcement` event in the `AuditEvent` shape `computeSignals()`
 * already reads, matching the event the instance writes to storage for the
 * same decision: `policy_evaluation`, the outcome, and the rule id in both
 * `detail.ruleId` and `policyRuleId`. The id is synthetic and local — this
 * mirror never reaches storage, and the handle hands plugins events, not the
 * audit table.
 */
function toAuditEvent(event: GovernanceEvent, agentId: string, seq: number): AuditEvent {
  const detail = event.detail;
  const ruleId = typeof detail.ruleId === "string" ? detail.ruleId : undefined;
  return {
    id: `scoring-mirror-${seq}`,
    agentId,
    eventType: "policy_evaluation",
    outcome: isAuditOutcome(detail.outcome) ? detail.outcome : "failure",
    severity: detail.blocked === true ? "warning" : "info",
    detail: {
      action: detail.action,
      tool: detail.tool,
      ruleId,
      reason: detail.reason,
      stage: detail.stage,
    },
    ...(ruleId ? { policyRuleId: ruleId } : {}),
    createdAt: event.timestamp,
  };
}

function reporterConfig<Config>(id: string, config: unknown): Config {
  if (config === null || typeof config !== "object") {
    throw new TypeError(
      `Reporter "${id}" expects a config object, got ${config === null ? "null" : typeof config}`,
    );
  }
  return config as Config;
}

// ─── Plugin ─────────────────────────────────────────────────────

/**
 * Register the posture scorer (`"scoring/agent"`, `"scoring/fleet"`) and the
 * behavioural scorer (`"scoring/behavioral"`) as reports.
 */
export function scoringPlugin(opts: ScoringPluginOptions = {}): GovernancePlugin {
  const cap = opts.maxEventsPerAgent ?? DEFAULT_EVENT_CAP;
  const observed = new Map<string, AuditEvent[]>();
  let seq = 0;
  let detach: (() => void) | undefined;

  function onEnforcement(event: GovernanceEvent): void {
    const agentId = event.agentId;
    if (!agentId) return;
    const events = observed.get(agentId) ?? [];
    events.push(toAuditEvent(event, agentId, ++seq));
    // Bounded: a long-lived process must not accumulate a decision per call.
    if (events.length > cap) events.splice(0, events.length - cap);
    observed.set(agentId, events);
  }

  return {
    id: "scoring/posture",
    version: WEIGHT_SET_REVISION,
    requires: { core: "^0.22.0", capabilities: ["reporters", "events"] },

    install(kernel: KernelHandle): void {
      kernel.registerReporter("scoring/agent", (config) => {
        const c = reporterConfig<AgentScoreConfig>("scoring/agent", config);
        return assessAgent(c.agentId, c.registration);
      });

      kernel.registerReporter("scoring/fleet", (config) => {
        const c = reporterConfig<FleetScoreConfig>("scoring/fleet", config);
        return assessFleet(c.agents);
      });

      kernel.registerReporter("scoring/behavioral", (config): BehavioralAssessment => {
        const c = reporterConfig<BehavioralScoreConfig>("scoring/behavioral", config);
        return computeBehavioralAdjustments({
          events: observed.get(c.agentId) ?? [],
          declaredTools: c.declaredTools ?? [],
          config: c.config ?? opts.behavioral,
        });
      });

      kernel.events.on("enforcement", onEnforcement);
      detach = () => kernel.events.off("enforcement", onEnforcement);
    },

    uninstall(): void {
      detach?.();
      detach = undefined;
      observed.clear();
    },
  };
}
