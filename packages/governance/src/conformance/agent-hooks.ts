/**
 * Agent Hooks conformance.
 *
 * Agent Hooks (Microsoft, 27 August 2026) is an open, framework-neutral
 * governance contract: eight interception points, three verdicts. It is the
 * closest thing the category has to a standard, and conforming to it means any
 * runtime that speaks it can use this SDK without a bespoke adapter — which is
 * a better outcome than competing with the contract.
 *
 * The mapping is deliberate, and two parts of it are lossy in ways worth
 * stating rather than hiding:
 *
 *   | Agent Hooks point | SDK stage / call                                  |
 *   |-------------------|---------------------------------------------------|
 *   | startup           | `register()`                                      |
 *   | input             | `enforcePreprocess()`                             |
 *   | preModel          | `enforcePreprocess()` (same stage, prompt text)   |
 *   | postModel         | `enforcePostprocess()`                            |
 *   | preTool           | `enforce()` at the `process` stage                |
 *   | postTool          | `scanToolResult()` at the `tool_result` stage     |
 *   | output            | `enforcePostprocess()` (final text to the user)   |
 *   | shutdown          | flush the session ledger, write a closing event   |
 *
 *   | SDK outcome        | Agent Hooks verdict                              |
 *   |--------------------|--------------------------------------------------|
 *   | allow              | allow                                            |
 *   | warn               | allow, with `annotations` carrying the reason    |
 *   | mask               | transform, with the redacted payload             |
 *   | block              | deny                                             |
 *   | require_approval   | deny, with `approval` metadata for the caller    |
 *
 * The lossy parts: Agent Hooks has no third state between allow and deny, so
 * `require_approval` arrives as a deny that the host is expected to turn into
 * a prompt — the approval id and poll URL ride along in `approval` so it can.
 * And `warn` is an allow, so a host that ignores `annotations` silently loses
 * the warning; that is a property of the contract, not of this mapping.
 */

import type { GovernanceInstance } from "../governance.js";
import type { EnforcementDecision, PolicyStage } from "../policy.js";
import { attachAdapterCore, type AdapterCoreConfig, type AdapterCore } from "../plugins/adapter-core.js";
import { buildRegistration } from "../plugins/adapter-core.js";

/** The three verdicts an Agent Hooks implementation may return. */
export type HookVerdict = "allow" | "deny" | "transform";

/** The eight interception points. */
export type HookPoint =
  | "startup"
  | "input"
  | "preModel"
  | "postModel"
  | "preTool"
  | "postTool"
  | "output"
  | "shutdown";

export const HOOK_POINTS: readonly HookPoint[] = [
  "startup",
  "input",
  "preModel",
  "postModel",
  "preTool",
  "postTool",
  "output",
  "shutdown",
];

/** What every hook returns. */
export interface HookResult<Payload = unknown> {
  verdict: HookVerdict;
  /** Why, for deny and for an allow carrying a warning. */
  reason?: string;
  /** The replacement payload when `verdict` is "transform". */
  payload?: Payload;
  /** Non-fatal notes — a `warn` outcome arrives here. */
  annotations?: string[];
  /** Present when a deny is really "a human must approve this first". */
  approval?: { id: string; pollUrl?: string };
  /** The underlying SDK decision, for hosts that want the detail. */
  decision?: EnforcementDecision;
}

export interface AgentHooksAdapter {
  readonly agentId: string;
  startup(): Promise<HookResult>;
  input(text: string): Promise<HookResult<string>>;
  preModel(text: string): Promise<HookResult<string>>;
  postModel(text: string): Promise<HookResult<string>>;
  preTool(tool: string, args?: Record<string, unknown>): Promise<HookResult>;
  postTool(tool: string, result: unknown, args?: Record<string, unknown>): Promise<HookResult>;
  output(text: string): Promise<HookResult<string>>;
  shutdown(): Promise<HookResult>;
  /** Which points this adapter implements — all eight. */
  readonly points: readonly HookPoint[];
}

/** Translate an SDK decision into an Agent Hooks verdict. */
export function toVerdict(decision: EnforcementDecision, payload?: string): HookResult<string> {
  const base = { decision, ...(decision.reason ? { reason: decision.reason } : {}) };
  switch (decision.outcome) {
    case "block":
      return { ...base, verdict: "deny" };
    case "require_approval":
      return {
        ...base,
        verdict: "deny",
        ...(decision.approvalId
          ? { approval: { id: decision.approvalId, ...(decision.approval?.pollUrl ? { pollUrl: decision.approval.pollUrl } : {}) } }
          : {}),
      };
    case "mask":
      // A mask that produced no redaction has already been turned into a
      // block by the engine, so `maskedText` is present whenever we get here.
      return { ...base, verdict: "transform", payload: decision.maskedText ?? payload };
    case "warn":
      return { ...base, verdict: "allow", annotations: [decision.reason] };
    default:
      return { decision, verdict: "allow" };
  }
}

export interface AgentHooksConfig extends AdapterCoreConfig {
  /** Emit a closing audit event on `shutdown()`. Default true. */
  auditShutdown?: boolean;
}

/**
 * Expose a governance instance through the Agent Hooks contract.
 *
 * Registers on construction, so `startup()` is a report of what registration
 * produced rather than a second registration.
 */
export async function createAgentHooksAdapter(
  governance: GovernanceInstance,
  config: AgentHooksConfig,
): Promise<AgentHooksAdapter> {
  const registered = await governance.register(
    buildRegistration(config, [], config.framework ?? "custom"),
  );
  const core: AdapterCore = attachAdapterCore(governance, config, {
    agentId: registered.id,
    agentLevel: registered.level,
    score: registered.score,
  });

  async function textStage(stage: PolicyStage, text: string): Promise<HookResult<string>> {
    const decision = await core.enforceStage(stage, {
      action: "message_send",
      ...(stage === "postprocess" ? { outputText: text } : { inputText: text, input: { message: text } }),
    });
    return toVerdict(decision, text);
  }

  return {
    agentId: core.agentId,
    points: HOOK_POINTS,

    async startup() {
      return {
        verdict: "allow",
        decision: undefined,
        annotations: [`registered ${core.agentId} at level ${core.agentLevel} (score ${core.score})`],
      };
    },

    input: (text) => textStage("preprocess", text),
    // Same stage as `input`: the SDK draws its boundary at "before the model
    // sees it", and both points are on that side of it.
    preModel: (text) => textStage("preprocess", text),
    postModel: (text) => textStage("postprocess", text),
    output: (text) => textStage("postprocess", text),

    async preTool(tool, args) {
      // enforce() here rather than core.enforce(), because Agent Hooks wants a
      // verdict returned, not an exception thrown.
      const decision = await governance.enforce(core.context({ tool, input: args }));
      return toVerdict(decision);
    },

    async postTool(tool, result, args) {
      const scan = await core.scanResult({ tool, result, ...(args ? { args } : {}) });
      const verdict = toVerdict(scan.decision);
      // The scanner already substituted a redacted or blocked payload; hand
      // the host the value it should actually use.
      if (verdict.verdict !== "allow") {
        return { ...verdict, payload: scan.result } as HookResult;
      }
      return verdict as HookResult;
    },

    async shutdown() {
      const annotations: string[] = [];
      const ledger = governance.ledger;
      if (ledger) {
        const snapshot = ledger.snapshot(ledger.keyFor(core.context({})));
        if (snapshot) {
          annotations.push(
            `session: ${snapshot.actionTimestamps.length} action(s), ${snapshot.tokensUsed} token(s), cost ${snapshot.cost}`,
          );
        }
      }
      if (config.auditShutdown !== false) {
        await governance.audit.log({
          agentId: core.agentId,
          eventType: "agent_shutdown",
          outcome: "success",
          severity: "info",
          detail: { annotations },
        });
      }
      return { verdict: "allow", annotations };
    },
  };
}
