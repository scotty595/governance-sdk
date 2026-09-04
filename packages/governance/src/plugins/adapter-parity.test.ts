/**
 * Cross-adapter parity.
 *
 * The same policy set, applied to the same agent registration and the same
 * tool call, must yield the same outcome no matter which framework adapter
 * carries it. This guards against adapters drifting in how they build the
 * EnforcementContext — e.g. nine adapters once hard-coded `agentLevel: 0`,
 * so `requireLevel(1)` blocked every tool call through them while the Vercel
 * path (which passed the real level) allowed it.
 *
 * The Vercel `createGovernedTools` path is the reference; every other adapter
 * must agree with it.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createGovernance,
  blockTools,
  blockTaintedTools,
  requireLevel,
  requireTierApproval,
} from "../index";
import type { GovernanceInstance } from "../index";
import type { EnforcementDecision, PolicyRule } from "../policy";
import { GovernanceApprovalRequiredError, GovernanceBlockedError } from "./outcome-handler";
import { governAnthropicTools } from "./anthropic";
import { createGovernedBedrock } from "./bedrock";
import { governGenkitTools } from "./genkit";
import { governTools as governLangChainTools } from "./langchain";
import { governLlamaIndexTools } from "./llamaindex";
import { createGovernedMCP } from "./mcp";
import type { MCPToolCallHandler } from "./mcp";
import { governMistralTools } from "./mistral";
import { governOllamaTools } from "./ollama";
import { governTools as governOpenAITools } from "./openai-agents";
import { createGovernedTools } from "./vercel-ai";

// ─── Fixtures ───────────────────────────────────────────────

type Outcome = "allowed" | "blocked" | "approval";

interface AdapterRun {
  /** Governance level the adapter's registration produced */
  level: number;
  /** What happened when the wrapped tool was invoked */
  outcome: Outcome;
}

/** One wrapped adapter, ready to have its tool invoked (possibly repeatedly). */
interface AdapterHandle {
  level: number;
  invoke: () => Promise<unknown>;
}

/**
 * Config every adapter receives. Passed as a variable, never as an inline
 * literal, so TypeScript's excess-property check does not reject the
 * cross-adapter fields on an adapter whose config type has not yet been
 * widened to `AdapterConfig` (Anthropic's).
 */
interface ParityConfig {
  agentName: string;
  owner: string;
  framework: "custom";
  hasAuth: boolean;
  hasGuardrails: boolean;
  hasObservability: boolean;
  metadata: Record<string, unknown>;
  toolTiers?: Record<string, "read_only" | "reversible" | "external" | "irreversible">;
  onBlocked?: (decision: EnforcementDecision, toolName: string) => void;
}

type AdapterFactory = (
  gov: GovernanceInstance,
  tool: string,
  config: ParityConfig,
) => Promise<AdapterHandle>;

/**
 * Identical registration input for every adapter — only the framework
 * wrapper differs. `framework: "custom"` keeps the scorer's per-framework
 * bonuses out of the comparison. Scores level 3 with the current scorer.
 */
const AGENT: ParityConfig = {
  agentName: "parity-agent",
  owner: "parity-team",
  framework: "custom",
  hasAuth: true,
  hasGuardrails: true,
  hasObservability: true,
  metadata: { suite: "adapter-parity" },
};

async function outcomeOf(run: () => Promise<unknown>): Promise<Outcome> {
  try {
    await run();
    return "allowed";
  } catch (err) {
    if (err instanceof GovernanceBlockedError) return "blocked";
    if (err instanceof GovernanceApprovalRequiredError) return "approval";
    throw err;
  }
}

const mcpHandler: MCPToolCallHandler = async () => ({ content: [{ type: "text", text: "ok" }] });

const adapters: Record<string, AdapterFactory> = {
  "vercel-ai": async (gov, tool, config) => {
    const { tools, level } = await createGovernedTools(gov, {
      [tool]: { description: tool, inputSchema: {}, execute: async () => "ok" },
    }, config);
    return { level, invoke: () => tools[tool].execute!({}, { toolCallId: "c1", messages: [] }) };
  },
  anthropic: async (gov, tool, config) => {
    const { tools, level } = await governAnthropicTools(gov, [
      { name: tool, description: tool, inputSchema: {}, execute: async () => "ok" },
    ], config);
    return { level, invoke: () => tools[0].execute({}) };
  },
  bedrock: async (gov, tool, config) => {
    const { guardToolUse, level } = await createGovernedBedrock(gov, async () => ({}), config);
    return { level, invoke: () => guardToolUse({ toolUseId: "t1", name: tool, input: {} }) };
  },
  genkit: async (gov, tool, config) => {
    const { tools, level } = await governGenkitTools(gov, [
      { name: tool, description: tool, call: async () => "ok" },
    ], config);
    return { level, invoke: () => tools[0].call({}) };
  },
  langchain: async (gov, tool, config) => {
    const { tools, level } = await governLangChainTools(gov, [
      { name: tool, description: tool, invoke: async () => "ok" },
    ], config);
    return { level, invoke: () => tools[0].invoke({}) };
  },
  llamaindex: async (gov, tool, config) => {
    const { tools, level } = await governLlamaIndexTools(gov, [
      { metadata: { name: tool, description: tool }, call: async () => "ok" },
    ], config);
    return { level, invoke: () => tools[0].call!({}) };
  },
  mcp: async (gov, tool, config) => {
    const { handleToolCall, level } = await createGovernedMCP(gov, mcpHandler, config);
    return {
      level,
      invoke: () => handleToolCall({ method: "tools/call", params: { name: tool, arguments: {} } }),
    };
  },
  mistral: async (gov, tool, config) => {
    const { tools, level } = await governMistralTools(gov, [
      { name: tool, description: tool, execute: async () => "ok" },
    ], config);
    return { level, invoke: () => tools[0].execute({}) };
  },
  ollama: async (gov, tool, config) => {
    const { tools, level } = await governOllamaTools(gov, [
      { name: tool, description: tool, execute: async () => "ok" },
    ], config);
    return { level, invoke: () => tools[0].execute({}) };
  },
  "openai-agents": async (gov, tool, config) => {
    const { tools, level } = await governOpenAITools(gov, [
      { type: "function", name: tool, description: tool, execute: async () => "ok" },
    ], config);
    return { level, invoke: () => tools[0].execute!({}) };
  },
};

/** Adapters with a `tool_result` stage — the only ones that accrue taint. */
const RESULT_SCANNING = ["genkit", "langchain", "llamaindex", "mcp", "openai-agents"] as const;

/** Run one tool call through every adapter, each on a fresh governance instance. */
async function runAll(
  rules: PolicyRule[],
  tool: string,
  config: ParityConfig = AGENT,
  names: readonly string[] = Object.keys(adapters),
): Promise<Record<string, AdapterRun>> {
  const results: Record<string, AdapterRun> = {};
  for (const name of names) {
    const handle = await adapters[name](createGovernance({ rules }), tool, config);
    results[name] = { level: handle.level, outcome: await outcomeOf(handle.invoke) };
  }
  return results;
}

function assertParity(
  results: Record<string, AdapterRun>,
  expected: Outcome,
  reference = "vercel-ai",
): void {
  const ref = results[reference];
  assert.equal(ref.outcome, expected, `${reference} reference outcome`);
  for (const [name, run] of Object.entries(results)) {
    assert.equal(
      run.outcome, ref.outcome,
      `${name} disagreed with ${reference} (${run.outcome} vs ${ref.outcome}): ${JSON.stringify(results)}`,
    );
    assert.equal(
      run.level, ref.level,
      `${name} registered at level ${run.level}, ${reference} at ${ref.level}`,
    );
  }
}

// ─── Tests ──────────────────────────────────────────────────

describe("adapter parity — same policy, same agent, same outcome on every adapter", () => {
  const rules = [blockTools(["shell_exec"]), requireLevel(1)];

  it("blockTools + requireLevel(1): a benign tool call is ALLOWED on every adapter", async () => {
    const results = await runAll(rules, "web_search");
    assert.ok(results["vercel-ai"].level >= 1, `fixture must score level >= 1, got ${results["vercel-ai"].level}`);
    assertParity(results, "allowed");
  });

  it("blockTools + requireLevel(1): the listed tool is BLOCKED on every adapter", async () => {
    assertParity(await runAll(rules, "shell_exec"), "blocked");
  });

  it("requireLevel above the agent's real level BLOCKS on every adapter (the level itself flows through)", async () => {
    const results = await runAll([requireLevel(4)], "web_search");
    assert.ok(results["vercel-ai"].level < 4, `fixture must score below level 4, got ${results["vercel-ai"].level}`);
    assertParity(results, "blocked");
  });

  it("the onBlocked callback fires on every adapter (each one wires its config into the core)", async () => {
    for (const name of Object.keys(adapters)) {
      const seen: string[] = [];
      const config: ParityConfig = {
        ...AGENT,
        onBlocked: (_decision, toolName) => { seen.push(toolName); },
      };
      const handle = await adapters[name](
        createGovernance({ rules: [blockTools(["shell_exec"])] }), "shell_exec", config,
      );
      assert.equal(await outcomeOf(handle.invoke), "blocked", `${name} did not block`);
      assert.deepEqual(seen, ["shell_exec"], `${name} did not fire onBlocked exactly once`);
    }
  });
});

// ─── Consequence tiers ──────────────────────────────────────

describe("adapter parity — config.toolTiers feeds ctx.actionTier on every adapter", () => {
  const rules = [requireTierApproval(["irreversible"])];

  it("a tool mapped to an irreversible tier REQUIRES APPROVAL on every adapter", async () => {
    const config: ParityConfig = { ...AGENT, toolTiers: { delete_account: "irreversible" } };
    assertParity(await runAll(rules, "delete_account", config), "approval");
  });

  it("an unmapped tool never matches a tier rule on any adapter", async () => {
    const config: ParityConfig = { ...AGENT, toolTiers: { delete_account: "irreversible" } };
    assertParity(await runAll(rules, "web_search", config), "allowed");
  });

  it("without toolTiers the same rule is inert on every adapter", async () => {
    assertParity(await runAll(rules, "delete_account"), "allowed");
  });
});

// ─── Provenance (taint) ─────────────────────────────────────

describe("adapter parity — blockTaintedTools sees the core's session taint", () => {
  const rules = [blockTaintedTools(["send_email"], { outcome: "block" })];

  it("with nothing ingested the rule is inert on every adapter", async () => {
    assertParity(await runAll(rules, "send_email"), "allowed");
  });

  // The core records a taint mark on every `scanResult()`, so the second call
  // through the same adapter instance carries `ctx.taint` and the rule fires.
  // Only adapters with a `tool_result` stage reach that state — the rest
  // (Vercel AI, Anthropic, Bedrock, Mistral, Ollama) expose no hook where a
  // tool return passes through governance, so `trackTaint` is inert for them
  // however the core is configured: an adapter-surface gap, not a
  // context-assembly one.
  it("after one tool result is ingested, every result-scanning adapter BLOCKS the next call", async () => {
    const results: Record<string, AdapterRun> = {};
    for (const name of RESULT_SCANNING) {
      const handle = await adapters[name](createGovernance({ rules }), "send_email", AGENT);
      // First call: no marks yet, so it runs and its result is scanned.
      assert.equal(await outcomeOf(handle.invoke), "allowed", `${name} blocked the first call`);
      results[name] = { level: handle.level, outcome: await outcomeOf(handle.invoke) };
    }
    assertParity(results, "blocked", "genkit");
  });

  it("trackTaint: false keeps the same adapters allowing the second call", async () => {
    const config = { ...AGENT, trackTaint: false };
    for (const name of RESULT_SCANNING) {
      const handle = await adapters[name](createGovernance({ rules }), "send_email", config);
      assert.equal(await outcomeOf(handle.invoke), "allowed", `${name} blocked the first call`);
      assert.equal(await outcomeOf(handle.invoke), "allowed", `${name} tracked taint when told not to`);
    }
  });
});
