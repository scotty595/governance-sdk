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
import { createGovernance, blockTools, requireLevel } from "../index";
import type { GovernanceInstance } from "../index";
import type { PolicyRule } from "../policy";
import { GovernanceBlockedError } from "./outcome-handler";
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

type Outcome = "allowed" | "blocked";

interface AdapterRun {
  /** Governance level the adapter's registration produced */
  level: number;
  /** What happened when the wrapped tool was invoked */
  outcome: Outcome;
}

type AdapterCall = (gov: GovernanceInstance, tool: string) => Promise<AdapterRun>;

/**
 * Identical registration input for every adapter — only the framework
 * wrapper differs. `framework: "custom"` keeps the scorer's per-framework
 * bonuses out of the comparison. Scores level 3 with the current scorer.
 */
const AGENT = {
  agentName: "parity-agent",
  owner: "parity-team",
  framework: "custom" as const,
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
    throw err;
  }
}

const mcpHandler: MCPToolCallHandler = async () => ({ content: [{ type: "text", text: "ok" }] });

const adapters: Record<string, AdapterCall> = {
  "vercel-ai": async (gov, tool) => {
    const { tools, level } = await createGovernedTools(gov, {
      [tool]: { description: tool, inputSchema: {}, execute: async () => "ok" },
    }, AGENT);
    return { level, outcome: await outcomeOf(() => tools[tool].execute!({}, { toolCallId: "c1", messages: [] })) };
  },
  anthropic: async (gov, tool) => {
    const { tools, level } = await governAnthropicTools(gov, [
      { name: tool, description: tool, inputSchema: {}, execute: async () => "ok" },
    ], AGENT);
    return { level, outcome: await outcomeOf(() => tools[0].execute({})) };
  },
  bedrock: async (gov, tool) => {
    const { guardToolUse, level } = await createGovernedBedrock(gov, async () => ({}), AGENT);
    return { level, outcome: await outcomeOf(() => guardToolUse({ toolUseId: "t1", name: tool, input: {} })) };
  },
  genkit: async (gov, tool) => {
    const { tools, level } = await governGenkitTools(gov, [
      { name: tool, description: tool, call: async () => "ok" },
    ], AGENT);
    return { level, outcome: await outcomeOf(() => tools[0].call({})) };
  },
  langchain: async (gov, tool) => {
    const { tools, level } = await governLangChainTools(gov, [
      { name: tool, description: tool, invoke: async () => "ok" },
    ], AGENT);
    return { level, outcome: await outcomeOf(() => tools[0].invoke({})) };
  },
  llamaindex: async (gov, tool) => {
    const { tools, level } = await governLlamaIndexTools(gov, [
      { metadata: { name: tool, description: tool }, call: async () => "ok" },
    ], AGENT);
    return { level, outcome: await outcomeOf(() => tools[0].call!({})) };
  },
  mcp: async (gov, tool) => {
    const { handleToolCall, level } = await createGovernedMCP(gov, mcpHandler, AGENT);
    return {
      level,
      outcome: await outcomeOf(() => handleToolCall({ method: "tools/call", params: { name: tool, arguments: {} } })),
    };
  },
  mistral: async (gov, tool) => {
    const { tools, level } = await governMistralTools(gov, [
      { name: tool, description: tool, execute: async () => "ok" },
    ], AGENT);
    return { level, outcome: await outcomeOf(() => tools[0].execute({})) };
  },
  ollama: async (gov, tool) => {
    const { tools, level } = await governOllamaTools(gov, [
      { name: tool, description: tool, execute: async () => "ok" },
    ], AGENT);
    return { level, outcome: await outcomeOf(() => tools[0].execute({})) };
  },
  "openai-agents": async (gov, tool) => {
    const { tools, level } = await governOpenAITools(gov, [
      { type: "function", name: tool, description: tool, execute: async () => "ok" },
    ], AGENT);
    return { level, outcome: await outcomeOf(() => tools[0].execute!({})) };
  },
};

/** Run one tool call through every adapter, each on a fresh governance instance. */
async function runAll(rules: PolicyRule[], tool: string): Promise<Record<string, AdapterRun>> {
  const results: Record<string, AdapterRun> = {};
  for (const [name, call] of Object.entries(adapters)) {
    results[name] = await call(createGovernance({ rules }), tool);
  }
  return results;
}

function assertParity(results: Record<string, AdapterRun>, expected: Outcome): void {
  const reference = results["vercel-ai"];
  assert.equal(reference.outcome, expected, "vercel-ai reference outcome");
  for (const [name, run] of Object.entries(results)) {
    assert.equal(
      run.outcome, reference.outcome,
      `${name} disagreed with vercel-ai (${run.outcome} vs ${reference.outcome}): ${JSON.stringify(results)}`,
    );
    assert.equal(
      run.level, reference.level,
      `${name} registered at level ${run.level}, vercel-ai at ${reference.level}`,
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
});
