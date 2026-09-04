/**
 * governance-sdk Anthropic — messages.create wrapper (pre/post)
 *
 * The Anthropic SDK has no native middleware hook, so we wrap
 * `client.messages.create`:
 *
 *   - pre  → scan the last user message block before sending
 *   - post → scan the assistant response content[] after receiving
 *
 * Returns a drop-in replacement for `client.messages.create`. Users keep
 * their existing call site; governance is applied transparently.
 *
 * @example
 * ```ts
 * import Anthropic from '@anthropic-ai/sdk';
 * import { createGovernance } from 'governance-sdk';
 * import { createGovernedMessages } from 'governance-sdk/plugins/anthropic';
 *
 * const client = new Anthropic();
 * const gov = createGovernance({ rules: [] });
 * const { id: agentId } = await gov.register({
 *   name: 'assistant', framework: 'anthropic', owner: 'team',
 * });
 *
 * const messages = createGovernedMessages(client.messages, gov, { agentId });
 * const res = await messages.create({
 *   model: 'claude-sonnet-4-5', max_tokens: 1024,
 *   messages: [{ role: 'user', content: 'hi' }],
 * });
 * ```
 */

import type { GovernanceInstance } from "../index";
import type { OutcomeCallbacks } from "./outcome-handler.js";
import { enforcePreprocess, enforcePostprocess } from "./pre-post-enforce.js";
import { extractLastText, partsToText, replaceContentText, replaceLastText } from "./text-extract.js";

// ─── Types ──────────────────────────────────────────────────────

/** Minimal shape of an Anthropic messages client (SDK-version-agnostic). */
export interface AnthropicMessagesClient {
  create: (params: AnthropicMessagesCreateParams) => Promise<AnthropicMessage>;
}

export interface AnthropicMessagesCreateParams {
  model: string;
  max_tokens: number;
  messages: Array<{ role: "user" | "assistant"; content: unknown }>;
  system?: unknown;
  [key: string]: unknown;
}

export interface AnthropicMessage {
  id?: string;
  role?: string;
  content?: Array<{ type: string; text?: string; [k: string]: unknown }>;
  usage?: { input_tokens?: number; output_tokens?: number; [k: string]: unknown };
  [key: string]: unknown;
}

export interface AnthropicMessagesConfig extends OutcomeCallbacks {
  /**
   * Bring-your-own agent id. This wrapper never calls `gov.register()`;
   * pass the `id` returned by your own registration (or a tool adapter's
   * `agentId`) so enforcement and audit bind to that agent row.
   */
  agentId: string;
  agentName?: string;
  /**
   * Governance level for `agent_level` rules such as `requireLevel()`. Pass
   * the `level` returned by `gov.register()`; when omitted the engine
   * treats the agent as level 0 and `requireLevel(1+)` blocks every call.
   */
  agentLevel?: number;
  /** Disable pre-scan (default: enabled). */
  preprocess?: boolean;
  /** Disable post-scan (default: enabled). */
  postprocess?: boolean;
  metadata?: Record<string, unknown>;
  sessionTokenTracker?: () => number;
}

// ─── Main Export ────────────────────────────────────────────────

export function createGovernedMessages(
  messages: AnthropicMessagesClient,
  governance: GovernanceInstance,
  config: AnthropicMessagesConfig,
): AnthropicMessagesClient {
  const callbacks: OutcomeCallbacks = config;
  const runPre = config.preprocess ?? true;
  const runPost = config.postprocess ?? true;

  return {
    create: async (params) => {
      let workingParams = params;

      if (runPre) {
        const text = extractLastText(params.messages);
        if (text) {
          const pre = await enforcePreprocess(governance, text, {
            agentId: config.agentId,
            agentName: config.agentName,
            agentLevel: config.agentLevel,
            metadata: config.metadata,
            sessionTokensUsed: config.sessionTokenTracker?.(),
            callbacks,
            toolName: "anthropic.messages.create:pre",
          });
          if (pre.text !== text) {
            workingParams = {
              ...params,
              messages: replaceLastText(params.messages, pre.text),
            };
          }
        }
      }

      const response = await messages.create(workingParams);

      if (!runPost) return response;
      const outText = extractAssistantText(response);
      if (!outText) return response;

      const post = await enforcePostprocess(governance, outText, {
        agentId: config.agentId,
        agentName: config.agentName,
        agentLevel: config.agentLevel,
        metadata: config.metadata,
        outputTokenCount: response.usage?.output_tokens,
        sessionTokensUsed: config.sessionTokenTracker?.(),
        callbacks,
        toolName: "anthropic.messages.create:post",
      });

      if (post.text === outText) return response;
      return replaceAssistantText(response, post.text);
    },
  };
}

// ─── Helpers ────────────────────────────────────────────────────
// Message text extraction and shape-preserving replacement live in
// text-extract.ts; only the assistant-response shape is Anthropic's own.

function extractAssistantText(message: AnthropicMessage): string {
  if (!Array.isArray(message.content)) return "";
  return partsToText(message.content);
}

function replaceAssistantText(
  message: AnthropicMessage,
  newText: string,
): AnthropicMessage {
  if (!Array.isArray(message.content)) return message;
  const content = replaceContentText(message.content, newText);
  return { ...message, content: content as AnthropicMessage["content"] };
}
