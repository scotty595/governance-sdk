/**
 * Taint marks — provenance for untrusted content.
 *
 * Detection is telemetry; provenance is a control. Once an agent has
 * ingested external content (a tool result, a retrieved document, an MCP
 * tool description, another agent's message) every argument it later passes
 * to a tool may be derived from that content. The design-pattern literature
 * on prompt injection (CaMeL; Beurer-Kellner et al. 2025) converges on one
 * rule: untrusted-derived data must not reach consequential actions without
 * a deterministic check outside the model.
 *
 * A `TaintMark` records that a source of untrusted content entered the
 * session. Adapters attach the session's marks to `EnforcementContext.taint`
 * on subsequent tool calls; the `tainted_input` condition and the
 * `blockTaintedTools()` preset turn that into policy. Marks are coarse by
 * design — they say "external content has been seen since this run began,"
 * not "this argument byte came from that document." Byte-level information
 * flow is a model-architecture problem, not an SDK one.
 *
 * The source vocabulary mirrors the attack-vector axis of the Agent
 * Governance Benchmark taxonomy (research/governance-benchmark).
 */

export type TaintSource =
  | "user_input"
  | "tool_result"
  | "retrieved_context"
  | "mcp_metadata"
  | "agent_message"
  | "memory_state"
  | "downstream_output"
  | "structured_data";

export interface TaintMark {
  source: TaintSource;
  /** Tool (or server / agent) the content came from, when known. */
  tool?: string;
  /** ISO timestamp the content was ingested. */
  at: string;
  /** True when a detector flagged the content as a probable injection. */
  suspicious?: boolean;
  /** Detector score (0–1) if one ran. */
  score?: number;
  detail?: Record<string, unknown>;
}

export interface TaintFilter {
  /** Only count marks from these sources. Default: any source. */
  sources?: TaintSource[];
  /** Only count marks a detector flagged. Default: any mark counts. */
  suspiciousOnly?: boolean;
}

/** Build a mark for content ingested now. */
export function markTaint(
  source: TaintSource,
  opts: { tool?: string; suspicious?: boolean; score?: number; detail?: Record<string, unknown>; at?: string } = {},
): TaintMark {
  return {
    source,
    ...(opts.tool !== undefined ? { tool: opts.tool } : {}),
    at: opts.at ?? new Date().toISOString(),
    ...(opts.suspicious !== undefined ? { suspicious: opts.suspicious } : {}),
    ...(opts.score !== undefined ? { score: opts.score } : {}),
    ...(opts.detail !== undefined ? { detail: opts.detail } : {}),
  };
}

/** True when any mark in `taint` passes the filter. */
export function hasTaint(taint: readonly TaintMark[] | undefined, filter: TaintFilter = {}): boolean {
  if (!taint || taint.length === 0) return false;
  return taint.some((m) => {
    if (filter.sources && !filter.sources.includes(m.source)) return false;
    if (filter.suspiciousOnly && m.suspicious !== true) return false;
    return true;
  });
}

/** Append a mark, capping the list so a long session cannot grow unbounded. */
export function appendTaint(
  taint: readonly TaintMark[] | undefined,
  mark: TaintMark,
  max = 200,
): TaintMark[] {
  const next = taint ? [...taint, mark] : [mark];
  return next.length > max ? next.slice(next.length - max) : next;
}
