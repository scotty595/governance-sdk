# Threat model

What the SDK defends, against whom, and where the boundary sits. Read with
[guarantees.md](./guarantees.md), which lists what is asserted by tests.

## System under consideration

An application written in TypeScript runs one or more AI agents. Each agent
receives prompts, calls a model, and invokes tools (functions in the same
process, MCP servers, HTTP APIs, shell commands). The SDK is embedded in that
process and is consulted at four points:

| Stage | What is examined | Typical attacker goal |
|---|---|---|
| `preprocess` | the user prompt before the model sees it | direct prompt injection, jailbreak, oversized input |
| `process` | a tool call the model has decided to make, before it executes | tool misuse, privilege abuse, budget exhaustion, acting on injected instructions |
| `tool_result` | what a tool returned, before the model ingests it | indirect injection via web pages, files, MCP results, other agents; secret leakage into context |
| `postprocess` | the model's output before the user sees it | data exfiltration, PII leakage |

The SDK produces a decision (`allow`, `block`, `warn`, `require_approval`,
`mask`), records it, and optionally hash-chains the record.

## Trust boundaries

**Trusted:** the application code that constructs the governance instance and
calls `enforce()`; the process memory; the policy rules the operator loads;
the storage adapter and its database; the signing key (with the caveats
below).

**Untrusted:** user prompts; every tool result; retrieved documents; MCP tool
descriptions and server responses; messages from other agents; anything in
long-term memory that was derived from the above; policy files loaded from
disk or a network (they are validated but their author is trusted only to the
extent your deployment trusts them); the remote governance API's responses
(shape-validated, treated as a transport failure when malformed).

**The model is not a security boundary.** Anything the model has read can
influence what it does next. The SDK's job is to make sure that influence
cannot reach consequential actions without a deterministic check outside the
model.

## Adversaries

1. **Remote content author.** Controls a web page, document, email, repository
   issue, MCP server response or another agent's output that the agent will
   read. Goal: make the agent call a tool with attacker-chosen arguments
   (exfiltrate data, send email, run commands), or corrupt the agent's memory.
   This is the adversary behind every documented 2025–2026 incident class:
   GitHub MCP exfiltration, Supabase and Asana MCP leaks, EchoLeak,
   ForcedLeak, Cursor and Copilot injection to RCE, malicious MCP servers.
2. **Direct user.** Sends prompts designed to bypass instructions or extract
   the system prompt. Lower severity than (1) because the user is usually
   authenticated and accountable.
3. **Malicious or compromised tool / MCP server.** Returns poisoned content,
   changes its tool description after approval (rug pull), or exfiltrates
   arguments it receives.
4. **Insider or compromised operator.** Has the database and wants to alter
   the audit record; may or may not hold the HMAC signing key.
5. **Denial of service.** Any of the above supplying input that makes the
   governance layer itself slow or crash, so that operators turn it off.
6. **Rogue or runaway agent.** Not malicious but wrong: loops, spends,
   deletes. The Replit production-database deletion is the canonical case.

## Controls, mapped to adversaries

| Control | Adversaries addressed | Notes |
|---|---|---|
| Deterministic tool-call policy (`blockTools`, `allowOnlyTools`, `requireToolApproval`, `scopeBoundary`, `networkAllowlist`) | 1, 2, 3, 6 | Runs outside the model. Evaluated before the tool executes. |
| Consequence tiers (`actionTier`, `requireTierApproval`) | 1, 6 | Irreversible and external actions require a person regardless of how the model was persuaded. Matches EU AI Act Art 14, MAS SAFR and the three-tier model in China's agent rules. |
| Provenance / taint (`taint`, `blockTaintedTools`) | 1, 3 | Once the session has ingested untrusted content, consequential tools need approval. This is the CaMeL / design-pattern control: it does not need to *detect* the injection to stop its effect. Marks are coarse (per source, per run), deliberately. |
| Tool-result scanning (`scanToolResult`, `toolResultInjectionGuard`) | 1, 3 | Telemetry that raises the taint mark's `suspicious` flag and can block obvious payloads. Not a sufficient control on its own. |
| Prompt pre-scan (`createInjectionGuard`) | 2 | Regex, high precision, low recall, English only. Telemetry. |
| Output post-scan and masking (`maskSensitiveOutput`, `outputPattern`) | 1, 2 | Reduces exfiltration through the reply channel. Mask fails closed. |
| Session ledger (`rateLimit`, `tokenBudget`, `costBudget`) | 5, 6 | Bounds runaway loops and spend per process. |
| Kill switch (system rules) | 6, and incident response for 1–3 | Every stage, local precedence over the remote API, not removable via the public rule API. Per process. |
| Rule validation at add time | operator error | A typo cannot become a rule that silently fails open. |
| Bounded regex cost | 5 | Every built-in pattern is tested against pathological inputs under a time budget. |
| HMAC-chained audit | 4 (without the key) | Edits, interior deletions, reordering and forged inserts are detectable offline. |
| Identity (Ed25519 tokens, `requireSignedIdentity`) | 3, impersonation | Audience, issuer, replay and rotation checks available; host performs the vault lookup. |
| Explicit fail modes (`failModes()`, `strict`) | operator error | The deployment knows which way each subsystem fails. |

## What is explicitly not defended

- **Prompt injection as such.** The SDK cannot make a model immune to
  instructions in its context. It makes the *consequences* controllable.
  Detection numbers are published so nobody mistakes the detector for a gate.
- **Tail truncation of the audit chain**, and **rewriting by a holder of the
  signing key.** Anchor the head externally; rotate the key.
- **Fleet-wide state.** Kill switch, ledger and taint are per process. Sharing
  them is the host's or a control plane's job.
- **Attacker-supplied code running in the process.** The SDK is not a sandbox.
- **Tools the SDK cannot see.** Bedrock action groups execute inside AWS; MCP
  servers you *consume* are governed at the agent-framework layer, not by the
  MCP server adapter (which governs servers you *publish*).
- **Argument-level information flow.** Taint marks say "external content has
  been seen since this run began," not "this byte came from that document."
  Byte-level flow tracking belongs in the model architecture (CaMeL-style
  dual-model designs), not in an SDK.

## Assumptions the controls rely on

- The adapter is actually on the path. A tool called outside the adapter, or
  a framework hook the adapter does not implement, is ungoverned. The Mastra
  processor's `processToolResult`, Vercel's `needsApproval`, OpenAI's tool
  guardrails and Claude's `PreToolUse` are the hooks the adapters bind to.
- Tools are mapped to tiers. An unmapped tool carries no tier and is not
  gated by `requireTierApproval()`; mapping is an operator responsibility.
- Policy files come from a trusted author. Validation stops malformed rules;
  it cannot stop a correctly formed rule that allows too much.
- The process is not compromised. If it is, the kill switch and ledger are
  attacker-controlled too.

## Reporting

Security issues: see [SECURITY.md](../SECURITY.md). Injection-detection
bypasses, audit-chain integrity issues, policy-enforcement bypasses and
kill-switch circumvention are in scope. Detector false positives and
negatives on ordinary text are bugs, not vulnerabilities.
