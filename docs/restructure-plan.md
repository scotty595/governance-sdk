# Restructure plan: kernel and plugins

Status: **plan, not started.** This document closes the hardening roadmap and
opens the next one. Nothing here changes behaviour; it changes where code
lives, how it is versioned, and what the SDK promises to keep stable.

## Why

The September 2026 review and the hardening work that followed made the
shape of the problem clear:

- The package is 23k lines. About 3.4k of them (enforce, policy engine,
  conditions, audit chain, storage contract, events) are the product. The
  rest is adapters (16k lines, 71 percent), detectors, scorers and standards
  mappings that change on other people's schedules.
- The adapters had already diverged: nine of them hard-coded `agentLevel: 0`,
  so one policy gave different answers on different frameworks. That class of
  bug is structural, not accidental, as long as each adapter re-declares the
  same scaffold (nine copies of `createEnforcer` and `createAuditor`, eight of
  `buildRegistration`, six each of the text extractors).
- The four standards mappings revise on four external clocks. OWASP is annual.
  The EU moved a date by sixteen months with one regulation. ISO 27090 and
  27091 publish this year. Coupling those to the core's semver means a core
  release for a date change, or a stale core.
- Every acquired detector library eventually stopped shipping (LLM Guard,
  Rebuff, Vigil). The detector must be swappable without touching the kernel.
- Microsoft's Agent Hooks (27 Aug 2026) and OWASP's Agent Control Standard
  (announced 1 Sep 2026) define a governance kernel as *interception points ×
  verdicts* and nothing else. Conforming to them is easiest when the kernel is
  exactly that small.

The maintainer's own instinct, that the SDK does too much, is right about the
package and the README and wrong about the kernel. The plan shrinks the
former and protects the latter.

## Target shape

One repository, one npm scope, four publishable units. Not twenty packages:
a solo maintainer cannot hold a twenty-way version matrix and users hate it.

```
packages/
  core/          @scope/core          the kernel — semver-stable
  adapters/      @scope/adapters      every framework adapter, one adapter kernel, subpath exports
  plugins/       @scope/plugins       detection, standards, scoring, identity, sinks, policy backends
  governance-sdk/ governance-sdk      compatibility meta-package re-exporting today's paths
  governance-platform/               unchanged
```

`governance-sdk` (the existing name) keeps working unchanged for at least two
minor releases after the split: every current subpath re-exports from the new
packages with a deprecation note in the `.d.ts`. Nobody's imports break on
the day of the split.

### What is in the kernel

| Stays | Why it is kernel |
|---|---|
| `createGovernance`, `enforce`, `enforcePreprocess/ToolResult/Postprocess`, `register`, `recordOutcome`, `audit.*` | the contract every adapter and plugin calls |
| Policy engine, condition registry, rule validation, the structural built-ins (`tool_*`, `action_type`, `action_tier`, `tainted_input`, `agent_level`, `tool_sequence`, `time_window`, `rate_limit`, `token_limit`, `cost_budget`, `concurrent_limit`, `network_allowlist`, `scope_boundary`, combinators) | deterministic, dependency-free, define the verdict semantics |
| The five verdicts, system rules, the priority clamp, decision detail and remedies | the guarantees in `docs/guarantees.md` |
| Audit chain: canonicalisation, HMAC, per-org heads, verifier | the differentiator |
| Storage contract + memory adapter; session ledger; taint and tier types | state the kernel itself needs |
| Typed event emitter and metrics | the plugin bus |
| `gov.use(plugin)` and the plugin lifecycle (below) | how everything else attaches |

Target: under 4,000 lines including validation and remedies. `index.ts`
splits into `governance.ts` (instance), `audit-chain.ts` (writeAudit and
export), `scoring-hooks.ts` (the behavioural re-score), `fail-modes.ts`.

### What becomes a plugin

| Moves | Package | Own version field | Notes |
|---|---|---|---|
| Injection detection, normalisation, classifier interface, sensitive patterns, mask helpers | `@scope/plugins/detect` | pattern-set revision | registers `injection_guard`, `ml_injection_guard`, `sensitive_data_filter`, `blocklist`, `input_pattern`, `output_pattern` conditions and the mask strategies |
| Benchmark runner | `research/` | n/a | not a production export |
| EU AI Act, OWASP ASI, NIST AI RMF (+600-1), ISO 42001, later CSA AICM, IMDA, MCP Top 10 | `@scope/plugins/standards/<name>` | standard + revision year | pure functions over governance state; each carries `sourceUrls` |
| Posture scorer, behavioural scorer | `@scope/plugins/scoring` | weight-set revision | subscribes to `enforcement` events |
| Ed25519 identity, HMAC identity (deprecated), replay store, future JWT/SPIFFE verifiers | `@scope/plugins/identity` | | registers `require_signed_identity` |
| Supply chain: CycloneDX SBOM, repo-patterns, monorepo detect, MCP trust registry | `@scope/plugins/supply-chain` | | |
| Postgres adapter, OTel exporter, webhook sink, anchor sink | `@scope/plugins/sinks/*` | | storage adapters are sinks with a read side |
| YAML loader, fluent builder, compose, Cedar and OPA bridges | `@scope/plugins/policy/*` | | |
| Kill switch, dry-run simulator | `@scope/plugins/ops` | | kill switch uses `addSystemRule` |

### What is cut or folded

- `plugins/mastra` (middleware): the processor supersedes it; keep one Mastra
  path. Deprecate for two minors, then remove.
- `mcp-call-recorder` and `mcp-chain-audit` as separate exports: fold into
  one MCP plugin.
- `token-types` (Lua-internal JWT shapes) and `scanner-plugins` as public
  subpaths: internal.
- `agent-identity` (HMAC): already deprecated; removal at the split's second
  minor.
- `injection-benchmark` as a production export: moves to `research/`.
- The `connect` CLI command as shipped: it assumes one vendor's API; replace
  with a generic contract check against `docs/remote-contract.md`.

## The plugin contract

```ts
export interface GovernancePlugin {
  /** Stable id, e.g. "standards/owasp-asi", "detect/regex", "sinks/otel". */
  id: string;
  /** Plugin's own version (for standards: the revision it implements). */
  version: string;
  /** What the plugin needs from the kernel; the kernel refuses to load it otherwise. */
  requires?: { core: string; capabilities?: KernelCapability[] };
  /** Called once from gov.use(); receives a scoped handle, not the whole instance. */
  install(kernel: KernelHandle): void | Promise<void>;
  /** Optional teardown. */
  uninstall?(): void | Promise<void>;
}

export interface KernelHandle {
  registerCondition(entry: RegisteredConditionType): void;
  registerMaskStrategy(conditionType: string, mask: (text, params) => string): void;
  registerVerifier(kind: "identity" | "remote-decision", verifier: unknown): void;
  events: GovernanceEmitter;               // subscribe
  audit: { log: GovernanceInstance["audit"]["log"] };
  addSink(sink: AuditSink): void;          // receives every audit event after the chain write
  failModes(): FailModes;
}
```

Rules of the contract:

- Plugins register; they do not reach into the instance. Anything a plugin
  needs that is not on `KernelHandle` is a kernel feature request.
- The kernel never imports a plugin. A lint rule enforces it (below).
- `gov.use()` is idempotent per plugin id and rejects a plugin whose
  `requires.core` range the kernel does not satisfy.
- Conditions registered by plugins are validated like built-ins; a rule that
  names a plugin condition before the plugin is installed is rejected at add
  time, exactly as today for unregistered types.

## The adapter kernel

One shared module replaces the nine copies:

```ts
export function createAdapterCore(gov: GovernanceInstance, config: AdapterConfig): AdapterCore;

interface AdapterCore {
  ready(): Promise<{ agentId: string; agentLevel: number }>;   // registers once, stable id honoured
  context(partial: Partial<EnforcementContext>): EnforcementContext; // fills agent fields, tier, taint, extracted targets
  enforce(stage: PolicyStage | undefined, partial): Promise<EnforcementDecision>;
  scanResult(input: Omit<ScanToolResultInput, "governance" | "agentId" | "agentLevel">): Promise<ScanToolResultOutput>;
  runWithOutcome<T>(partial, fn: () => Promise<T>): Promise<T>;
  handle(decision, callbacks): void;     // outcome-handler
  taint: { marks(): TaintMark[]; record(mark): void; reset(): void }; // per-run provenance keyed by the framework's run id
  text: { fromMessages, fromParts, replaceLast };  // the six duplicated extractors, once
}
```

Each adapter becomes a thin mapping from framework hook → `core.enforce(stage,
…)`, plus framework-specific stream plumbing where the framework has its own
stream part types. Target: each adapter under 200 lines. The parity test
becomes a required check for every adapter in the package.

Adapter tiers after the split:

| Tier | Adapters | Commitment |
|---|---|---|
| Maintained | Mastra processor, Vercel AI SDK, OpenAI Agents JS, MCP, **Claude Agent SDK (new)**, **Cloudflare Agents (new)** | parity test in CI, tracked against framework releases |
| Community | LangChain JS, Anthropic SDK, Genkit, LlamaIndex TS, Mistral, Ollama, Bedrock | parity test in CI, no proactive tracking; flagged in docs |

## Conformance targets

- **Agent Hooks** (Microsoft, 27 Aug 2026): eight interception points
  (startup, input, pre-model, post-model, pre-tool, post-tool, output,
  shutdown) with allow / deny / transform verdicts. Mapping: `preprocess` →
  input + pre-model; `process` → pre-tool; `tool_result` → post-tool;
  `postprocess` → post-model + output; `register` → startup; a new
  `shutdown` hook for ledger flush and final audit. Verdicts: `allow` →
  allow; `block` and `require_approval` → deny (with reason and approval
  metadata); `mask` → transform; `warn` → allow with annotation. The
  conformance suite runs in CI once the kernel exposes the eight points.
- **OWASP Agent Control Standard** (announced 1 Sep 2026): track the draft;
  map when text is published. The kernel already matches its framing (policy
  outside the model, before the action).

## Layering rule

A lint step (a small script over `import` statements, no new dependency)
fails CI when:

- anything under `packages/core/src` imports from `adapters/` or `plugins/`;
- anything under `packages/adapters/src` imports from `plugins/` other than
  `detect` (adapters need `scanToolResult`) — and that import goes through
  the kernel's registered condition, not a direct call, by the end of phase 3;
- anything under `packages/plugins/src` imports from `adapters/`.

This single rule is what stops the kernel from silently re-growing.

## Migration path

### Phase A — in-place (no import changes) · 2–3 weeks

1. Add `gov.use()` and `KernelHandle` to the current package. Port the
   standards mappings, scoring and detection to register through it, inside
   the same package. Root exports keep working.
2. Extract `createAdapterCore` and port Mastra, Vercel, OpenAI Agents and MCP.
   Delete their scaffold copies. Keep the parity test green throughout.
3. Split `index.ts` into the four files named above.
4. Add the layering lint over the current `src/` tree (paths, not packages).
5. Turn on `noUncheckedIndexedAccess` (161 errors at the time of writing,
   almost all in adapters and the YAML parser) and `exactOptionalPropertyTypes`
   while the adapter scaffold is being replaced anyway. `noUnusedLocals` is
   already on.

Exit criteria: all tests green, `governance-sdk` public API unchanged,
kernel files under 4k lines, no adapter over 250 lines among the four ported.

### Phase B — packages · 2 weeks

5. Create `packages/core`, `packages/adapters`, `packages/plugins`; move files;
   turn `packages/governance` into the meta-package with re-exports and
   deprecation JSDoc on every subpath.
6. Publish nothing yet (publishing is deferred by decision). CI builds and
   tests all packages; the meta-package's tests import from the new packages.
7. Port the remaining adapters to the adapter core; mark tiers in docs.

Exit criteria: `npm test` at the root runs every package; the meta-package
re-exports pass the existing test suite unchanged.

### Phase C — new surface · 2 weeks

8. Claude Agent SDK and Cloudflare Agents adapters on the adapter core.
9. Agent Hooks conformance mapping and suite in CI.
10. Standards plugins for NIST AI 600-1, CSA AICM v1.1 and IMDA agentic
    pillars, each with a `revision` field and `sourceUrls`.
11. Identity verifiers for externally issued JWT (Entra, Okta, Auth0) and
    SPIFFE SVIDs; delegation claims (`actor`, `principal`) carried into audit
    events.

### Deprecation timeline

| Item | Deprecated at | Removed at |
|---|---|---|
| `governance-sdk/plugins/mastra` (middleware) | split | split + 2 minors |
| `governance-sdk/agent-identity` (HMAC) | now (0.22) | split + 2 minors |
| `governance-sdk/token-types`, `scanner-plugins` subpaths | split | split + 2 minors |
| `governance-sdk/injection-benchmark` | split | split + 1 minor (moves to `research/`) |
| `mlInjectionScore` alias | now (0.22) | 1.0 |
| Every `governance-sdk/*` subpath (meta-package) | split | not before 1.0; re-exports stay |

## Risks

- **Two active repos, one package name.** Until the Lua question is settled,
  the split should be done on this fork's `main` without publishing. The
  meta-package design means the eventual publish is additive.
- **Version matrix.** Four packages is the ceiling. If a fifth seems needed,
  it is a subpath of one of the four.
- **Adapter regressions during port.** The parity test and each adapter's
  existing tests run on every commit; port one adapter per PR.
- **Plugin contract churn.** Keep `KernelHandle` deliberately small; add
  capabilities only when a second plugin needs them.
- **Standards plugins going stale.** Each carries `revision` and
  `sourceUrls`; a quarterly check is a calendar entry, not code.

## Acceptance criteria for the restructure as a whole

- `packages/core` under 4k lines, zero runtime deps, zero imports from
  adapters or plugins (lint-enforced).
- Every adapter passes the parity test; maintained-tier adapters under 200
  lines each.
- `governance-sdk` meta-package: today's full test suite passes against the
  re-exports with no test changes.
- Standards plugins each declare `standard`, `revision`, `sourceUrls`; the EU
  AI Act plugin computes deadlines from data, not constants.
- Agent Hooks conformance suite green in CI.
- `docs/guarantees.md` unchanged in substance: the restructure moves code, it
  does not weaken a single guarantee.

## Estimated effort

Roughly six to seven weeks of focused work for one person, sequenced as the
three phases above, each landing as a series of small PRs. Phase A can start
immediately and is the highest-value part: it removes the duplication that
produced the `agentLevel: 0` bug class and puts the plugin seam in place
before any package moves.
