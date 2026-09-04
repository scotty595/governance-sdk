# Guarantees and non-guarantees

This page is the procurement answer. Every claim below is either enforced by
code and covered by a test, or stated as a limit. If a sentence here and a
sentence in the README disagree, this page wins and the README has a bug.

Version: applies to the `main` branch after the 0.22 hardening work. Each
guarantee names the test file that asserts it.

## Policy evaluation

| Guarantee | Enforced by | Asserted in |
|---|---|---|
| A rule is validated when it is added. A misspelled outcome or stage, a non-finite priority, an unregistered condition type, an uncompilable regex or a malformed nested condition is rejected with `PolicyValidationError` at `createGovernance()`, `addRule()`, `createPolicyEngine()` and `fromYAML()`. | `policy-validate.ts` | `policy-validate.test.ts` |
| User rules cannot hold priority above 998. There is no id-prefix or other opt-out. | `policy.ts` (`clampPriority`) | `policy-system-rules.test.ts` |
| System rules (the kill switch) are installed only through `addSystemRule()`, evaluate at every stage, and cannot be replaced or removed through `addRule()` / `removeRule()`. | `policy.ts` (`systemIds`) | `policy-system-rules.test.ts` |
| A `mask` rule that cannot produce redacted text degrades to `block`. The engine never returns the original text under a `mask` label. The decision carries `degradedFrom: "mask"`. | `policy.ts` (`buildDecision`) | `policy-decision-detail.test.ts`, `policy.test.ts` |
| Every non-allow decision names the stage, the condition type and, for built-in conditions, a one-line remedy. | `policy-remedies.ts` | `policy-decision-detail.test.ts` |
| First match wins. Rules are evaluated in descending priority; ties keep insertion order. No combination of outcomes. | `policy.ts` | `policy.test.ts` |

## Plugins and conformance

| Guarantee | Enforced by | Asserted in |
|---|---|---|
| `gov.use()` is idempotent per plugin id, and refuses a second version of an installed id rather than silently keeping either. | `plugin.ts` | `plugin.test.ts` |
| A plugin whose `requires.core` range this kernel does not satisfy, or that requires a capability the kernel lacks, is refused at install time. | `plugin.ts` | `plugin.test.ts` |
| A plugin receives a `KernelHandle` with five registration verbs, the event stream, an audit writer and `failModes()` — never the instance, its storage or its rules. Every register verb returns a disposer, and `unuse()` rolls a plugin back in full, including restoring a built-in condition it overrode. | `plugin.ts` | `plugin.test.ts` |
| A condition a plugin registers is validated exactly like a built-in, so a rule naming it before the plugin is installed is rejected when the rule is added. | `policy-validate.ts` | `plugin.test.ts` |
| `getVerifier(kind)` is typed through `VerifierRegistry`, which the registering plugin augments; the kernel never imports a plugin's types, and a host that has not imported the plugin sees `unknown`. | `plugin.ts`, `ext/identity-plugin.ts` | `tsc -b` (compile-time) |
| An audit sink receives every event after it is written and chained. A sink that throws or rejects is routed to `onAuditError` and cannot change a decision. | `governance.ts`, `audit-chain.ts` | `plugin.test.ts` |
| A `mask` rule on a condition with no registered mask strategy still fails closed to `block`. | `policy.ts` | `plugin.test.ts` |
| All eight Agent Hooks interception points are implemented, and every SDK outcome maps to a defined verdict. | `conformance/agent-hooks.ts` | `conformance/agent-hooks.test.ts` |
| `preTool` returns a deny verdict rather than throwing; `postTool` hands back the substituted payload, never the original poisoned value. | `conformance/agent-hooks.ts` | `conformance/agent-hooks.test.ts` |

Not guaranteed, and stated in the mapping itself: Agent Hooks has no state
between allow and deny, so `require_approval` arrives as a deny carrying its
approval id and poll URL, and `warn` arrives as an allow carrying an
annotation. A host that ignores annotations loses the warning. That is a
property of the contract, not of this implementation.

## Layering

The SDK is four packages, and the layering rule is a build constraint rather
than a convention.

| Guarantee | Enforced by | Asserted in |
|---|---|---|
| `@governance-sdk/core` declares no dependencies and imports none. It contains no detector, no pattern corpus, no standards mapping and no scoring model; those reach it as kernel extensions or plugins. | `packages/core/package.json`, `tsc -b` project references | `scripts/check-layering.mjs` in `npm run lint` |
| Every cross-package import is declared in that package's `dependencies`, so nothing resolves only because npm hoisted it. | `scripts/check-layering.mjs` | `npm run lint` in CI |
| A test may reach the assembled system (`governance-sdk`) only as a devDependency, never as a runtime one. Tests are excluded from the build graph, which is exactly where a boundary would otherwise rot unnoticed. | `scripts/check-layering.mjs` | `npm run lint` in CI |
| `createGovernanceKernel()` with no extensions says what it lacks: a rule naming an unregistered condition is rejected when added, a mask with no strategy fails closed to `block`, `register()` returns level 0 labelled "Unscored" with an empty `dimensions` array, and `score()` / `scoreFleet()` throw `NoScorerError`. | `packages/core/src/governance.ts` | `governance-edge.test.ts`, `plugin.test.ts` |
| `createGovernance()` and the `governance-sdk/policy` subpath install the default extension set, so every documented built-in behaves as before. All 60 subpaths resolve from the built output. | `packages/governance/src/index.ts`, `policy-entry.ts` | `index.test.ts`, the root `npm test` |
| The `governance-sdk` tarball installs on its own: the three private packages are staged inside it, and installing it into a fresh project outside the workspace imports every subpath and runs the kernel, a standards report and the identity plugin. npm does not bundle workspace links, so `npm publish -w` would ship a package that installs and then fails on first import. | `scripts/pack-meta.mjs`, `bundleDependencies` | `scripts/verify-pack.mjs` in CI and the release workflow |
| The public API of every subpath is compared against the previous release before a restructure merges: exported symbol names and kinds, resolved through `export *`, plus runtime keys. | `scripts/api-surface.mjs`, `scripts/api-diff.mjs` | run by hand against a `main` worktree; results in the PR |

## Kill switch

| Guarantee | Enforced by | Asserted in |
|---|---|---|
| After `kill(agentId)`, `enforce()`, `enforcePreprocess()`, `enforceToolResult()` and `enforcePostprocess()` all return `block` for that agent. | system rules are stage-agnostic | `policy-system-rules.test.ts` |
| In hosted mode a local kill is checked before the remote API is called; the API cannot override it. | `index.ts` (`evaluateSystemRules` pre-check) | `policy-system-rules.test.ts` |
| A killed agent stays killed until `revive()`; `gov.removeRule()` cannot remove the kill rule. | `policy.ts` | `policy-system-rules.test.ts` |

Not guaranteed: kill state is per process. Another replica does not learn of
the kill unless you propagate it (a hosted API that holds kill state, pub/sub,
or polling storage). The kill switch is a local brake, not a distributed stop.

## Audit chain (when `integrityAudit` is configured)

| Guarantee | Enforced by | Asserted in |
|---|---|---|
| Every event written through the instance (`register`, `enforce*`, `recordOutcome`, `audit.log`, kill-switch events) is HMAC-SHA256 hash-chained: each hash covers the previous hash, the sequence number and the canonicalised event. | `audit-integrity.ts`, `index.ts` (`writeAudit`) | `audit-integrity.test.ts`, `audit-chain-e2e.test.ts` |
| Editing any event, deleting an interior event, reordering by renumbering, or inserting a forged event breaks verification. | `audit-integrity-verify.ts` | `audit-integrity-adversarial.test.ts` |
| Chains are scoped per organisation; an event cannot be relabelled into another organisation's chain without breaking its hash. | `canonicalize()` binds `organizationId` | `audit-chain-per-org.test.ts` |
| With a storage adapter that implements `appendToAuditChain` (Postgres, memory), concurrent writers across processes produce one contiguous chain with no duplicate sequences. | adapter-held per-org lock | `audit-chain-append-postgres.test.ts`, `audit-chain-multiwriter.test.ts` |
| Hash comparison in verification is constant-time. | `constantTimeEqualHex` | `audit-integrity.test.ts` |
| An empty signing key is rejected. A key under 16 characters is rejected under `strict` and warned about otherwise. | `index.ts` | `governance-observability.test.ts` |

Not guaranteed:

- **Tail truncation is not detectable.** Dropping the last *k* events leaves a
  chain that verifies as a shorter valid chain. This is a property of every
  hash chain, not a bug. Anchor the head (`integrityChain.stats()` returns
  `latestSequence` and `latestHash`) somewhere the writer cannot rewrite: a
  co-signed receipt, a transparency log, a counterparty's storage. The limit
  is asserted, not just documented, in `audit-chain-truncation.test.ts`.
- **Holders of the signing secret can rewrite history.** HMAC gives
  tamper-evidence to parties without the key and nothing to parties with it.
  There is no non-repudiation. Rotate the key and anchor externally.
- Events your application writes outside the instance (raw `fetch`, direct
  `storage.createAuditEvent()`) are not chained.
- `integrityAudit.onFailure: "allow"` (the default outside `strict`) means a
  failed chain write creates a gap that verification will detect later; it
  does not stop the decision from being applied. Use `"block"` or `strict`
  when a gap is unacceptable.

## Detection

| Guarantee | Enforced by | Asserted in |
|---|---|---|
| The built-in regex detector completes in bounded time on adversarial input. Every built-in pattern is exercised against pathological shapes under a time budget. | bounded quantifiers in `injection-patterns*.ts` | `injection-redos.test.ts` |
| `scanToolResult()` runs the detector on every tool return, sets `ctx.injectionScore`, and returns a provenance mark for the ingestion. | `tool-result-scan.ts` | `taint-tier.test.ts` |

Not guaranteed:

- **Detection is telemetry, not a gate.** The regex baseline scores F1 ≈ 0.48
  on the shipped 6,931-sample corpus: high precision, low recall, English
  only. ML classifiers plugged in through `InjectionClassifier` collapse to
  single-digit or low-double-digit recall on indirect and tool-use attacks
  out of distribution, per published 2026 evaluations. Adaptive attackers
  erase most static gains. Use `blockTaintedTools()` and
  `requireTierApproval()` for the consequential actions; use detection to
  decide when to look.
- Multi-modal content (images, PDFs, audio) is not scanned unless you
  register an extractor.

## Budgets and rate limits

| Guarantee | Enforced by | Asserted in |
|---|---|---|
| In local mode `rateLimit(n, windowMs)` blocks the *(n+1)*-th allowed action inside `windowMs` for a session, with no host wiring. `tokenBudget()` and `costBudget()` accumulate what `recordOutcome()` reports. | `session-ledger.ts` | `session-ledger.test.ts` |
| Host-supplied counters on the context always take precedence over the ledger. | `SessionLedger.populate` | `session-ledger.test.ts` |

Not guaranteed: the ledger is per process and in memory. For a fleet-wide
limit, keep the count in a shared store and set the context fields yourself.
Hosted mode never consults the ledger.

## Identity

| Guarantee | Enforced by | Asserted in |
|---|---|---|
| Ed25519 identity tokens are verified for signature, expiry (60 s skew), optional audience and issuer, optional key pinning (single key, key set, or resolver by `kid`), and optional replay (`jti`) through a pluggable store. | `agent-identity-ed25519-token.ts` | `agent-identity-ed25519-token.test.ts` |
| Delegated certificates carry a capability subset of their parent and inherit its expiry; verification of a delegated certificate requires the issuer's public key. | `agent-identity-ed25519.ts` | `agent-identity-ed25519.test.ts` |
| HMAC identity tokens (`agent-identity`, deprecated) sign every claim including expiry, compare in constant time, and reject v1 tokens. | `agent-identity.ts` | `agent-identity.test.ts` |
| Externally issued JWTs are verified on Web Crypto only, for RS256, ES256 and EdDSA. The algorithm is derived from the key material, never from the token header or the JWK's `alg`, so one key verifies exactly one algorithm; `HS*` and `none` are rejected and there is no option to enable them. | `identity-jwt.ts`, `identity-jwt-keys.ts` | `identity-jwt.test.ts` |
| JWT verification checks `exp` (required unless `requireExpiry: false`), `nbf`, `iat`, issuer, audience, replay by `jti` through the pluggable store, and rejects unsupported `crit` headers, with a 60 s default skew. | `identity-jwt-claims.ts` | `identity-jwt-claims.test.ts` |
| The JWKS resolver is bounded: a key cap, a TTL, a cooldown per unknown `kid`, a rolling refetch budget and coalesced concurrent misses. A caller choosing `kid` values cannot drive fetches to the IdP, and a failing IdP's error, not "unknown kid", is what callers see meanwhile. | `identity-jwks.ts` | `identity-jwks.test.ts` |
| A JWT-SVID must carry an audience and a workload SPIFFE ID whose trust domain is one you named; `parseSpiffeId()` rejects every form the SPIFFE ID spec forbids (scheme, userinfo, port, query, fragment, relative segments, percent-encoding, length). | `identity-spiffe.ts` | `identity-spiffe.test.ts` |
| `identityPlugin()` registers under `getVerifier("identity")`, returns exactly the context fields `require_signed_identity` reads, refuses a tool the token's capabilities do not cover, and writes an `identity_verification` audit event carrying the delegation chain (`act`, `azp`, `actor`). A verifier that throws is reported as a failed check, never as a verified one. | `ext/identity-plugin.ts` | `ext/identity-plugin.test.ts` |

Not guaranteed: the SDK does not run the vault lookup, and the kernel does not
call the verifier during `enforce()` — the policy engine is synchronous and
cannot fetch a JWKS mid-evaluation. `requireSignedIdentity()` reads
`ctx.identityVerified`, which your host sets from `check.context` (external
identity) or after calling `verifyAgentIdentity()` (self-issued). X.509-SVIDs
are not verified: Web Crypto has no certificate-chain validation.

## Hosted mode

| Guarantee | Enforced by | Asserted in |
|---|---|---|
| The remote decision is shape-validated. A malformed response is treated as a transport failure and resolved by `fallbackMode`. | `remote-enforce.ts` | `remote-enforce.test.ts` |
| 408, 425, 429 and 5xx are retried with backoff, honouring `Retry-After`. 401 and 403 throw. Other 4xx resolve by `fallbackMode`. | `remote-enforce.ts` | `remote-enforce.test.ts` |
| Local system rules are evaluated before any remote call. | `index.ts` | `policy-system-rules.test.ts` |

Not guaranteed: `fallbackMode` defaults to `allow` outside `strict`. With the
API unreachable, agents proceed. `audit.log()`, `recordOutcome()` and
kill-switch events write to local storage, not to the API; the instance warns
once at construction. The wire contract is documented in
[remote-contract.md](./remote-contract.md).

## Fail modes at a glance

`gov.failModes()` returns the resolved behaviour of an instance; pass
`logger` to have it summarised in one line at construction.

| Subsystem | Default | Under `strict: true` |
|---|---|---|
| Remote API unreachable | allow | block |
| Chained audit write fails | allow (gap detectable later) | block |
| Mask cannot be computed | block | block |
| Unknown condition type or malformed rule | reject at add time | reject at add time |
| Kill switch coverage | all stages, checked before remote | all stages, checked before remote |
| Signing key under 16 characters | warn | reject |
| Session ledger | on (local mode) | on (local mode) |

## Out of scope

- Process isolation. The SDK governs trusted application code calling models
  and tools. It is not a sandbox for attacker-supplied code; use containers,
  gVisor or Firecracker for that.
- Compliance certification. The standards modules produce self-assessments
  against a named revision of each standard. They are engineering posture
  tools, not legal advice.
- Evaluation and red-teaming harnesses. Route results from inspect-ai, PyRIT
  or Garak into the audit stream with `gov.audit.log()`.
