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

Not guaranteed: the SDK does not run the vault lookup. `requireSignedIdentity()`
reads `ctx.identityVerified`, which your host sets after calling
`verifyAgentIdentity()`. Self-issued tokens are not interoperable with Entra,
Okta, Auth0 or SPIFFE identities; verifiers for those are planned.

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
