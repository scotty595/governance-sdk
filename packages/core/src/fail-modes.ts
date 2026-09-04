/**
 * How an instance behaves when something goes wrong.
 *
 * Two subsystems fail open by default (an unreachable hosted API, a failed
 * chained-audit write) and three always fail closed (a mask that cannot
 * redact, a malformed rule, the kill switch). `strict: true` flips the first
 * two. A deployment should never have to guess which way it fails, so the
 * resolved answer is reportable through `gov.failModes()` and printable in one
 * line at construction through `config.logger`.
 */


/**
 * How each subsystem behaves when something goes wrong. Returned by
 * `gov.failModes()` and summarised in one line through `config.logger` at
 * construction, so a deployment never has to guess which way it fails.
 */
export interface FailModes {
  mode: "local" | "hosted";
  strict: boolean;
  /** Decision returned when the remote API is unreachable (hosted mode only). */
  remoteFallback: "allow" | "block" | "n/a";
  /** What `enforce()` does when a chained audit write fails. */
  integrityAudit: "off" | "allow" | "block";
  /** A `mask` rule that cannot produce redacted text degrades to `block`. Always. */
  maskFailure: "block";
  /** Rules with unknown condition types or bad shapes are rejected when added. Always. */
  unknownCondition: "reject";
  /** Kill-switch rules apply at every stage and are checked locally even in hosted mode. Always. */
  killSwitch: "all-stages";
  /** Whether the per-process session ledger fills budget / rate-limit counters. */
  ledger: "on" | "off";
}

// Re-export storage types (other modules import from ./index)
export type { GovernanceStorage, StoredAgent, AuditEvent, AuditOutcome, AuditQueryFilters } from "./storage.js";
export { createMemoryStorage } from "./storage.js";

// ─── Governance Instance ────────────────────────────────────────


/** Inputs the fail-mode summary is derived from. */
export interface FailModeInputs {
  remote: boolean;
  strict: boolean;
  fallbackMode: "allow" | "block";
  integrityOnFailure: "allow" | "block" | undefined;
  ledger: boolean;
}

/** Resolve the fail modes of an instance from its settled configuration. */
export function computeFailModes(input: FailModeInputs): FailModes {
  return {
    mode: input.remote ? "hosted" : "local",
    strict: input.strict,
    remoteFallback: input.remote ? input.fallbackMode : "n/a",
    integrityAudit: input.integrityOnFailure ?? "off",
    maskFailure: "block",
    unknownCondition: "reject",
    killSwitch: "all-stages",
    ledger: input.ledger ? "on" : "off",
  };
}

/** The one-line startup summary `config.logger` receives. */
export function describeFailModes(fm: FailModes): string {
  return `governance-sdk: mode=${fm.mode} strict=${fm.strict} remoteFallback=${fm.remoteFallback} integrityAudit=${fm.integrityAudit} maskFailure=${fm.maskFailure} unknownCondition=${fm.unknownCondition} killSwitch=${fm.killSwitch} ledger=${fm.ledger}`;
}
