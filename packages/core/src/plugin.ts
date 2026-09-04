/**
 * The plugin contract — how everything that is not the kernel attaches to it.
 *
 * The kernel is the policy engine, the audit chain, the storage contract and
 * the event stream. Detection corpora, standards mappings, scoring models,
 * identity verifiers and audit destinations all change on other people's
 * schedules (OWASP revises annually, a regulator can move a date by sixteen
 * months, an acquired detector library stops shipping), so they attach through
 * this contract instead of living in the kernel's semver.
 *
 * Rules:
 *   - Plugins register; they do not reach into the instance. A plugin receives
 *     a `KernelHandle`, never the `GovernanceInstance`. Anything a plugin needs
 *     that is not on the handle is a kernel feature request, not a cast.
 *   - The kernel never imports a plugin. A lint rule enforces it.
 *   - `gov.use()` is idempotent per plugin id and refuses a plugin whose
 *     `requires.core` range this kernel does not satisfy.
 *   - Conditions a plugin registers are validated exactly like built-ins, so a
 *     rule naming a plugin's condition before the plugin is installed is
 *     rejected when the rule is added, not when it first evaluates.
 *
 * See docs/restructure-plan.md for where each current module is headed.
 */

import type { EnforcementContext, RegisteredConditionType } from "./policy.js";
import type { GovernanceEmitter } from "./events.js";
import type { AuditEvent } from "./storage.js";

/** Capabilities a plugin can require of the kernel it is installed into. */
export type KernelCapability =
  | "conditions"
  | "mask-strategies"
  | "verifiers"
  | "reporters"
  | "sinks"
  | "events";

const KERNEL_CAPABILITIES: readonly KernelCapability[] = [
  "conditions",
  "mask-strategies",
  "verifiers",
  "reporters",
  "sinks",
  "events",
];

/**
 * Produce the redacted text for a `mask` decision on a given condition type.
 * Return `undefined` when this content cannot be redacted — the engine then
 * fails closed and turns the decision into a `block`, rather than passing the
 * original text through under a "mask" label.
 */
export type MaskStrategy = (
  text: string,
  params: Record<string, unknown>,
  ctx: EnforcementContext,
) => string | undefined;

/**
 * Receives every audit event after it has been written (and hash-chained, when
 * integrity audit is on). Sinks are how events reach OpenTelemetry, a webhook,
 * or an external anchor. A sink must not throw into the caller: failures are
 * routed to `onAuditError` and never block enforcement.
 */
export type AuditSink = (event: AuditEvent) => void | Promise<void>;

/** A named report over governance state — standards mappings register these. */
export type Reporter<Config = unknown, Report = unknown> = (config: Config) => Promise<Report> | Report;

/**
 * Undo one registration. Every register verb returns one, and the registry
 * records them per plugin so `gov.unuse(id)` rolls the plugin back in full
 * without the plugin author having to track anything.
 */
export type Disposer = () => void;

/** Verifier kinds the kernel knows how to consult. */
export type VerifierKind = "identity" | "remote-decision";

/** What `gov.failModes()` reports, re-declared structurally to avoid a cycle. */
export interface KernelFailModes {
  mode: "local" | "hosted";
  strict: boolean;
  remoteFallback: "allow" | "block" | "n/a";
  integrityAudit: "off" | "allow" | "block";
  maskFailure: "block";
  unknownCondition: "reject";
  killSwitch: "all-stages";
  ledger: "on" | "off";
}

/**
 * The surface a plugin is handed at install time. Deliberately small: every
 * verb here is something a plugin genuinely needs, and nothing here exposes
 * the instance, its storage, or its rules.
 */
export interface KernelHandle {
  /** Version of the kernel doing the installing, for a plugin's own checks. */
  readonly core: string;
  /**
   * Register a condition type. Validated like a built-in from this moment on.
   * The disposer restores whatever the registration displaced, so overriding
   * a built-in is reversible.
   */
  registerCondition(entry: RegisteredConditionType, opts?: { override?: boolean }): Disposer;
  /** Teach the engine how to redact for a condition type it can now match. */
  registerMaskStrategy(conditionType: string, mask: MaskStrategy): Disposer;
  /** Register a verifier the kernel consults (identity, remote decisions). */
  registerVerifier(kind: VerifierKind, verifier: unknown): Disposer;
  /**
   * Register a named report over governance state (EU AI Act, OWASP, …).
   * `Config` and `Report` flow through to `gov.report()` for callers who name
   * them, so a typed mapping does not have to narrow at the boundary.
   */
  registerReporter<Config = unknown, Report = unknown>(id: string, reporter: Reporter<Config, Report>): Disposer;
  /** Subscribe to enforcement, registration, policy and kill/revive events. */
  readonly events: GovernanceEmitter;
  /** Write an audit event through the instance (chained when integrity is on). */
  readonly audit: { log(event: Omit<AuditEvent, "id" | "createdAt">): Promise<AuditEvent> };
  /** Receive every audit event after it is written. */
  addSink(sink: AuditSink): Disposer;
  /** How this instance behaves under failure. */
  failModes(): KernelFailModes;
}

/** A unit of behaviour installed into a governance instance. */
export interface GovernancePlugin {
  /** Stable id, e.g. "standards/owasp-asi", "detect/regex", "sinks/otel". */
  id: string;
  /** The plugin's own version. For standards, the revision it implements. */
  version: string;
  /** What this plugin needs from the kernel; installation fails if unmet. */
  requires?: { core: string; capabilities?: KernelCapability[] };
  /** Called once, by `gov.use()`. */
  install(kernel: KernelHandle): void | Promise<void>;
  /** Optional teardown, called by `gov.unuse(id)`. */
  uninstall?(): void | Promise<void>;
}

/** What `gov.plugins()` reports for each installed plugin. */
export interface InstalledPlugin {
  id: string;
  version: string;
  installedAt: string;
}

export class PluginError extends Error {
  public readonly pluginId: string;
  constructor(pluginId: string, message: string) {
    super(`Plugin "${pluginId}": ${message}`);
    this.name = "PluginError";
    this.pluginId = pluginId;
  }
}

// ─── Version ranges ─────────────────────────────────────────────
//
// A deliberately small subset of the semver grammar — enough for a plugin to
// say which kernels it works with, without a dependency. Supported:
//   *  |  1.2.3  |  ^1.2.3  |  ~1.2.3  |  >=1.2.3  |  >1.2.3  |  <2.0.0
//   <=1.2.3  |  and space-separated conjunctions of the above.
// Pre-release identifiers are compared by presence only (1.2.3-rc < 1.2.3).

interface Parsed { major: number; minor: number; patch: number; pre: string }

function parseVersion(v: string): Parsed | null {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(v.trim());
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), pre: m[4] ?? "" };
}

function compare(a: Parsed, b: Parsed): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  if (a.pre === b.pre) return 0;
  if (a.pre === "") return 1;
  if (b.pre === "") return -1;
  return a.pre < b.pre ? -1 : 1;
}

function satisfiesComparator(version: Parsed, comparator: string): boolean {
  const c = comparator.trim();
  if (c === "" || c === "*" || c === "x") return true;

  const opMatch = /^(>=|<=|>|<|\^|~|=)?\s*(.+)$/.exec(c);
  if (!opMatch) return false;
  const op = opMatch[1] ?? "=";
  const rawTarget = opMatch[2];
  if (rawTarget === undefined) return false;
  const target = parseVersion(rawTarget);
  if (!target) return false;
  const cmp = compare(version, target);

  switch (op) {
    case ">=": return cmp >= 0;
    case "<=": return cmp <= 0;
    case ">": return cmp > 0;
    case "<": return cmp < 0;
    case "=": return cmp === 0;
    case "^": {
      // Caret: same left-most non-zero component. Below 1.0.0 that means the
      // minor is the compatibility boundary — which is the whole point for a
      // 0.x kernel whose minors carry breaking-ish changes.
      if (cmp < 0) return false;
      if (target.major > 0) return version.major === target.major;
      if (target.minor > 0) return version.major === 0 && version.minor === target.minor;
      return version.major === 0 && version.minor === 0 && version.patch === target.patch;
    }
    case "~": {
      if (cmp < 0) return false;
      return version.major === target.major && version.minor === target.minor;
    }
    default: return false;
  }
}

/** Whether `version` satisfies `range` (the subset documented above). */
export function satisfiesRange(version: string, range: string): boolean {
  const parsed = parseVersion(version);
  if (!parsed) return false;
  const trimmed = range.trim();
  if (trimmed === "" || trimmed === "*") return true;
  // Space-separated comparators are a conjunction; `||` is not supported and
  // is treated as unsatisfiable rather than silently ignored.
  if (trimmed.includes("||")) return false;
  return trimmed
    .split(/\s+/)
    .filter(Boolean)
    .every((c) => satisfiesComparator(parsed, c));
}

// ─── Registry ───────────────────────────────────────────────────

export interface PluginRegistry {
  use(plugin: GovernancePlugin): Promise<void>;
  unuse(id: string): Promise<boolean>;
  list(): InstalledPlugin[];
  has(id: string): boolean;
}

/**
 * Create the registry backing `gov.use()`. `handle` is what each plugin is
 * given; `coreVersion` is what `requires.core` is checked against.
 */
export function createPluginRegistry(
  handle: KernelHandle,
  coreVersion: string,
  capabilities: readonly KernelCapability[] = KERNEL_CAPABILITIES,
): PluginRegistry {
  const installed = new Map<string, { plugin: GovernancePlugin; record: InstalledPlugin; disposers: Disposer[] }>();

  return {
    async use(plugin: GovernancePlugin): Promise<void> {
      if (!plugin || typeof plugin !== "object") {
        throw new TypeError("gov.use() expects a GovernancePlugin object");
      }
      if (typeof plugin.id !== "string" || plugin.id.length === 0) {
        throw new TypeError("gov.use() expects a plugin with a non-empty string id");
      }
      if (typeof plugin.install !== "function") {
        throw new PluginError(plugin.id, "must provide an install(kernel) function");
      }

      const existing = installed.get(plugin.id);
      if (existing) {
        // Idempotent per id. Re-installing the same id at a different version
        // is a mistake worth surfacing rather than silently keeping either one.
        if (existing.record.version !== plugin.version) {
          throw new PluginError(
            plugin.id,
            `already installed at version ${existing.record.version}; refusing to install ${plugin.version}. Call gov.unuse("${plugin.id}") first.`,
          );
        }
        return;
      }

      const requires = plugin.requires;
      if (requires) {
        if (typeof requires.core === "string" && !satisfiesRange(coreVersion, requires.core)) {
          throw new PluginError(
            plugin.id,
            `requires kernel ${requires.core} but this kernel is ${coreVersion}`,
          );
        }
        for (const cap of requires.capabilities ?? []) {
          if (!capabilities.includes(cap)) {
            throw new PluginError(plugin.id, `requires capability "${cap}", which this kernel does not provide`);
          }
        }
      }

      // Every registration this plugin makes is recorded, so `unuse()` can
      // undo it without the plugin tracking its own teardown. A plugin's own
      // `uninstall()` is then only for resources the kernel never saw —
      // timers, connections, file handles.
      const disposers: Disposer[] = [];
      const record = <T extends unknown[]>(fn: (...args: T) => Disposer) => (...args: T): Disposer => {
        const dispose = fn(...args);
        disposers.push(dispose);
        return dispose;
      };
      const scoped: KernelHandle = {
        core: handle.core,
        registerCondition: record(handle.registerCondition.bind(handle)),
        registerMaskStrategy: record(handle.registerMaskStrategy.bind(handle)),
        registerVerifier: record(handle.registerVerifier.bind(handle)),
        registerReporter: record(handle.registerReporter.bind(handle)) as KernelHandle["registerReporter"],
        addSink: record(handle.addSink.bind(handle)),
        events: handle.events,
        audit: handle.audit,
        failModes: handle.failModes,
      };

      await plugin.install(scoped);
      installed.set(plugin.id, {
        plugin,
        disposers,
        record: { id: plugin.id, version: plugin.version, installedAt: new Date().toISOString() },
      });
    },

    async unuse(id: string): Promise<boolean> {
      const entry = installed.get(id);
      if (!entry) return false;
      await entry.plugin.uninstall?.();
      // Reverse order: a later registration may have displaced an earlier one.
      for (const dispose of [...entry.disposers].reverse()) dispose();
      installed.delete(id);
      return true;
    },

    list(): InstalledPlugin[] {
      return [...installed.values()].map((e) => ({ ...e.record }));
    },

    has(id: string): boolean {
      return installed.has(id);
    },
  };
}
