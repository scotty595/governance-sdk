/**
 * The four standards mappings, as plugins.
 *
 * Each standard revises on someone else's clock — OWASP annually, the EU by
 * regulation, NIST and ISO by edition — so each attaches through the plugin
 * contract and carries the revision it implements in its `version` field.
 * Installing one is purely additive: the `mapToX` / `assessX` functions are
 * untouched and keep working exactly as they do today, and these plugins are
 * a second route to the same report, not a replacement for the first.
 *
 * ⚠️  Every report here is an engineering self-assessment helper. None of them
 * is legal advice, and none is an endorsed certification — see the module
 * comment on each mapping for what it does and does not cover.
 */

import type { GovernancePlugin, KernelHandle } from "../plugin.js";
import { mapToEuAiAct } from "../compliance.js";
import type { ComplianceAssessmentConfig } from "../compliance-types.js";
import { coverageMatrix, mapToOwaspAgentic } from "../owasp-agentic.js";
import type { OwaspAssessmentConfig } from "../owasp-agentic-types.js";
import { mapToNistAiRmf, type NistAssessmentConfig } from "../nist-ai-rmf.js";
import { mapToIso42001, type Iso42001AssessmentConfig } from "../iso-42001.js";

// ─── Revisions ──────────────────────────────────────────────────
//
// A standards plugin's version IS the revision it implements. `gov.use()`
// refuses two versions of one id, so bumping these is how a deployment is
// forced to notice that the text underneath it moved.

/**
 * OJ publication date of Reg. (EU) 2026/1744 (the "Digital Omnibus on AI"),
 * i.e. `EU_AI_ACT_SCHEDULE.amendmentPublished`. The full revision string the
 * report carries is "Reg. (EU) 2024/1689 as amended by Reg. (EU) 2026/1744".
 */
const EU_AI_ACT_REVISION = "2026.7.24";

/** OWASP Top 10 for Agentic Applications, 2026 edition (published 2025-12-09). */
const OWASP_ASI_REVISION = "2026.0.0";

/** NIST AI Risk Management Framework 1.0 (NIST AI 100-1, January 2023). */
const NIST_AI_RMF_REVISION = "1.0.0";

/** ISO/IEC 42001:2023 — clauses 4, 5, 6, 8, 9, 10 (not the Annex A controls). */
const ISO_42001_REVISION = "2023.0.0";

/** Kernel range every standards mapping is written against. */
const CORE_RANGE = "^0.22.0";

// ─── Shared scaffold ────────────────────────────────────────────

/**
 * Narrow the `unknown` a reporter is handed by `gov.report(id, config)` to the
 * config its mapping function already takes. `KernelHandle.registerReporter`
 * is typed `Reporter<unknown, unknown>`, so the boundary has to be checked
 * somewhere; doing it here means one guard that names the reporter instead of
 * four blind casts.
 */
function reporterConfig<Config>(id: string, config: unknown): Config {
  if (config === null || typeof config !== "object") {
    throw new TypeError(
      `Reporter "${id}" expects its assessment config object, got ${config === null ? "null" : typeof config}`,
    );
  }
  return config as Config;
}

/** Every standards plugin is reporters-only on a 0.22 kernel. */
function standardsPlugin(
  id: string,
  version: string,
  install: (kernel: KernelHandle) => void,
): GovernancePlugin {
  return {
    id,
    version,
    requires: { core: CORE_RANGE, capabilities: ["reporters"] },
    install,
  };
}

// ─── Plugins ────────────────────────────────────────────────────

/** EU AI Act (Arts 9, 11, 12, 14, 15, 50) self-assessment. */
export function euAiActPlugin(): GovernancePlugin {
  return standardsPlugin("standards/eu-ai-act", EU_AI_ACT_REVISION, (kernel) => {
    kernel.registerReporter("standards/eu-ai-act", (config) =>
      mapToEuAiAct(reporterConfig<ComplianceAssessmentConfig>("standards/eu-ai-act", config)));
  });
}

/**
 * OWASP Top 10 for Agentic Applications (ASI01…ASI10).
 *
 * Two reports off one config: the full assessment, and the ten-row coverage
 * matrix teams actually paste into a review.
 */
export function owaspAgenticPlugin(): GovernancePlugin {
  return standardsPlugin("standards/owasp-asi", OWASP_ASI_REVISION, (kernel) => {
    kernel.registerReporter("standards/owasp-asi", (config) =>
      mapToOwaspAgentic(reporterConfig<OwaspAssessmentConfig>("standards/owasp-asi", config)));
    kernel.registerReporter("standards/owasp-asi/coverage", (config) =>
      coverageMatrix(reporterConfig<OwaspAssessmentConfig>("standards/owasp-asi/coverage", config)));
  });
}

/** NIST AI RMF 1.0 — 14 subcategories across Govern / Map / Measure / Manage. */
export function nistAiRmfPlugin(): GovernancePlugin {
  return standardsPlugin("standards/nist-ai-rmf", NIST_AI_RMF_REVISION, (kernel) => {
    kernel.registerReporter("standards/nist-ai-rmf", (config) =>
      mapToNistAiRmf(reporterConfig<NistAssessmentConfig>("standards/nist-ai-rmf", config)));
  });
}

/** ISO/IEC 42001:2023 AI management system clauses. */
export function iso42001Plugin(): GovernancePlugin {
  return standardsPlugin("standards/iso-42001", ISO_42001_REVISION, (kernel) => {
    kernel.registerReporter("standards/iso-42001", (config) =>
      mapToIso42001(reporterConfig<Iso42001AssessmentConfig>("standards/iso-42001", config)));
  });
}

/**
 * All four standards plugins, for the common case of wanting every mapping:
 * `for (const p of allStandardsPlugins()) await gov.use(p);`
 */
export function allStandardsPlugins(): GovernancePlugin[] {
  return [euAiActPlugin(), owaspAgenticPlugin(), nistAiRmfPlugin(), iso42001Plugin()];
}
