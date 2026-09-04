/**
 * The standards mappings, as plugins.
 *
 * Each standard revises on someone else's clock — OWASP annually, the EU by
 * regulation, NIST and ISO by edition, CSA and IMDA whenever they say so — so
 * each attaches through the plugin contract and carries the revision it
 * implements in its `version` field.
 * Installing one is purely additive: the `mapToX` / `assessX` functions are
 * untouched and keep working exactly as they do today, and these plugins are
 * a second route to the same report, not a replacement for the first.
 *
 * ⚠️  Every report here is an engineering self-assessment helper. None of them
 * is legal advice, and none is an endorsed certification — see the module
 * comment on each mapping for what it does and does not cover.
 */

import type { GovernancePlugin, KernelHandle } from "@governance-sdk/core/plugin.js";
import { mapToEuAiAct } from "../compliance.js";
import type { ComplianceAssessmentConfig, ComplianceReport } from "../compliance-types.js";
import { coverageMatrix, mapToOwaspAgentic } from "../owasp-agentic.js";
import type {
  OwaspAgenticReport,
  OwaspAssessmentConfig,
  OwaspCoverageEntry,
} from "../owasp-agentic-types.js";
import { mapToNistAiRmf, type NistAiRmfReport, type NistAssessmentConfig } from "../nist-ai-rmf.js";
import { mapToIso42001, type Iso42001AssessmentConfig, type Iso42001Report } from "../iso-42001.js";
import { mapToNistAi600, type NistAi600AssessmentConfig, type NistAi600Report } from "../nist-ai-600-1.js";
import { mapToCsaAicm, type CsaAicmAssessmentConfig, type CsaAicmReport } from "../csa-aicm.js";
import { mapToImdaAgentic, type ImdaAgenticAssessmentConfig, type ImdaAgenticReport } from "../imda-agentic.js";

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

/** NIST AI 600-1, Generative AI Profile — approved 2024-07-25, published July 2024. */
const NIST_AI_600_1_REVISION = "2024.7.26";

/** CSA AI Controls Matrix v1.1 (released 2026-06-22). Domain-level mapping only. */
const CSA_AICM_REVISION = "1.1.0";

/**
 * IMDA Model AI Governance Framework for Agentic AI, Version 1.0 (published
 * 2026-01-22). IMDA has since issued v1.5 (2026-05-20); this mapping has not
 * been re-verified against it, so the version stays at v1.0's date.
 */
const IMDA_AGENTIC_REVISION = "2026.1.22";

/** Kernel range every standards mapping is written against. */
const CORE_RANGE = "^0.22.0";

// ─── Shared scaffold ────────────────────────────────────────────

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
    kernel.registerReporter<ComplianceAssessmentConfig, ComplianceReport>(
      "standards/eu-ai-act", mapToEuAiAct,
    );
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
    kernel.registerReporter<OwaspAssessmentConfig, OwaspAgenticReport>(
      "standards/owasp-asi", mapToOwaspAgentic,
    );
    kernel.registerReporter<OwaspAssessmentConfig, OwaspCoverageEntry[]>(
      "standards/owasp-asi/coverage", coverageMatrix,
    );
  });
}

/** NIST AI RMF 1.0 — 14 subcategories across Govern / Map / Measure / Manage. */
export function nistAiRmfPlugin(): GovernancePlugin {
  return standardsPlugin("standards/nist-ai-rmf", NIST_AI_RMF_REVISION, (kernel) => {
    kernel.registerReporter<NistAssessmentConfig, NistAiRmfReport>(
      "standards/nist-ai-rmf", mapToNistAiRmf,
    );
  });
}

/** ISO/IEC 42001:2023 AI management system clauses. */
export function iso42001Plugin(): GovernancePlugin {
  return standardsPlugin("standards/iso-42001", ISO_42001_REVISION, (kernel) => {
    kernel.registerReporter<Iso42001AssessmentConfig, Iso42001Report>(
      "standards/iso-42001", mapToIso42001,
    );
  });
}

/**
 * NIST AI 600-1 (Generative AI Profile) — 19 AI RMF subcategories plus a
 * roll-up of the twelve §2 GAI risk categories. The companion to
 * {@link nistAiRmfPlugin}, which explicitly does not cover this profile.
 */
export function nistAi600Plugin(): GovernancePlugin {
  return standardsPlugin("standards/nist-ai-600-1", NIST_AI_600_1_REVISION, (kernel) => {
    kernel.registerReporter<NistAi600AssessmentConfig, NistAi600Report>(
      "standards/nist-ai-600-1", mapToNistAi600,
    );
  });
}

/**
 * CSA AI Controls Matrix v1.1 — all 18 domains enumerated, 10 scored. No
 * individual control objective is assessed; the report's `disclaimer` and
 * `scope` say exactly which domains are and are not covered.
 */
export function csaAicmPlugin(): GovernancePlugin {
  return standardsPlugin("standards/csa-aicm", CSA_AICM_REVISION, (kernel) => {
    kernel.registerReporter<CsaAicmAssessmentConfig, CsaAicmReport>(
      "standards/csa-aicm", mapToCsaAicm,
    );
  });
}

/** IMDA Model AI Governance Framework for Agentic AI v1.0 — the four pillars. */
export function imdaAgenticPlugin(): GovernancePlugin {
  return standardsPlugin("standards/imda-agentic", IMDA_AGENTIC_REVISION, (kernel) => {
    kernel.registerReporter<ImdaAgenticAssessmentConfig, ImdaAgenticReport>(
      "standards/imda-agentic", mapToImdaAgentic,
    );
  });
}

/**
 * All seven standards plugins, for the common case of wanting every mapping:
 * `for (const p of allStandardsPlugins()) await gov.use(p);`
 */
export function allStandardsPlugins(): GovernancePlugin[] {
  return [
    euAiActPlugin(),
    owaspAgenticPlugin(),
    nistAiRmfPlugin(),
    iso42001Plugin(),
    nistAi600Plugin(),
    csaAicmPlugin(),
    imdaAgenticPlugin(),
  ];
}
