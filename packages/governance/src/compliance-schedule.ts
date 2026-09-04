/**
 * EU AI Act phased application schedule — the single source of truth for
 * every date the compliance module reports.
 *
 * Regulation (EU) 2024/1689 (the AI Act) as amended by Regulation (EU)
 * 2026/1744 (the "Digital Omnibus on AI", published OJ 2026-07-24, in force
 * 2026-07-27). The Omnibus deferred the high-risk obligations only:
 *
 *   - Annex III stand-alone high-risk systems   2026-08-02 → 2027-12-02
 *   - Annex I product-embedded high-risk (Art 6(1))  2027-08-02 → 2028-08-02
 *
 * Unchanged: Art 5 prohibitions (2025-02-02), GPAI model obligations
 * (Arts 51-56, 2025-08-02) and Art 50 transparency (2026-08-02). Art 50(2)
 * machine-readable marking carries a grace period to 2026-12-02 for
 * generative systems already on the market before 2026-08-02.
 *
 * Every date below was checked on 2026-09-04 against at least two of the
 * `sourceUrls`:
 *   - CSA research note (omnibus): Reg. 2026/1744 "published in the Official
 *     Journal on July 24, 2026, and entered into force on July 27, 2026";
 *     Annex III "December 2, 2027"; Annex I "August 2, 2028"; Art 50 "took
 *     effect on schedule on August 2, 2026"; GPAI (Arts 51-56) "have applied
 *     since August 2, 2025"; Art 5 "in force since February 2, 2025".
 *   - Gibson Dunn: Annex III "2 December 2027", Annex I "2 August 2028",
 *     Art 50 "2 August 2026" (+ marking grace "until 2 December 2026"), GPAI
 *     2025-08-02 "No change to date".
 *   - Hunton: Reg. 2026/1744, OJ 2026-07-24, in force 2026-07-27,
 *     transparency 2026-08-02, Annex III 2027-12-02, Annex I 2028-08-02.
 *   - artificialintelligenceact.eu timeline: 2025-02-02 prohibitions,
 *     2025-08-02 GPAI, 2026-08-02 remainder of the Act (incl. Art 50),
 *     2027-12-02 Annex III, 2028-08-02 Annex I.
 *   - Cooley: Art 50 "Starting 2 August 2026"; Art 50(2) grace to 2026-12-02.
 *
 * NOT LEGAL ADVICE — see the disclaimer in compliance.ts.
 */

// ─── Types ───────────────────────────────────────────────────

/**
 * Which high-risk annex the assessed system falls under.
 *   - "III": stand-alone high-risk use cases (Annex III) — the default.
 *   - "I":   AI embedded in products covered by Annex I product-safety law.
 */
export type EuAiActAnnex = "I" | "III";

/** Which application milestone gates an article's obligations. */
export type EuAiActPhase = "highRisk" | "article50Transparency";

export type EuAiActMilestoneKey =
  | "prohibitedPractices"
  | "gpaiModelObligations"
  | "article50Transparency"
  | "annexIIIHighRisk"
  | "annexIHighRisk";

export interface EuAiActMilestone {
  /** ISO-8601 calendar date (YYYY-MM-DD) from which the obligations apply. */
  date: string;
  /** Short label for reports. */
  label: string;
  /** Provisions gated by this milestone. */
  scope: string;
  /** Pre-Omnibus date, where Reg. (EU) 2026/1744 moved it. */
  supersedes?: string;
  /** Grace periods or other caveats. */
  note?: string;
}

export interface EuAiActSchedule {
  readonly regulationRevision: string;
  readonly amendmentPublished: string;
  readonly amendmentInForce: string;
  readonly sourceUrls: readonly string[];
  readonly milestones: Readonly<Record<EuAiActMilestoneKey, EuAiActMilestone>>;
}

/** Report-facing milestone map. Legacy keys are retained for consumers. */
export interface EuAiActPhasedDeadlines {
  /** Art 5 prohibited practices (Chapters I-II). */
  prohibitedPractices: string;
  /** GPAI model obligations (Arts 51-56). */
  gpaiModelObligations: string;
  /**
   * @deprecated Alias of {@link EuAiActPhasedDeadlines.gpaiModelObligations}.
   * Earlier releases labelled this the Art 50 date; Art 50 applies from
   * `article50Transparency` (2026-08-02), not from the 2025-08-02 GPAI date.
   */
  gpaiTransparency: string;
  /** Art 50 transparency obligations. */
  article50Transparency: string;
  /** High-risk obligations (Arts 9-15 etc.) for the assessed annex. */
  highRiskObligations: string;
  annexIIIHighRisk: string;
  annexIHighRisk: string;
  /**
   * @deprecated Legacy label for the Art 113(c) milestone — Annex I
   * product-embedded systems — which was 2027-08-02 before Reg. (EU)
   * 2026/1744. Now equals `annexIHighRisk`.
   */
  postMarketAndDownstream: string;
}

// ─── Schedule ────────────────────────────────────────────────

export const EU_AI_ACT_SCHEDULE: EuAiActSchedule = {
  regulationRevision: "Reg. (EU) 2024/1689 as amended by Reg. (EU) 2026/1744",
  amendmentPublished: "2026-07-24",
  amendmentInForce: "2026-07-27",
  sourceUrls: [
    "https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-high-risk-deadline-omnibus-20260/",
    "https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/",
    "https://www.hunton.com/privacy-and-cybersecurity-law-blog/eu-digital-omnibus-on-ai-enters-into-force",
    "https://artificialintelligenceact.eu/implementation-timeline/",
    "https://www.cooley.com/news/insight/2026/2026-08-03-eu-ai-act-transparency-obligations-take-effect-2-august-2026",
  ],
  milestones: {
    prohibitedPractices: {
      date: "2025-02-02",
      label: "Prohibited practices",
      scope: "Art 5 prohibitions and Art 4 AI literacy (Chapters I-II)",
      note: "Reg. 2026/1744 added CSAM / non-consensual imagery prohibitions applying from 2026-12-02.",
    },
    gpaiModelObligations: {
      date: "2025-08-02",
      label: "GPAI model obligations",
      scope: "Arts 51-56 (Chapter V), governance (Chapter VII), penalties (Arts 99-100)",
      note: "GPAI models placed on the market before 2025-08-02 have until 2027-08-02.",
    },
    article50Transparency: {
      date: "2026-08-02",
      label: "Article 50 transparency",
      scope: "Art 50 AI-interaction disclosure and machine-readable content marking",
      note: "Art 50(2) marking: grace to 2026-12-02 for generative systems already on the market before 2026-08-02.",
    },
    annexIIIHighRisk: {
      date: "2027-12-02",
      label: "Annex III high-risk",
      scope: "Chapter III Sections 1-3 (Arts 8-27, incl. 9, 11, 12, 14, 15) for stand-alone Annex III systems",
      supersedes: "2026-08-02",
    },
    annexIHighRisk: {
      date: "2028-08-02",
      label: "Annex I high-risk",
      scope: "Chapter III Sections 1-3 for AI embedded in Annex I regulated products (Art 6(1))",
      supersedes: "2027-08-02",
    },
  },
};

// ─── Resolution helpers ──────────────────────────────────────

/** The high-risk milestone that applies to systems under `annex`. */
export function highRiskMilestone(annex: EuAiActAnnex = "III"): EuAiActMilestone {
  return annex === "I"
    ? EU_AI_ACT_SCHEDULE.milestones.annexIHighRisk
    : EU_AI_ACT_SCHEDULE.milestones.annexIIIHighRisk;
}

/** Application date (YYYY-MM-DD) for an article phase under `annex`. */
export function resolveDeadline(phase: EuAiActPhase, annex: EuAiActAnnex = "III"): string {
  return phase === "article50Transparency"
    ? EU_AI_ACT_SCHEDULE.milestones.article50Transparency.date
    : highRiskMilestone(annex).date;
}

/** Whole days from `now` until `isoDate` (negative once the date has passed). */
export function daysUntil(isoDate: string, now: Date = new Date()): number {
  return Math.ceil((new Date(isoDate).getTime() - now.getTime()) / 86_400_000);
}

/** Build the report-facing milestone map for `annex`. */
export function buildPhasedDeadlines(annex: EuAiActAnnex = "III"): EuAiActPhasedDeadlines {
  const m = EU_AI_ACT_SCHEDULE.milestones;
  return {
    prohibitedPractices: m.prohibitedPractices.date,
    gpaiModelObligations: m.gpaiModelObligations.date,
    gpaiTransparency: m.gpaiModelObligations.date,
    article50Transparency: m.article50Transparency.date,
    highRiskObligations: highRiskMilestone(annex).date,
    annexIIIHighRisk: m.annexIIIHighRisk.date,
    annexIHighRisk: m.annexIHighRisk.date,
    postMarketAndDownstream: m.annexIHighRisk.date,
  };
}
