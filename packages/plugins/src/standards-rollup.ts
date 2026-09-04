/**
 * Shared scoring roll-up for the standards mappings.
 *
 * Every mapping answers the same three questions in the same order — how did
 * each requirement land, what does that make the article/clause/domain, and
 * what does that make the report — so the arithmetic lives here once rather
 * than being retyped per standard.
 *
 * One deliberate difference from the older mappings (compliance.ts,
 * nist-ai-rmf.ts, iso-42001.ts, which each inline their own copy): a
 * `not-applicable` requirement is excluded from the denominator instead of
 * counting as a miss. The three newest standards each contain controls the
 * SDK genuinely cannot observe — NIST AI 600-1's fairness and environmental
 * measures, two thirds of the CSA AICM domains — and scoring those as
 * failures would understate a deployment that is doing everything the SDK can
 * see. An article with nothing assessable reports `not-applicable`, not zero.
 */

import type {
  ComplianceStatus,
  RequirementAssessment,
  ArticleAssessment,
} from "./compliance-articles.js";

// ─── Requirement constructors ────────────────────────────────

/** The requirement is met by observable governance state. */
export function ok(id: string, evidence: string): RequirementAssessment {
  return { requirementId: id, status: "compliant", evidence };
}

/** Some of the requirement is met; `remediation` says what closes the rest. */
export function partial(id: string, evidence: string, remediation?: string): RequirementAssessment {
  return { requirementId: id, status: "partial", evidence, remediation };
}

/** Nothing in the governance state meets the requirement. */
export function fail(id: string, evidence: string, remediation?: string): RequirementAssessment {
  return { requirementId: id, status: "non-compliant", evidence, remediation };
}

/**
 * The SDK cannot see this one. Not a pass and not a failure — it is excluded
 * from the score so that the number reports what was actually assessed.
 */
export function external(id: string, evidence: string, remediation?: string): RequirementAssessment {
  return { requirementId: id, status: "not-applicable", evidence, remediation };
}

// ─── Roll-up ─────────────────────────────────────────────────

/** ≥80 compliant, ≥40 partial, below that non-compliant. */
export function statusFor(score: number): ComplianceStatus {
  return score >= 80 ? "compliant" : score >= 40 ? "partial" : "non-compliant";
}

/**
 * Score one article from its requirements. A partial counts as a half.
 * Requirements assessed `not-applicable` are excluded from both numerator and
 * denominator; if that leaves nothing, the article is `not-applicable` at 0.
 */
export function rollUpArticle(
  article: string,
  title: string,
  requirements: RequirementAssessment[],
): ArticleAssessment {
  const assessable = requirements.filter((r) => r.status !== "not-applicable");
  const compliant = assessable.filter((r) => r.status === "compliant").length;
  const partials = assessable.filter((r) => r.status === "partial").length;
  const score =
    assessable.length === 0
      ? 0
      : Math.round(((compliant + partials * 0.5) / assessable.length) * 100);
  const coverage: ComplianceStatus = assessable.length === 0 ? "not-applicable" : statusFor(score);
  return { article, title, coverage, score, requirements, deadline: "", maxFine: "" };
}

/** Mean score across the articles that had something to assess. */
export function overallScore(articles: ArticleAssessment[]): number {
  const scored = articles.filter((a) => a.coverage !== "not-applicable");
  if (scored.length === 0) return 0;
  return Math.round(scored.reduce((sum, a) => sum + a.score, 0) / scored.length);
}

/** `"<title> (<id>): <evidence>"` for every non-compliant requirement. */
export function criticalGaps(articles: ArticleAssessment[]): string[] {
  return articles.flatMap((a) =>
    a.requirements
      .filter((r) => r.status === "non-compliant")
      .map((r) => `${a.title} (${a.article}): ${r.evidence}`),
  );
}

/** Every distinct remediation string, in first-seen order. */
export function recommendations(articles: ArticleAssessment[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const a of articles) {
    for (const r of a.requirements) {
      if (r.remediation !== undefined && !seen.has(r.remediation)) {
        seen.add(r.remediation);
        out.push(r.remediation);
      }
    }
  }
  return out;
}

/**
 * Fold the statuses of the requirements that address one theme (a GAI risk
 * category, say) into a single verdict. Strict on purpose: `compliant` only
 * when everything assessable is compliant, so a single met requirement cannot
 * make a whole risk category look covered.
 */
export function foldStatuses(statuses: ComplianceStatus[]): ComplianceStatus {
  const assessable = statuses.filter((s) => s !== "not-applicable");
  if (assessable.length === 0) return "not-applicable";
  if (assessable.every((s) => s === "compliant")) return "compliant";
  if (assessable.some((s) => s === "compliant" || s === "partial")) return "partial";
  return "non-compliant";
}
