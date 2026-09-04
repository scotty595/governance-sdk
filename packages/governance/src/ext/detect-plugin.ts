/**
 * Regex injection detection, as a plugin — the swappable detector.
 *
 * Every acquired detector library eventually stopped shipping (LLM Guard,
 * Rebuff, Vigil), so the corpus a deployment scans with has to be replaceable
 * without touching the kernel. That is what this plugin is for.
 *
 * Installed with no options it is deliberately a no-op: it registers the same
 * `sensitive_data_filter` mask strategy the engine already has, and leaves
 * `injection_guard` alone. Pass `patterns` and it overrides `injection_guard`
 * with a condition that scans the caller's corpus — same normalisation, same
 * scoring, same `threshold` / `skipCategories` params, different patterns.
 */

import type { GovernancePlugin, KernelHandle } from "../plugin.js";
import { getScanText } from "../policy.js";
import { maskSensitiveData } from "../mask.js";
import {
  detectInjection,
  getBuiltinPatterns,
  type InjectionCategory,
  type InjectionPattern,
} from "../injection-detect.js";
import { runBenchmark, type BenchmarkResults, type DetectorFn } from "../injection-benchmark.js";

/**
 * Pattern-corpus revision: the built-in corpus (`injection-patterns.ts` and
 * `injection-patterns-ext.ts`). Bump it when that corpus changes. A
 * caller-supplied `patterns` set does NOT move this number — the version
 * identifies the plugin build, and `gov.use()` refuses two versions of one id.
 */
const CORPUS_REVISION = "2026.9.0";

/** Default detection threshold, matching `detectInjection`'s own default. */
const DEFAULT_THRESHOLD = 0.5;

/**
 * Category the caller's patterns are re-keyed to before they are handed to
 * `detectInjection()`.
 *
 * `InjectionDetectorConfig` has no "replace the corpus" option: BUILTIN_PATTERNS
 * is always folded in, and `skipCategories` is the only removal lever — but
 * every one of the seven categories is in use by the built-ins, so skipping
 * "all built-in categories" would drop the caller's patterns along with them.
 * Re-keying the caller's patterns to a category no built-in declares leaves
 * them as the only survivors, which is how a caller-supplied corpus reaches
 * the existing normaliser and scorer without this file copying either.
 *
 * This is a workaround for a missing option, not a design — see the plugin's
 * notes: `InjectionDetectorConfig` wants a `patterns` (replace, don't append)
 * field. One consequence today: a caller pattern declared `obfuscation` loses
 * the extra raw-input pass `detectInjection()` gives that category.
 */
const OVERRIDE_CATEGORY = "plugin_corpus" as InjectionCategory;

/** Every category the built-in corpus uses — read from the corpus, not fixed here. */
const BUILTIN_CATEGORIES: InjectionCategory[] = [
  ...new Set(getBuiltinPatterns().map((p) => p.category)),
];

export interface DetectPluginOptions {
  /**
   * Corpus to scan with INSTEAD of the built-in patterns. When supplied, the
   * plugin overrides the `injection_guard` condition; when omitted, the
   * built-in condition is left exactly as it is.
   */
  patterns?: InjectionPattern[];
  /** Default threshold for rules that do not set one. Default 0.5. */
  threshold?: number;
}

/** Config for the `"detect/benchmark"` reporter. */
export interface BenchmarkReportConfig {
  /** The detector to score against the built-in labelled dataset. */
  detector: DetectorFn;
}

/**
 * The same walk over `ctx.input` the built-in condition does — it lives
 * module-private in `conditions/builtins.ts`. Kept identical so the override
 * differs from the built-in in exactly one way: which patterns it matches.
 */
function extractStrings(obj: Record<string, unknown>): string[] {
  const out: string[] = [];
  (function walk(v: unknown) {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v as Record<string, unknown>).forEach(walk);
  })(obj);
  if (out.length > 1) out.push(out.join(" "));
  return out;
}

/** Run `detectInjection`'s scorer over `patterns` alone. See OVERRIDE_CATEGORY. */
function scanCorpus(text: string, patterns: InjectionPattern[], threshold: number): boolean {
  return detectInjection(text, {
    threshold,
    customPatterns: patterns.map((p) => ({ ...p, category: OVERRIDE_CATEGORY })),
    skipCategories: BUILTIN_CATEGORIES,
  }).detected;
}

/**
 * Swap the injection detector without touching the kernel.
 *
 * @example
 * ```ts
 * await gov.use(detectPlugin({ patterns: myCorpus, threshold: 0.6 }));
 * ```
 */
export function detectPlugin(opts: DetectPluginOptions = {}): GovernancePlugin {
  const patterns = opts.patterns;
  const defaultThreshold = opts.threshold ?? DEFAULT_THRESHOLD;

  return {
    id: "detect/regex",
    version: CORPUS_REVISION,
    requires: { core: "^0.22.0", capabilities: ["conditions", "mask-strategies", "reporters"] },

    install(kernel: KernelHandle): void {
      // Byte-for-byte the strategy policy.ts already registers for this
      // condition, so installing the plugin cannot change what a mask rule
      // redacts. It is here so a deployment that swaps the detector still
      // gets a coherent detect bundle rather than half of one.
      kernel.registerMaskStrategy("sensitive_data_filter", (text, params) =>
        maskSensitiveData(text, params.patterns as string[] | undefined));

      kernel.registerReporter("detect/benchmark", (config): Promise<BenchmarkResults> => {
        const detector = (config as BenchmarkReportConfig | undefined)?.detector;
        if (typeof detector !== "function") {
          throw new TypeError(
            'Reporter "detect/benchmark" expects { detector }: (input: string) => DetectorResult',
          );
        }
        return runBenchmark(detector);
      });

      if (!patterns) return;

      kernel.registerCondition(
        {
          name: "injection_guard",
          description: `Detect prompt injection against a plugin-supplied corpus (${patterns.length} patterns)`,
          evaluator: (ctx, p, rule) => {
            const threshold = typeof p.threshold === "number" ? p.threshold : defaultThreshold;
            // `skipCategories` keeps its meaning against the caller's own
            // categories: filter before the corpus is re-keyed.
            const skip = new Set(Array.isArray(p.skipCategories) ? p.skipCategories : []);
            const active = skip.size > 0 ? patterns.filter((pat) => !skip.has(pat.category)) : patterns;
            if (active.length === 0) return false;

            const strings = getScanText(ctx, rule) ?? (ctx.input ? extractStrings(ctx.input) : []);
            for (const str of strings) {
              if (scanCorpus(str, active, threshold)) return true;
            }
            return false;
          },
        },
        { override: true },
      );
    },
  };
}
