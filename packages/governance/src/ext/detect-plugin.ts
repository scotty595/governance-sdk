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
import { extractStrings, getScanText } from "../policy.js";
import { maskSensitiveData } from "../mask.js";
import { detectInjection, type InjectionCategory, type InjectionPattern } from "../injection-detect.js";
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
 * Swap the injection detector without touching the kernel. `gov.unuse()` puts
 * the built-in `injection_guard` back — the kernel rolls each registration
 * back through the disposer it returned.
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

      kernel.registerReporter<BenchmarkReportConfig, BenchmarkResults>(
        "detect/benchmark", (config) => runBenchmark(config.detector),
      );

      if (!patterns) return;

      // The built-in evaluator, with `patterns` swapped for the caller's
      // corpus. `skipCategories` and `threshold` keep their meaning, the text
      // it scans comes from the same `getScanText` / `extractStrings` pair the
      // built-in uses, and `detectInjection` still does the normalising and
      // the scoring — so the override differs in exactly one thing.
      kernel.registerCondition(
        {
          name: "injection_guard",
          description: `Detect prompt injection against a plugin-supplied corpus (${patterns.length} patterns)`,
          evaluator: (ctx, p, rule) => {
            const threshold = typeof p.threshold === "number" ? p.threshold : defaultThreshold;
            const skip = (p.skipCategories ?? []) as InjectionCategory[];
            const strings = getScanText(ctx, rule) ?? (ctx.input ? extractStrings(ctx.input) : []);
            for (const str of strings) {
              const result = detectInjection(str, {
                threshold,
                patterns,
                skipCategories: skip.length > 0 ? skip : undefined,
              });
              if (result.detected) return true;
            }
            return false;
          },
        },
        { override: true },
      );
    },
  };
}
