/**
 * The default extension set the package barrel wires onto the kernel.
 *
 * These are the pieces the SDK's documented behaviour depends on but the
 * kernel does not carry: the regex detector behind `injection_guard`, and the
 * sensitive-data corpus behind `sensitive_data_filter` and its redaction.
 *
 * They live here, in the extension layer, so `packages/core` can ship without
 * a detector. `createGovernance()` installs them, so a caller sees no
 * difference; `createGovernanceKernel()` does not, so a caller who wants a
 * bare kernel gets one that says what it is missing rather than pretending.
 */

import type { RegisteredConditionType, EnforcementContext, PolicyRule } from "../policy.js";
import { getScanText, extractStrings } from "../policy.js";
import type { KernelExtensions } from "../governance.js";
import type { MaskStrategy } from "../plugin.js";
import { detectInjection, type InjectionCategory } from "../injection-detect.js";
import { evaluateSensitiveDataFilter } from "./sensitive-filter.js";
import { maskSensitiveData } from "../mask.js";

/** The regex detector, as the `injection_guard` condition. */
export function injectionGuardCondition(): RegisteredConditionType {
  return {
    name: "injection_guard",
    description: "Detect prompt injection attacks (regex detector, synchronous)",
    evaluator: (ctx: EnforcementContext, p: Record<string, unknown>, rule?: PolicyRule) => {
      const skip = (p.skipCategories ?? []) as InjectionCategory[];
      const opts = {
        threshold: p.threshold as number,
        ...(skip.length > 0 ? { skipCategories: skip } : {}),
        ...(Array.isArray(p.patterns) ? { patterns: p.patterns as never } : {}),
      };
      // A rule with `scanModalities` scans only those modalities' pre-extracted
      // text; without it, the legacy walk over ctx.input, unchanged.
      const strings = getScanText(ctx, rule) ?? (ctx.input ? extractStrings(ctx.input) : []);
      for (const str of strings) {
        if (detectInjection(str, opts).detected) return true;
      }
      return false;
    },
  };
}

/** The sensitive-data corpus, as the `sensitive_data_filter` condition. */
export function sensitiveDataFilterCondition(): RegisteredConditionType {
  return {
    name: "sensitive_data_filter",
    description: "Detect leaked credentials and secrets",
    evaluator: (ctx: EnforcementContext, p: Record<string, unknown>, rule?: PolicyRule) => {
      const patternIds = p.patterns as string[] | undefined;
      const scan = getScanText(ctx, rule);
      if (scan) {
        // Reuse the postprocess helper per modality so there is one source of
        // truth for which patterns count as sensitive.
        for (const text of scan) {
          const proxy = { ...ctx, outputText: text } as EnforcementContext;
          if (evaluateSensitiveDataFilter(proxy, patternIds)) return true;
        }
        return false;
      }
      return evaluateSensitiveDataFilter(ctx, patternIds);
    },
  };
}

/** Redaction for `sensitive_data_filter`, which needs the corpus. */
export const sensitiveDataMaskStrategy: MaskStrategy = (text, params) =>
  maskSensitiveData(text, params.patterns as string[] | undefined);

/**
 * Everything `createGovernance()` installs by default. Call it to build on
 * top of the defaults rather than replacing them:
 *
 * ```ts
 * const base = defaultExtensions();
 * createGovernanceKernel({
 *   extensions: { ...base, conditions: [...(base.conditions ?? []), mine] },
 * });
 * ```
 */
export function defaultExtensions(): KernelExtensions {
  return {
    conditions: [injectionGuardCondition(), sensitiveDataFilterCondition()],
    maskStrategies: { sensitive_data_filter: sensitiveDataMaskStrategy },
  };
}
