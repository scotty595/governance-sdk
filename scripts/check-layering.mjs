#!/usr/bin/env node
/**
 * Layering lint — the single rule that stops the kernel re-growing.
 *
 * The restructure (docs/restructure-plan.md) splits the SDK into three layers.
 * Today they are directories inside one package; in Phase B they become
 * separate packages. The rule is the same either way, so it is enforced now,
 * against paths, and the package split will not need a new one:
 *
 *   core      — the policy engine, audit chain, storage contract, event bus.
 *               May import only core.
 *   adapters  — src/plugins/** (one per framework) and src/conformance/**
 *               (the Agent Hooks contract). May import core.
 *   ext       — src/ext/**, detection / standards / scoring / sinks.
 *               May import core. Never an adapter.
 *
 * A violation is a file importing across a boundary the rule forbids. Known
 * violations are listed in EXCEPTIONS with the reason and the phase that
 * removes them: the lint fails on anything new, and on an exception that has
 * been fixed and should therefore be deleted from the list.
 *
 * Usage: node scripts/check-layering.mjs [--list]
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolvePath(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "packages/governance/src");

const ADAPTER_DIRS = ["plugins/", "conformance/"];
const EXT_DIR = "ext/";
/**
 * The CLI is an application on top of the SDK, not part of it — it consumes
 * every layer the way a user's own code does, so it sits above the rule.
 */
const APP_DIR = "cli/";

/**
 * Files that are logically `ext` but still sit in the core directory, because
 * moving them is Phase B (packages) and moving them early would change import
 * paths the public API depends on. Listing them here means the layering rule
 * is enforced against the ARCHITECTURE now, not against the directory tree
 * later — so core-to-detection coupling is visible today instead of being
 * discovered during the package split.
 *
 * A file leaves this list when it moves under src/ext/. The list only shrinks.
 */
const LOGICAL_EXT = new Set([
  // detection
  "injection-detect.ts",
  "injection-patterns.ts",
  "injection-patterns-ext.ts",
  "injection-classifier.ts",
  "injection-benchmark.ts",
  "conditions/sensitive-patterns.ts",
  "mask.ts",
  "scan/multi-modal.ts",
  // standards
  "compliance.ts",
  "compliance-articles.ts",
  "compliance-assessors.ts",
  "compliance-schedule.ts",
  "compliance-types.ts",
  "owasp-agentic.ts",
  "owasp-agentic-articles.ts",
  "owasp-agentic-assessors.ts",
  "owasp-agentic-types.ts",
  "nist-ai-rmf.ts",
  "nist-ai-rmf-articles.ts",
  "iso-42001.ts",
  "iso-42001-articles.ts",
  // scoring
  "scorer.ts",
  "scorer-dimensions.ts",
  "behavioral-scorer.ts",
  "repo-patterns.ts",
  // identity, supply chain, sinks
  "agent-identity.ts",
  "agent-identity-ed25519.ts",
  "agent-identity-ed25519-token.ts",
  "agent-identity-replay-store.ts",
  "supply-chain.ts",
  "supply-chain-cyclonedx.ts",
  "storage-postgres.ts",
  "storage-postgres-schema.ts",
  "otel-hooks.ts",
  // policy authoring surfaces
  "policy-yaml.ts",
  "policy-builder.ts",
  "policy-compose.ts",
  "policy-compose-presets.ts",
  "dry-run.ts",
]);

/**
 * Known, accepted violations: `"<from> -> <to>"`, with why and when it goes.
 * Keep this list shrinking. An entry that no longer matches a real import is
 * reported as stale, so a fix cannot leave dead scaffolding behind.
 */
const EXCEPTIONS = new Map([
  [
    "conditions/postprocess.ts -> conditions/sensitive-patterns.ts",
    "The sensitive-data evaluator reads the corpus directly. Moves with it in Phase B.",
  ],
  [
    "governance.ts -> scorer.ts",
    "register() scores an agent inline and returns the score, so scoring cannot be deferred to an async plugin without changing that signature. Resolve by making the scorer a kernel extension like the detector, once the package split proves the shape.",
  ],
  [
    "scoring-hooks.ts -> scorer.ts",
    "Same, for the re-scoring hooks. Moves to ext/scoring as a unit in Phase B.",
  ],
  [
    "scoring-hooks.ts -> behavioral-scorer.ts",
    "Same unit.",
  ],
  [
    "tool-result-scan.ts -> injection-detect.ts",
    "Tool-result scanning generates the detector signal it then enforces on. Phase B injects the detector through the plugin contract instead of importing it.",
  ],
]);

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (entry.endsWith(".ts") && !entry.endsWith(".test.ts")) out.push(full);
  }
  return out;
}

function layerOf(rel) {
  if (META.has(rel)) return "meta";
  if (rel.startsWith(APP_DIR)) return "app";
  if (ADAPTER_DIRS.some((d) => rel.startsWith(d))) return "adapters";
  if (rel.startsWith(EXT_DIR)) return "ext";
  if (LOGICAL_EXT.has(rel)) return "ext";
  return "core";
}

/** What each layer is allowed to IMPORT (re-exports are handled separately). */
const ALLOWED = {
  core: new Set(["core"]),
  adapters: new Set(["core", "adapters"]),
  ext: new Set(["core", "ext"]),
  app: new Set(["core", "adapters", "ext", "app", "meta"]),
  meta: new Set(["core", "adapters", "ext", "meta"]),
};

/**
 * Public barrels. A barrel's job is to re-export the whole surface under one
 * name — that is precisely what the `governance-sdk` meta-package becomes in
 * Phase B — so `export ... from` across a boundary is allowed here. A real
 * `import` in a barrel is still checked: re-exporting ext is the design,
 * depending on it is not.
 */
const BARRELS = new Set(["index.ts", "policy-entry.ts"]);

/**
 * The meta-package. It re-exports every layer under one name AND is the only
 * place that wires the default extension set onto the kernel, so it is the
 * one file allowed to import ext. In Phase B these become the
 * `governance-sdk` package and the others become its dependencies.
 */
const META = new Set(["index.ts", "policy-entry.ts"]);

/**
 * The one narrow cross-layer import the design allows: an adapter that
 * intercepts tool returns needs the detector to generate the signal it then
 * enforces on. Phase B injects this through the plugin contract instead.
 */
const ADAPTER_DETECTION_ALLOWANCE = new Set(["injection-detect.ts", "tool-result-scan.ts"]);

const IMPORT_RE = /(?:^|\n)\s*(import)\s[^;]*?from\s+["']([^"']+)["']/g;
const REEXPORT_RE = /(?:^|\n)\s*(export)\s[^;]*?from\s+["']([^"']+)["']/g;

const violations = [];
const seen = new Set();

for (const file of walk(SRC)) {
  const rel = relative(SRC, file);
  const from = layerOf(rel);
  const source = readFileSync(file, "utf8");
  const patterns = BARRELS.has(rel) ? [IMPORT_RE] : [IMPORT_RE, REEXPORT_RE];
  for (const re of patterns) {
    for (const m of source.matchAll(re)) {
      const spec = m[2];
      if (!spec.startsWith(".")) continue; // external / peer dependency
      const target = relative(SRC, resolvePath(dirname(file), spec)).replace(/\.js$/, ".ts");
      const to = layerOf(target);
      if (ALLOWED[from].has(to)) continue;
      if (from === "adapters" && ADAPTER_DETECTION_ALLOWANCE.has(target)) continue;
      const key = `${rel} -> ${target}`;
      seen.add(key);
      if (EXCEPTIONS.has(key)) continue;
      violations.push({ key, from, to });
    }
  }
}

const stale = [...EXCEPTIONS.keys()].filter((k) => !seen.has(k));

if (process.argv.includes("--list")) {
  console.log(`Layering: ${EXCEPTIONS.size} accepted exception(s), ${violations.length} violation(s).`);
  for (const [key, why] of EXCEPTIONS) console.log(`  accepted  ${key}\n            ${why}`);
}

let failed = false;
for (const v of violations) {
  failed = true;
  console.error(`::error::layering: ${v.from} must not import ${v.to} — ${v.key}`);
}
for (const key of stale) {
  failed = true;
  console.error(`::error::layering: exception "${key}" no longer matches a real import. Delete it from EXCEPTIONS in scripts/check-layering.mjs.`);
}

if (failed) {
  console.error("\nSee docs/restructure-plan.md § Layering rule.");
  process.exit(1);
}
console.log(`✓ layering clean (${EXCEPTIONS.size} accepted exception(s), all still real)`);
