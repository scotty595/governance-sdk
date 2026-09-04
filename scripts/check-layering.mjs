#!/usr/bin/env node
/**
 * Layering lint — the single rule that stops the kernel re-growing.
 *
 * Before the package split this compared paths. Now the layers are real
 * packages, so it compares what a package IMPORTS against what it DECLARES:
 *
 *   @governance-sdk/core      the kernel. Declares no dependencies, and must
 *                             import none. This is the whole point.
 *   @governance-sdk/plugins   detection, standards, scoring, identity, sinks,
 *                             policy authoring. May import core.
 *   @governance-sdk/adapters  framework adapters, the adapter kernel, the
 *                             Agent Hooks conformance surface. May import core
 *                             and plugins.
 *   governance-sdk            the meta-package: re-exports every layer under
 *                             one name and wires the default extension set.
 *
 * Two things this catches that `tsc` alone does not: an undeclared dependency
 * that only works because npm hoisted it, and a *test* reaching across a
 * boundary its package does not declare — tests are excluded from the build
 * graph, so they are exactly where a boundary quietly rots.
 *
 * Usage: node scripts/check-layering.mjs [--list]
 */

import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolvePath(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES = ["core", "plugins", "adapters", "governance"];

/** What each package is permitted to depend on, by design. */
const ALLOWED = {
  "@governance-sdk/core": new Set([]),
  "@governance-sdk/plugins": new Set(["@governance-sdk/core"]),
  "@governance-sdk/adapters": new Set(["@governance-sdk/core", "@governance-sdk/plugins"]),
  "governance-sdk": new Set([
    "@governance-sdk/core",
    "@governance-sdk/plugins",
    "@governance-sdk/adapters",
  ]),
};

/**
 * Packages a test file may reach for beyond its package's runtime deps. A test
 * of the kernel that needs the assembled system is legitimate — it is testing
 * what a user gets — as long as it is a devDependency and never a runtime one.
 */
const TEST_ONLY_ALLOWED = new Set(["governance-sdk"]);

function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

const SPEC_RE = /(?:import|export)\s[^;]*?from\s+["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;

/**
 * Strip comments and template literals before scanning.
 *
 * Without this the lint reads the `import` lines inside JSDoc examples, and
 * the scaffold the CLI writes into a user's project, as if they were real
 * imports — which is how a doc comment ends up "violating" a layer.
 */
function stripNonCode(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/`(?:\\.|[^`\\])*`/g, "``");
}

const violations = [];
const summary = [];

for (const pkg of PACKAGES) {
  const dir = join(ROOT, "packages", pkg);
  const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const name = manifest.name;
  const declared = new Set(Object.keys(manifest.dependencies ?? {}));
  const declaredDev = new Set(Object.keys(manifest.devDependencies ?? {}));
  const allowed = ALLOWED[name];
  if (!allowed) continue;

  // 1. Declared dependencies must be permitted by the design.
  for (const dep of declared) {
    if (!dep.startsWith("@governance-sdk/") && dep !== "governance-sdk") continue;
    if (!allowed.has(dep)) {
      violations.push(`${name} declares a dependency on ${dep}, which its layer forbids`);
    }
  }

  const used = new Set();
  for (const file of walk(join(dir, "src"))) {
    const rel = relative(dir, file);
    const isTest = file.endsWith(".test.ts");
    const source = stripNonCode(readFileSync(file, "utf8"));
    for (const m of source.matchAll(SPEC_RE)) {
      const spec = m[1] ?? m[2];
      if (!spec || spec.startsWith(".") || spec.startsWith("node:")) continue;
      const owner = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
      if (owner !== "governance-sdk" && !owner.startsWith("@governance-sdk/")) continue;
      used.add(owner);

      // 2. Never import your own package by name — it hides a cycle.
      if (owner === name) {
        violations.push(`${name}: ${rel} imports its own package by name (${spec}); use a relative path`);
        continue;
      }
      // 3. Imports must be within the layer's allowance...
      if (!allowed.has(owner)) {
        if (isTest && TEST_ONLY_ALLOWED.has(owner)) {
          if (!declaredDev.has(owner)) {
            violations.push(`${name}: ${rel} imports ${owner} but it is not a devDependency`);
          }
          continue;
        }
        violations.push(`${name}: ${rel} imports ${owner}, which its layer forbids`);
        continue;
      }
      // 4. ...and declared, so nothing works only because npm hoisted it.
      if (!declared.has(owner) && !(isTest && declaredDev.has(owner))) {
        violations.push(`${name}: ${rel} imports ${owner} but it is not a declared dependency`);
      }
    }
  }
  summary.push(`${name.padEnd(26)} → ${[...used].sort().join(", ") || "nothing"}`);
}

if (process.argv.includes("--list")) {
  console.log("Package dependency graph, as imported:");
  for (const line of summary) console.log("  " + line);
}

if (violations.length > 0) {
  for (const v of violations) console.error(`::error::layering: ${v}`);
  console.error("\nSee docs/restructure-plan.md § Layering rule.");
  process.exit(1);
}
console.log("✓ layering clean — the kernel depends on nothing, and every import is declared");
