#!/usr/bin/env node
/**
 * Build a self-contained `governance-sdk` tarball.
 *
 * The meta-package depends on three private workspace packages. `npm pack`
 * does not bundle workspace-linked dependencies — even with
 * `bundleDependencies` declared it emits the same tarball, and the declaration
 * then makes `npm install` succeed and the first `import` fail. So this script
 * stages a real directory: the meta-package's publishable files plus a
 * materialised `node_modules/@governance-sdk/*` holding each dependency's
 * manifest and `dist`, and packs that. The result installs anywhere with no
 * registry lookup for the scoped packages.
 *
 *   npm run build && node scripts/pack-meta.mjs [--out <dir>]
 *
 * Prints the tarball path. `scripts/verify-pack.mjs` installs it into a fresh
 * project and imports every subpath; CI runs both.
 */

import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const meta = path.join(root, "packages/governance");
const outArg = process.argv.indexOf("--out");
const outDir = outArg > -1 && process.argv[outArg + 1] ? path.resolve(process.argv[outArg + 1]) : path.join(root, "dist");

const manifest = JSON.parse(readFileSync(path.join(meta, "package.json"), "utf8"));
const bundled = manifest.bundleDependencies ?? [];
if (bundled.length === 0) fail("packages/governance/package.json declares no bundleDependencies; nothing to bundle");

/** Workspace directory for a scoped package name. */
function workspaceDir(name) {
  const short = name.split("/")[1];
  const dir = path.join(root, "packages", short);
  if (!existsSync(path.join(dir, "package.json"))) fail(`${name}: no workspace at packages/${short}`);
  return dir;
}

for (const dir of [meta, ...bundled.map(workspaceDir)]) {
  if (!existsSync(path.join(dir, "dist", "index.js"))) fail(`${path.relative(root, dir)}/dist is missing — run \`npm run build\` first`);
}

const staging = mkdtempSync(path.join(tmpdir(), "governance-sdk-pack-"));
try {
  // The meta-package itself: what its `files` field would ship.
  for (const f of ["package.json", "README.md", "LICENSE"]) cpSync(path.join(meta, f), path.join(staging, f));
  cpSync(path.join(meta, "dist"), path.join(staging, "dist"), { recursive: true, filter: publishable });

  // Each bundled dependency, materialised where node resolution will find it.
  for (const name of bundled) {
    const src = workspaceDir(name);
    const dest = path.join(staging, "node_modules", name);
    mkdirSync(dest, { recursive: true });
    const pkg = JSON.parse(readFileSync(path.join(src, "package.json"), "utf8"));
    // The manifest ships without workspace-only fields. `private` stays: it is
    // a statement about publishing this package on its own, which remains true.
    delete pkg.scripts;
    delete pkg.devDependencies;
    writeFileSync(path.join(dest, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
    cpSync(path.join(src, "dist"), path.join(dest, "dist"), { recursive: true, filter: publishable });
    cpSync(path.join(root, "LICENSE"), path.join(dest, "LICENSE"));
  }

  mkdirSync(outDir, { recursive: true });
  const json = execFileSync("npm", ["pack", "--ignore-scripts", "--json", "--pack-destination", outDir], {
    cwd: staging, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"],
  });
  const [info] = JSON.parse(json);
  const tarball = path.join(outDir, info.filename);

  // Prove the bundle is actually in there; this is the failure mode the script exists for.
  const listing = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" });
  for (const name of bundled) {
    const entry = `package/node_modules/${name}/dist/index.js`;
    if (!listing.includes(entry + "\n")) fail(`${info.filename} does not contain ${entry}`);
  }
  if (/\/src\/|\.test\.js|\.tsbuildinfo/.test(listing)) fail(`${info.filename} contains source, tests or build state`);

  console.log(tarball);
} finally {
  rmSync(staging, { recursive: true, force: true });
}

/** Only compiled output ships: no build state, no maps, no compiled tests. */
function publishable(src) {
  const base = path.basename(src);
  if (base.endsWith(".tsbuildinfo") || base.endsWith(".map")) return false;
  if (/\.test\.(js|d\.ts)$/.test(base)) return false;
  return true;
}

function fail(message) {
  console.error(`pack-meta: ${message}`);
  process.exit(1);
}
