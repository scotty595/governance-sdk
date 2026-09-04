#!/usr/bin/env node
/**
 * Plug this checkout's governance-sdk into a consumer project, reversibly.
 *
 *   npm run plug -- <consumer-dir>            # pack, then swap the tarball into
 *                                            #   <consumer>/node_modules/governance-sdk
 *   npm run plug -- <consumer-dir> --link     # symlink packages/governance instead
 *                                            #   (live: `tsc -b --watch` here shows up there)
 *   npm run plug -- <consumer-dir> --unplug   # put the consumer's own copy back
 *
 * The consumer's installed copy is moved to node_modules/.governance-sdk.plug-backup
 * and restored by --unplug; package.json and the lockfile are never touched, so
 * the consumer's git tree stays clean. Re-running plug refreshes the copy.
 *
 * Copy mode is what a user installs — the self-contained tarball, bundled
 * dependencies inside. Link mode resolves `@governance-sdk/*` and optional
 * peers from this repo's node_modules (Node follows the symlink to its real
 * path), so it is for iterating, not for the final check.
 */

import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const consumerArg = args.find((a) => !a.startsWith("--"));
const unplug = args.includes("--unplug");
const link = args.includes("--link");
if (!consumerArg) fail("usage: plug-into.mjs <consumer-dir> [--link] [--unplug]");

const consumer = path.resolve(consumerArg);
const nm = path.join(consumer, "node_modules");
const target = path.join(nm, "governance-sdk");
const backup = path.join(nm, ".governance-sdk.plug-backup");
const marker = path.join(target, ".plugged-from.json");
if (!existsSync(nm)) fail(`${consumer} has no node_modules — install the consumer first`);

if (unplug) {
  if (!existsSync(backup)) { console.log(`nothing plugged into ${consumer}`); process.exit(0); }
  rmSync(target, { recursive: true, force: true });
  renameSync(backup, target);
  console.log(`unplugged: ${consumer} is back on governance-sdk ${version(target)}`);
  process.exit(0);
}

const plugged = existsSync(backup);
if (!plugged) {
  if (!existsSync(target)) fail(`${target} does not exist — the consumer does not have governance-sdk installed`);
  renameSync(target, backup);
} else {
  rmSync(target, { recursive: true, force: true });
}

const sha = execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
if (link) {
  symlinkSync(path.join(root, "packages/governance"), target, "dir");
} else {
  const tarball = execFileSync(process.execPath, [path.join(root, "scripts/pack-meta.mjs")], { cwd: root, encoding: "utf8" }).trim().split("\n").pop();
  mkdirSync(target, { recursive: true });
  execFileSync("tar", ["-xzf", tarball, "-C", target, "--strip-components=1"]);
}
if (!link) writeFileSync(marker, JSON.stringify({ from: root, commit: sha, mode: "copy", at: new Date().toISOString(), restore: "npm run plug -- <consumer> --unplug" }, null, 2) + "\n");

const was = version(backup);
console.log(`${plugged ? "refreshed" : "plugged"}: ${consumer} now resolves governance-sdk ${version(target)} (${link ? "symlink to" : "tarball from"} ${root} @ ${sha}); its own ${was} is kept at node_modules/.governance-sdk.plug-backup`);
console.log(`unplug with: npm run plug -- ${consumerArg} --unplug`);

function version(dir) {
  try { return JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8")).version; } catch { return "?"; }
}
function fail(message) { console.error(`plug-into: ${message}`); process.exit(1); }
