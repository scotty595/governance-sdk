#!/usr/bin/env node
/**
 * Install the packed `governance-sdk` tarball into a fresh project outside the
 * workspace and use it — the consumer path the workspace's symlinks hide from
 * every unit test. Imports every subpath in the exports map, then runs the
 * kernel, a standards plugin and the identity plugin through the installed
 * copy.
 *
 *   node scripts/pack-meta.mjs && node scripts/verify-pack.mjs [<tarball>]
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const version = JSON.parse(readFileSync(path.join(root, "packages/governance/package.json"), "utf8")).version;
const tarball = path.resolve(process.argv[2] ?? path.join(root, "dist", `governance-sdk-${version}.tgz`));

const consumer = mkdtempSync(path.join(tmpdir(), "governance-sdk-consumer-"));
try {
  writeFileSync(path.join(consumer, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--no-package-lock", tarball], {
    cwd: consumer, stdio: ["ignore", "ignore", "inherit"],
  });

  writeFileSync(path.join(consumer, "probe.mjs"), `
    import { readFileSync } from "node:fs";
    const pkg = JSON.parse(readFileSync(new URL("./node_modules/governance-sdk/package.json", import.meta.url), "utf8"));
    const subpaths = Object.keys(pkg.exports);
    for (const sub of subpaths) await import("governance-sdk" + sub.slice(1));

    const { createGovernance, blockTools } = await import("governance-sdk");
    const gov = createGovernance({ rules: [blockTools(["rm"])] });
    const agent = await gov.register({ name: "probe", owner: "verify-pack", framework: "custom", tools: ["rm", "ls"], hasAuth: true });
    if (!(agent.level >= 1)) throw new Error("scoring extension missing: level " + agent.level);
    const blocked = await gov.enforce({ agentId: agent.id, action: "tool_call", tool: "rm" });
    if (blocked.outcome !== "block") throw new Error("expected block, got " + blocked.outcome);
    const allowed = await gov.enforce({ agentId: agent.id, action: "tool_call", tool: "ls" });
    if (allowed.outcome !== "allow") throw new Error("expected allow, got " + allowed.outcome);

    const { allStandardsPlugins } = await import("governance-sdk/ext/standards");
    for (const p of allStandardsPlugins()) await gov.use(p);
    const report = await gov.report("standards/nist-ai-600-1", { governance: gov, agents: await gov.storage.listAgents() });
    if (typeof report.disclaimer !== "string") throw new Error("600-1 report has no disclaimer");

    const { identityPlugin } = await import("governance-sdk/ext/identity");
    await gov.use(identityPlugin({ verifier: async () => ({ valid: false, reason: "probe" }) }));
    const check = await gov.getVerifier("identity").verify("not.a.token");
    if (check.verified !== false || check.context.identityVerified !== false) throw new Error("identity plugin did not fail closed");

    console.log(JSON.stringify({ subpaths: subpaths.length, plugins: gov.plugins().length, level: agent.level }));
  `);
  const out = execFileSync(process.execPath, ["probe.mjs"], { cwd: consumer, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  const result = JSON.parse(out.trim());
  console.log(`✓ verify-pack: ${path.basename(tarball)} installs standalone; ${result.subpaths} subpaths import; kernel, ${result.plugins} plugins and identity work from the installed copy`);
} finally {
  rmSync(consumer, { recursive: true, force: true });
}
