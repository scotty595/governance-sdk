/**
 * CORE_VERSION is what a plugin's `requires.core` range is checked against,
 * so it must not drift from the published package version.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CORE_VERSION } from "./index.js";

describe("CORE_VERSION", () => {
  it("matches the package version", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version: string };
    assert.equal(CORE_VERSION, pkg.version, "CORE_VERSION in src/index.ts is out of step with package.json");
  });
});
