#!/usr/bin/env node
// Dump the public API of every governance-sdk subpath: exported symbol names
// (types and values, resolved through `export *`) plus the runtime keys.
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
const [root, out] = process.argv.slice(2);
const require = createRequire(path.join(root, "package.json"));
const ts = require("typescript");
const pkgDir = path.join(root, "packages/governance");
const pkg = JSON.parse(readFileSync(path.join(pkgDir, "package.json"), "utf8"));
const entries = Object.entries(pkg.exports).sort(([a], [b]) => a.localeCompare(b));
const program = ts.createProgram(entries.map(([, v]) => path.join(pkgDir, v.types)), {
  module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext,
  target: ts.ScriptTarget.ES2022, skipLibCheck: true,
});
const checker = program.getTypeChecker();
const result = {};
for (const [sub, v] of entries) {
  const sf = program.getSourceFile(path.join(pkgDir, v.types));
  const sym = sf && checker.getSymbolAtLocation(sf);
  const symbols = {};
  for (const e of sym ? checker.getExportsOfModule(sym) : []) {
    const r = (e.flags & ts.SymbolFlags.Alias) ? checker.getAliasedSymbol(e) : e;
    const isValue = !!(r.flags & ts.SymbolFlags.Value), isType = !!(r.flags & ts.SymbolFlags.Type);
    symbols[e.name] = isValue && isType ? "value+type" : isValue ? "value" : "type";
  }
  let runtime;
  try { runtime = Object.keys(await import(pathToFileURL(path.join(pkgDir, v.import)).href)).sort(); }
  catch (err) { runtime = ["<import failed: " + String(err && err.message).split("\n")[0] + ">"]; }
  result[sub] = { symbols, runtime };
}
writeFileSync(out, JSON.stringify(result, null, 2));
console.log(`${out}: ${entries.length} subpaths, ${Object.values(result).reduce((n, r) => n + Object.keys(r.symbols).length, 0)} exported symbols`);
