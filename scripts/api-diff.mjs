#!/usr/bin/env node
import { readFileSync } from "node:fs";
const [a, b] = process.argv.slice(2).map((p) => JSON.parse(readFileSync(p, "utf8")));
const subs = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
let removedSyms = 0, addedSyms = 0, changedKind = 0, runtimeRemoved = 0;
for (const s of subs) {
  const A = a[s], B = b[s];
  if (!A) { console.log(`+ subpath ${s} (${Object.keys(B.symbols).length} symbols)`); addedSyms += Object.keys(B.symbols).length; continue; }
  if (!B) { console.log(`- subpath ${s} REMOVED (${Object.keys(A.symbols).length} symbols)`); removedSyms += Object.keys(A.symbols).length; continue; }
  const rem = Object.keys(A.symbols).filter((k) => !(k in B.symbols));
  const add = Object.keys(B.symbols).filter((k) => !(k in A.symbols));
  const kind = Object.keys(A.symbols).filter((k) => k in B.symbols && A.symbols[k] !== B.symbols[k]);
  const rtRem = A.runtime.filter((k) => !B.runtime.includes(k));
  const failA = A.runtime[0]?.startsWith("<import failed"), failB = B.runtime[0]?.startsWith("<import failed");
  if (rem.length || kind.length || rtRem.length || failA !== failB) {
    console.log(`! ${s}: removed=[${rem}] kindChanged=[${kind.map((k) => `${k}:${A.symbols[k]}→${B.symbols[k]}`)}] runtimeRemoved=[${rtRem}] importMain=${failA ? "FAIL" : "ok"} importBranch=${failB ? "FAIL" : "ok"}`);
  } else if (add.length) {
    console.log(`  ${s}: +${add.length} added (${add.slice(0, 6).join(", ")}${add.length > 6 ? ", …" : ""})`);
  }
  removedSyms += rem.length; addedSyms += add.length; changedKind += kind.length; runtimeRemoved += rtRem.length;
}
console.log(`\nTOTAL: subpaths main=${Object.keys(a).length} branch=${Object.keys(b).length}; symbols removed=${removedSyms} added=${addedSyms} kindChanged=${changedKind}; runtime keys removed=${runtimeRemoved}`);
console.log(`import failures: main=${Object.entries(a).filter(([, r]) => r.runtime[0]?.startsWith("<import failed")).map(([k]) => k)} branch=${Object.entries(b).filter(([, r]) => r.runtime[0]?.startsWith("<import failed")).map(([k]) => k)}`);
