# governance-sdk playground

An interactive React + Vite app for poking at the SDK in a browser. **Local
mode runs the SDK entirely client-side — no account, no API key, no server.**
Hosted mode is optional and targets any governance REST API.

```bash
cd examples/demo-app
npm install
npm run dev
# open http://localhost:5173
```

The app depends on the SDK via `file:../../packages/governance`, so run
`npm install && npm run build` at the repository root first if `dist/` is
missing.

## What you can do

| Tab | Local mode | Hosted mode |
|-----|-----------|-------------|
| **Configure** | Register an agent (name, framework, level) and toggle policy rules: blocked tools, `requireLevel`, injection-guard threshold. A **Generated Code** panel shows the exact `createGovernance({...})` call for what you clicked. | Enter an API URL + key, pick an existing agent (or create one) and inspect the policies the server applies to it. |
| **Test** | Fire prompts and tool calls through the three-stage pipeline — `preprocess` (injection scan) → `process` (tool-call policy) → `postprocess` (output scan/mask) — and watch each stage pass, block, or mask. Presets include a safe message, role-override and encoded injections, an API-key leak, and a PII disclosure. | Same UI; decisions come from the remote `enforce` endpoint. |
| **Audit** | Every scan and decision the session made, in order. | Same, from the session. |

Nothing here talks to an LLM — the point is to see what the governance layer
does *around* one.

## Hosted mode

Hosted mode needs a server that implements the governance REST API the SDK's
remote enforcer expects (documented in [`docs/remote-contract.md`](../../docs/remote-contract.md)).
[Lua Governance Cloud](https://heygovernance.ai) is one such implementation
and is a separate commercial product, not part of this repository. Paste its
URL and an API key into the **Configure** tab to use it.

## Prefer a terminal?

`npx governance-sdk demo` (or `npm run demo` from the repository root) runs
the same enforcement, injection, masking, and audit-chain story in-process in
under a second.
