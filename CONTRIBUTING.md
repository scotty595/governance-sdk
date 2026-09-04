# Contributing to governance-sdk

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/scotty595/governance-sdk.git
cd governance-sdk

# Install dependencies
npm install

# Build all packages
npm run build

# Run tests
npm test

# Type-check without emitting
npm run lint
```

### Requirements

- Node.js >= 20
- TypeScript >= 5.7

## Project Structure

```
packages/
  governance/          # Core SDK — policy enforcement, scoring, injection detection, framework adapters
  governance-platform/ # PostgreSQL storage layer — auto-migrating schema, org settings
```

## Code Style

- **Files**: `kebab-case.ts`
- **Functions/variables**: `camelCase`
- **No `any` types** — use proper TypeScript types throughout
- **< 300 LOC per file** — split into modules if approaching limit
- **Zero runtime dependencies** on the core SDK — never add to `dependencies`. Framework imports go in `peerDependencies` (optional).

## Making Changes

1. Fork the repository and create a feature branch
2. Make your changes
3. Run `npm test` — all tests must pass
4. Run `npm run build` — must compile clean
5. Submit a pull request

## Adding a Framework Adapter

1. Create `src/plugins/framework-name.ts`
2. Import types only from the framework — never add to `dependencies`
3. Create `src/plugins/framework-name.test.ts` with mock framework objects
4. Add to `package.json` exports AND `peerDependencies` + `peerDependenciesMeta`
5. Add to the framework table in `README.md`

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include tests for new functionality
- Update documentation if the public API changes
- Use imperative mood in commit messages (e.g., "Add rate limit policy", not "Added rate limit policy")

## Reporting Issues

- **Bugs**: Open a [GitHub issue](https://github.com/scotty595/governance-sdk/issues) with steps to reproduce, expected vs. actual behavior, and your Node/SDK version
- **Security vulnerabilities**: See [SECURITY.md](./SECURITY.md) — do not open a public issue
- **Feature requests**: Open a [GitHub issue](https://github.com/scotty595/governance-sdk/issues) describing the use case

## Checking a refactor

The unit suite proves behaviour for code that resolves through workspace
symlinks. Three checks see past that; run them before merging anything that
moves code between packages or touches the exports map.

1. **API surface.** Build `main` in a worktree and diff every subpath's
   exported symbols, kinds and resolved type text against the branch:
   ```sh
   git worktree add /tmp/main-wt main && (cd /tmp/main-wt && npm ci && npm run build)
   node scripts/api-surface.mjs /tmp/main-wt /tmp/api-main.json
   node scripts/api-surface.mjs . /tmp/api-branch.json
   node scripts/api-diff.mjs /tmp/api-main.json /tmp/api-branch.json
   ```
   A removed symbol, a changed kind, a widened union, a changed signature, or
   a subpath that no longer imports is a finding. Decide each one on purpose;
   a name-level diff alone would have missed the widened union that broke a
   downstream consumer during the package split.
2. **The tarball.** `npm run verify-pack` builds the self-contained tarball
   and installs it into a fresh project outside the workspace, then imports
   every subpath and runs the kernel, a standards report and the identity
   plugin from the installed copy. CI runs it on every push.
3. **A real consumer.** Install the tarball into a project that uses the SDK
   and run its typecheck, its tests, and the app itself. `npm run plug`
   swaps the packed tarball into that project's `node_modules` without
   touching its package.json or lockfile, and `--unplug` puts its own copy
   back:
   ```sh
   npm run plug -- ../consumer            # pack + swap in (re-run to refresh)
   (cd ../consumer && npx tsc --noEmit && npm test && npm run dev)
   npm run plug -- ../consumer --unplug   # restore
   ```
   `--link` symlinks `packages/governance` instead, so `tsc -b --watch`
   here shows up there live; use copy mode for the final check, since it is
   what a user installs. Compare any error count with the same run on the
   consumer's own version, so pre-existing errors are not blamed on the change.

## Releasing

Versions are tracked by git tags and the package changelog whether or not
the release goes to npm, so the two never drift.

1. Bump `version` in `packages/governance/package.json` (and
   `packages/governance-platform/package.json` if it changed) and run
   `npm install --package-lock-only` so the lockfile records the new version.
2. Turn the `## [Unreleased]` section of `packages/governance/CHANGELOG.md`
   into `## [<version>] - <YYYY-MM-DD> — <title>`; the title becomes the
   GitHub Release title and the section body becomes its notes.
3. Merge to `main`, then tag and push: `git tag v<version> && git push origin v<version>`.
4. The **Release** workflow (`.github/workflows/release.yml`) verifies the tag
   matches the package version, builds, tests, packs and verifies the tarball,
   creates the GitHub Release, and publishes to npm **only if** the repository
   variable `PUBLISH_TO_NPM` is `true` or the workflow is run manually with
   `publish_npm` checked. While publishing is paused the release notes say so.

The artifact that gets published is the tarball `npm run pack` builds, never
`npm publish -w packages/governance`: `governance-sdk` depends on three
private workspace packages and npm does not bundle workspace links, so a
`-w` publish would ship a package that installs and then fails on its first
`import`. `npm run verify-pack` installs the tarball into a fresh project
and imports every subpath; run it before tagging.

Switching npm publishing back on later needs no code change: set the variable
(or run the workflow manually for any already-tagged version) and the same
steps publish with provenance attestations. Versions that were tagged while
publishing was paused can be published afterwards by running the workflow
manually with their tag.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
