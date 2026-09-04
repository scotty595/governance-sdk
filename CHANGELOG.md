# Changelog

Per-package changelogs live alongside each package:

- [packages/governance/CHANGELOG.md](./packages/governance/CHANGELOG.md) — `governance-sdk` (core SDK)
- `packages/governance-platform/` — `governance-sdk-platform` (see git history; single-package changelog pending)

Releases are tagged `v<version>` on the core SDK (e.g. `v0.22.0`). Every tag
produces a GitHub Release with notes taken from the package changelog. npm
publishing is a separate, switchable step of the same workflow (repository
variable `PUBLISH_TO_NPM`, or a manual run with `publish_npm`); it is
currently paused, so the npm registry can lag the latest tag. See
[CONTRIBUTING.md](./CONTRIBUTING.md#releasing).
