# Security Policy

## Supported Versions

Security fixes land on the latest 0.x release only.

| Version | Supported |
|---------|-----------|
| 0.21.x  | ✅        |
| < 0.21  | ❌        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately through GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/scotty595/governance-sdk/security/advisories/new)**
(Security tab → *Report a vulnerability*). Include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Impact assessment (if known)

## What to Expect

- **Acknowledgment** within 48 hours
- **Assessment** within 5 business days
- **Fix timeline** communicated after assessment

## Scope

The following are considered security issues:

- Injection detection bypasses
- Audit trail integrity vulnerabilities (hash chain tampering)
- Policy enforcement bypasses
- Kill switch circumvention
- Authentication/authorization issues in remote enforcement

Also in scope: a detector or policy condition whose evaluation time grows
super-linearly on inputs within the configured `maxInputLength` (regex
backtracking that lets a tool result stall the event loop is a denial of
service, not a performance nit — see `injection-redos.test.ts`).

The following are **not** security issues:

- Injection detection false positives/negatives for edge cases (report as a regular issue)
- Performance degradation on inputs beyond the configured size limits
- Issues in peer dependency frameworks

The guarantees the SDK makes, and the limits it states, are listed in
[docs/guarantees.md](./docs/guarantees.md); the threat model is in
[docs/threat-model.md](./docs/threat-model.md).

## Responsible Disclosure

We ask that you give us reasonable time to address vulnerabilities before public disclosure. We will credit reporters in release notes (unless you prefer anonymity).
