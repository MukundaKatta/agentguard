# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

Production-polish branch (this PR): adds `CODE_OF_CONDUCT.md`, `CODEOWNERS` with security-critical paths called out, Dependabot config, issue + PR templates (with a security-routing block), release workflow with npm provenance OIDC + zero-runtime-deps gate, expanded CI (macOS + Windows spot-checks, coverage gate that runs the existing thresholds, `npm pack` content check, and a deny-by-default smoke that asserts the firewall actually blocks a fetch to an un-allowlisted host). README gets a CI badge + runtime-deps=0 badge. No source changes; the policy engine and fetch wrapper are untouched.

## [0.1.2] — 2026-04-28

### Fixed
- **Security:** `matchHost` now strips `[ ]` IPv6 brackets and lowercases
  patterns before comparison. Previously a deny rule like `["::1"]` would
  fail to match `http://[::1]/`, because `URL.hostname` returns the bracketed
  form. An attacker controlling the request URL could SSRF the loopback by
  switching from `http://localhost` to `http://[::1]`. **Anyone using
  agentguard to defend against SSRF should upgrade.**
- README: fixed the `block` mode recipe — was `const policy({...})` (missing
  assignment), now correctly assigns to `blockingPolicy` and shows it inside
  a `firewall()` block.

### Added
- 11 new SSRF regression tests in `test/policy.test.js`: localhost, 127.0.0.1,
  AWS IMDS (`169.254.169.254`), GCE bare `metadata` host, bracketed and
  unbracketed IPv6 loopback, case-insensitive allowlist, default-deny,
  invalid-URL fallback, method-blocked, lowercase-method allow.
- `c8` coverage tooling: `npm run test:coverage` reports per-file coverage and
  fails the build below 75% branches / 85% lines/functions/statements.
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`.

## [0.1.1] — 2026-04-25

Initial published release. Core API stable: `policy()`, `check()`,
`firewall()`, `wrapFetch()`, `PolicyViolation`, `blockResponse`. CLI for
ad-hoc and batch URL checks. TypeScript types. CI matrix on Node 20/22/24.

## [0.1.0]

Initial commit / placeholder for pre-release tagging.
