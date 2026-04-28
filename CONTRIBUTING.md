# Contributing to agentguard

Small, focused PRs welcome. Big design changes — open an issue first so we
can sanity-check direction before you build.

## Setup

```sh
gh repo clone MukundaKatta/agentguard
cd agentguard
npm install
```

## Run

```sh
npm test                 # 47 tests, runs on Node's built-in runner
npm run test:coverage    # gates at 75% branches / 85% lines+functions+statements
npm run test:examples    # runs the example snippets so they don't rot
```

If you're touching policy matching, add a regression test under
`test/policy.test.js`. If you're touching the CLI, add a fixture-based test
under `test/cli.test.js`.

## Style

- Plain ESM, zero runtime dependencies. If you think you need a dep, open an
  issue — likely the answer is "no, but here's the inline pattern."
- One PR = one focused change. Refactors that touch multiple modules go in
  their own PR with a quick design note.
- No emojis in source comments unless the comment is illustrating user-facing
  text.

## Releases

This repo uses semver:
- `0.1.x` patch releases: bug fixes, security fixes, no API change.
- `0.2.0` minor release will require an explicit migration note in the README.

## Reporting a security issue

Don't open a public issue. See [SECURITY.md](./SECURITY.md).
