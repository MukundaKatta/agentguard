---
name: Bug report (non-security)
about: Non-bypass bugs only — error messages, false positives that block legitimate traffic, CLI issues, type definitions.
title: "[bug] "
labels: bug
assignees: ''
---

> ⚠ **Found a way to bypass the allowlist?** Stop. That is a security issue.
> Please use [GitHub's private vulnerability reporting](https://github.com/MukundaKatta/agentguard/security/advisories/new) instead of this template. See `SECURITY.md` for the full scope and disclosure timeline.

## What happened

A clear, concise description of the actual behavior.

## What you expected

A clear, concise description of what should have happened.

## Reproduction

Minimal repro using only this library:

```js
import { policy, firewall, PolicyViolation } from '@mukundakatta/agentguard';

const p = policy({
  allow: ['api.example.com'],
  // ...
});

await firewall(p, async () => {
  const r = await fetch('https://api.example.com/v1/ping');
  // observed: ...
  // expected: ...
});
```

If this is **a false-positive denial** (legitimate request got blocked), please also include:

- The exact URL that was denied.
- The full policy spec (`allow`, `deny`, `mode`, anything custom).
- The `PolicyViolation` error message you received.

If this is **a CLI bug** (`npx agentguard ...`), please paste the exact command.

## Environment

- agentguard version: (`npm ls @mukundakatta/agentguard`)
- Node version: (`node --version` — agentguard requires Node 20+)
- OS: (macOS 14 / Ubuntu 22.04 / Windows 11)
- Where the wrapped fetch lives: (your own code / a provider SDK / an MCP client / an agent framework)

## Notes

Anything else — whether you're using `firewall(...)` or the bare `policy(url)` check, whether the URL went through any normalization in your code first, whether DNS for the host returns IPv4 / IPv6 / both.
