---
name: Feature request
about: Propose a new policy primitive, a new violation hook, or a behavior change.
title: "[feat] "
labels: enhancement
assignees: ''
---

## Scope check

Before opening, please confirm this proposal fits the project scope:

- [ ] It does **not** add a runtime dependency. (Zero deps is a hard line for a security primitive; PRs adding one will be redirected to discussion first.)
- [ ] It does **not** soften the policy by default. (New features must default to deny-on-conflict; explicit opt-in is required to broaden the allowlist.)
- [ ] It does **not** outsource policy decisions to the network. (No DNS / no remote allowlist fetches at policy-check time. The policy must be deterministic from local inputs.)

If any of those are unchecked, the right home is probably a separate package that depends on agentguard, not agentguard itself.

## What you want

A clear description of the proposed feature.

## Why

What real-world egress-control bug or workflow gap does this address? Concrete example of the traffic shape that would benefit.

## Proposed API shape

```jsonc
// new export, option, or violation hook:
// signature:
// policy spec extension (if applicable):
// failure mode (throw / 403 / both):
```

## Threat-model impact

Does this change the threat model in `SECURITY.md`?

- [ ] No — it adds an orthogonal feature with no bypass surface.
- [ ] Yes — and here is the new surface I'd add to SECURITY.md: ...

## Alternatives considered

What workarounds exist today (deny-list inversion, custom wrapper, undici interceptors) and why aren't they good enough?
