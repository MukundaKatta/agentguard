# agentguard

[![npm version](https://img.shields.io/npm/v/@mukundakatta/agentguard.svg)](https://www.npmjs.com/package/@mukundakatta/agentguard)
[![npm downloads](https://img.shields.io/npm/dm/@mukundakatta/agentguard.svg)](https://www.npmjs.com/package/@mukundakatta/agentguard)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Node](https://img.shields.io/node/v/@mukundakatta/agentguard.svg)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-47%2F47-brightgreen.svg)](./test)

**Network egress firewall for AI agents.** Declarative allowlist of domains an agent's tools can fetch; throws (or returns a 403) on anything else. Zero runtime dependencies. Drop it around any code that calls `fetch()`, including SDK clients you don't control.

```bash
npm install @mukundakatta/agentguard
```

```js
import { firewall, policy, PolicyViolation } from '@mukundakatta/agentguard';

const safe = policy({
  network: {
    allow: ['api.openai.com', 'api.anthropic.com', '*.example.com'],
    methods: ['GET', 'POST'],
  },
  budget: { maxRequests: 50 },
  violations: 'throw',
});

await firewall(safe, async () => {
  await myAgent.run('summarize today\'s news'); // any fetch outside the allowlist throws
});
```

If a tool call (or a model-driven SDK request) tries to hit a host that isn't on the list, `PolicyViolation` is thrown with `reason`, `detail`, `url`, and `method` set. Catch it, log it, page yourself, route to a human approver. Whatever your security model is, this gives you the seam.

TypeScript types ship in the box.

### See it in action

```bash
git clone https://github.com/MukundaKatta/agentguard && cd agentguard
node examples/demo-block.js
```

Three scenarios — happy path, throw on prompt-injection-driven exfiltration, and the same scenario in `block` mode (returns a 403 instead of throwing).

## Why

When you give an LLM tool-use access to `fetch` (or any SDK that uses fetch under the hood), you're trusting the model not to call hosts you didn't intend. That trust breaks when:

- A **prompt injection** convinces the model to fetch attacker-controlled URLs (data exfiltration via URL parameters, DNS lookups, etc.).
- A **model upgrade** silently changes which APIs the agent decides to hit.
- A **dependency update** to your tools or SDK quietly adds new endpoints (telemetry, fallback hosts).
- A **CI test run** accidentally hits production APIs because someone forgot to mock.

`agentguard` treats agent-driven HTTP as untrusted by default and gives you a one-line opt-in for what's allowed.

## API

### `policy(spec) → Policy`

Validate + freeze a policy declaration. Throws `TypeError` on a malformed spec.

```js
const p = policy({
  network: {
    allow: ['api.openai.com'],
    deny: ['*.internal.corp'],
    methods: ['GET', 'POST'],
  },
  budget: { maxRequests: 100 },
  violations: 'throw',
});
```

Host patterns:
- exact host: `'api.openai.com'`
- wildcard subdomain: `'*.example.com'` (matches `example.com` and any subdomain)
- global wildcard: `'*'` (useful as a catch-all in `deny`)

Deny rules win over allow rules.

### `firewall(spec, fn) → Promise`

Run `fn` with `globalThis.fetch` wrapped to enforce the policy. Reverted on exit (including on exceptions). Concurrent `firewall()` calls each get their own AsyncLocalStorage frame and don't conflict.

```js
await firewall(p, async () => {
  await myAgent.run('do task'); // any fetch inside is policy-checked
});
```

### `wrapFetch(spec) → fetch`

Get a fetch function that applies the policy without monkey-patching the global. Use this when you can pass `fetch` into an SDK directly:

```js
import Anthropic from '@anthropic-ai/sdk';
import { wrapFetch, policy } from '@mukundakatta/agentguard';

const client = new Anthropic({
  fetch: wrapFetch(policy({ network: { allow: ['api.anthropic.com'] } })),
});
```

Each `wrapFetch()` call returns a fresh fetch with its own internal request counter; budgets are per-fetch-instance.

### `check(policy, url, init?) → Decision`

Pure decision function. No side effects. Use this if you want to enforce the policy in a transport other than fetch (e.g. an HTTP/2 client) or to test policies in isolation.

```js
const decision = check(p, 'https://evil.com', { method: 'GET' });
// { action: 'deny', reason: 'not_in_allowlist', detail: 'evil.com' }
```

### `PolicyViolation`

Thrown by `firewall()` when a request is denied (default behavior). Catch programmatically:

```js
try {
  await firewall(p, fn);
} catch (err) {
  if (err instanceof PolicyViolation) {
    console.error(err.reason, err.url, err.detail);
  }
}
```

Stable `reason` codes:
- `not_in_allowlist` — host wasn't matched by any `allow` pattern
- `denylist_match` — host matched a `deny` pattern
- `method_blocked` — HTTP method not in `network.methods`
- `budget_exceeded` — `budget.maxRequests` was exceeded
- `invalid_url` — couldn't parse the URL

## Recipes

### CI agent that must not hit prod

```js
const ciPolicy = policy({
  network: {
    allow: ['localhost', '127.0.0.1', '*.test.invalid'],
    deny: ['*'],
  },
});
await firewall(ciPolicy, () => runMyAgentTests());
```

### Tight agent in production: only its known LLM provider

```js
const prodPolicy = policy({
  network: { allow: ['api.anthropic.com'] },
  budget: { maxRequests: 200 },
});
await firewall(prodPolicy, () => myAgent.handle(userRequest));
```

### Agent that needs the whole web but not your internal network

```js
const webPolicy = policy({
  network: {
    deny: ['*.internal.corp', '169.254.169.254', 'localhost', '127.0.0.1'],
    // no allow → everything else is permitted
  },
});
await firewall(webPolicy, () => researchAgent.run(query));
```

(`169.254.169.254` is the EC2/GCP/Azure metadata service — a classic SSRF target.)

### `block` mode: 403 instead of throw

```js
const blockingPolicy = policy({
  network: { allow: ['api.openai.com'] },
  violations: 'block',
});

await firewall(blockingPolicy, async () => {
  // blocked requests now return a synthetic 403 Response with
  // `x-agentguard-block: 1` headers. Useful when you want the agent to
  // see the rejection and recover, rather than crashing.
});
```

## CLI

`@mukundakatta/agentguard` ships an `agentguard` binary for one-off URL checks and CI-time policy validation:

```bash
# Validate a policy file before deploying it
npx -p @mukundakatta/agentguard agentguard validate-policy --policy policy.json

# Check a single URL against a policy (exit 1 if blocked)
npx -p @mukundakatta/agentguard agentguard check https://api.openai.com/v1/chat \
  --policy policy.json --method POST

# Bulk-check URLs from a file (or stdin via `-`); exits 1 if any are denied
cat candidate-urls.txt | npx -p @mukundakatta/agentguard agentguard check-batch - \
  --policy policy.json
```

Output is one JSON object per check on stdout (use `--pretty` for indented). Exit code is `0` when allowed/valid, `1` when denied/invalid, `2` on usage errors. Run `agentguard --help` for the full subcommand reference.

## What this is not

- **Not a sandbox.** Determined code can monkey-patch around `fetch` itself or use other transports (`net.connect`, `dgram`, raw HTTP/2). For hard isolation, use OS-level network namespaces, Linux `iptables`, k8s `NetworkPolicy`, or Firecracker microVMs (e2b, etc).
- **Not auth.** It blocks by host, not by user. Combine with proper auth at the API layer.
- **Not exhaustive.** v0.1 covers fetch-based egress only. File and shell egress are out of scope (would require monkey-patching `node:fs` and `node:child_process`, which is invasive enough to break other libraries' assumptions).

The right framing: `agentguard` is a *seatbelt for tool-use*. It catches accidents and most opportunistic attacks. Pair it with sandboxing, secret management, and auth for defense-in-depth.

## Sibling libraries

Part of the agent reliability stack — all `@mukundakatta/*` scoped, all zero-dep:

- [`@mukundakatta/agentfit`](https://www.npmjs.com/package/@mukundakatta/agentfit) — fit messages to budget. *Fit it.*
- [`@mukundakatta/agentsnap`](https://www.npmjs.com/package/@mukundakatta/agentsnap) — snapshot tests for tool-call traces. *Test it.*
- **`@mukundakatta/agentguard`** — network egress firewall. *Sandbox it.* (this)
- [`@mukundakatta/agentvet`](https://www.npmjs.com/package/@mukundakatta/agentvet) — tool-arg validator. *Vet it.*
- [`@mukundakatta/agentcast`](https://www.npmjs.com/package/@mukundakatta/agentcast) — structured output enforcer. *Validate it.*

Natural pipeline: **fit → guard → snap → vet → cast**.

## Status

v0.1.2 — security fix release. Core API stable. TypeScript types included. 47/47 tests, CI on Node 20/22/24.

**v0.2 plans** (post-real-world-feedback):
- Per-tool rate limits (e.g. "search_web: 10/min")
- Cost tracking integration (estimate $/run from request volume)
- Pluggable transports beyond fetch (OpenAI streaming, MCP stdio)
- Audit logging hook (every allow/deny → your sink of choice)

## License

MIT
