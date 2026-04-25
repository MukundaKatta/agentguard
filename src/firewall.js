import { AsyncLocalStorage } from 'node:async_hooks';

import { policy as makePolicy, check } from './policy.js';
import { PolicyViolation, blockResponse } from './violations.js';

const policyStore = new AsyncLocalStorage();

// We monkey-patch globalThis.fetch only while at least one firewall() call is
// active. The patch is reference-counted so nested + concurrent firewall()
// calls behave correctly (each contributes its own AsyncLocalStorage frame;
// the patched fetch dispatches on whichever policy is active for the current
// async context).
let savedFetch = null;
let activeBlocks = 0;

function ensurePatched() {
  if (activeBlocks === 0) {
    savedFetch = globalThis.fetch;
    globalThis.fetch = guardedFetch;
  }
  activeBlocks++;
}

function release() {
  activeBlocks--;
  if (activeBlocks === 0 && savedFetch) {
    globalThis.fetch = savedFetch;
    savedFetch = null;
  }
}

async function guardedFetch(url, init = {}) {
  const ctx = policyStore.getStore();
  // No active policy frame for this async context — fall through to the
  // original fetch. (Can happen if callbacks escape the firewall block via
  // setImmediate/etc. and lose the AsyncLocalStorage chain.)
  if (!ctx) return savedFetch(url, init);

  return runDecision(ctx.policy, ctx, url, init, savedFetch);
}

async function runDecision(policy, ctx, url, init, fetcher) {
  let decision = check(policy, url, init);

  if (decision.action === 'allow') {
    if (ctx) ctx.requestCount++;
    if (
      policy.budget?.maxRequests != null &&
      ctx &&
      ctx.requestCount > policy.budget.maxRequests
    ) {
      decision = {
        action: 'deny',
        reason: 'budget_exceeded',
        detail: `${ctx.requestCount}/${policy.budget.maxRequests}`,
      };
    }
  }

  if (decision.action === 'deny') {
    const v = new PolicyViolation(
      decision.reason,
      decision.detail,
      String(url),
      (init.method ?? 'GET').toUpperCase()
    );
    if (policy.violations === 'throw') throw v;
    return blockResponse(v);
  }

  return fetcher(url, init);
}

/**
 * Run an async function with globalThis.fetch wrapped to enforce the policy.
 * Returns whatever fn returns. The fetch patch is reverted on exit (including
 * on exceptions).
 *
 * @template T
 * @param {import('./policy.js').PolicySpec | import('./policy.js').Policy} spec
 * @param {() => Promise<T> | T} fn
 * @returns {Promise<T>}
 */
export async function firewall(spec, fn) {
  const policy = isNormalized(spec) ? spec : makePolicy(spec);
  const ctx = { policy, requestCount: 0 };
  ensurePatched();
  try {
    return await policyStore.run(ctx, () => fn());
  } finally {
    release();
  }
}

/**
 * Get a fetch function that applies the policy without monkey-patching the
 * global. Use this when you can pass `fetch` into an SDK directly:
 *
 *   const client = new Anthropic({ fetch: wrapFetch(myPolicy) });
 *
 * Each returned fetch has its own request counter; budgets are per-fetch-instance.
 *
 * @param {import('./policy.js').PolicySpec | import('./policy.js').Policy} spec
 * @returns {typeof fetch}
 */
export function wrapFetch(spec) {
  const policy = isNormalized(spec) ? spec : makePolicy(spec);
  const local = { policy, requestCount: 0 };
  return async function guardedFetchInstance(url, init = {}) {
    const fetcher = savedFetch ?? globalThis.fetch;
    return runDecision(policy, local, url, init, fetcher);
  };
}

function isNormalized(value) {
  return (
    value != null &&
    typeof value === 'object' &&
    'violations' in value &&
    Object.isFrozen(value)
  );
}
