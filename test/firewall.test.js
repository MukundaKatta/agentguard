import { test } from 'node:test';
import assert from 'node:assert/strict';

import { firewall, wrapFetch } from '../src/firewall.js';
import { PolicyViolation } from '../src/violations.js';

/**
 * The firewall monkey-patches globalThis.fetch. To keep tests hermetic and
 * avoid making real network requests, we install a stub fetch on the test's
 * global before each block — the firewall wraps THAT, and our stub is what
 * gets called when a request is allowed through.
 */
async function withStubFetch(handler, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => handler(String(url), init ?? {});
  try {
    // MUST await: a sync `return fn()` lets the finally restore globalThis.fetch
    // between the user's awaits, so any fetch after the first bypasses the firewall.
    return await fn();
  } finally {
    globalThis.fetch = original;
  }
}

test('firewall() allows whitelisted hosts to reach the underlying fetch', async () => {
  let called = null;
  await withStubFetch(
    (url) => {
      called = url;
      return new Response('ok', { status: 200 });
    },
    async () => {
      await firewall({ network: { allow: ['api.openai.com'] } }, async () => {
        const r = await fetch('https://api.openai.com/v1/chat');
        assert.equal(r.status, 200);
      });
      assert.equal(called, 'https://api.openai.com/v1/chat');
    }
  );
});

test('firewall() throws PolicyViolation on a blocked host (default)', async () => {
  await withStubFetch(
    () => new Response('should not reach'),
    async () => {
      await assert.rejects(
        () =>
          firewall({ network: { allow: ['api.openai.com'] } }, async () => {
            await fetch('https://internal.corp/exfil');
          }),
        (err) => err instanceof PolicyViolation && err.reason === 'not_in_allowlist'
      );
    }
  );
});

test("firewall() returns a 403 Response when violations: 'block'", async () => {
  await withStubFetch(
    () => new Response('should not reach'),
    async () => {
      let response;
      await firewall(
        { network: { allow: ['api.openai.com'] }, violations: 'block' },
        async () => {
          response = await fetch('https://internal.corp');
        }
      );
      assert.equal(response.status, 403);
      assert.equal(response.headers.get('x-agentguard-block'), '1');
      const body = await response.json();
      assert.equal(body.error, 'PolicyViolation');
      assert.equal(body.reason, 'not_in_allowlist');
    }
  );
});

test('firewall() restores the original fetch on exit (success)', async () => {
  await withStubFetch(
    () => new Response('ok'),
    async () => {
      const before = globalThis.fetch;
      await firewall({ network: { allow: ['x.com'] } }, async () => {
        assert.notEqual(globalThis.fetch, before, 'fetch should be patched inside');
      });
      assert.equal(globalThis.fetch, before, 'fetch should be restored after');
    }
  );
});

test('firewall() restores the original fetch on exit (exception)', async () => {
  await withStubFetch(
    () => new Response('ok'),
    async () => {
      const before = globalThis.fetch;
      await assert.rejects(() =>
        firewall({ network: { allow: ['x.com'] } }, async () => {
          throw new Error('boom');
        })
      );
      assert.equal(globalThis.fetch, before);
    }
  );
});

test('firewall() restores fetch even when PolicyViolation throws', async () => {
  await withStubFetch(
    () => new Response('ok'),
    async () => {
      const before = globalThis.fetch;
      await assert.rejects(
        () =>
          firewall({ network: { allow: ['x.com'] } }, async () => {
            await fetch('https://blocked.com');
          }),
        PolicyViolation
      );
      assert.equal(globalThis.fetch, before);
    }
  );
});

test('firewall() enforces budget.maxRequests', async () => {
  await withStubFetch(
    () => new Response('ok'),
    async () => {
      await assert.rejects(
        () =>
          firewall(
            {
              network: { allow: ['x.com'] },
              budget: { maxRequests: 2 },
            },
            async () => {
              await fetch('https://x.com/1');
              await fetch('https://x.com/2');
              await fetch('https://x.com/3'); // boom
            }
          ),
        (err) => err instanceof PolicyViolation && err.reason === 'budget_exceeded'
      );
    }
  );
});

test('concurrent firewall() calls do not cross-contaminate policies', async () => {
  await withStubFetch(
    (url) => new Response(url),
    async () => {
      const [r1, r2] = await Promise.all([
        firewall({ network: { allow: ['a.com'] } }, async () => {
          const r = await fetch('https://a.com');
          return await r.text();
        }),
        // Different policy; should permit b.com but block a.com
        (async () => {
          let blockedA;
          await firewall(
            { network: { allow: ['b.com'] }, violations: 'block' },
            async () => {
              const blocked = await fetch('https://a.com');
              blockedA = blocked.status;
              const ok = await fetch('https://b.com');
              return await ok.text();
            }
          );
          return blockedA;
        })(),
      ]);
      assert.equal(r1, 'https://a.com');
      assert.equal(r2, 403);
    }
  );
});

test('wrapFetch() returns an SDK-pluggable fetch that enforces policy', async () => {
  // wrapFetch operates on its own; doesn't depend on globalThis fetch patching
  let realCalled = null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url) => {
    realCalled = String(url);
    return new Response('ok');
  };
  try {
    const guarded = wrapFetch({ network: { allow: ['api.openai.com'] } });
    const ok = await guarded('https://api.openai.com/v1');
    assert.equal(ok.status, 200);
    assert.equal(realCalled, 'https://api.openai.com/v1');

    await assert.rejects(() => guarded('https://internal.corp'), PolicyViolation);
  } finally {
    globalThis.fetch = original;
  }
});

test('wrapFetch() instances have independent budget counters', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response('ok');
  try {
    const a = wrapFetch({ network: { allow: ['x.com'] }, budget: { maxRequests: 1 } });
    const b = wrapFetch({ network: { allow: ['x.com'] }, budget: { maxRequests: 1 } });
    await a('https://x.com');
    await b('https://x.com');  // should NOT count against a's budget
    await assert.rejects(() => a('https://x.com'), PolicyViolation);
  } finally {
    globalThis.fetch = original;
  }
});
