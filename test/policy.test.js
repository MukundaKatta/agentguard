import { test } from 'node:test';
import assert from 'node:assert/strict';

import { policy, check } from '../src/policy.js';

test('policy() freezes the result', () => {
  const p = policy({ network: { allow: ['x.com'] } });
  assert.throws(() => {
    p.violations = 'block';
  });
});

test('policy() defaults violations to throw', () => {
  const p = policy({});
  assert.equal(p.violations, 'throw');
});

test('policy() rejects bad violations mode', () => {
  assert.throws(() => policy({ violations: 'silent' }), TypeError);
});

test('policy() rejects bad pattern types', () => {
  assert.throws(() => policy({ network: { allow: 'x.com' } }), TypeError);
  assert.throws(() => policy({ network: { allow: [123] } }), TypeError);
  assert.throws(() => policy({ network: { allow: [''] } }), TypeError);
});

test('policy() rejects bad budget', () => {
  assert.throws(() => policy({ budget: { maxRequests: -1 } }), TypeError);
  assert.throws(() => policy({ budget: { maxRequests: 'lots' } }), TypeError);
});

test('policy() lowercases host patterns', () => {
  const p = policy({ network: { allow: ['API.OPENAI.COM'] } });
  assert.deepEqual(p.network.allow, ['api.openai.com']);
});

test('check() allows when no policy is set', () => {
  const p = policy({});
  assert.deepEqual(check(p, 'https://anywhere.com'), { action: 'allow' });
});

test('check() allows when host matches allowlist', () => {
  const p = policy({ network: { allow: ['api.openai.com'] } });
  assert.equal(check(p, 'https://api.openai.com/v1/chat').action, 'allow');
});

test('check() denies when host is not in allowlist', () => {
  const p = policy({ network: { allow: ['api.openai.com'] } });
  const r = check(p, 'https://internal.corp/exfil');
  assert.equal(r.action, 'deny');
  assert.equal(r.reason, 'not_in_allowlist');
});

test('check() supports wildcard subdomain (*.example.com)', () => {
  const p = policy({ network: { allow: ['*.example.com'] } });
  assert.equal(check(p, 'https://example.com').action, 'allow');
  assert.equal(check(p, 'https://api.example.com').action, 'allow');
  assert.equal(check(p, 'https://a.b.example.com').action, 'allow');
  assert.equal(check(p, 'https://example.org').action, 'deny');
});

test('check() supports global wildcard (*) — useful as catch-all in deny', () => {
  const p = policy({ network: { deny: ['*'], allow: ['api.openai.com'] } });
  // deny wins over allow → everything blocked even openai
  assert.equal(check(p, 'https://api.openai.com').action, 'deny');
});

test('check() denylist wins over allowlist', () => {
  const p = policy({
    network: { allow: ['*.example.com'], deny: ['evil.example.com'] },
  });
  assert.equal(check(p, 'https://example.com').action, 'allow');
  assert.equal(check(p, 'https://evil.example.com').action, 'deny');
});

test('check() enforces method allowlist', () => {
  const p = policy({ network: { methods: ['GET'] } });
  assert.equal(check(p, 'https://x.com', { method: 'GET' }).action, 'allow');
  const r = check(p, 'https://x.com', { method: 'POST' });
  assert.equal(r.action, 'deny');
  assert.equal(r.reason, 'method_blocked');
});

test('check() denies invalid URL with stable reason', () => {
  const p = policy({ network: { allow: ['x.com'] } });
  const r = check(p, 'not a url');
  assert.equal(r.action, 'deny');
  assert.equal(r.reason, 'invalid_url');
});

test('check() rejects bad input', () => {
  assert.throws(() => check(null, 'https://x'), TypeError);
});

test('host matching is case-insensitive', () => {
  const p = policy({ network: { allow: ['Api.Example.Com'] } });
  assert.equal(check(p, 'https://API.example.COM').action, 'allow');
});

test('check() handles port numbers in URL (port ignored for host match)', () => {
  const p = policy({ network: { allow: ['localhost'] } });
  assert.equal(check(p, 'http://localhost:8080/api').action, 'allow');
});
