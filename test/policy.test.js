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

// SSRF host coverage tests — verify the policy denies common SSRF
// targets when they appear (under various host shapes) and that
// allow/deny patterns work against IPv4 numeric, IPv6, and localhost
// variants. Each block checks one host shape; failures here would mean
// an agent's tool could reach an internal endpoint just by changing
// the URL form.

test('policy denies localhost when localhost is on the denylist', () => {
  const p = policy({
    network: { allow: ['*'], deny: ['localhost'] },
  });
  const decision = check(p, 'http://localhost:8080/admin');
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'denylist_match');
});

test('policy denies 127.0.0.1 when 127.0.0.1 is on the denylist', () => {
  const p = policy({
    network: { allow: ['*'], deny: ['127.0.0.1'] },
  });
  const decision = check(p, 'http://127.0.0.1:8080/admin');
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'denylist_match');
});

test('policy denies AWS IMDS endpoint when 169.254.169.254 is on the denylist', () => {
  // The classic SSRF target. If the deny rule misses this, the
  // firewall is not actually protecting cloud workloads.
  const p = policy({
    network: { allow: ['*'], deny: ['169.254.169.254'] },
  });
  const decision = check(p, 'http://169.254.169.254/latest/meta-data/');
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'denylist_match');
});

test('policy denies IPv6 loopback ::1 when [::1] is on the denylist', () => {
  // URL parsing strips the brackets — host pattern should still match.
  const p = policy({
    network: { allow: ['*'], deny: ['::1'] },
  });
  const decision = check(p, 'http://[::1]:8080/admin');
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'denylist_match');
});

test('policy denies bracketed IPv6 loopback when "[::1]" is on the denylist', () => {
  // Caller may write the bracketed form; should also match.
  const p = policy({
    network: { allow: ['*'], deny: ['[::1]'] },
  });
  const decision = check(p, 'http://[::1]/foo');
  assert.equal(decision.action, 'deny');
});

test('policy allowlist treats hostname matching as case-insensitive', () => {
  // Some apps log lowercased hosts but the URL was uppercased.
  const p = policy({
    network: { allow: ['Example.COM'] },
  });
  const decision = check(p, 'https://example.com/api');
  assert.equal(decision.action, 'allow');
});

test('policy denies a host that is not in the allowlist (default-deny when allow set)', () => {
  const p = policy({
    network: { allow: ['api.example.com'] },
  });
  const decision = check(p, 'http://internal-only.example.com/');
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'not_in_allowlist');
});

test('policy denies bare hostnames without a TLD (e.g. "metadata")', () => {
  // GCE / Kubernetes metadata is reachable via the bare hostname
  // "metadata" inside the cluster. Make sure it is denied as expected
  // when on the deny list.
  const p = policy({
    network: { allow: ['*'], deny: ['metadata'] },
  });
  const decision = check(p, 'http://metadata/computeMetadata/v1/');
  assert.equal(decision.action, 'deny');
});

test('policy treats invalid URL strings as deny with reason invalid_url', () => {
  // Defense-in-depth: a tool passing junk should not be silently
  // allowed by a permissive allowlist.
  const p = policy({
    network: { allow: ['*'] },
  });
  const decision = check(p, 'not a url');
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'invalid_url');
});

test('policy denies POST when methods allowlist excludes it', () => {
  // Method-restricted policies should reject mutations even when the
  // host is otherwise allowed.
  const p = policy({
    network: { allow: ['api.example.com'], methods: ['GET', 'HEAD'] },
  });
  const decision = check(p, 'https://api.example.com/users', { method: 'POST' });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'method_blocked');
});

test('policy lower-cases method input before checking the allowlist', () => {
  // method may arrive as 'post' or 'POST' from different clients.
  const p = policy({
    network: { allow: ['api.example.com'], methods: ['POST'] },
  });
  const decision = check(p, 'https://api.example.com/users', { method: 'post' });
  assert.equal(decision.action, 'allow');
});
