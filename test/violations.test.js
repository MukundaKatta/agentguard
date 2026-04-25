import { test } from 'node:test';
import assert from 'node:assert/strict';

import { PolicyViolation, blockResponse } from '../src/violations.js';

test('PolicyViolation carries structured fields', () => {
  const v = new PolicyViolation('not_in_allowlist', 'evil.com', 'https://evil.com/x', 'GET');
  assert.equal(v.name, 'PolicyViolation');
  assert.equal(v.reason, 'not_in_allowlist');
  assert.equal(v.detail, 'evil.com');
  assert.equal(v.url, 'https://evil.com/x');
  assert.equal(v.method, 'GET');
  assert.match(v.message, /blocked GET https:\/\/evil\.com\/x/);
  assert.match(v.message, /not_in_allowlist/);
});

test('PolicyViolation is catchable as Error and as PolicyViolation', () => {
  const v = new PolicyViolation('x', 'y', 'z', 'GET');
  assert.ok(v instanceof Error);
  assert.ok(v instanceof PolicyViolation);
});

test('blockResponse returns a 403 with structured body + telltale headers', async () => {
  const v = new PolicyViolation('denylist_match', 'evil.com matches *', 'https://evil.com', 'POST');
  const r = blockResponse(v);
  assert.equal(r.status, 403);
  assert.equal(r.headers.get('x-agentguard-block'), '1');
  assert.equal(r.headers.get('x-agentguard-reason'), 'denylist_match');
  const body = await r.json();
  assert.equal(body.error, 'PolicyViolation');
  assert.equal(body.reason, 'denylist_match');
  assert.equal(body.url, 'https://evil.com');
  assert.equal(body.method, 'POST');
});
