import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { main } from '../src/cli.js';

/**
 * The CLI writes JSON to stdout and human-readable error/help text to stderr.
 * For unit tests we patch process.stdout.write / process.stderr.write so we can
 * capture both streams without spawning subprocesses.
 */
async function captureMain(argv) {
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  let stdout = '';
  let stderr = '';
  process.stdout.write = (chunk) => {
    stdout += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    return true;
  };
  process.stderr.write = (chunk) => {
    stderr += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    return true;
  };
  try {
    const code = await main(argv);
    return { code, stdout, stderr };
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
}

function tempPolicy(spec) {
  const dir = mkdtempSync(join(tmpdir(), 'agentguard-cli-'));
  const path = join(dir, 'policy.json');
  writeFileSync(path, JSON.stringify(spec), 'utf8');
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('--help prints usage and exits 0', async () => {
  const { code, stdout } = await captureMain(['--help']);
  assert.equal(code, 0);
  assert.match(stdout, /agentguard v\d/);
  assert.match(stdout, /check/);
  assert.match(stdout, /validate-policy/);
});

test('check returns allowed=true and exits 0 for an allowlisted host', async () => {
  const { path, cleanup } = tempPolicy({ network: { allow: ['api.openai.com'] } });
  try {
    const { code, stdout } = await captureMain([
      'check',
      'https://api.openai.com/v1/chat',
      '--policy',
      path,
    ]);
    assert.equal(code, 0);
    const out = JSON.parse(stdout);
    assert.equal(out.allowed, true);
    assert.equal(out.url, 'https://api.openai.com/v1/chat');
    assert.equal(out.method, 'GET');
  } finally {
    cleanup();
  }
});

test('check returns allowed=false and exits 1 when host is blocked', async () => {
  const { path, cleanup } = tempPolicy({ network: { allow: ['api.openai.com'] } });
  try {
    const { code, stdout } = await captureMain([
      'check',
      'https://internal.corp/exfil',
      '--policy',
      path,
    ]);
    assert.equal(code, 1);
    const out = JSON.parse(stdout);
    assert.equal(out.allowed, false);
    assert.equal(out.reason, 'not_in_allowlist');
  } finally {
    cleanup();
  }
});

test('validate-policy reports invalid JSON and exits 1', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agentguard-cli-'));
  const path = join(dir, 'broken.json');
  writeFileSync(path, '{not valid', 'utf8');
  try {
    const { code, stdout } = await captureMain(['validate-policy', '--policy', path]);
    assert.equal(code, 1);
    const out = JSON.parse(stdout);
    assert.equal(out.valid, false);
    assert.ok(out.issues.some((i) => /invalid JSON/i.test(i.message)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('check-batch reads URLs (one per line) and exits 1 if any denied', async () => {
  const { path, cleanup } = tempPolicy({ network: { allow: ['api.openai.com'] } });
  const urlsDir = mkdtempSync(join(tmpdir(), 'agentguard-urls-'));
  const urlsPath = join(urlsDir, 'urls.txt');
  writeFileSync(
    urlsPath,
    [
      'https://api.openai.com/v1/foo',
      '# comment line is ignored',
      '',
      'https://internal.corp/bar',
    ].join('\n'),
    'utf8'
  );
  try {
    const { code, stdout } = await captureMain([
      'check-batch',
      urlsPath,
      '--policy',
      path,
    ]);
    assert.equal(code, 1);
    const lines = stdout.trim().split('\n');
    assert.equal(lines.length, 2);
    const first = JSON.parse(lines[0]);
    const second = JSON.parse(lines[1]);
    assert.equal(first.allowed, true);
    assert.equal(second.allowed, false);
  } finally {
    cleanup();
    rmSync(urlsDir, { recursive: true, force: true });
  }
});

test('unknown subcommand exits 2 with usage error', async () => {
  const { code, stderr } = await captureMain(['nope']);
  assert.equal(code, 2);
  assert.match(stderr, /unknown subcommand/);
});
