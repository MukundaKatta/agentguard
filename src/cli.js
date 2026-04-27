#!/usr/bin/env node
/**
 * agentguard CLI — policy-driven URL/method checks from the terminal.
 *
 * Subcommands:
 *   agentguard check <url> --policy <file.json> [--method GET] [--pretty]
 *   agentguard check-batch <urls.txt|-> --policy <file.json> [--method GET] [--pretty]
 *   agentguard validate-policy --policy <file.json> [--pretty]
 *
 * Conventions shared across the @mukundakatta agent CLIs:
 *   - `-` reads stdin
 *   - JSON to stdout for machine consumers; --pretty for humans
 *   - exit 0 = pass / allowed, 1 = denied / invalid, 2 = usage error
 */

import { readFileSync, existsSync } from 'node:fs';

import { policy as makePolicy, check } from './policy.js';
import { VERSION } from './version.js';

const USAGE = `agentguard v${VERSION} — egress firewall checks for AI agents.

Usage:
  agentguard check <url>  --policy FILE  [--method GET] [--pretty]
  agentguard check-batch  <urls.txt|->  --policy FILE  [--method GET] [--pretty]
  agentguard validate-policy  --policy FILE  [--pretty]
  agentguard --help | --version

Notes:
  Pass '-' as the input to read from stdin.
  check     emits {"url","method","allowed","reason","detail"}.
  check-batch emits one JSON line per input URL.
  validate-policy emits {"valid","issues"} and exits 1 when issues are found.
  Exit codes: 0 ok / allowed, 1 denied / invalid, 2 usage error.
`;

// --- main ---

export async function main(argv = process.argv.slice(2)) {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    process.stdout.write(USAGE);
    return 0;
  }
  if (argv[0] === '--version' || argv[0] === '-v') {
    process.stdout.write(VERSION + '\n');
    return 0;
  }

  const sub = argv[0];
  const rest = argv.slice(1);
  try {
    if (sub === 'check') return await runCheck(rest);
    if (sub === 'check-batch') return await runCheckBatch(rest);
    if (sub === 'validate-policy') return await runValidatePolicy(rest);
    process.stderr.write(`agentguard: unknown subcommand '${sub}'\n\n${USAGE}`);
    return 2;
  } catch (err) {
    return reportError(err);
  }
}

// --- check ---

async function runCheck(args) {
  const flags = parseFlags(args, {
    string: ['policy', 'method'],
    boolean: ['pretty'],
  });
  if (flags._.length === 0) {
    process.stderr.write('agentguard check: missing <url> argument\n');
    return 2;
  }
  if (!flags.policy) {
    process.stderr.write('agentguard check: --policy FILE is required\n');
    return 2;
  }
  const url = flags._[0];
  const policy = await loadPolicy(flags.policy);
  const decision = check(policy, url, { method: flags.method ?? 'GET' });
  emit(formatDecision(url, flags.method ?? 'GET', decision), flags.pretty);
  return decision.action === 'allow' ? 0 : 1;
}

// --- check-batch ---

async function runCheckBatch(args) {
  const flags = parseFlags(args, {
    string: ['policy', 'method'],
    boolean: ['pretty'],
  });
  if (flags._.length === 0) {
    process.stderr.write('agentguard check-batch: missing <urls.txt|-> argument\n');
    return 2;
  }
  if (!flags.policy) {
    process.stderr.write('agentguard check-batch: --policy FILE is required\n');
    return 2;
  }
  const policy = await loadPolicy(flags.policy);
  const raw = await resolveInput(flags._[0]);
  const urls = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));

  let anyDenied = false;
  for (const url of urls) {
    const decision = check(policy, url, { method: flags.method ?? 'GET' });
    if (decision.action !== 'allow') anyDenied = true;
    emit(formatDecision(url, flags.method ?? 'GET', decision), flags.pretty);
  }
  return anyDenied ? 1 : 0;
}

// --- validate-policy ---

async function runValidatePolicy(args) {
  const flags = parseFlags(args, {
    string: ['policy'],
    boolean: ['pretty'],
  });
  if (!flags.policy) {
    process.stderr.write('agentguard validate-policy: --policy FILE is required\n');
    return 2;
  }
  const issues = [];
  let raw;
  try {
    raw = readFileSync(flags.policy, 'utf8');
  } catch (err) {
    issues.push({ path: flags.policy, message: `cannot read file: ${err.message}` });
    emit({ valid: false, issues }, flags.pretty);
    return 1;
  }
  let spec;
  try {
    spec = JSON.parse(raw);
  } catch (err) {
    issues.push({ path: flags.policy, message: `invalid JSON: ${err.message}` });
    emit({ valid: false, issues }, flags.pretty);
    return 1;
  }
  try {
    makePolicy(spec);
  } catch (err) {
    issues.push({ path: flags.policy, message: err.message });
  }
  // Soft warnings: an empty allowlist with no deny means nothing is restricted.
  if (
    spec &&
    typeof spec === 'object' &&
    (!spec.network || (!spec.network.allow && !spec.network.deny))
  ) {
    issues.push({ path: 'network', message: 'no allow or deny rules defined; policy is permissive' });
  }
  const valid = issues.every((i) => i.message.startsWith('no allow or deny'));
  emit({ valid, issues }, flags.pretty);
  return valid ? 0 : 1;
}

// --- helpers ---

async function loadPolicy(path) {
  if (!existsSync(path)) {
    throw new UsageError(`policy file not found: ${path}`);
  }
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    throw new UsageError(`cannot read policy: ${err.message}`);
  }
  let spec;
  try {
    spec = JSON.parse(raw);
  } catch (err) {
    throw new UsageError(`policy is not valid JSON: ${err.message}`);
  }
  return makePolicy(spec);
}

function formatDecision(url, method, decision) {
  return {
    url,
    method,
    allowed: decision.action === 'allow',
    reason: decision.reason ?? null,
    detail: decision.detail ?? null,
  };
}

async function resolveInput(arg) {
  if (arg === '-') return await readStdin();
  if (existsSync(arg)) return readFileSync(arg, 'utf8');
  return arg;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

/**
 * Tiny argv parser. Same shape as the other @mukundakatta CLIs:
 *   --flag           boolean true
 *   --flag value     string value
 *   --flag=value     same as above
 *   positional args  collected in flags._
 */
function parseFlags(argv, schema) {
  const flags = { _: [] };
  for (const name of schema.boolean ?? []) flags[name] = false;
  for (const name of schema.string ?? []) flags[name] = undefined;

  const wantsValue = new Set(schema.string ?? []);

  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === '--') {
      flags._.push(...argv.slice(i + 1));
      break;
    }
    if (tok.startsWith('--')) {
      const eq = tok.indexOf('=');
      const name = eq === -1 ? tok.slice(2) : tok.slice(2, eq);
      const inlineValue = eq === -1 ? null : tok.slice(eq + 1);
      if (wantsValue.has(name)) {
        const raw = inlineValue ?? argv[++i];
        if (raw === undefined) throw new UsageError(`flag --${name} requires a value`);
        flags[name] = raw;
      } else if ((schema.boolean ?? []).includes(name)) {
        flags[name] = true;
      } else {
        throw new UsageError(`unknown flag --${name}`);
      }
    } else {
      flags._.push(tok);
    }
  }
  return flags;
}

function emit(value, pretty) {
  const json = pretty ? JSON.stringify(value, null, 2) : JSON.stringify(value);
  process.stdout.write(json + '\n');
}

class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
    this.exitCode = 2;
  }
}

function reportError(err) {
  if (err && err.name === 'UsageError') {
    process.stderr.write(`agentguard: ${err.message}\n`);
    return err.exitCode ?? 2;
  }
  process.stderr.write(`agentguard: ${err?.message ?? err}\n`);
  return 1;
}

const isMain =
  process.argv[1] && (process.argv[1].endsWith('cli.js') || process.argv[1].endsWith('agentguard'));
if (isMain) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      process.stderr.write(`agentguard: ${err?.stack ?? err}\n`);
      process.exit(1);
    }
  );
}
