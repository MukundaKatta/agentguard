/**
 * agentguard — network egress firewall for AI agents.
 *
 * Hand-maintained declarations. Source is JS (with JSDoc) so this file is the
 * single source of truth for TypeScript consumers. Keep in sync with src/*.js.
 */

export const VERSION: string;

/** Host pattern: "api.openai.com" | "*.example.com" | "*". */
export type HostPattern = string;

export interface NetworkPolicy {
  /** Allowlist of host patterns. If set, only matching hosts are permitted. */
  allow?: HostPattern[];
  /** Denylist of host patterns. Wins over allow. */
  deny?: HostPattern[];
  /** HTTP methods to permit (e.g. ['GET', 'POST']). Default: any. */
  methods?: string[];
}

export interface BudgetPolicy {
  /** Cap on total requests issued inside the firewall block. */
  maxRequests?: number;
}

/** What a policy violation does. 'throw' raises PolicyViolation; 'block' returns a 403. */
export type ViolationMode = 'throw' | 'block';

export interface PolicySpec {
  network?: NetworkPolicy;
  budget?: BudgetPolicy;
  violations?: ViolationMode;
}

export interface Policy {
  readonly network: Required<NetworkPolicy> | null;
  readonly budget: BudgetPolicy | null;
  readonly violations: ViolationMode;
}

export type Decision =
  | { action: 'allow' }
  | { action: 'deny'; reason: string; detail: string };

/**
 * Validate + normalize a policy spec. Throws if malformed. Pass either the spec
 * or the result back into firewall()/wrapFetch().
 */
export function policy(spec: PolicySpec): Policy;

/**
 * Pure decision function. No side effects. Use this if you want to enforce
 * the policy in a transport other than fetch (e.g. an HTTP/2 client).
 */
export function check(policy: Policy, url: string | URL, init?: { method?: string }): Decision;

/**
 * Run an async function with globalThis.fetch wrapped to enforce the policy.
 * The patch is reverted on exit (including on exceptions). Concurrent firewall()
 * calls each get their own AsyncLocalStorage frame and don't conflict.
 */
export function firewall<T>(spec: PolicySpec | Policy, fn: () => Promise<T> | T): Promise<T>;

/**
 * Get a fetch function that applies the policy without monkey-patching the global.
 * Each call returns a fresh fetch with its own internal request counter.
 *
 * Use this when you can pass `fetch` into an SDK constructor:
 *   const client = new Anthropic({ fetch: wrapFetch(myPolicy) });
 */
export function wrapFetch(spec: PolicySpec | Policy): typeof fetch;

/**
 * Thrown by firewall() when a request is denied and policy.violations === 'throw'
 * (the default). Catch programmatically to inspect what was blocked and why.
 */
export class PolicyViolation extends Error {
  name: 'PolicyViolation';
  /** Stable short code, e.g. 'not_in_allowlist', 'denylist_match', 'budget_exceeded'. */
  reason: string;
  detail: string;
  url: string;
  method: string;
  constructor(reason: string, detail: string, url: string, method: string);
}
