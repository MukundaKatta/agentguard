/**
 * agentguard — declarative network egress firewall for AI agents.
 *
 * Public surface:
 *   - policy(spec)              normalize + validate a policy declaration
 *   - firewall(policy, fn)      run fn with globalThis.fetch wrapped to enforce policy
 *   - wrapFetch(policy)         get a wrapped fetch you can pass into SDKs (Anthropic, OpenAI, ...)
 *   - check(policy, url, init)  pure decision function (no side effects); useful for custom enforcement
 *   - PolicyViolation           thrown (default) when a request is blocked
 */

export { policy, check } from './policy.js';
export { firewall, wrapFetch } from './firewall.js';
export { PolicyViolation } from './violations.js';
export { VERSION } from './version.js';
