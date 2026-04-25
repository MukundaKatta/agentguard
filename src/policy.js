/**
 * Policy declaration + checker.
 *
 * A policy is a plain object with three optional sections:
 *   - network: { allow?, deny?, methods? }    domain allow/deny + HTTP method allowlist
 *   - budget:  { maxRequests? }               cap on total requests in the firewall block
 *   - violations: 'throw' | 'block'           what to do when a request is denied
 *
 * Patterns supported in network.allow / network.deny:
 *   - exact host:           "api.openai.com"
 *   - wildcard subdomain:   "*.example.com"  (matches example.com and any subdomain)
 *   - global wildcard:      "*"              (matches everything; useful as catch-all in deny)
 */

/**
 * Validate + normalize a policy spec. Throws if the spec is malformed.
 *
 * @param {PolicySpec} spec
 * @returns {Policy}
 */
export function policy(spec) {
  if (!spec || typeof spec !== 'object') {
    throw new TypeError('policy: spec must be an object');
  }

  const network = spec.network ? normalizeNetwork(spec.network) : null;
  const budget = spec.budget ? normalizeBudget(spec.budget) : null;
  const violations = spec.violations ?? 'throw';
  if (violations !== 'throw' && violations !== 'block') {
    throw new TypeError(`policy: violations must be 'throw' or 'block', got ${JSON.stringify(violations)}`);
  }

  return Object.freeze({ network, budget, violations });
}

function normalizeNetwork(net) {
  if (typeof net !== 'object') {
    throw new TypeError('policy.network must be an object');
  }
  const allow = net.allow ? toPatternList(net.allow, 'network.allow') : null;
  const deny = net.deny ? toPatternList(net.deny, 'network.deny') : null;
  let methods = null;
  if (net.methods) {
    if (!Array.isArray(net.methods)) {
      throw new TypeError('policy.network.methods must be an array');
    }
    methods = net.methods.map((m) => String(m).toUpperCase());
  }
  return Object.freeze({ allow, deny, methods });
}

function normalizeBudget(budget) {
  if (typeof budget !== 'object') {
    throw new TypeError('policy.budget must be an object');
  }
  const out = {};
  if (budget.maxRequests != null) {
    if (typeof budget.maxRequests !== 'number' || budget.maxRequests < 0) {
      throw new TypeError('policy.budget.maxRequests must be a non-negative number');
    }
    out.maxRequests = budget.maxRequests;
  }
  return Object.freeze(out);
}

function toPatternList(value, label) {
  if (!Array.isArray(value)) {
    throw new TypeError(`${label} must be an array of host patterns`);
  }
  return value.map((p) => {
    if (typeof p !== 'string' || !p) {
      throw new TypeError(`${label} entries must be non-empty strings`);
    }
    return p.toLowerCase();
  });
}

/**
 * Pure decision function. Returns one of:
 *   { action: 'allow' }
 *   { action: 'deny', reason, detail }
 *
 * @param {Policy} policy
 * @param {string|URL} url
 * @param {{ method?: string }} [init]
 * @returns {Decision}
 */
export function check(policy, url, init = {}) {
  if (!policy || typeof policy !== 'object') {
    throw new TypeError('check: policy must be a normalized policy (use policy() first)');
  }

  let parsed;
  try {
    parsed = new URL(String(url));
  } catch {
    return { action: 'deny', reason: 'invalid_url', detail: String(url) };
  }

  const method = (init.method ?? 'GET').toUpperCase();

  if (policy.network?.methods && !policy.network.methods.includes(method)) {
    return { action: 'deny', reason: 'method_blocked', detail: method };
  }

  // deny rules win over allow rules
  if (policy.network?.deny) {
    for (const pattern of policy.network.deny) {
      if (matchHost(parsed.hostname, pattern)) {
        return {
          action: 'deny',
          reason: 'denylist_match',
          detail: `${parsed.hostname} matches ${pattern}`,
        };
      }
    }
  }

  if (policy.network?.allow) {
    let allowed = false;
    for (const pattern of policy.network.allow) {
      if (matchHost(parsed.hostname, pattern)) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      return {
        action: 'deny',
        reason: 'not_in_allowlist',
        detail: parsed.hostname,
      };
    }
  }

  return { action: 'allow' };
}

function matchHost(host, pattern) {
  const h = host.toLowerCase();
  if (pattern === '*') return true;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    return h === suffix || h.endsWith('.' + suffix);
  }
  return h === pattern;
}

/**
 * @typedef {Object} PolicySpec
 * @property {{ allow?: string[], deny?: string[], methods?: string[] }} [network]
 * @property {{ maxRequests?: number }} [budget]
 * @property {'throw' | 'block'} [violations]
 */

/**
 * @typedef {Object} Policy
 * @property {{ allow: string[]|null, deny: string[]|null, methods: string[]|null }|null} network
 * @property {{ maxRequests?: number }|null} budget
 * @property {'throw' | 'block'} violations
 */

/**
 * @typedef {{ action: 'allow' } | { action: 'deny', reason: string, detail: string }} Decision
 */
