/**
 * PolicyViolation — thrown when a request is denied by an agentguard policy
 * (or returned as a synthetic 403 Response when policy.violations === 'block').
 *
 * Catch this if you want to handle blocks programmatically:
 *
 *   try { await firewall(p, fn); }
 *   catch (e) {
 *     if (e instanceof PolicyViolation) console.log(e.reason, e.url);
 *   }
 */
export class PolicyViolation extends Error {
  /**
   * @param {string} reason     short stable code like 'not_in_allowlist'
   * @param {string} detail     human-readable detail
   * @param {string} url        the URL that was blocked
   * @param {string} method     HTTP method
   */
  constructor(reason, detail, url, method) {
    super(`agentguard: blocked ${method} ${url} — ${reason}: ${detail}`);
    this.name = 'PolicyViolation';
    this.reason = reason;
    this.detail = detail;
    this.url = url;
    this.method = method;
  }
}

/**
 * Build the synthetic 403 Response returned when policy.violations === 'block'.
 * Includes a header (`x-agentguard-block`) so callers can distinguish a real
 * 403 from one we synthesized.
 *
 * @param {PolicyViolation} violation
 * @returns {Response}
 */
export function blockResponse(violation) {
  const body = JSON.stringify({
    error: 'PolicyViolation',
    reason: violation.reason,
    detail: violation.detail,
    url: violation.url,
    method: violation.method,
  });
  return new Response(body, {
    status: 403,
    statusText: 'Forbidden',
    headers: {
      'content-type': 'application/json',
      'x-agentguard-block': '1',
      'x-agentguard-reason': violation.reason,
    },
  });
}
