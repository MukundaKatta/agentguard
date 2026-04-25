/**
 * How to use agentguard with the Anthropic SDK (or any SDK that accepts a
 * `fetch` parameter in its constructor):
 *
 *   import Anthropic from '@anthropic-ai/sdk';
 *   import { wrapFetch, policy } from '@mukundakatta/agentguard';
 *
 *   const client = new Anthropic({
 *     fetch: wrapFetch(policy({
 *       network: { allow: ['api.anthropic.com'] },
 *       budget: { maxRequests: 50 },
 *     })),
 *   });
 *
 *   // Now ANY call from this client is policy-checked. Tools you wire into
 *   // the SDK can't accidentally hit other domains, and the SDK can't make
 *   // more than 50 requests in this client's lifetime.
 *
 * The OpenAI SDK has the same `fetch` parameter; same pattern works.
 *
 * This file is documentation, not a runnable example (would need
 * @anthropic-ai/sdk installed and an API key). For a runnable demo, see
 * demo-block.js.
 */
console.log('See file comments for the integration pattern.');
