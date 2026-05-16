<!--
Thanks for sending a PR to agentguard.

Quick reminders before you submit:
  - agentguard is a security primitive. Every PR is reviewed for "could this loosen the gate, and is the loosening intentional and documented."
  - Zero runtime dependencies. A PR that adds one will be sent back to discussion first.
  - The policy must remain deterministic from local inputs. No DNS lookups, no remote allowlist fetches, at policy-check time.
  - Tests live in test/ and run via `npm test`. Add an adversarial test for any new normalization / parsing logic.
-->

## What this changes

A one-line summary, then a short paragraph if needed.

## Why

The user-visible bug or workflow gap this addresses.

## Type of change

- [ ] Bug fix in `policy()` / `firewall()` / `matchHost()` / `PolicyViolation`
- [ ] New normalization (IPv6 form, IDN, percent-encoding, etc.)
- [ ] New policy primitive (allow / deny / mode / hook)
- [ ] CLI fix
- [ ] Test coverage (especially adversarial cases)
- [ ] Documentation
- [ ] CI / build / release plumbing

## Security review

- [ ] This change does **not** loosen the policy by default. (Anything that broadens the allowlist must require explicit opt-in.)
- [ ] This change does **not** introduce a DNS lookup or remote fetch at policy-check time.
- [ ] If this touches host matching / URL parsing / normalization, I added at least one adversarial test for the new path (unicode confusables, IPv6 bracket forms, IPv4 numeric forms, trailing-dot hosts, etc.).
- [ ] If this changes the wrapped-fetch lifecycle, the firewall is still active for the entire `firewall(...)` callback, including async tails.

## Scope check

- [ ] No new runtime dependencies added (enforced by CI).
- [ ] If this changes the threat-model surface, `SECURITY.md` was updated in the same PR.

## Validation

- [ ] `npm run test:all` passes locally (unit + examples)
- [ ] `npm run test:coverage` still meets the configured thresholds (75% branches / 85% lines+functions+statements)
- [ ] Public API changes are reflected in `src/index.d.ts`

## Linked issue

Closes #
