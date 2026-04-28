# Security policy

agentguard is a security primitive (an egress firewall). If you find a way to
bypass its policy enforcement — for example a host pattern that misses,
a normalization bug that lets a denied URL through, or a way to drop the
fetch wrapper mid-execution — please report it privately.

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/MukundaKatta/agentguard/security/advisories/new)
on this repo. That goes straight to the maintainer; no public issue is opened
until a fix is ready.

If GitHub Security Advisories is not available to you, email
mukunda.vjcs6@gmail.com with subject `[agentguard security]`. Include:

- Affected version
- A minimal reproducer (URL pattern + policy spec is usually enough)
- Your proposed fix, if you have one

You will get an acknowledgement within 7 days. A patched release is the
target outcome; advisories will be coordinated under a CVE if appropriate.

## Scope

In scope:

- Bypasses of `policy()` allow/deny matching, including unicode/IDN, IPv6,
  IPv4 numeric, and CIDR-equivalent forms
- Race conditions where a request slips out during `firewall()` setup or
  teardown
- Bugs in `blockResponse` or `PolicyViolation` that leak the original
  request URL or headers when the user expected them to be redacted

Out of scope:

- Vulnerabilities in Node.js core, the user's code, or third-party fetch
  implementations agentguard wraps. Report those upstream.
- Performance or feature requests — open a normal issue.

## Supported versions

Only the latest published `0.1.x` is patched. Earlier preview versions are
not supported. Track this file's `[Unreleased]` section for in-flight fixes.
