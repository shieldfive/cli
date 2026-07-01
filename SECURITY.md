# Security Policy

ShieldFive takes the security of `@shieldfive/cli` seriously. This document
describes how to report a vulnerability, what we commit to, and the safe-harbor
terms for security researchers.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.** Instead, email us
directly:

- **Email:** `security@shieldfive.com`
- **PGP key:** Not yet published. Encrypt with a temporary key on request, or
  send in plaintext — we would rather know about the issue than have it sit in
  your inbox.

If you cannot encrypt the report, send it in plaintext anyway. We will follow up
over an encrypted channel.

### What to include

1. A description of the vulnerability and its impact.
2. Steps to reproduce, including a minimal proof-of-concept if possible.
3. The CLI version and runtime environment (Node version, operating system).
4. Whether the issue is already public or has been disclosed elsewhere.
5. Your name and a way to contact you (or "anonymous" if you prefer).

## Our commitments

| Severity                     | Acknowledgement | Initial response | Patch target |
| ---------------------------- | :-------------: | :--------------: | :----------: |
| Critical (key/plaintext leak)|    24 hours     |     48 hours     |   7 days     |
| High (integrity bypass)      |    48 hours     |     5 days       |   14 days    |
| Medium (DoS, info leakage)   |    72 hours     |     7 days       |   30 days    |
| Low (defense-in-depth)       |    7 days       |     14 days      |   90 days    |

We will:

- Acknowledge your report within the windows above.
- Keep you informed of our investigation.
- Credit you in the release notes (with your permission, or anonymously).
- Coordinate public disclosure with you, defaulting to a 90-day window.
- Publish a CVE when appropriate.

We will *not*:

- Take legal action against researchers acting in good faith (see Safe Harbor).
- Demand silence as a condition of bounty or credit.

## Safe Harbor

Security research conducted in accordance with this policy is authorized. We will
not pursue civil claims or refer law enforcement against researchers who:

1. Make a good-faith effort to avoid privacy violations, data destruction, and
   service interruption.
2. Do not access, modify, or exfiltrate data belonging to anyone other than
   themselves or research accounts.
3. Report the vulnerability promptly through this policy's channels.
4. Do not exploit the vulnerability beyond what is necessary to confirm it.
5. Do not publicly disclose before we have had a reasonable opportunity to
   remediate (the timelines above).

## Bug bounty

ShieldFive operates a paid bug bounty program. For current scope, reward tiers,
rules of engagement, and submission instructions, see
https://shieldfive.com/security/bug-bounty.

## Scope

In scope: this CLI — the way it derives keys, encrypts files and filenames,
constructs the upload proof, and transmits data. A demonstration that plaintext
or key material can leak from this client is the highest-value report.

Out of scope for *this* repository (report elsewhere or not at all):

- Vulnerabilities in the cryptographic core — report those against
  [`@shieldfive/crypto`](https://github.com/shieldfive/crypto).
- Vulnerabilities in dependencies (`@noble/*`, `@supabase/supabase-js`) — report
  those upstream.
- Server-side issues in the ShieldFive backend — report via the bug bounty
  program above.
- Attacks that require an attacker to already control the user's device.
