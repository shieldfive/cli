# Changelog

All notable changes to `@shieldfive/cli` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 - 2026-07-01

### Added

- **Two-factor authentication (TOTP).** Accounts with an authenticator app
  enrolled now complete the Supabase AAL2 step-up during sign-in, which the
  server's upload gate requires. After the password, the CLI prompts
  `Two-factor code (6 digits):` (or reads `SF_TOTP_CODE` in non-interactive
  contexts), runs the standard challenge/verify against the verified TOTP
  factor, and uses the elevated token for uploads. Only TOTP is supported; SMS
  and other factors are not. Accounts without 2FA are unaffected and are never
  prompted.

### Notes

- The step-up flow is covered by unit tests over a mocked Supabase client
  (no-MFA, success, missing factor, malformed/wrong code, lookup failure). The
  live challenge/verify round-trip against a real 2FA account has not yet been
  exercised.

## 0.1.0 - 2026-07-01

Initial public release.

### Added

- `sf encrypt <folder>` - encrypt each file locally (post-quantum hybrid demo);
  no account and no upload.
- `sf push <folder>` - sign in, unlock the vault, encrypt, and upload a folder.
  Picks the direct or multipart path automatically from file size.
- `sf sync <folder> [--watch] [--interval=<seconds>]` - upload new and changed
  files, once or on a poll loop, tracked by a local `.shieldfive-sync.json`
  manifest (size + mtime) so unchanged files are skipped.
- Chunked AES-GCM file encryption with a server-verified HMAC upload proof.
- Streaming chunk reader so large files never load fully into memory; multipart
  upload for files larger than 5 MiB.
- Baked-in ShieldFive public backend configuration, so only `SF_EMAIL` and
  `SF_PASSWORD` are required (endpoints override via env for a dev backend).

### Notes

- The cryptographic core (`@shieldfive/crypto`) has not had an external audit.
  Early software.
- The direct (single-chunk) upload path is validated against production. The
  multipart path is verified byte-for-byte against the server contract and
  tested end to end with mocks, but has not yet been run live with a real large
  file.
- `sf sync` is append-only: it does not yet mirror local deletions or renames.
