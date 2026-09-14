# Changelog

All notable changes to `@shieldfive/cli` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.1 - 2026-09-14

### Fixed

- **Files of 5 MiB or less could not be uploaded at all, since 2026-09-03.** The
  server moved the direct-upload path to a presigned S3 PUT and stopped
  returning `authToken` (web `b52b4c8`, PR #726); the client hard-required that
  token and threw `Direct upload session is missing credentials.` before sending
  a byte. The direct path now `PUT`s the ciphertext straight at the presigned
  URL with no `Authorization` and no `X-Bz-*` headers, and sends no `b2FileId`
  at finalize — a presigned PUT returns an ETag, not a Backblaze file id, and
  forwarding it would have been persisted verbatim as the storage id. Files
  larger than 5 MiB were never affected; the multipart path is unchanged and
  keeps its token, its `X-Bz-*` headers and its session-derived `b2FileId`.

### Changed

- **The direct path no longer sends a wire checksum.** It previously sent
  `X-Bz-Content-Sha1`, which Backblaze's native upload verified server-side and
  rejected on mismatch. A presigned PUT signed for `host` only carries no
  equivalent, and the server's finalize check compares the client's
  `ciphertextHash` against the client's own `partSha1Array[0]` — both
  client-supplied, so always equal. That protection is removed and not replaced:
  integrity on this path now rests on the upload proof and on AES-GCM's tag at
  download. Stated rather than left to be discovered.
- The direct path also no longer checks the upload response shape. It used to
  require a `fileId` in the body; a presigned PUT returns none, so any 2xx is
  now accepted and a PUT that answered 200 without durably storing the object
  surfaces later as finalize's 409 rather than immediately.

### Notes

- **The rewritten direct path has not been run against production.** It is
  covered by the offline mock test only, which is the same class of evidence
  that let 0.2.0 ship broken — the old fixture supplied an `authToken` the
  server had stopped sending. The mock now matches the live response shape, and
  four mutations of the client (re-adding `Authorization`, re-sending
  `b2FileId`, reverting to `POST`, restoring the token requirement) each fail
  the suite. That is a contract test, not a live one. One `sf push` of a file
  under 5 MiB and one over it, confirmed visible and decryptable in the web app,
  is still required.
- The direct path remains single-attempt: one `fetch`, no retry and no
  signature refresh, where the multipart path retries. A transient 5xx or a
  signature that expires mid-upload fails the file. Pre-existing, out of scope
  here, and worth fixing before `sf sync --watch` is relied on.

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
- The direct (single-chunk) upload path was validated against production as the
  backend stood on 2026-07-01. **That no longer holds:** the server moved the
  direct path to a presigned PUT on 2026-09-03, and this claim was false from
  that date until the fix in 0.2.1. The multipart path is verified
  byte-for-byte against the server contract and tested end to end with mocks,
  but has not yet been run live with a real large file.
- `sf sync` is append-only: it does not yet mirror local deletions or renames.
