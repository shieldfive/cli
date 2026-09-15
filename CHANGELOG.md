# Changelog

All notable changes to `@shieldfive/cli` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **`sf login`, `sf status`, `sf logout`.** `sf login` prompts for your password
  and, if two-factor is enabled, a code, then starts an agent that holds the
  signed-in session and the unlocked vault key in memory only. `sf push` and
  `sf sync` use it when it is running and need nothing in the environment. The
  agent locks itself after 8 hours without use (`--idle=<hours>` to change it),
  and `sf logout` revokes the session on the server.
- **`sf verify <file>...`** reports whether each file is safely stored in your
  vault. The bytes on disk now must match an upload the agent performed, and the
  server must confirm that upload at the moment of asking. Names and sizes play
  no part. Exits 0 only when every file is confirmed, so a script can gate on it.
- **Unattended sync on two-factor accounts.** One interactive `sf login` is
  enough: the agent refreshes the session without prompting again until it locks
  or you log out.

- **`sf logout --everywhere`** signs out every session on the account, including
  the browser and phone.

### Security

- The agent's socket accepts six operations: `status`, `upload`, `sync`,
  `verify`, `lock`, `logout`. None lists, downloads or decrypts vault contents,
  or returns key material, and a test pins the list.
- `sf login` never reads `SF_PASSWORD`. The agent is started with an explicit
  environment allowlist, so a password exported for the older flow does not
  reach it.
- Uploads are recorded in `~/.shieldfive/ledger/<account>.jsonl` with an HMAC of
  each file's contents under a key derived from the vault key rather than a
  plain hash, so the ledger cannot confirm which documents you hold to anyone
  without that key.
- Hardened before release after a security review:
  - The ledger records the MAC of the bytes actually encrypted, read in the
    same pass as the upload. Hashing the file before and after could not see a
    change made and undone mid-upload, and `sf verify` would then have called a
    file backed up that the vault did not hold.
  - Ledger records carry a tag under the vault-derived key and a device id;
    forged lines, and lines copied from another machine, are ignored.
  - `SF_EMAIL` and `SF_PASSWORD` take precedence over a running agent, so a
    script cannot be redirected to a different account.
  - A lock file stops two agents from starting at once, and an agent that is
    still revoking its session cannot delete the socket of the one that replaced
    it.
  - `sf status` no longer postpones the idle lock.
  - Stopping wipes keys before touching the network, and its token refresh and
    revoke share a 5 second budget, so an unreachable server cannot keep the
    agent alive. An upload already running keeps its own copy of the key.
  - The socket lives in `~/.shieldfive/run` everywhere, so cron jobs and other
    minimal environments find the agent.

### Notes

- `sf login` has not been run against production. The pieces are covered by
  offline tests, including one that runs the agent as its own process against a
  local stub of the auth and verify endpoints. Sign-in, unlock and session
  refresh against the live backend are not.
- The agent does not run on Windows. `SF_EMAIL` and `SF_PASSWORD` keep working
  there, and everywhere, exactly as before.
- The ledger starts empty. Existing `.shieldfive-sync.json` manifests are not
  imported: they hold no content hash to check a claim against.

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
