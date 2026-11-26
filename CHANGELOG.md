# Changelog

All notable changes to `@shieldfive/cli` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.6.2

- `sf push` of a folder tree or `--media`, `sf tidy` and `sf thumbnails` now
  work with the signed-in session (`sf login`): no SF_EMAIL / SF_PASSWORD and
  no logout. The agent runs them and prints a summary at the end.
- `sf tidy` counts first and says what to run next. `--delete` removes only
  empty NAS/system-named folders, including ones an earlier tidy left in the
  Bin, and re-checks on the server right before each delete that nothing
  under the folder holds a file.

## 0.6.1

- `sf push` skips NAS and system folders (`@eaDir`, `#recycle`, `#snapshot`,
  `$RECYCLE.BIN`, `lost+found`, ...). On a Synology share `@eaDir` held one
  folder per photo, so a photo library push made thousands of empty vault
  folders and stopped at the account's 10,000-folder limit with
  `POST /api/folders/create failed (HTTP 409)`.
- Before creating folders, `sf push` checks the folder limit and stops with a
  plain message saying how many folders it needs and what to delete.
- Folder errors now say which folder failed and why, in plain words.
- A rerun (also from another machine, or with the resume record gone) reuses
  existing Media subfolders by name instead of making copies, and an
  "already exists" answer for Media looks the folder up and uses it.
- New `sf tidy [<folder>] [--media] [--vault-folder=<path>]`: finds the empty
  NAS/system folders (`@eaDir`, `#recycle`, `.DS_Store`, `@SynoResource`, ...)
  an earlier push made, shows how many, and on confirmation moves them to the
  Bin. Folders holding any file are never touched. `--dry-run` only counts,
  `--yes` skips the question, `--delete` then removes exactly those folders
  from the Bin (Bin folders still count toward the folder limit).

## 0.6.0

- `sf push --media <folder>` uploads into Media (the photo and video gallery)
  instead of a new Drive folder. Top-level files go into Media itself,
  subfolders become Media subfolders, and the Media folder is created if the
  account has none. It keeps its own resume record, separate from a Drive push
  of the same folder.
- Photos and videos pushed with `sf push` now carry an encrypted preview, so
  they show a thumbnail in Drive and Media. The JPEG (<=512 px, ~55 KB budget)
  is made locally and encrypted under the file's content key in the format the
  web and mobile apps already read; only ciphertext is sent. Images use the new
  optional dependency `sharp`; video previews (and HEIC) need `ffmpeg` on PATH,
  and without it those files upload without a preview, with one note.
  `--no-thumbnails` turns previews off.
- `sf sync` and pushes through the agent (`sf login`) make the same previews.
  `SF_NO_THUMBNAILS=1` turns them off for every command.
- `sf thumbnails <folder>` adds previews to photos and videos already in the
  vault, from the originals still in `<folder>`: each vault file is matched to
  the local file at the same path with the same size, and only the encrypted
  preview is sent. No file is uploaded again and nothing is downloaded.
  `--dry-run` counts first; `--media` or `--vault-folder=<a/b>` say which vault
  folder holds the copy (default: the folder `sf push` made for it). Previews go
  in batches when the server accepts them; reruns skip what is done.

## 0.5.3

- A single transient server error no longer fails an upload. Creating the
  upload session, getting upload credentials, uploading parts and completing
  the upload each retry HTTP 5xx, 429, connection resets and timeouts with
  bounded, randomized backoff (7 attempts). A reply cut off mid-body is
  retried instead of being read as empty.
- Requests have a deadline (90 s for API calls, 10 min per storage part), so a
  stalled connection is retried instead of hanging the upload.
- An API HTTP 401 during an upload refreshes the sign-in once and repeats the
  request. If the refresh fails, the upload stops with the sign-in-again
  message. Other 4xx answers are never retried.

## 0.5.2

- Uploads that take longer than the sign-in lifetime (about an hour, e.g. a
  multi-gigabyte file) no longer fail with "Get upload credentials failed
  (HTTP 401)": the agent and `sf sync` refresh the access token per request.
- A 401 during an upload now says the sign-in expired or was revoked and to
  run `sf logout`, then `sf login`.

## 0.5.1

- Installation requires no lifecycle scripts. Argon2id uses the web vault's
  WebAssembly implementation and produces the same keys.
- `sf push` uses signed multipart uploads when the server allocates them.
  Transient failures retry with fresh credentials and randomized backoff.
- On Windows, agent sign-in points to `SF_EMAIL` and `SF_PASSWORD` for
  `sf push` and `sf sync`. The package provides both `sf` and `shieldfive`.

## 0.5.0 — 2026-11-16

### Behaviour changes

- **`sf push` copies the whole folder tree.** It creates one vault folder named
  after the source and recreates every subfolder inside it (folder keys and
  names made as the web app's Upload folder makes them). It used to upload only
  the files at the top of the folder, to the vault root. Through the agent it
  still does that, and refuses a folder with subfolders.
- **`sf push` is resumable.** A 0600 state file in `~/.shieldfive/push/` records
  finished folders and files; rerunning skips them. A file whose finalize was
  cut off is settled by asking the server, not uploaded twice.

### Added

- Retries with backoff for network errors and 5xx/408/429 answers on the
  session, the direct PUT, each part and the folder calls; 3 files at a time
  (`SF_PUSH_CONCURRENCY`); per-file output and a progress line every 10 s;
  first Ctrl-C finishes uploads in progress, second quits.
- The access token is refreshed during a long push, including in the middle of
  a large file.
- File and folder names are sent in Unicode NFC.

### Verified

- Run against production on 2026-11-16 with the canary account: 248 files /
  534 MB in 10 folders (520 MB and 12 MB files, Unicode/long/duplicate names),
  killed and interrupted midway, resumed; all 247 non-empty files `ready` with
  the recorded ids, sizes and folders; three of them (including the 520 MB
  file) downloaded byte-identical in the web app; the 0-byte file skipped
  (production does not accept empty files yet).

## 0.4.0 — 2026-10-12

### Behaviour changes

- `sf push` now skips dotfiles (`.env`, `.git`, ...) by default; pass
  `--include-dotfiles` to upload them as before.
- Sign-in refuses a server answer of auth version 1 for an account previously
  signed in with version 2; pass `--allow-legacy-login` to override.
- Symlinks are skipped instead of followed.

### Security

- **Symlinks are not followed.** `push`, `sync` and the agent list files with
  `lstat` and skip symlinks, and files are opened with `O_NOFOLLOW`, so a link
  inside the folder can no longer upload a file from outside it.
- **`push` skips dotfiles by default** (`.env`, `.git`, ...), as `sync` already
  did. `sf push --include-dotfiles` restores the old behaviour.
- **Sync manifest written 0600.** `.shieldfive-sync.json` lists file names and
  vault ids; it is no longer world-readable.
- **README and npm description** now state the scheme precisely: contents are
  AES-256-GCM under a post-quantum hybrid key, names are AES-256-GCM under the
  vault key, and size, part hashes and timestamps are visible to the server.

### Fixed

- A failed upload cancels its pending session (`POST /api/files/delete`, as the
  web app does) instead of leaving a row holding quota until the reaper runs.
  Not done when only the finalize answer was lost, since the file may be in.
- 0-byte files: uploaded as a header-only cipher-v3 object with the server's
  empty-file proof when `/api/files/upload-capabilities` says `emptyCipherV3`;
  otherwise skipped with a clear message (exit code 2) before any session.
- New uploads send a v6 row-bound encrypted name from upload start (#14).
- **Downgrade pin for sign-in.** After a sign-in with a login secret (auth
  version 2), the CLI records the account (a SHA-256 of the email) in
  `~/.shieldfive/auth-pins.json` (mode 0600). A later server answer of
  version 1 for that account is refused before the raw password is sent.
  `--allow-legacy-login` on `sf login`, `sf push` or `sf sync` overrides it.

## 0.3.1 - 2026-10-01

### Security

- **`sf push` and `sf sync` write the web's default format.** They wrote the
  deprecated v0 format (AES-GCM chunks, no header), which the format spec
  forbids for new writes: a server could drop trailing chunks and the file
  still decrypted, could move a file's bytes onto another row, and there was no
  post-quantum layer despite the description. Uploads are now `cipher_version`
  3 (suite 0x03, ML-KEM-1024 + X25519 hybrid, v1 wire format) written by
  `@shieldfive/crypto`'s stream encoder, with the row id as the header's
  `file_id` and the filename re-sealed bound to the row (v6) at finalize. The
  recipient key is derived locally from the root key, never fetched. Files
  uploaded by earlier versions still open in the apps. Shared decrypt vectors:
  `test/vectors/v3-upload.json`.
- `@shieldfive/crypto` is pinned to `~1.0.1` (was `^1.0.0-beta.1`, which a
  global install could float to any 1.x).

### Fixed

- `sf sync --watch` refreshes its session before the access token expires.
  It signed in once, so after about an hour every pass failed every changed
  file while the process kept running. If the session cannot be refreshed, sync
  now stops with an error. A single `sf sync` pass with failed files exits
  non-zero.

- **Sign-in works for accounts on ShieldFive's current sign-in scheme.** 0.3.0
  posted your password straight to the authentication service, which fails for every account that
  signs in with a client-derived login secret (all new accounts, and every
  account migrated on its next web or app sign-in), and sent the password to
  the server on each failed attempt. `sf login`, `sf push` and `sf sync` now ask
  ShieldFive how the account signs in, derive the login secret locally
  (Argon2id, the same parameters and bytes as the web and Android apps) and
  send only that. The raw password is sent only for an account the server
  reports as not yet migrated, and only to ShieldFive's sign-in route. If that
  lookup fails for any reason, sign-in stops before anything is sent.
- A vault password typed with leading or trailing spaces now unlocks a vault
  created on the web, which trims them.

### Changed

- Argon2id runs natively (the `argon2` package, off the main thread) when it
  installs, and falls back to the bundled WebAssembly implementation when it
  does not, so installation never fails on a platform without a prebuilt
  binary. Both produce identical keys; parameters are unchanged.

## 0.3.0 - 2026-09-16

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
  at finalize — a presigned PUT returns an ETag, not a storage file ID, and
  forwarding it would have been persisted verbatim as the storage id. Files
  larger than 5 MiB were never affected; the multipart path is unchanged and
  keeps its token, its `X-Bz-*` headers and its session-derived `b2FileId`.

### Changed

- **The direct path no longer sends a wire checksum.** It previously sent
  `X-Bz-Content-Sha1`, which the native storage upload verified server-side and
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
  enrolled now complete the AAL2 step-up during sign-in, which the
  server's upload gate requires. After the password, the CLI prompts
  `Two-factor code (6 digits):` (or reads `SF_TOTP_CODE` in non-interactive
  contexts), runs the standard challenge/verify against the verified TOTP
  factor, and uses the elevated token for uploads. Only TOTP is supported; SMS
  and other factors are not. Accounts without 2FA are unaffected and are never
  prompted.

### Notes

- The step-up flow is covered by unit tests over a mocked authentication client
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
