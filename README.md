# @shieldfive/cli

> Command-line client for [ShieldFive](https://shieldfive.com). Encrypt a folder
> on your machine, then push or continuously sync it to your EU-hosted vault.
> File contents and names are encrypted locally before they leave your machine
> (contents with a post-quantum hybrid key). Read the code and verify that for
> yourself.

[![CI](https://github.com/shieldfive/cli/actions/workflows/ci.yml/badge.svg)](https://github.com/shieldfive/cli/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-early-yellow.svg)](#honest-scope)

The point of this tool being open source is that you do not have to trust a
marketing claim. The plaintext of your files and their names is never sent to a
ShieldFive server:

- **File contents** — AES-256-GCM chunks under a per-file key that combines a
  random envelope key (wrapped by your vault root key) with an ML-KEM-1024 +
  X25519 hybrid encapsulation to your vault identity.
- **File names** — AES-256-GCM under a key derived from your vault root key
  (not the post-quantum layer), plus a keyed HMAC of the lowercased name so the
  server can spot duplicates without reading it.

What the server does see, by design: the plaintext size of each file, part
hashes (SHA-1 of ciphertext), the wrapped keys, an upload proof, timestamps and
your account. Sign-in sends a secret derived from your password, never the
password itself. Two files carry the whole story:

- [`src/uploadCrypto.mjs`](src/uploadCrypto.mjs) — the encryption applied to
  every chunk and to the filename.
- [`src/upload.mjs`](src/upload.mjs) — the only place file bytes are sent over
  the network. Every file body it sends is ciphertext.

If you want to see encryption happen without an account at all, run
`sf encrypt <folder>` — it encrypts each file locally and prints the ciphertext
size, uploading nothing.

## Honest scope

- The underlying cryptography ([`@shieldfive/crypto`](https://github.com/shieldfive/crypto))
  has **not** undergone an external audit yet. Treat this as early software.
- **`sf push` was run against production on 2026-11-16** (0.5.0, with the
  dedicated canary account) on a tree of 248 files (534 MB) in 10 folders: a
  520 MB file, a 12 MB file, 240 small files, an empty folder, a 0-byte file,
  Unicode, 200-character and duplicate names, two `.DS_Store` files and a
  symlink. The first run was killed (SIGKILL) after 81 files, the second was
  stopped with Ctrl-C after 60 more, the third resumed and finished, and a
  fourth uploaded nothing. In the production database all 247 non-empty files
  are `ready`, each with its id, plaintext size and folder exactly as the client
  recorded them, and the 10 folders form the source tree. The hidden files and
  the symlink were skipped. Three of the files (a small one at the top, the
  Unicode-named one and the 520 MB one) were then downloaded in the web app and
  decrypted byte-identical. Uploading left the account's download allowance
  counter unchanged. One `sf sync` pass of a flat folder uploaded both of its
  files to the vault root. Production does not accept 0-byte files yet:
  `sf push` skips them, says so, and exits 2.
- These `sf push` behaviours are covered by offline tests only and have **not**
  been exercised against production: retries after network errors and 5xx/429
  answers, stopping on a full vault, refreshing the session during a run longer
  than the access token's lifetime, settling a file whose finalize was cut off,
  a file changing while it uploads, a vault folder deleted between runs, and a
  vault password different from the account password.
- `sf sync` is **append-only**: it uploads new and changed files; it does not
  yet mirror local deletions or renames into the vault.
- **`sf login` and the agent have not been run against production.** They are
  covered by offline tests, including one that runs the agent as its own process
  and reaches it from separate `sf` processes against a local stub of the auth
  and verify endpoints. Sign-in, unlock and session refresh against the live
  backend are not covered.

## Requirements

- Node.js >= 20
- A ShieldFive account with a vault (create one in the web app first)

## Install

```sh
npm install -g @shieldfive/cli    # installs sf and shieldfive
```

The package installs without lifecycle scripts.

Or run it without installing:

```sh
npx @shieldfive/cli --help
```

To read and build from source (the whole point — verify what it does before you
trust it):

```sh
git clone https://github.com/shieldfive/cli.git
cd cli
npm ci
npm test
```

## Commands

```
sf login [--idle=<hours>]                    sign in once; an agent holds the session in memory (locks after 8 h idle)
sf status                                    is an agent running, and for which account
sf logout [--everywhere]                     revoke the session and stop the agent; --everywhere signs out every device
sf push <folder> [--include-dotfiles]        copy a whole folder tree into a new vault folder; rerun to resume
sf sync <folder> [--watch] [--interval=N]    upload new/changed files; --watch keeps a poll loop (N seconds, default 5)
sf verify <file>...                          report whether each file is safely stored in your vault
sf encrypt <folder>                          encrypt each file locally, upload nothing (no account needed)
sf inspect <folder>                          read-only recursive migration inventory; upload nothing
```

`sf push` and `sf sync` pick the direct or multipart upload path automatically
from the file size. Symlinks are never followed (files are opened with
`O_NOFOLLOW`), and names starting with `.` (`.DS_Store`, `.git`, `.env`) are
skipped unless you pass `sf push --include-dotfiles`. An empty (0-byte) file is
uploaded only when the server says it accepts empty files; otherwise it is
reported as skipped and the exit code is 2. If an upload fails after its session
was created, the pending session is cancelled so it does not hold quota.

`sf push` copies the whole tree: it creates one vault folder named after
`<folder>` and recreates every subfolder (empty ones too) inside it, the way the
web app's Upload folder does. Three files upload at a time
(`SF_PUSH_CONCURRENCY`, 1-8); large files also send three parts at a time
(`SF_UPLOAD_CONCURRENCY`). Network errors, 5xx, 408 and 429 answers are retried
with backoff. It prints each file as it finishes and a progress line every 10
seconds. A full vault or a refused session stops the run; any other file that
fails is listed, the rest continue, and the exit code is 2.

It is resumable. A state file in `~/.shieldfive/push/` (mode 0600; file names
and vault ids, never keys) records each folder made and each file once its
upload is final, so running the same command again skips those and uploads the
rest; a file interrupted halfway starts again from its beginning. The first
Ctrl-C lets the uploads in progress finish and exits 130; a second quits at once.
A run killed during a file's last step is settled on the next run by asking the
server whether that file arrived, so it is not uploaded twice. A file that
changes while it uploads is reported, and uploaded again on the next run. Files
you delete from the vault after a run are not re-uploaded by a rerun.

Through the agent (`sf login`), `sf push` uploads only the files at the top of
the folder, to the vault root, and refuses a folder with subfolders; use the
environment variables below for a tree. `sf sync` is also top-level only and
uploads to the vault root.

`sf inspect` reports JSON counts of files, directories, bytes and skipped entries.
It includes nested/hidden files and empty folders, reads metadata only, and
does not follow symbolic links. Exit code 2 means entries were skipped. It does
not upload anything or prove that a migration has completed. Current push/sync
remain top-level only; do not use their completion as proof of a whole-tree copy.

With an agent running, `sf sync` records uploads in the agent's ledger (see
[What the agent can and cannot do](#what-the-agent-can-and-cannot-do)) and
`sf verify` works. Without one, `sf sync` writes a `.shieldfive-sync.json`
manifest in the target folder that records what has already been uploaded (by
size and mtime), so unchanged files are skipped and an interrupted run does not
re-upload everything; `sf verify` needs the agent.

## Running the live commands

### With `sf login`

```sh
sf login
sf push ./my-folder
sf sync ./my-folder --watch
sf verify ./my-folder/tax-return-2025.pdf
sf logout
```

`sf login` prompts for your email, your password and, if it differs, your vault
password. It never reads them from the environment and there is no flag for
them. It then starts an agent in the background and exits; every later command
talks to that agent and needs nothing exported.

If `SF_EMAIL` and `SF_PASSWORD` are also set, `sf push` and `sf sync` sign in
with those instead and tell you an agent is running, so a script written for one
account is never sent to another. `sf push` exits 2 if a file changed while it
was being uploaded: the vault then holds the version that was read, not the file
as it is now.

### Without an agent

`sf push` and `sf sync` still work from environment variables, exactly as
before. Your password is typed, never passed on the command line:

```sh
export SF_EMAIL=you@example.com
read -rs SF_PASSWORD; echo; export SF_PASSWORD
# If your vault password differs, set SF_VAULT_PASSWORD as well.

sf push ./my-folder
sf sync ./my-folder --watch
```

On Windows, use PowerShell:

```powershell
$env:SF_EMAIL = 'you@example.com'
$env:SF_PASSWORD = [System.Net.NetworkCredential]::new('', (Read-Host 'ShieldFive password' -AsSecureString)).Password
sf push 'C:\Users\you\Documents'
Remove-Item Env:SF_PASSWORD
```

The backend endpoints default to ShieldFive, so there is nothing else to
configure. `SF_API_BASE_URL`, `SF_SUPABASE_URL`, and `SF_SUPABASE_ANON_KEY` are
baked in with ShieldFive's public values (the public auth key is a `role=anon`
JWT gated by row-level security, the same value any browser receives) and only
need overriding if you point the CLI at a development backend.

### Two-factor authentication

If your account has an authenticator app (TOTP) enabled, the CLI performs the
AAL2 step-up automatically: after your password it prompts

```
Two-factor code (6 digits):
```

Enter the current code from your authenticator. In a non-interactive context
(scripts, CI) set `SF_TOTP_CODE` to the current code instead of being prompted.
Only TOTP is supported; SMS and other factors are not.

With `sf login` you are asked once. The agent refreshes the stepped-up session
on its own, so `sf sync --watch` keeps working on a two-factor account until the
agent locks or you log out.

## Migrating from Dropbox or Google Drive with rclone

For most people the web app is simpler: sync Dropbox to your computer, then
**Upload > Upload folder** in the browser
(see [Move from Dropbox to ShieldFive](https://shieldfive.com/help/move-from-dropbox)).
For a large or scripted move:

```sh
# 1. Copy your cloud files to a local folder (rclone.org; `rclone config` first)
rclone copy dropbox: ~/dropbox-export --progress
#    Google Drive: rclone copy gdrive: ~/drive-export --progress

# 2. Encrypt and upload it, keeping the folder structure
export SF_EMAIL=you@example.com
read -rs SF_PASSWORD; echo; export SF_PASSWORD
sf push ~/dropbox-export

# 3. If it stops for any reason, run the same command again: it resumes.
sf push ~/dropbox-export
```

Your vault gets a folder named `dropbox-export` with the same tree inside. The
command exits 0 only when every file is in the vault. Uploads do not count
toward your monthly download allowance. `sf push` copies once; it does not keep
the folder in sync afterwards.

## What the agent can and cannot do

The agent keeps two things in memory: your signed-in session and your unlocked
vault key. Neither is written to disk. It listens on a Unix socket in
`~/.shieldfive/run`, a directory only your user can enter, and refuses to start
if that directory is a symlink, owned by someone else or open to other users.
Only one agent runs at a time.

It accepts six requests: `status`, `upload`, `sync`, `verify`, `lock` and
`logout`. It cannot list what is in your vault, download a file, decrypt
anything, or hand out the key, because there is no request for any of those. A
process that reaches the socket can put files into your vault and ask whether
files are backed up. It cannot read your vault through the agent.

Uploads are recorded in `~/.shieldfive/ledger/<account>.jsonl`: the path, size,
time, vault file id, and an HMAC of the bytes that were actually encrypted, under
a key derived from your vault key. A plain hash would let anyone holding the
ledger confirm whether you have a particular known document; the HMAC does not,
without your vault key. Each record also carries a tag under that key, so a line
added to the ledger by anything other than the agent is ignored, and records
made on another machine do not count on this one.

`sf verify` reports a file as **backed up** only when the bytes on disk now
match an upload in the ledger and the server confirms, at that moment, that the
upload is stored, complete, intact and not in your Bin. It never decides by name
or size. The other answers:

| Answer | Meaning |
|---|---|
| `NOT confirmed` | these bytes were uploaded, but the server cannot confirm they are still safely stored |
| `changed since upload` | this path was uploaded, but the file has changed since |
| `no upload record` | this agent never uploaded these bytes; they may still be in your vault from another device |
| `unreadable` | the local file could not be read |

`no upload record` does not mean the file is missing from your vault. Do not
delete anything on the strength of that answer.

The agent locks itself after 8 hours without an upload, sync or verify
(`sf login --idle=<hours>` to change it; `sf status` does not count). Locking and
`sf logout` both overwrite the key in memory first and then sign the session out
on the server. Sessions on ShieldFive do not expire on their own, so a session
that is forgotten rather than signed out would stay valid. If the server cannot
be reached when you log out, `sf logout` says the session is still valid and
exits 1; run `sf login` and then `sf logout --everywhere` once you are online.

Limits:

- The agent is available on macOS and Linux. On Windows, set `SF_EMAIL` and
  `SF_PASSWORD` in PowerShell and run `sf push` or `sf sync`.
- Node cannot see which process connected to the socket, so directory
  permissions are the only gate. This is also how `ssh-agent` works on macOS.
- Overwriting the key in memory is best-effort. A garbage-collected runtime can
  copy key material during crypto operations.
- The ledger is per device. A file uploaded from another machine shows as
  `no upload record` here.

The full design, including the threat model, is in
[`docs/agent-design.md`](docs/agent-design.md).

## How the upload works (for auditors)

Uploads are written in the format the web app writes by default:
`cipher_version` 3, suite `0x03` (post-quantum hybrid) in the v1 wire format
(`@shieldfive/crypto` `spec/format-v1.md`), using the library's own stream
encoder.

- **Filename** — encrypted with AES-GCM under a key derived from your vault root
  key via Argon2id (`encryptMetadataV4`), then, at finalize, re-sealed with the
  file's row id as additional data (v6, `encryptNameV6`), so the server cannot
  move one file's name onto another row. A keyed HMAC of the lowercased name
  (`hashMetadataV4`) lets the server deduplicate without learning the name.
- **File content** — a MAC'd header carries the file's `file_id` (the row id the
  server assigned, so the stored object is bound to its row), the plaintext size
  and the chunk count. The content key combines a per-file envelope key (wrapped
  by your root key in `csk_wrapped`) with an ML-KEM-1024 + X25519 encapsulation
  to your vault identity, which is derived on this machine from your root key,
  as the web app derives it; the server cannot substitute a recipient. Each 5 MiB
  chunk is AES-256-GCM with its index, the total and an is-final flag in the
  additional data, so a dropped, reordered or truncated chunk fails to decrypt.
- **Upload proof** — base64 of `[3][3] || HMAC-SHA256(proofKey, [3][3] || header
  || frame_0)` (`buildUploadProofV3` in `@shieldfive/crypto`, the same function
  the web and the MCP server use). The server issues `proofKey` when it creates
  the session and verifies the proof against the stored object when finalizing.
- **Parts** — each storage part is exactly one encrypted chunk frame; part 1 also
  carries the header.

Versions up to 0.3.0 wrote the legacy v0 format (AES-GCM chunks under a random
nonce prefix, no header): no truncation detection, no row binding and no
post-quantum layer. Files already uploaded that way still open in the apps;
this client no longer writes it.

- **Direct** (≤ 5 MiB) — the single encrypted chunk is `PUT` at a presigned S3
  URL the server issues with the session. The URL's SigV4 signature is the only
  credential and it authorises exactly one object key, so the request carries no
  `Authorization` header and no `X-Bz-*` headers; the client sends no storage id
  at finalize, because the server reads the real one off the stored object.
  Because the signature covers `host` only, nothing on this path binds the body:
  the server compares the client's `ciphertextHash` against the client's own
  `partSha1Array[0]`, so they always agree. Integrity here rests on the upload
  proof and on the header MAC and chunk tags at download, not on a wire checksum.
- **Multipart** (> 5 MiB) — the file is streamed one 5 MiB chunk at a time (never
  loaded whole into memory). The server can allocate signed part URLs or native
  multipart credentials. The server finishes the file with the ordered part
  manifest. Transient failures retry the same encrypted part with fresh
  credentials. Rerunning `sf push` skips files already completed.

The mock end-to-end test in [`test/upload.flow.test.mjs`](test/upload.flow.test.mjs)
captures every byte this client would send, opens the stored object with
`@shieldfive/crypto`'s reference reader from nothing but the session fields and
the root key, and asserts the result equals the original file and the header's
`file_id` equals the row id. [`test/v1Format.test.mjs`](test/v1Format.test.mjs)
checks the shared vectors in [`test/vectors/v3-upload.json`](test/vectors/v3-upload.json)
(regenerate with `node scripts/generate-vectors.mjs`) against the library's
blob and streaming readers.

## Layout

- `src/cli.mjs` — the `sf` entry point (argument parsing, command dispatch)
- `src/auth.mjs` — sign-in to a Bearer token through ShieldFive's sign-in route,
  with two-factor step-up
- `src/loginSecret.mjs` — the login secret derived from your password; for
  accounts on the current scheme the password itself is never sent
- `src/argon2.mjs` — Argon2id via the shared WebAssembly implementation
- `src/vault.mjs` / `src/unlock.mjs` — fetch the wrapped vault key, unwrap the
  root key from your password (Argon2id / PBKDF2)
- `src/uploadCrypto.mjs` — filename encryption, the suite-0x03 part writer,
  upload proof, multipart ciphertext hash
- `src/upload.mjs` — create session, encrypt, upload (direct + multipart),
  finalize; the streaming chunk reader
- `src/sync.mjs` — `sf sync`: manifest, change detection, reconcile pass, watch
  loop (reuses `upload.mjs`)
- `src/prompt.mjs` — terminal prompts; the password prompt echoes nothing
- `src/agent/` — `sf login`'s agent: `server.mjs` (the process and its six
  requests), `client.mjs`, `protocol.mjs` (the request allowlist), `ledger.mjs`
  (HMAC upload ledger and `verify` classification), `paths.mjs` (socket
  directory checks), `main.mjs` (entry point and session handoff)
- `docs/agent-design.md` — design record and threat model for the agent
- `src/sfCrypto.mjs` — the post-quantum hybrid encrypt/decrypt used by the
  `sf encrypt` demo
- `test/*.test.mjs` — round-trip guarantees plus the mock end-to-end upload and
  sync tests

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not
open a public issue for security reports.

## License

[Apache-2.0](LICENSE)
