# @shieldfive/cli

> Command-line client for [ShieldFive](https://shieldfive.com). Encrypt a folder
> on your machine, then push or continuously sync it to your EU-hosted,
> post-quantum vault. Everything is encrypted locally before it leaves your
> machine. Read the code and verify that for yourself.

[![CI](https://github.com/shieldfive/cli/actions/workflows/ci.yml/badge.svg)](https://github.com/shieldfive/cli/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-early-yellow.svg)](#honest-scope)

The point of this tool being open source is that you do not have to trust a
marketing claim. The plaintext of your files is never sent to a ShieldFive
server. The only bytes that leave your machine are AES-GCM ciphertext and a
short cryptographic proof. Two files carry the whole story:

- [`src/uploadCrypto.mjs`](src/uploadCrypto.mjs) — the encryption applied to
  every chunk and to the filename.
- [`src/upload.mjs`](src/upload.mjs) — the only place bytes are sent over the
  network. Every request body is ciphertext.

If you want to see encryption happen without an account at all, run
`sf encrypt <folder>` — it encrypts each file locally and prints the ciphertext
size, uploading nothing.

## Honest scope

- The underlying cryptography ([`@shieldfive/crypto`](https://github.com/shieldfive/crypto))
  has **not** undergone an external audit yet. Treat this as early software.
- **Neither upload path has been exercised against production since 2026-09-03.**
  The direct (≤ 5 MiB) path was validated end to end against the backend as it
  stood at 0.1.0, but the server then moved that path to a presigned S3 PUT and
  stopped issuing an upload token. 0.2.0 hard-required that token, so it could
  not upload any file of 5 MiB or less at all. This release rewrites the direct
  path to the presigned PUT. It is covered by the offline mock test in
  [`test/upload.flow.test.mjs`](test/upload.flow.test.mjs) and sends byte-for-byte
  the request the web app sends, but it has not been run live.
- The **multipart** path (files larger than 5 MiB) is covered by a byte-for-byte
  review against the server contract and a mock end-to-end test that decrypts
  every part, but has not yet been exercised against production with a real
  large file.
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
npm install -g @shieldfive/cli    # provides the `sf` command
```

Or run it without installing:

```sh
npx @shieldfive/cli --help
```

To read and build from source (the whole point — verify what it does before you
trust it):

```sh
git clone https://github.com/shieldfive/cli.git
cd cli
npm install     # @shieldfive/crypto (+ libsodium), @supabase/supabase-js, @noble/*
npm test        # 89 tests
```

## Commands

```
sf login [--idle=<hours>]                    sign in once; an agent holds the session in memory (locks after 8 h idle)
sf status                                    is an agent running, and for which account
sf logout                                    revoke the session on the server and stop the agent
sf push <folder>                             encrypt and upload every file once
sf sync <folder> [--watch] [--interval=N]    upload new/changed files; --watch keeps a poll loop (N seconds, default 5)
sf verify <file>...                          report whether each file is safely stored in your vault
sf encrypt <folder>                          encrypt each file locally, upload nothing (no account needed)
```

`sf push` and `sf sync` pick the direct or multipart upload path automatically
from the file size.

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

### Without an agent

`sf push` and `sf sync` still work from environment variables, exactly as
before. Your password is typed, never passed on the command line:

```sh
export SF_EMAIL=you@example.com
read -rs SF_PASSWORD; echo; export SF_PASSWORD
export SF_VAULT_PASSWORD="$SF_PASSWORD"   # only if your vault password differs

sf push ./my-folder
sf sync ./my-folder --watch
```

The backend endpoints default to ShieldFive, so there is nothing else to
configure. `SF_API_BASE_URL`, `SF_SUPABASE_URL`, and `SF_SUPABASE_ANON_KEY` are
baked in with ShieldFive's public values (the Supabase anon key is a `role=anon`
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

## What the agent can and cannot do

The agent keeps two things in memory: your signed-in session and your unlocked
vault key. Neither is written to disk. It listens on a Unix socket inside a
directory only your user can enter (`$XDG_RUNTIME_DIR/shieldfive` on Linux,
`$TMPDIR/shieldfive-agent` on macOS), and refuses to start if that directory is
owned by someone else or open to other users.

It accepts six requests: `status`, `upload`, `sync`, `verify`, `lock` and
`logout`. It cannot list what is in your vault, download a file, decrypt
anything, or hand out the key, because there is no request for any of those. A
process that reaches the socket can put files into your vault and ask whether
files are backed up. It cannot read your vault through the agent.

Uploads are recorded in `~/.shieldfive/ledger/<account>.jsonl`: the path, size,
time, vault file id, and an HMAC of the file's contents under a key derived from
your vault key. A plain hash would let anyone holding the ledger confirm whether
you have a particular known document; the HMAC does not, without your vault key.

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

The agent locks itself after 8 hours without a request (`sf login --idle=<hours>`
to change it). Locking and `sf logout` both sign the session out on the server
and overwrite the key in memory. Sessions on ShieldFive do not expire on their
own, so a session that is forgotten rather than signed out would stay valid;
if you are offline when you log out, `sf logout` says so.

Limits:

- Windows is not supported. Use `SF_EMAIL` and `SF_PASSWORD` there.
- Node cannot see which process connected to the socket, so directory
  permissions are the only gate. This is also how `ssh-agent` works on macOS.
- Overwriting the key in memory is best-effort. A garbage-collected runtime can
  copy key material during crypto operations.
- The ledger is per device. A file uploaded from another machine shows as
  `no upload record` here.

The full design, including the threat model, is in
[`docs/agent-design.md`](docs/agent-design.md).

## How the upload works (for auditors)

The upload uses **chunked AES-GCM** for file content and issues a
server-verified HMAC proof. (The `sf encrypt` demo uses the post-quantum hybrid
suite; the sync/push path uses AES-GCM, which is what the vault's upload
protocol and server-side proof expect.)

- **Filename** — encrypted with AES-GCM under a key derived from your vault root
  key via Argon2id (`encryptMetadataV4`). The server stores ciphertext; it never
  sees the name. A keyed HMAC of the lowercased name (`hashMetadataV4`) lets the
  server deduplicate without learning the name.
- **File content** — each chunk is AES-GCM encrypted under a per-file content
  key (itself wrapped by your root key). The nonce is a 4-byte random prefix
  followed by an 8-byte big-endian chunk counter, so every chunk has a distinct
  nonce.
- **Upload proof** — `HMAC-SHA256(proofKey, prefix || ciphertext)` over the first
  chunk, where `prefix = [version=1][cipherVersion=1][chunkSize u32 BE][noncePrefix 4]`.
  The server issues `proofKey` when it creates the session and verifies the proof
  when finalizing. It ties the stored ciphertext to the session without the
  server ever seeing plaintext.
- **Direct** (≤ 5 MiB) — the single encrypted chunk is `PUT` at a presigned S3
  URL the server issues with the session. The URL's SigV4 signature is the only
  credential and it authorises exactly one object key, so the request carries no
  `Authorization` header and no `X-Bz-*` headers; the client sends no storage id
  at finalize, because the server reads the real one off the stored object.
  Because the signature covers `host` only, nothing on this path binds the body:
  the server compares the client's `ciphertextHash` against the client's own
  `partSha1Array[0]`, so they always agree. Integrity here rests on the upload
  proof and on AES-GCM's tag at download, not on a wire checksum.
- **Multipart** (> 5 MiB) — the file is streamed one 5 MiB chunk at a time (never
  loaded whole into memory), each chunk uploaded as a Backblaze part. The
  ciphertext hash the server checks is SHA-1 over the concatenated raw part
  digests; the server finishes the large file with the ordered part list.

The mock end-to-end test in [`test/upload.flow.test.mjs`](test/upload.flow.test.mjs)
captures every byte this client would send, decrypts each part with the key
recovered from the session envelope, and asserts the result equals the original
file — a machine-checked demonstration that only ciphertext is uploaded.

## Layout

- `src/cli.mjs` — the `sf` entry point (argument parsing, command dispatch)
- `src/auth.mjs` — Supabase sign-in to a Bearer token
- `src/vault.mjs` / `src/unlock.mjs` — fetch the wrapped vault key, unwrap the
  root key from your password (Argon2id / PBKDF2)
- `src/uploadCrypto.mjs` — filename and chunk encryption, upload proof, multipart
  ciphertext hash
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
