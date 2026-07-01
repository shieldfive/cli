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
- The direct upload path (files up to one 5 MiB chunk) has been run end to end
  against the production backend: files uploaded by this CLI appear in the web
  app with their real names and decrypt correctly.
- The **multipart** path (files larger than 5 MiB) is covered by a byte-for-byte
  review against the server contract and a mock end-to-end test that decrypts
  every part, but has not yet been exercised against production with a real
  large file.
- `sf sync` is **append-only**: it uploads new and changed files; it does not
  yet mirror local deletions or renames into the vault.

## Requirements

- Node.js >= 20
- A ShieldFive account with a vault (create one in the web app first)

Not yet published to npm. For now, clone and run:

```sh
git clone https://github.com/shieldfive/cli.git
cd cli
npm install     # @shieldfive/crypto (+ libsodium), @supabase/supabase-js, @noble/*
npm test        # 27/27
```

## Commands

```
sf encrypt <folder>                          encrypt each file locally, upload nothing (no account needed)
sf push <folder>                             sign in, unlock, encrypt, upload every file once
sf sync <folder> [--watch] [--interval=N]    upload new/changed files; --watch keeps a poll loop (N seconds, default 5)
```

`sf push` and `sf sync` pick the direct or multipart upload path automatically
from the file size. `sf sync` writes a `.shieldfive-sync.json` manifest in the
target folder that records what has already been uploaded (by size and mtime),
so unchanged files are skipped and an interrupted run does not re-upload
everything.

## Running the live commands

`sf push` and `sf sync` need only your ShieldFive account. Your password is
typed, never passed on the command line:

```sh
export SF_EMAIL=you@example.com
read -rs SF_PASSWORD; echo; export SF_PASSWORD
export SF_VAULT_PASSWORD="$SF_PASSWORD"   # only if your vault password differs

sf push ./my-folder
sf sync ./my-folder --watch
```

The backend endpoints default to ShieldFive, so there is nothing else to
configure. `SF_API_BASE_URL`, `SF_SUPABASE_URL`, and `SF_SUPABASE_ANON_KEY` are
baked in with ShieldFive's public values — the Supabase anon key is a `role=anon`
JWT gated by row-level security, the same value any browser receives — and only
need overriding if you point the CLI at a development backend. If two-factor
authentication is enabled on your account, the MFA step-up is not yet handled by
the CLI.

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
- `src/sfCrypto.mjs` — the post-quantum hybrid encrypt/decrypt used by the
  `sf encrypt` demo
- `test/*.test.mjs` — round-trip guarantees plus the mock end-to-end upload and
  sync tests

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not
open a public issue for security reports.

## License

[Apache-2.0](LICENSE)
