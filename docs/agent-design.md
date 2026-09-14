# `sf agent`: design record

Status: accepted, 2026-09-14. Implementation in progress on `feat/agent`.

## Problem

`sf push` and `sf sync` read the account password from `SF_PASSWORD` and sign in
fresh on every run. That has three consequences.

1. Anything that wants to back files up on the user's behalf has to hold the
   password. The password derives the key that unwraps the vault root key, so
   holding it is holding the root key one Argon2id call away.
2. An account with two-factor authentication cannot sync unattended. The upload
   routes require an `aal2` token, and a process with no terminal cannot answer
   a TOTP prompt.
3. `@shieldfive/mcp` cannot offer `upload_to_vault` or a useful
   `compare_local_to_vault`. Its design record
   (`docs/mcp-v1-step0-discovery.md` in `shieldfive/web`, § 5) names a CLI-held
   credential as the only route to either that weakens nothing.

## Decision

A long-running `sf agent`, in the style of `ssh-agent`.

- `sf login` prompts for the password (hidden) and, if enrolled, a TOTP code,
  signs in, unwraps the root key, and hands the session and the key to a
  detached agent process. Nothing is written to disk.
- The agent keeps the root key and the refresh token **in memory only** and
  listens on a Unix domain socket in a directory only the user can enter.
- The socket protocol is **write-only with respect to the vault**. It can upload
  a file and answer whether a local file is safely stored. It has no operation
  that lists vault contents, downloads, decrypts, or returns key material, and
  none will be added.
- `sf logout` revokes the session server-side, overwrites the key buffers, and
  exits. The agent also locks itself after an idle period.

### Why not store the credential in the OS keychain

A keychain item created by a Node script is readable by any Node script running
as the user, because the macOS keychain ACL is bound to the binary (`node`), not
to the script. It would also put the secret at rest, in backups and disk images.
An agent holds nothing at rest, loses everything on reboot or logout, and can be
asked to act without ever being asked to disclose.

### Why a refresh token survives two-factor

The server's bearer MFA gate (`utils/mfa.ts` in `shieldfive/web`) reads the `aal`
claim from the JWT and requires `aal2` when the user has a verified TOTP factor.
It applies no recency window. Supabase stores `aal` on the session row
(`auth.sessions.aal`), so a session stepped up once mints `aal2` access tokens on
every refresh. One interactive `sf login` therefore unlocks unattended sync on a
two-factor account until the session is revoked.

Measured on production, 2026-09-14: 0 of 120 sessions carry `not_after`, and the
oldest is 39.6 days old. Sessions are not time-boxed. A leaked refresh token
would be valid until someone signs it out, which is why it never touches disk
and why `sf logout` revokes rather than merely forgetting it.

## The ledger

`compare_local_to_vault` needs to know which local files were uploaded, from
where, and whether they have changed since. The existing `.shieldfive-sync.json`
cannot answer that (discovery § 7): it keys by basename, stores no content hash,
records no absolute path, device or account, and a copied folder carries a
manifest that asserts uploads that never happened.

The agent keeps its own ledger instead, at
`~/.shieldfive/ledger/<account-id>.jsonl`, append-only, one record per upload:

```json
{"v":1,"path":"/Users/me/Taxes/2025.pdf","size":48211,"mtimeMs":1757340012345,
 "mac":"<hex>","fileId":"9c1e…","uploadedAt":"2026-09-14T…","device":"<uuid>"}
```

`mac` is `HMAC-SHA256(ledgerKey, plaintext)`, where
`ledgerKey = HKDF-SHA256(rootKey, "shieldfive/cli/ledger/v1")`. A plain SHA-256
of every uploaded file, on disk, would let anyone who reads the ledger confirm
whether you hold a specific known document. Keyed under the root key, the
entries are unlinkable without it, and only the unlocked agent can compute the
MAC of a local file to compare.

The ledger is never used to decide anything by filename or size. A local file
counts as backed up only when all of these hold:

1. its current MAC matches a ledger entry for this account, and
2. `POST /api/mobile/media/verify` reports that entry's `fileId` as `verified`
   at the moment of asking. That route fails closed: an unknown id, a row in the
   Bin, a missing storage object or a size mismatch all come back `missing`.

The existing manifest is not imported. It has no hash to check, so importing it
would be exactly the inference this design exists to avoid. The ledger starts
empty.

## Protocol

Newline-delimited JSON over the socket. One request, one response.

| op | request | response |
|---|---|---|
| `status` | — | `{unlocked, account, idleLocksInSec}` |
| `upload` | `{path}` | `{fileId, recorded, size}`, or `recorded: false` with `reason: changed_during_upload` |
| `sync` | `{folder}` | `{uploaded, skipped, failed, errors}` |
| `verify` | `{paths}` (≤ 500) | per path: `verified` · `missing` · `changed_since_upload` · `not_in_ledger` |
| `lock` | — | `{locked: true}` |
| `logout` | — | `{loggedOut: true}` |

Paths must be absolute. The agent opens files with the user's own permissions,
so it can read nothing the caller could not.

No response carries a MAC. The ledger needs them; a process on the socket
does not, and a keyed digest handed out on request is one more thing to
reason about.

`upload` hashes the file before and after `uploadFile` reads it. If the two
differ, what reached the vault is bytes nobody can name, so nothing is
recorded and the next sync pass uploads it again.

## Where things live

| Platform | Socket directory |
|---|---|
| Linux | `$XDG_RUNTIME_DIR/shieldfive` (tmpfs, removed at logout) |
| macOS | `$TMPDIR/shieldfive-agent` (`$TMPDIR` is already per-user) |
| fallback | `~/.shieldfive/run` |

The agent refuses to start if the directory is not owned by the current user or
is accessible to anyone else (mode wider than `0700`), and removes a stale socket
only after confirming nothing answers on it.

## Threat model

| Adversary | Outcome |
|---|---|
| The ShieldFive server | Unchanged. It sees ciphertext and, as before, a bearer token. The ledger MACs never leave the machine. |
| Someone with the disk but not a running session (stolen laptop powered off, a backup, a disk image) | Gets the ledger: paths, sizes, times and unlinkable MACs. No key, no token, no password. |
| Another local user | Cannot enter the socket directory. |
| Malware running as the user while the agent is unlocked | Can upload files into the vault and ask whether files are backed up. Cannot read, list, download or decrypt vault contents through the agent, and cannot extract the key through it. It can already read and delete the user's local files directly, so this grants nothing it lacked except a way to write into the vault. |
| Malware running as the user that reads process memory | Out of scope. It can read the key from the agent, as it could from any process that ever unlocks the vault, including `sf sync` today. |

## Known limits

- **No peer credential check.** Node exposes no `SO_PEERCRED`/`getpeereid`, so
  the agent cannot see which process connected. Directory permissions are the
  only gate, which is also the model `ssh-agent` relies on on macOS.
- **Key erasure is best-effort.** Buffers are overwritten on lock and logout, but
  V8 may have copied key material during crypto calls, and a garbage-collected
  runtime gives no guarantee that every copy is gone.
- **Windows is not supported.** Named pipes have a different permission model and
  it has not been designed.
- **The ledger is per device.** A file uploaded from another machine is
  `not_in_ledger` here, even when it is safely in the vault.
- **`not_in_ledger` is not `missing`.** A tool presenting these results must not
  treat "we never saw this upload" as "this file is not backed up".

## Consequences for `@shieldfive/mcp`

`@shieldfive/mcp@0.1.0` ships as built: local tools only, no socket, no
subprocess. A later version can add `upload_to_vault` and
`compare_local_to_vault` by talking to a running agent over its socket. That
changes one boundary the 0.1.0 README asserts: it will import `node:net`, for a
single Unix domain connection to a filesystem path, never a host or port. The MCP
still holds no credential and imports no crypto; it asks the agent, and the agent
never answers with a key.
