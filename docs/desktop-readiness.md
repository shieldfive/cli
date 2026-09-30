# Desktop and migration acceptance

Status: not ready for customer distribution. Windows is the first desktop
priority; macOS also in scope. Website traffic is supporting evidence, not a
paid-customer conversion measure.

## 30 September 2026: auth compatibility

The CLI originally posted the raw password directly to Supabase and could not
sign in to an auth-v2 account. It now fetches the auth salt, derives the same
domain-separated login secret as web/mobile, uses the version-aware ShieldFive
login endpoint, and installs that session before the existing MFA step-up.
Lookup failures stop sign-in before posting credentials.

Native async Argon2id preserves version 0x13, parallelism 1, moderate 256 MiB /
3 passes and sensitive 1 GiB / 4 passes. Long salts use the existing HKDF
compression. No derivation parameters are weakened. Native login derivation
matches both pinned 16- and 32-byte-salt web/mobile vectors; event-loop progress
continues during the KDF. Existing independent library-wrap/native-unwrap tests
exercise the vault key path. Sensitive-preset interoperability is still pending.

Evidence: 112/112 offline tests pass (64.01 seconds), plus the updated five
auth-v2 tests pass (48.85 seconds). A pre-existing logout test had attached its
rejection handler late and relied on an 80 ms sleep; it now attaches immediately
and waits for the actual upload to start before logout.

Live disposable Cyan QA account: auth-v2 sign-in and existing vault unlock pass.
Before native KDF: sign-in 23,714 ms, unlock 21,989 ms. After native KDF: sign-in
11,707 ms, unlock 8,424 ms. Concurrent Android/iOS builds were running, so these
are loaded-machine observations, not release performance baselines. Both QA
sessions were revoked locally, HTTP 204; no other sessions were signed out.
No files uploaded or changed in these live checks.

## Remaining gates

- Windows agent IPC with tested Windows ACLs; Unix filesystem permissions are
  not a Windows access-control design. Existing agent refuses Windows.
- Desktop interface, installers, Windows signing and macOS signing/notarization.
- Real Windows acceptance and packaged macOS acceptance.
- Native KDF packaged ABI and quieter sign-in timings on both OSes.
- Live MFA, token refresh and sign-out; no credential/key persistence leaks.
- Live direct and multipart uploads, retry, interrupted resume and bounded RAM.
- Current post-quantum upload format and independent decrypted-byte verification.
- Recursive folders, empty folders, hidden files, Unicode names, inaccessible
  sources and symlinks; existing sync only scans top-level files.
- Safe source retention. Destination byte verification must precede any cleanup;
  copying alone must never remove the source.
- Migration checkpoint ownership and idempotent restart without duplicate files.
- Seafile export/provider import, with approximately 70 GB as Kevin's use case.
  No direct migration exists today; do not announce it as available.

Customer emails require José's approval of the complete draft before sending.
