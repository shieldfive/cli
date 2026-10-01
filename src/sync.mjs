// ShieldFive CLI — `sf sync`: keep a folder mirrored into your vault.
//
// One reconcile pass uploads every file that is new or changed since the last
// run; `--watch` repeats the pass on an interval until interrupted. The upload
// protocol is unchanged — sync reuses uploadFile (direct + multipart). The new
// logic here is change detection: a local manifest (.shieldfive-sync.json in
// the synced folder) records each file's size + mtime + resulting vault fileId,
// so unchanged files are skipped and a crash mid-sync doesn't re-upload
// everything.
//
// Scope notes: change is detected by (size, mtimeMs) — the rsync default, cheap
// and good enough; a same-size same-mtime edit is not re-uploaded. Deletions
// and renames are NOT mirrored (a file removed locally stays in the vault); sync
// is append-only for now. Each changed file becomes a new vault upload at the
// vault root (the server does not overwrite by name); earlier versions are kept,
// not replaced or trashed, so they count against storage until removed in the
// app. Replacing the previous fileId needs the Bin's folder key to re-wrap it,
// which this client does not hold yet.

import { open, readFile, readdir, rename, stat } from 'node:fs/promises'
import { join } from 'node:path'

export const MANIFEST_NAME = '.shieldfive-sync.json'
const MANIFEST_VERSION = 1

// A file's change signature. Same string => treated as unchanged.
export function signatureOf({ size, mtimeMs }) {
  return `${size}:${mtimeMs}`
}

// List regular files to consider for sync: skips directories, dotfiles (which
// includes the manifest itself), and any explicitly excluded names.
export async function scanFiles(folder, { exclude = [] } = {}) {
  const skip = new Set(exclude)
  const entries = []
  for (const name of await readdir(folder)) {
    if (name.startsWith('.') || skip.has(name)) continue
    const path = join(folder, name)
    const info = await stat(path)
    if (info.isFile()) {
      entries.push({ name, path, size: info.size, mtimeMs: info.mtimeMs })
    }
  }
  return entries
}

export async function loadManifest(manifestPath) {
  let raw
  try {
    raw = await readFile(manifestPath, 'utf8')
  } catch (err) {
    if (err.code === 'ENOENT') return { version: MANIFEST_VERSION, files: {} }
    throw err
  }
  const parsed = JSON.parse(raw)
  return {
    version: MANIFEST_VERSION,
    files: parsed && typeof parsed.files === 'object' ? parsed.files : {},
  }
}

// Atomic-ish write: write a temp sibling then rename over the target, so a crash
// during the write can't leave a half-written manifest.
export async function saveManifest(manifestPath, manifest) {
  const body = JSON.stringify(
    { version: MANIFEST_VERSION, files: manifest.files },
    null,
    2,
  )
  const tmp = `${manifestPath}.tmp`
  const handle = await open(tmp, 'w')
  try {
    await handle.writeFile(body)
    await handle.sync()
  } finally {
    await handle.close()
  }
  await rename(tmp, manifestPath)
}

// Pure: split scanned entries into what must upload vs what's unchanged, by
// comparing each entry's signature to the manifest.
export function planSync(entries, manifest) {
  const toUpload = []
  const unchanged = []
  for (const entry of entries) {
    const prev = manifest.files[entry.name]
    if (prev && prev.signature === signatureOf(entry)) {
      unchanged.push(entry)
    } else {
      toUpload.push(entry)
    }
  }
  return { toUpload, unchanged }
}

// One reconcile pass. uploadFn is injected (defaults to the real uploadFile) so
// the pass is unit-testable without a network. Returns a summary and mutates
// `manifest` in place, persisting after each successful upload.
//
// `accessToken` is a string, or a function returning one; the function is
// called before every upload, so a long pass picks up a refreshed session. If
// it throws (the session cannot be refreshed) the pass stops and the error
// propagates: nothing after it could succeed.
export async function syncOnce({
  apiBaseUrl,
  accessToken,
  rootKey,
  folder,
  manifestPath,
  manifest,
  uploadFn,
  log = () => {},
}) {
  const entries = await scanFiles(folder, { exclude: [MANIFEST_NAME] })
  const { toUpload, unchanged } = planSync(entries, manifest)

  let uploaded = 0
  let failed = 0
  const errors = []

  const tokenFor = typeof accessToken === 'function' ? accessToken : async () => accessToken
  for (const entry of toUpload) {
    const token = await tokenFor()
    try {
      const { fileId } = await uploadFn({
        apiBaseUrl,
        accessToken: token,
        rootKey,
        name: entry.name,
        path: entry.path,
        size: entry.size,
      })
      manifest.files[entry.name] = {
        signature: signatureOf(entry),
        size: entry.size,
        mtimeMs: entry.mtimeMs,
        fileId,
        uploadedAt: new Date().toISOString(),
      }
      await saveManifest(manifestPath, manifest)
      uploaded += 1
      log(`synced ${entry.name}`)
    } catch (err) {
      failed += 1
      errors.push({ name: entry.name, message: err.message })
      log(`failed ${entry.name}: ${err.message}`)
    }
  }

  return { uploaded, skipped: unchanged.length, failed, errors }
}

function sleep(ms, signal) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer)
        resolve()
      },
      { once: true },
    )
  })
}

// Refresh this long before the access token expires (seconds).
const REFRESH_MARGIN_S = 120

/**
 * The access token for the next request: the current one while it has more
 * than REFRESH_MARGIN_S left, otherwise a refreshed one. Supabase rotates
 * refresh tokens and revokes the session if one is presented twice, so the
 * refresh is single-flight and the rotated token replaces the old one.
 * Without an expiry or a refresh function (tests, old callers) the token is
 * used as is.
 */
export function createSessionTokens({ accessToken, refreshToken, expiresAt, refresh, now = () => Date.now() }) {
  let tokens = { access: accessToken, refresh: refreshToken, expiresAt }
  let inflight = null
  return async function current() {
    if (!refresh || !tokens.expiresAt || now() / 1000 < tokens.expiresAt - REFRESH_MARGIN_S) {
      return tokens.access
    }
    inflight ??= refresh(tokens.refresh)
      .then((s) => {
        tokens = { access: s.accessToken, refresh: s.refreshToken, expiresAt: s.expiresAt }
        return tokens.access
      })
      .finally(() => {
        inflight = null
      })
    return inflight
  }
}

// Orchestrates a real sync: sign in + unlock once, then run one pass (or loop on
// an interval under --watch). authAndUnlock is injected so the CLI can share its
// sign-in/unlock path and tests can stub it. It may also return refreshToken,
// expiresAt (unix seconds) and refreshSession(refreshToken); with them the
// session is refreshed before it expires, so `--watch` keeps working past the
// access token's lifetime (about an hour). A refresh that fails ends the sync
// with an error (non-zero exit) instead of failing every file on every pass
// while looking healthy to a supervisor.
//
// Returns the last pass's summary. A single pass with failed files rejects, so
// `sf sync` exits non-zero; under --watch failed files are retried next pass.
export async function runSync({
  cfg,
  folder,
  watch = false,
  intervalMs = 5000,
  authAndUnlock,
  uploadFn,
  log = (m) => process.stdout.write(`${m}\n`),
  status = (m) => process.stderr.write(`${m}\n`),
  now = () => Date.now(),
}) {
  const session = await authAndUnlock(cfg)
  const { rootKey } = session
  const accessToken = createSessionTokens({
    accessToken: session.accessToken,
    refreshToken: session.refreshToken,
    expiresAt: session.expiresAt,
    refresh: session.refreshSession,
    now,
  })
  const manifestPath = join(folder, MANIFEST_NAME)
  const manifest = await loadManifest(manifestPath)

  const controller = new AbortController()
  const onSigint = () => {
    status('\nstopping…')
    controller.abort()
  }
  if (watch) process.on('SIGINT', onSigint)

  let summary
  try {
    do {
      summary = await syncOnce({
        apiBaseUrl: cfg.apiBaseUrl,
        accessToken,
        rootKey,
        folder,
        manifestPath,
        manifest,
        uploadFn,
        log,
      })
      status(
        `pass: ${summary.uploaded} synced, ${summary.skipped} unchanged` +
          (summary.failed ? `, ${summary.failed} failed` : ''),
      )
      if (!watch || controller.signal.aborted) break
      await sleep(intervalMs, controller.signal)
    } while (!controller.signal.aborted)
  } finally {
    if (watch) process.off('SIGINT', onSigint)
  }
  if (!watch && summary?.failed) {
    throw new Error(`${summary.failed} file(s) failed to sync.`)
  }
  return summary
}
