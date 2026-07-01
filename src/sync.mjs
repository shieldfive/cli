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
// is append-only for now. Each changed file becomes a new vault upload (the
// server does not overwrite by name), which is the intended versioning
// behaviour.

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

  for (const entry of toUpload) {
    try {
      const { fileId } = await uploadFn({
        apiBaseUrl,
        accessToken,
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

// Orchestrates a real sync: sign in + unlock once, then run one pass (or loop on
// an interval under --watch). authAndUnlock is injected so the CLI can share its
// sign-in/unlock path and tests can stub it.
export async function runSync({
  cfg,
  folder,
  watch = false,
  intervalMs = 5000,
  authAndUnlock,
  uploadFn,
  log = (m) => process.stdout.write(`${m}\n`),
  status = (m) => process.stderr.write(`${m}\n`),
}) {
  const { accessToken, rootKey } = await authAndUnlock(cfg)
  const manifestPath = join(folder, MANIFEST_NAME)
  const manifest = await loadManifest(manifestPath)

  const controller = new AbortController()
  const onSigint = () => {
    status('\nstopping…')
    controller.abort()
  }
  if (watch) process.on('SIGINT', onSigint)

  try {
    do {
      const summary = await syncOnce({
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
}
