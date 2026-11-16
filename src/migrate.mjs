// ShieldFive CLI — `sf push`: copy a whole folder tree into the vault, the way a
// migration from Dropbox or Google Drive needs it.
//
//   - The tree is recreated in the vault under one new top-level folder named
//     after the source folder. Folder names and keys are made exactly as the
//     web app's "Upload folder" makes them (a fresh folder key wrapped by the
//     parent's key, a v6 name sealed to the folder's row id).
//   - Rerunnable. A state file (outside the source folder, so a read-only
//     export works) records the vault folder made for each directory and each
//     file once its upload is final. A rerun skips those and uploads the rest.
//     Before a file starts, its row id is recorded as pending, so a run killed
//     during finalize is settled on the next run by asking the server whether
//     that row is ready, rather than uploading the file twice.
//   - Transient failures (network, 5xx, 408, 429) are retried with backoff. A
//     full vault or a refused session stops the run; other per-file failures
//     are reported and the run goes on.
//
// No key is ever written to disk: folder keys are unwrapped from the server's
// folder tree with the vault root key on every run.

import { createHash } from 'node:crypto'
import { lstat, mkdir, open, readFile, readdir, rename } from 'node:fs/promises'
import { homedir } from 'node:os'
import { basename, join, relative, resolve, sep } from 'node:path'

import { encryptNameV6 } from '@shieldfive/crypto/vault'

import {
  EmptyFileUnsupportedError,
  httpError,
  newRowBoundId,
  resolveToken,
  uploadFile,
} from './upload.mjs'
import {
  base64ToBytes,
  bytesToBase64,
  generateRandomKeyB64,
  hashMetadataV4,
  unwrapKeyB64,
  wrapKeyB64,
} from './uploadCrypto.mjs'

const STATE_VERSION = 1
const DEFAULT_CONCURRENCY = 3
const MAX_CONCURRENCY = 8
const MAX_FILE_ATTEMPTS = 8
const RETRY_BASE_MS = 2000
const RETRY_MAX_MS = 60_000
const VERIFY_BATCH = 100

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export function resolvePushConcurrency(env = process.env) {
  const raw = Number.parseInt(env.SF_PUSH_CONCURRENCY ?? '', 10)
  if (Number.isInteger(raw) && raw >= 1) return Math.min(raw, MAX_CONCURRENCY)
  return DEFAULT_CONCURRENCY
}

export function defaultStatePath(source, home = homedir()) {
  const id = createHash('sha256').update(resolve(source)).digest('hex').slice(0, 32)
  return join(home, '.shieldfive', 'push', `${id}.json`)
}

// Names go to the vault in NFC, the form browsers and the other apps use, so a
// name read from a macOS disk in decomposed form looks the same in the vault.
const vaultName = (name) => name.normalize('NFC')

// Walk the source. lstat, never stat: a symlink is listed as skipped, never
// followed (it could point outside the folder). Dotfiles (.DS_Store, .git,
// .env, ...) are skipped unless includeDotfiles. Directories are returned
// parents first; relative paths use '/'.
export async function scanTree(source, { includeDotfiles = false } = {}) {
  const dirs = []
  const files = []
  const skipped = { symlinks: [], dotfiles: [], other: [] }
  async function walk(dir, rel) {
    const names = (await readdir(dir)).sort()
    for (const name of names) {
      const path = join(dir, name)
      const relPath = rel ? `${rel}/${name}` : name
      if (name.startsWith('.') && !includeDotfiles) {
        skipped.dotfiles.push(relPath)
        continue
      }
      const info = await lstat(path)
      if (info.isSymbolicLink()) skipped.symlinks.push(relPath)
      else if (info.isDirectory()) {
        dirs.push(relPath)
        await walk(path, relPath)
      } else if (info.isFile()) {
        files.push({ rel: relPath, dir: rel, name, path, size: info.size, mtimeMs: info.mtimeMs })
      } else skipped.other.push(relPath)
    }
  }
  await walk(source, '')
  dirs.sort((a, b) => a.split('/').length - b.split('/').length || (a < b ? -1 : 1))
  return { dirs, files, skipped }
}

const signatureOf = ({ size, mtimeMs }) => `${size}:${mtimeMs}`

export async function loadState(statePath, { account, source }) {
  const fresh = { version: STATE_VERSION, account, source, rootFolderId: null, folders: {}, files: {}, pending: {} }
  let raw
  try {
    raw = await readFile(statePath, 'utf8')
  } catch (err) {
    if (err.code === 'ENOENT') return fresh
    throw err
  }
  const parsed = JSON.parse(raw)
  // Another account's ids mean nothing here: start over for this one.
  if (!parsed || parsed.version !== STATE_VERSION || parsed.account !== account) return fresh
  return {
    ...fresh,
    rootFolderId: parsed.rootFolderId ?? null,
    folders: parsed.folders ?? {},
    files: parsed.files ?? {},
    pending: parsed.pending ?? {},
  }
}

// Write to a temp sibling, fsync, rename: a crash never leaves half a file.
// 0600: it lists file names and vault ids.
export async function saveState(statePath, state) {
  await mkdir(join(statePath, '..'), { recursive: true, mode: 0o700 })
  const tmp = `${statePath}.tmp`
  const handle = await open(tmp, 'w', 0o600)
  try {
    await handle.chmod(0o600)
    await handle.writeFile(JSON.stringify(state))
    await handle.sync()
  } finally {
    await handle.close()
  }
  await rename(tmp, statePath)
}

async function apiJson(apiBaseUrl, accessToken, path, { method = 'GET', body } = {}) {
  const res = await fetch(new URL(path, apiBaseUrl), {
    method,
    headers: {
      Authorization: `Bearer ${await resolveToken(accessToken)}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  const json = await res.json().catch(() => ({}))
  if (!res.ok) {
    const err = httpError(`${method} ${path} failed (HTTP ${res.status}): ${JSON.stringify(json)}`, res.status, json)
    err.retryAfterMs = Number(res.headers.get('retry-after')) * 1000 || null
    throw err
  }
  return json
}

export function isTransient(err) {
  if (err?.status === undefined) {
    // Network / transport failures only (fetch throws TypeError 'fetch failed').
    return (
      err?.name === 'TypeError' ||
      err?.finalizeOutcomeUnknown === true ||
      /fetch failed|ECONNRESET|ETIMEDOUT|EPIPE|ENOTFOUND|EAI_AGAIN|socket|network/i.test(err?.message ?? '')
    )
  }
  return err.status >= 500 || err.status === 408 || err.status === 429
}

// A refusal that every remaining file would meet too: stop the run.
export function isRunFatal(err) {
  return (
    err?.status === 401 ||
    err?.status === 402 ||
    err?.status === 412 ||
    (err?.status === 413 && err?.serverCode !== 'too_many_parts') ||
    (err?.status === 403 && /mfa|step/i.test(err?.message ?? ''))
  )
}

async function withRetry(fn, { onRetry = () => {}, attempts = MAX_FILE_ATTEMPTS } = {}) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await fn(attempt)
    } catch (err) {
      if (attempt >= attempts || !isTransient(err) || isRunFatal(err)) throw err
      const delay = Math.min(err.retryAfterMs ?? RETRY_BASE_MS * 2 ** (attempt - 1), RETRY_MAX_MS)
      onRetry(err, attempt, delay)
      await sleep(delay)
    }
  }
}

function flattenTree(nodes, out = new Map()) {
  for (const n of nodes ?? []) {
    out.set(n.id, n)
    flattenTree(n.children, out)
  }
  return out
}

// The folder's key, unwrapped down the chain from the root key; null when the
// folder is gone or sits in the Bin (a binned folder is not a place to resume
// into: the user threw it away).
function folderKeyFor(id, byId, rootKeyB64, cache) {
  if (cache.has(id)) return cache.get(id)
  const node = byId.get(id)
  let key = null
  if (node && !node.is_bin && node.fk_wrapped && node.fk_iv) {
    const parentKey = node.parent_id ? folderKeyFor(node.parent_id, byId, rootKeyB64, cache) : rootKeyB64
    if (parentKey) {
      try {
        key = unwrapKeyB64({ wrappingKeyB64: parentKey, wrappedKeyB64: node.fk_wrapped, ivB64: node.fk_iv })
      } catch {
        key = null
      }
    }
  }
  cache.set(id, key)
  return key
}

// Build the create request once; retries resend the same id and body, and the
// server answers a repeated create whose first answer was lost with the folder
// it already made, so a retry never makes a second folder.
async function prepareFolder({ rootKeyB64, name, parentId, parentKeyB64 }) {
  const id = newRowBoundId()
  const envelope = await encryptNameV6({ name, folderKey: base64ToBytes(parentKeyB64), rowId: id })
  const folderKey = generateRandomKeyB64()
  const wrapped = wrapKeyB64({ wrappingKeyB64: parentKeyB64, keyToWrapB64: folderKey })
  const body = {
    id,
    name_encrypted: JSON.stringify(envelope),
    nameHash: hashMetadataV4(name.toLowerCase(), rootKeyB64),
    parentFolderId: parentId,
    fk_wrapped: wrapped.wrapped,
    fk_iv: wrapped.iv,
  }
  return { id, key: folderKey, body }
}

async function sendFolder({ apiBaseUrl, accessToken, prepared }) {
  const res = await apiJson(apiBaseUrl, accessToken, '/api/folders/create', { method: 'POST', body: prepared.body })
  if (res?.folder?.id !== prepared.id) throw new Error(`folders/create returned ${res?.folder?.id} for ${prepared.id}`)
  return { id: prepared.id, key: prepared.key }
}

async function verifyReady({ apiBaseUrl, accessToken, ids }) {
  const ready = new Set()
  for (let i = 0; i < ids.length; i += VERIFY_BATCH) {
    const batch = ids.slice(i, i + VERIFY_BATCH)
    const res = await withRetry(() =>
      apiJson(apiBaseUrl, accessToken, '/api/mobile/media/verify', { method: 'POST', body: { fileIds: batch } }),
    )
    for (const id of res.verified ?? []) ready.add(id)
  }
  return ready
}

const fmtBytes = (n) => {
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1000 && i < u.length - 1) {
    n /= 1000
    i += 1
  }
  return `${i ? n.toFixed(1) : n} ${u[i]}`
}

/**
 * Push `source` into the vault. Returns a summary; never throws for a single
 * file's failure (those are in summary.failed), only for run-level problems.
 */
export async function runPush({
  source,
  apiBaseUrl,
  accessToken,
  rootKey,
  account,
  statePath = defaultStatePath(source),
  includeDotfiles = false,
  concurrency = resolvePushConcurrency(),
  uploadFn = uploadFile,
  log = (m) => process.stdout.write(`${m}\n`),
  status = (m) => process.stderr.write(`${m}\n`),
  signal,
  progressEveryMs = 10_000,
}) {
  source = resolve(source)
  const rootKeyB64 = bytesToBase64(rootKey)
  const scan = await scanTree(source, { includeDotfiles })
  const totalBytes = scan.files.reduce((s, f) => s + f.size, 0)
  status(
    `found ${scan.files.length} files (${fmtBytes(totalBytes)}) in ${scan.dirs.length} folders` +
      (scan.skipped.dotfiles.length ? `; skipping ${scan.skipped.dotfiles.length} hidden (use --include-dotfiles to send them)` : '') +
      (scan.skipped.symlinks.length ? `; skipping ${scan.skipped.symlinks.length} symlinks` : '') +
      (scan.skipped.other.length ? `; skipping ${scan.skipped.other.length} special files` : ''),
  )
  for (const p of scan.skipped.symlinks) log(`skipped ${p}: symbolic link (not followed)`)
  for (const p of scan.skipped.other) log(`skipped ${p}: not a regular file`)

  const state = await loadState(statePath, { account, source })
  const save = (() => {
    let chain = Promise.resolve()
    return () => (chain = chain.then(() => saveState(statePath, state)))
  })()

  // Folders: resume into the ones recorded, create the rest.
  const tree = await withRetry(() => apiJson(apiBaseUrl, accessToken, '/api/folders/tree'))
  const byId = flattenTree(tree.tree)
  const keyCache = new Map()
  const folderIds = new Map() // rel dir ('' = top) -> { id, key }

  const ensure = async (rel, name, parent) => {
    const recorded = rel === '' ? state.rootFolderId : state.folders[rel]
    const node = recorded ? byId.get(recorded) : null
    if (node && (node.parent_id ?? null) === (parent?.id ?? null)) {
      const key = folderKeyFor(recorded, byId, rootKeyB64, keyCache)
      if (key) {
        folderIds.set(rel, { id: recorded, key })
        return false
      }
    }
    const prepared = await prepareFolder({
      rootKeyB64,
      name: vaultName(name),
      parentId: parent?.id ?? null,
      parentKeyB64: parent?.key ?? rootKeyB64,
    })
    const made = await withRetry(
      () => sendFolder({ apiBaseUrl, accessToken, prepared }),
      { onRetry: (e, n, d) => status(`creating folder ${rel || name}: ${e.message}; retrying in ${Math.round(d / 1000)} s`) },
    )
    folderIds.set(rel, made)
    if (rel === '') {
      state.rootFolderId = made.id
      // A new top folder means nothing recorded under the old one is there.
      state.folders = {}
      state.files = {}
      state.pending = {}
    } else {
      state.folders[rel] = made.id
      // The folder was (re)made, so files recorded in the old one are not in
      // this one: forget them so they upload again.
      for (const key of Object.keys(state.files)) {
        const cut = key.lastIndexOf('/')
        if ((cut === -1 ? '' : key.slice(0, cut)) === rel) delete state.files[key]
      }
    }
    await save()
    return true
  }

  const topCreated = await ensure('', basename(source), null)
  status(`${topCreated ? 'created' : 'resuming into'} vault folder "${vaultName(basename(source))}"`)
  let foldersCreated = 0
  for (const rel of scan.dirs) {
    const cut = rel.lastIndexOf('/')
    const parent = folderIds.get(cut === -1 ? '' : rel.slice(0, cut))
    if (await ensure(rel, cut === -1 ? rel : rel.slice(cut + 1), parent)) foldersCreated += 1
  }

  // Settle uploads a previous run started but may not have seen finish.
  const pendingEntries = Object.entries(state.pending)
  if (pendingEntries.length) {
    const ready = await verifyReady({ apiBaseUrl, accessToken, ids: pendingEntries.map(([, p]) => p.fileId) })
    for (const [rel, p] of pendingEntries) {
      if (ready.has(p.fileId)) state.files[rel] = { signature: p.signature, fileId: p.fileId }
      delete state.pending[rel]
    }
    await save()
  }

  const summary = { uploaded: 0, alreadyThere: 0, failed: [], changed: [], skippedEmpty: [], bytesUploaded: 0, foldersCreated, stoppedBy: null, interrupted: false }
  const todo = []
  for (const f of scan.files) {
    const done = state.files[f.rel]
    if (done && done.signature === signatureOf(f)) summary.alreadyThere += 1
    else todo.push(f)
  }
  if (summary.alreadyThere) status(`${summary.alreadyThere} files already uploaded by an earlier run; skipping them`)
  const todoBytes = todo.reduce((s, f) => s + f.size, 0)
  status(`uploading ${todo.length} files (${fmtBytes(todoBytes)}), ${concurrency} at a time`)

  let inFlightBytes = 0
  let completed = 0
  const started = Date.now()
  const timer = progressEveryMs
    ? setInterval(() => {
        const secs = (Date.now() - started) / 1000
        const sent = summary.bytesUploaded + inFlightBytes
        status(
          `progress: ${completed}/${todo.length} files, ${fmtBytes(summary.bytesUploaded)} of ${fmtBytes(todoBytes)}` +
            (secs > 0 ? `, ${fmtBytes(sent / secs)}/s` : ''),
        )
      }, progressEveryMs)
    : null
  timer?.unref?.()

  let next = 0
  const stopping = () => summary.stoppedBy || signal?.aborted

  const uploadOne = async (f) => {
    const before = await lstat(f.path).catch(() => null)
    if (!before?.isFile()) {
      summary.failed.push({ rel: f.rel, message: 'file disappeared or is no longer a regular file' })
      log(`failed ${f.rel}: file disappeared or is no longer a regular file`)
      return
    }
    const entry = { ...f, size: before.size, mtimeMs: before.mtimeMs }
    const folder = folderIds.get(f.dir)
    let progressed = 0
    try {
      await withRetry(
        async () => {
          const fileId = newRowBoundId()
          state.pending[f.rel] = { fileId, signature: signatureOf(entry) }
          await save()
          progressed = 0
          try {
            await uploadFn({
              apiBaseUrl,
              accessToken,
              rootKey,
              name: vaultName(f.name),
              path: f.path,
              size: entry.size,
              rowId: fileId,
              folderId: folder.id,
              folderKey: base64ToBytes(folder.key),
              onPlaintextChunk: (c) => {
                progressed += c.length
                inFlightBytes += c.length
              },
            })
          } catch (err) {
            inFlightBytes -= progressed
            progressed = 0
            // Finalize may have landed even though its answer was lost.
            const landed =
              err?.finalizeOutcomeUnknown &&
              (await verifyReady({ apiBaseUrl, accessToken, ids: [fileId] }).catch(() => new Set())).has(fileId)
            if (!landed) {
              // Keep the pending record when we cannot tell: the next run asks again.
              if (!err?.finalizeOutcomeUnknown) {
                delete state.pending[f.rel]
                await save()
              }
              throw err
            }
          }
          inFlightBytes -= progressed
          state.files[f.rel] = { signature: signatureOf(entry), fileId }
          delete state.pending[f.rel]
          await save()
        },
        {
          onRetry: (e, n, d) =>
            status(`${f.rel}: ${e.message.slice(0, 200)}; retry ${n} in ${Math.round(d / 1000)} s`),
        },
      )
    } catch (err) {
      if (err instanceof EmptyFileUnsupportedError) {
        summary.skippedEmpty.push(f.rel)
        log(`skipped ${f.rel}: empty file, and this server does not accept empty files`)
        return
      }
      if (isRunFatal(err)) {
        summary.stoppedBy ??= err
        return
      }
      summary.failed.push({ rel: f.rel, message: err.message })
      log(`failed ${f.rel}: ${err.message}`)
      return
    }
    summary.uploaded += 1
    summary.bytesUploaded += entry.size
    completed += 1
    const after = await lstat(f.path).catch(() => null)
    if (!after || signatureOf(after) !== signatureOf(entry)) {
      // What was read is in the vault; the file on disk is different now. Do
      // not record it as done, so the next run uploads the new version.
      delete state.files[f.rel]
      await save()
      summary.changed.push(f.rel)
      log(`uploaded ${f.rel}, but it changed while uploading; run again to upload the new version`)
    } else {
      log(`[${completed}/${todo.length}] uploaded ${f.rel} (${fmtBytes(entry.size)})`)
    }
  }

  const worker = async () => {
    while (!stopping() && next < todo.length) {
      const f = todo[next++]
      await uploadOne(f)
    }
  }
  try {
    await Promise.all(Array.from({ length: Math.min(concurrency, todo.length || 1) }, worker))
  } finally {
    if (timer) clearInterval(timer)
  }
  summary.interrupted = Boolean(signal?.aborted)
  summary.notStarted = todo.length - next
  return summary
}

export const _internals = { flattenTree, folderKeyFor, signatureOf, relative, sep }
