// ShieldFive CLI — `sf thumbnails <folder>`: add encrypted previews to photos
// and videos that are already in the vault, from the originals still on this
// machine. Nothing is uploaded again and nothing is downloaded: the vault copy
// of <folder> is walked folder by folder, each photo or video without a
// preview is matched to the local file at the same path with the same size,
// a preview is made from the local file, encrypted under that vault file's own
// content key (unwrapped here from its folder key), and only that ciphertext is
// sent.
//
// Which vault folder is <folder>'s copy: --media (the Media folder), the folder
// an earlier `sf push` of <folder> recorded, or else the one top-level folder
// named like <folder>. --vault-folder=<a/b> names it explicitly.
//
// Resumable and polite: files that got a preview are recorded in a state file
// (~/.shieldfive/thumbnails/, ids only), and the server skips files that
// already have one. Previews are sent in batches when the server accepts them
// (one at a time otherwise), and 429s are waited out.

import { createHash } from 'node:crypto'
import { lstat, mkdir, open, readdir, readFile, rename } from 'node:fs/promises'
import { homedir } from 'node:os'
import { basename, join, resolve } from 'node:path'

import { decryptName, parseNameEnvelope } from '@shieldfive/crypto/vault'

import { _internals, defaultStatePath } from './migrate.mjs'
import { makeThumbnail, mediaKindOf, thumbnailFields, thumbnailSupport } from './thumbnail.mjs'
import { base64ToBytes, bytesToBase64, decryptMetadataV4, unwrapKeyB64 } from './uploadCrypto.mjs'

const { apiJson, flattenTree, folderKeyFor, withRetry } = _internals
const LIST_PAGE = 100
const BATCH = 20
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export function defaultBackfillStatePath(source, home = homedir()) {
  const id = createHash('sha256').update(resolve(source)).digest('hex').slice(0, 32)
  return join(home, '.shieldfive', 'thumbnails', `${id}.json`)
}

async function loadDone(path, account) {
  try {
    const s = JSON.parse(await readFile(path, 'utf8'))
    if (s.account === account) return new Set(s.done ?? [])
  } catch {}
  return new Set()
}

async function saveDone(path, account, done) {
  await mkdir(join(path, '..'), { recursive: true, mode: 0o700 })
  const tmp = `${path}.tmp`
  const h = await open(tmp, 'w', 0o600)
  try {
    await h.writeFile(JSON.stringify({ account, done: [...done] }))
  } finally {
    await h.close()
  }
  await rename(tmp, path)
}

// A stored name: v6 envelope (CLI, current apps) bound to the row, else the
// older v4 JSON payload under the root key. null if neither opens.
export async function decryptStoredName(stored, parentKeyB64, rootKeyB64, rowId) {
  if (typeof stored !== 'string') return null
  try {
    return await decryptName({ envelope: parseNameEnvelope(stored), folderKey: base64ToBytes(parentKeyB64), rowId })
  } catch {}
  try {
    const payload = JSON.parse(stored)
    if (payload?.v === 4) return decryptMetadataV4(payload, rootKeyB64)
  } catch {}
  return null
}

// Local directory entries by NFC name (push stored names in NFC; a macOS disk
// may hold them decomposed).
async function localEntries(dir) {
  const map = new Map()
  let names
  try {
    names = await readdir(dir)
  } catch {
    return map
  }
  for (const n of names) map.set(n.normalize('NFC'), n)
  return map
}

async function* listFolderFiles({ apiBaseUrl, accessToken, folderId }) {
  let cursor = null
  for (;;) {
    const q = new URLSearchParams({ limit: String(LIST_PAGE) })
    if (folderId) q.set('folderId', folderId)
    if (cursor) q.set('cursor', cursor)
    const res = await withRetry(() => apiJson(apiBaseUrl, accessToken, `/api/files?${q}`))
    for (const f of res.files ?? []) yield f
    cursor = res.pagination?.hasMore ? res.pagination.nextCursor : null
    if (!cursor) return
  }
}

export async function findVaultRoot({ source, media, vaultFolder, byId, rootKeyB64, keyCache, account }) {
  const roots = [...byId.values()].filter((n) => !n.parent_id && !n.is_bin)
  if (media) {
    const m = roots.find((n) => n.is_media)
    if (!m) throw new Error('this account has no Media folder yet')
    return m
  }
  const nameOf = async (n) =>
    decryptStoredName(n.name, n.parent_id ? folderKeyFor(n.parent_id, byId, rootKeyB64, keyCache) : rootKeyB64, rootKeyB64, n.id)
  if (vaultFolder) {
    let level = roots
    let node = null
    for (const part of vaultFolder.split('/').filter(Boolean)) {
      node = null
      for (const n of level) if ((await nameOf(n)) === part.normalize('NFC')) node = n
      if (!node) throw new Error(`no vault folder "${vaultFolder}"`)
      level = [...byId.values()].filter((c) => c.parent_id === node.id && !c.is_bin)
    }
    if (!node) throw new Error('--vault-folder is empty')
    return node
  }
  // The folder an earlier `sf push` of this source made.
  try {
    const st = JSON.parse(await readFile(defaultStatePath(source), 'utf8'))
    const n = st.account === account ? byId.get(st.rootFolderId) : null
    if (n && !n.is_bin) return n
  } catch {}
  const want = basename(source).normalize('NFC')
  const hits = []
  for (const n of roots) if (!n.is_media && (await nameOf(n)) === want) hits.push(n)
  if (hits.length === 1) return hits[0]
  if (hits.length === 0) throw new Error(`no top-level vault folder named "${want}"; pass --vault-folder=<path> or --media`)
  throw new Error(`${hits.length} top-level vault folders are named "${want}"; pass --vault-folder=<path>`)
}

/**
 * Walk the vault copy of `source` and match photos/videos without a preview to
 * local originals (same relative path, same size). Returns the matches and
 * counts; uploads nothing.
 */
export async function planBackfill({ source, apiBaseUrl, accessToken, rootKey, account, media = false, vaultFolder = null, status = () => {} }) {
  source = resolve(source)
  const rootKeyB64 = bytesToBase64(rootKey)
  const tree = await withRetry(() => apiJson(apiBaseUrl, accessToken, '/api/folders/tree'))
  const byId = flattenTree(tree.tree)
  const keyCache = new Map()
  const root = await findVaultRoot({ source, media, vaultFolder, byId, rootKeyB64, keyCache, account })
  const counts = { vaultFiles: 0, media: 0, haveThumbnail: 0, matched: 0, noLocal: 0, sizeDiffers: 0, unreadableName: 0 }
  const matches = []
  const queue = [{ node: root, dir: source }]
  while (queue.length) {
    const { node, dir } = queue.shift()
    const key = folderKeyFor(node.id, byId, rootKeyB64, keyCache)
    if (!key) continue
    const local = await localEntries(dir)
    for await (const f of listFolderFiles({ apiBaseUrl, accessToken, folderId: node.id })) {
      counts.vaultFiles += 1
      const name = await decryptStoredName(f.name, key, rootKeyB64, f.id)
      if (name === null) {
        counts.unreadableName += 1
        continue
      }
      if (!mediaKindOf(name)) continue
      counts.media += 1
      if (f.has_thumbnail) {
        counts.haveThumbnail += 1
        continue
      }
      const localName = local.get(name.normalize('NFC'))
      const st = localName ? await lstat(join(dir, localName)).catch(() => null) : null
      if (!st?.isFile()) {
        counts.noLocal += 1
        continue
      }
      // size_declared is the plaintext size; size_bytes is the stored
      // ciphertext (header and tags included), so it never equals the original.
      if (f.size_declared == null || st.size !== Number(f.size_declared)) {
        counts.sizeDiffers += 1
        continue
      }
      counts.matched += 1
      matches.push({ fileId: f.id, name, path: join(dir, localName), size: st.size, parentKeyB64: key, cskWrapped: f.csk_wrapped, cskIv: f.csk_iv })
    }
    for (const child of byId.values()) {
      if (child.parent_id !== node.id || child.is_bin) continue
      const childName = await decryptStoredName(child.name, key, rootKeyB64, child.id)
      const localChild = childName ? local.get(childName.normalize('NFC')) : null
      if (localChild) queue.push({ node: child, dir: join(dir, localChild) })
    }
    status(`scanned: ${counts.vaultFiles} vault files, ${counts.matched} photos/videos to add a preview to`)
  }
  return { root, counts, matches }
}

// Send previews: batched ({items}) when the server supports it, else one by
// one. Returns per-file outcome: 'ok' | 'exists' | 'failed'.
async function sendPreviews({ apiBaseUrl, accessToken, items, state, onWait }) {
  const post = async (body) => {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await apiJson(apiBaseUrl, accessToken, '/api/files/thumbnail', { method: 'POST', body })
      } catch (err) {
        if (err?.status === 409) return { exists: true }
        const transient = err?.status === 429 || err?.status === undefined || err?.status >= 500
        if (!transient || attempt >= 8) throw err
        const wait = err?.status === 429 ? Math.max(err.retryAfterMs ?? 0, 20_000) : 2000 * attempt
        onWait?.(err, wait)
        await sleep(wait)
      }
    }
  }
  const outcome = new Map()
  if (state.batch !== false && items.length > 1) {
    try {
      const res = await post({ items })
      if (Array.isArray(res?.results)) {
        for (const r of res.results) outcome.set(r.fileId, r.ok ? 'ok' : r.status === 409 ? 'exists' : 'failed')
        return outcome
      }
    } catch (err) {
      if (err?.status !== 400) throw err
    }
    state.batch = false // an older server: one at a time from here on
  }
  for (const it of items) {
    try {
      const res = await post(it)
      outcome.set(it.fileId, res?.exists ? 'exists' : 'ok')
    } catch (err) {
      if (err?.status === 404 || err?.status === 400) outcome.set(it.fileId, 'failed')
      else throw err
    }
  }
  return outcome
}

export async function runBackfill({
  source,
  apiBaseUrl,
  accessToken,
  rootKey,
  account,
  media = false,
  vaultFolder = null,
  dryRun = false,
  statePath = defaultBackfillStatePath(source),
  concurrency = 4,
  makeThumbnailFn = makeThumbnail,
  thumbnailSupportFn = thumbnailSupport,
  log = (m) => process.stdout.write(`${m}\n`),
  status = (m) => process.stderr.write(`${m}\n`),
  signal,
}) {
  const plan = await planBackfill({ source, apiBaseUrl, accessToken, rootKey, account, media, vaultFolder, status })
  const done = await loadDone(statePath, account)
  const todo = plan.matches.filter((m) => !done.has(m.fileId))
  const summary = { ...plan.counts, alreadyDone: plan.matches.length - todo.length, toDo: todo.length, added: 0, exists: 0, failed: 0, noPreview: 0, interrupted: false }
  if (dryRun) return summary

  const support = await thumbnailSupportFn()
  const kinds = new Set(todo.map((m) => mediaKindOf(m.name)))
  if (kinds.has('video') && !support.video) status('note: install ffmpeg for video previews; videos are skipped for now')
  if (kinds.has('image') && !support.image) status('note: no image encoder (sharp or ffmpeg); photos are skipped for now')

  const state = { batch: true }
  let next = 0
  let pending = []
  let flushing = Promise.resolve()
  const flush = async () => {
    const items = pending
    pending = []
    if (!items.length) return
    const outcome = await sendPreviews({
      apiBaseUrl, accessToken, state,
      items: items.map(({ fileId, fields }) => ({ fileId, ...fields })),
      onWait: (err, ms) => status(`server busy (${err.message.slice(0, 80)}); waiting ${Math.round(ms / 1000)} s`),
    })
    for (const { fileId, name } of items) {
      const o = outcome.get(fileId) ?? 'failed'
      if (o === 'ok') summary.added += 1
      else if (o === 'exists') summary.exists += 1
      else {
        summary.failed += 1
        log(`failed ${name}`)
        continue
      }
      done.add(fileId)
    }
    await saveDone(statePath, account, done)
    status(`previews: ${summary.added} added, ${summary.exists} already there, ${summary.failed} failed, ${summary.noPreview} not possible, of ${todo.length}`)
  }

  const worker = async () => {
    while (!signal?.aborted && next < todo.length) {
      const m = todo[next++]
      const kind = mediaKindOf(m.name)
      const jpeg = support[kind] ? await makeThumbnailFn({ path: m.path, name: m.name, size: m.size }) : null
      if (!jpeg || !m.cskWrapped || !m.cskIv) {
        summary.noPreview += 1
        continue
      }
      const csk = base64ToBytes(unwrapKeyB64({ wrappingKeyB64: m.parentKeyB64, wrappedKeyB64: m.cskWrapped, ivB64: m.cskIv }))
      let fields
      try {
        fields = thumbnailFields(jpeg, csk)
      } finally {
        csk.fill(0)
      }
      if (!fields) {
        summary.noPreview += 1
        continue
      }
      pending.push({ fileId: m.fileId, name: m.name, fields })
      if (pending.length >= BATCH) {
        flushing = flushing.then(flush)
        await flushing
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, todo.length || 1) }, worker))
  flushing = flushing.then(flush)
  await flushing
  summary.interrupted = Boolean(signal?.aborted)
  return summary
}
