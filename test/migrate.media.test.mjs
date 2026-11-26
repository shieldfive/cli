// `sf push --media` against a vault that already has Media and its
// subfolders (a NAS user's rerun after the 0.6.0 HTTP 409).
import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, test } from 'node:test'

import { runPush, scanTree } from '../src/migrate.mjs'

const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
const quiet = { log: () => {}, status: () => {}, progressEveryMs: 0, thumbnails: false }
let dir
let realFetch
let server

// Mirrors /api/folders/create: one top-level Media per account (409
// folderExists when the lookup of the winner fails), a per-account folder
// ceiling (409 with the limit text), and the create body stored as-is.
function stubServer({ mediaLookupFails = false, limit = 10_000 } = {}) {
  const folders = new Map()
  const calls = { create: 0 }
  globalThis.fetch = async (url, init = {}) => {
    const path = new URL(url).pathname
    const body = init.body ? JSON.parse(init.body) : null
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status })
    if (path === '/api/folders/tree') {
      const nodes = [...folders.values()].map((f) => ({ ...f, children: [] }))
      const byId = new Map(nodes.map((n) => [n.id, n]))
      const roots = []
      for (const n of nodes) (n.parent_id ? byId.get(n.parent_id).children : roots).push(n)
      return json({ tree: roots })
    }
    if (path === '/api/folders/create') {
      calls.create += 1
      if (body.isMedia && !body.parentFolderId) {
        const m = [...folders.values()].find((f) => f.is_media && !f.parent_id)
        if (m) return mediaLookupFails ? json({ error: 'Folder already exists', code: 'folderExists' }, 409) : json({ folder: m, existing: true })
      }
      if (folders.size >= limit) {
        return json({ error: 'You have reached the maximum number of folders. Delete some folders to create more.' }, 409)
      }
      const row = { id: body.id, name: body.name_encrypted, parent_id: body.parentFolderId, is_bin: false, is_media: Boolean(body.isMedia), fk_wrapped: body.fk_wrapped, fk_iv: body.fk_iv }
      folders.set(body.id, row)
      return json({ folder: row })
    }
    if (path === '/api/mobile/media/verify') return json({ verified: [] })
    if (path === '/api/files') return json({ files: [], pagination: { hasMore: false } })
    return json({ error: 'not stubbed' }, 404)
  }
  return { folders, calls }
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'sf-media-'))
  realFetch = globalThis.fetch
})
afterEach(async () => {
  globalThis.fetch = realFetch
  await rm(dir, { recursive: true, force: true })
})

async function nasTree() {
  const src = join(dir, 'photo')
  await mkdir(join(src, '2024', 'Trip'), { recursive: true })
  await mkdir(join(src, '2024', '@eaDir', 'a.jpg'), { recursive: true })
  await mkdir(join(src, '#recycle'), { recursive: true })
  await writeFile(join(src, 'top.jpg'), 'j')
  await writeFile(join(src, '2024', 'a.jpg'), 'a')
  await writeFile(join(src, '2024', '@eaDir', 'a.jpg', 'SYNOPHOTO_THUMB_M.jpg'), 't')
  await writeFile(join(src, '2024', 'Trip', 'b.jpg'), 'b')
  return src
}

const uploader = (rec) => async (a) => {
  rec.push(a)
  return { fileId: `f-${rec.length}-${a.name}` }
}
const push = (src, extra = {}) =>
  runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', media: true, statePath: join(dir, 'state.json'), ...quiet, ...extra })

test('scanTree skips Synology/NAS system folders', async () => {
  const scan = await scanTree(await nasTree())
  assert.deepEqual(scan.dirs, ['2024', '2024/Trip'])
  assert.deepEqual(scan.skipped.system.sort(), ['#recycle', '2024/@eaDir'])
  assert.ok(!scan.files.some((f) => f.rel.includes('@eaDir')))
})

test('push --media twice reuses Media and its subfolders, even with the state file gone', async () => {
  server = stubServer()
  const src = await nasTree()
  const first = []
  await push(src, { uploadFn: uploader(first) })
  assert.equal(server.folders.size, 3) // Media, 2024, 2024/Trip
  assert.equal(first.length, 3)

  const again = []
  const s2 = await push(src, { uploadFn: uploader(again) })
  assert.equal(server.calls.create, 3)
  assert.equal(s2.foldersCreated, 0)

  // A fresh machine: no state. Existing Media and subfolders are found by name.
  await rm(join(dir, 'state.json'))
  const third = []
  const s3 = await push(src, { uploadFn: uploader(third) })
  assert.equal(server.folders.size, 3)
  assert.equal(s3.foldersCreated, 0)
  const ids = new Set([...server.folders.keys()])
  for (const u of third) assert.ok(ids.has(u.folderId))
})

test('a 409 "already exists" for Media is resolved by looking Media up', async () => {
  server = stubServer({ mediaLookupFails: true })
  const src = await nasTree()
  await push(src, { uploadFn: uploader([]) })
  await rm(join(dir, 'state.json'))
  // Hide Media from the first tree read so the CLI tries to create it.
  const realTreeFetch = globalThis.fetch
  let hidden = true
  globalThis.fetch = async (url, init) => {
    if (hidden && new URL(url).pathname === '/api/folders/tree') {
      hidden = false
      return new Response(JSON.stringify({ tree: [] }), { status: 200 })
    }
    return realTreeFetch(url, init)
  }
  const up = []
  await push(src, { uploadFn: uploader(up) })
  const media = [...server.folders.values()].filter((f) => f.is_media)
  assert.equal(media.length, 1)
  assert.equal(up.find((u) => u.name === 'top.jpg').folderId, media[0].id)
})

test('a paid vault already past 10,000 folders pushes: the server, not the CLI, owns the limit', async () => {
  server = stubServer({ limit: 100_000 })
  const src = await nasTree()
  for (let i = 0; i < 10_000; i += 1) server.folders.set(`x${i}`, { id: `x${i}`, name: '', parent_id: null, is_bin: false })
  const notes = []
  const up = []
  await push(src, { uploadFn: uploader(up), status: (m) => notes.push(m) })
  assert.equal(up.length, 3)
  assert.ok(notes.some((m) => m.includes('sf tidy --media --dry-run')))
})

test('a server folder-limit 409 is reported plainly, not as POST /api/folders/create', async () => {
  server = stubServer({ limit: 1 })
  const src = await nasTree()
  await assert.rejects(push(src, { uploadFn: uploader([]) }), (e) => {
    assert.match(e.message, /could not create the folder "2024" in your vault: .*folder limit/)
    assert.match(e.message, /sf tidy --media --dry-run/)
    assert.doesNotMatch(e.message, /HTTP 409|\/api\//)
    return true
  })
})

test('a push with no local record skips files already in the vault (same name and size)', async () => {
  server = stubServer()
  const src = await nasTree()
  const rows = []
  await push(src, { uploadFn: async (a) => { rows.push(a); return { fileId: `f-${rows.length}` } } })
  // The stub vault now "holds" those files: serve them from /api/files.
  const { encryptNameV6 } = await import('@shieldfive/crypto/vault')
  const { base64ToBytes } = await import('../src/uploadCrypto.mjs')
  const listed = new Map()
  for (const r of rows) {
    const env = await encryptNameV6({ name: r.name, folderKey: base64ToBytes(Buffer.from(r.folderKey).toString('base64')), rowId: `row-${r.name}` })
    if (!listed.has(r.folderId)) listed.set(r.folderId, [])
    listed.get(r.folderId).push({ id: `row-${r.name}`, name: JSON.stringify(env), size_bytes: r.size + 1761, size_declared: r.size })
  }
  const inner = globalThis.fetch
  globalThis.fetch = async (url, init) => {
    const u = new URL(url)
    if (u.pathname === '/api/files') return new Response(JSON.stringify({ files: listed.get(u.searchParams.get('folderId')) ?? [], pagination: { hasMore: false } }), { status: 200 })
    return inner(url, init)
  }
  await rm(join(dir, 'state.json'))
  const again = []
  const s = await push(src, { uploadFn: uploader(again) })
  assert.equal(again.length, 0)
  assert.equal(s.alreadyThere, 3)
})
