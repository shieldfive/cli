// sf thumbnails: match vault photos/videos to local originals, send only
// encrypted previews (batched, or one by one on an older server), resumable.

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, test } from 'node:test'

import { encryptNameV6 } from '@shieldfive/crypto/vault'

import { runBackfill } from '../src/thumbnailBackfill.mjs'
import { newRowBoundId } from '../src/upload.mjs'
import { base64ToBytes, bytesToBase64, generateRandomKeyB64, unwrapKeyB64, wrapKeyB64 } from '../src/uploadCrypto.mjs'

const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
const rootB64 = bytesToBase64(rootKey)
let dir
let realFetch

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'sf-backfill-'))
  realFetch = globalThis.fetch
})
afterEach(async () => {
  globalThis.fetch = realFetch
  await rm(dir, { recursive: true, force: true })
})

async function folder(name, parent, parentKeyB64) {
  const id = newRowBoundId()
  const key = generateRandomKeyB64()
  const w = wrapKeyB64({ wrappingKeyB64: parentKeyB64, keyToWrapB64: key })
  const env = await encryptNameV6({ name, folderKey: base64ToBytes(parentKeyB64), rowId: id })
  return { node: { id, name: JSON.stringify(env), parent_id: parent, is_bin: false, is_media: false, fk_wrapped: w.wrapped, fk_iv: w.iv }, key }
}

async function file(name, folderId, folderKeyB64, size, hasThumb = false) {
  const id = newRowBoundId()
  const csk = generateRandomKeyB64()
  const w = wrapKeyB64({ wrappingKeyB64: folderKeyB64, keyToWrapB64: csk })
  const env = await encryptNameV6({ name, folderKey: base64ToBytes(folderKeyB64), rowId: id })
  return { row: { id, name: JSON.stringify(env), folder_id: folderId, size_bytes: size, has_thumbnail: hasThumb, csk_wrapped: w.wrapped, csk_iv: w.iv }, csk }
}

function server({ folders, files, batch = true }) {
  const posts = []
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(url)
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status })
    if (u.pathname === '/api/folders/tree') {
      const nodes = folders.map((f) => ({ ...f, children: [] }))
      const byId = new Map(nodes.map((n) => [n.id, n]))
      const roots = []
      for (const n of nodes) (n.parent_id ? byId.get(n.parent_id).children : roots).push(n)
      return json({ tree: roots })
    }
    if (u.pathname === '/api/files') {
      const fid = u.searchParams.get('folderId')
      const all = files.filter((f) => f.folder_id === fid)
      const start = Number(u.searchParams.get('cursor') ?? 0)
      const page = all.slice(start, start + 100)
      const hasMore = start + 100 < all.length
      return json({ files: page, pagination: { hasMore, nextCursor: hasMore ? String(start + 100) : null } })
    }
    if (u.pathname === '/api/files/thumbnail' && init.method === 'POST') {
      const body = JSON.parse(init.body)
      if (body.items) {
        if (!batch) return json({ error: 'Invalid thumbnail' }, 400)
        posts.push(...body.items)
        return json({ results: body.items.map((i) => ({ fileId: i.fileId, ok: true })) })
      }
      posts.push(body)
      return json({ ok: true })
    }
    return json({ error: 'nope' }, 404)
  }
  return { posts }
}

async function scenario() {
  const top = await folder('Camera', null, rootB64)
  const sub = await folder('Trip', top.node.id, top.key)
  const a = await file('a.jpg', top.node.id, top.key, 3)
  const b = await file('b.mp4', sub.node.id, sub.key, 4)
  const have = await file('c.jpg', top.node.id, top.key, 1, true)
  const txt = await file('notes.txt', top.node.id, top.key, 2)
  const gone = await file('gone.jpg', top.node.id, top.key, 5)
  const resized = await file('d.png', top.node.id, top.key, 99)
  const src = join(dir, 'Camera')
  await mkdir(join(src, 'Trip'), { recursive: true })
  await writeFile(join(src, 'a.jpg'), 'aaa')
  await writeFile(join(src, 'Trip', 'b.mp4'), 'bbbb')
  await writeFile(join(src, 'c.jpg'), 'c')
  await writeFile(join(src, 'notes.txt'), 'nn')
  await writeFile(join(src, 'd.png'), 'dd')
  return {
    src,
    folders: [top.node, sub.node],
    files: [a, b, have, txt, gone, resized].map((f) => f.row),
    cskById: new Map([a, b].map((f) => [f.row.id, f.csk])),
  }
}

const common = (s, extra = {}) => ({
  source: s.src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x',
  statePath: join(dir, 'state.json'),
  thumbnailSupportFn: async () => ({ image: true, video: true }),
  makeThumbnailFn: async ({ name }) => new TextEncoder().encode(`jpeg:${name}`),
  log: () => {}, status: () => {},
  ...extra,
})

async function openPreview(post, cskB64) {
  const iv = new Uint8Array(12)
  iv.set(base64ToBytes(post.thumbnail_nonce_prefix))
  const key = await webcrypto.subtle.importKey('raw', base64ToBytes(cskB64), 'AES-GCM', false, ['decrypt'])
  return new TextDecoder().decode(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, base64ToBytes(post.thumbnail_ciphertext_b64)))
}

test('dry run counts and sends nothing', async () => {
  const s = await scenario()
  const srv = server(s)
  const r = await runBackfill(common(s, { dryRun: true }))
  assert.equal(r.vaultFiles, 6)
  assert.equal(r.media, 5)
  assert.equal(r.haveThumbnail, 1)
  assert.equal(r.matched, 2)
  assert.equal(r.noLocal, 1)
  assert.equal(r.sizeDiffers, 1)
  assert.equal(r.toDo, 2)
  assert.equal(srv.posts.length, 0)
})

test('adds previews encrypted under each file key, batched; a rerun sends nothing', async () => {
  const s = await scenario()
  const srv = server(s)
  const r = await runBackfill(common(s))
  assert.equal(r.added, 2)
  assert.equal(srv.posts.length, 2)
  for (const p of srv.posts) {
    const name = await openPreview(p, s.cskById.get(p.fileId))
    assert.match(name, /^jpeg:(a\.jpg|b\.mp4)$/)
  }
  const again = await runBackfill(common(s))
  assert.equal(again.alreadyDone, 2)
  assert.equal(again.added, 0)
  assert.equal(srv.posts.length, 2)
})

test('falls back to one-by-one on a server without batch support', async () => {
  const s = await scenario()
  const srv = server({ ...s, batch: false })
  const r = await runBackfill(common(s))
  assert.equal(r.added, 2)
  assert.equal(srv.posts.length, 2)
  assert.ok(srv.posts.every((p) => !p.items))
})

test('--vault-folder picks the folder by path; unknown path is an error', async () => {
  const s = await scenario()
  server(s)
  const r = await runBackfill(common({ ...s, src: join(s.src, 'Trip') }, { vaultFolder: 'Camera/Trip', dryRun: true }))
  assert.equal(r.matched, 1)
  await assert.rejects(runBackfill(common(s, { vaultFolder: 'Nope', dryRun: true })), /no vault folder/)
})
