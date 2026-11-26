// Encrypted previews (thumbnail.mjs) and `sf push --media`.
//
// The decrypt below is the web app's legacy-format reader (utils/thumbnail.ts
// decryptThumbnail): WebCrypto AES-GCM, key = the CSK the client unwraps from
// csk_wrapped with the parent key, IV = base64 4-byte prefix || 8 zero bytes.

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { webcrypto } from 'node:crypto'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, test } from 'node:test'

import { runPush } from '../src/migrate.mjs'
import {
  encryptThumbnail,
  makeThumbnail,
  mediaKindOf,
  THUMBNAIL_MAX_BYTES,
  THUMBNAIL_MAX_SIDE,
} from '../src/thumbnail.mjs'
import { createUploadSession } from '../src/upload.mjs'
import { base64ToBytes, bytesToBase64, unwrapKeyB64 } from '../src/uploadCrypto.mjs'

const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
const hasFfmpeg = spawnSync('ffmpeg', ['-version']).status === 0
let sharp = null
try {
  sharp = (await import('sharp')).default
} catch {}

async function webDecrypt(ciphertext, cskBytes, noncePrefixB64) {
  const prefix = base64ToBytes(noncePrefixB64)
  assert.equal(prefix.length, 4)
  const iv = new Uint8Array(12)
  iv.set(prefix)
  const key = await webcrypto.subtle.importKey('raw', cskBytes, { name: 'AES-GCM' }, false, ['decrypt'])
  return new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext))
}

const jpegSize = async (bytes) => {
  const meta = await sharp(Buffer.from(bytes)).metadata()
  return { format: meta.format, width: meta.width, height: meta.height }
}

let dir
let realFetch
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'sf-thumb-'))
  realFetch = globalThis.fetch
})
afterEach(async () => {
  globalThis.fetch = realFetch
  await rm(dir, { recursive: true, force: true })
})

test('mediaKindOf picks images and videos by extension', () => {
  assert.equal(mediaKindOf('IMG_1.JPG'), 'image')
  assert.equal(mediaKindOf('a.heic'), 'image')
  assert.equal(mediaKindOf('clip.MOV'), 'video')
  assert.equal(mediaKindOf('notes.pdf'), null)
})

test('encryptThumbnail output opens with the web legacy reader', async () => {
  const csk = webcrypto.getRandomValues(new Uint8Array(32))
  const plain = webcrypto.getRandomValues(new Uint8Array(1000))
  const { ciphertext, noncePrefix } = encryptThumbnail(plain, csk)
  assert.equal(ciphertext.length, plain.length + 16)
  assert.deepEqual(await webDecrypt(ciphertext, csk, noncePrefix), plain)
  // A fresh prefix each time.
  assert.notEqual(encryptThumbnail(plain, csk).noncePrefix, noncePrefix)
})

test('image thumbnail: JPEG, longest side 512, under the byte budget', { skip: !sharp && 'sharp not installed' }, async () => {
  const path = join(dir, 'big.png')
  // Noisy so the encoder has to work for the budget.
  const raw = Buffer.from(webcrypto.getRandomValues(new Uint8Array(1600 * 900 * 3).subarray(0, 65536)))
  const pixels = Buffer.alloc(1600 * 900 * 3)
  for (let i = 0; i < pixels.length; i += raw.length) raw.copy(pixels, i)
  await sharp(pixels, { raw: { width: 1600, height: 900, channels: 3 } }).png().toFile(path)
  const out = await makeThumbnail({ path, name: 'big.png', size: 1 })
  const meta = await jpegSize(out)
  assert.equal(meta.format, 'jpeg')
  assert.equal(meta.width, THUMBNAIL_MAX_SIDE)
  assert.equal(meta.height, 288)
  assert.ok(out.length <= THUMBNAIL_MAX_BYTES * 1.5, `thumbnail ${out.length} bytes`)
})

test('small images are not enlarged; undecodable ones give null', { skip: !sharp && 'sharp not installed' }, async () => {
  const path = join(dir, 'small.jpg')
  await sharp({ create: { width: 40, height: 30, channels: 3, background: '#c00' } }).jpeg().toFile(path)
  const meta = await jpegSize(await makeThumbnail({ path, name: 'small.jpg', size: 1 }))
  assert.deepEqual([meta.width, meta.height], [40, 30])
  await writeFile(join(dir, 'fake.jpg'), 'not a jpeg')
  assert.equal(await makeThumbnail({ path: join(dir, 'fake.jpg'), name: 'fake.jpg', size: 10 }), null)
  assert.equal(await makeThumbnail({ path: join(dir, 'fake.jpg'), name: 'fake.txt', size: 10 }), null)
})

test('video poster via ffmpeg', { skip: !hasFfmpeg && 'ffmpeg not on PATH' }, async () => {
  const path = join(dir, 'clip.mp4')
  const r = spawnSync('ffmpeg', ['-v', 'error', '-f', 'lavfi', '-i', 'testsrc=duration=2:size=1280x720:rate=10', '-pix_fmt', 'yuv420p', path])
  assert.equal(r.status, 0)
  const out = await makeThumbnail({ path, name: 'clip.mp4', size: 1 })
  assert.ok(out && out[0] === 0xff && out[1] === 0xd8, 'JPEG')
  if (sharp) {
    const meta = await jpegSize(out)
    assert.deepEqual([meta.width, meta.height], [512, 288])
  }
})

test('create-upload-session carries a thumbnail the web decrypts with the unwrapped CSK', async () => {
  let sent
  globalThis.fetch = async (_url, init) => {
    sent = JSON.parse(init.body)
    return new Response(JSON.stringify({ fileId: sent.clientUploadId }), { status: 200 })
  }
  const folderKey = webcrypto.getRandomValues(new Uint8Array(32))
  const thumb = new Uint8Array([0xff, 0xd8, 1, 2, 3, 0xff, 0xd9])
  await createUploadSession({
    apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, name: 'a.jpg', size: 10,
    rowId: '01900000-0000-7000-8000-000000000000', folderId: 'f', folderKey, thumbnail: thumb,
  })
  const csk = unwrapKeyB64({ wrappingKeyB64: bytesToBase64(folderKey), wrappedKeyB64: sent.csk_wrapped, ivB64: sent.csk_iv })
  const plain = await webDecrypt(base64ToBytes(sent.thumbnail_ciphertext_b64), base64ToBytes(csk), sent.thumbnail_nonce_prefix)
  assert.deepEqual(plain, thumb)

  // No thumbnail: both fields null, as before.
  await createUploadSession({ apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, name: 'a.txt', size: 1, rowId: '01900000-0000-7000-8000-000000000001' })
  assert.equal(sent.thumbnail_ciphertext_b64, null)
  assert.equal(sent.thumbnail_nonce_prefix, null)
})

function mediaServer({ existingMedia = null } = {}) {
  const folders = new Map()
  if (existingMedia) folders.set(existingMedia.id, existingMedia)
  const created = []
  globalThis.fetch = async (url, init = {}) => {
    const path = new URL(url).pathname
    const body = init.body ? JSON.parse(init.body) : null
    const json = (o) => new Response(JSON.stringify(o), { status: 200 })
    if (path === '/api/folders/tree') {
      return json({ tree: [...folders.values()].filter((f) => !f.parent_id).map((f) => ({ ...f, children: [...folders.values()].filter((c) => c.parent_id === f.id).map((c) => ({ ...c, children: [] })) })) })
    }
    if (path === '/api/folders/create') {
      created.push(body)
      const row = { id: body.id, name: body.name_encrypted, parent_id: body.parentFolderId, is_bin: false, is_media: Boolean(body.isMedia), fk_wrapped: body.fk_wrapped, fk_iv: body.fk_iv }
      folders.set(body.id, row)
      return json({ folder: row })
    }
    if (path === '/api/mobile/media/verify') return json({ verified: [] })
    return new Response('{}', { status: 404 })
  }
  return { folders, created }
}

const quiet = { log: () => {}, status: () => {}, progressEveryMs: 0 }

async function mediaSource() {
  const src = join(dir, 'Camera')
  await mkdir(join(src, 'Trip'), { recursive: true })
  await writeFile(join(src, 'a.jpg'), 'x')
  await writeFile(join(src, 'Trip', 'b.mp4'), 'y')
  await writeFile(join(src, 'notes.txt'), 'z')
  return src
}

test('push --media uploads into the existing Media folder, with previews for photos and videos only', async () => {
  const wrap = (await import('../src/uploadCrypto.mjs')).wrapKeyB64
  const mediaKey = bytesToBase64(webcrypto.getRandomValues(new Uint8Array(32)))
  const env = wrap({ wrappingKeyB64: bytesToBase64(rootKey), keyToWrapB64: mediaKey })
  const media = { id: 'media-1', name: 'x', parent_id: null, is_bin: false, is_media: true, fk_wrapped: env.wrapped, fk_iv: env.iv }
  const server = mediaServer({ existingMedia: media })
  const src = await mediaSource()
  const uploads = []
  const s = await runPush({
    source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', media: true,
    statePath: join(dir, 'state.json'),
    uploadFn: async (a) => { uploads.push(a); return { fileId: a.rowId } },
    thumbnailSupportFn: async () => ({ image: true, video: true }),
    makeThumbnailFn: async ({ name }) => new TextEncoder().encode(`thumb:${name}`),
    ...quiet,
  })
  assert.equal(s.uploaded, 3)
  // Only the subfolder is created, under Media; no new top-level folder.
  assert.equal(server.created.length, 1)
  assert.equal(server.created[0].parentFolderId, 'media-1')
  assert.equal(server.created[0].isMedia, undefined)
  const byName = Object.fromEntries(uploads.map((u) => [u.name, u]))
  assert.equal(byName['a.jpg'].folderId, 'media-1')
  assert.equal(bytesToBase64(byName['a.jpg'].folderKey), mediaKey)
  assert.equal(new TextDecoder().decode(byName['a.jpg'].thumbnail), 'thumb:a.jpg')
  assert.equal(new TextDecoder().decode(byName['b.mp4'].thumbnail), 'thumb:b.mp4')
  assert.equal(byName['notes.txt'].thumbnail, null)
})

test('push --media creates the Media folder when the account has none; --no-thumbnails sends none', async () => {
  const server = mediaServer()
  const src = await mediaSource()
  const uploads = []
  let made = 0
  await runPush({
    source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', media: true, thumbnails: false,
    statePath: join(dir, 'state.json'),
    uploadFn: async (a) => { uploads.push(a); return { fileId: a.rowId } },
    makeThumbnailFn: async () => { made += 1; return new Uint8Array([1]) },
    ...quiet,
  })
  const top = server.created.find((c) => c.parentFolderId === null)
  assert.equal(top.isMedia, true)
  assert.equal(uploads.find((u) => u.name === 'a.jpg').folderId, top.id)
  assert.equal(made, 0)
  assert.ok(uploads.every((u) => u.thumbnail === null))
})

test('push without --media still makes a Drive folder named after the source', async () => {
  const server = mediaServer()
  const src = await mediaSource()
  await runPush({
    source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x',
    statePath: join(dir, 'state.json'),
    uploadFn: async (a) => ({ fileId: a.rowId }),
    thumbnailSupportFn: async () => ({ image: false, video: false }),
    ...quiet,
  })
  const top = server.created.find((c) => c.parentFolderId === null)
  assert.equal(top.isMedia, undefined)
})

test('uploadFile without an explicit thumbnail makes one (sync, agent); SF_NO_THUMBNAILS=1 turns it off', { skip: !sharp && 'sharp not installed' }, async () => {
  const { uploadFile } = await import('../src/upload.mjs')
  const path = join(dir, 'p.jpg')
  await sharp({ create: { width: 800, height: 600, channels: 3, background: '#0a0' } }).jpeg().toFile(path)
  const bodies = []
  globalThis.fetch = async (_url, init) => {
    bodies.push(JSON.parse(init.body))
    return new Response(JSON.stringify({ error: 'stop here' }), { status: 400 })
  }
  const args = { apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, name: 'p.jpg', path, size: 10 }
  await assert.rejects(uploadFile(args))
  assert.ok(bodies[0].thumbnail_ciphertext_b64)
  process.env.SF_NO_THUMBNAILS = '1'
  try {
    await assert.rejects(uploadFile(args))
  } finally {
    delete process.env.SF_NO_THUMBNAILS
  }
  assert.equal(bodies[1].thumbnail_ciphertext_b64, null)
})
