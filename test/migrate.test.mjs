// sf push (migrate.mjs): folder tree, resume, retries and run-level stops,
// against a stub of the folder and verify endpoints with an injected uploader.

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, test } from 'node:test'

import { decryptName, parseNameEnvelope } from '@shieldfive/crypto/vault'

import { isRunFatal, isTransient, runPush, scanTree } from '../src/migrate.mjs'
import { base64ToBytes, bytesToBase64, unwrapKeyB64 } from '../src/uploadCrypto.mjs'

const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
let dir
let realFetch
let server

function stubServer() {
  const folders = new Map()
  const ready = new Set()
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
      const row = { id: body.id, name: body.name_encrypted, parent_id: body.parentFolderId, is_bin: false, fk_wrapped: body.fk_wrapped, fk_iv: body.fk_iv }
      folders.set(body.id, row)
      return json({ folder: row })
    }
    if (path === '/api/mobile/media/verify') {
      return json({ verified: body.fileIds.filter((id) => ready.has(id)) })
    }
    return json({ error: 'not stubbed' }, 404)
  }
  return { folders, ready, calls }
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'sf-migrate-'))
  realFetch = globalThis.fetch
  server = stubServer()
})
afterEach(async () => {
  globalThis.fetch = realFetch
  await rm(dir, { recursive: true, force: true })
})

async function makeTree() {
  const src = join(dir, 'Dropbox')
  await mkdir(join(src, 'Photos', '2024'), { recursive: true })
  await mkdir(join(src, 'Empty dir'))
  await writeFile(join(src, 'a.txt'), 'a')
  await writeFile(join(src, 'Photos', '2024', 'Café.jpg'), 'jpg') // decomposed é
  await writeFile(join(src, 'Photos', 'zero.bin'), '')
  await writeFile(join(src, '.DS_Store'), 'x')
  await symlink('/etc/hosts', join(src, 'link'))
  return src
}

function fakeUploader(record, { failTimes = new Map(), fail = new Map() } = {}) {
  return async (args) => {
    const n = failTimes.get(args.name) ?? 0
    if (n > 0) {
      failTimes.set(args.name, n - 1)
      const err = new Error('HTTP 503')
      err.status = 503
      throw err
    }
    if (fail.has(args.name)) throw fail.get(args.name)
    record.push(args)
    server.ready.add(args.rowId)
    return { fileId: args.rowId }
  }
}

const quiet = { log: () => {}, status: () => {}, progressEveryMs: 0 }

test('scanTree lists dirs parents-first and skips dotfiles and symlinks', async () => {
  const src = await makeTree()
  const scan = await scanTree(src)
  assert.deepEqual(scan.dirs, ['Empty dir', 'Photos', 'Photos/2024'])
  assert.deepEqual(scan.files.map((f) => f.rel).sort(), ['Photos/2024/Café.jpg', 'Photos/zero.bin', 'a.txt'])
  assert.deepEqual(scan.skipped.dotfiles, ['.DS_Store'])
  assert.deepEqual(scan.skipped.symlinks, ['link'])
})

test('push recreates the tree with folder keys the root key unwraps, and NFC names', async () => {
  const src = await makeTree()
  const uploads = []
  const statePath = join(dir, 'state.json')
  const s = await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath, uploadFn: fakeUploader(uploads), ...quiet })
  assert.equal(s.uploaded, 3)
  assert.equal(server.folders.size, 4) // Dropbox, Empty dir, Photos, Photos/2024

  const top = [...server.folders.values()].find((f) => f.parent_id === null)
  const topKey = unwrapKeyB64({ wrappingKeyB64: bytesToBase64(rootKey), wrappedKeyB64: top.fk_wrapped, ivB64: top.fk_iv })
  assert.equal(await decryptName({ envelope: parseNameEnvelope(top.name), folderKey: rootKey, rowId: top.id }), 'Dropbox')

  const photosId = JSON.parse(await readFile(statePath, 'utf8')).folders.Photos
  const photos = server.folders.get(photosId)
  assert.equal(photos.parent_id, top.id)
  const photosKey = unwrapKeyB64({ wrappingKeyB64: topKey, wrappedKeyB64: photos.fk_wrapped, ivB64: photos.fk_iv })
  assert.equal(await decryptName({ envelope: parseNameEnvelope(photos.name), folderKey: base64ToBytes(topKey), rowId: photos.id }), 'Photos')

  const jpg = uploads.find((u) => u.name.startsWith('Caf'))
  assert.equal(jpg.name, 'Café.jpg') // NFC
  const y2024 = server.folders.get(jpg.folderId)
  const y2024Key = unwrapKeyB64({ wrappingKeyB64: photosKey, wrappedKeyB64: y2024.fk_wrapped, ivB64: y2024.fk_iv })
  assert.equal(bytesToBase64(jpg.folderKey), y2024Key)
  assert.equal(uploads.find((u) => u.name === 'a.txt').folderId, top.id)
})

test('a rerun skips finished files and folders and uploads only what is new', async () => {
  const src = await makeTree()
  const statePath = join(dir, 'state.json')
  const first = []
  await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath, uploadFn: fakeUploader(first), ...quiet })
  await writeFile(join(src, 'Photos', 'new.txt'), 'new')
  const second = []
  const s = await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath, uploadFn: fakeUploader(second), ...quiet })
  assert.deepEqual(second.map((u) => u.name), ['new.txt'])
  assert.equal(s.alreadyThere, 3)
  assert.equal(server.calls.create, 4) // no folder made twice
})

test('a pending upload that did finalize is settled by verify, not re-uploaded', async () => {
  const src = await makeTree()
  const statePath = join(dir, 'state.json')
  // First run is "killed" during a.txt's finalize: the server made it ready,
  // the client never heard back.
  const killErr = Object.assign(new TypeError('fetch failed'), { finalizeOutcomeUnknown: true })
  let killed = false
  const uploads = []
  const uploader = async (args) => {
    if (args.name === 'a.txt' && !killed) {
      killed = true
      server.ready.add(args.rowId)
      throw killErr
    }
    return fakeUploader(uploads)(args)
  }
  const s = await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath, uploadFn: uploader, ...quiet })
  assert.equal(s.failed.length, 0)
  assert.equal(uploads.filter((u) => u.name === 'a.txt').length, 0) // settled, not uploaded again
  const state = JSON.parse(await readFile(statePath, 'utf8'))
  assert.ok(state.files['a.txt'])
})

test('transient failures are retried; a full vault stops the run', async () => {
  assert.equal(isTransient(Object.assign(new Error('x'), { status: 503 })), true)
  assert.equal(isTransient(Object.assign(new Error('x'), { status: 400 })), false)
  assert.equal(isTransient(new TypeError('fetch failed')), true)
  assert.equal(isTransient(new Error('create-upload-session returned file id x')), false)
  assert.equal(isRunFatal(Object.assign(new Error('x'), { status: 413, serverCode: 'storage_limit_exceeded' })), true)
  assert.equal(isRunFatal(Object.assign(new Error('x'), { status: 413, serverCode: 'too_many_parts' })), false)

  const src = join(dir, 'src')
  await mkdir(src)
  await writeFile(join(src, 'one'), '1')
  const uploads = []
  const s = await runPush({
    source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath: join(dir, 's.json'),
    uploadFn: fakeUploader(uploads, { failTimes: new Map([['one', 1]]) }), ...quiet,
  })
  assert.equal(s.uploaded, 1)

  await writeFile(join(src, 'two'), '2')
  const full = Object.assign(new Error('Upgrade to upload more'), { status: 402 })
  const s2 = await runPush({
    source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath: join(dir, 's.json'),
    uploadFn: fakeUploader([], { fail: new Map([['two', full]]) }), ...quiet,
  })
  assert.equal(s2.stoppedBy, full)
})

test('another account never reuses the state file', async () => {
  const src = await makeTree()
  const statePath = join(dir, 'state.json')
  await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath, uploadFn: fakeUploader([]), ...quiet })
  const again = []
  await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'b@x', statePath, uploadFn: fakeUploader(again), ...quiet })
  assert.equal(again.length, 3)
})

test('an aborted run starts nothing new', async () => {
  const src = await makeTree()
  const controller = new AbortController()
  const uploads = []
  const uploader = async (args) => {
    controller.abort()
    return fakeUploader(uploads)(args)
  }
  const s = await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath: join(dir, 's.json'), uploadFn: uploader, concurrency: 1, signal: controller.signal, ...quiet })
  assert.equal(uploads.length, 1)
  assert.equal(s.interrupted, true)
  assert.equal(s.notStarted, 2)
})

test('a vault folder deleted between runs is made again and its files re-uploaded', async () => {
  const src = await makeTree()
  const statePath = join(dir, 'state.json')
  await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath, uploadFn: fakeUploader([]), ...quiet })
  const state = JSON.parse(await readFile(statePath, 'utf8'))
  server.folders.delete(state.folders['Photos/2024'])
  const again = []
  await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath, uploadFn: fakeUploader(again), ...quiet })
  assert.deepEqual(again.map((u) => u.name), ['Caf\u00e9.jpg'])
})

test('a file that changes while it uploads is reported and not recorded as done', async () => {
  const src = join(dir, 'src')
  await mkdir(src)
  await writeFile(join(src, 'f.txt'), 'one')
  const statePath = join(dir, 's.json')
  const uploader = async (args) => {
    await writeFile(args.path, 'changed, longer')
    return fakeUploader([])(args)
  }
  const s = await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath, uploadFn: uploader, ...quiet })
  assert.deepEqual(s.changed, ['f.txt'])
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).files['f.txt'], undefined)
})

test('a folder create whose answer was lost is retried with the same id', async () => {
  const src = join(dir, 'src')
  await mkdir(join(src, 'sub'), { recursive: true })
  const inner = globalThis.fetch
  const ids = []
  let dropped = false
  globalThis.fetch = async (url, init) => {
    if (new URL(url).pathname === '/api/folders/create') {
      ids.push(JSON.parse(init.body).id)
      if (!dropped) {
        dropped = true
        await inner(url, init) // the server makes it...
        throw new TypeError('fetch failed') // ...the answer is lost
      }
    }
    return inner(url, init)
  }
  await runPush({ source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', statePath: join(dir, 's.json'), uploadFn: fakeUploader([]), ...quiet })
  assert.equal(ids[0], ids[1])
  assert.equal(server.folders.size, 2)
})

test('keeps an unconfirmed finalization in the checkpoint for the next run', async () => {
  const src = join(dir, 'source')
  await mkdir(src)
  await writeFile(join(src, 'a.txt'), 'a')
  const statePath = join(dir, 'state.json')
  const args = {
    source: src, apiBaseUrl: 'https://x.test', accessToken: 't', rootKey,
    account: 'a@x', statePath, ...quiet,
  }
  const uploadAttempts = []
  const summary = await runPush({
    ...args,
    uploadFn: async ({ rowId }) => {
      uploadAttempts.push(rowId)
      throw Object.assign(new Error('Complete upload could not reach the server'), {
        uploadNetworkError: true, finalizeOutcomeUnknown: true,
      })
    },
  })
  assert.equal(summary.failed.length, 1)
  assert.equal(uploadAttempts.length, 1)
  const pending = JSON.parse(await readFile(statePath, 'utf8')).pending['a.txt']
  assert.equal(pending.fileId, uploadAttempts[0])
  server.ready.add(pending.fileId)
  const uploads = []
  const resumed = await runPush({ ...args, uploadFn: fakeUploader(uploads) })
  assert.equal(resumed.alreadyThere, 1)
  assert.deepEqual(uploads, [])
})
