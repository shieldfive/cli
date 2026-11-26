// `sf tidy`: empty @eaDir-style folders under Media go to the Bin; anything
// holding a file stays; names and keys are re-sealed for the Bin.
import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, test } from 'node:test'

import { decryptName, encryptNameV6, parseNameEnvelope } from '@shieldfive/crypto/vault'

import { runTidy } from '../src/tidy.mjs'
import { newRowBoundId } from '../src/upload.mjs'
import { base64ToBytes, bytesToBase64, generateRandomKeyB64, unwrapKeyB64, wrapKeyB64 } from '../src/uploadCrypto.mjs'

const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
const rootB64 = bytesToBase64(rootKey)
let realFetch
let srv

function vault() {
  const folders = new Map()
  const files = new Map() // folderId -> count
  const keys = new Map()
  const calls = { move: 0, del: 0, list: 0 }
  const add = async (name, parent, extra = {}) => {
    const id = newRowBoundId()
    const key = generateRandomKeyB64()
    const pk = parent ? keys.get(parent) : rootB64
    const w = wrapKeyB64({ wrappingKeyB64: pk, keyToWrapB64: key })
    const env = await encryptNameV6({ name, folderKey: base64ToBytes(pk), rowId: id })
    folders.set(id, { id, name: JSON.stringify(env), parent_id: parent, is_bin: false, is_media: false, fk_wrapped: w.wrapped, fk_iv: w.iv, ...extra })
    keys.set(id, key)
    return id
  }
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(url)
    const body = init.body ? JSON.parse(init.body) : null
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status })
    if (u.pathname === '/api/folders/tree') {
      const nodes = [...folders.values()].map((f) => ({ ...f, children: [] }))
      const byId = new Map(nodes.map((n) => [n.id, n]))
      const roots = []
      for (const n of nodes) (n.parent_id ? byId.get(n.parent_id).children : roots).push(n)
      return json({ tree: roots })
    }
    if (u.pathname === '/api/files') {
      calls.list += 1
      const n = files.get(u.searchParams.get('folderId')) ?? 0
      return json({ files: Array.from({ length: Math.min(n, 5) }, (_, i) => ({ id: `f${i}` })), pagination: { hasMore: false } })
    }
    if (u.pathname === '/api/folders/create') {
      const row = { id: body.id, name: body.name_encrypted, parent_id: null, is_bin: true, is_media: false, fk_wrapped: body.fk_wrapped, fk_iv: body.fk_iv }
      folders.set(body.id, row)
      return json({ folder: row })
    }
    if (u.pathname === '/api/folders/move') {
      calls.move += 1
      for (const it of body.items) Object.assign(folders.get(it.id), { parent_id: body.newParentId, name: it.name_encrypted, fk_wrapped: it.fk_wrapped, fk_iv: it.fk_iv })
      return json({ success: true, moved: body.items.length })
    }
    if (u.pathname === '/api/folders/delete') {
      calls.del += 1
      const gone = [body.folderId]
      while (gone.length) {
        const id = gone.pop()
        for (const f of folders.values()) if (f.parent_id === id) gone.push(f.id)
        folders.delete(id)
      }
      return json({ success: true })
    }
    return json({ error: 'not stubbed' }, 404)
  }
  return { folders, files, keys, calls, add }
}

beforeEach(() => {
  realFetch = globalThis.fetch
  srv = vault()
})
afterEach(() => {
  globalThis.fetch = realFetch
})

async function nasVault() {
  const media = await srv.add('Media', null, { is_media: true })
  const y = await srv.add('2024', media)
  const ea = await srv.add('@eaDir', y)
  for (let i = 0; i < 5; i += 1) await srv.add(`IMG_${i}.jpg`, ea)
  const ea2 = await srv.add('@eaDir', media)
  const keepMe = await srv.add('a.jpg', ea2)
  srv.files.set(keepMe, 2) // has files: stays
  const rec = await srv.add('#recycle', media)
  const ds = await srv.add('.DS_Store', y)
  srv.files.set(y, 10)
  const trip = await srv.add('Trip', y) // normal empty folder: never touched
  return { media, y, ea, ea2, rec, ds, trip }
}
const opts = (extra = {}) => ({ apiBaseUrl: 'https://x.test', accessToken: 't', rootKey, account: 'a@x', media: true, listGapMs: 0, moveGapMs: 0, ...extra })

test('dry run counts empty system folders and changes nothing', async () => {
  await nasVault()
  const before = JSON.stringify([...srv.folders.values()])
  const s = await runTidy(opts())
  assert.equal(s.candidates, 4)
  assert.equal(s.empty, 3) // @eaDir under 2024, #recycle, .DS_Store
  assert.equal(s.emptyFolders, 8)
  assert.equal(s.keptWithFiles, 1)
  assert.equal(srv.calls.move, 0)
  assert.equal(JSON.stringify([...srv.folders.values()]), before)
})

test('apply moves only empty system folders to the Bin, re-sealed for it', async () => {
  const t = await nasVault()
  const s = await runTidy(opts({ apply: true }))
  assert.equal(s.movedToBin, 3)
  const bin = [...srv.folders.values()].find((f) => f.is_bin)
  assert.ok(bin)
  const binKey = unwrapKeyB64({ wrappingKeyB64: rootB64, wrappedKeyB64: bin.fk_wrapped, ivB64: bin.fk_iv })
  for (const id of [t.ea, t.rec, t.ds]) {
    const f = srv.folders.get(id)
    assert.equal(f.parent_id, bin.id)
    assert.equal(unwrapKeyB64({ wrappingKeyB64: binKey, wrappedKeyB64: f.fk_wrapped, ivB64: f.fk_iv }), srv.keys.get(id))
    const name = await decryptName({ envelope: parseNameEnvelope(f.name), folderKey: base64ToBytes(binKey), rowId: id })
    assert.ok(['@eaDir', '#recycle', '.DS_Store'].includes(name))
  }
  assert.equal(srv.folders.get(t.ea2).parent_id, t.media) // has files
  assert.equal(srv.folders.get(t.trip).parent_id, t.y) // not a system name
  assert.equal(srv.calls.del, 0)
})

test('declining the question changes nothing; --delete purges only what moved', async () => {
  const t = await nasVault()
  const no = await runTidy(opts({ apply: true, confirm: async () => false }))
  assert.equal(no.declined, true)
  assert.equal(srv.calls.move, 0)
  const s = await runTidy(opts({ apply: true, purge: true }))
  assert.equal(s.purged, 3)
  for (const id of [t.ea, t.rec, t.ds]) assert.ok(!srv.folders.has(id))
  assert.ok(srv.folders.has(t.ea2))
  assert.ok(srv.folders.has(t.trip))
  // A second run finds nothing to do.
  const again = await runTidy(opts({ apply: true }))
  assert.equal(again.empty, 0)
})

test('--delete on a later run removes the empty system folders an earlier tidy left in the Bin', async () => {
  const t = await nasVault()
  await runTidy(opts({ apply: true }))
  const s = await runTidy(opts({ apply: true, purge: true }))
  assert.equal(s.empty, 0)
  assert.equal(s.inBin, 3)
  assert.equal(s.purged, 3)
  for (const id of [t.ea, t.rec, t.ds]) assert.ok(!srv.folders.has(id))
  assert.ok(srv.folders.has(t.ea2))
})

test('no Bin and at the folder limit: a plain message, nothing moved', async () => {
  await nasVault()
  const real = globalThis.fetch
  globalThis.fetch = async (url, init) =>
    new URL(url).pathname === '/api/folders/create'
      ? new Response(JSON.stringify({ error: 'You have reached the maximum number of folders. Delete some folders to create more.' }), { status: 409 })
      : real(url, init)
  await assert.rejects(runTidy(opts({ apply: true })), /no Bin yet.*folder limit/)
  assert.equal(srv.calls.move, 0)
})

test('--delete re-checks each folder right before deleting it and skips one that gained a file', async () => {
  const t = await nasVault()
  const child = [...srv.folders.values()].find((f) => f.parent_id === t.ea)
  const s = await runTidy(opts({ apply: true, purge: true, confirm: async () => { srv.files.set(child.id, 1); return true } }))
  assert.equal(s.skippedNotEmpty, 1)
  assert.equal(s.purged, 2)
  assert.ok(srv.folders.has(t.ea))
  assert.ok(srv.folders.has(child.id))
})
