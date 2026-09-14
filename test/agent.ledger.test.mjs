// VERIFIED (offline): the upload ledger. The ledger decides whether a local file
// counts as backed up, which a tool may then act on by removing the local copy,
// so every state is pinned — especially the ones that must NOT come back
// `verified`.

import assert from 'node:assert/strict'
import { createHmac, webcrypto } from 'node:crypto'
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  VERIFY_BATCH,
  appendEntry,
  classify,
  deriveLedgerKey,
  ledgerPath,
  macFile,
  readEntries,
} from '../src/agent/ledger.mjs'

const ACCOUNT = '3f0b2c9e-1d4a-4b6f-9c2e-7a8d5e6f1a2b'
const rootKey = () => webcrypto.getRandomValues(new Uint8Array(32))

async function tmp() {
  return mkdtemp(join(tmpdir(), 'sf-cli-ledger-'))
}

test('deriveLedgerKey is deterministic per root key and differs across root keys', () => {
  const rk = rootKey()
  assert.deepEqual(deriveLedgerKey(rk), deriveLedgerKey(rk))
  assert.equal(deriveLedgerKey(rk).length, 32)
  assert.notDeepEqual(deriveLedgerKey(rk), deriveLedgerKey(rootKey()))
  assert.throws(() => deriveLedgerKey(new Uint8Array(16)), /32-byte/)
})

test('macFile is HMAC-SHA256 of the bytes, and unlinkable under a different key', async () => {
  const dir = await tmp()
  const file = join(dir, 'doc.pdf')
  await writeFile(file, 'the same document')
  const k1 = deriveLedgerKey(rootKey())
  const k2 = deriveLedgerKey(rootKey())

  const expected = createHmac('sha256', k1).update('the same document').digest('hex')
  assert.equal(await macFile(file, k1), expected)
  assert.notEqual(await macFile(file, k1), await macFile(file, k2))
})

test('ledgerPath refuses anything that is not a UUID account id', () => {
  const dir = '/tmp/ledger'
  assert.equal(ledgerPath(dir, ACCOUNT.toUpperCase()), join(dir, `${ACCOUNT}.jsonl`))
  for (const bad of ['../../etc/passwd', 'abc', '', null]) {
    assert.throws(() => ledgerPath(dir, bad), /malformed account id/)
  }
})

test('appendEntry writes a 0600 file; readEntries skips malformed lines and counts them', async () => {
  const dir = await tmp()
  const file = ledgerPath(join(dir, 'ledger'), ACCOUNT)
  const mac = 'a'.repeat(64)
  await appendEntry(file, { path: '/x', size: 1, mtimeMs: 1, mac, fileId: 'f1', uploadedAt: 'now', device: 'd' })
  await writeFile(file, (await readFile(file, 'utf8')) + 'not json\n{"v":1,"path":"/y"}\n', { flag: 'w' })
  await appendEntry(file, { path: '/z', size: 1, mtimeMs: 1, mac, fileId: 'f2', uploadedAt: 'now', device: 'd' })

  assert.equal((await stat(file)).mode & 0o777, 0o600)
  const { entries, malformed } = await readEntries(file)
  assert.deepEqual(entries.map((e) => e.fileId), ['f1', 'f2'])
  assert.equal(malformed, 2)
})

test('readEntries on a ledger that does not exist yet is empty, not an error', async () => {
  const dir = await tmp()
  assert.deepEqual(await readEntries(join(dir, 'nope.jsonl')), { entries: [], malformed: 0 })
})

async function fixture() {
  const dir = await tmp()
  const key = deriveLedgerKey(rootKey())
  const write = async (name, content) => {
    const p = join(dir, name)
    await writeFile(p, content)
    return p
  }
  return { dir, key, write }
}

const verifier = (verifiedIds) => {
  const calls = []
  return {
    calls,
    fn: async (ids) => {
      calls.push(ids)
      return ids.filter((id) => verifiedIds.includes(id))
    },
  }
}

test('classify: uploaded bytes that the server confirms are verified', async () => {
  const { key, write } = await fixture()
  const p = await write('a.txt', 'alpha')
  const entries = [{ v: 1, path: p, mac: await macFile(p, key), fileId: 'f-a' }]
  const v = verifier(['f-a'])
  const [r] = await classify([p], { entries, ledgerKey: key, verifyFileIds: v.fn })
  assert.equal(r.state, 'verified')
  assert.equal(r.fileId, 'f-a')
})

test('classify: uploaded bytes the server CANNOT confirm are missing, never verified', async () => {
  const { key, write } = await fixture()
  const p = await write('a.txt', 'alpha')
  const entries = [{ v: 1, path: p, mac: await macFile(p, key), fileId: 'f-in-bin' }]
  const [r] = await classify([p], { entries, ledgerKey: key, verifyFileIds: verifier([]).fn })
  assert.equal(r.state, 'missing')
})

test('classify: a file edited after upload is changed_since_upload, not verified', async () => {
  const { key, write } = await fixture()
  const p = await write('a.txt', 'version one')
  const entries = [{ v: 1, path: p, mac: await macFile(p, key), fileId: 'f-old' }]
  await writeFile(p, 'version two')
  const [r] = await classify([p], { entries, ledgerKey: key, verifyFileIds: verifier(['f-old']).fn })
  assert.equal(r.state, 'changed_since_upload')
})

test('classify: SAME NAME AND SIZE with different bytes is not treated as backed up', async () => {
  // The inference this ledger exists to avoid. Both files are "invoice.pdf" and
  // both are 8 bytes; only one was uploaded.
  const { dir, key } = await fixture()
  const uploaded = join(dir, 'invoice.pdf')
  await writeFile(uploaded, 'AAAAAAAA')
  const entries = [{ v: 1, path: uploaded, mac: await macFile(uploaded, key), fileId: 'f-1' }]

  const other = join(dir, 'other', 'invoice.pdf')
  await (await import('node:fs/promises')).mkdir(join(dir, 'other'))
  await writeFile(other, 'BBBBBBBB')

  const [r] = await classify([other], { entries, ledgerKey: key, verifyFileIds: verifier(['f-1']).fn })
  assert.equal(r.state, 'not_in_ledger')
})

test('classify: a copy of uploaded bytes at another path is verified, and says which path matched', async () => {
  const { key, write } = await fixture()
  const original = await write('orig.bin', 'identical bytes')
  const copy = await write('copy.bin', 'identical bytes')
  const entries = [{ v: 1, path: original, mac: await macFile(original, key), fileId: 'f-o' }]
  const [r] = await classify([copy], { entries, ledgerKey: key, verifyFileIds: verifier(['f-o']).fn })
  assert.equal(r.state, 'verified')
  assert.equal(r.matchedPath, original)
})

test('classify: unreadable inputs never reach the server', async () => {
  const { dir, key } = await fixture()
  const v = verifier(['anything'])
  const results = await classify(['relative.txt', join(dir, 'gone.txt'), dir], {
    entries: [],
    ledgerKey: key,
    verifyFileIds: v.fn,
  })
  assert.deepEqual(results.map((r) => r.state), ['unreadable', 'unreadable', 'unreadable'])
  assert.equal(v.calls.length, 0)
})

test(`classify: server verification is batched at ${VERIFY_BATCH}`, async () => {
  const { key, write } = await fixture()
  const paths = []
  const entries = []
  for (let i = 0; i < VERIFY_BATCH + 50; i++) {
    const p = await write(`f${i}.txt`, `content ${i}`)
    paths.push(p)
    entries.push({ v: 1, path: p, mac: await macFile(p, key), fileId: `id-${i}` })
  }
  const v = verifier(entries.map((e) => e.fileId))
  const results = await classify(paths, { entries, ledgerKey: key, verifyFileIds: v.fn })
  assert.equal(results.every((r) => r.state === 'verified'), true)
  assert.deepEqual(v.calls.map((c) => c.length), [VERIFY_BATCH, 50])
})
