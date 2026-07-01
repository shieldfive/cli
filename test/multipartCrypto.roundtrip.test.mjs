// VERIFIED: the two new multipart primitives — getCiphertextHashFromParts (must
// match the server's computeLargeFileSha1) and readFileChunks (bounded-memory
// disk reader). A porting bug here silently fails against the live backend.

import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { getCiphertextHashFromParts } from '../src/uploadCrypto.mjs'
import { readFileChunks } from '../src/upload.mjs'

const sha1HexOf = (bytes) => createHash('sha1').update(Buffer.from(bytes)).digest('hex')
const randPartHash = () =>
  sha1HexOf(webcrypto.getRandomValues(new Uint8Array(16)))

test('getCiphertextHashFromParts: single part is the part hash, lowercased', async () => {
  const h = randPartHash().toUpperCase()
  assert.equal(await getCiphertextHashFromParts([h]), h.toLowerCase())
})

test('getCiphertextHashFromParts: many parts == SHA1 over concatenated raw digests', async () => {
  const parts = [randPartHash(), randPartHash(), randPartHash()]
  // Independent reference: exactly what web/utils/ciphertextHash.ts does.
  const ref = createHash('sha1')
  for (const p of parts) ref.update(Buffer.from(p, 'hex'))
  assert.equal(await getCiphertextHashFromParts(parts), ref.digest('hex'))
})

test('getCiphertextHashFromParts rejects a malformed part hash', async () => {
  await assert.rejects(
    () => getCiphertextHashFromParts([randPartHash(), 'not-a-sha1']),
    /Invalid part SHA1 value/,
  )
})

test('getCiphertextHashFromParts rejects an empty manifest', async () => {
  await assert.rejects(() => getCiphertextHashFromParts([]), /Missing part hashes/)
})

test('readFileChunks slices a file into bounded chunks that reconcatenate exactly', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sf-cli-chunks-'))
  try {
    const content = webcrypto.getRandomValues(new Uint8Array(23)) // 2*8 + 7
    const path = join(dir, 'blob.bin')
    await writeFile(path, content)

    const chunks = []
    for await (const c of readFileChunks(path, 8)) chunks.push(c)

    assert.deepEqual(
      chunks.map((c) => c.length),
      [8, 8, 7],
    )
    const joined = new Uint8Array(23)
    let off = 0
    for (const c of chunks) {
      joined.set(c, off)
      off += c.length
    }
    assert.deepEqual(joined, content)

    // Chunks must be independent copies — the reader reuses its buffer, so a
    // retained chunk must not mutate when the next read happens.
    assert.notEqual(chunks[0].buffer, chunks[1].buffer)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('readFileChunks: exact multiple of chunkSize yields full chunks, no trailing empty', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sf-cli-chunks-'))
  try {
    const content = webcrypto.getRandomValues(new Uint8Array(16)) // 2 * 8, no remainder
    const path = join(dir, 'exact.bin')
    await writeFile(path, content)
    const sizes = []
    for await (const c of readFileChunks(path, 8)) sizes.push(c.length)
    assert.deepEqual(sizes, [8, 8]) // not [8, 8, 0]
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('readFileChunks yields nothing for an empty file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sf-cli-chunks-'))
  try {
    const path = join(dir, 'empty.bin')
    await writeFile(path, new Uint8Array(0))
    const chunks = []
    for await (const c of readFileChunks(path, 8)) chunks.push(c)
    assert.equal(chunks.length, 0)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
