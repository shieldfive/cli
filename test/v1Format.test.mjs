// What `sf push` / `sf sync` write: the web's default format (cipher_version 3,
// suite 0x03, v1 wire format), not the deprecated v0 the CLI used to write.
//
// Every check here opens the CLI's output through @shieldfive/crypto's own
// readers (test/v1Reference.mjs), the code path the web app and the reference
// decryptor use, from nothing but the stored fields and the owner's root key.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { createIdentity } from '@shieldfive/crypto/identity'
import { decryptStreamPqHybridV1 } from '@shieldfive/crypto/streams/pq-hybrid-v1'
import { decryptName, parseNameEnvelope } from '@shieldfive/crypto/vault'

import {
  base64ToBytes,
  encryptPartsV3,
  generateRandomKeyB64,
  uuidToBytes,
  vaultMlKemPublicKey,
  wrapKeyB64,
  bytesToBase64,
} from '../src/uploadCrypto.mjs'
import { concat, referenceDecrypt, uuidBytes } from './v1Reference.mjs'

const vector = JSON.parse(readFileSync(new URL('./vectors/v3-upload.json', import.meta.url), 'utf8'))
const vRootKey = base64ToBytes(vector.rootKey)
const vStored = concat(vector.parts.map(base64ToBytes))

test('vector: the stored object opens with the root key alone, through the reference reader', async () => {
  const { plaintext, header } = await referenceDecrypt({
    stored: vStored,
    rootKey: vRootKey,
    cskWrapped: vector.cskWrapped,
    cskIv: vector.cskIv,
  })
  assert.deepEqual(plaintext, base64ToBytes(vector.plaintext))
  assert.equal(header.suite, 3)
  assert.equal(header.chunkSize, vector.chunkSize)
  assert.equal(header.totalChunks, vector.parts.length)
  assert.deepEqual(header.fileId, uuidBytes(vector.rowId), 'header file_id is the row id')
})

test('vector: the web streaming reader (decryptStreamPqHybridV1) opens it too', async () => {
  const identity = await createIdentity({ userId: 'web', masterSecret: vRootKey })
  const { webcrypto } = await import('node:crypto')
  const k = await webcrypto.subtle.importKey('raw', vRootKey, 'AES-GCM', false, ['decrypt'])
  const envelopeKey = new Uint8Array(
    await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBytes(vector.cskIv) }, k, base64ToBytes(vector.cskWrapped)),
  )
  const { plaintext } = decryptStreamPqHybridV1(new Blob([vStored]).stream(), {
    recipientSecretKey: identity.mlKemSecretKey,
    envelopeKey,
  })
  assert.deepEqual(new Uint8Array(await new Response(plaintext).arrayBuffer()), base64ToBytes(vector.plaintext))
})

test('vector: the ML-KEM identity is the one the web derives from the root key', async () => {
  const pk = await vaultMlKemPublicKey(vRootKey)
  assert.equal(createHash('sha256').update(pk).digest('hex'), vector.mlKemPublicKeySha256)
  const web = await createIdentity({ userId: 'any-placeholder', masterSecret: vRootKey })
  assert.deepEqual(pk, web.publicBundle.mlKemPublicKey)
})

test('vector: names open with the library reader; v6 only for its own row', async () => {
  assert.equal(
    await decryptName({ envelope: parseNameEnvelope(vector.nameEncrypted), folderKey: vRootKey }),
    vector.name,
  )
  const v6 = parseNameEnvelope(vector.nameEncryptedV6)
  assert.equal(await decryptName({ envelope: v6, folderKey: vRootKey, rowId: vector.rowId }), vector.name)
  await assert.rejects(decryptName({ envelope: v6, folderKey: vRootKey, rowId: '00000000-0000-4000-8000-000000000000' }))
})

test('vector: dropping the last chunk is detected (v0 could not detect this)', async () => {
  const cut = concat(vector.parts.slice(0, -1).map(base64ToBytes))
  await assert.rejects(
    referenceDecrypt({ stored: cut, rootKey: vRootKey, cskWrapped: vector.cskWrapped, cskIv: vector.cskIv }),
  )
})

test('vector: swapping two chunks is detected', async () => {
  const p = vector.parts.map(base64ToBytes)
  const swapped = concat([p[0], p[2], p[1], ...p.slice(3)])
  await assert.rejects(
    referenceDecrypt({ stored: swapped, rootKey: vRootKey, cskWrapped: vector.cskWrapped, cskIv: vector.cskIv }),
  )
})

test('fresh output: one part per chunk, part 0 carries the header, sizes in the header', async () => {
  const rootKey = crypto.getRandomValues(new Uint8Array(32))
  const rowId = crypto.randomUUID()
  const plaintext = crypto.getRandomValues(new Uint8Array(100))
  const csk = generateRandomKeyB64()
  const wrap = wrapKeyB64({ wrappingKeyB64: bytesToBase64(rootKey), keyToWrapB64: csk })
  // Enqueue the plaintext in odd-sized pieces: the split into parts must come
  // from the format, not from how the input was chunked.
  async function* pieces() {
    for (let i = 0; i < plaintext.length; i += 7) yield plaintext.slice(i, i + 7)
  }
  const parts = []
  for await (const part of encryptPartsV3({
    plaintextChunks: pieces(),
    plaintextSize: plaintext.length,
    chunkSize: 32,
    envelopeKey: base64ToBytes(csk),
    fileId: uuidToBytes(rowId),
    recipientPublicKey: await vaultMlKemPublicKey(rootKey),
  })) {
    parts.push(part)
  }
  assert.equal(parts.length, 4) // 32, 32, 32, 4
  for (const frame of parts.slice(1)) {
    const len = new DataView(frame.buffer, frame.byteOffset).getUint32(0, false)
    assert.equal(frame.length, 4 + len, 'each later part is exactly one frame')
  }
  const { plaintext: out, header } = await referenceDecrypt({
    stored: concat(parts),
    rootKey,
    cskWrapped: wrap.wrapped,
    cskIv: wrap.iv,
  })
  assert.deepEqual(out, plaintext)
  assert.equal(header.plaintextSize, 100)
  assert.deepEqual(header.fileId, uuidBytes(rowId))
})

test('a file that changes size while it is read is refused, not uploaded short', async () => {
  const rootKey = crypto.getRandomValues(new Uint8Array(32))
  async function* shrunk() {
    yield new Uint8Array(10)
  }
  const run = async () => {
    for await (const _ of encryptPartsV3({
      plaintextChunks: shrunk(),
      plaintextSize: 50,
      chunkSize: 32,
      envelopeKey: crypto.getRandomValues(new Uint8Array(32)),
      fileId: uuidToBytes(crypto.randomUUID()),
      recipientPublicKey: await vaultMlKemPublicKey(rootKey),
    })) {
      // drain
    }
  }
  await assert.rejects(run)
})
