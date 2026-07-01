// VERIFIED (offline): the full `sf push` upload protocol, driven against a
// mocked backend + Backblaze. These assert the exact wire contract the live
// server checks in web/app/api/files/{create-upload-session,upload-part-url,
// complete-upload} — part numbering, per-chunk nonce sequencing, the
// first-chunk-only upload proof, the multipart ciphertextHash, part-URL refresh
// on an expired token, and the finalize payload. A drift here is a silent
// live-upload failure, so we reproduce the server's own checks locally.

import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { gcm } from '@noble/ciphers/aes.js'

import { uploadFile } from '../src/upload.mjs'
import {
  base64ToBytes,
  bytesToBase64,
  computeAesGcmUploadProof,
  getCiphertextHashFromParts,
  unwrapKeyB64,
} from '../src/uploadCrypto.mjs'

const API = 'https://api.test'
const PROOF_KEY = 'ab'.repeat(32) // 64 hex, shape the server issues
const sha1HexOf = (bytes) => createHash('sha1').update(Buffer.from(bytes)).digest('hex')

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  }
}

// Rebuild the 12-byte nonce the way encryptFileChunk / the apps do:
// 4-byte prefix || 8-byte big-endian chunk counter.
function nonceFor(noncePrefixB64, chunkIndex) {
  const nonce = new Uint8Array(12)
  nonce.set(base64ToBytes(noncePrefixB64), 0)
  let counter = BigInt(chunkIndex)
  for (let i = 0; i < 8; i += 1) {
    nonce[11 - i] = Number(counter & 0xffn)
    counter >>= 8n
  }
  return nonce
}

async function withTempFile(content, fn) {
  const dir = await mkdtemp(join(tmpdir(), 'sf-cli-flow-'))
  try {
    const path = join(dir, 'secret.bin')
    await writeFile(path, content)
    return await fn(path)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

test('multipart push: parts, nonce sequencing, first-chunk proof, ciphertextHash, refresh', async () => {
  const chunkSize = 8
  const content = webcrypto.getRandomValues(new Uint8Array(20)) // 3 parts: 8,8,4
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))

  let createBody = null
  const parts = [] // { partNumber, sha1, body } captured in call order
  let finalizeBody = null
  let refreshCount = 0
  let firstPartRejectedOnce = false

  const originalFetch = globalThis.fetch
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.toString()

    if (url === `${API}/api/files/create-upload-session`) {
      createBody = JSON.parse(init.body)
      return jsonResponse(200, {
        uploadKind: 'large',
        fileId: 'file-abc',
        uploadUrl: 'https://b2.test/part',
        authToken: 'tok-initial',
        chunkSize,
        b2FileId: 'b2-large-1',
        proofKey: PROOF_KEY,
      })
    }

    if (url === `${API}/api/files/upload-part-url`) {
      refreshCount += 1
      return jsonResponse(200, {
        uploadUrl: 'https://b2.test/part-refreshed',
        authToken: 'tok-refreshed',
      })
    }

    if (url.startsWith('https://b2.test/part')) {
      const partNumber = Number(init.headers['X-Bz-Part-Number'])
      // Force one expired-token response on the very first attempt at part 1
      // to exercise the refresh-and-retry path.
      if (partNumber === 1 && !firstPartRejectedOnce) {
        firstPartRejectedOnce = true
        return jsonResponse(403, { code: 'expired_auth_token' })
      }
      parts.push({
        partNumber,
        sha1: init.headers['X-Bz-Content-Sha1'],
        authToken: init.headers.Authorization,
        body: new Uint8Array(init.body),
      })
      return jsonResponse(200, { fileId: `b2-part-${partNumber}` })
    }

    if (url === `${API}/api/files/complete-upload`) {
      finalizeBody = JSON.parse(init.body)
      return jsonResponse(200, { ok: true, fileId: finalizeBody.fileId })
    }

    throw new Error(`unexpected fetch: ${url}`)
  }

  try {
    await withTempFile(content, (path) =>
      uploadFile({
        apiBaseUrl: API,
        accessToken: 'bearer-xyz',
        rootKey,
        name: 'Secret Q3.pdf',
        path,
        size: content.length,
      }),
    )
  } finally {
    globalThis.fetch = originalFetch
  }

  // Session was requested with the true byte size.
  assert.equal(createBody.sizeBytes, 20)

  // Exactly three parts landed, numbered 1..3 in order.
  assert.deepEqual(
    parts.map((p) => p.partNumber),
    [1, 2, 3],
  )
  // The refresh happened exactly once; the retried part 1 used the refreshed
  // token, and later parts reuse it rather than re-refreshing per part.
  assert.equal(refreshCount, 1)
  assert.equal(parts[0].authToken, 'tok-refreshed')
  assert.equal(parts[1].authToken, 'tok-refreshed')

  // Recover the content key from the create-session envelope (the server can't,
  // but we hold the rootKey) and decrypt each part with its per-chunk nonce.
  const cskB64 = unwrapKeyB64({
    wrappingKeyB64: bytesToBase64(rootKey),
    wrappedKeyB64: createBody.csk_wrapped,
    ivB64: createBody.csk_iv,
  })
  const noncePrefixB64 = createBody.cipher_nonce_prefix
  const decrypted = []
  parts.forEach((part, i) => {
    // Each part body's SHA-1 must equal the header the client sent to Backblaze.
    assert.equal(part.sha1, sha1HexOf(part.body), `part ${i + 1} sha1`)
    const plain = gcm(base64ToBytes(cskB64), nonceFor(noncePrefixB64, i)).decrypt(part.body)
    decrypted.push(plain)
  })
  const joined = new Uint8Array(20)
  let off = 0
  for (const c of decrypted) {
    joined.set(c, off)
    off += c.length
  }
  assert.deepEqual(joined, content, 'reassembled plaintext == original file')

  // Finalize payload matches the server's expectations exactly.
  const partSha1Array = parts.map((p) => p.sha1)
  assert.equal(finalizeBody.fileId, 'file-abc')
  assert.equal(finalizeBody.b2FileId, 'b2-large-1') // the large-file id, not a part id
  assert.deepEqual(finalizeBody.partSha1Array, partSha1Array)
  assert.equal(
    finalizeBody.ciphertextHash,
    await getCiphertextHashFromParts(partSha1Array),
  )
  // Proof is computed from the FIRST chunk only (server re-reads chunkSize+tag).
  assert.equal(
    finalizeBody.proof,
    computeAesGcmUploadProof({
      proofKeyHex: PROOF_KEY,
      cipherVersion: 1,
      chunkSize,
      noncePrefixB64,
      ciphertextChunk: parts[0].body,
    }),
  )
})

test('direct push: single chunk, storage id from PUT, single-part ciphertextHash', async () => {
  const content = webcrypto.getRandomValues(new Uint8Array(64)) // <= chunkSize -> direct
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))

  let createBody = null
  let putBody = null
  let putSha1 = null
  let finalizeBody = null

  const originalFetch = globalThis.fetch
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === `${API}/api/files/create-upload-session`) {
      createBody = JSON.parse(init.body)
      return jsonResponse(200, {
        uploadKind: 'direct',
        fileId: 'file-direct',
        uploadUrl: 'https://b2.test/direct',
        authToken: 'tok-direct',
        storagePath: 'storage/uuid',
        chunkSize: 5 * 1024 * 1024,
        proofKey: PROOF_KEY,
      })
    }
    if (url === 'https://b2.test/direct') {
      putBody = new Uint8Array(init.body)
      putSha1 = init.headers['X-Bz-Content-Sha1']
      return jsonResponse(200, { fileId: 'b2-direct-storage-id' })
    }
    if (url === `${API}/api/files/complete-upload`) {
      finalizeBody = JSON.parse(init.body)
      return jsonResponse(200, { ok: true, fileId: finalizeBody.fileId })
    }
    throw new Error(`unexpected fetch: ${url}`)
  }

  try {
    await withTempFile(content, (path) =>
      uploadFile({
        apiBaseUrl: API,
        accessToken: 'bearer-xyz',
        rootKey,
        name: 'small.txt',
        path,
        size: content.length,
      }),
    )
  } finally {
    globalThis.fetch = originalFetch
  }

  assert.equal(createBody.sizeBytes, 64)
  assert.equal(putSha1, sha1HexOf(putBody))

  const cskB64 = unwrapKeyB64({
    wrappingKeyB64: bytesToBase64(rootKey),
    wrappedKeyB64: createBody.csk_wrapped,
    ivB64: createBody.csk_iv,
  })
  const plain = gcm(
    base64ToBytes(cskB64),
    nonceFor(createBody.cipher_nonce_prefix, 0),
  ).decrypt(putBody)
  assert.deepEqual(plain, content)

  assert.equal(finalizeBody.b2FileId, 'b2-direct-storage-id') // from the PUT, not the session
  assert.deepEqual(finalizeBody.partSha1Array, [putSha1])
  assert.equal(finalizeBody.ciphertextHash, putSha1) // single part
})
