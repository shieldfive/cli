// VERIFIED (offline): the full `sf push` upload protocol, driven against a
// mocked backend + storage. These assert the wire contract the live server
// checks in web/app/api/files/{create-upload-session,upload-part-url,
// complete-upload} — part numbering, per-chunk nonce sequencing, the
// first-chunk-only upload proof, the multipart ciphertextHash, part-URL refresh
// on an expired token, and the finalize payload. A drift here is a silent
// live-upload failure, so we reproduce the server's own checks locally.
//
// Offline is the limit, and it has already cost one release. These mocks are
// written from the server's source, not from a live response, so a fixture that
// supplies a field the server stopped sending will keep passing while every
// real upload fails — which is what happened to the direct path between
// 2026-09-03 and this change. The fixtures are the assertion; keep them honest.

import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { decryptName, parseNameEnvelope } from '@shieldfive/crypto/vault'

import { uploadFile } from '../src/upload.mjs'
import { getCiphertextHashFromParts } from '../src/uploadCrypto.mjs'
import { concat, independentV3Proof, referenceDecrypt, uuidBytes } from './v1Reference.mjs'

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

// Row ids are UUIDs: the header's file_id is the row id's 16 bytes.
const FILE_ID = '3f1c2a9e-7b4d-4c1e-9a2f-0d6e8b5c4a71'
const DIRECT_FILE_ID = '9e2b7c4d-1a3f-4e8b-8c6d-5f0a2b9e7d13'

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
  // Serial: this test asserts exact arrival order + a single URL refresh, which
  // only hold when one part is in flight at a time. Concurrency is covered by
  // the out-of-order test below.
  const prevConcurrency = process.env.SF_UPLOAD_CONCURRENCY
  process.env.SF_UPLOAD_CONCURRENCY = '1'
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
        fileId: FILE_ID,
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
    if (prevConcurrency === undefined) delete process.env.SF_UPLOAD_CONCURRENCY
    else process.env.SF_UPLOAD_CONCURRENCY = prevConcurrency
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

  // The web's default format, not v0: cipher_version 3 and none of the v0-only
  // fields (the server rejects them for the v1 wire format).
  assert.equal(createBody.cipherVersion, 3)
  assert.ok(!('cipher_nonce_prefix' in createBody), 'no v0 nonce prefix')
  assert.ok(!('chunkSize' in createBody), 'no v0 chunk size')

  parts.forEach((part, i) => {
    // Each part body's SHA-1 must equal the header the client sent to Backblaze.
    assert.equal(part.sha1, sha1HexOf(part.body), `part ${i + 1} sha1`)
  })
  // The stored object (parts in order) opens through the reference decryptor
  // with only the owner's root key, and is bound to its row.
  const stored = concat(parts.map((p) => p.body))
  const { plaintext, header } = await referenceDecrypt({
    stored,
    rootKey,
    cskWrapped: createBody.csk_wrapped,
    cskIv: createBody.csk_iv,
  })
  assert.deepEqual(plaintext, content, 'reassembled plaintext == original file')
  assert.equal(header.suite, 3)
  assert.deepEqual(header.fileId, uuidBytes(FILE_ID), 'header file_id is the row id')
  assert.equal(header.totalChunks, 3)
  assert.equal(header.plaintextSize, 20)

  // Finalize payload matches the server's expectations exactly.
  const partSha1Array = parts.map((p) => p.sha1)
  assert.equal(finalizeBody.fileId, FILE_ID)
  assert.equal(finalizeBody.b2FileId, 'b2-large-1') // the large-file id, not a part id
  assert.deepEqual(finalizeBody.partSha1Array, partSha1Array)
  assert.equal(
    finalizeBody.ciphertextHash,
    await getCiphertextHashFromParts(partSha1Array),
  )
  // Proof covers header || frame_0, which is exactly part 1.
  assert.equal(finalizeBody.proof, independentV3Proof(PROOF_KEY, parts[0].body))

  // The name is re-sealed bound to the row (v6) at finalize.
  const v6 = parseNameEnvelope(finalizeBody.nameEncryptedV6)
  assert.equal(v6.v, 6)
  assert.equal(await decryptName({ envelope: v6, folderKey: rootKey, rowId: FILE_ID }), 'Secret Q3.pdf')
  await assert.rejects(
    decryptName({ envelope: v6, folderKey: rootKey, rowId: DIRECT_FILE_ID }),
    'a v6 name does not open for another row',
  )
})

test('multipart push: parts completing OUT OF ORDER still finalize in chunk order', async () => {
  // The reordering guarantee. With concurrency, parts finish in an order the
  // network decides, not chunk order. The server's b2_finish_large_file needs
  // partSha1Array in strict part order (part 1..N), and the multipart
  // ciphertextHash is SHA-1 over the concatenated part digests in that same
  // order — so a single scrambled slot silently corrupts the stored file.
  // We run 5 parts fully concurrent and force completion order 5,4,3,2,1, then
  // assert the finalized manifest is back in chunk order and the file reassembles.
  const prevConcurrency = process.env.SF_UPLOAD_CONCURRENCY
  process.env.SF_UPLOAD_CONCURRENCY = '5'
  const chunkSize = 8
  const partCount = 5
  const content = webcrypto.getRandomValues(new Uint8Array(36)) // 8,8,8,8,4 -> 5 parts
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))

  let createBody = null
  let finalizeBody = null
  let refreshCount = 0
  const parts = [] // captured in COMPLETION order (when each PUT resolves)
  const pending = new Map() // partNumber -> () => resolve its PUT

  const originalFetch = globalThis.fetch
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.toString()

    if (url === `${API}/api/files/create-upload-session`) {
      createBody = JSON.parse(init.body)
      return jsonResponse(200, {
        uploadKind: 'large',
        fileId: FILE_ID,
        uploadUrl: 'https://b2.test/part-seed',
        authToken: 'tok-seed',
        chunkSize,
        b2FileId: 'b2-large-1',
        proofKey: PROOF_KEY,
      })
    }

    if (url === `${API}/api/files/upload-part-url`) {
      refreshCount += 1
      return jsonResponse(200, {
        uploadUrl: `https://b2.test/part-refreshed-${refreshCount}`,
        authToken: `tok-refreshed-${refreshCount}`,
      })
    }

    if (url.startsWith('https://b2.test/part')) {
      const partNumber = Number(init.headers['X-Bz-Part-Number'])
      const captured = {
        partNumber,
        sha1: init.headers['X-Bz-Content-Sha1'],
        body: new Uint8Array(init.body),
      }
      // Hold every part open until all N have been PUT, then release them in
      // strict reverse order so completion order is deterministically [5..1].
      return await new Promise((resolve) => {
        pending.set(partNumber, () => {
          parts.push(captured) // completion order
          resolve(jsonResponse(200, { fileId: `b2-part-${partNumber}` }))
        })
        if (pending.size === partCount) {
          for (const pn of [...pending.keys()].sort((a, b) => b - a)) {
            pending.get(pn)()
          }
        }
      })
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
        name: 'Big Secret.pdf',
        path,
        size: content.length,
      }),
    )
  } finally {
    globalThis.fetch = originalFetch
    if (prevConcurrency === undefined) delete process.env.SF_UPLOAD_CONCURRENCY
    else process.env.SF_UPLOAD_CONCURRENCY = prevConcurrency
  }

  // All five parts landed, and they completed in reverse order — proving the
  // reordering path is actually exercised (not accidentally sequential).
  assert.deepEqual(
    parts.map((p) => p.partNumber),
    [5, 4, 3, 2, 1],
    'completion order was forced reverse',
  )
  // One upload URL per concurrent connection: the seed plus four refreshes.
  assert.equal(refreshCount, partCount - 1)

  // The finalized manifest is in CHUNK order (part 1..N), NOT completion order.
  const sha1ByPart = new Map(parts.map((p) => [p.partNumber, p.sha1]))
  const chunkOrderSha1 = Array.from({ length: partCount }, (_v, i) => sha1ByPart.get(i + 1))
  assert.equal(finalizeBody.partSha1Array.length, partCount, 'no missing/duplicate slot')
  assert.deepEqual(finalizeBody.partSha1Array, chunkOrderSha1, 'manifest in chunk order')
  assert.notDeepEqual(
    finalizeBody.partSha1Array,
    parts.map((p) => p.sha1),
    'manifest is not in completion order',
  )
  assert.equal(
    finalizeBody.ciphertextHash,
    await getCiphertextHashFromParts(chunkOrderSha1),
    'ciphertextHash hashes the chunk-order digests',
  )

  // Reassemble in chunk order and decrypt: the plaintext must equal the file.
  const bodyByPart = new Map(parts.map((p) => [p.partNumber, p.body]))
  const ordered = []
  for (let i = 0; i < partCount; i += 1) {
    const body = bodyByPart.get(i + 1)
    assert.equal(sha1ByPart.get(i + 1), sha1HexOf(body), `part ${i + 1} sha1`)
    ordered.push(body)
  }
  const { plaintext } = await referenceDecrypt({
    stored: concat(ordered),
    rootKey,
    cskWrapped: createBody.csk_wrapped,
    cskIv: createBody.csk_iv,
  })
  assert.deepEqual(plaintext, content, 'reassembled plaintext == original file')

  // Proof is still computed from part 1, regardless of completion order.
  assert.equal(finalizeBody.proof, independentV3Proof(PROOF_KEY, bodyByPart.get(1)))
})

test('multipart push: a 5xx on a part is retried with a fresh URL and succeeds', async () => {
  // Serial: asserts an exact attempt count and a single URL refresh, which only
  // hold with one part in flight (concurrency would prefetch extra part URLs).
  const prevConcurrency = process.env.SF_UPLOAD_CONCURRENCY
  process.env.SF_UPLOAD_CONCURRENCY = '1'
  const chunkSize = 8
  const content = webcrypto.getRandomValues(new Uint8Array(12)) // 2 parts: 8, 4
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))

  const parts = []
  let refreshCount = 0
  let part1Attempts = 0
  let finalizeBody = null

  const originalFetch = globalThis.fetch
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.toString()

    if (url === `${API}/api/files/create-upload-session`) {
      return jsonResponse(200, {
        uploadKind: 'large',
        fileId: FILE_ID,
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
      // First attempt at part 1 fails with a transient 503; the retry succeeds.
      if (partNumber === 1) {
        part1Attempts += 1
        if (part1Attempts === 1) {
          return jsonResponse(503, { code: 'service_unavailable' })
        }
      }
      parts.push({
        partNumber,
        sha1: init.headers['X-Bz-Content-Sha1'],
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
        name: 'Secret.pdf',
        path,
        size: content.length,
      }),
    )
  } finally {
    globalThis.fetch = originalFetch
    if (prevConcurrency === undefined) delete process.env.SF_UPLOAD_CONCURRENCY
    else process.env.SF_UPLOAD_CONCURRENCY = prevConcurrency
  }

  // Part 1 was attempted twice (503 then 200); a fresh part URL was fetched for
  // the retry; both parts ultimately landed in order and the upload finalized.
  assert.equal(part1Attempts, 2)
  assert.equal(refreshCount, 1)
  assert.deepEqual(
    parts.map((p) => p.partNumber),
    [1, 2],
  )
  assert.equal(finalizeBody.fileId, FILE_ID)
})

test('direct push: presigned PUT, no Authorization, no b2FileId at finalize', async () => {
  const content = webcrypto.getRandomValues(new Uint8Array(64)) // <= chunkSize -> direct
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))

  let createBody = null
  let putBody = null
  let putMethod = null
  let putHeaders = null
  let finalizeBody = null

  const originalFetch = globalThis.fetch
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === `${API}/api/files/create-upload-session`) {
      createBody = JSON.parse(init.body)
      // No authToken and no storagePath: this is the live direct-branch shape
      // since web b52b4c8 (PR #726). The old fixture supplied both, which is
      // exactly why the suite stayed green while every real <= 5 MiB upload
      // threw 'Direct upload session is missing credentials.'
      return jsonResponse(200, {
        uploadKind: 'direct',
        fileId: DIRECT_FILE_ID,
        uploadUrl: 'https://b2.test/direct',
        chunkSize: 5 * 1024 * 1024,
        contentType: 'application/octet-stream',
        proofKey: PROOF_KEY,
      })
    }
    if (url === 'https://b2.test/direct') {
      putBody = new Uint8Array(init.body)
      putMethod = init.method
      putHeaders = init.headers
      // A presigned S3 PUT answers with an ETag header and an empty body --
      // no JSON, and in particular no fileId. Returning one here would let a
      // client that still reads body.fileId pass.
      return jsonResponse(200, {})
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

  // The wire contract of the direct path. None of this was asserted before,
  // which is how the POST/b2_upload_file shape survived the server's move to a
  // presigned PUT.
  const putSha1 = sha1HexOf(putBody)
  assert.equal(putMethod, 'PUT')
  assert.equal(putHeaders.Authorization, undefined)
  assert.deepEqual(
    Object.keys(putHeaders).filter((k) => k.toLowerCase().startsWith('x-bz-')),
    [],
    'presigned PUT is signed for host only; X-Bz-* headers are not signed',
  )
  assert.deepEqual(
    Object.keys(putHeaders).map((k) => k.toLowerCase()),
    ['content-type'],
    'Content-Type is the only header the presigned PUT may carry',
  )

  assert.equal(createBody.cipherVersion, 3)
  const { plaintext, header } = await referenceDecrypt({
    stored: putBody,
    rootKey,
    cskWrapped: createBody.csk_wrapped,
    cskIv: createBody.csk_iv,
  })
  assert.deepEqual(plaintext, content)
  assert.deepEqual(header.fileId, uuidBytes(DIRECT_FILE_ID), 'header file_id is the row id')
  assert.equal(finalizeBody.proof, independentV3Proof(PROOF_KEY, putBody))

  // A presigned PUT returns an ETag, not a Backblaze file id. Forwarding it
  // would be persisted verbatim into files.b2_file_id; the server HEADs the
  // stored object for the real one instead.
  assert.ok(
    !('b2FileId' in finalizeBody),
    'direct finalize must send no b2FileId',
  )
  assert.deepEqual(finalizeBody.partSha1Array, [putSha1])
  assert.equal(finalizeBody.ciphertextHash, putSha1) // single part
})
