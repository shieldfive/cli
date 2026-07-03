// ShieldFive CLI — upload: create-session -> chunk-encrypt -> Backblaze PUT ->
// finalize. Ported from the apps (mobile cloudApi.ts + syncService.ts).
//
// Two paths, chosen by the server:
//   direct  — a single-chunk file (<= chunkSize). One b2_upload_file POST.
//   large   — a multipart file (> chunkSize). b2_upload_part per chunk, then
//             b2_finish_large_file (server-side) at finalize.
//
// Chunks are read from disk one at a time (never the whole file into memory),
// so a multi-gigabyte upload holds at most one chunk (~5 MiB) resident.

import { open } from 'node:fs/promises'

import {
  bytesToBase64,
  encryptChunkWithDigest,
  encryptMetadataV4,
  generateNoncePrefixB64,
  generateRandomKeyB64,
  getCiphertextHashFromParts,
  hashMetadataV4,
  wrapKeyB64,
} from './uploadCrypto.mjs'

const CREATE_SESSION_PATH = '/api/files/create-upload-session'
const COMPLETE_PATH = '/api/files/complete-upload'
const PART_URL_PATH = '/api/files/upload-part-url'
const CHUNK_SIZE = 5 * 1024 * 1024

// Read a file in fixed-size chunks without holding it all in memory. Each yield
// is an independent copy (the read buffer is reused), so the caller may retain
// or transform a chunk across the next read safely.
export async function* readFileChunks(path, chunkSize) {
  const handle = await open(path, 'r')
  try {
    const buffer = Buffer.allocUnsafe(chunkSize)
    for (;;) {
      // Fill up to chunkSize across as many reads as it takes, so every chunk
      // but the last is exactly chunkSize. A single fs.read may return short
      // (FUSE/network mounts, signals) — if a non-final part were short, its
      // ciphertext length would desync the multipart proof and part manifest.
      let filled = 0
      while (filled < chunkSize) {
        const { bytesRead } = await handle.read(
          buffer,
          filled,
          chunkSize - filled,
          null,
        )
        if (bytesRead === 0) break // EOF
        filled += bytesRead
      }
      if (filled === 0) break
      yield new Uint8Array(buffer.subarray(0, filled))
      if (filled < chunkSize) break // last (short) chunk
    }
  } finally {
    await handle.close()
  }
}

export async function createUploadSession({
  apiBaseUrl,
  accessToken,
  rootKey,
  name,
  size,
}) {
  const rootKeyB64 = bytesToBase64(rootKey)
  const nameEnvelope = await encryptMetadataV4(name, rootKeyB64)
  const csk = generateRandomKeyB64()
  const cskEnvelope = wrapKeyB64({ wrappingKeyB64: rootKeyB64, keyToWrapB64: csk })
  const noncePrefix = generateNoncePrefixB64()

  const res = await fetch(new URL(CREATE_SESSION_PATH, apiBaseUrl), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name_encrypted: JSON.stringify(nameEnvelope),
      nameHash: hashMetadataV4(name.toLowerCase(), rootKeyB64),
      csk_wrapped: cskEnvelope.wrapped,
      csk_iv: cskEnvelope.iv,
      cipher_nonce_prefix: noncePrefix,
      sizeBytes: size,
      chunkSize: CHUNK_SIZE,
      folderId: null,
      contentType: 'application/octet-stream',
      thumbnail_ciphertext_b64: null,
      thumbnail_nonce_prefix: null,
    }),
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(
      `create-upload-session failed (HTTP ${res.status}): ${JSON.stringify(body)}`,
    )
  }
  return { session: body, csk, noncePrefix }
}

// Direct upload: b2_upload_file. Returns the storage file id the server patches
// into the row before verifying the proof.
async function putDirectToBackblaze({ session, ciphertext, sha1 }) {
  const res = await fetch(session.uploadUrl, {
    method: 'POST', // Backblaze b2_upload_file is a POST
    headers: {
      Authorization: session.authToken,
      'X-Bz-File-Name': encodeURIComponent(session.storagePath),
      'X-Bz-Content-Sha1': sha1,
      'Content-Type': 'application/octet-stream',
    },
    body: ciphertext,
  })
  if (!res.ok) {
    throw new Error(
      `Backblaze upload failed (HTTP ${res.status}): ${await res.text().catch(() => '')}`,
    )
  }
  const body = await res.json().catch(() => ({}))
  if (!body.fileId) {
    throw new Error(`Backblaze response missing fileId: ${JSON.stringify(body)}`)
  }
  return body.fileId
}

// Ask the server for a fresh b2_upload_part URL + token when the current one
// expires (Backblaze part tokens are short-lived and single-host).
async function refreshUploadPartUrl({ apiBaseUrl, accessToken, fileId }) {
  const res = await fetch(new URL(PART_URL_PATH, apiBaseUrl), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ fileId }),
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok || !body.uploadUrl || !body.authToken) {
    throw new Error(
      `upload-part-url failed (HTTP ${res.status}): ${JSON.stringify(body)}`,
    )
  }
  return { uploadUrl: body.uploadUrl, authToken: body.authToken }
}

// One b2_upload_part POST. On an expired token (401/403) refresh the part URL
// once and retry, mirroring uploadMultipartCiphertextPart in the apps. Returns
// the (possibly refreshed) url/token so the caller reuses them for the next part.
async function putPartToBackblaze({
  apiBaseUrl,
  accessToken,
  fileId,
  uploadUrl,
  authToken,
  partNumber,
  ciphertext,
  sha1,
}) {
  const attempt = (url, token) =>
    fetch(url, {
      method: 'POST', // Backblaze b2_upload_part is a POST
      headers: {
        Authorization: token,
        'X-Bz-Part-Number': String(partNumber),
        'X-Bz-Content-Sha1': sha1,
        'Content-Type': 'application/octet-stream',
      },
      body: ciphertext,
    })

  let url = uploadUrl
  let token = authToken
  let res = await attempt(url, token)

  if (res.status === 401 || res.status === 403) {
    const refreshed = await refreshUploadPartUrl({ apiBaseUrl, accessToken, fileId })
    url = refreshed.uploadUrl
    token = refreshed.authToken
    res = await attempt(url, token)
  }

  if (!res.ok) {
    throw new Error(
      `Backblaze part ${partNumber} upload failed (HTTP ${res.status}): ` +
        `${await res.text().catch(() => '')}`,
    )
  }
  return { uploadUrl: url, authToken: token }
}

async function finalizeUpload({
  apiBaseUrl,
  accessToken,
  fileId,
  b2FileId,
  partSha1Array,
  proof,
  ciphertextHash,
}) {
  const res = await fetch(new URL(COMPLETE_PATH, apiBaseUrl), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ fileId, b2FileId, partSha1Array, proof, ciphertextHash }),
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(
      `complete-upload failed (HTTP ${res.status}): ${JSON.stringify(body)}`,
    )
  }
  return body
}

// Single-chunk file: encrypt the one chunk (AES-GCM, suite 0x01) + SHA-1 +
// proof, PUT it, finalize. b2FileId is the id Backblaze returns from the PUT.
async function uploadDirect({ apiBaseUrl, accessToken, session, csk, noncePrefix, path }) {
  const chunkSize = session.chunkSize ?? CHUNK_SIZE
  let plaintext = null
  for await (const chunk of readFileChunks(path, chunkSize)) {
    if (plaintext !== null) {
      throw new Error('Direct upload session is larger than a single chunk.')
    }
    plaintext = chunk
  }
  if (plaintext === null) plaintext = new Uint8Array(0)

  const { ciphertext, sha1Hex, proofHex } = await encryptChunkWithDigest({
    cskB64: csk,
    noncePrefixB64: noncePrefix,
    chunkIndex: 0,
    plaintext,
    proofKeyHex: session.proofKey,
    chunkSize,
  })

  const b2FileId = await putDirectToBackblaze({ session, ciphertext, sha1: sha1Hex })

  return finalizeUpload({
    apiBaseUrl,
    accessToken,
    fileId: session.fileId,
    b2FileId,
    partSha1Array: [sha1Hex],
    proof: proofHex,
    ciphertextHash: sha1Hex,
  })
}

// Multipart file: stream each chunk, encrypt (per-chunk nonce via chunkIndex),
// b2_upload_part, collect part SHA-1s. The upload proof is computed from the
// FIRST chunk only — the server re-derives it from the first chunkSize+tag
// bytes of the stored object, which is exactly part 1. b2FileId is the
// large-file id from the session; the server calls b2_finish_large_file with
// the ordered part hashes at finalize.
async function uploadMultipart({ apiBaseUrl, accessToken, session, csk, noncePrefix, path }) {
  if (!session.b2FileId) {
    throw new Error('Multipart upload session is missing storage id (b2FileId).')
  }
  const chunkSize = session.chunkSize ?? CHUNK_SIZE

  let uploadUrl = session.uploadUrl
  let authToken = session.authToken
  const partSha1Array = []
  let proof
  let chunkIndex = 0

  for await (const plaintext of readFileChunks(path, chunkSize)) {
    const encrypted = await encryptChunkWithDigest({
      cskB64: csk,
      noncePrefixB64: noncePrefix,
      chunkIndex,
      plaintext,
      // Only the first chunk carries the proof; the server verifies over part 1.
      proofKeyHex: chunkIndex === 0 ? session.proofKey : undefined,
      chunkSize: chunkIndex === 0 ? chunkSize : undefined,
    })
    if (chunkIndex === 0) proof = encrypted.proofHex

    const updated = await putPartToBackblaze({
      apiBaseUrl,
      accessToken,
      fileId: session.fileId,
      uploadUrl,
      authToken,
      partNumber: chunkIndex + 1, // Backblaze parts are 1-based
      ciphertext: encrypted.ciphertext,
      sha1: encrypted.sha1Hex,
    })
    uploadUrl = updated.uploadUrl
    authToken = updated.authToken
    partSha1Array.push(encrypted.sha1Hex)
    chunkIndex += 1
  }

  if (!partSha1Array.length || !proof) {
    throw new Error('Multipart upload produced no parts.')
  }

  const ciphertextHash = await getCiphertextHashFromParts(partSha1Array)

  return finalizeUpload({
    apiBaseUrl,
    accessToken,
    fileId: session.fileId,
    b2FileId: session.b2FileId,
    partSha1Array,
    proof,
    ciphertextHash,
  })
}

export async function uploadFile({ apiBaseUrl, accessToken, rootKey, name, path, size }) {
  const { session, csk, noncePrefix } = await createUploadSession({
    apiBaseUrl,
    accessToken,
    rootKey,
    name,
    size,
  })

  if (session.uploadKind === 'direct') {
    if (!session.uploadUrl || !session.authToken || !session.storagePath) {
      throw new Error('Direct upload session is missing credentials.')
    }
    await uploadDirect({ apiBaseUrl, accessToken, session, csk, noncePrefix, path })
  } else if (session.uploadKind === 'large') {
    if (!session.uploadUrl || !session.authToken) {
      throw new Error('Multipart upload session is missing credentials.')
    }
    await uploadMultipart({ apiBaseUrl, accessToken, session, csk, noncePrefix, path })
  } else {
    throw new Error(`Unknown uploadKind "${session.uploadKind}" for "${name}".`)
  }

  return { fileId: session.fileId }
}
