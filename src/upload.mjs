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

// Backblaze documents retrying b2_upload_part on 5xx / network failures, and a
// part upload is idempotent by (part number, SHA-1) — retrying overwrites the
// same part. Bound the retries and back off so one transient blip does not
// abort a whole multi-gigabyte upload.
const MAX_PART_ATTEMPTS = 3
const PART_RETRY_BASE_DELAY_MS = 250

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const partRetryDelayMs = (attempt) =>
  PART_RETRY_BASE_DELAY_MS * 2 ** (attempt - 1) // 250ms, 500ms, ...

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
// and retry immediately, mirroring uploadMultipartCiphertextPart in the apps.
// On a transient failure (5xx / 408 / 429 / network error) refresh the part URL
// and retry with exponential backoff, up to MAX_PART_ATTEMPTS, so a single blip
// does not abort the whole upload. Returns the (possibly refreshed) url/token so
// the caller reuses them for the next part.
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
  let lastError

  for (let tries = 1; tries <= MAX_PART_ATTEMPTS; tries += 1) {
    let res
    try {
      res = await attempt(url, token)
    } catch (err) {
      // Network/transport failure (reset, timeout, DNS). Retry with a fresh
      // part URL after a backoff.
      lastError = err
      if (tries === MAX_PART_ATTEMPTS) break
      await sleep(partRetryDelayMs(tries))
      ;({ uploadUrl: url, authToken: token } = await refreshUploadPartUrl({
        apiBaseUrl,
        accessToken,
        fileId,
      }))
      continue
    }

    if (res.status === 401 || res.status === 403) {
      // Expected token rotation, not a transient failure: refresh and retry
      // immediately without consuming a backoff slot.
      const refreshed = await refreshUploadPartUrl({ apiBaseUrl, accessToken, fileId })
      url = refreshed.uploadUrl
      token = refreshed.authToken
      res = await attempt(url, token)
    }

    if (res.ok) return { uploadUrl: url, authToken: token }

    lastError = new Error(
      `Backblaze part ${partNumber} upload failed (HTTP ${res.status}): ` +
        `${await res.text().catch(() => '')}`,
    )

    // 5xx / 408 / 429 are worth retrying; other 4xx (after the auth refresh
    // above) are terminal.
    const retryable =
      res.status >= 500 || res.status === 429 || res.status === 408
    if (!retryable || tries === MAX_PART_ATTEMPTS) throw lastError

    await sleep(partRetryDelayMs(tries))
    ;({ uploadUrl: url, authToken: token } = await refreshUploadPartUrl({
      apiBaseUrl,
      accessToken,
      fileId,
    }))
  }

  throw lastError ?? new Error(`Backblaze part ${partNumber} upload failed`)
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
// Bounded concurrency for multipart part uploads. The serial version left the
// network idle during encrypt and the CPU idle during each PUT; uploading a few
// parts at once fills the pipe. Backblaze needs one upload URL per concurrent
// connection, so K concurrent parts draw K URLs from a small pool. Default 3;
// override with SF_UPLOAD_CONCURRENCY (clamped 1..6). SF_UPLOAD_CONCURRENCY=1
// reproduces the exact serial behaviour. Memory ceiling ≈ 2 * K * chunkSize
// (K plaintext chunks + K ciphertexts resident at once).
const DEFAULT_UPLOAD_CONCURRENCY = 3
const MAX_UPLOAD_CONCURRENCY = 6
function resolveUploadConcurrency() {
  const raw = Number.parseInt(process.env.SF_UPLOAD_CONCURRENCY ?? '', 10)
  if (Number.isInteger(raw) && raw >= 1) {
    return Math.min(raw, MAX_UPLOAD_CONCURRENCY)
  }
  return DEFAULT_UPLOAD_CONCURRENCY
}

async function uploadMultipart({ apiBaseUrl, accessToken, session, csk, noncePrefix, path }) {
  if (!session.b2FileId) {
    throw new Error('Multipart upload session is missing storage id (b2FileId).')
  }
  const chunkSize = session.chunkSize ?? CHUNK_SIZE
  const concurrency = resolveUploadConcurrency()

  // Part SHA-1s keyed by chunkIndex, NOT push order, so parts finishing out of
  // order under concurrency never scramble the manifest the server checks.
  const partSha1ByIndex = []
  let proof // computed from chunk 0 only (the server verifies the proof over part 1)
  let firstError = null

  // Pool of b2_upload_part URLs — one per concurrent connection. Seed with the
  // session URL, fetch more on demand up to `concurrency`, and return each after
  // a successful part so URLs are reused rather than re-fetched per part.
  // putPartToBackblaze already self-heals expired tokens and retries 5xx.
  const urlPool = [{ uploadUrl: session.uploadUrl, authToken: session.authToken }]
  const acquireUrl = async () =>
    urlPool.pop() ??
    (await refreshUploadPartUrl({ apiBaseUrl, accessToken, fileId: session.fileId }))

  const inFlight = new Set()
  const dispatch = (chunkIndex, plaintext) => {
    const run = (async () => {
      try {
        const encrypted = await encryptChunkWithDigest({
          cskB64: csk,
          noncePrefixB64: noncePrefix,
          chunkIndex,
          plaintext,
          proofKeyHex: chunkIndex === 0 ? session.proofKey : undefined,
          chunkSize: chunkIndex === 0 ? chunkSize : undefined,
        })
        if (chunkIndex === 0) proof = encrypted.proofHex

        const slot = await acquireUrl()
        const updated = await putPartToBackblaze({
          apiBaseUrl,
          accessToken,
          fileId: session.fileId,
          uploadUrl: slot.uploadUrl,
          authToken: slot.authToken,
          partNumber: chunkIndex + 1, // Backblaze parts are 1-based
          ciphertext: encrypted.ciphertext,
          sha1: encrypted.sha1Hex,
        })
        // Return the (possibly refreshed) URL for the next part to reuse. A URL
        // whose part failed is intentionally NOT returned (it may be bad).
        urlPool.push({ uploadUrl: updated.uploadUrl, authToken: updated.authToken })
        partSha1ByIndex[chunkIndex] = encrypted.sha1Hex
      } catch (err) {
        if (!firstError) firstError = err
      }
    })()
    inFlight.add(run)
    run.finally(() => inFlight.delete(run))
  }

  let chunkIndex = 0
  for await (const plaintext of readFileChunks(path, chunkSize)) {
    if (firstError) break
    // Backpressure: hold at most `concurrency` parts in flight. inFlight is
    // non-empty when this runs (size >= concurrency >= 1), so race never hangs.
    while (inFlight.size >= concurrency) {
      await Promise.race(inFlight)
      if (firstError) break
    }
    if (firstError) break
    dispatch(chunkIndex, plaintext)
    chunkIndex += 1
  }

  // Let every in-flight part settle before finalizing or surfacing the error.
  await Promise.allSettled(inFlight)
  if (firstError) throw firstError

  if (!chunkIndex || !proof) {
    throw new Error('Multipart upload produced no parts.')
  }
  // Dense, in chunk order; a gap means a part silently went missing.
  const partSha1Array = Array.from(
    { length: chunkIndex },
    (_value, index) => partSha1ByIndex[index],
  )
  if (partSha1Array.some((sha1) => typeof sha1 !== 'string')) {
    throw new Error('Multipart upload is missing a part.')
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
