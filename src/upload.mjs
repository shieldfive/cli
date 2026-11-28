// ShieldFive CLI — upload: create-session -> chunk-encrypt -> upload -> finalize.
// Ported from the apps (mobile cloudApi.ts + syncService.ts).
//
// The server selects a direct PUT, signed multipart PUTs, or native multipart.
// Chunks are read from disk one at a time (never the whole file into memory),
// so a multi-gigabyte upload holds at most a few chunks (~5 MiB each) resident.
//
// Format: cipher_version 3, the web's default (suite 0x03, v1 wire format; see
// uploadCrypto.mjs). Every storage part is one encrypted chunk frame; part 1
// also carries the header. The header's file_id is the row id the server
// assigned at create-upload-session, so the stored object is bound to its row.

import { constants as fsConstants } from 'node:fs'
import { open } from 'node:fs/promises'
import { createHash, webcrypto } from 'node:crypto'

import { Agent } from 'undici'
import { encryptNameV6 } from '@shieldfive/crypto/vault'
import { makeThumbnail, thumbnailFields } from './thumbnail.mjs'
import { MAX_RETRY_DELAY_MS, STORAGE_REQUEST_TIMEOUT_MS, networkRequest, readJson, resolveToken } from './network.mjs'

export { resolveToken } from './network.mjs'

import {
  base64ToBytes,
  bytesToBase64,
  CIPHER_VERSION_PQ,
  computeV3EmptyUploadProof,
  computeV3UploadProof,
  encryptPartsV3,
  generateRandomKeyB64,
  getCiphertextHashFromParts,
  hashMetadataV4,
  sha1Hex,
  uuidToBytes,
  V1_CHUNK_SIZE,
  vaultMlKemPublicKey,
  wrapKeyB64,
} from './uploadCrypto.mjs'

const CREATE_SESSION_PATH = '/api/files/create-upload-session'
const COMPLETE_PATH = '/api/files/complete-upload'
const NATIVE_UPLOAD_PATH = '/api/files/upload-native-target'
const PART_URL_PATH = '/api/files/upload-part-url'
const DELETE_PATH = '/api/files/delete'
const CAPABILITIES_PATH = '/api/files/upload-capabilities'

const MAX_PART_ATTEMPTS = 7
// Session creation and completion are each limited to 100 requests a minute.
const UPLOAD_RATE_WINDOW_MS = 60_000
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export const isRetryableStatus = (status) =>
  status === 408 || status === 429 || (status >= 500 && status <= 599)

export function retryDelayMs(attempt, retryAfterMs = 0) {
  return Math.min(MAX_RETRY_DELAY_MS, Math.max(retryAfterMs, Math.random() * Math.min(32_000, 1000 * 2 ** (attempt - 1))))
}

export function responseError(operation, res, body, { status = res.status, fallbackRetryAfterMs } = {}) {
  let guidance = ''
  if (body?.code === 'mfa_required') guidance = 'Two-factor verification is required.'
  if (status === 412) guidance = 'Acknowledge your recovery key in the web app before uploading.'
  if (status === 402 || body?.code === 'storage_limit_exceeded') guidance = 'Your vault storage limit was reached.'
  if (status === 401 && !guidance) guidance = 'Your sign-in expired or was revoked. Run `sf logout`, then `sf login`, and retry; files already saved are kept.'
  if (status === 409 && /maximum number of folders/i.test(body?.error ?? '')) guidance = 'Your vault reached its folder limit.'
  else if (status === 409 && body?.code === 'folderExists') guidance = 'A folder with that id already exists.'
  if (status === 413 && !guidance) guidance = 'This file exceeds the upload size limit.'
  const error = new Error(`${operation} failed (HTTP ${status})${guidance ? `. ${guidance}` : ''}`)
  error.status = status
  if (typeof body?.code === 'string') error.serverCode = body.code
  else if (status === 409 && /maximum number of folders/i.test(body?.error ?? '')) error.serverCode = 'folderLimitReached'
  error.retryAfterMs = fallbackRetryAfterMs
  const header = res.headers?.get('retry-after')
  if (header) {
    const delay = /^\d+$/.test(header) ? Number(header) * 1000 : Date.parse(header) - Date.now()
    if (Number.isFinite(delay)) error.retryAfterMs = Math.max(0, delay)
  }
  return error
}

// One API call with the bearer token. On HTTP 401 the token is refreshed once
// (when the caller supplied a refreshable getter) and the call is repeated; if
// that refresh fails, or the repeat is refused too, the 401 surfaces with its
// sign-in-again guidance. Other statuses are left to the caller.
async function apiRequest({ url, accessToken, body, operation, auth, timeoutMs, contentType = 'application/json' }) {
  const send = async (token) => networkRequest(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': contentType },
    redirect: 'error',
    body,
  }, operation, timeoutMs)
  const res = await send(await resolveToken(accessToken))
  if (res.status !== 401 || typeof accessToken !== 'function' || auth.refreshed) return res
  auth.refreshed = true
  let fresh
  try {
    fresh = await resolveToken(accessToken, { forceRefresh: true })
  } catch {
    return res
  }
  void res.body?.cancel().catch(() => {})
  return send(fresh)
}

async function withUploadRetry(send, onRetry, attempts = MAX_PART_ATTEMPTS, stopRetrying) {
  let refreshedAuth = false
  let lastStorageError
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await send(attempt)
    } catch (error) {
      if (error.storageFailure) lastStorageError = error
      else if (lastStorageError && error.uploadRetriesExhausted) {
        lastStorageError.message += `; ${error.message}`
        throw lastStorageError
      }
      const authRejected = error.storageAuthRejected && !refreshedAuth
      if (attempt >= attempts || error.uploadRetriesExhausted || stopRetrying?.(error) ||
          !(authRejected || error.uploadNetworkError || error.storageBusy || isRetryableStatus(error.status))) throw error
      refreshedAuth ||= authRejected
      const delay = authRejected ? Math.min(error.retryAfterMs ?? 0, MAX_RETRY_DELAY_MS) : retryDelayMs(attempt, error.retryAfterMs)
      const wait = delay >= 1000 ? ` in ${Math.ceil(delay / 1000)} s` : ''
      onRetry?.(`${error.message}, retrying${wait}`)
      if (delay > 0) await sleep(delay)
    }
  }
}

// Read a file in fixed-size chunks without holding it all in memory. Each yield
// is an independent copy (the read buffer is reused), so the caller may retain
// or transform a chunk across the next read safely.
//
// O_NOFOLLOW: callers list files with lstat and skip symlinks, but a regular
// file could be swapped for a symlink between that check and this open. With
// O_NOFOLLOW the open fails (ELOOP) instead of uploading whatever the link
// points at, possibly outside the folder being pushed. (Undefined on Windows,
// where it is simply not applied.)
const OPEN_READ_NOFOLLOW = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0)

export async function* readFileChunks(path, chunkSize) {
  const handle = await open(path, OPEN_READ_NOFOLLOW)
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

// A fresh UUIDv7 (RFC 9562): 48-bit ms timestamp, version 7, variant 10.
// The web app's newRowBoundId (utils/fileRowBinding.ts) builds the same shape;
// the server's create-upload-session takes it as clientUploadId.
export function newRowBoundId(now = Date.now()) {
  const bytes = webcrypto.getRandomValues(new Uint8Array(16))
  let ts = BigInt(now)
  for (let i = 5; i >= 0; i -= 1) {
    bytes[i] = Number(ts & 0xffn)
    ts >>= 8n
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

export async function createUploadSession({
  apiBaseUrl,
  accessToken,
  rootKey,
  name,
  size,
  rowId,
  onRetry,
  folderId = null,
  folderKey = null,
  thumbnail = null,
}) {
  const rootKeyB64 = bytesToBase64(rootKey)
  // The parent's key: the root key at the vault root, else the folder's own
  // key. The name is sealed under it and the envelope key wrapped by it,
  // exactly as the web uploader does for a file inside a folder. The name hash
  // is always keyed by the root key (web hashMetadataClient(name, rootKey)).
  const parentKey = folderKey ?? rootKey
  const parentKeyB64 = bytesToBase64(parentKey)
  // The client picks the row id (UUIDv7, sent as clientUploadId), so the very
  // first stored name is already the v6 envelope bound to that row. No v4
  // (row-unbound) name is ever written, even for an upload that fails before
  // finalize.
  const nameEnvelopeV6 = await encryptNameV6({ name, folderKey: parentKey, rowId })
  // For suite 0x03 this is the classical envelope key; csk_wrapped holds it
  // under the parent key.
  const csk = generateRandomKeyB64()
  const cskEnvelope = wrapKeyB64({ wrappingKeyB64: parentKeyB64, keyToWrapB64: csk })
  // Optional preview (JPEG bytes from thumbnail.mjs), encrypted under this
  // file's content key exactly as the web uploader does. Only ciphertext leaves.
  let thumb = null
  if (thumbnail?.length) {
    const cskBytes = base64ToBytes(csk)
    try {
      thumb = thumbnailFields(thumbnail, cskBytes)
    } finally {
      cskBytes.fill(0)
    }
  }

  // Replays of this row ID must carry the same encrypted name and wrapped key.
  const payload = JSON.stringify({
    clientUploadId: rowId,
    // Use file-scoped native B2 credentials for multipart. The regional
    // S3 endpoint can be unreachable even when B2's upload pods work.
    vaultS3Multipart: false,
    name_encrypted: JSON.stringify(nameEnvelopeV6),
    nameHash: hashMetadataV4(name.toLowerCase(), rootKeyB64),
    csk_wrapped: cskEnvelope.wrapped,
    csk_iv: cskEnvelope.iv,
    cipherVersion: CIPHER_VERSION_PQ,
    sizeBytes: size,
    folderId,
    contentType: 'application/octet-stream',
    thumbnail_ciphertext_b64: thumb?.thumbnail_ciphertext_b64 ?? null,
    thumbnail_nonce_prefix: thumb?.thumbnail_nonce_prefix ?? null,
  })
  // Safe to repeat: the server treats a replay of the same clientUploadId with
  // the same name and wrapped key as the same session.
  const auth = { refreshed: false }
  const body = await withUploadRetry(async () => {
    const operation = 'Create upload session'
    const res = await apiRequest({
      url: new URL(CREATE_SESSION_PATH, apiBaseUrl), accessToken, body: payload, operation, auth,
    })
    const json = await readJson(res, operation)
    if (!res.ok) throw responseError(operation, res, json, {
      fallbackRetryAfterMs: res.status === 429 ? UPLOAD_RATE_WINDOW_MS : undefined,
    })
    return json
  }, onRetry)
  return { session: body, csk, nameEncryptedV6: JSON.stringify(nameEnvelopeV6) }
}

// Signed URLs name a single object or part. Keep the ciphertext unchanged
// across attempts and obtain replacement credentials after a refused send.
async function refreshUploadUrl(context, metadata, onRetry) {
  try {
    return await withUploadRetry(() => requestUploadUrl(context, metadata), onRetry, 3)
  } catch (err) {
    err.uploadRetriesExhausted = true
    throw err
  }
}

async function requestUploadUrl({ apiBaseUrl, accessToken, fileId, auth }, metadata) {
  const operation = 'Get upload credentials'
  const res = await apiRequest({
    url: new URL(PART_URL_PATH, apiBaseUrl),
    accessToken,
    body: JSON.stringify({ fileId, ...metadata }),
    operation,
    auth,
  })
  const body = await readJson(res, operation)
  if (!res.ok) throw responseError(operation, res, body)
  if (!body?.uploadUrl || (metadata ? body.uploadKind !== metadata.kind : !body.authToken)) {
    throw new Error('Get upload credentials failed (incomplete response).')
  }
  return body
}

const STORAGE_ATTEMPTS = 3
const CONSECUTIVE_STORAGE_FAILURES = 3

export function storageFailureLimit() {
  let consecutive = 0
  return {
    record(error) {
      if (!error) consecutive = 0
      else if (error.storageFailure || error.code === 'storage_failure') {
        consecutive += 1
        if (consecutive >= CONSECUTIVE_STORAGE_FAILURES) {
          return new Error(`Stopping after ${consecutive} consecutive storage failures. ${error.message}`)
        }
      }
      return null
    },
  }
}
const STORAGE_CODES = new Set([
  'AccessDenied', 'ExpiredToken', 'InvalidAccessKeyId', 'RequestExpired',
  'RequestTimeTooSkewed', 'SignatureDoesNotMatch', 'AuthorizationHeaderMalformed',
  'NoSuchBucket', 'NoSuchUpload', 'ServiceUnavailable', 'SlowDown',
  'bad_auth_token', 'expired_auth_token', 'too_busy', 'unauthorized',
])

const storageDispatcher = new Agent({
  connect: process.env.SF_STORAGE_IPV4 === '1'
    ? { family: 4 }
    : { autoSelectFamily: true, autoSelectFamilyAttemptTimeout: 250 },
})

async function sendStorage(url, init, operation) {
  const host = new URL(url).host
  let res
  try {
    res = await networkRequest(url, { ...init, redirect: 'error', dispatcher: storageDispatcher }, operation, STORAGE_REQUEST_TIMEOUT_MS)
  } catch (err) {
    err.storageFailure = true
    throw err
  }
  if (res.ok) return res
  const body = await res.text().catch(() => '')
  const candidate = /<Code>([A-Za-z_]+)<\/Code>|"code"\s*:\s*"([A-Za-z_]+)"/.exec(body)
  const code = candidate?.[1] ?? candidate?.[2]
  const error = responseError(operation, res)
  error.message += ` at ${host}`
  if (STORAGE_CODES.has(code)) error.message += ` (${code}${code === 'RequestTimeTooSkewed' ? ', clock skew' : ''})`
  error.storageFailure = true
  error.host = host
  error.storageAuthRejected = res.status === 401 || res.status === 403
  error.storageBusy = code === 'too_busy' || code === 'ServiceUnavailable' || code === 'SlowDown'
  throw error
}

function canFallback(error) {
  return error.storageFailure && ['ETIMEDOUT', 'ECONNRESET', 'EPIPE'].includes(error.networkCode)
}

async function timeUpload(phase, run) {
  if (process.env.SF_UPLOAD_TIMINGS !== '1') return run()
  const started = performance.now()
  try {
    return await run()
  } finally {
    process.stderr.write(`upload timing ${phase} ${Math.round(performance.now() - started)} ms\n`)
  }
}

async function postNative({ apiBaseUrl, accessToken, fileId, ciphertext, sha1, onRetry, beforeStorage, directUpload }) {
  const operation = 'Get native upload target'
  const auth = { refreshed: false }
  const { objectKey, stagedFileId } = await withUploadRetry(async () => {
    try {
      const cached = directUpload.target
      const reuse = cached?.apiBaseUrl === String(apiBaseUrl) && cached.expiresAt > Date.now()
      const target = await timeUpload('native_target', async () => {
        const res = await apiRequest({
          url: new URL(NATIVE_UPLOAD_PATH, apiBaseUrl), accessToken,
          body: JSON.stringify({ fileId, sha1, ...(reuse && { reuseUploadTarget: true }) }), operation, auth,
        })
        const target = await readJson(res, operation)
        if (!res.ok) throw responseError(operation, res, target)
        return target
      })
      const credentials = reuse && target?.uploadUrl === undefined && target?.authorizationToken === undefined
        ? cached
        : target
      const url = URL.canParse(credentials?.uploadUrl ?? '') ? new URL(credentials.uploadUrl) : null
      if (!url || url.protocol !== 'https:' || url.port || url.username || url.password ||
          !/^pod-[a-z0-9-]+\.backblaze(?:b2)?\.com$/.test(url.hostname) ||
          !/^\/b2api\/v[1-4]\/b2_upload_file(?:\/|$)/.test(url.pathname) ||
          typeof credentials.authorizationToken !== 'string' || !credentials.authorizationToken ||
          typeof target?.objectKey !== 'string' || !target.objectKey) {
        throw new Error('Native direct upload target is invalid.')
      }
      await beforeStorage?.(url)
      const receipt = await timeUpload('native_pod', async () => {
        try {
          const uploaded = await sendStorage(url, {
            method: 'POST',
            headers: {
              Authorization: credentials.authorizationToken,
              'X-Bz-File-Name': encodeURIComponent(target.objectKey),
              'X-Bz-Content-Sha1': sha1,
              'Content-Type': 'application/octet-stream',
              'Content-Length': String(ciphertext.byteLength),
            },
            body: ciphertext,
          }, 'Native direct upload')
          return await readJson(uploaded, 'Native direct upload')
        } catch (error) {
          delete directUpload.target
          if (error.status === 503 || error.status === 429 || error.storageBusy) directUpload.onCongestion?.()
          throw error
        }
      })
      if (typeof receipt?.fileId !== 'string' ||
          !/^[a-zA-Z0-9_-]{1,200}$/.test(receipt.fileId)) {
        throw new Error('Native direct upload returned an invalid version ID.')
      }
      if (credentials !== cached && directUpload.reuseTargets) {
        directUpload.target = {
          apiBaseUrl: String(apiBaseUrl),
          uploadUrl: credentials.uploadUrl,
          authorizationToken: credentials.authorizationToken,
          expiresAt: Date.now() + 23 * 60 * 60_000,
        }
      }
      return { objectKey: target.objectKey, stagedFileId: receipt.fileId }
    } catch (err) {
      err.storageFailure = true
      throw err
    }
  }, onRetry, STORAGE_ATTEMPTS)

  // Retry promotion with the same staged version. A lost response can arrive
  // after the server already copied and deleted that version.
  await withUploadRetry(() => timeUpload('native_promote', async () => {
    const operation = 'Promote native upload'
    try {
      const promoted = await apiRequest({
        url: new URL(NATIVE_UPLOAD_PATH, apiBaseUrl), accessToken,
        body: JSON.stringify({ fileId, objectKey, stagedFileId }),
        operation, auth,
      })
      if (!promoted.ok) throw responseError(operation, promoted, await readJson(promoted, operation))
      const timing = promoted.headers.get('server-timing')
      if (process.env.SF_UPLOAD_TIMINGS === '1' && timing) {
        process.stderr.write(`upload timing native_server ${timing}\n`)
      }
    } catch (error) {
      error.storageFailure = true
      if (error.status === 503 || error.status === 429) directUpload.onCongestion?.()
      throw error
    }
  }), onRetry, STORAGE_ATTEMPTS)
}

async function putDirectPresigned({ context, session, ciphertext, onRetry, beforeStorage, directUpload }) {
  await withUploadRetry(async (attempt) => {
    const credentials = attempt === 1
      ? session
      : await refreshUploadUrl(context, { kind: 'direct' }, onRetry)
    await beforeStorage?.(new URL(credentials.uploadUrl))
    const res = await sendStorage(credentials.uploadUrl, {
      method: 'PUT',
      headers: {
        'Content-Type': session.contentType || 'application/octet-stream',
        'Content-Length': String(ciphertext.byteLength),
      },
      body: ciphertext,
    }, 'Direct upload')
    void res.body?.cancel().catch(() => {})
  }, onRetry, STORAGE_ATTEMPTS, directUpload.mode === 's3' ? undefined : canFallback)
}

async function finalizeUpload({
  apiBaseUrl,
  accessToken,
  fileId,
  b2FileId,
  partSha1Array,
  partETags,
  onRetry,
  proof,
  ciphertextHash,
  nameEncryptedV6,
}) {
  const operation = 'Complete upload'
  const auth = { refreshed: false }
  let outcomeUnknown = false
  try {
    return await withUploadRetry(async () => {
      // Reuse the manifest and row if storage completed before the reply was lost.
      try {
        const res = await apiRequest({
          url: new URL(COMPLETE_PATH, apiBaseUrl),
          accessToken,
          body: JSON.stringify({ fileId, b2FileId, partSha1Array, partETags, proof, ciphertextHash, nameEncryptedV6 }),
          operation,
          auth,
        })
        const body = await readJson(res, operation)
        if (!res.ok) throw responseError(operation, res, body, {
          fallbackRetryAfterMs: res.status === 429 ? UPLOAD_RATE_WINDOW_MS : undefined,
        })
        return body
      } catch (error) {
        outcomeUnknown ||= error.uploadNetworkError === true || error.status >= 500
        throw error
      }
    }, onRetry)
  } catch (error) {
    if (outcomeUnknown) error.finalizeOutcomeUnknown = true
    throw error
  }
}

// Single-chunk file: one part (header || frame_0), SHA-1 + proof, PUT it at
// the presigned URL, finalize. No b2FileId is sent -- the server HEADs the
// stored object and derives the storage id itself.
async function uploadDirect({ apiBaseUrl, accessToken, session, parts, nameEncryptedV6, onRetry, onPartUploaded, beforeStorage, directUpload, empty = false }) {
  let ciphertext = null
  for await (const part of parts) {
    if (ciphertext !== null) {
      throw new Error('Direct upload session is larger than a single chunk.')
    }
    ciphertext = part
  }
  if (ciphertext === null) throw new Error('Direct upload produced no ciphertext.')
  // For a 0-byte file part 1 is the header alone, and the proof covers it:
  // the server's empty-file contract is HMAC(proofKey, [3][3] || header).
  const sha1 = await sha1Hex(ciphertext)
  const proof = empty
    ? computeV3EmptyUploadProof({ proofKeyHex: session.proofKey, header: ciphertext })
    : await computeV3UploadProof({ proofKeyHex: session.proofKey, part0: ciphertext })

  if (directUpload.mode !== 'native') {
    try {
      await putDirectPresigned({
        context: { apiBaseUrl, accessToken, fileId: session.fileId, auth: { refreshed: false } },
        session, ciphertext, onRetry, beforeStorage, directUpload,
      })
    } catch (err) {
      if (directUpload.mode === 's3' || !canFallback(err)) throw err
      onRetry?.(`${err.message}; trying a direct native upload`)
      try {
        await postNative({ apiBaseUrl, accessToken, fileId: session.fileId, ciphertext, sha1, onRetry, beforeStorage, directUpload })
      } catch (nativeError) {
        nativeError.message = `${err.message}; ${nativeError.message}`
        throw nativeError
      }
      directUpload.mode = 'native'
    }
  } else {
    await postNative({ apiBaseUrl, accessToken, fileId: session.fileId, ciphertext, sha1, onRetry, beforeStorage, directUpload })
  }
  onPartUploaded?.()

  // b2FileId is deliberately omitted. JSON.stringify drops the undefined key,
  // so complete-upload/finalize.ts takes its "no client-supplied id" branch and
  // HEADs the object for the real version id. Forwarding the PUT's ETag instead
  // would be persisted verbatim into files.b2_file_id with no format check --
  // a bogus delete handle, permanently, which is worse than failing.
  return timeUpload('finalize', () => finalizeUpload({
    apiBaseUrl,
    accessToken,
    fileId: session.fileId,
    partSha1Array: [sha1],
    onRetry,
    proof,
    ciphertextHash: sha1,
    nameEncryptedV6,
  }))
}

// Each concurrent upload holds one encrypted frame and, for the native
// transport, leases its own upload URL until the request succeeds.
const DEFAULT_UPLOAD_CONCURRENCY = 3
const MAX_UPLOAD_CONCURRENCY = 6
function resolveUploadConcurrency() {
  const raw = Number.parseInt(process.env.SF_UPLOAD_CONCURRENCY ?? '', 10)
  if (Number.isInteger(raw) && raw >= 1) {
    return Math.min(raw, MAX_UPLOAD_CONCURRENCY)
  }
  return DEFAULT_UPLOAD_CONCURRENCY
}

async function uploadMultipart({ apiBaseUrl, accessToken, session, parts, nameEncryptedV6, onRetry, onPartUploaded, beforeStorage }) {
  if (!session.b2FileId) {
    throw new Error('Multipart upload session is missing its storage ID.')
  }
  const concurrency = resolveUploadConcurrency()

  // Part SHA-1s keyed by chunkIndex, NOT push order, so parts finishing out of
  // order under concurrency never scramble the manifest the server checks.
  const partSha1ByIndex = []
  let proof // computed from chunk 0 only (the server verifies the proof over part 1)
  let firstError = null

  const signed = session.uploadKind === 's3-multipart'
  const partETags = signed ? [] : undefined
  // One token refresh per upload, shared by every part's credential request.
  const context = { apiBaseUrl, accessToken, fileId: session.fileId, auth: { refreshed: false } }
  const urlPool = [session]

  const inFlight = new Set()
  const dispatch = (chunkIndex, ciphertext) => {
    const run = (async () => {
      try {
        const sha1 = await sha1Hex(ciphertext)
        if (chunkIndex === 0) {
          proof = await computeV3UploadProof({ proofKeyHex: session.proofKey, part0: ciphertext })
        }

        const partNumber = chunkIndex + 1
        const operation = `Upload part ${partNumber}`
        if (signed) {
          const checksum = createHash('md5').update(ciphertext).digest('hex')
          const etag = await withUploadRetry(async () => {
            const { uploadUrl } = await refreshUploadUrl(context, {
              kind: 's3-multipart', partNumber, contentLength: ciphertext.byteLength,
            }, onRetry)
            await beforeStorage?.(new URL(uploadUrl))
            const res = await sendStorage(uploadUrl, {
              method: 'PUT',
              headers: { 'Content-Length': String(ciphertext.byteLength) },
              body: ciphertext,
            }, operation)
            const tag = res.headers.get('etag')
            void res.body?.cancel().catch(() => {})
            if (tag !== checksum && tag !== `"${checksum}"`) {
              throw Object.assign(new Error(`${operation} returned an invalid checksum at ${new URL(uploadUrl).host}`), { storageFailure: true })
            }
            return tag
          }, onRetry, STORAGE_ATTEMPTS)
          partETags[chunkIndex] = etag
        } else {
          const slot = urlPool.pop()
          const credentials = await withUploadRetry(async (attempt) => {
            const current = (attempt === 1 && slot) || await refreshUploadUrl(context, undefined, onRetry)
            await beforeStorage?.(new URL(current.uploadUrl))
            const res = await sendStorage(current.uploadUrl, {
              method: 'POST',
              headers: {
                Authorization: current.authToken,
                'X-Bz-Part-Number': String(partNumber),
                'X-Bz-Content-Sha1': sha1,
                'Content-Type': 'application/octet-stream',
              },
              body: ciphertext,
            }, operation)
            void res.body?.cancel().catch(() => {})
            return current
          }, onRetry, STORAGE_ATTEMPTS)
          urlPool.push(credentials)
        }
        partSha1ByIndex[chunkIndex] = sha1
        onPartUploaded?.()
      } catch (err) {
        if (!firstError) firstError = err
      }
    })()
    inFlight.add(run)
    run.finally(() => inFlight.delete(run))
  }

  let chunkIndex = 0
  try {
    for await (const ciphertext of parts) {
      while (inFlight.size >= concurrency && !firstError) await Promise.race(inFlight)
      if (firstError) break
      dispatch(chunkIndex, ciphertext)
      chunkIndex += 1
    }
  } finally {
    await Promise.allSettled(inFlight)
  }
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
    partETags,
    onRetry,
    proof,
    ciphertextHash,
    nameEncryptedV6,
  })
}

// Best-effort cancel of a session that will never finalize. The pending row
// otherwise holds quota (and, for multipart, an unfinished storage
// upload) until the server's stale-upload reaper gets to it. POST
// /api/files/delete with the row id is what the web app's cancel path uses:
// for a non-ready row it cancels the large file and drops the metadata. Never
// throws; a failure here must not hide the error that caused it.
export async function deleteUpload({ apiBaseUrl, accessToken, fileId, pendingOnly = false }) {
  const operation = pendingOnly ? 'Cancel upload' : 'Delete test upload'
  const auth = { refreshed: false }
  return withUploadRetry(async () => {
    const res = await apiRequest({
      url: new URL(DELETE_PATH, apiBaseUrl), accessToken, operation, auth,
      body: JSON.stringify({ ids: [fileId], ...(pendingOnly && { preserveUploadId: true }) }),
      timeoutMs: 10_000,
    })
    if (!res.ok && res.status !== 404) throw responseError(operation, res, await readJson(res, operation))
    void res.body?.cancel().catch(() => {})
  }, undefined, 2)
}

export async function cancelUploadSession(options) {
  try {
    await deleteUpload({ ...options, pendingOnly: true })
    return true
  } catch {
    return false
  }
}

export class EmptyFileUnsupportedError extends Error {
  constructor(name) {
    super(
      `"${name}" is empty (0 bytes) and this ShieldFive server does not accept ` +
        'empty files yet. Nothing was uploaded for it.',
    )
    this.name = 'EmptyFileUnsupportedError'
    this.code = 'empty_file_unsupported'
  }
}

// Zero-byte cipher-v3 uploads are behind a server capability (web
// docs/desktop-empty-file-contract.md). Ask before creating a session, so an
// older or flag-off server gets no pending row at all.
async function serverAcceptsEmptyFiles({ apiBaseUrl, accessToken }) {
  try {
    return await withUploadRetry(async () => {
      const operation = 'Check upload capabilities'
      const res = await networkRequest(new URL(CAPABILITIES_PATH, apiBaseUrl), {
        headers: { Authorization: `Bearer ${await resolveToken(accessToken)}` },
      }, operation)
      const body = await readJson(res, operation)
      if (!res.ok) throw responseError(operation, res, body)
      return body?.emptyCipherV3 === true
    }, undefined, 3)
  } catch {
    return false
  }
}

// `onPlaintextChunk`, when given, is called with every plaintext chunk in file
// order, from the same read that feeds encryption. The agent hashes those
// chunks to record what was actually uploaded; hashing the file separately,
// before or after, cannot see a change made and undone while it was being read.
// Bulk push supplies the row ID from its checkpoint. Other callers get a fresh UUIDv7.
export async function uploadFile({ apiBaseUrl, accessToken, rootKey, name, path, size, onPlaintextChunk, onPartUploaded, onRetry, beforeStorage, directUpload = {}, rowId = newRowBoundId(), folderId = null, folderKey = null, thumbnail }) {
  // Derived before anything is sent, so a vault whose identity cannot be
  // derived fails before a session (and a pending row) exists.
  const recipientPublicKey = await vaultMlKemPublicKey(rootKey)
  if (size === 0 && !(await serverAcceptsEmptyFiles({ apiBaseUrl, accessToken }))) {
    throw new EmptyFileUnsupportedError(name)
  }
  // Not given (sync, the agent): make the encrypted preview here for photos and
  // videos. null means none. SF_NO_THUMBNAILS=1 turns it off everywhere.
  if (thumbnail === undefined) {
    thumbnail = process.env.SF_NO_THUMBNAILS === '1' ? null : await makeThumbnail({ path, name, size })
  }
  const { session, csk, nameEncryptedV6 } = await timeUpload('session_create', () => createUploadSession({
    apiBaseUrl,
    accessToken,
    rootKey,
    name,
    size,
    rowId,
    onRetry,
    folderId,
    folderKey,
    thumbnail,
  }))
  // From here on a pending row exists. Any failure before finalize answers
  // cancels it (see cancelUploadSession).
  const envelopeKey = base64ToBytes(csk)
  try {
    // The name and the file header are bound to rowId. A server that ignored
    // clientUploadId would hand back another id; refuse it (and cancel the
    // row it made) rather than upload under a mismatched binding.
    if (session?.fileId !== rowId) {
      throw new Error(
        'The upload session returned an unexpected file ID. This ShieldFive server may be too old for this client.',
      )
    }
    await sendUpload({ apiBaseUrl, accessToken, path, size, onPlaintextChunk, onPartUploaded, onRetry, beforeStorage, directUpload, session, envelopeKey, recipientPublicKey, nameEncryptedV6 })
  } catch (err) {
    if (err && typeof err === 'object') err.uploadRetriesExhausted = true
    if (err.storageFailure) onRetry?.(`${err.message}; cleaning up the upload session`)
    if (!err?.finalizeOutcomeUnknown && session?.fileId) {
      await cancelUploadSession({ apiBaseUrl, accessToken, fileId: session.fileId })
    }
    throw err
  } finally {
    envelopeKey.fill(0)
  }

  return { fileId: session.fileId }
}

async function sendUpload({ apiBaseUrl, accessToken, path, size, onPlaintextChunk, onPartUploaded, onRetry, beforeStorage, directUpload, session, envelopeKey, recipientPublicKey, nameEncryptedV6 }) {
  if (!session.proofKey) throw new Error('Upload session is missing its proof key.')

  // The server's v1 chunk size (5 MiB): each encrypted chunk is one storage part.
  const chunkSize = session.chunkSize ?? V1_CHUNK_SIZE
  async function* plaintextChunks() {
    for await (const chunk of readFileChunks(path, chunkSize)) {
      onPlaintextChunk?.(chunk)
      yield chunk
    }
  }
  const parts = encryptPartsV3({
    plaintextChunks: plaintextChunks(),
    plaintextSize: size,
    chunkSize,
    envelopeKey,
    fileId: uuidToBytes(session.fileId),
    recipientPublicKey,
  })
  // The same v6 name sent at create (bound to the row id) is sent again at
  // finalize, which still expects it.
  if (session.uploadKind === 'direct') {
    if (!session.uploadUrl) {
      throw new Error('Direct upload session is missing an upload URL.')
    }
    await uploadDirect({ apiBaseUrl, accessToken, session, parts, nameEncryptedV6, onRetry, onPartUploaded, beforeStorage, directUpload, empty: size === 0 })
  } else if (session.uploadKind === 'large' || session.uploadKind === 's3-multipart') {
    if (session.uploadKind === 'large' && (!session.uploadUrl || !session.authToken)) {
      throw new Error('Multipart upload session is missing credentials.')
    }
    await uploadMultipart({ apiBaseUrl, accessToken, session, parts, nameEncryptedV6, onRetry, onPartUploaded, beforeStorage })
  } else {
    throw new Error('The server selected an unsupported upload transport.')
  }
}
