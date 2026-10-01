// ShieldFive CLI — upload field crypto. The key wrap, v4 filename envelope and
// keyed name hash are ported byte-for-byte from the apps
// (mobile/src/features/crypto/encryptionCompat.ts); the file body is the web's
// default format, written by @shieldfive/crypto (see the end of this file). Same @noble versions as the apps
// (@noble/ciphers@2, @noble/hashes@2) so the bytes match.

import { webcrypto } from 'node:crypto'

import { gcm } from '@noble/ciphers/aes.js'
import { argon2id } from '@noble/hashes/argon2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import sodium from 'libsodium-wrappers-sumo'

import { parseHeader } from '@shieldfive/crypto/format'
import { createIdentity } from '@shieldfive/crypto/identity'
import { encryptStreamPqHybridV1 } from '@shieldfive/crypto/streams/pq-hybrid-v1'
import { buildUploadProofV3 } from '@shieldfive/crypto/vault'

// libsodium's Argon2id (crypto_pwhash) is byte-identical to @noble's at the same
// params but ~15x faster (native/WASM vs pure JS). It is used for the ENCRYPT
// side of the v4 filename metadata — the once-per-file KDF that makes `sf sync`
// over many files KDF-bound. decryptMetadataV4 stays on @noble (off the hot
// path, and a second independent implementation guards reads against a
// libsodium regression). libsodium is already a dependency and initialised in
// the unlock path; this memoised gate awaits sodium.ready once.
let sodiumReadyPromise
const getSodium = async () => {
  if (!sodiumReadyPromise) {
    sodiumReadyPromise = (async () => {
      await sodium.ready
      return sodium
    })()
  }
  return sodiumReadyPromise
}

const AES_GCM_TAG_BYTES = 16

const utf8 = (s) => new TextEncoder().encode(s)
export const bytesToBase64 = (u8) => Buffer.from(u8).toString('base64')
export const base64ToBytes = (b64) => new Uint8Array(Buffer.from(b64, 'base64'))
const bytesToHex = (u8) => Buffer.from(u8).toString('hex')
const randomBytes = (n) => webcrypto.getRandomValues(new Uint8Array(n))

// gcm().encrypt returns ciphertext||tag; gcm().decrypt expects the same.
export function aesGcmEncrypt(key, iv, plaintext) {
  return gcm(key, iv).encrypt(plaintext)
}

export function generateRandomKeyB64(bytes = 32) {
  return bytesToBase64(randomBytes(bytes))
}

export function wrapKeyB64({ wrappingKeyB64, keyToWrapB64 }) {
  const iv = randomBytes(12)
  const ciphertext = aesGcmEncrypt(
    base64ToBytes(wrappingKeyB64),
    iv,
    base64ToBytes(keyToWrapB64),
  )
  return { wrapped: bytesToBase64(ciphertext), iv: bytesToBase64(iv) }
}

export function unwrapKeyB64({ wrappingKeyB64, wrappedKeyB64, ivB64 }) {
  const plaintext = gcm(
    base64ToBytes(wrappingKeyB64),
    base64ToBytes(ivB64),
  ).decrypt(base64ToBytes(wrappedKeyB64))
  return bytesToBase64(plaintext)
}

export function hashMetadataV4(input, rootKeySecret) {
  const hmacKey = sha256(utf8(rootKeySecret))
  const signature = hmac(sha256, hmacKey, utf8(input))
  return `v4:${bytesToHex(signature)}`
}

const ARGON2_PARAMS = {
  interactive: { t: 2, m: 64 * 1024, p: 1, version: 0x13, dkLen: 32 },
  moderate: { t: 3, m: 256 * 1024, p: 1, version: 0x13, dkLen: 32 },
}

// v4 filename metadata (Argon2id "interactive" + AES-GCM) — the format the web
// reads. rootKeySecret is the base64 string of the vault root key.
//
// Derives the metadata key with libsodium crypto_pwhash (ARGON2ID13, opslimit=2,
// memlimit=64 MiB) — byte-identical to ARGON2_PARAMS.interactive but far faster.
// The envelope (v/ct/iv/tag/salt/kdf) is unchanged, so it decrypts on the web
// and mobile clients exactly as before. Async because of the libsodium ready
// gate; the sole caller (createUploadSession) is already async.
export async function encryptMetadataV4(plaintext, rootKeySecret) {
  const s = await getSodium()
  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const metadataKey = s.crypto_pwhash(
    32,
    rootKeySecret,
    salt,
    2,
    64 * 1024 * 1024,
    s.crypto_pwhash_ALG_ARGON2ID13,
  )
  const ciphertextWithTag = aesGcmEncrypt(metadataKey, iv, utf8(plaintext))
  const tagStart = ciphertextWithTag.length - AES_GCM_TAG_BYTES
  return {
    v: 4,
    ct: bytesToBase64(ciphertextWithTag.slice(0, tagStart)),
    iv: bytesToBase64(iv),
    tag: bytesToBase64(ciphertextWithTag.slice(tagStart)),
    salt: bytesToBase64(salt),
    kdf: 'interactive',
  }
}

export function decryptMetadataV4(payload, rootKeySecret) {
  const params = ARGON2_PARAMS[payload.kdf === 'moderate' ? 'moderate' : 'interactive']
  const metadataKey = argon2id(rootKeySecret, base64ToBytes(payload.salt), params)
  const ct = base64ToBytes(payload.ct)
  const tag = base64ToBytes(payload.tag)
  const combined = new Uint8Array(ct.length + tag.length)
  combined.set(ct, 0)
  combined.set(tag, ct.length)
  const plaintext = gcm(metadataKey, base64ToBytes(payload.iv)).decrypt(combined)
  return new TextDecoder().decode(plaintext)
}

// ── Storage-part digests ────────────────────────────────────────────────────

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export async function sha1Hex(bytes) {
  const digest = await webcrypto.subtle.digest('SHA-1', bytes)
  return bytesToHex(new Uint8Array(digest))
}

// Multipart ciphertextHash — the value `complete-upload` checks against the
// server's own computeLargeFileSha1. One part: the part's SHA-1, lowercased.
// Many parts: SHA-1 over the concatenated raw 20-byte part digests (NOT the
// hex strings). Ported from encryptionCompat.ts:getCiphertextHashFromParts.
export async function getCiphertextHashFromParts(partSha1Array) {
  if (!partSha1Array.length) throw new Error('Missing part hashes')
  if (partSha1Array.length === 1) return partSha1Array[0].trim().toLowerCase()
  const bytes = new Uint8Array(partSha1Array.length * 20)
  let offset = 0
  for (const part of partSha1Array) {
    const normalized = part.trim().toLowerCase()
    if (!/^[0-9a-f]{40}$/.test(normalized)) {
      throw new Error('Invalid part SHA1 value')
    }
    bytes.set(hexToBytes(normalized), offset)
    offset += 20
  }
  return sha1Hex(bytes)
}

// ── File encryption, v1 wire format, suite 0x03 (cipher_version 3) ───────────
//
// What the web app writes by default (encryptModal.tsx, `v1-pq-hybrid`), using
// the same @shieldfive/crypto stream encoder: a MAC'd header carrying
// plaintext_size and total_chunks, chunk AAD binding index/total/is_final (so a
// dropped or reordered chunk fails to decrypt), file_id = the server row id (so
// the blob cannot be moved onto another row), and ML-KEM-1024 + X25519 hybrid
// key encapsulation to the owner's vault identity.
//
// This replaces the legacy v0 writer (suite 0x01 chunks under a random 4-byte
// nonce prefix, no header): no truncation detection, no file binding, no PQ.
// The spec (crypto spec/format-v0.md) forbids new v0 writes.

export const V1_CHUNK_SIZE = 5 * 1024 * 1024
export const CIPHER_VERSION_PQ = 3
const FRAME_LENGTH_BYTES = 4

export function uuidToBytes(id) {
  const hex = String(id).replace(/-/g, '')
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error(`Not a UUID: ${id}`)
  return hexToBytes(hex.toLowerCase())
}

// The owner's ML-KEM public key, derived from the root key exactly as the web
// keyring does (utils/pqIdentity.ts: createIdentity with the root key as the
// master secret; userId does not affect the key bytes). Derived locally, never
// taken from the server, so a server cannot substitute a recipient. Cached by a
// hash of the root key: the public key is not secret, the derivation is not free.
const identityCache = new Map()
export async function vaultMlKemPublicKey(rootKey) {
  const id = bytesToHex(sha256(rootKey))
  let pk = identityCache.get(id)
  if (!pk) {
    const identity = await createIdentity({ userId: 'shieldfive-cli', masterSecret: rootKey })
    identity.mlKemSecretKey?.fill?.(0)
    pk = identity.publicBundle.mlKemPublicKey
    identityCache.set(id, pk)
  }
  return pk
}

function toReadableStream(iterable) {
  const it = iterable[Symbol.asyncIterator]()
  return new ReadableStream({
    async pull(controller) {
      const { value, done } = await it.next()
      if (done) controller.close()
      else controller.enqueue(value)
    },
    async cancel() {
      await it.return?.()
    },
  })
}

/**
 * Encrypt a plaintext chunk stream as one suite-0x03 object and yield it as
 * storage parts: part 0 is `header || frame_0`, part i is `frame_i`. That is the
 * layout the server's proof verifier and the web uploader use (one encrypted
 * chunk per storage part). The split is made from the bytes themselves (header
 * length, then each frame's length prefix), not from how the encoder happens
 * to enqueue its output.
 */
export async function* encryptPartsV3({
  plaintextChunks,
  plaintextSize,
  chunkSize,
  envelopeKey,
  fileId,
  recipientPublicKey,
}) {
  const { ciphertext, combinedKey } = await encryptStreamPqHybridV1(toReadableStream(plaintextChunks), {
    recipientPublicKey,
    envelopeKey,
    plaintextSize,
    chunkSize,
    fileId,
  })
  // combinedKey is used by the stream while it runs; wiped in the finally below.

  const reader = ciphertext.getReader()
  let buf = new Uint8Array(0)
  let done = false
  const pull = async () => {
    const r = await reader.read()
    if (r.done) {
      done = true
      return
    }
    const next = new Uint8Array(buf.length + r.value.length)
    next.set(buf, 0)
    next.set(r.value, buf.length)
    buf = next
  }
  const take = (n) => {
    const out = buf.slice(0, n)
    buf = buf.slice(n)
    return out
  }
  const readFrame = async () => {
    while (buf.length < FRAME_LENGTH_BYTES && !done) await pull()
    if (buf.length === 0 && done) return null
    if (buf.length < FRAME_LENGTH_BYTES) throw new Error('Encrypted stream ended inside a chunk frame.')
    const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0, false)
    while (buf.length < FRAME_LENGTH_BYTES + len && !done) await pull()
    if (buf.length < FRAME_LENGTH_BYTES + len) throw new Error('Encrypted stream ended inside a chunk frame.')
    return take(FRAME_LENGTH_BYTES + len)
  }

  try {
    // Header: parse as soon as enough bytes are buffered.
    let headerLength = null
    while (headerLength === null) {
      try {
        headerLength = parseHeader(buf).headerLength
      } catch (err) {
        if (done) throw err
        await pull()
      }
    }
    const header = take(headerLength)
    const first = await readFrame()
    if (!first) throw new Error('Encrypted stream has no chunks.')
    const part0 = new Uint8Array(header.length + first.length)
    part0.set(header, 0)
    part0.set(first, header.length)
    yield part0
    for (;;) {
      const frame = await readFrame()
      if (!frame) break
      yield frame
    }
  } finally {
    reader.releaseLock()
    combinedKey.fill(0)
  }
}

/** The suite-0x03 upload proof, from the library both other writers use. */
export function computeV3UploadProof({ proofKeyHex, part0 }) {
  return buildUploadProofV3({ proofKeyHex, ciphertext: part0 })
}
