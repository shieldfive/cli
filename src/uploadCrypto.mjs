// ShieldFive CLI — upload field crypto, ported byte-for-byte from the apps
// (mobile/src/features/crypto/encryptionCompat.ts). These produce the fields the
// `create-upload-session` endpoint expects: the wrapped content key, the v4
// filename envelope, and the keyed name hash. Same @noble versions as the apps
// (@noble/ciphers@2, @noble/hashes@2) so the bytes match.

import { webcrypto } from 'node:crypto'

import { gcm } from '@noble/ciphers/aes.js'
import { argon2id } from '@noble/hashes/argon2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'

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

export function generateNoncePrefixB64() {
  return bytesToBase64(randomBytes(4))
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
export function encryptMetadataV4(plaintext, rootKeySecret) {
  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const metadataKey = argon2id(rootKeySecret, salt, ARGON2_PARAMS.interactive)
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

// ── File chunk encryption (suite 0x01 AES-GCM) + Backblaze upload proof ───────

const UPLOAD_PROOF_VERSION = 1

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

// nonce = 4-byte random prefix || 8-byte big-endian chunk counter.
export function encryptFileChunk({ cskB64, noncePrefixB64, chunkIndex, plaintext }) {
  const noncePrefix = base64ToBytes(noncePrefixB64)
  if (noncePrefix.length !== 4) throw new Error('Invalid nonce prefix')
  const nonce = new Uint8Array(12)
  nonce.set(noncePrefix, 0)
  let counter = BigInt(chunkIndex)
  for (let i = 0; i < 8; i += 1) {
    nonce[11 - i] = Number(counter & 0xffn)
    counter >>= 8n
  }
  return aesGcmEncrypt(base64ToBytes(cskB64), nonce, plaintext)
}

function buildUploadProofPrefix({ cipherVersion, chunkSize, noncePrefixBytes }) {
  const size = Math.floor(chunkSize)
  if (!Number.isFinite(size) || size <= 0) {
    throw new Error('Invalid chunk size for upload proof')
  }
  if (noncePrefixBytes.length !== 4) {
    throw new Error('Invalid nonce prefix length for upload proof')
  }
  const prefix = new Uint8Array(1 + 1 + 4 + 4)
  prefix[0] = UPLOAD_PROOF_VERSION
  prefix[1] = cipherVersion
  new DataView(prefix.buffer).setUint32(2, size, false)
  prefix.set(noncePrefixBytes, 6)
  return prefix
}

export function computeAesGcmUploadProof({
  proofKeyHex,
  cipherVersion,
  chunkSize,
  noncePrefixB64,
  ciphertextChunk,
}) {
  const proofKey = hexToBytes(proofKeyHex)
  const prefix = buildUploadProofPrefix({
    cipherVersion,
    chunkSize,
    noncePrefixBytes: base64ToBytes(noncePrefixB64),
  })
  const payload = new Uint8Array(prefix.length + ciphertextChunk.length)
  payload.set(prefix, 0)
  payload.set(ciphertextChunk, prefix.length)
  return bytesToHex(hmac(sha256, proofKey, payload))
}

export async function sha1Hex(bytes) {
  const digest = await webcrypto.subtle.digest('SHA-1', bytes)
  return bytesToHex(new Uint8Array(digest))
}

// Encrypt one chunk and produce its SHA-1 (for Backblaze) and the upload proof.
export async function encryptChunkWithDigest({
  cskB64,
  noncePrefixB64,
  chunkIndex,
  plaintext,
  proofKeyHex,
  chunkSize,
}) {
  const ciphertext = encryptFileChunk({
    cskB64,
    noncePrefixB64,
    chunkIndex,
    plaintext,
  })
  const digest = await sha1Hex(ciphertext)
  const proofHex =
    proofKeyHex && chunkSize
      ? computeAesGcmUploadProof({
          proofKeyHex,
          cipherVersion: 1,
          chunkSize,
          noncePrefixB64,
          ciphertextChunk: ciphertext,
        })
      : undefined
  return { ciphertext, sha1Hex: digest, proofHex }
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
