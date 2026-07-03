// VERIFIED: the create-session field crypto, ported from the apps. These
// round-trips catch porting bugs before the live call; the server validates the
// rest (it must accept name_encrypted / nameHash / csk_wrapped to issue a session).

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { test } from 'node:test'

import { gcm } from '@noble/ciphers/aes.js'
import { argon2id } from '@noble/hashes/argon2.js'

import {
  base64ToBytes,
  bytesToBase64,
  computeAesGcmUploadProof,
  decryptMetadataV4,
  encryptFileChunk,
  encryptMetadataV4,
  generateNoncePrefixB64,
  generateRandomKeyB64,
  hashMetadataV4,
  unwrapKeyB64,
  wrapKeyB64,
} from '../src/uploadCrypto.mjs'

const randKeyB64 = () =>
  bytesToBase64(webcrypto.getRandomValues(new Uint8Array(32)))

test('wrapKeyB64 / unwrapKeyB64 round-trip (csk wrap)', () => {
  const wrappingKeyB64 = randKeyB64()
  const keyToWrapB64 = randKeyB64()
  const { wrapped, iv } = wrapKeyB64({ wrappingKeyB64, keyToWrapB64 })
  const recovered = unwrapKeyB64({
    wrappingKeyB64,
    wrappedKeyB64: wrapped,
    ivB64: iv,
  })
  assert.equal(recovered, keyToWrapB64)
})

test('encryptMetadataV4 (libsodium KDF) / decryptMetadataV4 (@noble KDF) round-trip', async () => {
  const rootKeyB64 = randKeyB64()
  // encrypt derives the key with libsodium; decrypt derives it with @noble.
  // A successful round-trip proves the two Argon2id backends agree byte-for-byte.
  const envelope = await encryptMetadataV4('Quarterly-Report-Q3.pdf', rootKeyB64)
  assert.equal(envelope.v, 4)
  assert.equal(envelope.kdf, 'interactive')
  assert.equal(decryptMetadataV4(envelope, rootKeyB64), 'Quarterly-Report-Q3.pdf')
})

test('decryptMetadataV4 still reads a legacy envelope produced by the @noble encrypt path', () => {
  // Reproduce the pre-change encrypt exactly (pure @noble Argon2id) so this test
  // fails if the v4 envelope format or KDF params ever drift and break stored
  // production filenames.
  const rootKeyB64 = randKeyB64()
  const name = 'Legacy File (2025).pdf'
  const salt = webcrypto.getRandomValues(new Uint8Array(16))
  const iv = webcrypto.getRandomValues(new Uint8Array(12))
  const metadataKey = argon2id(rootKeyB64, salt, {
    t: 2,
    m: 64 * 1024,
    p: 1,
    version: 0x13,
    dkLen: 32,
  })
  const ctWithTag = gcm(metadataKey, iv).encrypt(new TextEncoder().encode(name))
  const legacyEnvelope = {
    v: 4,
    ct: bytesToBase64(ctWithTag.slice(0, ctWithTag.length - 16)),
    iv: bytesToBase64(iv),
    tag: bytesToBase64(ctWithTag.slice(ctWithTag.length - 16)),
    salt: bytesToBase64(salt),
    kdf: 'interactive',
  }
  assert.equal(decryptMetadataV4(legacyEnvelope, rootKeyB64), name)
})

test('hashMetadataV4 is deterministic and v4-prefixed', () => {
  const rootKeyB64 = bytesToBase64(new Uint8Array(32).fill(7))
  const h1 = hashMetadataV4('report.pdf', rootKeyB64)
  const h2 = hashMetadataV4('report.pdf', rootKeyB64)
  assert.equal(h1, h2)
  assert.match(h1, /^v4:[0-9a-f]{64}$/)
})

test('generateNoncePrefixB64 decodes to 4 bytes', () => {
  assert.equal(base64ToBytes(generateNoncePrefixB64()).length, 4)
})

test('encryptFileChunk round-trips (suite 0x01 AES-GCM, nonce = prefix||counter)', async () => {
  const cskB64 = generateRandomKeyB64()
  const noncePrefixB64 = generateNoncePrefixB64()
  const plaintext = new TextEncoder().encode('the file contents, kept private')
  const ciphertext = await encryptFileChunk({
    cskB64,
    noncePrefixB64,
    chunkIndex: 0,
    plaintext,
  })
  const nonce = new Uint8Array(12)
  nonce.set(base64ToBytes(noncePrefixB64), 0) // chunkIndex 0 -> counter is all zero
  // Decrypt with @noble: proves the WebCrypto ciphertext||tag is the exact
  // format @noble (and the server / apps) expect.
  const recovered = gcm(base64ToBytes(cskB64), nonce).decrypt(ciphertext)
  assert.deepEqual(recovered, plaintext)
})

test('encryptFileChunk (WebCrypto) is byte-identical to @noble AES-GCM', async () => {
  const cskB64 = generateRandomKeyB64()
  const noncePrefixB64 = generateNoncePrefixB64()
  const plaintext = new TextEncoder().encode(
    'a longer chunk that spans a counter increment to be safe',
  )
  const chunkIndex = 7

  const viaWebCrypto = await encryptFileChunk({
    cskB64,
    noncePrefixB64,
    chunkIndex,
    plaintext,
  })

  // Rebuild the nonce exactly as encryptFileChunk does, then encrypt with
  // @noble and assert the bytes match — the byte-for-byte compatibility proof.
  const nonce = new Uint8Array(12)
  nonce.set(base64ToBytes(noncePrefixB64), 0)
  let counter = BigInt(chunkIndex)
  for (let i = 0; i < 8; i += 1) {
    nonce[11 - i] = Number(counter & 0xffn)
    counter >>= 8n
  }
  const viaNoble = gcm(base64ToBytes(cskB64), nonce).encrypt(plaintext)

  assert.deepEqual(viaWebCrypto, viaNoble)
})

test('encryptFileChunk handles an empty chunk (ciphertext = tag only)', async () => {
  const cskB64 = generateRandomKeyB64()
  const noncePrefixB64 = generateNoncePrefixB64()
  const empty = new Uint8Array(0)
  const ciphertext = await encryptFileChunk({
    cskB64,
    noncePrefixB64,
    chunkIndex: 0,
    plaintext: empty,
  })
  assert.equal(ciphertext.length, 16) // GCM tag only, no plaintext
  const nonce = new Uint8Array(12)
  nonce.set(base64ToBytes(noncePrefixB64), 0)
  assert.deepEqual(gcm(base64ToBytes(cskB64), nonce).decrypt(ciphertext), empty)
})

test('computeAesGcmUploadProof is deterministic 64-hex', () => {
  const args = {
    proofKeyHex: 'ab'.repeat(32),
    cipherVersion: 1,
    chunkSize: 5 * 1024 * 1024,
    noncePrefixB64: bytesToBase64(new Uint8Array([1, 2, 3, 4])),
    ciphertextChunk: new Uint8Array([9, 9, 9, 9]),
  }
  const p1 = computeAesGcmUploadProof(args)
  const p2 = computeAesGcmUploadProof(args)
  assert.equal(p1, p2)
  assert.match(p1, /^[0-9a-f]{64}$/)
})
