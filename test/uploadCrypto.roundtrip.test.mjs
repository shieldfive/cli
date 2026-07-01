// VERIFIED: the create-session field crypto, ported from the apps. These
// round-trips catch porting bugs before the live call; the server validates the
// rest (it must accept name_encrypted / nameHash / csk_wrapped to issue a session).

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { test } from 'node:test'

import { gcm } from '@noble/ciphers/aes.js'

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

test('encryptMetadataV4 / decryptMetadataV4 round-trip (filename)', () => {
  const rootKeyB64 = randKeyB64()
  const envelope = encryptMetadataV4('Quarterly-Report-Q3.pdf', rootKeyB64)
  assert.equal(envelope.v, 4)
  assert.equal(envelope.kdf, 'interactive')
  assert.equal(decryptMetadataV4(envelope, rootKeyB64), 'Quarterly-Report-Q3.pdf')
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

test('encryptFileChunk round-trips (suite 0x01 AES-GCM, nonce = prefix||counter)', () => {
  const cskB64 = generateRandomKeyB64()
  const noncePrefixB64 = generateNoncePrefixB64()
  const plaintext = new TextEncoder().encode('the file contents, kept private')
  const ciphertext = encryptFileChunk({
    cskB64,
    noncePrefixB64,
    chunkIndex: 0,
    plaintext,
  })
  const nonce = new Uint8Array(12)
  nonce.set(base64ToBytes(noncePrefixB64), 0) // chunkIndex 0 -> counter is all zero
  const recovered = gcm(base64ToBytes(cskB64), nonce).decrypt(ciphertext)
  assert.deepEqual(recovered, plaintext)
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
