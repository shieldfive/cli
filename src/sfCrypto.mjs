// ShieldFive CLI — file encryption core (suite 0x03, PQ-hybrid).
//
// This is the VERIFIED part of the CLI: it produces ciphertext that the web and
// mobile apps decrypt, using the same published @shieldfive/crypto library they
// run. It is exercised by an encrypt -> decrypt round-trip test
// (test/crypto.roundtrip.test.mjs) and needs no backend to verify.
//
// Mirrors the reference offline decryptor (crypto/examples/decrypt-one.mjs):
//   rootKey -> createIdentity (ML-KEM keypair); per-file csk is the classical
//   "envelope key"; encryptBlob/autoDecryptBlob run suite 0x03.

import { webcrypto } from 'node:crypto'

import { autoDecryptBlob } from '@shieldfive/crypto'
import { createIdentity } from '@shieldfive/crypto/identity'
import { encryptBlob } from '@shieldfive/crypto/pq-hybrid-v1'

const CONTENT_KEY_BYTES = 32

/**
 * Derive the vault owner's ML-KEM identity from the vault root key.
 * `rootKey` comes from unlocking the vault (see auth/unlock — needs the live
 * API). `userId` is metadata only and does not affect the derived key bytes.
 * @param {Uint8Array} rootKey 32-byte vault root key
 */
export async function deriveVaultIdentity(rootKey) {
  const id = await createIdentity({
    userId: 'shieldfive-cli',
    masterSecret: rootKey,
  })
  return {
    mlKemPublicKey: id.publicBundle.mlKemPublicKey,
    mlKemSecretKey: id.mlKemSecretKey,
    publicBundleBytes: id.publicBundleBytes,
  }
}

/**
 * Encrypt one file's bytes for the owner's vault.
 * Returns the encrypted blob plus the fresh per-file content key (`csk`); the
 * app wraps `csk` under the parent folder/root key for storage.
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} mlKemPublicKey owner identity public key (1568 bytes)
 */
export async function encryptFileForVault(plaintext, mlKemPublicKey) {
  const csk = webcrypto.getRandomValues(new Uint8Array(CONTENT_KEY_BYTES))
  const result = await encryptBlob({
    blob: new Blob([plaintext]),
    recipientPublicKey: mlKemPublicKey,
    envelopeKey: csk,
  })
  return {
    encryptedBlob: result.blob,
    csk,
    fileId: result.fileId,
    suite: result.suite,
    totalChunks: result.totalChunks,
    plaintextSize: result.plaintextSize,
  }
}

/**
 * Decrypt an encrypted blob (used for round-trip verification and reads).
 * @param {Blob} encryptedBlob
 * @param {Uint8Array} csk per-file content key (the classical envelope key)
 * @param {Uint8Array} mlKemSecretKey owner identity secret key
 * @returns {Promise<Uint8Array>}
 */
export async function decryptFileFromVault(encryptedBlob, csk, mlKemSecretKey) {
  const result = await autoDecryptBlob({
    blob: encryptedBlob,
    envelopeKey: csk,
    recipientSecretKey: mlKemSecretKey,
  })
  const out = result?.blob ?? result
  return new Uint8Array(await out.arrayBuffer())
}
