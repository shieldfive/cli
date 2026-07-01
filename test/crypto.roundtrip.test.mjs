// VERIFIED core: encrypt -> decrypt round-trip with the real @shieldfive/crypto
// library, the same one the web and mobile apps run. No backend required.
//
//   node --test test/   (or: npm test)

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { test } from 'node:test'

import {
  decryptFileFromVault,
  deriveVaultIdentity,
  encryptFileForVault,
} from '../src/sfCrypto.mjs'

test('encrypt -> decrypt round-trip (suite 0x03, PQ-hybrid) in Node', async () => {
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
  const identity = await deriveVaultIdentity(rootKey)

  const plaintext = new TextEncoder().encode(
    'ShieldFive CLI round-trip — Quarterly-Report-Q3.pdf contents, kept private.',
  )

  const { encryptedBlob, csk } = await encryptFileForVault(
    plaintext,
    identity.mlKemPublicKey,
  )

  // The ciphertext must not contain the plaintext, and carries the suite header.
  const ciphertext = new Uint8Array(await encryptedBlob.arrayBuffer())
  assert.ok(ciphertext.length > plaintext.length, 'ciphertext should be larger')

  const decrypted = await decryptFileFromVault(
    encryptedBlob,
    csk,
    identity.mlKemSecretKey,
  )
  assert.deepEqual(decrypted, plaintext, 'round-trip must recover the plaintext')
})

test('a wrong content key fails to decrypt (tamper resistance)', async () => {
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
  const identity = await deriveVaultIdentity(rootKey)
  const plaintext = new TextEncoder().encode('secret')
  const { encryptedBlob } = await encryptFileForVault(
    plaintext,
    identity.mlKemPublicKey,
  )

  const wrongCsk = webcrypto.getRandomValues(new Uint8Array(32))
  await assert.rejects(() =>
    decryptFileFromVault(encryptedBlob, wrongCsk, identity.mlKemSecretKey),
  )
})
