// VERIFIED: the password -> root-key unwrap, round-tripped against the same
// Argon2id KDF the apps use. (A real vault_keys row unwraps the same way; this
// proves the offline crypto without a backend.)

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { test } from 'node:test'

import { deriveMasterSecret } from '@shieldfive/crypto/kdf/argon2id'

import { unlockRootKey } from '../src/unlock.mjs'

const subtle = webcrypto.subtle
const b64 = (u8) => Buffer.from(u8).toString('base64')

// Wrap a root key under an Argon2id user key (the inverse of unlock), producing
// the same fields the server's vault_keys row carries.
async function wrapRootKeyUnderPassword({ password, preset, rootKey }) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16))
  const iv = webcrypto.getRandomValues(new Uint8Array(12))
  const { masterSecret } = await deriveMasterSecret({
    passphrase: password,
    salt,
    preset,
  })
  const uk = await subtle.importKey('raw', masterSecret, { name: 'AES-GCM' }, false, [
    'encrypt',
  ])
  const wrapped = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv }, uk, rootKey),
  )
  return {
    ukSalt: b64(salt),
    ukIv: b64(iv),
    ukKdf: 'argon2id',
    ukArgon2Preset: preset,
    rkWrappedByUk: b64(wrapped),
  }
}

test('unlockRootKey recovers a root key wrapped under an Argon2id user key', async () => {
  const password = 'correct horse battery staple'
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
  const vaultKey = await wrapRootKeyUnderPassword({
    password,
    preset: 'moderate',
    rootKey,
  })

  const unlocked = await unlockRootKey({ password, vaultKey })
  assert.deepEqual(unlocked, rootKey)
})

test('a wrong password fails to unlock', async () => {
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
  const vaultKey = await wrapRootKeyUnderPassword({
    password: 'the-right-password',
    preset: 'moderate',
    rootKey,
  })

  await assert.rejects(() =>
    unlockRootKey({ password: 'the-wrong-password', vaultKey }),
  )
})
