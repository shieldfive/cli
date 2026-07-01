// ShieldFive CLI — vault unlock (VERIFIED crypto).
//
// Turns your password into the vault root key, client-side, exactly the way the
// apps do. Mirrors crypto/examples/decrypt-one.mjs (the reference offline
// decryptor), so a real vault_keys row unwraps here too. Exercised by an
// encrypt -> unwrap round-trip test (test/unlock.roundtrip.test.mjs).
//
// The only LIVE part is fetching the vault_keys row from the server
// (GET the wrapped root key + KDF params); the unwrap itself is offline.

import { webcrypto } from 'node:crypto'

import { deriveMasterSecret } from '@shieldfive/crypto/kdf/argon2id'

const subtle = webcrypto.subtle

export function base64ToBytes(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'))
}

async function aesGcmDecrypt(key, iv, ciphertext) {
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext))
}

/**
 * Derive the user key (an AES-GCM key) that wraps the root key, from the
 * password and the stored KDF parameters. Supports the legacy PBKDF2 vaults and
 * the current Argon2id vaults.
 */
export async function deriveUserKey({
  password,
  salt,
  kdf,
  iterations,
  argon2Preset,
}) {
  if (kdf === 'pbkdf2-sha256') {
    if (!iterations || iterations <= 0) {
      throw new Error('PBKDF2 unwrap requires a positive iteration count')
    }
    const material = await subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    )
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    )
  }
  if (kdf === 'argon2id') {
    if (argon2Preset !== 'moderate' && argon2Preset !== 'sensitive') {
      throw new Error(`Unsupported Argon2id preset: ${argon2Preset}`)
    }
    const { masterSecret } = await deriveMasterSecret({
      passphrase: password,
      salt,
      preset: argon2Preset,
    })
    return subtle.importKey('raw', masterSecret, { name: 'AES-GCM' }, false, [
      'decrypt',
    ])
  }
  throw new Error(`Unsupported vault KDF: ${kdf}`)
}

/**
 * Unwrap the vault root key from the password. `vaultKey` carries the base64
 * fields of the server's vault_keys row (same shape as the export bundle's
 * vault.json): ukSalt, ukIv, ukKdf, ukIterations?, ukArgon2Preset?, rkWrappedByUk.
 * @returns {Promise<Uint8Array>} the 32-byte root key
 */
export async function unlockRootKey({ password, vaultKey }) {
  const uk = await deriveUserKey({
    password,
    salt: base64ToBytes(vaultKey.ukSalt),
    kdf: vaultKey.ukKdf,
    iterations: vaultKey.ukIterations,
    argon2Preset: vaultKey.ukArgon2Preset,
  })
  return aesGcmDecrypt(
    uk,
    base64ToBytes(vaultKey.ukIv),
    base64ToBytes(vaultKey.rkWrappedByUk),
  )
}

/** Recovery-key path: unwrap the root key with the base64 recovery key. */
export async function unlockRootKeyWithRecovery({ recoveryKeyB64, vaultKey }) {
  const recKey = await subtle.importKey(
    'raw',
    base64ToBytes(recoveryKeyB64.trim()),
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  )
  return aesGcmDecrypt(
    recKey,
    base64ToBytes(vaultKey.recIv),
    base64ToBytes(vaultKey.rkWrappedByRec),
  )
}
