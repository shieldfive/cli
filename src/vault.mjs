// ShieldFive CLI — fetch + unlock the vault key.
//
// One authenticated GET returns the vault_keys row (camelCase fields:
// rkWrappedByUk, ukSalt, ukIv, ukKdf, ukIterations? / ukArgon2Preset?), then the
// VERIFIED unlock crypto (unlock.mjs) unwraps the root key client-side. The GET
// is the only live part; the unwrap is offline and round-trip tested.

import { unlockRootKey } from './unlock.mjs'

const DEFAULT_VAULT_KEY_PATH = '/api/vault-key'

export async function fetchVaultKeyRecord({
  apiBaseUrl,
  accessToken,
  vaultKeyPath = DEFAULT_VAULT_KEY_PATH,
}) {
  const res = await fetch(new URL(vaultKeyPath, apiBaseUrl), {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  if (res.status === 404) {
    throw new Error(
      'No vault found for this account. Create your vault in the web app first.',
    )
  }
  if (!res.ok) {
    throw new Error(`Failed to fetch vault key (HTTP ${res.status}).`)
  }
  const record = await res.json()
  for (const field of ['rkWrappedByUk', 'ukSalt', 'ukIv', 'ukKdf']) {
    if (!record?.[field]) {
      throw new Error(`Vault key response is missing "${field}".`)
    }
  }
  return record
}

/**
 * Fetch the vault key with the access token, then unwrap the root key with the
 * vault password.
 * @returns {Promise<Uint8Array>} the 32-byte vault root key
 */
export async function fetchAndUnlockVault({ apiBaseUrl, accessToken, password }) {
  const record = await fetchVaultKeyRecord({ apiBaseUrl, accessToken })
  return unlockRootKey({ password, vaultKey: record })
}
