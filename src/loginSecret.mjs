// Client-side derivation of the LOGIN SECRET, byte-identical to the web
// (utils/auth/loginSecret.ts) and Android (src/features/auth/loginSecret.ts):
//
//     loginSecret = base64url_unpadded(
//         Argon2id( DOMAIN || "\n" || password, authSalt, moderate ) )
//
// The password is used EXACTLY as typed: no trim, no Unicode normalisation.
// That is what web sign-in, signup, reset and change-password all feed this
// derivation, so it is what the secret GoTrue holds was derived from. (The
// vault KDF is different: the web keyring trims the vault password. See
// src/unlock.mjs.)
import { deriveMasterSecret } from './argon2.mjs'

const DOMAIN = 'shieldfive/v1/auth/login-secret'

export async function deriveLoginSecret({ password, authSalt }) {
  if (typeof password !== 'string' || !password) throw new Error('Password is required')
  if (typeof authSalt !== 'string' || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(authSalt)) {
    throw new Error('Invalid secure sign-in salt')
  }
  // Node's base64 decoder accepts base64 and base64url alike, as the web does.
  const salt = new Uint8Array(Buffer.from(authSalt, 'base64'))
  if (salt.length < 16 || salt.length > 64) throw new Error('Invalid secure sign-in salt')
  const { masterSecret } = await deriveMasterSecret({
    passphrase: `${DOMAIN}\n${password}`, salt, preset: 'moderate',
  })
  try { return Buffer.from(masterSecret).toString('base64url') }
  finally { masterSecret.fill(0) }
}

/**
 * The credential half of the sign-in body, per POST /api/auth/salt:
 *
 *   version 2                    -> { loginSecret }                       (no password)
 *   version 1, migration on      -> { password, loginSecret, authSalt }   (server verifies, then migrates)
 *   version 1, migration off     -> { password }
 *
 * The raw password is only ever returned when the server AFFIRMATIVELY said
 * version 1. Unlike the web's fetchAuthSalt, a failed, throttled or malformed
 * lookup never falls back to version 1: for a migrated account that would post
 * the password to the server and still not sign in. Throws before anything is
 * posted to the login route.
 */
export async function buildSignInCredentials({ apiBaseUrl, email, password, fetchImpl = fetch }) {
  let response
  try {
    response = await fetchImpl(new URL('/api/auth/salt', apiBaseUrl), {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ email }), signal: AbortSignal.timeout(30_000),
    })
  } catch {
    throw new Error('Unable to prepare secure sign-in. Check your connection and try again.')
  }
  if (response.status === 429) throw new Error('Too many sign-in attempts. Try again shortly.')
  const body = await response.json().catch(() => null)
  if (!response.ok || !body || ![1, 2].includes(body.authVersion) ||
      typeof body.authSalt !== 'string' || !body.authSalt) {
    throw new Error('Unable to prepare secure sign-in. Please try again.')
  }
  if (body.authVersion === 1 && body.migrationEnabled !== true) return { password }
  const loginSecret = await deriveLoginSecret({ password, authSalt: body.authSalt })
  return body.authVersion === 2 ? { loginSecret } : { password, loginSecret, authSalt: body.authSalt }
}
