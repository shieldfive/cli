import { deriveMasterSecret } from './argon2.mjs'

const DOMAIN = 'shieldfive/v1/auth/login-secret'

export async function deriveLoginSecret({ password, authSalt }) {
  if (typeof password !== 'string' || !password) throw new Error('Password is required')
  if (typeof authSalt !== 'string' || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(authSalt)) {
    throw new Error('Invalid secure sign-in salt')
  }
  const salt = new Uint8Array(Buffer.from(authSalt, 'base64'))
  if (salt.length < 16 || salt.length > 64) throw new Error('Invalid secure sign-in salt')
  const { masterSecret } = await deriveMasterSecret({
    passphrase: `${DOMAIN}\n${password}`, salt, preset: 'moderate',
  })
  try { return Buffer.from(masterSecret).toString('base64url') }
  finally { masterSecret.fill(0) }
}

// Never guess version 1 when the lookup is unavailable: that would expose a
// migrated account's vault password to the server without allowing sign-in.
export async function buildSignInCredentials({ apiBaseUrl, email, password, fetchImpl = fetch }) {
  const response = await fetchImpl(new URL('/api/auth/salt', apiBaseUrl), {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email }), signal: AbortSignal.timeout(30_000),
  })
  const body = await response.json().catch(() => null)
  if (!response.ok || !body || ![1, 2].includes(body.authVersion) ||
      typeof body.authSalt !== 'string' || !body.authSalt) {
    throw new Error('Unable to prepare secure sign-in. Please try again.')
  }
  if (body.authVersion === 1 && body.migrationEnabled !== true) return { password }
  const loginSecret = await deriveLoginSecret({ password, authSalt: body.authSalt })
  return body.authVersion === 2 ? { loginSecret } : { password, loginSecret, authSalt: body.authSalt }
}
