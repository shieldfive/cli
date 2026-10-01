import assert from 'node:assert/strict'
import { test } from 'node:test'
import { deriveLoginSecret, buildSignInCredentials } from '../src/loginSecret.mjs'
import { signIn } from '../src/auth.mjs'

const password = 'correct horse battery staple 42'
const salt = Buffer.alloc(32, 7).toString('base64')
const secret = '-3MAPAD6FFMypDmTdLMY0ivfscMAlhyFK5aj5-1c8N8'
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

test('login derivation matches the pinned web/mobile 32-byte-salt vector', async () => {
  let ticks = 0
  const timer = setInterval(() => { ticks++ }, 10)
  try { assert.equal(await deriveLoginSecret({ password, authSalt: salt }), secret) }
  finally { clearInterval(timer) }
  assert.ok(ticks > 0, 'Argon2id must leave the event loop responsive')
  assert.equal(await deriveLoginSecret({ password, authSalt: Buffer.alloc(16, 7).toString('base64') }),
    'YRxqCqxxKe-kWjq0T9jwIe22GOLJlROTlKkedBS8qd4')
})

test('migrated sign-in never posts raw password; establishes session before checking MFA', async () => {
  const requests = []
  const actions = []
  const session = { access_token: 'ACCESS', refresh_token: 'REFRESH', expires_at: 12345, user: { id: 'QA' } }
  const result = await signIn({ apiBaseUrl: 'https://api.test', supabaseUrl: 'https://s.test', anonKey: 'PUBLIC', email: 'qa@example.test', password,
    fetchImpl: async (url, options) => {
      requests.push({ url: String(url), body: JSON.parse(options.body) })
      return String(url).endsWith('/salt') ? json({ authVersion: 2, authSalt: salt }) : json({ accessToken: 'ACCESS', refreshToken: 'REFRESH' })
    },
    createClientImpl: () => ({ auth: {
      setSession: async (tokens) => { actions.push(tokens); return { data: { session }, error: null } },
      mfa: { getAuthenticatorAssuranceLevel: async () => { actions.push('MFA'); return { data: { currentLevel: 'aal1', nextLevel: 'aal1' }, error: null } } },
    } }),
  })
  assert.deepEqual(requests, [
    { url: 'https://api.test/api/auth/salt', body: { email: 'qa@example.test' } },
    { url: 'https://api.test/api/mobile/auth/login', body: { email: 'qa@example.test', loginSecret: secret } },
  ])
  assert.deepEqual(actions, [{ access_token: 'ACCESS', refresh_token: 'REFRESH' }, 'MFA'])
  assert.equal(result.accessToken, 'ACCESS')
  assert.equal(result.refreshToken, 'REFRESH')
  assert.equal(result.userId, 'QA')
})

test('failed or unknown auth-version lookup stops before credential submission', async () => {
  for (const response of [json({}, 503), json({ authVersion: 3, authSalt: salt }), json({ authVersion: 2 })]) {
    let calls = 0
    await assert.rejects(signIn({ apiBaseUrl: 'https://api.test', email: 'qa@example.test', password,
      fetchImpl: async () => { calls++; return response }, createClientImpl: () => { throw new Error('Must not establish session') },
    }), /Unable to prepare secure sign-in/)
    assert.equal(calls, 1)
  }
})

test('legacy migration body matches the server contract; migration-off preserves legacy sign-in', async () => {
  const input = { apiBaseUrl: 'https://api.test', email: 'qa@example.test', password }
  assert.deepEqual(await buildSignInCredentials({ ...input, fetchImpl: async () => json({ authVersion: 1, authSalt: salt, migrationEnabled: true }) }),
    { password, loginSecret: secret, authSalt: salt })
  assert.deepEqual(await buildSignInCredentials({ ...input, fetchImpl: async () => json({ authVersion: 1, authSalt: salt, migrationEnabled: false }) }), { password })
})

test('invalid salt is refused before expensive derivation', async () => {
  for (const authSalt of ['', '!!!', 'YQ==', Buffer.alloc(65).toString('base64')]) {
    await assert.rejects(deriveLoginSecret({ password, authSalt }), /Invalid secure sign-in salt/)
  }
})
