// The raw password must never leave the machine for a version-2 account, on
// ANY path: success, MFA step-up, a refused login, or a salt lookup that fails
// in any way. For a version-1 account it may go to exactly one place, the
// version-aware login route, and only after the salt endpoint affirmatively
// said version 1.
//
// Every outbound request is captured: signIn's fetch, the global fetch (so
// nothing can slip out through a default), and every argument handed to the
// Supabase client. Each is serialised and searched for the password.
import assert from 'node:assert/strict'
import { afterEach, beforeEach, test } from 'node:test'

import { signIn } from '../src/auth.mjs'

const PASSWORD = 'Unique-Pa55word-🔑-never-on-the-wire'
const SALT = Buffer.alloc(32, 7).toString('base64')
const EMAIL = 'qa@example.test'
const API = 'https://api.test'

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

let wire
let realFetch
beforeEach(() => {
  wire = []
  realFetch = globalThis.fetch
  globalThis.fetch = async (url, options) => {
    wire.push({ via: 'global fetch', url: String(url), body: String(options?.body ?? '') })
    throw new Error('unexpected global fetch')
  }
})
afterEach(() => { globalThis.fetch = realFetch })

function supabaseStub({ mfa = false } = {}) {
  const record = (method) => (...args) => {
    wire.push({ via: `supabase.${method}`, url: '', body: JSON.stringify(args) })
  }
  const session = { access_token: 'AAL1', refresh_token: 'R1', expires_at: 1, user: { id: 'U' } }
  const stepped = { access_token: 'AAL2', refresh_token: 'R2', expires_at: 2, user: { id: 'U' } }
  return (...createArgs) => {
    record('createClient')(...createArgs)
    let current = session
    return {
      auth: {
        signInWithPassword: async (...a) => { record('signInWithPassword')(...a); throw new Error('must not be called') },
        setSession: async (...a) => { record('setSession')(...a); return { data: { session, user: session.user }, error: null } },
        getSession: async () => ({ data: { session: current }, error: null }),
        mfa: {
          getAuthenticatorAssuranceLevel: async () => ({
            data: { currentLevel: 'aal1', nextLevel: mfa ? 'aal2' : 'aal1' }, error: null,
          }),
          listFactors: async () => ({ data: { totp: [{ id: 'F', status: 'verified' }] }, error: null }),
          challenge: async (...a) => { record('mfa.challenge')(...a); return { data: { id: 'C' }, error: null } },
          verify: async (...a) => { record('mfa.verify')(...a); current = stepped; return { data: stepped, error: null } },
        },
      },
    }
  }
}

function fetchStub({ salt, login = () => json({ accessToken: 'AAL1', refreshToken: 'R1' }) }) {
  return async (url, options) => {
    wire.push({ via: 'signIn fetch', url: String(url), body: String(options?.body ?? '') })
    if (String(url).endsWith('/api/auth/salt')) return salt()
    if (String(url).endsWith('/api/mobile/auth/login')) return login()
    throw new Error(`unexpected request to ${url}`)
  }
}

const run = (opts) => signIn({
  apiBaseUrl: API, supabaseUrl: 'https://s.test', anonKey: 'ANON', email: EMAIL, password: PASSWORD,
  getTotpCode: async () => '123456', ...opts,
})

function leaks() {
  return wire.filter((r) => r.url.includes(PASSWORD) || r.body.includes(PASSWORD) ||
    r.body.includes(JSON.stringify(PASSWORD).slice(1, -1)))
}

test('version 2: success', async () => {
  const out = await run({ fetchImpl: fetchStub({ salt: () => json({ authVersion: 2, authSalt: SALT }) }), createClientImpl: supabaseStub() })
  assert.equal(out.accessToken, 'AAL1')
  assert.deepEqual(leaks(), [])
  const login = wire.find((r) => r.url.endsWith('/api/mobile/auth/login'))
  assert.deepEqual(Object.keys(JSON.parse(login.body)).sort(), ['email', 'loginSecret'])
})

test('version 2: MFA step-up', async () => {
  const out = await run({ fetchImpl: fetchStub({ salt: () => json({ authVersion: 2, authSalt: SALT }) }), createClientImpl: supabaseStub({ mfa: true }) })
  assert.equal(out.accessToken, 'AAL2')
  assert.equal(out.refreshToken, 'R2')
  assert.ok(wire.some((r) => r.via === 'supabase.mfa.verify'))
  assert.deepEqual(leaks(), [])
})

test('version 2: login refused (401) and throttled (429)', async () => {
  for (const [status, message] of [[401, /Sign-in failed/], [429, /Too many/]]) {
    wire.length = 0
    await assert.rejects(run({
      fetchImpl: fetchStub({ salt: () => json({ authVersion: 2, authSalt: SALT }), login: () => json({ error: 'x' }, status) }),
      createClientImpl: supabaseStub(),
    }), message)
    assert.deepEqual(leaks(), [])
  }
})

test('version 2: login route unreachable', async () => {
  await assert.rejects(run({
    fetchImpl: fetchStub({ salt: () => json({ authVersion: 2, authSalt: SALT }), login: () => { throw new TypeError('fetch failed') } }),
    createClientImpl: supabaseStub(),
  }), /could not reach/)
  assert.deepEqual(leaks(), [])
})

test('salt lookup failures abort before any credential is posted', async () => {
  const failures = {
    'network error': () => { throw new TypeError('fetch failed') },
    'HTTP 403': () => json({ error: 'forbidden' }, 403),
    'HTTP 429': () => json({ error: 'slow down' }, 429),
    'HTTP 500': () => json({ error: 'boom' }, 500),
    'HTTP 503 no body': () => new Response('upstream', { status: 503 }),
    'non-JSON 200': () => new Response('<html>', { status: 200 }),
    'unknown version': () => json({ authVersion: 3, authSalt: SALT }),
    'version as string': () => json({ authVersion: '1', authSalt: SALT }),
    'missing version': () => json({ authSalt: SALT }),
    'missing salt': () => json({ authVersion: 2 }),
  }
  for (const [name, salt] of Object.entries(failures)) {
    wire.length = 0
    await assert.rejects(run({ fetchImpl: fetchStub({ salt }), createClientImpl: supabaseStub() }), undefined, name)
    assert.deepEqual(leaks(), [], name)
    assert.ok(!wire.some((r) => r.url.endsWith('/api/mobile/auth/login')), `${name}: login route must not be called`)
    assert.ok(!wire.some((r) => r.via.startsWith('supabase')), `${name}: no Supabase client`)
  }
})

test('version 1: the password goes ONLY to the login route, never to Supabase or the salt lookup', async () => {
  for (const migrationEnabled of [true, false]) {
    wire.length = 0
    await run({
      fetchImpl: fetchStub({ salt: () => json({ authVersion: 1, authSalt: SALT, migrationEnabled }) }),
      createClientImpl: supabaseStub({ mfa: true }),
    })
    const leaked = leaks()
    assert.equal(leaked.length, 1, `migrationEnabled=${migrationEnabled}`)
    assert.equal(leaked[0].url, `${API}/api/mobile/auth/login`)
    const body = JSON.parse(leaked[0].body)
    assert.deepEqual(Object.keys(body).sort(),
      migrationEnabled ? ['authSalt', 'email', 'loginSecret', 'password'] : ['email', 'password'])
  }
})

test('Supabase signInWithPassword and the global fetch are never used', async () => {
  await run({ fetchImpl: fetchStub({ salt: () => json({ authVersion: 2, authSalt: SALT }) }), createClientImpl: supabaseStub({ mfa: true }) })
  assert.ok(!wire.some((r) => r.via === 'supabase.signInWithPassword'))
  assert.ok(!wire.some((r) => r.via === 'global fetch'))
})
