// Downgrade pin (audit 2026-10-02, Batch R): once this computer has signed in
// to an account with a login secret, a server "version 1" answer for it must
// not make the CLI send the raw password, unless --allow-legacy-login.
import assert from 'node:assert/strict'
import { mkdtemp, readFile, stat, writeFile, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { signIn } from '../src/auth.mjs'
import { AUTH_PIN_FILE, fileAuthPin, LegacyLoginRefusedError } from '../src/authPin.mjs'
import { buildSignInCredentials } from '../src/loginSecret.mjs'

const password = 'correct horse battery staple 42'
const salt = Buffer.alloc(32, 7).toString('base64')
const email = 'qa@example.test'
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const tempHome = () => mkdtemp(join(tmpdir(), 'sf-pin-'))

function fakeServer(saltAnswer) {
  const requests = []
  const fetchImpl = async (url, options) => {
    requests.push({ url: String(url), body: JSON.parse(options.body) })
    return String(url).endsWith('/salt')
      ? json(saltAnswer())
      : json({ accessToken: 'ACCESS', refreshToken: 'REFRESH' })
  }
  return { requests, fetchImpl }
}

const createClientImpl = () => ({
  auth: {
    setSession: async () => ({
      data: { session: { access_token: 'ACCESS', refresh_token: 'REFRESH', user: { id: 'U' } } },
      error: null,
    }),
    mfa: {
      getAuthenticatorAssuranceLevel: async () => ({
        data: { currentLevel: 'aal1', nextLevel: 'aal1' }, error: null,
      }),
    },
  },
})

const base = { apiBaseUrl: 'https://api.test', supabaseUrl: 'https://s.test', anonKey: 'PUBLIC', email, password, createClientImpl }

test('pin file is 0600 in a 0700 directory and holds no plaintext email', async () => {
  const home = await tempHome()
  const pin = fileAuthPin({ home })
  assert.equal(await pin.isPinned(email), false)
  await pin.pin(email)
  await pin.pin(email) // idempotent
  assert.equal(await pin.isPinned('  QA@Example.TEST '), true)
  assert.equal(await pin.isPinned('other@example.test'), false)
  assert.equal((await stat(pin.file)).mode & 0o777, 0o600)
  assert.equal((await stat(join(home, '.shieldfive'))).mode & 0o777, 0o700)
  const raw = await readFile(pin.file, 'utf8')
  assert.ok(!raw.includes('example'), 'email must not be stored in plaintext')
  assert.equal(JSON.parse(raw).v2.length, 1)
})

test('a corrupt pin file reads as empty and is replaced on the next pin', async () => {
  const home = await tempHome()
  await mkdir(join(home, '.shieldfive'), { mode: 0o700 })
  await writeFile(join(home, '.shieldfive', AUTH_PIN_FILE), 'not json', { mode: 0o644 })
  const pin = fileAuthPin({ home })
  assert.equal(await pin.isPinned(email), false)
  await pin.pin(email)
  assert.equal(await pin.isPinned(email), true)
  assert.equal((await stat(pin.file)).mode & 0o777, 0o600)
})

test('a version-2 sign-in pins the account', async () => {
  const home = await tempHome()
  const authPin = fileAuthPin({ home })
  const { fetchImpl } = fakeServer(() => ({ authVersion: 2, authSalt: salt }))
  await signIn({ ...base, fetchImpl, authPin })
  assert.equal(await authPin.isPinned(email), true)
})

test('a version-1 sign-in does not pin', async () => {
  const home = await tempHome()
  const authPin = fileAuthPin({ home })
  const { fetchImpl } = fakeServer(() => ({ authVersion: 1, authSalt: salt, migrationEnabled: false }))
  await signIn({ ...base, fetchImpl, authPin })
  assert.equal(await authPin.isPinned(email), false)
})

test('pinned account: a version-1 answer is refused before the password is posted', async () => {
  const home = await tempHome()
  const authPin = fileAuthPin({ home })
  await authPin.pin(email)
  for (const migrationEnabled of [false, true]) {
    const { requests, fetchImpl } = fakeServer(() => ({ authVersion: 1, authSalt: salt, migrationEnabled }))
    await assert.rejects(signIn({ ...base, fetchImpl, authPin }), LegacyLoginRefusedError)
    assert.equal(requests.length, 1, 'only the salt lookup may go out')
    assert.ok(!JSON.stringify(requests).includes(password))
  }
})

test('pinned account: --allow-legacy-login lets a version-1 sign-in through', async () => {
  const home = await tempHome()
  const authPin = fileAuthPin({ home })
  await authPin.pin(email)
  const { requests, fetchImpl } = fakeServer(() => ({ authVersion: 1, authSalt: salt, migrationEnabled: false }))
  await signIn({ ...base, fetchImpl, authPin, allowLegacyLogin: true })
  assert.deepEqual(requests[1].body, { email, password })
  // The pin stays: one consented downgrade does not disarm the next refusal.
  assert.equal(await authPin.isPinned(email), true)
})

test('pinned account: a version-2 answer still signs in normally', async () => {
  const home = await tempHome()
  const authPin = fileAuthPin({ home })
  await authPin.pin(email)
  const { requests, fetchImpl } = fakeServer(() => ({ authVersion: 2, authSalt: salt }))
  await signIn({ ...base, fetchImpl, authPin })
  assert.equal(requests.length, 2)
  assert.ok(!('password' in requests[1].body))
})

test('buildSignInCredentials refuses version 1 for a pinned account', async () => {
  const fetchImpl = async () => json({ authVersion: 1, authSalt: salt, migrationEnabled: false })
  await assert.rejects(
    buildSignInCredentials({ apiBaseUrl: 'https://api.test', email, password, fetchImpl, pinnedV2: true }),
    { code: 'legacy_login_refused' },
  )
  assert.deepEqual(
    await buildSignInCredentials({ apiBaseUrl: 'https://api.test', email, password, fetchImpl, pinnedV2: true, allowLegacyLogin: true }),
    { password },
  )
})
