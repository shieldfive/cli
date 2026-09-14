// VERIFIED (offline): the session handoff from `sf login` to the agent, and the
// token helpers the agent relies on to stay signed in and to sign out.

import assert from 'node:assert/strict'
import { Readable } from 'node:stream'
import { test } from 'node:test'

import { readHandoff } from '../src/agent/main.mjs'
import { refreshAccessToken, revokeSession } from '../src/auth.mjs'

const config = { apiBaseUrl: 'https://a.test', supabaseUrl: 'https://s.test', anonKey: 'anon' }
const key32 = Buffer.alloc(32, 7).toString('base64')
const stream = (text) => Readable.from([text])

test('readHandoff accepts a well-formed handoff', async () => {
  const h = await readHandoff(stream(JSON.stringify({ session: { userId: 'u' }, rootKey: key32, config, idleMs: 1000 })))
  assert.equal(h.rootKey.length, 32)
  assert.equal(h.idleMs, 1000)
  assert.deepEqual(h.config, config)
})

test('readHandoff refuses a missing or short key, missing config, bad JSON and oversized input', async () => {
  await assert.rejects(readHandoff(stream(JSON.stringify({ rootKey: 'AAAA', config }))), /32-byte/)
  await assert.rejects(readHandoff(stream(JSON.stringify({ rootKey: key32, config: { ...config, anonKey: '' } }))), /anonKey/)
  await assert.rejects(readHandoff(stream('{not json')), /not valid JSON/)
  await assert.rejects(readHandoff(stream('x'.repeat(70_000))), /too large/)
})

function recordingFetch(response) {
  const calls = []
  const fn = async (url, init) => {
    calls.push({ url: String(url), init })
    return response
  }
  return { calls, fn }
}

test('refreshAccessToken rotates tokens and sends only the refresh token', async () => {
  const f = recordingFetch({
    ok: true,
    status: 200,
    json: async () => ({ access_token: 'at2', refresh_token: 'rt2', expires_at: 123, user: { id: 'u1' } }),
  })
  const s = await refreshAccessToken({ supabaseUrl: 'https://s.test', anonKey: 'anon', refreshToken: 'rt1', fetchImpl: f.fn })
  assert.deepEqual(s, { accessToken: 'at2', refreshToken: 'rt2', expiresAt: 123, userId: 'u1' })
  assert.equal(f.calls[0].url, 'https://s.test/auth/v1/token?grant_type=refresh_token')
  assert.equal(f.calls[0].init.headers.apikey, 'anon')
  assert.equal(f.calls[0].init.headers.Authorization, undefined)
  assert.deepEqual(JSON.parse(f.calls[0].init.body), { refresh_token: 'rt1' })
})

test('refreshAccessToken carries the HTTP status on failure so the agent can tell revoked from offline', async () => {
  const f = recordingFetch({ ok: false, status: 400, json: async () => ({ error_description: 'Invalid Refresh Token: Already Used' }) })
  await assert.rejects(
    refreshAccessToken({ supabaseUrl: 'https://s.test', anonKey: 'anon', refreshToken: 'rt1', fetchImpl: f.fn }),
    (e) => e.status === 400 && /Already Used/.test(e.message),
  )
  await assert.rejects(
    refreshAccessToken({ supabaseUrl: 'https://s.test', anonKey: 'anon', refreshToken: null, fetchImpl: f.fn }),
    /No refresh token/,
  )
})

test('revokeSession signs out this session only, with the bearer token', async () => {
  const f = recordingFetch({ ok: true, status: 204, json: async () => ({}) })
  assert.deepEqual(await revokeSession({ supabaseUrl: 'https://s.test', anonKey: 'anon', accessToken: 'at1', fetchImpl: f.fn }), {
    revoked: true,
    status: 204,
  })
  assert.equal(f.calls[0].url, 'https://s.test/auth/v1/logout?scope=local')
  assert.equal(f.calls[0].init.headers.Authorization, 'Bearer at1')

  const none = recordingFetch({})
  assert.deepEqual(await revokeSession({ supabaseUrl: 'https://s.test', anonKey: 'anon', accessToken: null, fetchImpl: none.fn }), {
    revoked: false,
    status: 0,
  })
  assert.equal(none.calls.length, 0)
})
