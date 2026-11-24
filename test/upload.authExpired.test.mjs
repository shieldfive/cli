// Gate: an expired or revoked token must produce an actionable message, not a
// bare "HTTP 401" (a customer saw "Get upload credentials failed (HTTP 401)").
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { responseError } from '../src/upload.mjs'

const res = (status) => ({ status, headers: new Headers() })

test('401 from any upload step tells the user to sign in again', () => {
  for (const op of ['Create upload session', 'Get upload credentials', 'Complete upload']) {
    const err = responseError(op, res(401), { code: 'invalid_token' })
    assert.equal(err.status, 401)
    assert.match(err.message, /sign-in expired or was revoked/)
    assert.match(err.message, /sf login/)
  }
})

test('a 401 that is really MFA keeps the MFA guidance', () => {
  assert.match(responseError('Get upload credentials', res(401), { code: 'mfa_required' }).message, /Two-factor/)
})
