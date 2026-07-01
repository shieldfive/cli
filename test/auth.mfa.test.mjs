// VERIFIED (offline): the 2FA step-up decision + TOTP challenge/verify flow.
// The real Supabase interaction is exercised live; here we mock the client to
// prove the CLI calls challenge/verify with the right arguments, elevates to the
// AAL2 token on success, and fails clearly on every error path. A regression
// here means 2FA accounts silently can't upload.

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { stepUpMfaIfRequired } from '../src/auth.mjs'

// Minimal Supabase-shaped stub. Each auth.mfa method returns a { data, error }
// pair from the provided fixtures and records its call args.
function mockSupabase(fixtures) {
  const calls = { challenge: [], verify: [], listFactors: 0, aal: 0 }
  return {
    calls,
    auth: {
      mfa: {
        getAuthenticatorAssuranceLevel: async () => {
          calls.aal += 1
          return fixtures.aal
        },
        listFactors: async () => {
          calls.listFactors += 1
          return fixtures.factors
        },
        challenge: async (args) => {
          calls.challenge.push(args)
          return fixtures.challenge
        },
        verify: async (args) => {
          calls.verify.push(args)
          return fixtures.verify
        },
      },
    },
  }
}

const ok = (data) => ({ data, error: null })
const fail = (message) => ({ data: null, error: { message } })

test('no MFA enrolled: returns null and never prompts for a code', async () => {
  const supabase = mockSupabase({ aal: ok({ currentLevel: 'aal1', nextLevel: 'aal1' }) })
  let prompted = false
  const result = await stepUpMfaIfRequired({
    supabase,
    getTotpCode: async () => {
      prompted = true
      return '000000'
    },
  })
  assert.equal(result, null)
  assert.equal(prompted, false)
  assert.equal(supabase.calls.challenge.length, 0)
  assert.equal(supabase.calls.listFactors, 0)
})

test('already AAL2: returns null (no re-challenge)', async () => {
  const supabase = mockSupabase({ aal: ok({ currentLevel: 'aal2', nextLevel: 'aal2' }) })
  const result = await stepUpMfaIfRequired({ supabase, getTotpCode: async () => '111111' })
  assert.equal(result, null)
  assert.equal(supabase.calls.challenge.length, 0)
})

test('step-up success: challenges the verified factor, verifies the code, returns AAL2 token', async () => {
  const supabase = mockSupabase({
    aal: ok({ currentLevel: 'aal1', nextLevel: 'aal2' }),
    factors: ok({
      totp: [
        { id: 'unverified-1', status: 'unverified' },
        { id: 'factor-1', status: 'verified' },
      ],
    }),
    challenge: ok({ id: 'challenge-1' }),
    verify: ok({ access_token: 'AAL2-TOKEN' }),
  })
  const token = await stepUpMfaIfRequired({
    supabase,
    getTotpCode: async () => ' 123456 ', // whitespace should be trimmed
  })
  assert.equal(token, 'AAL2-TOKEN')
  // Challenged the verified factor, not the unverified one.
  assert.deepEqual(supabase.calls.challenge, [{ factorId: 'factor-1' }])
  assert.deepEqual(supabase.calls.verify, [
    { factorId: 'factor-1', challengeId: 'challenge-1', code: '123456' },
  ])
})

test('step-up required but no code source provided: clear error, no challenge', async () => {
  const supabase = mockSupabase({ aal: ok({ currentLevel: 'aal1', nextLevel: 'aal2' }) })
  await assert.rejects(
    () => stepUpMfaIfRequired({ supabase, getTotpCode: undefined }),
    /two-factor authentication enabled/i,
  )
  assert.equal(supabase.calls.challenge.length, 0)
})

test('no verified TOTP factor: refuses rather than hanging', async () => {
  const supabase = mockSupabase({
    aal: ok({ currentLevel: 'aal1', nextLevel: 'aal2' }),
    factors: ok({ totp: [{ id: 'x', status: 'unverified' }] }),
  })
  await assert.rejects(
    () => stepUpMfaIfRequired({ supabase, getTotpCode: async () => '123456' }),
    /no verified authenticator/i,
  )
})

test('malformed code: rejected before calling verify', async () => {
  const supabase = mockSupabase({
    aal: ok({ currentLevel: 'aal1', nextLevel: 'aal2' }),
    factors: ok({ totp: [{ id: 'factor-1', status: 'verified' }] }),
    challenge: ok({ id: 'challenge-1' }),
  })
  await assert.rejects(
    () => stepUpMfaIfRequired({ supabase, getTotpCode: async () => 'not-a-code' }),
    /6-digit/,
  )
  assert.equal(supabase.calls.verify.length, 0)
})

test('wrong code (server rejects): surfaces the verify error', async () => {
  const supabase = mockSupabase({
    aal: ok({ currentLevel: 'aal1', nextLevel: 'aal2' }),
    factors: ok({ totp: [{ id: 'factor-1', status: 'verified' }] }),
    challenge: ok({ id: 'challenge-1' }),
    verify: fail('Invalid TOTP code'),
  })
  await assert.rejects(
    () => stepUpMfaIfRequired({ supabase, getTotpCode: async () => '654321' }),
    /Two-factor verification failed: Invalid TOTP code/,
  )
})

test('AAL lookup failure: fails closed with a clear message', async () => {
  const supabase = mockSupabase({ aal: fail('service down') })
  await assert.rejects(
    () => stepUpMfaIfRequired({ supabase, getTotpCode: async () => '123456' }),
    /Could not check two-factor status: service down/,
  )
})
