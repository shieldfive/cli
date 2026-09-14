// ShieldFive CLI — authentication.
//
// Signs in via Supabase to obtain a Bearer access token, elevating to AAL2 when
// the account has two-factor authentication (TOTP) enabled. The upload routes
// accept this token, and their server-side MFA gate requires an AAL2 token for
// enrolled accounts — so the step-up here is what makes `sf push` / `sf sync`
// work with 2FA on.
//
// This uses the standard Supabase MFA API (challenge + verify) directly on the
// signed-in client. The resulting AAL2 session token is what the server checks
// via getAuthenticatorAssuranceLevel.

import { createClient } from '@supabase/supabase-js'

// If the account requires an AAL2 step-up, run the TOTP challenge/verify flow
// and return the elevated access token. Returns null when no step-up is needed
// (the caller keeps the AAL1 token). `getTotpCode` is an async function that
// yields the 6-digit code; it is only invoked when a step-up is actually needed.
export async function stepUpMfaIfRequired({ supabase, getTotpCode }) {
  const { data: aal, error: aalError } =
    await supabase.auth.mfa.getAuthenticatorAssuranceLevel()
  if (aalError) {
    throw new Error(`Could not check two-factor status: ${aalError.message}`)
  }
  const needsStepUp = aal?.nextLevel === 'aal2' && aal?.currentLevel !== 'aal2'
  if (!needsStepUp) return null

  if (typeof getTotpCode !== 'function') {
    throw new Error(
      'This account has two-factor authentication enabled. Run in an ' +
        'interactive terminal, or set SF_TOTP_CODE to your current 6-digit code.',
    )
  }

  const { data: factors, error: factorsError } =
    await supabase.auth.mfa.listFactors()
  if (factorsError) {
    throw new Error(`Could not list two-factor methods: ${factorsError.message}`)
  }
  const totp = (factors?.totp ?? []).filter(
    (f) => f?.id && f?.status === 'verified',
  )
  if (totp.length === 0) {
    throw new Error(
      'Two-factor is required but no verified authenticator app (TOTP) is ' +
        'enrolled on this account. The CLI supports TOTP only.',
    )
  }
  const factorId = totp[0].id

  const { data: challenge, error: challengeError } =
    await supabase.auth.mfa.challenge({ factorId })
  if (challengeError) {
    throw new Error(
      `Could not start two-factor challenge: ${challengeError.message}`,
    )
  }

  const code = String(await getTotpCode()).trim()
  if (!/^\d{6}$/.test(code)) {
    throw new Error('Expected a 6-digit authenticator code.')
  }

  const { data: verified, error: verifyError } = await supabase.auth.mfa.verify({
    factorId,
    challengeId: challenge.id,
    code,
  })
  if (verifyError) {
    throw new Error(`Two-factor verification failed: ${verifyError.message}`)
  }
  const token = verified?.access_token
  if (!token) {
    throw new Error('Two-factor verification did not return a session token.')
  }
  return token
}

export async function signIn({
  supabaseUrl,
  anonKey,
  email,
  password,
  getTotpCode,
}) {
  const supabase = createClient(supabaseUrl, anonKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  })
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  })
  if (error) throw new Error(`Sign-in failed: ${error.message}`)

  const aal1Token = data.session?.access_token
  if (!aal1Token) {
    throw new Error('Sign-in returned no access token.')
  }

  const aal2Token = await stepUpMfaIfRequired({ supabase, getTotpCode })

  // The refresh token has to come from the session that was stepped up.
  // Refreshing the pre-step-up session mints aal1 tokens, and every upload
  // route would start answering 403 once the first access token expired.
  // supabase-js replaces its in-memory session on mfa.verify, so read it back
  // and only trust it if it is the session that produced the aal2 token. If it
  // is not, return no refresh token: the agent refuses to start rather than
  // running on a credential that will fail an hour later.
  let session = data.session
  if (aal2Token) {
    const { data: current } = await supabase.auth.getSession()
    session = current?.session?.access_token === aal2Token ? current.session : null
  }

  return {
    accessToken: aal2Token ?? aal1Token,
    refreshToken: session?.refresh_token ?? null,
    expiresAt: session?.expires_at ?? null,
    userId: session?.user?.id ?? data.user?.id ?? null,
  }
}

// Exchange a refresh token for a new session. Supabase rotates refresh tokens,
// so the caller must replace the one it holds with the one returned, and must
// never run two refreshes with the same token at once: reuse outside the
// server's short grace window revokes the whole session.
export async function refreshAccessToken({
  supabaseUrl,
  anonKey,
  refreshToken,
  fetchImpl = fetch,
}) {
  if (!refreshToken) {
    throw new Error('No refresh token is held. Run sf login again.')
  }
  const res = await fetchImpl(new URL('/auth/v1/token?grant_type=refresh_token', supabaseUrl), {
    method: 'POST',
    headers: { apikey: anonKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok || !body.access_token || !body.refresh_token) {
    const reason = body.error_description ?? body.msg ?? body.error ?? 'no session returned'
    const err = new Error(`Session refresh failed (HTTP ${res.status}): ${reason}`)
    err.status = res.status
    throw err
  }
  return {
    accessToken: body.access_token,
    refreshToken: body.refresh_token,
    expiresAt: body.expires_at ?? Math.floor(Date.now() / 1000) + (body.expires_in ?? 3600),
    userId: body.user?.id ?? null,
  }
}

// Sign this session out on the server. Sessions on the production project are
// not time-boxed, so a refresh token that is merely forgotten stays valid until
// someone revokes it; this is that revocation. `scope=local` ends only this
// session, not the user's browser or phone.
export async function revokeSession({ supabaseUrl, anonKey, accessToken, fetchImpl = fetch }) {
  if (!accessToken) return { revoked: false, status: 0 }
  const res = await fetchImpl(new URL('/auth/v1/logout?scope=local', supabaseUrl), {
    method: 'POST',
    headers: { apikey: anonKey, Authorization: `Bearer ${accessToken}` },
  })
  return { revoked: res.status === 204 || res.status === 200, status: res.status }
}
