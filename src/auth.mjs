// ShieldFive CLI — authentication.
//
// Signs in via Supabase to obtain a Bearer access token. The web upload routes
// now accept this token (Track A: cookie -> Bearer), so it is what `sf push`
// will use. Same token shape the mobile app uses.
//
// NEEDS LIVE TEST: requires your real Supabase URL + anon key + account. If you
// have 2FA enabled, an AAL2 step-up is required and is NOT handled here yet
// (mirror the mobile MFA flow when you wire it).

import { createClient } from '@supabase/supabase-js'

export async function signIn({ supabaseUrl, anonKey, email, password }) {
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

  const accessToken = data.session?.access_token
  if (!accessToken) {
    throw new Error(
      'No access token returned. If 2FA is enabled, the MFA step-up is not yet ' +
        'implemented in the CLI.',
    )
  }
  return { accessToken }
}
