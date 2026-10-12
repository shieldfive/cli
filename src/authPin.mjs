// "This account signs in with a login secret" -- remembered on this computer.
//
// /api/auth/salt is the server telling the CLI how to sign in: version 2 means
// send only the derived login secret, version 1 means send the raw password.
// A server that has been tampered with (or an account a stolen session
// downgraded) can answer version 1 for an account that is really version 2,
// and a CLI that obeys sends the raw password -- the one thing version 2
// promises never leaves this machine. The mobile app and the web already pin;
// this is the CLI's pin.
//
// Once a sign-in has gone through with the server saying version 2, the
// account is recorded here. Afterwards a version-1 answer for it is refused
// unless the user passes --allow-legacy-login.
//
// File: ~/.shieldfive/auth-pins.json, mode 0600 in a 0700 directory. It holds
// SHA-256 hashes of lower-cased email addresses, not the addresses, so the file
// does not list which accounts this computer uses.

import { createHash } from 'node:crypto'
import { chmod, readFile, rename, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'

import { ensurePrivateDir, shieldfiveHome } from './agent/paths.mjs'

export const AUTH_PIN_FILE = 'auth-pins.json'

export class LegacyLoginRefusedError extends Error {
  constructor() {
    super(
      'Refusing to sign in: this computer has signed in to this account with a ' +
        'login secret before, but the server now asks for the raw password ' +
        '(auth version 1). That should not happen to an account that has moved ' +
        'to version 2, so the password was not sent. If you know why (for ' +
        'example ShieldFive support reset the account), run the command again ' +
        'with --allow-legacy-login.',
    )
    this.name = 'LegacyLoginRefusedError'
    this.code = 'legacy_login_refused'
  }
}

function emailKey(email) {
  return createHash('sha256')
    .update(String(email ?? '').trim().toLowerCase())
    .digest('hex')
}

/**
 * The pin store backed by ~/.shieldfive/auth-pins.json. `home` is injectable
 * for tests. A file that cannot be read as a pin list is treated as holding
 * no pins for reads, and is replaced on the next write.
 */
export function fileAuthPin({ home = homedir() } = {}) {
  const dir = shieldfiveHome(home)
  const file = join(dir, AUTH_PIN_FILE)

  const readKeys = async () => {
    let raw
    try {
      raw = await readFile(file, 'utf8')
    } catch (err) {
      if (err.code === 'ENOENT') return []
      throw err
    }
    try {
      const parsed = JSON.parse(raw)
      return Array.isArray(parsed?.v2)
        ? parsed.v2.filter((k) => typeof k === 'string' && /^[0-9a-f]{64}$/.test(k))
        : []
    } catch {
      return []
    }
  }

  return {
    file,
    async isPinned(email) {
      return (await readKeys()).includes(emailKey(email))
    },
    async pin(email) {
      await ensurePrivateDir(dir)
      const keys = await readKeys()
      const key = emailKey(email)
      if (keys.includes(key)) return
      keys.push(key)
      // Write-then-rename so a crash never leaves a half-written file, and
      // chmod after rename in case an older file had looser bits.
      const tmp = `${file}.${process.pid}.tmp`
      await writeFile(tmp, JSON.stringify({ v2: keys }) + '\n', { mode: 0o600 })
      await rename(tmp, file)
      await chmod(file, 0o600)
    },
  }
}
