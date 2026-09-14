// ShieldFive CLI — where the agent keeps its socket, ledger and device id.
//
// The socket directory is the agent's only access control. Node exposes no
// SO_PEERCRED, so the agent cannot see which process connected; what stops
// another local user is that they cannot enter the directory. That makes the
// checks here load-bearing, and it is why the agent refuses to start in a
// directory it does not own or that anyone else can reach, rather than
// quietly tightening the mode and carrying on.

import { randomUUID } from 'node:crypto'
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const SOCKET_NAME = 'agent.sock'

export class UnsafeDirectoryError extends Error {
  constructor(message) {
    super(message)
    this.name = 'UnsafeDirectoryError'
  }
}

/** The directory holding the agent socket for this user and platform. */
export function agentDir({
  env = process.env,
  platform = process.platform,
  home = homedir(),
} = {}) {
  if (platform === 'win32') {
    throw new Error(
      'sf agent does not run on Windows yet: named pipes have a different ' +
        'permission model and it has not been designed. Use SF_EMAIL and ' +
        'SF_PASSWORD with sf push / sf sync instead.',
    )
  }
  // Linux: tmpfs owned by the user and removed when their session ends.
  if (platform === 'linux' && env.XDG_RUNTIME_DIR) {
    return join(env.XDG_RUNTIME_DIR, 'shieldfive')
  }
  // macOS gives every user a private $TMPDIR under /var/folders.
  if (platform === 'darwin' && env.TMPDIR) {
    return join(env.TMPDIR, 'shieldfive-agent')
  }
  return join(home, '.shieldfive', 'run')
}

export function socketPath(options) {
  return join(agentDir(options), SOCKET_NAME)
}

export function shieldfiveHome(home = homedir()) {
  return join(home, '.shieldfive')
}

export function ledgerDir(home = homedir()) {
  return join(shieldfiveHome(home), 'ledger')
}

/**
 * Create `dir` if needed, then refuse unless it is a real directory owned by
 * this user with no group or other permission bits.
 */
export async function ensurePrivateDir(dir, { uid = process.getuid?.() } = {}) {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  return assertPrivateDir(dir, { uid })
}

export async function assertPrivateDir(dir, { uid = process.getuid?.() } = {}) {
  const st = await lstat(dir)
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new UnsafeDirectoryError(
      `${dir} is not a real directory. The agent will not follow a link to ` +
        'decide where its socket lives.',
    )
  }
  if (uid !== undefined && st.uid !== uid) {
    throw new UnsafeDirectoryError(
      `${dir} is owned by uid ${st.uid}, not by you (uid ${uid}). Remove it ` +
        'and run sf login again.',
    )
  }
  if ((st.mode & 0o077) !== 0) {
    throw new UnsafeDirectoryError(
      `${dir} is accessible to other users (mode ` +
        `${(st.mode & 0o777).toString(8)}). Run: chmod 700 '${dir}'`,
    )
  }
  return dir
}

/**
 * A random identifier for this installation, created on first use.
 *
 * Not a secret. It lets a ledger entry say which machine an upload came from,
 * so a ledger copied to another computer does not vouch for files there.
 */
export async function deviceId(home = homedir()) {
  const dir = shieldfiveHome(home)
  await ensurePrivateDir(dir)
  const file = join(dir, 'device.json')

  const read = async () => {
    const parsed = JSON.parse(await readFile(file, 'utf8'))
    if (typeof parsed?.id !== 'string' || !/^[0-9a-f-]{36}$/i.test(parsed.id)) {
      throw new Error(`${file} does not hold a valid device id`)
    }
    return parsed.id
  }

  try {
    return await read()
  } catch (err) {
    if (err.code !== 'ENOENT') throw err
  }

  const id = randomUUID()
  try {
    await writeFile(file, JSON.stringify({ id }) + '\n', { mode: 0o600, flag: 'wx' })
    return id
  } catch (err) {
    // Another sf process created it first; theirs wins.
    if (err.code === 'EEXIST') return read()
    throw err
  }
}
