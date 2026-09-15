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

export class UnsupportedPlatformError extends Error {
  constructor(message) {
    super(message)
    this.name = 'UnsupportedPlatformError'
    this.code = 'unsupported_platform'
  }
}

/**
 * The directory holding the agent socket: always ~/.shieldfive/run.
 *
 * An earlier version preferred $XDG_RUNTIME_DIR on Linux and $TMPDIR on macOS.
 * Cron jobs and `env -i` shells set neither, so `sf sync` run from cron looked
 * in a different directory from the one `sf login` used, reported that no agent
 * was running, and fell back to asking for a password. Unattended sync is the
 * reason the agent exists, so every process the user runs has to find it in the
 * same place.
 */
export function agentDir({ platform = process.platform, home = homedir() } = {}) {
  if (platform === 'win32') {
    throw new UnsupportedPlatformError(
      'sf agent does not run on Windows yet: named pipes have a different ' +
        'permission model and it has not been designed. Use SF_EMAIL and ' +
        'SF_PASSWORD with sf push / sf sync instead.',
    )
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
 * Not a secret. Every ledger record carries it, and `verify` only counts
 * records made on this device, so a ledger copied from another computer does
 * not vouch for files here.
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
