// VERIFIED (offline): where the agent keeps its socket, and the directory checks
// that are its only access control.

import assert from 'node:assert/strict'
import { chmod, lstat, mkdir, mkdtemp, readFile, stat, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  UnsafeDirectoryError,
  UnsupportedPlatformError,
  agentDir,
  assertPrivateDir,
  deviceId,
  ensurePrivateDir,
} from '../src/agent/paths.mjs'

async function tmp() {
  return mkdtemp(join(tmpdir(), 'sf-cli-paths-'))
}

test('agentDir is ~/.shieldfive/run on every POSIX platform, whatever the environment says', () => {
  // A cron job or an `env -i` shell has no TMPDIR or XDG_RUNTIME_DIR. If the
  // location depended on either, unattended sync would look in the wrong place.
  for (const platform of ['linux', 'darwin', 'freebsd']) {
    assert.equal(agentDir({ platform, home: '/home/u' }), '/home/u/.shieldfive/run')
  }
  assert.equal(
    agentDir({ platform: 'darwin', home: '/Users/u', env: { TMPDIR: '/var/folders/x/T/', XDG_RUNTIME_DIR: '/run/user/1' } }),
    '/Users/u/.shieldfive/run',
  )
})

test('agentDir on Windows throws an error callers can recognise', () => {
  assert.throws(
    () => agentDir({ platform: 'win32', home: 'C:\\u' }),
    (e) => e instanceof UnsupportedPlatformError && e.code === 'unsupported_platform',
  )
})

test('ensurePrivateDir creates a 0700 directory', async () => {
  const dir = join(await tmp(), 'nested', 'agent')
  await ensurePrivateDir(dir)
  assert.equal((await stat(dir)).mode & 0o777, 0o700)
})

test('assertPrivateDir refuses a directory other users can enter', async () => {
  const dir = await tmp()
  await chmod(dir, 0o755)
  await assert.rejects(() => assertPrivateDir(dir), (e) => e instanceof UnsafeDirectoryError && /chmod 700/.test(e.message))
})

test('assertPrivateDir refuses a symlink, even to a private directory', async () => {
  const base = await tmp()
  const real = join(base, 'real')
  await mkdir(real, { mode: 0o700 })
  const link = join(base, 'link')
  await symlink(real, link)
  await assert.rejects(() => assertPrivateDir(link), /not a real directory/)
})

test('assertPrivateDir refuses a directory owned by someone else', async () => {
  const dir = await tmp()
  await chmod(dir, 0o700)
  const { uid } = await lstat(dir)
  await assert.rejects(() => assertPrivateDir(dir, { uid: uid + 1 }), /owned by uid/)
})

test('deviceId is created once, is stable, and is written 0600', async () => {
  const home = await tmp()
  const first = await deviceId(home)
  assert.match(first, /^[0-9a-f-]{36}$/)
  assert.equal(await deviceId(home), first)

  const file = join(home, '.shieldfive', 'device.json')
  assert.equal((await stat(file)).mode & 0o777, 0o600)
  assert.equal(JSON.parse(await readFile(file, 'utf8')).id, first)
  assert.equal((await stat(join(home, '.shieldfive'))).mode & 0o777, 0o700)
})
