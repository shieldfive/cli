// VERIFIED (offline): where the agent keeps its socket, and the directory checks
// that are its only access control.

import assert from 'node:assert/strict'
import { chmod, lstat, mkdir, mkdtemp, readFile, stat, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  UnsafeDirectoryError,
  agentDir,
  assertPrivateDir,
  deviceId,
  ensurePrivateDir,
} from '../src/agent/paths.mjs'

async function tmp() {
  return mkdtemp(join(tmpdir(), 'sf-cli-paths-'))
}

test('agentDir: XDG_RUNTIME_DIR on Linux, TMPDIR on macOS, ~/.shieldfive/run otherwise', () => {
  assert.equal(
    agentDir({ platform: 'linux', env: { XDG_RUNTIME_DIR: '/run/user/1000' }, home: '/home/u' }),
    '/run/user/1000/shieldfive',
  )
  assert.equal(
    agentDir({ platform: 'darwin', env: { TMPDIR: '/var/folders/ab/T/' }, home: '/Users/u' }),
    '/var/folders/ab/T/shieldfive-agent',
  )
  assert.equal(agentDir({ platform: 'linux', env: {}, home: '/home/u' }), '/home/u/.shieldfive/run')
  assert.throws(() => agentDir({ platform: 'win32', env: {}, home: 'C:\\u' }), /Windows/)
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
