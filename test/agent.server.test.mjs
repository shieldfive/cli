// VERIFIED (offline): the agent end to end over a real Unix socket, with the
// network and the upload pipeline stubbed. What matters most is pinned here: no
// response carries key material, verification fails closed, a file that changes
// mid-upload is never recorded, concurrent requests share one token refresh, and
// logout revokes the session and removes the socket.

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { mkdtemp, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'

import { AgentUnavailableError, request } from '../src/agent/client.mjs'
import { readEntries, ledgerPath } from '../src/agent/ledger.mjs'
import { ledgerDir } from '../src/agent/paths.mjs'
import { createAgent } from '../src/agent/server.mjs'

const ACCOUNT = '3f0b2c9e-1d4a-4b6f-9c2e-7a8d5e6f1a2b'

// Unix socket paths are capped near 104 bytes on macOS, and os.tmpdir() there is
// already half of that, so sockets live under /tmp.
async function harness({ idleMs = 60_000, expiresInSec = 3600, verified = new Set(), verifyStatus = 200, uploadHook } = {}) {
  const home = await mkdtemp('/tmp/sfa-home-')
  const runDir = await mkdtemp('/tmp/sfa-run-')
  const socket = join(runDir, 'agent.sock')
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))

  const calls = { refresh: 0, logout: [], verify: [], uploads: [] }
  let nextAccess = 1

  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url)
    const json = (status, body) => ({ status, ok: status >= 200 && status < 300, json: async () => body })
    if (u.pathname === '/auth/v1/token') {
      calls.refresh++
      await new Promise((r) => setTimeout(r, 30))
      nextAccess++
      return json(200, {
        access_token: `at-${nextAccess}`,
        refresh_token: `rt-${nextAccess}`,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      })
    }
    if (u.pathname === '/auth/v1/logout') {
      calls.logout.push(init.headers.Authorization)
      return { status: 204, ok: true, json: async () => ({}) }
    }
    if (u.pathname === '/api/mobile/media/verify') {
      const { fileIds } = JSON.parse(init.body)
      calls.verify.push({ auth: init.headers.Authorization, fileIds })
      if (verifyStatus !== 200) return json(verifyStatus, { code: 'boom' })
      return json(200, { verified: fileIds.filter((id) => verified.has(id)), missing: [] })
    }
    throw new Error(`unexpected fetch ${url}`)
  }

  let n = 0
  const uploadFile = async (args) => {
    calls.uploads.push({ ...args, rootKey: Buffer.from(args.rootKey).toString('hex') })
    if (uploadHook) await uploadHook(args)
    n++
    return { fileId: `file-${n}` }
  }

  const agent = createAgent({
    session: { accessToken: 'at-1', refreshToken: 'rt-1', expiresAt: Math.floor(Date.now() / 1000) + expiresInSec, userId: ACCOUNT },
    rootKey,
    config: { apiBaseUrl: 'https://api.test', supabaseUrl: 'https://sb.test', anonKey: 'anon' },
    socket,
    home,
    device: '00000000-0000-4000-8000-000000000000',
    idleMs,
    uploadFile,
    fetchImpl,
  })
  await agent.start()

  const call = (op, args) => request(op, args, { path: socket, timeoutMs: 5_000 })
  const ledger = async () => (await readEntries(ledgerPath(ledgerDir(home), ACCOUNT))).entries
  const file = async (name, content) => {
    const p = join(home, name)
    await writeFile(p, content)
    return p
  }
  return { agent, socket, home, rootKey, calls, call, ledger, file, verified }
}

async function eventually(check, ms = 2_000) {
  const until = Date.now() + ms
  for (;;) {
    if (await check()) return
    if (Date.now() > until) throw new Error('condition not met in time')
    await new Promise((r) => setTimeout(r, 25))
  }
}

test('status answers over the socket; socket is 0600 inside a 0700 directory', async () => {
  const h = await harness()
  try {
    const s = await h.call('status')
    assert.equal(s.unlocked, true)
    assert.equal(s.account, ACCOUNT)
    assert.equal((await stat(h.socket)).mode & 0o777, 0o600)
    assert.equal((await stat(join(h.socket, '..'))).mode & 0o777, 0o700)
  } finally {
    await h.agent.stop('test')
  }
})

test('upload records a ledger entry and no response ever contains key material', async () => {
  const h = await harness()
  try {
    const p = await h.file('a.txt', 'alpha')
    const result = await h.call('upload', { path: p })
    assert.deepEqual(Object.keys(result).sort(), ['fileId', 'recorded', 'size'])
    assert.equal(result.recorded, true)

    const [entry] = await h.ledger()
    assert.equal(entry.path, p)
    assert.equal(entry.fileId, result.fileId)
    assert.match(entry.mac, /^[0-9a-f]{64}$/)

    const keyHex = Buffer.from(h.rootKey).toString('hex')
    const keyB64 = Buffer.from(h.rootKey).toString('base64')
    assert.equal(h.calls.uploads[0].rootKey, keyHex, 'uploadFile received the real key')
    for (const op of ['status', 'verify']) {
      const text = JSON.stringify(await h.call(op, op === 'verify' ? { paths: [p] } : {}))
      assert.ok(!text.includes(keyHex) && !text.includes(keyB64), `${op} response leaked the root key`)
      assert.ok(!text.includes(entry.mac), `${op} response leaked a ledger MAC`)
    }
  } finally {
    await h.agent.stop('test')
  }
})

test('verify: verified, missing and not_in_ledger come from ledger plus server, never from names', async () => {
  const h = await harness()
  try {
    const kept = await h.file('kept.txt', 'kept bytes')
    const binned = await h.file('binned.txt', 'binned bytes')
    const never = await h.file('never.txt', 'never uploaded')
    const { fileId: keptId } = await h.call('upload', { path: kept })
    await h.call('upload', { path: binned })
    h.verified.add(keptId)

    const results = await h.call('verify', { paths: [kept, binned, never] })
    assert.deepEqual(results.map((r) => r.state), ['verified', 'missing', 'not_in_ledger'])
  } finally {
    await h.agent.stop('test')
  }
})

test('verify fails closed when the server cannot verify', async () => {
  const h = await harness({ verifyStatus: 503 })
  try {
    const p = await h.file('a.txt', 'alpha')
    await h.call('upload', { path: p })
    await assert.rejects(() => h.call('verify', { paths: [p] }), (e) => e.code === 'verify_failed')
  } finally {
    await h.agent.stop('test')
  }
})

test('a file that changes during upload is not recorded as a backup', async () => {
  const h = await harness({
    uploadHook: async ({ path }) => {
      await writeFile(path, 'edited while uploading')
    },
  })
  try {
    const p = await h.file('a.txt', 'original')
    const result = await h.call('upload', { path: p })
    assert.equal(result.recorded, false)
    assert.equal(result.reason, 'changed_during_upload')
    assert.deepEqual(await h.ledger(), [])
    const [r] = await h.call('verify', { paths: [p] })
    assert.equal(r.state, 'not_in_ledger')
  } finally {
    await h.agent.stop('test')
  }
})

test('sync uploads new files, skips unchanged ones, and re-uploads edits', async () => {
  const h = await harness()
  try {
    const folder = await mkdtemp('/tmp/sfa-sync-')
    await writeFile(join(folder, 'one.txt'), '1')
    await writeFile(join(folder, 'two.txt'), '2')
    await writeFile(join(folder, '.hidden'), 'skip me')

    assert.deepEqual(await h.call('sync', { folder }), { uploaded: 2, skipped: 0, failed: 0, errors: [] })
    assert.deepEqual(await h.call('sync', { folder }), { uploaded: 0, skipped: 2, failed: 0, errors: [] })
    await writeFile(join(folder, 'two.txt'), '2 edited')
    assert.deepEqual(await h.call('sync', { folder }), { uploaded: 1, skipped: 1, failed: 0, errors: [] })
  } finally {
    await h.agent.stop('test')
  }
})

test('concurrent requests at an expired token share ONE refresh and use the new token', async () => {
  const h = await harness({ expiresInSec: -10 })
  try {
    const p = await h.file('a.txt', 'alpha')
    await h.call('upload', { path: p })
    assert.equal(h.calls.refresh, 1)

    await Promise.all([1, 2, 3].map(() => h.call('verify', { paths: [p] })))
    assert.equal(h.calls.refresh, 1, 'a rotated refresh token must never be presented twice')
    assert.ok(h.calls.verify.every((v) => v.auth === 'Bearer at-2'))
  } finally {
    await h.agent.stop('test')
  }
})

test('an unknown operation is refused and the agent keeps running', async () => {
  const h = await harness()
  try {
    await assert.rejects(() => h.call('download', { path: '/x' }), (e) => e.code === 'unknown_op')
    assert.equal((await h.call('status')).unlocked, true)
  } finally {
    await h.agent.stop('test')
  }
})

test('logout revokes the session, removes the socket, and further requests find no agent', async () => {
  const h = await harness()
  const result = await h.call('logout')
  assert.equal(result.loggedOut, true)
  assert.equal(result.sessionRevoked, true)
  assert.deepEqual(h.calls.logout, ['Bearer at-1'])
  await eventually(async () => {
    try {
      await stat(h.socket)
      return false
    } catch {
      return true
    }
  })
  await assert.rejects(() => h.call('status'), (e) => e instanceof AgentUnavailableError)
})

test('the agent locks itself after the idle period and revokes the session', async () => {
  const h = await harness({ idleMs: 150 })
  await eventually(() => h.agent.stopped, 3_000)
  await eventually(() => h.calls.logout.length === 1, 3_000)
  await assert.rejects(() => h.call('status'), (e) => e instanceof AgentUnavailableError)
})

test('a second agent on the same socket refuses to start; a stale socket file does not block', async () => {
  const h = await harness()
  const clash = createAgent({
    session: { accessToken: 'x', refreshToken: 'y', expiresAt: Math.floor(Date.now() / 1000) + 3600, userId: ACCOUNT },
    rootKey: webcrypto.getRandomValues(new Uint8Array(32)),
    config: { apiBaseUrl: 'https://api.test', supabaseUrl: 'https://sb.test', anonKey: 'anon' },
    socket: h.socket,
    home: h.home,
    device: 'd',
    uploadFile: async () => ({ fileId: 'z' }),
    fetchImpl: async () => ({ status: 204, ok: true, json: async () => ({}) }),
  })
  await assert.rejects(() => clash.start(), (e) => e.code === 'already_running')
  await h.agent.stop('test')

  // The first agent removed its socket; leave a dead file there and start again.
  await writeFile(h.socket, '')
  await clash.start()
  assert.equal((await request('status', {}, { path: h.socket })).unlocked, true)
  await clash.stop('test')
})

test('refuses to start without a refresh token for the stepped-up session', () => {
  assert.throws(
    () =>
      createAgent({
        session: { accessToken: 'x', refreshToken: null, userId: ACCOUNT },
        rootKey: new Uint8Array(32),
        config: {},
        socket: '/tmp/x',
        home: '/tmp',
        uploadFile: async () => ({}),
      }),
    (e) => e.code === 'no_refresh_token',
  )
})
