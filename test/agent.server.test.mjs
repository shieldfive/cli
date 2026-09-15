// VERIFIED (offline): the agent end to end over a real Unix socket, with the
// network and the upload pipeline stubbed. Pinned here, most of it from a
// security review that demonstrated each case: no response carries key
// material; verification fails closed; the ledger records the MAC of the bytes
// actually uploaded, so a file changed and restored mid-upload is never
// reported backed up; concurrent requests share one token refresh; stopping
// wipes keys before the network and cannot hang; an in-flight upload keeps its
// own key; status probes do not keep the agent unlocked; and two agents cannot
// both start, or delete each other's socket.

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'

import { AgentUnavailableError, request } from '../src/agent/client.mjs'
import { appendEntry, deriveLedgerKey, ledgerPath, macFile, readEntries } from '../src/agent/ledger.mjs'
import { ledgerDir } from '../src/agent/paths.mjs'
import { createAgent } from '../src/agent/server.mjs'

const ACCOUNT = '3f0b2c9e-1d4a-4b6f-9c2e-7a8d5e6f1a2b'
const DEVICE = '00000000-0000-4000-8000-000000000000'
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Unix socket paths are capped near 104 bytes on macOS, and os.tmpdir() there is
// already half of that, so sockets live under /tmp.
async function harness({
  idleMs = 60_000,
  expiresInSec = 3600,
  verifyStatus = 200,
  uploadHook,
  refreshHang = false,
  logoutDelayMs = 0,
  stopBudgetMs,
  home,
  socket,
  rootKey = webcrypto.getRandomValues(new Uint8Array(32)),
} = {}) {
  home ??= await mkdtemp('/tmp/sfa-home-')
  socket ??= join(await mkdtemp('/tmp/sfa-run-'), 'agent.sock')

  const verified = new Set()
  const calls = { refresh: 0, logout: [], verify: [], uploads: [] }
  let nextAccess = 1

  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url)
    const json = (status, body) => ({ status, ok: status >= 200 && status < 300, json: async () => body })
    if (u.pathname === '/auth/v1/token') {
      calls.refresh++
      if (refreshHang) {
        return new Promise((_, reject) =>
          init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))),
        )
      }
      await sleep(30)
      nextAccess++
      return json(200, {
        access_token: `at-${nextAccess}`,
        refresh_token: `rt-${nextAccess}`,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      })
    }
    if (u.pathname === '/auth/v1/logout') {
      // Like fetch: a request made with an aborted signal fails at once.
      if (init.signal?.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError' })
      if (logoutDelayMs) await sleep(logoutDelayMs)
      calls.logout.push({ auth: init.headers.Authorization, scope: u.searchParams.get('scope') })
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

  // Reads the file the way uploadFile does and reports its plaintext through the
  // hook. uploadHook runs before and after that read.
  let n = 0
  const uploadFile = async (args) => {
    const record = { rootKeyAtStart: Buffer.from(args.rootKey).toString('hex') }
    calls.uploads.push(record)
    await uploadHook?.({ ...args, phase: 'before-read' })
    const bytes = await readFile(args.path)
    args.onPlaintextChunk?.(bytes)
    await uploadHook?.({ ...args, phase: 'after-read' })
    record.keyIntactAtEnd = Buffer.from(args.rootKey).some((b) => b !== 0)
    n++
    return { fileId: `file-${n}` }
  }

  const agent = createAgent({
    session: { accessToken: 'at-1', refreshToken: 'rt-1', expiresAt: Math.floor(Date.now() / 1000) + expiresInSec, userId: ACCOUNT },
    rootKey,
    config: { apiBaseUrl: 'https://api.test', supabaseUrl: 'https://sb.test', anonKey: 'anon' },
    socket,
    home,
    device: DEVICE,
    idleMs,
    uploadFile,
    fetchImpl,
    ...(stopBudgetMs ? { stopBudgetMs } : {}),
  })
  await agent.start()

  const ledgerKey = deriveLedgerKey(rootKey)
  const ledgerFile = ledgerPath(ledgerDir(home), ACCOUNT)
  const call = (op, args, opts = {}) => request(op, args, { path: socket, timeoutMs: 5_000, ...opts })
  const ledger = async () => (await readEntries(ledgerFile, { ledgerKey })).entries
  const file = async (name, content) => {
    const p = join(home, name)
    await writeFile(p, content)
    return p
  }
  return { agent, socket, home, rootKey, ledgerKey, ledgerFile, calls, call, ledger, file, verified }
}

async function eventually(check, ms = 2_000) {
  const until = Date.now() + ms
  for (;;) {
    if (await check()) return
    if (Date.now() > until) throw new Error('condition not met in time')
    await sleep(25)
  }
}

const gone = async (p) => {
  try {
    await stat(p)
    return false
  } catch {
    return true
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

test('upload records a tagged ledger entry and no response ever contains key material or a MAC', async () => {
  const h = await harness()
  try {
    const p = await h.file('a.txt', 'alpha')
    const result = await h.call('upload', { path: p })
    assert.deepEqual(Object.keys(result).sort(), ['fileId', 'matchesFileNow', 'size'])
    assert.equal(result.matchesFileNow, true)

    const [entry] = await h.ledger()
    assert.equal(entry.path, p)
    assert.equal(entry.fileId, result.fileId)
    assert.equal(entry.device, DEVICE)
    assert.equal(entry.mac, await macFile(p, h.ledgerKey))

    const keyHex = Buffer.from(h.rootKey).toString('hex')
    const keyB64 = Buffer.from(h.rootKey).toString('base64')
    assert.equal(h.calls.uploads[0].rootKeyAtStart, keyHex, 'uploadFile received the real key')
    for (const [op, args] of [['status', {}], ['verify', { paths: [p] }], ['upload', { path: p }]]) {
      const text = JSON.stringify(await h.call(op, args))
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

test('A file changed and then restored while uploading is NOT reported backed up', async () => {
  // The finding: MACs taken before and after the upload both saw version A, the
  // upload read version B, and verify said "backed up" for bytes the vault did
  // not hold. The ledger now records the MAC of what was actually read.
  let original
  const h = await harness({
    uploadHook: async ({ path, phase }) => {
      if (phase === 'before-read') {
        original = await readFile(path)
        await writeFile(path, 'B'.repeat(original.length))
      } else {
        await writeFile(path, original)
      }
    },
  })
  try {
    const p = await h.file('a.txt', 'AAAAAAAA')
    const result = await h.call('upload', { path: p })
    assert.equal(result.matchesFileNow, false)

    const [entry] = await h.ledger()
    assert.notEqual(entry.mac, await macFile(p, h.ledgerKey), 'the recorded MAC is of the uploaded bytes')
    h.verified.add(entry.fileId)

    const [r] = await h.call('verify', { paths: [p] })
    assert.notEqual(r.state, 'verified')
    assert.equal(r.state, 'changed_since_upload')
  } finally {
    await h.agent.stop('test')
  }
})

test('a file that changes size mid-upload is not recorded at all', async () => {
  const h = await harness({
    uploadHook: async ({ path, phase }) => {
      if (phase === 'before-read') await writeFile(path, 'grew during the upload')
    },
  })
  try {
    const p = await h.file('a.txt', 'short')
    await assert.rejects(() => h.call('upload', { path: p }), (e) => e.code === 'not_recorded')
    assert.deepEqual(await h.ledger(), [])
  } finally {
    await h.agent.stop('test')
  }
})

test('a forged ledger line cannot make a file verify', async () => {
  const h = await harness()
  try {
    const p = await h.file('never-uploaded.txt', 'never uploaded')
    const mac = await macFile(p, h.ledgerKey)
    h.verified.add('real-file-id')
    const { appendFile } = await import('node:fs/promises')
    const { mkdir } = await import('node:fs/promises')
    await mkdir(join(h.home, '.shieldfive', 'ledger'), { recursive: true })
    await appendFile(
      h.ledgerFile,
      JSON.stringify({ v: 1, path: p, size: 14, mtimeMs: 1, mac, fileId: 'real-file-id', uploadedAt: 'x', device: DEVICE, tag: '0'.repeat(64) }) + '\n',
    )
    const [r] = await h.call('verify', { paths: [p] })
    assert.equal(r.state, 'not_in_ledger')
  } finally {
    await h.agent.stop('test')
  }
})

test('verify ignores ledger records made on another device', async () => {
  const h = await harness()
  try {
    const p = await h.file('a.txt', 'alpha')
    await appendEntry(
      h.ledgerFile,
      { path: p, size: 5, mtimeMs: 1, mac: await macFile(p, h.ledgerKey), fileId: 'from-elsewhere', uploadedAt: 'x', device: 'ffffffff-ffff-4fff-8fff-ffffffffffff' },
      { ledgerKey: h.ledgerKey },
    )
    h.verified.add('from-elsewhere')
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

    assert.deepEqual(await h.call('sync', { folder }), { uploaded: 2, skipped: 0, failed: 0, changed: 0, errors: [] })
    assert.deepEqual(await h.call('sync', { folder }), { uploaded: 0, skipped: 2, failed: 0, changed: 0, errors: [] })
    await writeFile(join(folder, 'two.txt'), '2 edited')
    assert.deepEqual(await h.call('sync', { folder }), { uploaded: 1, skipped: 1, failed: 0, changed: 0, errors: [] })
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

test('logout revokes this session, removes the socket, and further requests find no agent', async () => {
  const h = await harness()
  const result = await h.call('logout')
  assert.deepEqual(result, { loggedOut: true, everywhere: false, sessionRevoked: true, revokeStatus: 204 })
  assert.deepEqual(h.calls.logout, [{ auth: 'Bearer at-1', scope: 'local' }])
  await eventually(() => gone(h.socket))
  await assert.rejects(() => h.call('status'), (e) => e instanceof AgentUnavailableError)
})

test('logout --everywhere signs out every session on the account', async () => {
  const h = await harness()
  const result = await h.call('logout', { everywhere: true })
  assert.equal(result.everywhere, true)
  assert.deepEqual(h.calls.logout, [{ auth: 'Bearer at-1', scope: 'global' }])
})

test('lock reports whether the session was revoked', async () => {
  const h = await harness()
  assert.deepEqual(await h.call('lock'), { locked: true, sessionRevoked: true, revokeStatus: 204 })
})

test('stopping cannot hang on a token refresh that never answers', async () => {
  const h = await harness({ expiresInSec: -10, refreshHang: true, stopBudgetMs: 300 })
  const started = Date.now()
  const result = await h.agent.stop('test')
  assert.ok(Date.now() - started < 2_000, `stop took ${Date.now() - started} ms`)
  assert.equal(result.revoked, false)
})

test('the agent locks itself after the idle period and revokes the session', async () => {
  const h = await harness({ idleMs: 150 })
  await eventually(() => h.agent.stopped, 3_000)
  await eventually(() => h.calls.logout.length === 1, 3_000)
  await assert.rejects(() => h.call('status'), (e) => e instanceof AgentUnavailableError)
})

test('status probes do not count as use: polling cannot keep the agent unlocked', async () => {
  const h = await harness({ idleMs: 400 })
  const until = Date.now() + 1_500
  while (Date.now() < until && !h.agent.stopped) {
    await h.call('status').catch(() => {})
    await sleep(100)
  }
  assert.equal(h.agent.stopped, true)
})

test('logout during a sync stops it, and the upload in flight keeps an intact key', async () => {
  const h = await harness({
    uploadHook: async ({ phase }) => {
      if (phase === 'after-read') await sleep(150)
    },
  })
  const folder = await mkdtemp('/tmp/sfa-sync-')
  for (let i = 0; i < 5; i++) await writeFile(join(folder, `f${i}.txt`), `file ${i}`)

  const syncing = h.call('sync', { folder }, { timeoutMs: 0 })
  await sleep(80)
  await h.call('logout')

  await assert.rejects(syncing, (e) => e.code === 'locked')
  assert.ok(h.calls.uploads.length >= 1)
  assert.ok(
    h.calls.uploads.every((u) => u.keyIntactAtEnd),
    'a logout mid-upload must not zero the key an upload is still using',
  )
})

test('two agents starting at once: exactly one wins', async () => {
  const home = await mkdtemp('/tmp/sfa-home-')
  const socket = join(await mkdtemp('/tmp/sfa-run-'), 'agent.sock')
  const make = () =>
    createAgent({
      session: { accessToken: 'x', refreshToken: 'y', expiresAt: Math.floor(Date.now() / 1000) + 3600, userId: ACCOUNT },
      rootKey: webcrypto.getRandomValues(new Uint8Array(32)),
      config: { apiBaseUrl: 'https://api.test', supabaseUrl: 'https://sb.test', anonKey: 'anon' },
      socket,
      home,
      device: DEVICE,
      uploadFile: async () => ({ fileId: 'z' }),
      fetchImpl: async () => ({ status: 204, ok: true, json: async () => ({}) }),
    })
  const [a, b] = [make(), make()]
  const results = await Promise.allSettled([a.start(), b.start()])
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1)
  assert.equal(results.find((r) => r.status === 'rejected').reason.code, 'already_running')
  const winner = results[0].status === 'fulfilled' ? a : b
  await winner.stop('test')
})

test("an old agent that is still revoking does not delete a newer agent's socket", async () => {
  const first = await harness({ logoutDelayMs: 300 })
  const stopping = first.agent.stop('test')

  const second = createAgent({
    session: { accessToken: 'x', refreshToken: 'y', expiresAt: Math.floor(Date.now() / 1000) + 3600, userId: ACCOUNT },
    rootKey: webcrypto.getRandomValues(new Uint8Array(32)),
    config: { apiBaseUrl: 'https://api.test', supabaseUrl: 'https://sb.test', anonKey: 'anon' },
    socket: first.socket,
    home: first.home,
    device: DEVICE,
    uploadFile: async () => ({ fileId: 'z' }),
    fetchImpl: async () => ({ status: 204, ok: true, json: async () => ({}) }),
  })

  // While the first agent holds its lock, the second cannot start.
  await assert.rejects(() => second.start(), (e) => e.code === 'already_running')
  await stopping

  await second.start()
  await sleep(100)
  assert.equal((await request('status', {}, { path: first.socket })).unlocked, true)
  await second.stop('test')
})

test('a leftover socket file and lock from a dead agent do not block a new one', async () => {
  const home = await mkdtemp('/tmp/sfa-home-')
  const runDir = await mkdtemp('/tmp/sfa-run-')
  const socket = join(runDir, 'agent.sock')
  await writeFile(socket, '')
  await writeFile(join(runDir, 'agent.lock'), '999999:dead')

  const h = await harness({ home, socket })
  assert.equal((await h.call('status')).unlocked, true)
  await h.agent.stop('test')
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
        device: DEVICE,
        uploadFile: async () => ({}),
      }),
    (e) => e.code === 'no_refresh_token',
  )
})
