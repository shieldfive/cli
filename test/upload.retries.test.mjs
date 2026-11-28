// Transient-failure handling in the upload path, against a real local HTTP
// server (not a fetch stub): the server answers 502s, resets connections
// (ECONNRESET) and cuts reply bodies short, the way a proxy in front of a
// storage backend does. Every idempotent-safe step (create session, upload
// credentials, part upload, complete) must ride those out; 4xx validation and
// auth answers must not be retried, except one token refresh on a 401.

import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import dns from 'node:dns'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { runDoctor } from '../src/doctor.mjs'
import { runPush } from '../src/migrate.mjs'
import { bytesToBase64, generateRandomKeyB64, wrapKeyB64 } from '../src/uploadCrypto.mjs'

import { uploadFile } from '../src/upload.mjs'
import { createSessionTokens } from '../src/sync.mjs'

const FILE_ID = '01928c3a-1b2c-7d3e-8f40-123456789abc'
const POD = 'https://pod-test.backblazeb2.com'
const NATIVE_TARGET = '/api/files/upload-native-target'
const PROOF_KEY = 'ab'.repeat(32)

// faults: { [route]: array of actions consumed per request, then 'ok' }.
// Actions: 'ok', 'stall', 'reset' (destroy the socket), 'cut' (200 with a truncated
// body), or a number (that HTTP status, JSON body).
async function startServer(faults = {}, { direct = false, folderTree = [], clockOffset = 0, mode, allFail = false, storageHost, reuseNative = false } = {}) {
  const hits = {}
  const auth = []
  const manifests = []
  const sessions = []
  const deleted = []
  const storageRequests = []
  const nativeRequests = []
  const nativeTargets = []
  const storageUrl = (fileId) => {
    if (mode === 'dns' && (allFail || fileId === sessions[0]?.clientUploadId)) {
      return 'http://shieldfive-storage-test.invalid/secret-key?signature=private'
    }
    const origin = storageHost ? base.replace('127.0.0.1', storageHost) : base
    return `${origin}/storage/${fileId}?signature=private`
  }
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const url = new URL(req.url, 'http://x')
      const route = url.pathname.startsWith('/storage/') ? 'storage' : url.pathname
      hits[route] = (hits[route] ?? 0) + 1
      if (route !== 'storage' && !route.startsWith('/b2api/')) auth.push(req.headers.authorization)
      if (route === 'storage') storageRequests.push({ method: req.method, headers: req.headers, body: Buffer.concat(chunks) })
      const firstUpload = allFail || url.pathname === `/storage/${sessions[0]?.clientUploadId}`
      const action = faults[route]?.shift() ?? (route === 'storage' && firstUpload ? mode : null) ?? 'ok'
      if (action === 'stall') return
      if (action === 'body-stall') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.write('{')
        return
      }
      if (action === 'clock') {
        res.writeHead(403)
        return res.end('<Error><Code>RequestTimeTooSkewed</Code><Message>private-key</Message></Error>')
      }
      if (action === 'reset') return req.socket.destroy()
      if (action === 'cut') {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '500' })
        res.write('{"fileId":"')
        return setImmediate(() => req.socket.destroy())
      }
      if (typeof action === 'number') {
        res.writeHead(action, { 'Content-Type': 'application/json', 'Retry-After': '0' })
        return res.end(JSON.stringify({ error: `injected ${action}` }))
      }
      const json = (body) => {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(body))
      }
      const body = Buffer.concat(chunks)
      if (route === '/api/uptime') {
        res.writeHead(200, { Date: new Date(Date.now() + clockOffset).toUTCString() })
        return res.end()
      }
      if (route === '/api/folders/tree') return json({ tree: folderTree })
      if (route === '/api/files') return json({ files: [], pagination: { hasMore: false } })
      if (route === '/api/files/create-upload-session') {
        if (direct) {
          const payload = JSON.parse(body)
          sessions.push(payload)
          const fileId = payload.clientUploadId
          return json({ fileId, uploadKind: 'direct', uploadUrl: storageUrl(fileId), proofKey: PROOF_KEY })
        }
        return json({
          fileId: FILE_ID, uploadKind: 's3-multipart', b2FileId: 'upload-1',
          chunkSize: 8, proofKey: PROOF_KEY,
        })
      }
      if (route === '/api/files/upload-part-url') {
        const { fileId, partNumber } = JSON.parse(body)
        if (direct) return json({ uploadKind: 'direct', uploadUrl: storageUrl(fileId) })
        return json({ uploadKind: 's3-multipart', uploadUrl: `${base}/storage/${partNumber}` })
      }
      if (route === 'storage') {
        res.writeHead(200, { ETag: `"${createHash('md5').update(body).digest('hex')}"` })
        return res.end()
      }
      if (route === NATIVE_TARGET && direct) {
        const { fileId, sha1, stagedFileId, objectKey, reuseUploadTarget } = JSON.parse(body)
        if (stagedFileId) {
          assert.equal(objectKey, fileId)
          assert.equal(stagedFileId, 'staging-version')
          return res.writeHead(204).end()
        }
        assert.match(sha1, /^[a-f0-9]{40}$/)
        nativeTargets.push(reuseUploadTarget === true)
        if (reuseNative && reuseUploadTarget) return json({ objectKey: fileId })
        return json({
          uploadUrl: `${POD}/b2api/v4/b2_upload_file/${fileId}`,
          authorizationToken: 'pod-token', objectKey: fileId,
        })
      }
      if (route.startsWith('/b2api/v4/b2_upload_file/')) {
        nativeRequests.push({ method: req.method, headers: req.headers, body, fileId: route.split('/').at(-1) })
        return json({ fileId: 'staging-version' })
      }
      if (route === '/api/files/complete-upload') {
        manifests.push(JSON.parse(body))
        return json({ ok: true })
      }
      if (route === '/api/files/delete') {
        deleted.push(JSON.parse(body))
        return json({ ok: true })
      }
      res.writeHead(404)
      res.end()
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const base = `http://127.0.0.1:${server.address().port}`
  return { base, hits, auth, manifests, sessions, deleted, storageRequests, nativeRequests, nativeTargets, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r) }) }
}

function connectPodToTestServer(t, server) {
  const fetch = globalThis.fetch
  t.mock.method(globalThis, 'fetch', (url, init) => {
    const target = new URL(url)
    return fetch(target.origin === POD ? new URL(target.pathname, server.base) : url, init)
  })
}

async function upload(t, server, extra = {}) {
  // Zero jitter: retries happen at once, so the suite stays fast.
  t.mock.method(Math, 'random', () => 0)
  const dir = await mkdtemp(join(tmpdir(), 'sf-cli-retry-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, 'big.bin')
  const content = webcrypto.getRandomValues(new Uint8Array(20)) // 3 parts
  await writeFile(path, content)
  const messages = []
  const result = await uploadFile({
    apiBaseUrl: server.base,
    accessToken: 'tok-1',
    rootKey: webcrypto.getRandomValues(new Uint8Array(32)),
    name: 'big.bin',
    path,
    size: content.length,
    rowId: FILE_ID,
    onRetry: (m) => messages.push(m),
    ...extra,
  })
  return { result, messages }
}

test('a storage connection falls back to IPv4 when its first IPv6 address cannot connect', async (t) => {
  const storageHost = 'shieldfive-dual-stack.test'
  const server = await startServer({}, { direct: true, storageHost })
  t.after(server.close)
  const lookup = dns.lookup
  let dualStackLookups = 0
  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    if (hostname !== storageHost) return lookup(hostname, options, callback)
    assert.equal(options.all, true)
    dualStackLookups++
    process.nextTick(callback, null, [
      { address: '::1', family: 6 },
      { address: '127.0.0.1', family: 4 },
    ])
  })
  await upload(t, server)
  assert.equal(dualStackLookups, 1)
  assert.equal(server.hits.storage, 1)
  assert.equal(server.hits['/api/files/complete-upload'], 1)
})

test('a stalled part is retried using fresh credentials', { timeout: 5000 }, async (t) => {
  const server = await startServer({ storage: ['stall'] })
  t.after(server.close)
  const deadline = AbortSignal.timeout.bind(AbortSignal)
  t.mock.method(AbortSignal, 'timeout', (ms) => deadline(ms === 120_000 ? 500 : ms))
  await upload(t, server)
  assert.equal(server.hits.storage, 4)
  assert.equal(server.hits['/api/files/upload-part-url'], 4)
  assert.equal(server.hits['/api/files/complete-upload'], 1)
})

test('a stalled cancellation releases the upload worker with its original error', { timeout: 5000 }, async (t) => {
  const server = await startServer({ storage: [400], '/api/files/delete': ['stall'] })
  t.after(server.close)
  const deadline = AbortSignal.timeout.bind(AbortSignal)
  t.mock.method(AbortSignal, 'timeout', (ms) => deadline(Math.min(ms, 1000)))
  await assert.rejects(upload(t, server), /Upload part \d+ failed \(HTTP 400\)/)
  assert.equal(server.hits['/api/files/delete'], 2)
  assert.equal(server.hits['/api/files/complete-upload'] ?? 0, 0)
})

test('502s, connection resets and cut replies at every step are retried to completion', async (t) => {
  const server = await startServer({
    '/api/files/create-upload-session': [502, 'reset', 'cut'],
    '/api/files/upload-part-url': [502, 'reset'],
    storage: ['reset', 503],
    '/api/files/complete-upload': [502, 'reset'],
  })
  t.after(server.close)
  const { result, messages } = await upload(t, server)
  assert.equal(result.fileId, FILE_ID)
  assert.equal(server.hits['/api/files/create-upload-session'], 4)
  assert.equal(server.hits['/api/files/complete-upload'], 3)
  assert.equal(server.hits['/api/files/delete'], undefined, 'a recovered upload is not cancelled')
  assert.equal(server.manifests.length, 1)
  assert.equal(server.manifests[0].partSha1Array.length, 3)
  assert.ok(messages.includes('Create upload session failed (HTTP 502), retrying'))
  assert.ok(messages.some((m) => /^Create upload session failed \(ECONNRESET\) at .*retrying$/.test(m)))
  assert.ok(messages.some((m) => /^Create upload session reply failed \(ECONNRESET\) at .*retrying$/.test(m)))
  assert.ok(messages.some((m) => /^Upload part \d failed \(ECONNRESET\) at .*retrying$/.test(m)))
  assert.ok(messages.some((m) => /^Upload part \d failed \(HTTP 503\) at .*retrying$/.test(m)))
})

test('a persistent 502 gives up after bounded attempts with the HTTP status', async (t) => {
  const server = await startServer({ '/api/files/create-upload-session': Array(20).fill(502) })
  t.after(server.close)
  await assert.rejects(upload(t, server), /Create upload session failed \(HTTP 502\)/)
  assert.equal(server.hits['/api/files/create-upload-session'], 7)
})

test('4xx validation answers are not retried', async (t) => {
  for (const status of [400, 403, 404, 409, 413]) {
    const server = await startServer({ '/api/files/create-upload-session': [status] })
    await assert.rejects(upload(t, server), new RegExp(`HTTP ${status}`))
    assert.equal(server.hits['/api/files/create-upload-session'], 1, `HTTP ${status} retried`)
    await server.close()
  }
})

test('a 401 refreshes the token once and repeats the request', async (t) => {
  const server = await startServer({
    '/api/files/create-upload-session': [401],
    '/api/files/complete-upload': [401],
  })
  t.after(server.close)
  let refreshes = 0
  const tokens = createSessionTokens({
    accessToken: 'tok-1', refreshToken: 'r-1', expiresAt: Math.floor(Date.now() / 1000) + 3600,
    refresh: async () => {
      refreshes += 1
      return { accessToken: `tok-${refreshes + 1}`, refreshToken: `r-${refreshes + 1}`, expiresAt: Math.floor(Date.now() / 1000) + 3600 }
    },
  })
  const { result } = await upload(t, server, { accessToken: tokens })
  assert.equal(result.fileId, FILE_ID)
  assert.equal(refreshes, 2, 'one refresh per refused step')
  assert.deepEqual(server.auth.slice(0, 2), ['Bearer tok-1', 'Bearer tok-2'])
  assert.equal(server.auth.at(-1), 'Bearer tok-3')
})

test('a 401 that survives the refresh, or a failed refresh, says to sign in again', async (t) => {
  const twice = await startServer({ '/api/files/create-upload-session': [401, 401] })
  const refreshed = createSessionTokens({
    accessToken: 'a', refreshToken: 'r', expiresAt: Math.floor(Date.now() / 1000) + 3600,
    refresh: async () => ({ accessToken: 'b', refreshToken: 'r2', expiresAt: Math.floor(Date.now() / 1000) + 3600 }),
  })
  await assert.rejects(upload(t, twice, { accessToken: refreshed }), /HTTP 401\).*sf login/)
  assert.equal(twice.hits['/api/files/create-upload-session'], 2)
  await twice.close()

  const failing = await startServer({ '/api/files/create-upload-session': [401] })
  const broken = createSessionTokens({
    accessToken: 'a', refreshToken: 'r', expiresAt: Math.floor(Date.now() / 1000) + 3600,
    refresh: async () => { throw new Error('refresh token revoked') },
  })
  await assert.rejects(upload(t, failing, { accessToken: broken }), /HTTP 401\).*sf login/)
  assert.equal(failing.hits['/api/files/create-upload-session'], 1)
  await failing.close()

  // A plain string token cannot be refreshed: no repeat.
  const plain = await startServer({ '/api/files/create-upload-session': [401] })
  await assert.rejects(upload(t, plain), /HTTP 401\).*sf login/)
  assert.equal(plain.hits['/api/files/create-upload-session'], 1)
  await plain.close()
})

function shortenDeadlines(t, timeout = 250) {
  const deadline = AbortSignal.timeout.bind(AbortSignal)
  t.mock.method(AbortSignal, 'timeout', (ms) => deadline(Math.min(ms, timeout)))
  t.mock.method(Math, 'random', () => 0)
}

function vaultFolder(rootKey, { isMedia = true, isBin = false } = {}) {
  const { wrapped, iv } = wrapKeyB64({ wrappingKeyB64: bytesToBase64(rootKey), keyToWrapB64: generateRandomKeyB64() })
  return {
    id: FILE_ID, is_media: isMedia, is_bin: isBin, parent_id: null,
    fk_wrapped: wrapped, fk_iv: iv, children: [],
  }
}

const failureModes = [
  ['stall', /ETIMEDOUT.*127\.0\.0\.1/],
  ['reset', /ECONNRESET.*127\.0\.0\.1/],
  ['clock', /HTTP 403.*127\.0\.0\.1.*RequestTimeTooSkewed, clock skew/],
  ['dns', /ENOTFOUND.*shieldfive-storage-test\.invalid/],
]

for (const [mode, diagnostic] of failureModes) {
  test(`Media push reports ${mode}, bounds stalled cleanup, and continues`, { timeout: 12_000 }, async (t) => {
    shortenDeadlines(t)
    const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
    const server = await startServer({ '/api/files/delete': ['stall', 'stall'], [NATIVE_TARGET]: [404] }, {
      direct: true, mode, folderTree: [vaultFolder(rootKey)],
    })
    t.after(server.close)
    const dir = await mkdtemp(join(tmpdir(), 'sf-cli-pool-'))
    t.after(() => rm(dir, { recursive: true, force: true }))
    const source = join(dir, 'source')
    await mkdir(source)
    await writeFile(join(source, 'a.txt'), 'failed file')
    await writeFile(join(source, 'b.txt'), 'next file')
    const progress = []
    const options = {
      source, statePath: join(dir, 'state.json'), apiBaseUrl: server.base,
      accessToken: 'secret-token', rootKey, account: 'private-account', media: true,
      concurrency: 1, thumbnails: false, progressEveryMs: 0, status: () => {}, log: () => {},
      progress: (line) => progress.push(line),
    }
    const legacySource = process.env.SF_TEST_064_MIGRATE
    if (legacySource) {
      const legacy = await import(legacySource)
      const settled = legacy.runPush(options).then(() => true, () => true)
      for (let i = 0; i < 75 && !server.hits['/api/files/delete']; i++) await delay(50)
      assert.equal(server.hits['/api/files/delete'], 1, '0.6.4 reached cleanup')
      assert.equal(await Promise.race([settled, delay(400, false)]), false, '0.6.4 still blocked')
      assert.equal(server.sessions.length, 1, '0.6.4 never scheduled the second file')
      await server.close()
      await settled
      return
    }
    const result = await runPush(options)
    assert.equal(result.uploaded, 1)
    assert.equal(result.failed.length, 1)
    assert.match(result.failed[0].message, diagnostic)
    assert.match(progress.join('\n'), diagnostic)
    assert.doesNotMatch(progress.join('\n'), /secret-token|private-key|signature=|secret-key/)
    assert.equal(server.hits['/api/files/delete'], 2)
    assert.equal(server.manifests.length, 1)
  })
}

for (const mode of ['stall', 'reset']) {
  test(`Media push falls back after an S3 PUT ${mode} and reuses the working native path`, async (t) => {
    shortenDeadlines(t, 2000)
    const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
    const server = await startServer({ [NATIVE_TARGET]: ['ok', 503] }, { direct: true, mode, allFail: true, folderTree: [vaultFolder(rootKey)] })
    t.after(server.close)
    connectPodToTestServer(t, server)
    const source = await mkdtemp(join(tmpdir(), 'sf-cli-native-'))
    t.after(() => rm(source, { recursive: true, force: true }))
    await writeFile(join(source, 'a.txt'), Buffer.alloc(5 * 1024 * 1024))
    await writeFile(join(source, 'b.txt'), 'second file')
    const summary = await runPush({
      source, statePath: join(source, '.state.json'), apiBaseUrl: server.base,
      accessToken: 'secret-token', rootKey, account: 'account', media: true,
      concurrency: 1, thumbnails: false, progressEveryMs: 0, status: () => {}, log: () => {},
    })
    assert.equal(summary.uploaded, 2)
    assert.equal(summary.failed.length, 0)
    assert.equal(server.storageRequests.length, 1)
    assert.equal(server.nativeRequests.length, 2)
    assert.equal(server.hits[NATIVE_TARGET], 5, 'retry promotion without sending ciphertext again')
    const [s3] = server.storageRequests
    assert.equal(s3.method, 'PUT')
    assert.equal(s3.headers['content-length'], String(s3.body.length))
    for (const header of Object.keys(s3.headers)) {
      assert.doesNotMatch(header, /^(expect|transfer-encoding|content-md5|x-amz-.*checksum|authorization)$/)
    }
    assert.deepEqual(server.nativeRequests[0].body, s3.body)
    for (const [index, request] of server.nativeRequests.entries()) {
      assert.equal(request.method, 'POST')
      assert.equal(request.headers.authorization, 'pod-token')
      assert.equal(request.headers['x-bz-file-name'], request.fileId)
      assert.equal(request.headers['x-bz-content-sha1'], server.manifests[index].ciphertextHash)
      assert.equal(request.headers['content-length'], String(request.body.length))
      assert.equal(request.fileId, server.manifests[index].fileId)
      assert.equal(createHash('sha1').update(request.body).digest('hex'), server.manifests[index].ciphertextHash)
    }
    assert.equal(server.deleted.length, 0)
  })
}

test('reuses a worker target until the pod rejects it, then rotates credentials', async (t) => {
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
  const dir = await mkdtemp(join(tmpdir(), 'sf-cli-native-reuse-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const server = await startServer({}, { direct: true, reuseNative: true })
  t.after(server.close)
  connectPodToTestServer(t, server)
  const path = join(dir, 'photo.jpg')
  await writeFile(path, Buffer.alloc(128 * 1024))
  let congestion = 0
  const directUpload = { mode: 'native', reuseTargets: true, onCongestion: () => congestion++ }
  const send = () => uploadFile({
    apiBaseUrl: server.base, accessToken: 'token', rootKey, name: 'photo.jpg',
    path, size: 128 * 1024, thumbnail: null, directUpload,
  })
  const first = await send()
  const second = await send()
  const rejectedRoute = '/b2api/v4/b2_upload_file/' + first.fileId
  // The rejected response retains no upload receipt.
  const cachedFetch = globalThis.fetch
  let reject = true
  t.mock.method(globalThis, 'fetch', (url, init) => {
    if (reject && new URL(url).pathname === rejectedRoute) {
      reject = false
      return Promise.resolve(new Response('{"code":"service_unavailable"}', {
        status: 503, headers: { 'Retry-After': '0' },
      }))
    }
    return cachedFetch(url, init)
  })
  const third = await send()
  assert.equal(congestion, 1)
  assert.deepEqual(server.nativeTargets, [false, true, true, false])
  assert.deepEqual(server.nativeRequests.map(({ fileId }) => fileId), [
    first.fileId, first.fileId, third.fileId,
  ])
  assert.equal(server.nativeRequests[1].headers['x-bz-file-name'], second.fileId)
  assert.deepEqual(server.manifests.map(({ fileId }) => fileId), [
    first.fileId, second.fileId, third.fileId,
  ])
  assert.equal(server.storageRequests.length, 0)
})

test('three consecutive file failures stop scheduling with the last storage diagnostic', async (t) => {
  shortenDeadlines(t)
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
  const server = await startServer({}, { direct: true, mode: 'clock', allFail: true, folderTree: [vaultFolder(rootKey)] })
  t.after(server.close)
  const dir = await mkdtemp(join(tmpdir(), 'sf-cli-stop-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const source = join(dir, 'source')
  await mkdir(source)
  for (const name of ['a', 'b', 'c', 'd']) await writeFile(join(source, name), name)
  const summary = await runPush({
    source, statePath: join(dir, 'state.json'), apiBaseUrl: server.base,
    accessToken: 'token', rootKey, account: 'account', media: true, concurrency: 1, thumbnails: false,
    progressEveryMs: 0, status: () => {}, log: () => {},
  })
  assert.equal(summary.failed.length, 3)
  assert.equal(summary.notStarted, 1)
  assert.match(summary.stoppedBy.message, /3 consecutive storage failures.*Direct upload.*HTTP 403.*clock skew/)
})

test('doctor reports API time, DNS, TLS, both upload paths and Bin deletion', async (t) => {
  const rootKey = webcrypto.getRandomValues(new Uint8Array(32))
  const bin = vaultFolder(rootKey, { isMedia: false, isBin: true })
  const server = await startServer({}, { direct: true, folderTree: [bin] })
  t.after(server.close)
  connectPodToTestServer(t, server)
  const report = await runDoctor({
    apiBaseUrl: server.base, getSession: () => ({ rootKey, accessToken: 'private-token' }),
    dnsCheck: async () => [{ address: '127.0.0.1', family: 4 }, { address: '::1', family: 6 }],
    tlsCheck: async (url, { address }) => {
      assert.ok([server.base, POD].includes(url.origin))
      if (address === '::1') throw Object.assign(new Error(), { code: 'ETIMEDOUT' })
      assert.equal(address, '127.0.0.1')
    },
  })
  assert.deepEqual(report.map((line) => line.split(' (')[0]), [
    'PASS API reachability', 'PASS Clock skew', 'PASS Storage DNS', 'PASS Storage TLS IPv4', 'WARN Storage TLS IPv6',
    'PASS Test upload S3 PUT', 'PASS Delete test upload S3 PUT',
    'PASS Storage DNS', 'PASS Storage TLS IPv4', 'WARN Storage TLS IPv6',
    'PASS Test upload Native direct', 'PASS Delete test upload Native direct',
  ])
  assert.match(report.join('\n'), /PASS Storage TLS IPv4.*127\.0\.0\.1/)
  assert.match(report.join('\n'), /WARN Storage TLS IPv6.*ETIMEDOUT.*::1/)
  assert.equal(server.sessions[0].folderId, bin.id)
  assert.equal(server.hits.storage, 1)
  assert.equal(server.nativeRequests.length, 1)
  assert.equal(server.manifests.length, 2)
  assert.deepEqual(server.deleted, server.manifests.map(({ fileId }) => ({ ids: [fileId] })))
  assert.doesNotMatch(report.join('\n'), /private-token|signature=|ShieldFive doctor|secret-key/)
})

test('doctor reports skew and DNS failures without exposing signed URL or provider message', async (t) => {
  shortenDeadlines(t)
  const server = await startServer({}, { direct: true, mode: 'dns', clockOffset: 300_000 })
  t.after(server.close)
  connectPodToTestServer(t, server)
  const report = await runDoctor({
    apiBaseUrl: server.base,
    getSession: () => ({ rootKey: webcrypto.getRandomValues(new Uint8Array(32)), accessToken: 'private-token' }),
  })
  const skewSeconds = Number(report.find((line) => line.startsWith('FAIL Clock skew'))?.match(/\((-?\d+) s/)?.[1])
  assert.ok(Math.abs(skewSeconds - 300) <= 2, `reported skew: ${skewSeconds} s`)
  assert.match(report.join('\n'), /FAIL Storage DNS.*ENOTFOUND/)
  assert.match(report.join('\n'), /SKIP Storage TLS IPv4/)
  assert.match(report.join('\n'), /FAIL Test upload S3 PUT \/ Send storage part.*ENOTFOUND/)
  assert.match(report.join('\n'), /PASS Test upload Native direct/)
  assert.doesNotMatch(report.join('\n'), /signature|private|secret-key/)
})

test('a stalled complete response body times out and retries the same manifest', async (t) => {
  shortenDeadlines(t)
  const server = await startServer({ '/api/files/complete-upload': ['body-stall'] })
  t.after(server.close)
  const { messages } = await upload(t, server)
  assert.equal(server.hits['/api/files/complete-upload'], 2)
  assert.match(messages.join('\n'), /Complete upload reply failed \(ETIMEDOUT\)/)
})
