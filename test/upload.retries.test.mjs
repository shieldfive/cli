// Transient-failure handling in the upload path, against a real local HTTP
// server (not a fetch stub): the server answers 502s, resets connections
// (ECONNRESET) and cuts reply bodies short, the way a proxy in front of a
// storage backend does. Every idempotent-safe step (create session, upload
// credentials, part upload, complete) must ride those out; 4xx validation and
// auth answers must not be retried, except one token refresh on a 401.

import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { uploadFile } from '../src/upload.mjs'
import { createSessionTokens } from '../src/sync.mjs'

const FILE_ID = '01928c3a-1b2c-7d3e-8f40-123456789abc'
const PROOF_KEY = 'ab'.repeat(32)

// faults: { [route]: array of actions consumed per request, then 'ok' }.
// Actions: 'ok', 'reset' (destroy the socket), 'cut' (200 with a truncated
// body), or a number (that HTTP status, JSON body).
async function startServer(faults = {}) {
  const hits = {}
  const auth = []
  const manifests = []
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const url = new URL(req.url, 'http://x')
      const route = url.pathname.startsWith('/storage/') ? 'storage' : url.pathname
      hits[route] = (hits[route] ?? 0) + 1
      if (route !== 'storage') auth.push(req.headers.authorization)
      const action = faults[route]?.shift() ?? 'ok'
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
      if (route === '/api/files/create-upload-session') {
        return json({
          fileId: FILE_ID, uploadKind: 's3-multipart', b2FileId: 'upload-1',
          chunkSize: 8, proofKey: PROOF_KEY,
        })
      }
      if (route === '/api/files/upload-part-url') {
        const { partNumber } = JSON.parse(body)
        return json({ uploadKind: 's3-multipart', uploadUrl: `${base}/storage/${partNumber}` })
      }
      if (route === 'storage') {
        res.writeHead(200, { ETag: `"${createHash('md5').update(body).digest('hex')}"` })
        return res.end()
      }
      if (route === '/api/files/complete-upload') {
        manifests.push(JSON.parse(body))
        return json({ ok: true })
      }
      if (route === '/api/files/delete') return json({ ok: true })
      res.writeHead(404)
      res.end()
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const base = `http://127.0.0.1:${server.address().port}`
  return { base, hits, auth, manifests, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r) }) }
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
  assert.ok(messages.includes('Create upload session could not reach the server, retrying'))
  assert.ok(messages.includes("Create upload session could not read the server's reply, retrying"))
  assert.ok(messages.some((m) => /^Upload part \d could not reach the server, retrying$/.test(m)))
  assert.ok(messages.some((m) => /^Upload part \d failed \(HTTP 503\), retrying$/.test(m)))
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
