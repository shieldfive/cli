// Batch I hardening: cancel a pending session on failure, 0-byte files, no
// symlink following, manifest mode 0600, dotfiles skipped by push.

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHmac, webcrypto } from 'node:crypto'
import { mkdtemp, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { parseHeader } from '@shieldfive/crypto/format'

import { readFileChunks, uploadFile } from '../src/upload.mjs'
import { saveManifest, scanFiles } from '../src/sync.mjs'

const API = 'https://api.test'
const PROOF_KEY = 'cd'.repeat(32)
const FILE_ID = '01928c3a-1b2c-7d3e-af40-123456789abd'

function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body) }
}

async function tempDir(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'sf-cli-hard-'))
  try {
    return await fn(dir)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

async function withFetch(handler, fn) {
  const original = globalThis.fetch
  globalThis.fetch = async (input, init = {}) => handler(typeof input === 'string' ? input : input.toString(), init)
  try {
    return await fn()
  } finally {
    globalThis.fetch = original
  }
}

const rootKey = () => webcrypto.getRandomValues(new Uint8Array(32))

test('a failed upload cancels its pending session', async () => {
  const deletes = []
  await tempDir(async (dir) => {
    const path = join(dir, 'a.bin')
    await writeFile(path, 'hello')
    await withFetch(
      (url, init) => {
        if (url === `${API}/api/files/create-upload-session`) {
          return jsonResponse(200, { uploadKind: 'direct', fileId: FILE_ID, uploadUrl: 'https://s3.test/put', proofKey: PROOF_KEY })
        }
        if (url === 'https://s3.test/put') return jsonResponse(500, { error: 'boom' })
        if (url === `${API}/api/files/delete`) {
          deletes.push({ body: JSON.parse(init.body), auth: init.headers.Authorization })
          return jsonResponse(200, {})
        }
        throw new Error(`unexpected fetch: ${url}`)
      },
      () =>
        assert.rejects(
          uploadFile({ apiBaseUrl: API, accessToken: 'tok', rootKey: rootKey(), name: 'a.bin', path, size: 5, rowId: FILE_ID }),
          /Direct upload failed \(HTTP 500\)/,
        ),
    )
  })
  assert.deepEqual(deletes, [{ body: { ids: [FILE_ID] }, auth: 'Bearer tok' }])
})

test('a lost finalize answer does NOT cancel (the file may already be in the vault)', async () => {
  let deleted = false
  await tempDir(async (dir) => {
    const path = join(dir, 'a.bin')
    await writeFile(path, 'hello')
    await withFetch(
      (url) => {
        if (url === `${API}/api/files/create-upload-session`) {
          return jsonResponse(200, { uploadKind: 'direct', fileId: FILE_ID, uploadUrl: 'https://s3.test/put', proofKey: PROOF_KEY })
        }
        if (url === 'https://s3.test/put') return jsonResponse(200, {})
        if (url === `${API}/api/files/complete-upload`) throw new TypeError('fetch failed')
        if (url === `${API}/api/files/delete`) {
          deleted = true
          return jsonResponse(200, {})
        }
        throw new Error(`unexpected fetch: ${url}`)
      },
      () => assert.rejects(uploadFile({ apiBaseUrl: API, accessToken: 'tok', rootKey: rootKey(), name: 'a.bin', path, size: 5, rowId: FILE_ID })),
    )
  })
  assert.equal(deleted, false)
})

test('0-byte file: refused before any session when the server lacks the capability', async () => {
  const calls = []
  await tempDir(async (dir) => {
    const path = join(dir, 'empty')
    await writeFile(path, '')
    await withFetch(
      (url) => {
        calls.push(url)
        if (url === `${API}/api/files/upload-capabilities`) return jsonResponse(200, { version: 1, emptyCipherV3: false })
        throw new Error(`unexpected fetch: ${url}`)
      },
      () =>
        assert.rejects(
          uploadFile({ apiBaseUrl: API, accessToken: 'tok', rootKey: rootKey(), name: 'empty', path, size: 0, rowId: FILE_ID }),
          (err) => err.code === 'empty_file_unsupported',
        ),
    )
  })
  assert.deepEqual(calls, [`${API}/api/files/upload-capabilities`])
})

test('0-byte file: header-only part and the server empty-file proof', async () => {
  let put = null
  let finalize = null
  let createBody = null
  await tempDir(async (dir) => {
    const path = join(dir, 'empty')
    await writeFile(path, '')
    await withFetch(
      (url, init) => {
        if (url === `${API}/api/files/upload-capabilities`) return jsonResponse(200, { version: 1, emptyCipherV3: true })
        if (url === `${API}/api/files/create-upload-session`) {
          createBody = JSON.parse(init.body)
          return jsonResponse(200, { uploadKind: 'direct', fileId: FILE_ID, uploadUrl: 'https://s3.test/put', proofKey: PROOF_KEY })
        }
        if (url === 'https://s3.test/put') {
          put = new Uint8Array(init.body)
          return jsonResponse(200, {})
        }
        if (url === `${API}/api/files/complete-upload`) {
          finalize = JSON.parse(init.body)
          return jsonResponse(200, { ok: true })
        }
        throw new Error(`unexpected fetch: ${url}`)
      },
      () => uploadFile({ apiBaseUrl: API, accessToken: 'tok', rootKey: rootKey(), name: 'empty', path, size: 0, rowId: FILE_ID }),
    )
  })
  assert.equal(createBody.sizeBytes, 0)
  const header = parseHeader(put)
  assert.equal(header.headerLength, put.length, 'part is the header alone')
  assert.equal(header.totalChunks, 0)
  assert.equal(header.plaintextSize, 0)
  const prefix = Buffer.from([3, 3])
  const mac = createHmac('sha256', Buffer.from(PROOF_KEY, 'hex')).update(prefix).update(put).digest()
  assert.equal(finalize.proof, Buffer.concat([prefix, mac]).toString('base64'))
  assert.equal(finalize.partSha1Array.length, 1)
})

test('sync scan skips symlinks and dotfiles; reading through a symlink fails', async () => {
  await tempDir(async (dir) => {
    await writeFile(join(dir, 'real.txt'), 'x')
    await writeFile(join(dir, '.env'), 'SECRET=1')
    const outside = await mkdtemp(join(tmpdir(), 'sf-cli-outside-'))
    try {
      await writeFile(join(outside, 'id_ed25519'), 'private')
      await symlink(join(outside, 'id_ed25519'), join(dir, 'link'))
      const names = (await scanFiles(dir)).map((e) => e.name)
      assert.deepEqual(names, ['real.txt'])
      await assert.rejects(async () => {
        for await (const _ of readFileChunks(join(dir, 'link'), 8)) void _
      }, (err) => err.code === 'ELOOP' || err.code === 'EMLINK')
    } finally {
      await rm(outside, { recursive: true, force: true })
    }
  })
})

test('sync manifest is written with mode 0600', { skip: process.platform === 'win32' }, async () => {
  await tempDir(async (dir) => {
    const p = join(dir, '.shieldfive-sync.json')
    await writeFile(`${p}.tmp`, 'stale', { mode: 0o644 })
    await saveManifest(p, { files: {} })
    assert.equal((await stat(p)).mode & 0o777, 0o600)
  })
})

test('push/encrypt listing skips dotfiles and symlinks', async () => {
  const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url))
  await tempDir(async (dir) => {
    await writeFile(join(dir, 'doc.txt'), 'hello')
    await writeFile(join(dir, '.env'), 'SECRET=1')
    await symlink(join(dir, 'doc.txt'), join(dir, 'alias.txt'))
    const { stdout } = await promisify(execFile)(process.execPath, [cli, 'encrypt', dir])
    assert.match(stdout, /encrypted doc\.txt/)
    assert.doesNotMatch(stdout, /\.env|alias\.txt/)
  })
})

test('a server that ignores clientUploadId is refused and its row cancelled', async () => {
  const deletes = []
  await tempDir(async (dir) => {
    const path = join(dir, 'a.bin')
    await writeFile(path, 'hello')
    await withFetch(
      (url, init) => {
        if (url === `${API}/api/files/create-upload-session`) {
          return jsonResponse(200, { uploadKind: 'direct', fileId: '957a1070-c734-4d7b-9430-27df8de29d58', uploadUrl: 'https://s3.test/put', proofKey: PROOF_KEY })
        }
        if (url === `${API}/api/files/delete`) {
          deletes.push(JSON.parse(init.body))
          return jsonResponse(200, { ok: true })
        }
        throw new Error(`unexpected fetch ${url}`)
      },
      () =>
        assert.rejects(
          uploadFile({ apiBaseUrl: API, accessToken: 'tok', rootKey: rootKey(), name: 'a.bin', path, size: 5, rowId: FILE_ID }),
          /too old/,
        ),
    )
  })
  assert.deepEqual(deletes, [{ ids: ['957a1070-c734-4d7b-9430-27df8de29d58'] }])
})
