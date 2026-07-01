// VERIFIED: `sf sync` change detection + reconcile pass. The upload protocol is
// covered by upload.flow.test.mjs; these cover the new logic — the manifest,
// planSync, and syncOnce (new/changed uploads, unchanged skips, exclusions,
// per-file persistence, and failure isolation) with an injected upload function.

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  MANIFEST_NAME,
  loadManifest,
  planSync,
  runSync,
  saveManifest,
  scanFiles,
  signatureOf,
  syncOnce,
} from '../src/sync.mjs'

async function tmp() {
  return mkdtemp(join(tmpdir(), 'sf-cli-sync-'))
}

// A syncOnce harness with an injected uploadFn that records calls.
function recordingUpload() {
  const calls = []
  let n = 0
  const uploadFn = async ({ name }) => {
    calls.push(name)
    n += 1
    return { fileId: `file-${n}` }
  }
  return { uploadFn, calls }
}

async function runPass(dir, manifest, uploadFn) {
  return syncOnce({
    apiBaseUrl: 'https://api.test',
    accessToken: 'tok',
    rootKey: new Uint8Array(32),
    folder: dir,
    manifestPath: join(dir, MANIFEST_NAME),
    manifest,
    uploadFn,
  })
}

test('planSync splits new/changed vs unchanged by signature', () => {
  const entries = [
    { name: 'a', size: 10, mtimeMs: 1 },
    { name: 'b', size: 20, mtimeMs: 2 },
    { name: 'c', size: 30, mtimeMs: 3 },
  ]
  const manifest = {
    files: {
      a: { signature: signatureOf(entries[0]) }, // unchanged
      b: { signature: '999:999' }, // changed
      // c absent -> new
    },
  }
  const { toUpload, unchanged } = planSync(entries, manifest)
  assert.deepEqual(
    toUpload.map((e) => e.name),
    ['b', 'c'],
  )
  assert.deepEqual(
    unchanged.map((e) => e.name),
    ['a'],
  )
})

test('loadManifest returns empty for a missing file; save/load round-trips', async () => {
  const dir = await tmp()
  try {
    const path = join(dir, MANIFEST_NAME)
    const empty = await loadManifest(path)
    assert.deepEqual(empty.files, {})

    empty.files['x.txt'] = { signature: '1:2', fileId: 'file-1' }
    await saveManifest(path, empty)
    const reloaded = await loadManifest(path)
    assert.deepEqual(reloaded.files['x.txt'], { signature: '1:2', fileId: 'file-1' })
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('scanFiles skips dotfiles, the manifest, and directories', async () => {
  const dir = await tmp()
  try {
    await writeFile(join(dir, 'keep.txt'), 'a')
    await writeFile(join(dir, '.hidden'), 'b')
    await writeFile(join(dir, MANIFEST_NAME), '{}')
    const names = (await scanFiles(dir, { exclude: [MANIFEST_NAME] }))
      .map((e) => e.name)
      .sort()
    assert.deepEqual(names, ['keep.txt'])
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('syncOnce uploads new files and records them in the manifest', async () => {
  const dir = await tmp()
  try {
    await writeFile(join(dir, 'one.txt'), 'hello')
    await writeFile(join(dir, 'two.bin'), 'world!!')
    const manifest = { files: {} }
    const { uploadFn, calls } = recordingUpload()

    const summary = await runPass(dir, manifest, uploadFn)

    assert.equal(summary.uploaded, 2)
    assert.equal(summary.skipped, 0)
    assert.equal(summary.failed, 0)
    assert.deepEqual(calls.sort(), ['one.txt', 'two.bin'])
    assert.ok(manifest.files['one.txt'].fileId)
    assert.ok(manifest.files['one.txt'].signature)

    // Manifest was persisted to disk during the pass.
    const onDisk = JSON.parse(await readFile(join(dir, MANIFEST_NAME), 'utf8'))
    assert.ok(onDisk.files['two.bin'].fileId)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('syncOnce skips unchanged files and re-uploads changed ones', async () => {
  const dir = await tmp()
  try {
    const p1 = join(dir, 'stable.txt')
    const p2 = join(dir, 'edited.txt')
    await writeFile(p1, 'unchanging')
    await writeFile(p2, 'v1')
    const manifest = { files: {} }

    const first = recordingUpload()
    await runPass(dir, manifest, first.uploadFn)
    assert.equal(first.calls.length, 2)

    // Change one file's content (size changes -> signature changes); leave the
    // other untouched.
    await writeFile(p2, 'a much longer version 2')

    const second = recordingUpload()
    const summary = await runPass(dir, manifest, second.uploadFn)

    assert.deepEqual(second.calls, ['edited.txt']) // only the changed file
    assert.equal(summary.uploaded, 1)
    assert.equal(summary.skipped, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('syncOnce detects an mtime-only change', async () => {
  const dir = await tmp()
  try {
    const p = join(dir, 'file.txt')
    await writeFile(p, 'same size')
    const manifest = { files: {} }
    await runPass(dir, manifest, recordingUpload().uploadFn)

    // Bump mtime forward without changing content.
    const future = new Date(Date.now() + 60_000)
    await utimes(p, future, future)

    const second = recordingUpload()
    const summary = await runPass(dir, manifest, second.uploadFn)
    assert.deepEqual(second.calls, ['file.txt'])
    assert.equal(summary.uploaded, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('runSync (single pass) authenticates once, runs a pass, and persists', async () => {
  const dir = await tmp()
  try {
    await writeFile(join(dir, 'doc.txt'), 'contents')
    let authCalls = 0
    const { uploadFn, calls } = recordingUpload()

    await runSync({
      cfg: { apiBaseUrl: 'https://api.test' },
      folder: dir,
      watch: false,
      authAndUnlock: async () => {
        authCalls += 1
        return { accessToken: 'tok', rootKey: new Uint8Array(32) }
      },
      uploadFn,
      log: () => {},
      status: () => {},
    })

    assert.equal(authCalls, 1)
    assert.deepEqual(calls, ['doc.txt'])
    const onDisk = await loadManifest(join(dir, MANIFEST_NAME))
    assert.ok(onDisk.files['doc.txt'].fileId)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('syncOnce isolates a failed upload: it is not recorded and others still sync', async () => {
  const dir = await tmp()
  try {
    await writeFile(join(dir, 'good.txt'), 'ok')
    await writeFile(join(dir, 'bad.txt'), 'boom')
    const manifest = { files: {} }

    const uploadFn = async ({ name }) => {
      if (name === 'bad.txt') throw new Error('server said no')
      return { fileId: `file-${name}` }
    }

    const summary = await runPass(dir, manifest, uploadFn)
    assert.equal(summary.uploaded, 1)
    assert.equal(summary.failed, 1)
    assert.equal(summary.errors[0].name, 'bad.txt')
    assert.ok(manifest.files['good.txt']) // recorded
    assert.equal(manifest.files['bad.txt'], undefined) // NOT recorded -> retried next pass

    // A later pass with a now-working upload retries only the failed file.
    const retry = recordingUpload()
    const s2 = await runPass(dir, manifest, retry.uploadFn)
    assert.deepEqual(retry.calls, ['bad.txt'])
    assert.equal(s2.uploaded, 1)
    assert.equal(s2.skipped, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
