// VERIFIED (offline): the agent wire protocol. The operation allowlist is the
// security boundary of the agent, so it is pinned exactly: a test failure here
// means someone changed what a process that can reach the socket may do.

import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  MAX_VERIFY_PATHS,
  OPS,
  ProtocolError,
  lineSplitter,
  parseRequest,
} from '../src/agent/protocol.mjs'

const req = (obj) => JSON.stringify(obj)

test('the operation list is exactly the write-only set', () => {
  // push / thumbnails write; tidy only moves or deletes EMPTY NAS/system
  // folders. None returns a name, a key or file contents: counts only.
  assert.deepEqual([...OPS].sort(), ['doctor', 'lock', 'logout', 'push', 'status', 'sync', 'thumbnails', 'tidy', 'upload', 'verify'])
})

test('operations that would read, list, decrypt or export are refused', () => {
  for (const op of ['download', 'decrypt', 'key', 'rootKey', 'list', 'export', 'exec', 'token', 'read']) {
    assert.throws(
      () => parseRequest(req({ id: 1, op, args: {} })),
      (e) => e instanceof ProtocolError && e.code === 'unknown_op',
      `op ${op} must be refused`,
    )
  }
})

test('rejects non-JSON, non-objects and bad ids', () => {
  assert.throws(() => parseRequest('{nope'), /not valid JSON/)
  assert.throws(() => parseRequest('[1,2]'), /JSON object/)
  assert.throws(() => parseRequest(req({ id: { x: 1 }, op: 'status' })), /id must be/)
  assert.throws(() => parseRequest(req({ id: 'x'.repeat(65), op: 'status' })), /id must be/)
})

test('upload and sync accept only absolute paths', () => {
  assert.deepEqual(parseRequest(req({ id: 1, op: 'upload', args: { path: '/a/b.txt' } })), {
    id: 1,
    op: 'upload',
    args: { path: '/a/b.txt' },
  })
  assert.throws(() => parseRequest(req({ id: 1, op: 'upload', args: { path: 'b.txt' } })), /absolute/)
  assert.throws(() => parseRequest(req({ id: 1, op: 'upload', args: { path: '/a\u0000b' } })), /absolute/)
  assert.throws(() => parseRequest(req({ id: 1, op: 'sync', args: {} })), /folder must be/)
})

test('verify bounds the number of paths', () => {
  const paths = Array.from({ length: MAX_VERIFY_PATHS + 1 }, (_, i) => `/f${i}`)
  assert.throws(() => parseRequest(req({ id: 1, op: 'verify', args: { paths } })), /At most/)
  assert.throws(() => parseRequest(req({ id: 1, op: 'verify', args: { paths: [] } })), /non-empty/)
  assert.throws(
    () => parseRequest(req({ id: 1, op: 'verify', args: { paths: ['/ok', 'relative'] } })),
    /paths\[1\]/,
  )
})

test('ops without arguments drop whatever args were sent', () => {
  assert.deepEqual(parseRequest(req({ id: 7, op: 'status', args: { path: '/x' } })), {
    id: 7,
    op: 'status',
    args: {},
  })
})

test('logout carries only a boolean everywhere flag', () => {
  assert.deepEqual(parseRequest(req({ id: 1, op: 'logout', args: { everywhere: true } })), {
    id: 1,
    op: 'logout',
    args: { everywhere: true },
  })
  assert.deepEqual(parseRequest(req({ id: 1, op: 'logout', args: { everywhere: 'yes', other: 1 } })).args, {
    everywhere: false,
  })
})

test('lineSplitter reassembles lines split across chunks and handles several per chunk', () => {
  const lines = []
  const feed = lineSplitter((l) => lines.push(l))
  feed('{"a":')
  feed('1}\n{"b":2}\n\n{"c"')
  feed(':3}\n')
  assert.deepEqual(lines, ['{"a":1}', '{"b":2}', '{"c":3}'])
})

test('lineSplitter refuses an unbounded line', () => {
  const feed = lineSplitter(() => {}, { maxBytes: 16 })
  assert.throws(() => feed('x'.repeat(32)), (e) => e.code === 'line_too_long')
})

test('push, tidy and thumbnails carry only absolute paths and flags', () => {
  const p = parseRequest(req({ id: 1, op: 'push', args: { folder: '/tmp/x', media: true, extra: 'no' } }))
  assert.deepEqual(p.args, { folder: '/tmp/x', media: true, includeDotfiles: false, thumbnails: true })
  const t = parseRequest(req({ id: 2, op: 'tidy', args: { media: true, purge: true, apply: true } }))
  assert.deepEqual(t.args, { folder: null, media: true, vaultFolder: null, apply: true, purge: true, dryRun: false })
  assert.throws(() => parseRequest(req({ id: 3, op: 'push', args: { folder: 'rel' } })), ProtocolError)
})
