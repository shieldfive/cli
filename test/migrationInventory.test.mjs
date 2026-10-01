import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtemp, mkdir, writeFile, symlink, open, rm, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { inventoryFolder, inspectMigrationSource } from '../src/migrationInventory.mjs'

test('inventory preserves nested, hidden, Unicode and empty folders without modifying sources', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'sf-inventory-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  await mkdir(join(root, 'Albúm'))
  await mkdir(join(root, 'empty'))
  await writeFile(join(root, 'Albúm', 'photo.txt'), 'fixture')
  await writeFile(join(root, '.hidden'), '123')
  const entries = []
  for await (const entry of inventoryFolder(root)) entries.push(entry)
  assert.deepEqual(entries.filter(e => e.kind === 'file').map(e => e.path).sort(), ['.hidden', 'Albúm/photo.txt'])
  assert.deepEqual(await inspectMigrationSource(root), { files: 2, directories: 2, bytes: 10, skipped: 0 })
  assert.equal(await readFile(join(root, 'Albúm', 'photo.txt'), 'utf8'), 'fixture')
})

test('links outside the source and loops are reported and not traversed', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'sf-inventory-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const source = join(root, 'source'); await mkdir(source)
  await writeFile(join(root, 'outside.txt'), 'private fixture')
  await symlink(join(root, 'outside.txt'), join(source, 'linked.txt'))
  await symlink(source, join(source, 'loop'))
  const entries = []
  for await (const entry of inventoryFolder(source)) entries.push(entry)
  assert.equal(entries.length, 2)
  assert.ok(entries.every(e => e.kind === 'skipped' && e.reason === 'symbolic_link'))
  await assert.rejects(async () => { for await (const entry of inventoryFolder(join(source, 'loop'))) void entry }, /real source folder/)
})

test('70 GiB sparse source is counted using metadata without reading its contents', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'sf-inventory-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const file = await open(join(root, 'large.bin'), 'w')
  try { await file.truncate(70 * 1024 ** 3) } finally { await file.close() }
  assert.deepEqual(await inspectMigrationSource(root), { files: 1, directories: 0, bytes: 70 * 1024 ** 3, skipped: 0 })
})
