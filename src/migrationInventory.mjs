import { lstat, opendir } from 'node:fs/promises'
import { join, relative, resolve, sep } from 'node:path'

// Read-only preflight: includes hidden files and empty directories, preserves
// names, and reports unsupported entries instead of silently omitting them.
// It streams metadata without reading file contents or holding an inventory in
// memory. Upload must revalidate each source: this is not an immutable snapshot.
export async function* inventoryFolder(folder) {
  const root = resolve(folder)
  const initial = await lstat(root)
  if (!initial.isDirectory() || initial.isSymbolicLink()) throw new Error('Select a real source folder, not a symbolic link')
  const pending = [root]
  while (pending.length) {
    const directory = pending.pop()
    const directoryInfo = await lstat(directory)
    if (directoryInfo.isSymbolicLink() || !directoryInfo.isDirectory()) {
      yield { kind: 'skipped', path: relative(root, directory).split(sep).join('/'), reason: 'source_changed' }
      continue
    }
    for await (const entry of await opendir(directory)) {
      const absolutePath = join(directory, entry.name)
      const path = relative(root, absolutePath).split(sep).join('/')
      let info
      try { info = await lstat(absolutePath) }
      catch (error) { yield { kind: 'skipped', path, reason: error.code ?? 'unreadable' }; continue }
      if (info.isSymbolicLink()) yield { kind: 'skipped', path, reason: 'symbolic_link' }
      else if (info.isDirectory()) {
        yield { kind: 'directory', path }
        pending.push(absolutePath)
      } else if (info.isFile()) yield { kind: 'file', path, size: info.size, mtimeMs: info.mtimeMs }
      else yield { kind: 'skipped', path, reason: 'unsupported_file_type' }
    }
  }
}

export async function inspectMigrationSource(folder) {
  const totals = { files: 0, directories: 0, bytes: 0, skipped: 0 }
  for await (const entry of inventoryFolder(folder)) {
    if (entry.kind === 'file') { totals.files++; totals.bytes += entry.size }
    else if (entry.kind === 'directory') totals.directories++
    else totals.skipped++
    if (!Number.isSafeInteger(totals.bytes)) throw new Error('Source size exceeds the supported inventory limit')
  }
  return totals
}
