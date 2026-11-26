// ShieldFive CLI — `sf tidy`: move empty NAS/system folders (@eaDir, #recycle,
// .DS_Store, ...) that an earlier push made out of a vault tree and into the
// Bin. Before 0.6.1, `sf push` copied a Synology share's @eaDir folders (one
// per photo) as vault folders, which could fill the account's folder limit.
//
// Only folders whose name is on push's skip list are touched, and only when
// neither they nor anything under them holds a file. Nothing is deleted
// unless `purge` is set, and then only the folders this run moved.

import { encryptNameV6 } from '@shieldfive/crypto/vault'

import { _internals, isSystemDir } from './migrate.mjs'
import { decryptStoredName, findVaultRoot } from './thumbnailBackfill.mjs'
import { base64ToBytes, bytesToBase64, generateRandomKeyB64, hashMetadataV4, unwrapKeyB64, wrapKeyB64 } from './uploadCrypto.mjs'
import { newRowBoundId } from './upload.mjs'

const { apiJson, flattenTree, folderKeyFor, withRetry } = _internals
const MOVE_BATCH = 200 // MAX_BULK_FOLDERS in /api/folders/move
const LIST_GAP_MS = 220 // /api/files allows 300 a minute
const MOVE_GAP_MS = 6_500 // folders/move and folders/delete allow 10 a minute
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function pacer(gapMs) {
  let next = 0
  return async () => {
    const now = Date.now()
    const wait = Math.max(0, next - now)
    next = Math.max(now, next) + gapMs
    if (wait) await sleep(wait)
  }
}

/**
 * Find (and with `apply`, move to the Bin) empty system folders under the
 * vault tree that `source` / `media` / `vaultFolder` names.
 */
export async function runTidy({
  source = '.',
  apiBaseUrl,
  accessToken,
  rootKey,
  account,
  media = false,
  vaultFolder = null,
  apply = false,
  purge = false,
  confirm = async () => true,
  status = () => {},
  listGapMs = LIST_GAP_MS,
  moveGapMs = MOVE_GAP_MS,
}) {
  const rootKeyB64 = bytesToBase64(rootKey)
  const tree = await withRetry(() => apiJson(apiBaseUrl, accessToken, '/api/folders/tree'))
  const byId = flattenTree(tree.tree)
  const keyCache = new Map()
  const root = await findVaultRoot({ source, media, vaultFolder, byId, rootKeyB64, keyCache, account })
  const children = new Map()
  for (const n of byId.values()) {
    if (!n.parent_id) continue
    if (!children.has(n.parent_id)) children.set(n.parent_id, [])
    children.get(n.parent_id).push(n)
  }
  const nameOf = async (n) => {
    const pk = n.parent_id ? folderKeyFor(n.parent_id, byId, rootKeyB64, keyCache) : rootKeyB64
    if (!pk) return null
    try {
      return await decryptStoredName(n.name, pk, rootKeyB64, n.id)
    } catch {
      return null
    }
  }

  // Candidates: the top-most system-named folders under root.
  const candidates = []
  const stack = [...(children.get(root.id) ?? [])]
  while (stack.length) {
    const n = stack.pop()
    if (n.is_bin) continue
    const name = await nameOf(n)
    if (name && isSystemDir(name)) candidates.push({ node: n, name })
    else stack.push(...(children.get(n.id) ?? []))
  }

  // Empty means no file in the folder or anywhere under it.
  const pace = pacer(listGapMs)
  const hasFile = async (folderId) => {
    await pace()
    const q = new URLSearchParams({ limit: '5', folderId })
    const res = await withRetry(() => apiJson(apiBaseUrl, accessToken, `/api/files?${q}`))
    return (res.files ?? []).length > 0
  }
  const subtree = (n) => {
    const out = []
    const s = [n]
    while (s.length) {
      const x = s.pop()
      out.push(x)
      s.push(...(children.get(x.id) ?? []))
    }
    return out
  }
  const empty = []
  let kept = 0
  let checked = 0
  const totalFolders = candidates.reduce((s, c) => s + subtree(c.node).length, 0)
  status(`found ${candidates.length} NAS/system folders (${totalFolders} folders with their subfolders); checking they hold no files`)
  for (const c of candidates) {
    const all = subtree(c.node)
    let full = false
    for (const x of all) {
      checked += 1
      if (checked % 500 === 0) status(`checked ${checked} of ${totalFolders} folders`)
      if (await hasFile(x.id)) {
        full = true
        break
      }
    }
    if (full) kept += 1
    else empty.push({ ...c, count: all.length })
  }
  const summary = {
    candidates: candidates.length,
    empty: empty.length,
    emptyFolders: empty.reduce((s, c) => s + c.count, 0),
    keptWithFiles: kept,
    movedToBin: 0,
    foldersMoved: 0,
    purged: 0,
    vaultFolders: byId.size,
  }
  // With purge, also the empty system folders an earlier tidy left in the Bin.
  const binNode = [...byId.values()].find((n) => n.is_bin && !n.parent_id)
  const inBin = []
  if (purge && binNode) {
    const binKeyB64 = unwrapKeyB64({ wrappingKeyB64: rootKeyB64, wrappedKeyB64: binNode.fk_wrapped, ivB64: binNode.fk_iv })
    for (const n of children.get(binNode.id) ?? []) {
      let name = null
      try {
        name = await decryptStoredName(n.name, binKeyB64, rootKeyB64, n.id)
      } catch {}
      if (!name || !isSystemDir(name)) continue
      let full = false
      for (const x of subtree(n)) if (await hasFile(x.id)) { full = true; break }
      if (!full) inBin.push({ node: n, name, count: subtree(n).length })
    }
  }
  summary.inBin = inBin.length
  if (!apply || empty.length + inBin.length === 0) return summary
  if (!(await confirm(summary))) return { ...summary, declined: true }
  const moved = []
  if (empty.length) {

  // The Bin: one top-level folder per account; make it if missing.
  let bin = binNode
  let binKey
  if (bin) binKey = unwrapKeyB64({ wrappingKeyB64: rootKeyB64, wrappedKeyB64: bin.fk_wrapped, ivB64: bin.fk_iv })
  else {
    const id = newRowBoundId()
    const key = generateRandomKeyB64()
    const w = wrapKeyB64({ wrappingKeyB64: rootKeyB64, keyToWrapB64: key })
    const env = await encryptNameV6({ name: 'Bin', folderKey: rootKey, rowId: id })
    let res
    try {
      res = await withRetry(() =>
        apiJson(apiBaseUrl, accessToken, '/api/folders/create', {
          method: 'POST',
          body: { id, name_encrypted: JSON.stringify(env), nameHash: hashMetadataV4('bin', rootKeyB64), parentFolderId: null, fk_wrapped: w.wrapped, fk_iv: w.iv, isBin: true },
        }),
      )
    } catch (err) {
      throw new Error(
        `your vault has no Bin yet and making one failed: ${err.message} ` +
          'Open the web app once (it makes the Bin), or delete one folder there, then run sf tidy again.',
      )
    }
    bin = res.folder
    binKey = bin.id === id ? key : unwrapKeyB64({ wrappingKeyB64: rootKeyB64, wrappedKeyB64: bin.fk_wrapped, ivB64: bin.fk_iv })
  }
  if (!binKey) throw new Error('could not open your Bin folder with this vault key')

  const movePace = pacer(moveGapMs)
  for (let i = 0; i < empty.length; i += MOVE_BATCH) {
    const batch = empty.slice(i, i + MOVE_BATCH)
    const items = []
    for (const { node, name } of batch) {
      const fromKey = node.parent_id ? folderKeyFor(node.parent_id, byId, rootKeyB64, keyCache) : rootKeyB64
      const fk = unwrapKeyB64({ wrappingKeyB64: fromKey, wrappedKeyB64: node.fk_wrapped, ivB64: node.fk_iv })
      const w = wrapKeyB64({ wrappingKeyB64: binKey, keyToWrapB64: fk })
      const env = await encryptNameV6({ name, folderKey: base64ToBytes(binKey), rowId: node.id })
      items.push({ id: node.id, name_encrypted: JSON.stringify(env), nameHash: hashMetadataV4(name.toLowerCase(), rootKeyB64), fk_wrapped: w.wrapped, fk_iv: w.iv })
    }
    await movePace()
    let res
    try {
      res = await withRetry(() =>
        apiJson(apiBaseUrl, accessToken, '/api/folders/move', { method: 'POST', body: { newParentId: bin.id, items } }),
      )
    } catch (err) {
      throw new Error(`could not move folders to the Bin (${moved.length} moved so far): ${err.message}`)
    }
    const refused = new Set((res?.refused ?? []).map((r) => r.id))
    for (const c of batch) if (!refused.has(c.node.id)) moved.push(c)
    status(`moved ${moved.length} of ${empty.length} to the Bin`)
  }
  summary.movedToBin = moved.length
  summary.foldersMoved = moved.reduce((s, c) => s + c.count, 0)
  }

  if (purge) {
    const movePace = pacer(moveGapMs)
    for (const c of [...moved, ...inBin]) {
      await movePace()
      try {
        await withRetry(() =>
          apiJson(apiBaseUrl, accessToken, '/api/folders/delete', { method: 'POST', body: { folderId: c.node.id } }),
        )
      } catch (err) {
        throw new Error(`could not delete folders from the Bin (${summary.purged} deleted so far; the rest stay in the Bin): ${err.message}`)
      }
      summary.purged += 1
      if (summary.purged % 20 === 0) status(`deleted ${summary.purged} of ${moved.length + inBin.length} from the Bin`)
    }
  }
  return summary
}
