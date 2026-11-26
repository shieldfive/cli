// ShieldFive CLI — `sf tidy`: move empty NAS/system folders (@eaDir, #recycle,
// .DS_Store, ...) that an earlier push made out of a vault tree and into the
// Bin. Before 0.6.1, `sf push` copied a Synology share's @eaDir folders (one
// per photo) as vault folders, which could fill the account's folder limit.
//
// Only folders whose name is on push's skip list are touched, and only when
// neither they nor anything under them holds a file. Nothing is deleted
// unless `purge` is set, and then only the folders this run moved.

import { encryptNameV6 } from '@shieldfive/crypto/vault'

import { _internals, isSystemDir, SYSTEM_DIR_NAMES } from './migrate.mjs'
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
  // Names by keyed hash (no decrypting, which costs ~90 ms a name) when the
  // server has /api/folders/index; else decrypt each name.
  let hashOf = null
  try {
    const idx = await withRetry(() => apiJson(apiBaseUrl, accessToken, '/api/folders/index'))
    hashOf = new Map((idx.folders ?? []).map((f) => [f.id, f.name_hash]))
  } catch (err) {
    if (err?.status !== 404 && err?.status !== 405) throw err
  }
  const sysByHash = new Map(SYSTEM_DIR_NAMES.map((n) => [hashMetadataV4(n.toLowerCase(), rootKeyB64), n]))
  const nameOf = async (n) => {
    if (hashOf && hashOf.get(n.id)) return sysByHash.get(hashOf.get(n.id)) ?? ''
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

  // Which of these folders hold a file: one call per 1,000 folders on a
  // server with /api/folders/with-files, else one /api/files call per folder.
  const pace = pacer(listGapMs)
  let batched = true
  const withFiles = async (ids) => {
    const out = new Set()
    if (batched) {
      try {
        for (let i = 0; i < ids.length; i += 1000) {
          const res = await withRetry(() =>
            apiJson(apiBaseUrl, accessToken, '/api/folders/with-files', { method: 'POST', body: { ids: ids.slice(i, i + 1000) } }),
          )
          for (const id of res.withFiles ?? []) out.add(id)
        }
        return out
      } catch (err) {
        if (err?.status !== 404 && err?.status !== 405) throw err
        batched = false
      }
    }
    for (const id of ids) {
      await pace()
      const q = new URLSearchParams({ limit: '5', folderId: id })
      const res = await withRetry(() => apiJson(apiBaseUrl, accessToken, `/api/files?${q}`))
      if ((res.files ?? []).length) out.add(id)
    }
    return out
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
  const totalFolders = candidates.reduce((n, c) => n + subtree(c.node).length, 0)
  status(`found ${candidates.length} NAS/system folders (${totalFolders} folders with their subfolders); checking they hold no files`)
  const full = await withFiles(candidates.flatMap((c) => subtree(c.node).map((x) => x.id)))
  for (const c of candidates) {
    const all = subtree(c.node)
    if (all.some((x) => full.has(x.id))) kept += 1
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
      if (hashOf && hashOf.get(n.id)) name = sysByHash.get(hashOf.get(n.id)) ?? null
      else {
        try {
          name = await decryptStoredName(n.name, binKeyB64, rootKeyB64, n.id)
        } catch {}
      }
      if (name && isSystemDir(name)) inBin.push({ node: n, name, count: subtree(n).length })
    }
    const binFull = await withFiles(inBin.flatMap((c) => subtree(c.node).map((x) => x.id)))
    for (let i = inBin.length - 1; i >= 0; i -= 1) if (subtree(inBin[i].node).some((x) => binFull.has(x.id))) inBin.splice(i, 1)
  }
  summary.inBin = inBin.length
  if (!apply || empty.length + inBin.length === 0) return summary
  if (!(await confirm(summary))) return { ...summary, declined: true }
  const moved = []

  // The Bin: one top-level folder per account; make it if missing.
  let bin = binNode
  let binKey
  if (bin) binKey = unwrapKeyB64({ wrappingKeyB64: rootKeyB64, wrappedKeyB64: bin.fk_wrapped, ivB64: bin.fk_iv })
  else {
    const made = await createFolder({ name: 'Bin', parentId: null, parentKeyB64: rootKeyB64, isBin: true }).catch((err) => {
      throw new Error(
        `your vault has no Bin yet and making one failed: ${err.message} ` +
          'Open the web app once (it makes the Bin), or delete one folder there, then run sf tidy again.',
      )
    })
    bin = made.folder
    binKey = made.key
  }
  if (!binKey) throw new Error('could not open your Bin folder with this vault key')

  // With --delete, gather everything into one folder inside the Bin and delete
  // that once: folders/delete allows 10 calls a minute, and an account can have
  // hundreds of @eaDir parents. If that folder cannot be made (no free folder
  // slot), delete them one by one.
  let target = { id: bin.id, key: binKey }
  let container = null
  if (purge) {
    try {
      const made = await createFolder({ name: 'Removed by sf tidy', parentId: bin.id, parentKeyB64: binKey })
      container = { id: made.folder.id, key: made.key }
      target = container
    } catch {}
  }

  const keyOfParent = (node) => (node.parent_id === bin.id ? binKey : node.parent_id ? folderKeyFor(node.parent_id, byId, rootKeyB64, keyCache) : rootKeyB64)
  const toMove = container ? [...empty, ...inBin] : empty
  const movePace = pacer(moveGapMs)
  for (let i = 0; i < toMove.length; i += MOVE_BATCH) {
    const batch = toMove.slice(i, i + MOVE_BATCH)
    const items = []
    for (const { node, name } of batch) {
      const fk = unwrapKeyB64({ wrappingKeyB64: keyOfParent(node), wrappedKeyB64: node.fk_wrapped, ivB64: node.fk_iv })
      const w = wrapKeyB64({ wrappingKeyB64: target.key, keyToWrapB64: fk })
      const env = await encryptNameV6({ name, folderKey: base64ToBytes(target.key), rowId: node.id })
      items.push({ id: node.id, name_encrypted: JSON.stringify(env), nameHash: hashMetadataV4(name.toLowerCase(), rootKeyB64), fk_wrapped: w.wrapped, fk_iv: w.iv })
    }
    await movePace()
    let res
    try {
      res = await withRetry(() =>
        apiJson(apiBaseUrl, accessToken, '/api/folders/move', { method: 'POST', body: { newParentId: target.id, items } }),
      )
    } catch (err) {
      throw new Error(`could not move folders to the Bin (${moved.length} moved so far): ${err.message}`)
    }
    const refused = new Set((res?.refused ?? []).map((r) => r.id))
    for (const c of batch) if (!refused.has(c.node.id)) moved.push(c)
    status(`moved ${moved.length} of ${toMove.length} to the Bin`)
  }
  const movedFromVault = moved.filter((c) => !inBin.includes(c))
  summary.movedToBin = movedFromVault.length
  summary.foldersMoved = movedFromVault.reduce((n, c) => n + c.count, 0)

  if (purge) {
    summary.skippedNotEmpty = 0
    // Fresh tree: anything added under these folders since the scan counts.
    const fresh = flattenTree((await withRetry(() => apiJson(apiBaseUrl, accessToken, '/api/folders/tree'))).tree)
    const freshKids = new Map()
    for (const n of fresh.values()) {
      if (!n.parent_id) continue
      if (!freshKids.has(n.parent_id)) freshKids.set(n.parent_id, [])
      freshKids.get(n.parent_id).push(n)
    }
    const under = (id) => {
      const ids = []
      const st = [id]
      while (st.length) {
        const x = st.pop()
        ids.push(x)
        for (const k of freshKids.get(x) ?? []) st.push(k.id)
      }
      return ids
    }
    const del = async (id) => {
      await movePace()
      try {
        await withRetry(() => apiJson(apiBaseUrl, accessToken, '/api/folders/delete', { method: 'POST', body: { folderId: id } }))
      } catch (err) {
        throw new Error(`could not delete folders from the Bin (${summary.purged} deleted so far; the rest stay in the Bin): ${err.message}`)
      }
    }
    // Re-check on the server, right before deleting, that nothing under these
    // folders holds a file. One that does is left in the Bin.
    const items = container ? moved : [...moved, ...inBin]
    const live = items.filter((c) => fresh.has(c.node.id))
    const holding = await withFiles(container ? under(container.id) : live.flatMap((c) => under(c.node.id)))
    const ok = live.filter((c) => !under(c.node.id).some((id) => holding.has(id)))
    summary.skippedNotEmpty = live.length - ok.length
    if (container && ok.length === live.length && !holding.has(container.id)) {
      await del(container.id)
      summary.purged = ok.length
    } else {
      for (const c of ok) {
        await del(c.node.id)
        summary.purged += 1
        if (summary.purged % 20 === 0) status(`deleted ${summary.purged} of ${ok.length} from the Bin`)
      }
      if (container && summary.skippedNotEmpty === 0) await del(container.id)
    }
  }
  return summary

  async function createFolder({ name, parentId, parentKeyB64, isBin = false }) {
    const id = newRowBoundId()
    const key = generateRandomKeyB64()
    const w = wrapKeyB64({ wrappingKeyB64: parentKeyB64, keyToWrapB64: key })
    const env = await encryptNameV6({ name, folderKey: base64ToBytes(parentKeyB64), rowId: id })
    const res = await withRetry(() =>
      apiJson(apiBaseUrl, accessToken, '/api/folders/create', {
        method: 'POST',
        body: { id, name_encrypted: JSON.stringify(env), nameHash: hashMetadataV4(name.toLowerCase(), rootKeyB64), parentFolderId: parentId, fk_wrapped: w.wrapped, fk_iv: w.iv, ...(isBin ? { isBin: true } : {}) },
      }),
    )
    const folder = res.folder
    return { folder, key: folder.id === id ? key : unwrapKeyB64({ wrappingKeyB64: parentKeyB64, wrappedKeyB64: folder.fk_wrapped, ivB64: folder.fk_iv }) }
  }
}
